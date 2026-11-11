using Microsoft.Data.Sqlite;
using UltimateWindows.Core.Models;
using UltimateWindows.Modules.Cleaner.Contracts;
using UltimateWindows.Modules.Cleaner.Models;

namespace UltimateWindows.Modules.Cleaner.Browsers;

/// <summary>
/// Виды данных браузера, которые пользователь может отметить для очистки отдельно друг от друга.
/// Пароли, автозаполнение форм, ключи шифрования, закладки и настройки расширений сюда не входят —
/// они защищены всегда и в обычный выбор не попадают.
/// </summary>
public enum BrowserDataKind
{
    Cache = 0,
    History = 1,
    Downloads = 2,
    Cookies = 3,
    Sessions = 4
}

/// <summary>
/// Выбор пользователя для очистки данных браузеров по пунктам.
/// По умолчанию включён только кэш.
/// </summary>
public sealed record BrowserCleanupSelection
{
    public bool CleanCache { get; init; } = true;
    public bool CleanHistory { get; init; }
    public bool CleanDownloads { get; init; }
    public bool CleanCookies { get; init; }
    public bool CleanSessions { get; init; }

    /// <summary>
    /// Сайты, чьи cookie и вход в учётную запись нужно сохранить при очистке cookie
    /// (например, «google.com», «github.com»). Субдомены сохраняются вместе с основным доменом.
    /// </summary>
    public IReadOnlyList<string> KeepCookieDomains { get; init; } = [];
}

/// <summary>
/// Сводка по одному профилю браузера и одному виду данных.
/// </summary>
public sealed record BrowserDataItemSummary(
    DiscoveredBrowserProfile Profile,
    BrowserDataKind Kind,
    string FriendlyTitle,
    string FriendlyDescription,
    int ItemCount,
    long EstimatedBytes,
    int PreservedCookieCount,
    bool RequiresClosedBrowser)
{
    public bool BlockedByRunningBrowser => RequiresClosedBrowser && Profile.IsBrowserCurrentlyRunning;

    public string FormattedAmount => Kind switch
    {
        BrowserDataKind.Cache or BrowserDataKind.Sessions => ByteFormatter.Format(EstimatedBytes),
        BrowserDataKind.Cookies when PreservedCookieCount > 0 =>
            $"{ItemCount:N0} шт. (сохранится: {PreservedCookieCount:N0})",
        _ => $"{ItemCount:N0} записей"
    };
}

public sealed record BrowserDataScanReport(
    DateTimeOffset ScannedAtUtc,
    IReadOnlyList<DiscoveredBrowserProfile> Profiles,
    IReadOnlyList<BrowserDataItemSummary> Items,
    IReadOnlyList<string> Warnings)
{
    public int TotalHistoryItems => Items.Where(i => i.Kind == BrowserDataKind.History).Sum(i => i.ItemCount);
    public int TotalDownloadItems => Items.Where(i => i.Kind == BrowserDataKind.Downloads).Sum(i => i.ItemCount);
    public int TotalCookieItems => Items.Where(i => i.Kind == BrowserDataKind.Cookies).Sum(i => i.ItemCount);
    public long TotalSessionBytes => Items.Where(i => i.Kind == BrowserDataKind.Sessions).Sum(i => i.EstimatedBytes);
}

public sealed record BrowserDataCleanResult(
    int DeletedHistoryRows,
    int DeletedDownloadRows,
    int DeletedCookieRows,
    int PreservedCookieRows,
    int DeletedSessionFiles,
    long FreedSessionBytes,
    int SkippedRunningProfiles,
    IReadOnlyList<string> Warnings,
    string UserSummaryMessage);

/// <summary>
/// Выборочная очистка данных браузеров по пунктам: история посещений, список загрузок,
/// cookie со списком сайтов «сохранить» и вкладки прошлого сеанса.
/// <para>
/// Жёсткое правило: файлы паролей («Login Data», «Ya Passman Data», «logins.json», «key4.db», «Local State»),
/// автозаполнения форм («Web Data», «Ya Autofill Data», «formhistory.sqlite»), закладок («Bookmarks»,
/// в Firefox — таблицы <c>moz_bookmarks</c> и <c>moz_anno_attributes</c> внутри «places.sqlite») и настроек
/// расширений этим классом никогда не открываются на запись и не удаляются.
/// </para>
/// <para>
/// Если браузер сейчас открыт, его история, загрузки, cookie и сеансы не трогаются: правка открытой базы SQLite
/// повредила бы её. Пользователю возвращается понятное предупреждение.
/// </para>
/// </summary>
public sealed class BrowserDataCleaner
{
    private static readonly string[] ChromiumSessionRelativePaths =
    [
        "Current Session",
        "Current Tabs",
        "Last Session",
        "Last Tabs"
    ];

    private static readonly string[] FirefoxSessionRelativePaths =
    [
        "sessionstore.jsonlz4",
        Path.Combine("sessionstore-backups", "recovery.jsonlz4"),
        Path.Combine("sessionstore-backups", "recovery.baklz4"),
        Path.Combine("sessionstore-backups", "previous.jsonlz4")
    ];

    private readonly ICleanerPlatformBridge _bridge;

    public BrowserDataCleaner(ICleanerPlatformBridge bridge)
    {
        _bridge = bridge ?? throw new ArgumentNullException(nameof(bridge));
    }

    /// <summary>
    /// Приводит строку со списком доменов (через запятую, точку с запятой, пробел или перевод строки)
    /// к аккуратному набору доменов в нижнем регистре без схем, путей и начальной точки.
    /// </summary>
    public static IReadOnlyList<string> ParseKeepCookieDomains(string? rawText)
    {
        if (string.IsNullOrWhiteSpace(rawText))
        {
            return [];
        }

        var parts = rawText.Split([',', ';', '\r', '\n', '\t', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return NormalizeDomains(parts);
    }

    public static IReadOnlyList<string> NormalizeDomains(IEnumerable<string>? domains)
    {
        if (domains is null)
        {
            return [];
        }

        var result = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var raw in domains)
        {
            var d = NormalizeSingleDomain(raw);
            if (d.Length > 0 && seen.Add(d))
            {
                result.Add(d);
            }
        }

        return result;
    }

    /// <summary>
    /// Проверяет, должен ли домен cookie из базы браузера сохраниться при данном списке исключений.
    /// Домен «google.com» сохраняет и «google.com», и «.google.com», и «mail.google.com», но не «notgoogle.com».
    /// </summary>
    public static bool ShouldKeepCookieHost(string? cookieHost, IReadOnlyList<string> normalizedKeepDomains)
    {
        if (string.IsNullOrWhiteSpace(cookieHost) || normalizedKeepDomains.Count == 0)
        {
            return false;
        }

        var host = cookieHost.Trim().TrimStart('.').ToLowerInvariant();
        if (host.Length == 0)
        {
            return false;
        }

        foreach (var keep in normalizedKeepDomains)
        {
            if (string.Equals(host, keep, StringComparison.Ordinal))
            {
                return true;
            }

            if (host.Length > keep.Length &&
                host[host.Length - keep.Length - 1] == '.' &&
                host.EndsWith(keep, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Подсчитывает объём истории, загрузок, cookie и сеансов по найденным профилям без каких-либо изменений на диске.
    /// </summary>
    public BrowserDataScanReport Scan(
        IReadOnlyList<DiscoveredBrowserProfile> profiles,
        IReadOnlyList<string>? keepCookieDomains = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(profiles);

        var keep = NormalizeDomains(keepCookieDomains);
        var items = new List<BrowserDataItemSummary>();
        var warnings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var profile in profiles)
        {
            ct.ThrowIfCancellationRequested();

            if (profile.IsBrowserCurrentlyRunning)
            {
                warnings.Add($"«{profile.BrowserName}» сейчас открыт: закройте браузер, чтобы очистить его историю, загрузки, cookie или вкладки.");
            }

            if (profile.IsGeckoFirefox)
            {
                ScanFirefoxProfile(profile, keep, items);
            }
            else
            {
                ScanChromiumProfile(profile, keep, items);
            }
        }

        return new BrowserDataScanReport(DateTimeOffset.UtcNow, profiles, items, warnings.ToList());
    }

    /// <summary>
    /// Выполняет выбранную пользователем очистку истории, загрузок, cookie и сеансов.
    /// Профили открытых браузеров пропускаются целиком.
    /// </summary>
    public BrowserDataCleanResult Clean(
        IReadOnlyList<DiscoveredBrowserProfile> profiles,
        BrowserCleanupSelection selection,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(profiles);
        ArgumentNullException.ThrowIfNull(selection);

        if (!selection.CleanHistory && !selection.CleanDownloads && !selection.CleanCookies && !selection.CleanSessions)
        {
            return new BrowserDataCleanResult(0, 0, 0, 0, 0, 0, 0, [], "Дополнительные пункты браузеров не выбраны.");
        }

        var keep = NormalizeDomains(selection.KeepCookieDomains);
        var warnings = new List<string>();
        int deletedHistory = 0, deletedDownloads = 0, deletedCookies = 0, preservedCookies = 0, deletedSessions = 0, skippedRunning = 0;
        long freedSessions = 0;

        foreach (var profile in profiles)
        {
            ct.ThrowIfCancellationRequested();

            if (IsProfileRunningNow(profile))
            {
                skippedRunning++;
                warnings.Add($"Профиль «{profile.BrowserName} ({profile.ProfileName})» пропущен: браузер открыт.");
                continue;
            }

            if (profile.IsGeckoFirefox)
            {
                CleanFirefoxProfile(
                    profile, selection, keep,
                    ref deletedHistory, ref deletedDownloads, ref deletedCookies, ref preservedCookies,
                    ref deletedSessions, ref freedSessions, warnings);
            }
            else
            {
                CleanChromiumProfile(
                    profile, selection, keep,
                    ref deletedHistory, ref deletedDownloads, ref deletedCookies, ref preservedCookies,
                    ref deletedSessions, ref freedSessions, warnings);
            }
        }

        var parts = new List<string>();
        if (deletedHistory > 0) parts.Add($"история: {deletedHistory:N0}");
        if (deletedDownloads > 0) parts.Add($"список загрузок: {deletedDownloads:N0}");
        if (deletedCookies > 0)
        {
            parts.Add(preservedCookies > 0
                ? $"cookie: {deletedCookies:N0} (сохранено по списку: {preservedCookies:N0})"
                : $"cookie: {deletedCookies:N0}");
        }

        if (deletedSessions > 0) parts.Add($"сеансы: {ByteFormatter.Format(freedSessions)}");
        if (skippedRunning > 0) parts.Add($"пропущено открытых профилей: {skippedRunning}");

        var summary = parts.Count > 0
            ? "Браузеры — удалено (" + string.Join(", ", parts) + "). Пароли, автозаполнение и закладки не тронуты."
            : "В выбранных пунктах браузеров удалять нечего.";

        return new BrowserDataCleanResult(
            deletedHistory, deletedDownloads, deletedCookies, preservedCookies,
            deletedSessions, freedSessions, skippedRunning, warnings, summary);
    }

    // ---------------------------------------------------------------------------------------------
    // Чтение без изменений
    // ---------------------------------------------------------------------------------------------

    private static void ScanChromiumProfile(
        DiscoveredBrowserProfile profile,
        IReadOnlyList<string> keepDomains,
        List<BrowserDataItemSummary> sink)
    {
        var historyDb = Path.Combine(profile.ProfileDataDirectory, "History");
        if (File.Exists(historyDb))
        {
            var (urls, downloads) = CountChromiumHistoryAndDownloads(historyDb);
            if (urls > 0)
            {
                sink.Add(new BrowserDataItemSummary(
                    profile, BrowserDataKind.History,
                    $"{profile.BrowserName} ({profile.ProfileName}) — история посещений",
                    "Адреса и заголовки открытых страниц. Закладки и пароли не затрагиваются.",
                    urls, SafeFileLength(historyDb), 0, RequiresClosedBrowser: true));
            }

            if (downloads > 0)
            {
                sink.Add(new BrowserDataItemSummary(
                    profile, BrowserDataKind.Downloads,
                    $"{profile.BrowserName} ({profile.ProfileName}) — список загрузок",
                    "Журнал скачанных файлов в браузере. Сами файлы в папке «Загрузки» остаются на месте.",
                    downloads, 0, 0, RequiresClosedBrowser: true));
            }
        }

        var cookiesDb = ResolveChromiumCookiesPath(profile.ProfileDataDirectory);
        if (cookiesDb is not null)
        {
            var (toDelete, toKeep) = CountCookies(cookiesDb, "cookies", "host_key", keepDomains);
            if (toDelete > 0 || toKeep > 0)
            {
                sink.Add(new BrowserDataItemSummary(
                    profile, BrowserDataKind.Cookies,
                    $"{profile.BrowserName} ({profile.ProfileName}) — файлы cookie",
                    "Выход с сайтов, кроме перечисленных в списке «сохранить». Пароли остаются в браузере.",
                    toDelete, SafeFileLength(cookiesDb), toKeep, RequiresClosedBrowser: true));
            }
        }

        var sessionFiles = EnumerateChromiumSessionFiles(profile.ProfileDataDirectory);
        if (sessionFiles.Count > 0)
        {
            sink.Add(new BrowserDataItemSummary(
                profile, BrowserDataKind.Sessions,
                $"{profile.BrowserName} ({profile.ProfileName}) — открытые вкладки",
                "Сохранённый набор последних открытых вкладок и окон.",
                sessionFiles.Count, sessionFiles.Sum(SafeFileLength), 0, RequiresClosedBrowser: true));
        }
    }

    private static void ScanFirefoxProfile(
        DiscoveredBrowserProfile profile,
        IReadOnlyList<string> keepDomains,
        List<BrowserDataItemSummary> sink)
    {
        var placesDb = Path.Combine(profile.ProfileDataDirectory, "places.sqlite");
        if (File.Exists(placesDb))
        {
            var (visits, downloads) = CountFirefoxHistoryAndDownloads(placesDb);
            if (visits > 0)
            {
                sink.Add(new BrowserDataItemSummary(
                    profile, BrowserDataKind.History,
                    $"{profile.BrowserName} ({profile.ProfileName}) — история посещений",
                    "Посещённые страницы в places.sqlite; таблица закладок moz_bookmarks остаётся нетронутой.",
                    visits, 0, 0, RequiresClosedBrowser: true));
            }

            if (downloads > 0)
            {
                sink.Add(new BrowserDataItemSummary(
                    profile, BrowserDataKind.Downloads,
                    $"{profile.BrowserName} ({profile.ProfileName}) — список загрузок",
                    "Записи о скачанных файлах в браузере. Сами скачанные файлы на диске остаются.",
                    downloads, 0, 0, RequiresClosedBrowser: true));
            }
        }

        var cookiesDb = Path.Combine(profile.ProfileDataDirectory, "cookies.sqlite");
        if (File.Exists(cookiesDb))
        {
            var (toDelete, toKeep) = CountCookies(cookiesDb, "moz_cookies", "host", keepDomains);
            if (toDelete > 0 || toKeep > 0)
            {
                sink.Add(new BrowserDataItemSummary(
                    profile, BrowserDataKind.Cookies,
                    $"{profile.BrowserName} ({profile.ProfileName}) — файлы cookie",
                    "Выход с сайтов, кроме перечисленных в списке «сохранить». Пароли в logins.json не затрагиваются.",
                    toDelete, SafeFileLength(cookiesDb), toKeep, RequiresClosedBrowser: true));
            }
        }

        var sessionFiles = EnumerateFirefoxSessionFiles(profile.ProfileDataDirectory);
        if (sessionFiles.Count > 0)
        {
            sink.Add(new BrowserDataItemSummary(
                profile, BrowserDataKind.Sessions,
                $"{profile.BrowserName} ({profile.ProfileName}) — открытые вкладки",
                "Сохранённые вкладки прошлого сеанса Firefox.",
                sessionFiles.Count, sessionFiles.Sum(SafeFileLength), 0, RequiresClosedBrowser: true));
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Очистка закрытого профиля
    // ---------------------------------------------------------------------------------------------

    private void CleanChromiumProfile(
        DiscoveredBrowserProfile profile,
        BrowserCleanupSelection selection,
        IReadOnlyList<string> keepDomains,
        ref int deletedHistory,
        ref int deletedDownloads,
        ref int deletedCookies,
        ref int preservedCookies,
        ref int deletedSessions,
        ref long freedSessions,
        List<string> warnings)
    {
        if (selection.CleanHistory || selection.CleanDownloads)
        {
            var historyDb = Path.Combine(profile.ProfileDataDirectory, "History");
            if (File.Exists(historyDb) && !_bridge.IsFileLockedByAnotherProcess(historyDb))
            {
                try
                {
                    using var conn = OpenWritableConnection(historyDb);
                    if (selection.CleanHistory)
                    {
                        deletedHistory += ExecuteDeleteIfTableExists(conn, "visits");
                        deletedHistory += ExecuteDeleteIfTableExists(conn, "urls");
                        _ = ExecuteDeleteIfTableExists(conn, "keyword_search_terms");
                        _ = ExecuteDeleteIfTableExists(conn, "segment_usage");
                        _ = ExecuteDeleteIfTableExists(conn, "segments");
                        _ = ExecuteDeleteIfTableExists(conn, "content_annotations");
                        _ = ExecuteDeleteIfTableExists(conn, "context_annotations");
                    }

                    if (selection.CleanDownloads)
                    {
                        _ = ExecuteDeleteIfTableExists(conn, "downloads_url_chains");
                        _ = ExecuteDeleteIfTableExists(conn, "downloads_slices");
                        deletedDownloads += ExecuteDeleteIfTableExists(conn, "downloads");
                    }

                    TryVacuum(conn);
                }
                catch (Exception ex)
                {
                    warnings.Add($"Не удалось очистить историю {profile.BrowserName}: {ex.Message}");
                }
            }

            if (selection.CleanHistory)
            {
                foreach (var aux in new[] { "Visited Links", "History-journal", "Favicons", "Favicons-journal", "Top Sites", "Top Sites-journal" })
                {
                    TryDeleteUnlockedFile(Path.Combine(profile.ProfileDataDirectory, aux), out _);
                }
            }
        }

        if (selection.CleanCookies)
        {
            var cookiesDb = ResolveChromiumCookiesPath(profile.ProfileDataDirectory);
            if (cookiesDb is not null && !_bridge.IsFileLockedByAnotherProcess(cookiesDb))
            {
                try
                {
                    var (del, kept) = DeleteCookiesSelective(cookiesDb, "cookies", "host_key", keepDomains);
                    deletedCookies += del;
                    preservedCookies += kept;
                }
                catch (Exception ex)
                {
                    warnings.Add($"Не удалось очистить cookie {profile.BrowserName}: {ex.Message}");
                }
            }
        }

        if (selection.CleanSessions)
        {
            foreach (var file in EnumerateChromiumSessionFiles(profile.ProfileDataDirectory))
            {
                if (TryDeleteUnlockedFile(file, out var bytes))
                {
                    deletedSessions++;
                    freedSessions += bytes;
                }
            }
        }
    }

    private void CleanFirefoxProfile(
        DiscoveredBrowserProfile profile,
        BrowserCleanupSelection selection,
        IReadOnlyList<string> keepDomains,
        ref int deletedHistory,
        ref int deletedDownloads,
        ref int deletedCookies,
        ref int preservedCookies,
        ref int deletedSessions,
        ref long freedSessions,
        List<string> warnings)
    {
        if (selection.CleanHistory || selection.CleanDownloads)
        {
            var placesDb = Path.Combine(profile.ProfileDataDirectory, "places.sqlite");
            if (File.Exists(placesDb) && !_bridge.IsFileLockedByAnotherProcess(placesDb))
            {
                try
                {
                    using var conn = OpenWritableConnection(placesDb);
                    if (selection.CleanDownloads)
                    {
                        // В Firefox записи загрузок хранятся как аннотации с именем «downloads/...» в moz_annos
                        deletedDownloads += ExecuteNonQuerySafe(
                            conn,
                            """
                            DELETE FROM moz_annos
                            WHERE anno_attribute_id IN (
                                SELECT id FROM moz_anno_attributes WHERE name LIKE 'downloads/%'
                            );
                            """);
                    }

                    if (selection.CleanHistory)
                    {
                        deletedHistory += ExecuteDeleteIfTableExists(conn, "moz_historyvisits");
                        _ = ExecuteDeleteIfTableExists(conn, "moz_inputhistory");

                        // Удаляем из moz_places только те адреса, на которые НЕ ссылаются закладки moz_bookmarks!
                        _ = ExecuteNonQuerySafe(
                            conn,
                            """
                            DELETE FROM moz_places
                            WHERE id NOT IN (SELECT fk FROM moz_bookmarks WHERE fk IS NOT NULL);
                            UPDATE moz_places SET visit_count = 0, last_visit_date = NULL
                            WHERE id IN (SELECT fk FROM moz_bookmarks WHERE fk IS NOT NULL);
                            """);
                    }

                    TryVacuum(conn);
                }
                catch (Exception ex)
                {
                    warnings.Add($"Не удалось очистить историю Firefox: {ex.Message}");
                }
            }
        }

        if (selection.CleanCookies)
        {
            var cookiesDb = Path.Combine(profile.ProfileDataDirectory, "cookies.sqlite");
            if (File.Exists(cookiesDb) && !_bridge.IsFileLockedByAnotherProcess(cookiesDb))
            {
                try
                {
                    var (del, kept) = DeleteCookiesSelective(cookiesDb, "moz_cookies", "host", keepDomains);
                    deletedCookies += del;
                    preservedCookies += kept;
                }
                catch (Exception ex)
                {
                    warnings.Add($"Не удалось очистить cookie Firefox: {ex.Message}");
                }
            }
        }

        if (selection.CleanSessions)
        {
            foreach (var file in EnumerateFirefoxSessionFiles(profile.ProfileDataDirectory))
            {
                if (TryDeleteUnlockedFile(file, out var bytes))
                {
                    deletedSessions++;
                    freedSessions += bytes;
                }
            }
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Работа с SQLite без блокировки чужих файлов: при анализе читаем временную копию
    // ---------------------------------------------------------------------------------------------

    private static (int Urls, int Downloads) CountChromiumHistoryAndDownloads(string dbPath)
    {
        return WithReadOnlyTempCopy(dbPath, conn =>
        {
            var urls = ScalarCountIfTableExists(conn, "urls");
            var downloads = ScalarCountIfTableExists(conn, "downloads");
            return (urls, downloads);
        }, fallback: (0, 0));
    }

    private static (int Visits, int Downloads) CountFirefoxHistoryAndDownloads(string dbPath)
    {
        return WithReadOnlyTempCopy(dbPath, conn =>
        {
            var visits = ScalarCountIfTableExists(conn, "moz_historyvisits");
            var downloads = 0;
            if (TableExists(conn, "moz_annos") && TableExists(conn, "moz_anno_attributes"))
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    SELECT COUNT(*) FROM moz_annos
                    WHERE anno_attribute_id IN (SELECT id FROM moz_anno_attributes WHERE name LIKE 'downloads/%');
                    """;
                downloads = Convert.ToInt32(cmd.ExecuteScalar());
            }

            return (visits, downloads);
        }, fallback: (0, 0));
    }

    private static (int ToDelete, int ToKeep) CountCookies(
        string dbPath,
        string tableName,
        string hostColumn,
        IReadOnlyList<string> keepDomains)
    {
        return WithReadOnlyTempCopy(dbPath, conn =>
        {
            if (!TableExists(conn, tableName))
            {
                return (0, 0);
            }

            using var cmd = conn.CreateCommand();
            cmd.CommandText = $"SELECT {hostColumn} FROM {tableName};";
            using var reader = cmd.ExecuteReader();
            int del = 0, keep = 0;
            while (reader.Read())
            {
                var host = reader.IsDBNull(0) ? "" : reader.GetString(0);
                if (ShouldKeepCookieHost(host, keepDomains))
                {
                    keep++;
                }
                else
                {
                    del++;
                }
            }

            return (del, keep);
        }, fallback: (0, 0));
    }

    private static (int Deleted, int Preserved) DeleteCookiesSelective(
        string dbPath,
        string tableName,
        string hostColumn,
        IReadOnlyList<string> keepDomains)
    {
        using var conn = OpenWritableConnection(dbPath);
        if (!TableExists(conn, tableName))
        {
            return (0, 0);
        }

        if (keepDomains.Count == 0)
        {
            var all = ExecuteDeleteIfTableExists(conn, tableName);
            TryVacuum(conn);
            return (all, 0);
        }

        var rowIdsToDelete = new List<long>();
        var preserved = 0;

        using (var select = conn.CreateCommand())
        {
            select.CommandText = $"SELECT rowid, {hostColumn} FROM {tableName};";
            using var reader = select.ExecuteReader();
            while (reader.Read())
            {
                var rowId = reader.GetInt64(0);
                var host = reader.IsDBNull(1) ? "" : reader.GetString(1);
                if (ShouldKeepCookieHost(host, keepDomains))
                {
                    preserved++;
                }
                else
                {
                    rowIdsToDelete.Add(rowId);
                }
            }
        }

        if (rowIdsToDelete.Count > 0)
        {
            using var tx = conn.BeginTransaction();
            using var delCmd = conn.CreateCommand();
            delCmd.Transaction = tx;
            delCmd.CommandText = $"DELETE FROM {tableName} WHERE rowid = $id;";
            var param = delCmd.CreateParameter();
            param.ParameterName = "$id";
            delCmd.Parameters.Add(param);

            foreach (var id in rowIdsToDelete)
            {
                param.Value = id;
                delCmd.ExecuteNonQuery();
            }

            tx.Commit();
            TryVacuum(conn);
        }

        return (rowIdsToDelete.Count, preserved);
    }

    private static T WithReadOnlyTempCopy<T>(string dbPath, Func<SqliteConnection, T> reader, T fallback)
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "uw-bscan-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(tempDir);
            var copyPath = Path.Combine(tempDir, Path.GetFileName(dbPath));
            CopySharedRead(dbPath, copyPath);
            foreach (var sidecar in new[] { "-wal", "-shm" })
            {
                if (File.Exists(dbPath + sidecar))
                {
                    CopySharedRead(dbPath + sidecar, copyPath + sidecar);
                }
            }

            var cs = new SqliteConnectionStringBuilder
            {
                DataSource = copyPath,
                Mode = SqliteOpenMode.ReadOnly,
                Pooling = false
            }.ToString();

            using var conn = new SqliteConnection(cs);
            conn.Open();
            return reader(conn);
        }
        catch
        {
            return fallback;
        }
        finally
        {
            try
            {
                if (Directory.Exists(tempDir))
                {
                    Directory.Delete(tempDir, recursive: true);
                }
            }
            catch
            {
                // Временная папка уберётся при следующей очистке Temp
            }
        }
    }

    private static void CopySharedRead(string source, string destination)
    {
        using var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var output = new FileStream(destination, FileMode.Create, FileAccess.Write, FileShare.None);
        input.CopyTo(output);
    }

    private static SqliteConnection OpenWritableConnection(string dbPath)
    {
        var cs = new SqliteConnectionStringBuilder
        {
            DataSource = dbPath,
            Mode = SqliteOpenMode.ReadWrite,
            Pooling = false,
            DefaultTimeout = 3
        }.ToString();

        var conn = new SqliteConnection(cs);
        conn.Open();
        return conn;
    }

    private static bool TableExists(SqliteConnection conn, string tableName)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = $name LIMIT 1;";
        cmd.Parameters.AddWithValue("$name", tableName);
        return cmd.ExecuteScalar() is not null;
    }

    private static int ScalarCountIfTableExists(SqliteConnection conn, string tableName)
    {
        if (!TableExists(conn, tableName))
        {
            return 0;
        }

        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT COUNT(*) FROM \"{tableName}\";";
        return Convert.ToInt32(cmd.ExecuteScalar());
    }

    private static int ExecuteDeleteIfTableExists(SqliteConnection conn, string tableName)
    {
        if (!TableExists(conn, tableName))
        {
            return 0;
        }

        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"DELETE FROM \"{tableName}\";";
        return cmd.ExecuteNonQuery();
    }

    private static int ExecuteNonQuerySafe(SqliteConnection conn, string sql)
    {
        try
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = sql;
            return cmd.ExecuteNonQuery();
        }
        catch
        {
            return 0;
        }
    }

    private static void TryVacuum(SqliteConnection conn) => ExecuteNonQuerySafe(conn, "VACUUM;");

    // ---------------------------------------------------------------------------------------------
    // Вспомогательные методы по файлам сеансов и процессам
    // ---------------------------------------------------------------------------------------------

    private static string? ResolveChromiumCookiesPath(string profileDir)
    {
        var networkCookies = Path.Combine(profileDir, "Network", "Cookies");
        if (File.Exists(networkCookies))
        {
            return networkCookies;
        }

        var legacyCookies = Path.Combine(profileDir, "Cookies");
        return File.Exists(legacyCookies) ? legacyCookies : null;
    }

    private static List<string> EnumerateChromiumSessionFiles(string profileDir)
    {
        var list = new List<string>();
        foreach (var rel in ChromiumSessionRelativePaths)
        {
            var candidate = Path.Combine(profileDir, rel);
            if (File.Exists(candidate))
            {
                list.Add(candidate);
            }
        }

        var sessionsDir = Path.Combine(profileDir, "Sessions");
        if (Directory.Exists(sessionsDir))
        {
            try
            {
                foreach (var file in Directory.EnumerateFiles(sessionsDir))
                {
                    var name = Path.GetFileName(file);
                    if (name.StartsWith("Session_", StringComparison.OrdinalIgnoreCase) ||
                        name.StartsWith("Tabs_", StringComparison.OrdinalIgnoreCase))
                    {
                        list.Add(file);
                    }
                }
            }
            catch
            {
                // Папка недоступна
            }
        }

        return list;
    }

    private static List<string> EnumerateFirefoxSessionFiles(string profileDir)
    {
        var list = new List<string>();
        foreach (var rel in FirefoxSessionRelativePaths)
        {
            var candidate = Path.Combine(profileDir, rel);
            if (File.Exists(candidate))
            {
                list.Add(candidate);
            }
        }

        return list;
    }

    private bool TryDeleteUnlockedFile(string path, out long freedBytes)
    {
        freedBytes = 0;
        if (!File.Exists(path) || _bridge.IsFileLockedByAnotherProcess(path))
        {
            return false;
        }

        try
        {
            var len = SafeFileLength(path);
            File.Delete(path);
            freedBytes = len;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private bool IsProfileRunningNow(DiscoveredBrowserProfile profile)
    {
        if (profile.IsBrowserCurrentlyRunning)
        {
            return true;
        }

        var procNames = GuessProcessNames(profile.BrowserName);
        return procNames.Length > 0 && _bridge.IsProcessRunningByName(procNames);
    }

    private static string[] GuessProcessNames(string browserName) => browserName switch
    {
        "Google Chrome" => ["chrome"],
        "Microsoft Edge" => ["msedge"],
        "Яндекс Браузер" => ["browser"],
        "Brave Browser" or "Brave" => ["brave"],
        "Vivaldi" => ["vivaldi"],
        "Opera" or "Opera GX" => ["opera"],
        "Mozilla Firefox" => ["firefox"],
        "Chromium" => ["chromium"],
        _ => []
    };

    private static long SafeFileLength(string path)
    {
        try
        {
            var fi = new FileInfo(path);
            return fi.Exists ? fi.Length : 0;
        }
        catch
        {
            return 0;
        }
    }

    private static string NormalizeSingleDomain(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return "";
        }

        var s = raw.Trim().ToLowerInvariant();
        var schemeIdx = s.IndexOf("://", StringComparison.Ordinal);
        if (schemeIdx >= 0)
        {
            s = s[(schemeIdx + 3)..];
        }

        var slashIdx = s.IndexOfAny(['/', '?', '#']);
        if (slashIdx >= 0)
        {
            s = s[..slashIdx];
        }

        var colonIdx = s.IndexOf(':');
        if (colonIdx >= 0)
        {
            s = s[..colonIdx];
        }

        s = s.Trim().Trim('.');
        if (s.StartsWith("www.", StringComparison.Ordinal) && s.Length > 4 && s[4..].Contains('.'))
        {
            s = s[4..];
        }

        return s.Contains('.') && !s.Any(char.IsWhiteSpace) ? s : "";
    }
}
