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
    internal IReadOnlyList<FileRevision> Sources { get; init; } = [];
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
    internal IReadOnlyList<string> KeepDomains { get; init; } = [];
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
public sealed partial class BrowserDataCleaner
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
