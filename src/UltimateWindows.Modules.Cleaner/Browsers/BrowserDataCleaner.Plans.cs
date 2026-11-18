using Microsoft.Data.Sqlite;
using UltimateWindows.Modules.Cleaner.Models;

namespace UltimateWindows.Modules.Cleaner.Browsers;

public sealed partial class BrowserDataCleaner
{
    // Без копирования личных БД в Temp. Нет чтения открытых профилей и незавершённых журналов.
    public BrowserDataScanReport Scan(IReadOnlyList<DiscoveredBrowserProfile> profiles,
        IReadOnlyList<string>? keepCookieDomains = null, CancellationToken ct = default, BrowserCleanupSelection? selection = null)
    {
        var keep = NormalizeDomains(keepCookieDomains);
        var items = new List<BrowserDataItemSummary>();
        var warnings = new List<string>();
        foreach (var profile in profiles)
        {
            ct.ThrowIfCancellationRequested();
            var name = $"{profile.BrowserName} ({profile.ProfileName})";
            if (IsProfileRunningNow(profile)) { warnings.Add($"{name}: закройте браузер и повторите анализ."); continue; }
            var dir = profile.ProfileDataDirectory;
            var firefox = profile.IsGeckoFirefox;
            void Add(BrowserDataKind kind, string title, string detail, int count, int kept, IReadOnlyList<FileRevision> files)
            {
                if (count + kept > 0) items.Add(new(profile, kind, $"{name} — {title}", detail, count,
                    files.Sum(f => f.Length), kept, true) { Sources = files });
            }
            void ReadDatabase(string? path, Action<SqliteConnection, FileRevision> read)
            {
                if (path is null || !File.Exists(path)) return;
                try
                {
                    CheckJournal(path);
                    var stamp = FileRevision.Read(path, hash: true);
                    using var db = OpenDatabase(path, SqliteOpenMode.ReadOnly);
                    Execute(db, "BEGIN");
                    // Захватить снимок SQLite до проверки его соответствия файлу.
                    Execute(db, "SELECT count(*) FROM sqlite_master");
                    CheckJournal(path);
                    if (File.GetLastWriteTimeUtc(path) != stamp.WriteTimeUtc) throw new IOException("База изменилась во время анализа.");
                    read(db, stamp);
                }
                catch (Exception e) when (IsReadError(e)) { warnings.Add($"{name}, {Path.GetFileName(path)}: {e.Message}"); }
            }
            if (selection is null || selection.CleanHistory || selection.CleanDownloads)
                ReadDatabase(Path.Combine(dir, firefox ? "places.sqlite" : "History"), (db, stamp) =>
                {
                    if (selection?.CleanHistory != false)
                        Add(BrowserDataKind.History, "история посещений", "Закладки не входят в очистку.",
                            ScalarCountIfTableExists(db, firefox ? "moz_historyvisits" : "urls"), 0, [stamp]);
                    if (selection?.CleanDownloads != false)
                    {
                        int count = !firefox ? ScalarCountIfTableExists(db, "downloads") :
                            TableExists(db, "moz_annos") && TableExists(db, "moz_anno_attributes")
                                ? Count(db, "SELECT COUNT(*) FROM moz_annos WHERE " + DownloadAnnoFilter) : 0;
                        Add(BrowserDataKind.Downloads, "журнал загрузок", "Скачанные файлы останутся на диске.", count, 0, [stamp]);
                    }
                });
            if (selection?.CleanCookies != false)
                ReadDatabase(firefox ? Path.Combine(dir, "cookies.sqlite") : ResolveChromiumCookiesPath(dir), (db, stamp) =>
                {
                    var (remove, kept) = SelectCookies(db, firefox, keep);
                    Add(BrowserDataKind.Cookies, "cookie", "Выход с сайтов, кроме указанных исключений.", remove.Count, kept, [stamp]);
                });
            if (selection?.CleanSessions != false)
            {
                var files = new List<FileRevision>();
                foreach (var path in firefox ? EnumerateFirefoxSessionFiles(dir) : EnumerateChromiumSessionFiles(dir))
                {
                    ct.ThrowIfCancellationRequested();
                    try { files.Add(FileRevision.Read(path, hash: true)); }
                    catch (Exception e) when (IsReadError(e)) { warnings.Add($"{path}: {e.Message}"); }
                }
                Add(BrowserDataKind.Sessions, "вкладки сеанса", "Сохранённые окна и вкладки.", files.Count, 0, files);
            }
        }
        return new(DateTimeOffset.UtcNow, profiles, items.AsReadOnly(), warnings.AsReadOnly()) { KeepDomains = keep.ToArray() };
    }

    /// <summary>Применяются только адреса из плана; выбор профилей и файлов сеансов не повторяется.</summary>
    public BrowserDataCleanResult Clean(BrowserDataScanReport plan, CancellationToken ct = default)
    {
        var warnings = new List<string>();
        int history = 0, downloads = 0, cookies = 0, kept = 0, sessions = 0, running = 0;
        long sessionBytes = 0;
        foreach (var profile in plan.Items.Where(i => i.ItemCount > 0 && i.Sources.Count > 0).GroupBy(i => i.Profile))
        {
            ct.ThrowIfCancellationRequested();
            if (IsProfileRunningNow(profile.Key))
            {
                running++;
                warnings.Add($"{profile.Key.BrowserName} ({profile.Key.ProfileName}): браузер открыт, профиль пропущен.");
                continue;
            }
            foreach (var group in profile.Where(i => i.Kind != BrowserDataKind.Sessions).GroupBy(i => i.Sources.Single()))
            {
                var file = group.Key;
                var kinds = group.Select(i => i.Kind).ToHashSet();
                try
                {
                    ct.ThrowIfCancellationRequested();
                    CheckJournal(file.FullPath);
                    if (_bridge.IsFileLockedByAnotherProcess(file.FullPath) || FileRevision.Read(file.FullPath) != (file with { Sha256 = null }))
                        throw new IOException("База занята или изменилась после анализа.");
                    using var db = OpenDatabase(file.FullPath, SqliteOpenMode.ReadWrite);
                    // SQLite не допустит параллельную запись между проверкой ревизии и COMMIT.
                    Execute(db, "BEGIN IMMEDIATE");
                    CheckJournal(file.FullPath);
                    if (FileRevision.Read(file.FullPath, hash: true) != file) throw new IOException("База изменилась после анализа.");
                    var h = 0; var d = 0; var c = 0; var k = 0;
                    var firefox = profile.Key.IsGeckoFirefox;
                    if (kinds.Contains(BrowserDataKind.Downloads))
                    {
                        if (firefox) d = Execute(db, "DELETE FROM moz_annos WHERE " + DownloadAnnoFilter);
                        else
                        {
                            ExecuteDeleteIfTableExists(db, "downloads_url_chains");
                            ExecuteDeleteIfTableExists(db, "downloads_slices");
                            d = ExecuteDeleteIfTableExists(db, "downloads");
                        }
                    }
                    if (kinds.Contains(BrowserDataKind.History)) h = ClearHistory(db, firefox);
                    if (kinds.Contains(BrowserDataKind.Cookies)) (c, k) = ClearCookies(db, firefox, plan.KeepDomains);
                    ct.ThrowIfCancellationRequested();
                    Execute(db, "COMMIT");
                    history += h; downloads += d; cookies += c; kept += k;
                }
                catch (Exception e) when (IsReadError(e)) { warnings.Add($"{file.FullPath}: пропущено — {e.Message}"); }
            }
            foreach (var file in profile.Where(i => i.Kind == BrowserDataKind.Sessions).SelectMany(i => i.Sources))
            {
                ct.ThrowIfCancellationRequested();
                if (_bridge.TryRemovePreviewedFile(file) == FileRemovalOutcome.Removed) { sessions++; sessionBytes += file.Length; }
                else warnings.Add($"{file.FullPath}: файл изменился, исчез или занят.");
            }
        }
        return new(history, downloads, cookies, kept, sessions, sessionBytes, running, warnings,
            $"Браузеры: удалено записей истории — {history}, загрузок — {downloads}, cookie — {cookies}, файлов сеансов — {sessions}. " +
            $"Сохранено cookie по исключениям: {kept}. Предупреждений: {warnings.Count}.");
    }

    private const string DownloadAnnoFilter = "anno_attribute_id IN (SELECT id FROM moz_anno_attributes WHERE name LIKE 'downloads/%')";
    private static bool IsReadError(Exception ex) => ex is SqliteException or IOException or UnauthorizedAccessException;

    private static void CheckJournal(string path)
    {
        foreach (var suffix in new[] { "-wal", "-journal" })
            if (new FileInfo(path + suffix) is { Exists: true, Length: > 0 })
                throw new IOException("Непустой журнал SQLite. Завершите работу браузера и повторите анализ.");
    }

    private static SqliteConnection OpenDatabase(string path, SqliteOpenMode mode)
    {
        var db = new SqliteConnection(new SqliteConnectionStringBuilder
            { DataSource = path, Mode = mode, Pooling = false, DefaultTimeout = 2 }.ToString());
        try { db.Open(); return db; }
        catch { db.Dispose(); throw; }
    }

    private static int Execute(SqliteConnection db, string sql)
    {
        using var cmd = db.CreateCommand(); cmd.CommandText = sql; return cmd.ExecuteNonQuery();
    }

    private static int Count(SqliteConnection db, string sql)
    {
        using var cmd = db.CreateCommand(); cmd.CommandText = sql; return Convert.ToInt32(cmd.ExecuteScalar());
    }

    private static int ClearHistory(SqliteConnection db, bool firefox)
    {
        if (!firefox)
        {
            foreach (var table in new[] { "visits", "keyword_search_terms", "segment_usage", "segments", "content_annotations", "context_annotations" })
                ExecuteDeleteIfTableExists(db, table);
            return ExecuteDeleteIfTableExists(db, "urls");
        }
        // Не удалять адреса, на которые ссылаются закладки или аннотации (в т.ч. журнал загрузок).
        var retainAnnotations = TableExists(db, "moz_annos") ? " AND id NOT IN (SELECT place_id FROM moz_annos WHERE place_id IS NOT NULL)" : "";
        Execute(db, "DELETE FROM moz_places WHERE id IN (SELECT place_id FROM moz_historyvisits) AND id NOT IN (SELECT fk FROM moz_bookmarks WHERE fk IS NOT NULL)" + retainAnnotations);
        Execute(db, "UPDATE moz_places SET visit_count = 0, last_visit_date = NULL WHERE id IN (SELECT place_id FROM moz_historyvisits)");
        ExecuteDeleteIfTableExists(db, "moz_inputhistory");
        return ExecuteDeleteIfTableExists(db, "moz_historyvisits");
    }

    private static (List<long> Delete, int Keep) SelectCookies(SqliteConnection db, bool firefox, IReadOnlyList<string> keep)
    {
        var table = firefox ? "moz_cookies" : "cookies";
        var ids = new List<long>(); var kept = 0;
        if (!TableExists(db, table)) return (ids, 0);
        using var cmd = db.CreateCommand();
        cmd.CommandText = firefox ? "SELECT rowid, host FROM moz_cookies" : "SELECT rowid, host_key FROM cookies";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            if (ShouldKeepCookieHost(reader.IsDBNull(1) ? null : reader.GetString(1), keep)) kept++;
            else ids.Add(reader.GetInt64(0));
        }
        return (ids, kept);
    }

    private static (int Deleted, int Kept) ClearCookies(SqliteConnection db, bool firefox, IReadOnlyList<string> keep)
    {
        var (ids, kept) = SelectCookies(db, firefox, keep);
        using var cmd = db.CreateCommand();
        cmd.CommandText = firefox ? "DELETE FROM moz_cookies WHERE rowid = $id" : "DELETE FROM cookies WHERE rowid = $id";
        var id = cmd.Parameters.Add("$id", SqliteType.Integer);
        var deleted = 0;
        foreach (var row in ids) { id.Value = row; deleted += cmd.ExecuteNonQuery(); }
        return (deleted, kept);
    }
}
