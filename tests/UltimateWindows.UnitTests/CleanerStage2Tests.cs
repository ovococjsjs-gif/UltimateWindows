using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using UltimateWindows.Core.Guards;
using UltimateWindows.Modules.Cleaner.Browsers;
using UltimateWindows.Modules.Cleaner.Contracts;
using UltimateWindows.Modules.Cleaner.DiskMap;
using UltimateWindows.Modules.Cleaner.Models;
using UltimateWindows.Modules.Cleaner.Rules;
using UltimateWindows.Modules.Cleaner.Scanners;
using UltimateWindows.Modules.Cleaner.Services;
using UltimateWindows.Modules.Safety.Services;
using Xunit;

namespace UltimateWindows.UnitTests;

/// <summary>
/// Проверки этапа 2 «Очистка 2.0»:
/// 1) целостность встроенного каталога правил программ (9 JSON-файлов) и строгая валидация загрузчика;
/// 2) совместимость с форматом Winapp2.ini и защита от опасных внешних правил через CleanupPathGuard + BrowserVaultGuard;
/// 3) выборочная очистка браузеров (история, загрузки, cookie со списком «сохранить», сеансы) с побайтовой проверкой
///    неизменности всех файлов паролей, автозаполнения, ключей шифрования и закладок (Chrome + Firefox);
/// 4) разбор бинарных записей NTFS $MFT (Update Sequence Array, Win32 vs DOS 8.3, нерезидентный $DATA) и сборка дерева диска.
/// </summary>
public sealed class CleanerStage2Tests : IDisposable
{
    private readonly string _sandbox;

    public CleanerStage2Tests()
    {
        _sandbox = Path.Combine(Path.GetTempPath(), $"uw_stage2_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_sandbox);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_sandbox))
            {
                Directory.Delete(_sandbox, recursive: true);
            }
        }
        catch
        {
            // Transient OS file lock
        }
    }

    [Fact]
    public void BuiltInCleanupRuleCatalog_LoadsAllFiles_AndPassesValidation()
    {
        var catalog = CleanupRuleCatalogLoader.LoadBuiltIn();
        Assert.True(catalog.Rules.Count >= 80);
        Assert.NotNull(catalog.FindById("win.temp-user"));
        Assert.NotNull(catalog.FindById("browser.chrome.cache"));
        Assert.NotNull(catalog.FindById("game.steam.web-cache"));
        Assert.NotNull(catalog.FindById("app.embedded-browser-cache"));

        // Дубликат идентификатора или попытка чистить %LocalAppData% целиком отвергаются загрузчиком
        var badJson = """
            {
              "schemaVersion": 1,
              "rules": [
                {
                  "id": "bad.root",
                  "section": "Utilities",
                  "app": "Bad",
                  "title": "Bad",
                  "explanation": "Bad",
                  "kind": "Cache",
                  "default": false,
                  "files": [ { "path": "%LocalAppData%", "match": ["*"], "recurse": true } ]
                }
              ]
            }
            """;

        Assert.Throws<InvalidDataException>(() =>
            CleanupRuleCatalogLoader.Load([new CleanupRuleDocument("bad.json", badJson)]));
    }

    [Fact]
    public void RuleEngine_AndWinapp2Reader_FindAppLeftovers_WhileBlockingProtectedBrowserAndSystemFiles()
    {
        var env = CleanupEnvironment.ForRoot(_sandbox);
        var localApp = env.ResolveSingle("LocalAppData")!;
        var roamingApp = env.ResolveSingle("AppData")!;

        // 1. Встроенные правила: Discord (embedded Chromium cache) и NVIDIA (установщики)
        var discordCache = WriteBytes(Path.Combine(roamingApp, "discord", "Cache", "Cache_Data", "f_0001"), "DISCORD_CACHE_PAYLOAD"u8.ToArray());
        var discordTokenLike = WriteBytes(Path.Combine(roamingApp, "discord", "Local Storage", "leveldb", "0005.ldb"), "DISCORD_AUTH_STORAGE"u8.ToArray());

        // 2. Профиль Chrome с паролями + кэшем
        var chromeDefault = Path.Combine(localApp, "Google", "Chrome", "User Data", "Default");
        var loginData = WriteBytes(Path.Combine(chromeDefault, "Login Data"), "SECRET_PASSWORDS_SQLITE_BYTES"u8.ToArray());
        var chromeCache = WriteBytes(Path.Combine(chromeDefault, "Cache", "Cache_Data", "data_1"), "CHROME_DISPOSABLE_CACHE"u8.ToArray());
        var loginHashBefore = Sha256OfFile(loginData);

        // 3. Подключаем внешний Winapp2.ini: одно нормальное правило для 7-Zip/CustomApp и одно вредоносное, целящееся в весь профиль Chrome!
        var winapp2Ini = """
            [Custom Photo Tool Cache*]
            Section=Multimedia
            DetectFile=%LocalAppData%\CustomPhotoTool
            FileKey1=%LocalAppData%\CustomPhotoTool\Cache|*.*|RECURSE

            [Dangerous Malicious Browser Rule*]
            LangSecRef=3029
            DetectFile=%LocalAppData%\Google\Chrome\User Data
            FileKey1=%LocalAppData%\Google\Chrome\User Data\Default|*.*|RECURSE
            """;

        var parsedWinapp2 = Winapp2Reader.Parse(winapp2Ini, "custom-winapp2.ini");
        Assert.Equal(2, parsedWinapp2.Rules.Count);
        Assert.All(parsedWinapp2.Rules, r =>
        {
            Assert.False(r.SelectedByDefault);
            Assert.Equal(CleanupRuleOrigin.External, r.Origin);
        });

        var photoCache = WriteBytes(Path.Combine(localApp, "CustomPhotoTool", "Cache", "thumb01.bin"), "PHOTO_THUMB_CACHE"u8.ToArray());

        var bridge = new StubBridge();
        var engine = new CleanupRuleEngine(bridge, env);
        var rules = CleanupRuleCatalogLoader.LoadBuiltIn().Rules.Concat(parsedWinapp2.Rules).ToList();

        var scan = engine.Scan(rules);

        // Находки по Discord, Chrome и внешнему правилу Custom Photo Tool присутствуют
        Assert.Contains(scan.Findings, f => f.Application == "Discord" && f.HasAnythingToClean);
        Assert.Contains(scan.Findings, f => f.Rule.Id == "browser.chrome.cache" && f.HasAnythingToClean);
        var extPhotoFinding = Assert.Single(scan.Findings, f => f.Application == "Custom Photo Tool Cache");
        Assert.True(extPhotoFinding.HasAnythingToClean);

        // Вредоносное внешнее правило не смогло захватить Login Data — сработала защита BrowserVaultGuard / CleanupPathGuard!
        var maliciousFinding = Assert.Single(scan.Findings, f => f.Application == "Dangerous Malicious Browser Rule");
        Assert.DoesNotContain(maliciousFinding.Files, f => f.FullPath.EndsWith("Login Data", StringComparison.OrdinalIgnoreCase));
        Assert.True(maliciousFinding.BlockedByProtectionCount > 0);

        // Выполняем очистку всех найденных правил (включая внешние)
        var exec = engine.Execute(scan.Findings.Where(f => f.CanCleanNow).ToList());
        Assert.True(exec.DeletedFiles >= 3);

        Assert.False(File.Exists(discordCache));
        Assert.False(File.Exists(chromeCache));
        Assert.False(File.Exists(photoCache));

        // Защищённые данные целы и побайтово совпадают!
        Assert.True(File.Exists(discordTokenLike));
        Assert.True(File.Exists(loginData));
        Assert.Equal(loginHashBefore, Sha256OfFile(loginData));
    }

    [Fact]
    public async Task BrowserGranularCleaner_CleansHistoryDownloadsSessionsAndFilteredCookies_WhilePreservingPasswordsAutofillAndBookmarksByteForByte()
    {
        var localApp = Path.Combine(_sandbox, "LocalApp");
        var roamingApp = Path.Combine(_sandbox, "RoamingApp");
        var vaultDir = Path.Combine(_sandbox, "Vault");

        // --- Профиль Google Chrome ---
        var chromeProf = Path.Combine(localApp, "Google", "Chrome", "User Data", "Default");
        Directory.CreateDirectory(Path.Combine(chromeProf, "Network"));
        Directory.CreateDirectory(Path.Combine(chromeProf, "Sessions"));

        var chromeLocalState = WriteBytes(Path.Combine(localApp, "Google", "Chrome", "User Data", "Local State"), "OS_CRYPT_AES_KEY_V10"u8.ToArray());
        var chromeLoginData = WriteBytes(Path.Combine(chromeProf, "Login Data"), "CHROME_SAVED_PASSWORDS_DB_BYTES_12345"u8.ToArray());
        var chromeWebData = WriteBytes(Path.Combine(chromeProf, "Web Data"), "CHROME_AUTOFILL_CARDS_AND_FORMS_67890"u8.ToArray());
        var chromeBookmarks = WriteBytes(Path.Combine(chromeProf, "Bookmarks"), "{\"roots\":{\"bookmark_bar\":{\"children\":[{\"name\":\"Arena\"}]}}}"u8.ToArray());
        var chromeSession = WriteBytes(Path.Combine(chromeProf, "Sessions", "Session_133700"), "OPEN_TABS_BINARY"u8.ToArray());

        CreateChromiumHistoryDb(Path.Combine(chromeProf, "History"));
        CreateChromiumCookiesDb(Path.Combine(chromeProf, "Network", "Cookies"));

        // --- Профиль Mozilla Firefox (кэш в Local, данные в Roaming) ---
        var ffLocal = Path.Combine(localApp, "Mozilla", "Firefox", "Profiles", "abcd.default-release");
        var ffRoaming = Path.Combine(roamingApp, "Mozilla", "Firefox", "Profiles", "abcd.default-release");
        Directory.CreateDirectory(ffLocal);
        Directory.CreateDirectory(ffRoaming);

        var ffLogins = WriteBytes(Path.Combine(ffRoaming, "logins.json"), "{\"logins\":[{\"hostname\":\"https://bank.example\"}]}"u8.ToArray());
        var ffKey4 = WriteBytes(Path.Combine(ffRoaming, "key4.db"), "NSS_MASTER_KEY_SQLITE_BINARY"u8.ToArray());
        var ffFormHistory = WriteBytes(Path.Combine(ffRoaming, "formhistory.sqlite"), "FIREFOX_FORM_AUTOFILL_SQLITE"u8.ToArray());
        var ffSession = WriteBytes(Path.Combine(ffRoaming, "sessionstore.jsonlz4"), "MOZLZ40\0SESSION"u8.ToArray());

        var ffPlacesPath = Path.Combine(ffRoaming, "places.sqlite");
        CreateFirefoxPlacesDbWithBookmarks(ffPlacesPath);
        CreateFirefoxCookiesDb(Path.Combine(ffRoaming, "cookies.sqlite"));

        // Снимаем контрольные SHA-256 всех защищённых файлов ДО любых операций
        var protectedFiles = new[]
        {
            chromeLocalState, chromeLoginData, chromeWebData, chromeBookmarks,
            ffLogins, ffKey4, ffFormHistory
        };
        var hashesBefore = protectedFiles.ToDictionary(p => p, Sha256OfFile);

        var bridge = new StubBridge();
        var vault = new ZeroBloatVaultService(vaultDir);
        var browserScanner = new BrowserCacheScanner(bridge, localApp, roamingApp);
        var cleaner = new VaultSafeCleanerService(vault, bridge, browserScanner);

        // 1. Анализ с исключением cookie для github.com и google.com
        var keepDomains = new[] { "github.com", "https://mail.google.com/mail" }; // нормализуется в github.com и mail.google.com
        var scanDetails = await cleaner.ScanBrowserDataDetailsAsync(["github.com", "google.com"]);
        Assert.Equal(2, scanDetails.TotalHistoryItems); // 1 в Chrome + 1 визит в Firefox
        Assert.Equal(2, scanDetails.TotalDownloadItems); // 1 в Chrome + 1 в Firefox

        // 2. Выборочная очистка истории, загрузок, сеансов и cookie (с сохранением github.com и google.com)
        var cleanRes = await cleaner.CleanBrowserDataDetailsAsync(new BrowserCleanupSelection
        {
            CleanHistory = true,
            CleanDownloads = true,
            CleanCookies = true,
            CleanSessions = true,
            KeepCookieDomains = ["github.com", "google.com"]
        });

        Assert.True(cleanRes.DeletedHistoryRows >= 2);
        Assert.Equal(2, cleanRes.DeletedDownloadRows);
        Assert.Equal(4, cleanRes.PreservedCookieRows); // .github.com + accounts.google.com в Chrome и Firefox
        Assert.Equal(4, cleanRes.DeletedCookieRows);   // tracker.ads.example и shop.other.org в Chrome и Firefox
        Assert.Equal(2, cleanRes.DeletedSessionFiles);
        Assert.False(File.Exists(chromeSession));
        Assert.False(File.Exists(ffSession));

        // 3. Побайтовая проверка: ни один байт паролей, ключей, автозаполнения и закладок Chrome не изменился!
        foreach (var (filePath, expectedSha) in hashesBefore)
        {
            Assert.True(File.Exists(filePath), $"Защищённый файл исчез: {filePath}");
            Assert.Equal(expectedSha, Sha256OfFile(filePath));
        }

        // 4. В Firefox внутри places.sqlite закладки moz_bookmarks и их URL сохранились, а несвязанные визиты удалены
        using (var conn = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = ffPlacesPath, Pooling = false }.ToString()))
        {
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM moz_bookmarks;";
            Assert.Equal(1L, (long)cmd.ExecuteScalar()!);

            cmd.CommandText = "SELECT url FROM moz_places;";
            Assert.Equal("https://keep-bookmarked.example/", (string)cmd.ExecuteScalar()!);
        }
    }

    [Fact]
    public void NtfsMftParser_FixesSectorUsa_PrefersWin32OverDos83_AndBuildsAccurateDiskTree()
    {
        // Синтезируем настоящие 1024-байтные записи FILE с маркером целостности USA на границе секторов 510..511 и 1022..1023
        var rootRec = BuildSyntheticMftRecord(recordNumber: 5, parentRecord: 5, isDir: true, win32Name: "", dosName: null, dataSize: 0);
        var gamesDirRec = BuildSyntheticMftRecord(recordNumber: 40, parentRecord: 5, isDir: true, win32Name: "GamesLibrary", dosName: "GAMESL~1", dataSize: 0);
        var archiveFileRec = BuildSyntheticMftRecord(recordNumber: 41, parentRecord: 40, isDir: false, win32Name: "textures_pack.pak", dosName: "TEXTUR~1.PAK", dataSize: 10_485_760);
        var rootLogRec = BuildSyntheticMftRecord(recordNumber: 42, parentRecord: 5, isDir: false, win32Name: "boot_diag.log", dosName: null, dataSize: 4096);
        var systemMftMeta = BuildSyntheticMftRecord(recordNumber: 0, parentRecord: 5, isDir: false, win32Name: "$MFT", dosName: null, dataSize: 67_108_864);

        Assert.True(NtfsMftParser.TryParseRecord(rootRec, 5, out var eRoot));
        Assert.True(NtfsMftParser.TryParseRecord(gamesDirRec, 40, out var eGames));
        Assert.Equal("GamesLibrary", eGames.Name); // выбрано длинное имя Win32, а не короткое GAMESL~1!

        Assert.True(NtfsMftParser.TryParseRecord(archiveFileRec, 41, out var ePak));
        Assert.Equal("textures_pack.pak", ePak.Name);
        Assert.Equal(10_485_760L, ePak.SizeBytes);

        Assert.True(NtfsMftParser.TryParseRecord(rootLogRec, 42, out var eLog));
        // Системный метафайл $MFT (запись 0) отфильтровывается, чтобы не искажать пользовательскую карту
        Assert.False(NtfsMftParser.TryParseRecord(systemMftMeta, 0, out _));

        // Повреждённый маркер сектора USA должен отбраковываться
        var corrupted = BuildSyntheticMftRecord(recordNumber: 43, parentRecord: 5, isDir: false, win32Name: "bad.bin", dosName: null, dataSize: 100);
        corrupted[510] ^= 0xFF;
        Assert.False(NtfsMftParser.TryParseRecord(corrupted, 43, out _));

        var volRoot = Path.Combine(_sandbox, "FakeVolumeC");
        var report = NtfsMftParser.BuildReportFromEntries(
            [eRoot, eGames, ePak, eLog],
            volumeRoot: volRoot,
            targetFullPath: volRoot,
            methodDescription: "Тест прямого чтения $MFT",
            elapsed: TimeSpan.FromMilliseconds(12),
            topDirectoryLimit: 10,
            largestFilesLimit: 10);

        Assert.NotNull(report);
        Assert.Equal(10_485_760L + 4096L, report!.TotalScannedBytes);
        Assert.Equal(2, report.TotalFilesCount);
        Assert.Equal(1, report.TotalFoldersCount);
        Assert.Equal("GamesLibrary", report.TopDirectories[0].Name);
        Assert.Equal("textures_pack.pak", report.LargestFiles[0].Name);
    }

    // ---------------------------------------------------------------------------------------------
    // Вспомогательные генераторы тестовых SQLite-баз и MFT-записей
    // ---------------------------------------------------------------------------------------------

    private static void CreateChromiumHistoryDb(string path)
    {
        using var conn = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString());
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER);
            CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER);
            CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT, total_bytes INTEGER);
            CREATE TABLE downloads_url_chains (id INTEGER, chain_index INTEGER, url TEXT);
            INSERT INTO urls VALUES (1, 'https://example.org/news', 'News', 3);
            INSERT INTO visits VALUES (1, 1, 13370000000);
            INSERT INTO downloads VALUES (1, 'C:\Users\Tester\Downloads\installer.exe', 5242880);
            INSERT INTO downloads_url_chains VALUES (1, 0, 'https://example.org/installer.exe');
            """;
        cmd.ExecuteNonQuery();
    }

    private static void CreateChromiumCookiesDb(string path)
    {
        using var conn = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString());
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE cookies (host_key TEXT, name TEXT, encrypted_value BLOB);
            INSERT INTO cookies VALUES ('.github.com', 'user_session', X'0102');
            INSERT INTO cookies VALUES ('accounts.google.com', 'SID', X'0304');
            INSERT INTO cookies VALUES ('.tracker.ads.example', 'uid', X'0506');
            INSERT INTO cookies VALUES ('shop.other.org', 'cart', X'0708');
            """;
        cmd.ExecuteNonQuery();
    }

    private static void CreateFirefoxPlacesDbWithBookmarks(string path)
    {
        using var conn = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString());
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_date INTEGER);
            CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER);
            CREATE TABLE moz_bookmarks (id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER, title TEXT);
            CREATE TABLE moz_anno_attributes (id INTEGER PRIMARY KEY, name TEXT);
            CREATE TABLE moz_annos (id INTEGER PRIMARY KEY, place_id INTEGER, anno_attribute_id INTEGER, content TEXT);
            INSERT INTO moz_places VALUES (1, 'https://keep-bookmarked.example/', 'Saved Bookmark', 5, 1700000000);
            INSERT INTO moz_places VALUES (2, 'https://ephemeral-history.example/', 'Visited Once', 1, 1700000100);
            INSERT INTO moz_historyvisits VALUES (1, 2, 1700000100);
            INSERT INTO moz_bookmarks VALUES (1, 1, 1, 'Important');
            INSERT INTO moz_anno_attributes VALUES (1, 'downloads/destinationFileURI');
            INSERT INTO moz_annos VALUES (1, 2, 1, 'file:///C:/Users/Tester/Downloads/archive.zip');
            """;
        cmd.ExecuteNonQuery();
    }

    private static void CreateFirefoxCookiesDb(string path)
    {
        using var conn = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString());
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, host TEXT, name TEXT, value TEXT);
            INSERT INTO moz_cookies VALUES (1, '.github.com', 'logged_in', 'yes');
            INSERT INTO moz_cookies VALUES (2, 'accounts.google.com', 'LSID', 'abc');
            INSERT INTO moz_cookies VALUES (3, '.tracker.ads.example', 't', '1');
            INSERT INTO moz_cookies VALUES (4, 'shop.other.org', 's', '2');
            """;
        cmd.ExecuteNonQuery();
    }

    private static byte[] BuildSyntheticMftRecord(
        ulong recordNumber,
        ulong parentRecord,
        bool isDir,
        string win32Name,
        string? dosName,
        long dataSize)
    {
        var buf = new byte[1024];
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(0, 4), NtfsMftParser.FileSignature);
        ushort usaOffset = 48;
        ushort usaCount = 3; // check word + 2 сектора по 512 Б
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(4, 2), usaOffset);
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(6, 2), usaCount);

        ushort attrOffset = 56;
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(20, 2), attrOffset);
        ushort flags = (ushort)(NtfsMftParser.FlagInUse | (isDir ? NtfsMftParser.FlagIsDirectory : 0));
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(22, 2), flags);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(44, 4), (uint)recordNumber);

        int pos = attrOffset;

        // Опционально сначала пишем короткое имя DOS 8.3, чтобы убедиться, что парсер предпочтёт длинное Win32
        if (!string.IsNullOrEmpty(dosName))
        {
            pos += WriteFileNameAttr(buf.AsSpan(pos), parentRecord, dosName, NtfsMftParser.NamespaceDos, dataSize);
        }

        if (!string.IsNullOrEmpty(win32Name))
        {
            pos += WriteFileNameAttr(buf.AsSpan(pos), parentRecord, win32Name, NtfsMftParser.NamespaceWin32, dataSize);
        }

        if (!isDir)
        {
            // Нерезидентный поток $DATA (64 байта заголовка, LowestVcn = 0, RealSize по смещению +48)
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(pos, 4), NtfsMftParser.AttrData);
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(pos + 4, 4), 64);
            buf[pos + 8] = 1; // non-resident
            buf[pos + 9] = 0; // unnamed primary stream
            BinaryPrimitives.WriteInt64LittleEndian(buf.AsSpan(pos + 16, 8), 0L); // LowestVcn
            BinaryPrimitives.WriteInt64LittleEndian(buf.AsSpan(pos + 48, 8), dataSize); // RealSize
            pos += 64;
        }

        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(pos, 4), NtfsMftParser.AttrEnd);
        pos += 8;
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(24, 4), (uint)pos);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(28, 4), 1024);

        // Запечатываем концы секторов (510..511 и 1022..1023) через Update Sequence Array
        ushort checkWord = 0xABCD;
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(usaOffset, 2), checkWord);
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(usaOffset + 2, 2), BinaryPrimitives.ReadUInt16LittleEndian(buf.AsSpan(510, 2)));
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(usaOffset + 4, 2), BinaryPrimitives.ReadUInt16LittleEndian(buf.AsSpan(1022, 2)));
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(510, 2), checkWord);
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(1022, 2), checkWord);

        return buf;
    }

    private static int WriteFileNameAttr(Span<byte> dest, ulong parentRef, string name, byte nameNamespace, long size)
    {
        var nameBytes = Encoding.Unicode.GetBytes(name);
        int valLen = 66 + nameBytes.Length;
        int attrLen = (24 + valLen + 7) & ~7;

        BinaryPrimitives.WriteUInt32LittleEndian(dest[..4], NtfsMftParser.AttrFileName);
        BinaryPrimitives.WriteUInt32LittleEndian(dest.Slice(4, 4), (uint)attrLen);
        dest[8] = 0; // resident
        dest[9] = 0;
        BinaryPrimitives.WriteUInt32LittleEndian(dest.Slice(16, 4), (uint)valLen);
        BinaryPrimitives.WriteUInt16LittleEndian(dest.Slice(20, 2), 24);

        var val = dest.Slice(24, valLen);
        BinaryPrimitives.WriteUInt64LittleEndian(val[..8], parentRef & 0x0000FFFFFFFFFFFFUL);
        BinaryPrimitives.WriteInt64LittleEndian(val.Slice(16, 8), DateTime.UtcNow.ToFileTimeUtc());
        BinaryPrimitives.WriteInt64LittleEndian(val.Slice(48, 8), size);
        val[64] = (byte)name.Length;
        val[65] = nameNamespace;
        nameBytes.CopyTo(val[66..]);
        return attrLen;
    }

    private static string WriteBytes(string fullPath, byte[] bytes)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        File.WriteAllBytes(fullPath, bytes);
        return fullPath;
    }

    private static string Sha256OfFile(string fullPath)
    {
        var hash = SHA256.HashData(File.ReadAllBytes(fullPath));
        return Convert.ToHexString(hash);
    }

    private sealed class StubBridge : DefaultCleanerPlatformBridge
    {
        public override bool IsProcessRunningByName(ReadOnlySpan<string> processNamesWithoutExtension) => false;
        public override bool IsFileLockedByAnotherProcess(string filePath) => false;
    }
}
