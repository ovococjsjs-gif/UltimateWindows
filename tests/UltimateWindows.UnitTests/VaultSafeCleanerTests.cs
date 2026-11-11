using System.Text;
using UltimateWindows.Core.Contracts;
using UltimateWindows.Core.Enums;
using UltimateWindows.Core.Models;
using UltimateWindows.Modules.Cleaner.Contracts;
using UltimateWindows.Modules.Cleaner.DiskMap;
using UltimateWindows.Modules.Cleaner.Models;
using UltimateWindows.Modules.Cleaner.Scanners;
using UltimateWindows.Modules.Cleaner.Services;
using UltimateWindows.Modules.Cleaner.Utilities;
using UltimateWindows.Modules.Safety.Services;
using Xunit;

namespace UltimateWindows.UnitTests;

public sealed class VaultSafeCleanerTests : IDisposable
{
    private readonly string _sandboxDir;

    public VaultSafeCleanerTests()
    {
        _sandboxDir = Path.Combine(Path.GetTempPath(), $"uw_cleaner_tests_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_sandboxDir);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_sandboxDir))
            {
                Directory.Delete(_sandboxDir, recursive: true);
            }
        }
        catch
        {
            // Ignore transient AV/OS file lock during teardown
        }
    }

    [Fact]
    public async Task MultiBrowserCleanup_DeletesCaches_WhileStrictlyPreservingPasswordsAndAutofill()
    {
        var localApp = Path.Combine(_sandboxDir, "LocalAppData");
        var roamingApp = Path.Combine(_sandboxDir, "RoamingAppData");
        var vaultDir = Path.Combine(_sandboxDir, "Vault");

        // 1. Создаем структуру Google Chrome (Default + Profile 1) и Яндекс Браузера
        var chromeDefault = Path.Combine(localApp, "Google", "Chrome", "User Data", "Default");
        var chromeProfile1 = Path.Combine(localApp, "Google", "Chrome", "User Data", "Profile 1");
        var chromeLocalState = Path.Combine(localApp, "Google", "Chrome", "User Data", "Local State");
        var yandexDefault = Path.Combine(localApp, "Yandex", "YandexBrowser", "User Data", "Default");

        WriteFakeFile(chromeLocalState, "os_crypt_master_key_secret");
        var chromePasswords = WriteFakeFile(Path.Combine(chromeDefault, "Login Data"), "SQLITE_PASSWORDS_DEFAULT");
        var chromeAutofill = WriteFakeFile(Path.Combine(chromeDefault, "Web Data"), "SQLITE_AUTOFILL_FORMS");
        var chromeCookies = WriteFakeFile(Path.Combine(chromeDefault, "Network", "Cookies"), "ENCRYPTED_SESSION_COOKIES");
        var profile1Passwords = WriteFakeFile(Path.Combine(chromeProfile1, "Login Data"), "SQLITE_PASSWORDS_PROFILE1");
        var yandexVault = WriteFakeFile(Path.Combine(yandexDefault, "Ya Passman Data"), "YANDEX_PASSWORD_VAULT");

        // Создаем удаляемый кэш в Chrome и Яндекс
        var chromeCache1 = WriteFakeFile(Path.Combine(chromeDefault, "Cache", "Cache_Data", "f_0001a"), new string('C', 4096));
        var chromeGpuCache = WriteFakeFile(Path.Combine(chromeProfile1, "GPUCache", "data_1"), new string('G', 2048));
        var yandexCodeCache = WriteFakeFile(Path.Combine(yandexDefault, "Code Cache", "js", "script_01"), new string('J', 1024));

        // 2. Создаем профиль Mozilla Firefox (Roaming: пароли/формы, Local: cache2)
        var ffRoamingRoot = Path.Combine(roamingApp, "Mozilla", "Firefox");
        WriteFakeFile(
            Path.Combine(ffRoamingRoot, "profiles.ini"),
            "[Profile0]\nName=default-release\nIsRelative=1\nPath=Profiles/abcd1234.default-release\n");

        var ffRoamingProf = Path.Combine(ffRoamingRoot, "Profiles", "abcd1234.default-release");
        var ffLocalProf = Path.Combine(localApp, "Mozilla", "Firefox", "Profiles", "abcd1234.default-release");

        var ffLogins = WriteFakeFile(Path.Combine(ffRoamingProf, "logins.json"), "{\"logins\":[{\"hostname\":\"https://bank.example\"}]}");
        var ffKey4 = WriteFakeFile(Path.Combine(ffRoamingProf, "key4.db"), "NSS_MASTER_KEY_DB");
        var ffForms = WriteFakeFile(Path.Combine(ffRoamingProf, "formhistory.sqlite"), "SAVED_FORM_INPUTS");
        var ffCacheEntry = WriteFakeFile(Path.Combine(ffLocalProf, "cache2", "entries", "9A8B7C6D"), new string('F', 3072));

        var bridge = new FakeCleanerBridge();
        var browserScanner = new BrowserCacheScanner(bridge, localApp, roamingApp);
        var emptySysPaths = CreateEmptySystemPaths();
        var sysScanner = new SystemJunkScanner(emptySysPaths);
        var vault = new ZeroBloatVaultService(vaultDir);
        var service = new VaultSafeCleanerService(vault, bridge, browserScanner, sysScanner);

        var options = new CleanupOptions
        {
            PreservePasswordsAndAutofill = true,
            CleanBrowserCaches = true,
            CleanSystemTempAndShaders = false,
            CleanRegistryOrphans = false
        };

        var scan = await service.ScanAsync(options);
        Assert.Equal(4, scan.TotalFilesCount);
        Assert.Equal(4096 + 2048 + 1024 + 3072, scan.TotalReclaimableBytes);

        var result = await service.ExecuteCleanupAsync(scan, options);
        Assert.Equal(4, result.DeletedFilesCount);

        // Кэш удален
        Assert.False(File.Exists(chromeCache1));
        Assert.False(File.Exists(chromeGpuCache));
        Assert.False(File.Exists(yandexCodeCache));
        Assert.False(File.Exists(ffCacheEntry));

        // Пароли, ключи шифрования, формы автозаполнения и куки на 100% целы!
        Assert.Equal("os_crypt_master_key_secret", File.ReadAllText(chromeLocalState));
        Assert.Equal("SQLITE_PASSWORDS_DEFAULT", File.ReadAllText(chromePasswords));
        Assert.Equal("SQLITE_AUTOFILL_FORMS", File.ReadAllText(chromeAutofill));
        Assert.Equal("ENCRYPTED_SESSION_COOKIES", File.ReadAllText(chromeCookies));
        Assert.Equal("SQLITE_PASSWORDS_PROFILE1", File.ReadAllText(profile1Passwords));
        Assert.Equal("YANDEX_PASSWORD_VAULT", File.ReadAllText(yandexVault));
        Assert.Contains("bank.example", File.ReadAllText(ffLogins));
        Assert.Equal("NSS_MASTER_KEY_DB", File.ReadAllText(ffKey4));
        Assert.Equal("SAVED_FORM_INPUTS", File.ReadAllText(ffForms));
    }

    [Fact]
    public async Task SystemTempCleanup_Respects24HourAgeGuard_AndSkipsLockedFilesGracefully()
    {
        var tempRoot = Path.Combine(_sandboxDir, "UserTemp");
        var localApp = Path.Combine(_sandboxDir, "SysLocal");
        Directory.CreateDirectory(tempRoot);

        // Свежий файл установщика (15 минут назад) — НЕ должен удаляться!
        var freshInstallerFile = WriteFakeFile(Path.Combine(tempRoot, "active_setup_session.tmp"), "ACTIVE_PAYLOAD");
        File.SetLastWriteTimeUtc(freshInstallerFile, DateTime.UtcNow.AddMinutes(-15));

        // Старый временный файл (48 часов назад) — ДОЛЖЕН быть удален
        var staleTempFile = WriteFakeFile(Path.Combine(tempRoot, "old_crash_log.tmp"), new string('T', 2000));
        File.SetLastWriteTimeUtc(staleTempFile, DateTime.UtcNow.AddHours(-48));

        // Заблокированный открытой программой старый файл — должен быть аккуратно пропущен без сбоя
        var lockedOldFile = WriteFakeFile(Path.Combine(tempRoot, "locked_by_editor.tmp"), new string('L', 1500));
        File.SetLastWriteTimeUtc(lockedOldFile, DateTime.UtcNow.AddHours(-36));

        // Старый кэш шейдеров NVIDIA DXCache (6 часов назад)
        var oldShader = WriteFakeFile(Path.Combine(localApp, "NVIDIA", "DXCache", "shader_bin_01.bin"), new string('S', 5000));
        File.SetLastWriteTimeUtc(oldShader, DateTime.UtcNow.AddHours(-6));

        var bridge = new FakeCleanerBridge();
        bridge.LockedFiles.Add(lockedOldFile);

        var paths = new SystemJunkPathsConfig(
            UserTempDirectory: tempRoot,
            SystemTempDirectory: tempRoot,
            LocalAppDataDirectory: localApp,
            RoamingAppDataDirectory: Path.Combine(_sandboxDir, "EmptyRoam"),
            CommonAppDataDirectory: Path.Combine(_sandboxDir, "EmptyProgData"),
            WindowsDirectory: Path.Combine(_sandboxDir, "EmptyWin"));

        var vault = new ZeroBloatVaultService(Path.Combine(_sandboxDir, "VaultTemp"));
        var service = new VaultSafeCleanerService(
            vault,
            bridge,
            new BrowserCacheScanner(bridge, Path.Combine(_sandboxDir, "NoBrowsers"), Path.Combine(_sandboxDir, "NoRoam")),
            new SystemJunkScanner(paths));

        var options = new CleanupOptions
        {
            CleanBrowserCaches = false,
            CleanSystemTempAndShaders = true,
            CleanRegistryOrphans = false,
            MinimumTempFileAgeHours = 24
        };

        var scan = await service.ScanAsync(options);
        // В кандидаты попадают только staleTempFile, lockedOldFile и oldShader (но НЕ freshInstallerFile!)
        Assert.DoesNotContain(scan.CandidateFiles, c => c.FullPath == freshInstallerFile);
        Assert.Equal(3, scan.TotalFilesCount);

        var exec = await service.ExecuteCleanupAsync(scan, options);
        Assert.Equal(2, exec.DeletedFilesCount);
        Assert.Equal(1, exec.SkippedLockedFilesCount);

        Assert.True(File.Exists(freshInstallerFile));
        Assert.True(File.Exists(lockedOldFile));
        Assert.False(File.Exists(staleTempFile));
        Assert.False(File.Exists(oldShader));
    }

    [Fact]
    public void CommandLinePathExtractor_ExtractsDeadLocalApps_AndBlocksSystemHostsUncAndComClsid()
    {
        Assert.Equal(
            @"C:\Games\SpaceGame\Launcher.exe",
            CommandLinePathExtractor.TryExtractLocalExecutablePath("\"C:\\Games\\SpaceGame\\Launcher.exe\" --silent --autostart"));

        Assert.Equal(
            @"D:\Tools\OldHelper\helper.exe",
            CommandLinePathExtractor.TryExtractLocalExecutablePath(@"D:\Tools\OldHelper\helper.exe /background"));

        Assert.Equal(
            @"C:\RemovedApp\client.exe",
            CommandLinePathExtractor.TryExtractFromMuiCacheValueName(@"C:\RemovedApp\client.exe.FriendlyAppName"));

        Assert.Equal(
            @"C:\OldServer\node_agent.exe",
            CommandLinePathExtractor.TryExtractFromFirewallRule(@"v2.31|Action=Allow|Active=TRUE|Dir=In|App=C:\OldServer\node_agent.exe|Name=Agent|"));

        // Системные хосты, сетевые диски и UWP-правила никогда не признаются сиротами
        Assert.Null(CommandLinePathExtractor.TryExtractLocalExecutablePath(@"msiexec.exe /X{12345678-1234-1234-1234-1234567890AB}"));
        Assert.Null(CommandLinePathExtractor.TryExtractLocalExecutablePath(@"C:\Windows\System32\rundll32.exe shell32.dll,Control_RunDLL"));
        Assert.Null(CommandLinePathExtractor.TryExtractLocalExecutablePath(@"\\CorporateNas\Tools\deploy.exe"));
        Assert.Null(CommandLinePathExtractor.TryExtractFromFirewallRule(@"v2.31|Action=Allow|Active=TRUE|App=C:\App\uwp.exe|AppPkgId=S-1-15-2-123|"));

        // Запрет на чистку COM/CLSID/TypeLib/WinSxS
        Assert.True(CommandLinePathExtractor.IsForbiddenComOrSystemRegistryKey(@"HKCR\CLSID\{00021401-0000-0000-C000-000000000046}"));
        Assert.True(CommandLinePathExtractor.IsForbiddenComOrSystemRegistryKey(@"HKCU\Software\Classes\CLSID\{ABCD}"));
        Assert.True(CommandLinePathExtractor.IsForbiddenComOrSystemRegistryKey(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide\Winners"));
        Assert.False(CommandLinePathExtractor.IsForbiddenComOrSystemRegistryKey(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"));
    }

    [Fact]
    public async Task VerifiedRegistryOrphanCleanup_RecordsCompactRollbackTransactionInVault()
    {
        var bridge = new FakeCleanerBridge();
        bridge.RegistryOrphans.Add(new RegistryOrphanCandidate(
            Kind: RegistryOrphanKind.OrphanedStartupRun,
            HiveName: "HKCU",
            SubKeyPath: @"Software\Microsoft\Windows\CurrentVersion\Run",
            ValueName: "OldMessenger",
            MissingReferencedFilePath: @"C:\Program Files\OldMessenger\app.exe",
            PreviousValueSerialized: "\"C:\\Program Files\\OldMessenger\\app.exe\" --tray",
            RegistryValueKindCode: 1,
            FriendlyReason: "Запись автозагрузки указывает на удаленную программу"));

        var applier = new RecordingStateApplier();
        var vault = new ZeroBloatVaultService(Path.Combine(_sandboxDir, "VaultReg"), stateApplier: applier);
        var service = new VaultSafeCleanerService(
            vault,
            bridge,
            new BrowserCacheScanner(bridge, Path.Combine(_sandboxDir, "NoB1"), Path.Combine(_sandboxDir, "NoB2")),
            new SystemJunkScanner(CreateEmptySystemPaths()));

        var options = new CleanupOptions
        {
            CleanBrowserCaches = false,
            CleanSystemTempAndShaders = false,
            CleanRegistryOrphans = true
        };

        var scan = await service.ScanAsync(options);
        Assert.Equal(1, scan.TotalRegistryOrphansCount);

        var exec = await service.ExecuteCleanupAsync(scan, options);
        Assert.Equal(1, exec.CleanedRegistryOrphansCount);
        Assert.NotNull(exec.RollbackSessionId);

        // Проверяем, что откат в 1 клик восстанавливает удаленную запись реестра из Zero-Bloat Vault!
        await vault.RollbackTransactionAsync(exec.RollbackSessionId!.Value);
        Assert.Single(applier.RestoredDeltas);
        Assert.Equal(StateTargetKind.RegistryValue, applier.RestoredDeltas[0].TargetKind);
        Assert.Contains("OldMessenger", applier.RestoredDeltas[0].PreviousStateJson);
    }

    [Fact]
    public async Task FastDiskSpaceAnalyzer_RanksTopDirectoriesAndLargestFilesAccurately()
    {
        var root = Path.Combine(_sandboxDir, "DiskMapRoot");
        WriteFakeFile(Path.Combine(root, "Games", "Starfield", "archive01.ba2"), new string('A', 20_000));
        WriteFakeFile(Path.Combine(root, "Games", "Starfield", "archive02.ba2"), new string('B', 10_000));
        WriteFakeFile(Path.Combine(root, "Videos", "capture.mp4"), new string('V', 15_000));
        WriteFakeFile(Path.Combine(root, "Notes", "todo.txt"), new string('N', 500));

        var analyzer = new FastDiskSpaceAnalyzer();
        var report = await analyzer.AnalyzeDirectoryOrDriveAsync(root, topDirectoryLimit: 5, largestFilesLimit: 3);

        Assert.Equal(45_500, report.TotalScannedBytes);
        Assert.Equal(4, report.TotalFilesCount);
        Assert.Equal("Games", report.TopDirectories[0].Name);
        Assert.Equal(30_000, report.TopDirectories[0].SizeBytes);
        Assert.Equal("Videos", report.TopDirectories[1].Name);
        Assert.Equal(3, report.LargestFiles.Count);
        Assert.Equal("archive01.ba2", report.LargestFiles[0].Name);
        Assert.Equal("capture.mp4", report.LargestFiles[1].Name);

        // v2.0 WizTree hierarchical tree + extension stats verification
        Assert.NotEmpty(report.SafeTreeNodes);
        var rootNode = report.SafeTreeNodes[0];
        Assert.True(rootNode.IsDirectory);
        Assert.Equal("Games", rootNode.Children[0].Name);
        Assert.Contains(report.SafeExtensionStats, e => e.Extension == ".ba2" && e.SizeBytes == 30_000);
        Assert.Contains(report.SafeExtensionStats, e => e.Extension == ".mp4" && e.SizeBytes == 15_000);
    }

    [Fact]
    public async Task DuplicateFileFinder_GroupsIdenticalSha256Files_AndPreservesOldestAsSuggestedOriginal()
    {
        var dupRoot = Path.Combine(_sandboxDir, "DupRoot");
        var payloadA = new string('X', 20_480);
        var payloadB = new string('Y', 20_480);

        var orig = WriteFakeFile(Path.Combine(dupRoot, "Docs", "report_final.pdf"), payloadA);
        File.SetLastWriteTimeUtc(orig, DateTime.UtcNow.AddDays(-10));

        var copy1 = WriteFakeFile(Path.Combine(dupRoot, "Downloads", "report_final (1).pdf"), payloadA);
        File.SetLastWriteTimeUtc(copy1, DateTime.UtcNow.AddDays(-2));

        var copy2 = WriteFakeFile(Path.Combine(dupRoot, "Desktop", "copy_report.pdf"), payloadA);
        File.SetLastWriteTimeUtc(copy2, DateTime.UtcNow.AddHours(-3));

        // Same size (20_480 bytes), different content -> must NOT be grouped as duplicate!
        WriteFakeFile(Path.Combine(dupRoot, "Other", "different_file.bin"), payloadB);

        var finder = new DuplicateFileFinder();
        var dupReport = await finder.FindExactDuplicatesAsync(dupRoot, minFileSizeBytes: 4096);

        var grp = Assert.Single(dupReport.Groups);
        Assert.Equal(3, grp.Entries.Count);
        Assert.Equal(40_960, dupReport.TotalReclaimableBytes);
        Assert.Equal(1, grp.Entries.Count(e => e.IsOriginalKeepSuggested));
        Assert.Equal(orig, grp.Entries.Single(e => e.IsOriginalKeepSuggested).FullPath);
    }

    private SystemJunkPathsConfig CreateEmptySystemPaths() => new(
        UserTempDirectory: Path.Combine(_sandboxDir, "EmptyT1"),
        SystemTempDirectory: Path.Combine(_sandboxDir, "EmptyT2"),
        LocalAppDataDirectory: Path.Combine(_sandboxDir, "EmptyL"),
        RoamingAppDataDirectory: Path.Combine(_sandboxDir, "EmptyR"),
        CommonAppDataDirectory: Path.Combine(_sandboxDir, "EmptyC"),
        WindowsDirectory: Path.Combine(_sandboxDir, "EmptyW"));

    private static readonly Encoding Utf8NoBom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

    private static string WriteFakeFile(string fullPath, string content)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        File.WriteAllText(fullPath, content, Utf8NoBom);
        return fullPath;
    }

    private sealed class FakeCleanerBridge : DefaultCleanerPlatformBridge
    {
        public HashSet<string> LockedFiles { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<RegistryOrphanCandidate> RegistryOrphans { get; } = [];

        public override bool IsProcessRunningByName(ReadOnlySpan<string> processNamesWithoutExtension) => false;

        public override bool IsFileLockedByAnotherProcess(string filePath) => LockedFiles.Contains(filePath);

        public override Task<IReadOnlyList<RegistryOrphanCandidate>> ScanVerifiedRegistryOrphansAsync(CancellationToken ct = default)
            => Task.FromResult<IReadOnlyList<RegistryOrphanCandidate>>(RegistryOrphans);

        public override Task<int> DeleteVerifiedRegistryOrphansAsync(IReadOnlyList<RegistryOrphanCandidate> candidates, CancellationToken ct = default)
            => Task.FromResult(candidates.Count);
    }

    private sealed class RecordingStateApplier : ISystemStateApplier
    {
        public List<StateDeltaRecord> RestoredDeltas { get; } = [];

        public Task ApplyRollbackDeltaAsync(
            StateDeltaRecord delta,
            Func<string, CancellationToken, Task<byte[]>> restoreBlobBytesAsync,
            CancellationToken ct = default)
        {
            RestoredDeltas.Add(delta);
            return Task.CompletedTask;
        }
    }
}
