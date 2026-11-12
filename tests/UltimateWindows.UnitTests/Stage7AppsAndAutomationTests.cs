using System.IO.Compression;
using UltimateWindows.Core.Contracts;
using UltimateWindows.Modules.Apps.Catalog;
using UltimateWindows.Modules.Apps.Contracts;
using UltimateWindows.Modules.Apps.Models;
using UltimateWindows.Modules.Apps.Readiness;
using UltimateWindows.Modules.Apps.Services;
using UltimateWindows.Modules.Apps.Support;
using UltimateWindows.Modules.Apps.Uninstaller;
using UltimateWindows.Modules.Apps.Winget;
using UltimateWindows.Modules.Cleaner.Services;
using UltimateWindows.Modules.Drivers.Orchestration;
using UltimateWindows.Modules.Drivers.Services;
using UltimateWindows.Modules.Hardware.Services;
using UltimateWindows.Modules.Optimizer.Models;
using UltimateWindows.Modules.Optimizer.Services;
using UltimateWindows.Modules.Repair.Services;
using UltimateWindows.Modules.Safety.Services;
using UltimateWindows.Modules.Security.Services;
using Xunit;

namespace UltimateWindows.UnitTests;

public sealed class Stage7AppsAndAutomationTests : IDisposable
{
    private readonly string _tempDir;
    private readonly ZeroBloatVaultService _vault;

    public Stage7AppsAndAutomationTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "UW_Stage7Tests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _vault = new ZeroBloatVaultService(_tempDir);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDir))
            {
                Directory.Delete(_tempDir, recursive: true);
            }
        }
        catch
        {
            // Ignore cleanup lock
        }
    }

    [Fact]
    public void WingetOutputParser_ParsesEnglishUpgradeTableWithSpinnerAndPinnedSection()
    {
        var raw =
            "   -\r   \\\r   |\r   ████████▒▒▒▒▒▒\r" +
            "Name                           Id                           Version       Available     Source\n" +
            "----------------------------------------------------------------------------------------------\n" +
            "7-Zip 23.01 (x64)              7zip.7zip                    23.01         24.08         winget\n" +
            "VLC media player               VideoLAN.VLC                 3.0.20        3.0.21        winget\n" +
            "Notepad++ (64-bit x64)         Notepad++.Notepad++          < 8.6.0       8.7.1         winget\n" +
            "3 upgrades available.\n\n" +
            "The following packages have pins that prevent upgrade:\n" +
            "Name                           Id                           Version       Available     Source\n" +
            "----------------------------------------------------------------------------------------------\n" +
            "Git                            Git.Git                      2.45.0        2.47.1        winget\n";

        var items = WingetOutputParser.ParseUpgradeTable(raw);
        Assert.Equal(4, items.Count);

        Assert.Equal("7zip.7zip", items[0].PackageId);
        Assert.Equal("7-Zip 23.01 (x64)", items[0].Name);
        Assert.Equal("23.01", items[0].InstalledVersion);
        Assert.Equal("24.08", items[0].AvailableVersion);
        Assert.False(items[0].IsPinned);

        Assert.Equal("Notepad++.Notepad++", items[2].PackageId);
        Assert.Equal("< 8.6.0", items[2].InstalledVersion);
        Assert.Equal("8.7.1", items[2].AvailableVersion);

        Assert.Equal("Git.Git", items[3].PackageId);
        Assert.True(items[3].IsPinned);
    }

    [Fact]
    public void WingetOutputParser_ParsesRussianLocalizedUpgradeTable()
    {
        var raw = """
            Имя                            ИД                           Версия        Доступно      Источник
            ------------------------------------------------------------------------------------------------
            Telegram Desktop               Telegram.TelegramDesktop     5.6.2         5.8.1         winget
            ShareX                         ShareX.ShareX                Неизвестно    16.1.0        winget
            Доступно обновлений: 2.
            """;

        var items = WingetOutputParser.ParseUpgradeTable(raw);
        Assert.Equal(2, items.Count);
        Assert.Equal("Telegram.TelegramDesktop", items[0].PackageId);
        Assert.Equal("5.8.1", items[0].AvailableVersion);
        Assert.Equal("ShareX.ShareX", items[1].PackageId);
        Assert.Equal("16.1.0", items[1].AvailableVersion);
    }

    [Fact]
    public void WingetOutputParser_ExtractsInstalledIdsFromWingetList()
    {
        var raw = """
            Name                           Id                               Version      Source
            -----------------------------------------------------------------------------------
            7-Zip 24.08 (x64)              7zip.7zip                        24.08        winget
            Microsoft PowerToys            Microsoft.PowerToys              0.86.0       winget
            Mozilla Firefox (x64 ru)       Mozilla.Firefox                  132.0.1      winget
            """;

        var set = WingetOutputParser.ParseInstalledPackageIds(raw);
        Assert.Contains("7zip.7zip", set);
        Assert.Contains("Microsoft.PowerToys", set);
        Assert.Contains("Mozilla.Firefox", set);
    }

    [Fact]
    public void EssentialSoftwareCatalog_LoadsAll36CuratedEntriesAndEvaluatesInstalledAppsCleanly()
    {
        var all = EssentialSoftwareCatalog.GetAll();
        Assert.Equal(36, all.Count);
        Assert.Equal(36, all.Select(x => x.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.Equal(36, all.Select(x => x.WingetId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.All(all, e => Assert.StartsWith("https://", e.WebsiteUrl, StringComparison.OrdinalIgnoreCase));

        Assert.NotEmpty(EssentialSoftwareCatalog.GetByPreset(EssentialAppBundlePreset.FreshHomeInstall));
        Assert.NotEmpty(EssentialSoftwareCatalog.GetByPreset(EssentialAppBundlePreset.GamerPc));
        Assert.NotEmpty(EssentialSoftwareCatalog.GetByPreset(EssentialAppBundlePreset.PowerUserAndDev));

        // Проверяем, что "GitHub Desktop" не даёт ложного срабатывания на короткое слово "Git"
        var installedWin32 = new[]
        {
            new InstalledApplicationInfo(@"HKLM\SOFTWARE\Uninstall\7-Zip", "7-Zip 24.08 (x64)", "24.08", "Igor Pavlov", null, null, 0),
            new InstalledApplicationInfo(@"HKCU\Software\Uninstall\GitHubDesktop", "GitHub Desktop", "3.4.9", "GitHub, Inc.", null, null, 0)
        };

        var statuses = EssentialSoftwareCatalog.EvaluateInstalledStates(installedWin32);
        var sevenZip = statuses.Single(s => s.Entry.Id == "7zip");
        var git = statuses.Single(s => s.Entry.Id == "git");

        Assert.True(sevenZip.IsInstalled);
        Assert.Equal("24.08", sevenZip.InstalledVersion);
        Assert.False(git.IsInstalled);
    }

    [Fact]
    public void LeftoverSafetyGuard_BlocksBrowserPasswordsSystemFoldersAndSharedVendorRoots()
    {
        Assert.False(LeftoverSafetyGuard.IsSafeFilesystemLeftoverCandidate(@"C:\Windows\System32"));
        Assert.False(LeftoverSafetyGuard.IsSafeFilesystemLeftoverCandidate(@"C:\Program Files"));
        Assert.False(LeftoverSafetyGuard.IsSafeFilesystemLeftoverCandidate(@"C:\Users\Alex\Documents"));
        Assert.False(LeftoverSafetyGuard.IsSafeFilesystemLeftoverCandidate(@"C:\Users\Alex\AppData\Local\Microsoft"));
        Assert.False(LeftoverSafetyGuard.IsSafeFilesystemLeftoverCandidate(@"C:\Users\Alex\AppData\Local\Google"));
        Assert.False(LeftoverSafetyGuard.IsSafeFilesystemLeftoverCandidate(@"C:\Users\Alex\AppData\Local\Google\Chrome\User Data\Default\Login Data"));

        Assert.True(LeftoverSafetyGuard.IsSafeFilesystemLeftoverCandidate(@"C:\Users\Alex\AppData\Roaming\ShareX"));
        Assert.True(LeftoverSafetyGuard.IsSafeFilesystemLeftoverCandidate(@"C:\ProgramData\FooVideoConverter"));

        Assert.False(LeftoverSafetyGuard.IsSafeRegistryLeftoverCandidate(@"HKCU\Software\Microsoft"));
        Assert.False(LeftoverSafetyGuard.IsSafeRegistryLeftoverCandidate(@"HKLM\Software\Classes"));
        Assert.False(LeftoverSafetyGuard.IsSafeRegistryLeftoverCandidate(@"HKLM\Software\WOW6432Node\Google"));
        Assert.True(LeftoverSafetyGuard.IsSafeRegistryLeftoverCandidate(@"HKCU\Software\ShareX"));
        Assert.True(LeftoverSafetyGuard.IsSafeRegistryLeftoverCandidate(@"HKLM\Software\WOW6432Node\FooVideoConverter"));
    }

    [Fact]
    public void LeftoverScanner_FindsAppDataShortcutsAndRegistryWhileSparingSiblingInstalledApps()
    {
        var fakeLocalAppData = Path.Combine(_tempDir, "Users", "User", "AppData", "Local");
        var fakeDesktop = Path.Combine(_tempDir, "Users", "User", "Desktop");
        var targetAppData = Path.Combine(fakeLocalAppData, "SuperRecorderPro");
        var siblingAppData = Path.Combine(fakeLocalAppData, "ActiveEditorSuite");

        Directory.CreateDirectory(targetAppData);
        Directory.CreateDirectory(siblingAppData);
        Directory.CreateDirectory(fakeDesktop);

        File.WriteAllBytes(Path.Combine(targetAppData, "cache.bin"), new byte[4096]);
        File.WriteAllBytes(Path.Combine(siblingAppData, "settings.json"), new byte[512]);
        File.WriteAllBytes(Path.Combine(fakeDesktop, "SuperRecorderPro.lnk"), new byte[128]);

        var targetApp = new InstalledApplicationInfo(
            @"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\SuperRecorderPro_is1",
            "SuperRecorderPro 4.2.1 (64-bit)",
            "4.2.1",
            "Acme Media",
            null,
            null,
            0);

        var siblingApp = new InstalledApplicationInfo(
            @"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\ActiveEditorSuite",
            "ActiveEditorSuite 2.0",
            "2.0",
            "Acme Media",
            null,
            null,
            0);

        var roots = new (AppLeftoverKind Kind, string RootDirectory)[]
        {
            (AppLeftoverKind.AppDataDirectory, fakeLocalAppData),
            (AppLeftoverKind.ShortcutFile, fakeDesktop)
        };

        var regKeys = new[]
        {
            @"HKCU\Software\Microsoft",
            @"HKCU\Software\SuperRecorderPro",
            @"HKCU\Software\ActiveEditorSuite"
        };

        var leftovers = LeftoverScanner.ScanLeftovers(targetApp, [targetApp, siblingApp], roots, regKeys);

        Assert.Equal(3, leftovers.Count);
        Assert.Contains(leftovers, l => l.Kind == AppLeftoverKind.AppDataDirectory && l.TargetPath.EndsWith("SuperRecorderPro", StringComparison.Ordinal));
        Assert.Contains(leftovers, l => l.Kind == AppLeftoverKind.ShortcutFile && l.TargetPath.EndsWith("SuperRecorderPro.lnk", StringComparison.Ordinal));
        Assert.Contains(leftovers, l => l.Kind == AppLeftoverKind.RegistrySubKey && l.TargetPath == @"HKCU\Software\SuperRecorderPro");
        Assert.DoesNotContain(leftovers, l => l.TargetPath.Contains("ActiveEditorSuite", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Windows11ReadinessEvaluator_EvaluatesFullCompatibilityAndWindows10EsuGuidance()
    {
        var win10BiosOnlyFacts = new Win11RawHardwareFacts(
            OsCaption: "Windows 10 Pro (22H2)",
            OsMajorVersion: 10,
            OsBuildNumber: 19045,
            Is64BitArchitecture: true,
            CpuBrand: "AMD Ryzen 5 5600X",
            CpuCores: 6,
            CpuMaxClockMhz: 3700,
            Sse42Supported: true,
            PopcntSupported: true,
            TotalRamBytes: 16L * 1024 * 1024 * 1024,
            SystemDriveTotalBytes: 500L * 1024 * 1024 * 1024,
            IsUefiBoot: true,
            IsSystemDiskGpt: true,
            IsSecureBootEnabled: false,
            TpmPresent: false,
            TpmSpecVersion: "отсутствует",
            DirectX12AndWddm2Ready: true,
            HasConsumerEsuMarker: false);

        var win10Report = Windows11ReadinessEvaluator.Evaluate(win10BiosOnlyFacts);
        Assert.False(win10Report.IsFullyCompatible);
        Assert.Equal(5, win10Report.PassedCount);
        Assert.Equal(7, win10Report.TotalCount);
        Assert.False(win10Report.Lifecycle.IsWindows11);
        Assert.Contains("14.10.2025", win10Report.Lifecycle.EsuStatusHeadline);
        Assert.Contains("12.10.2027", win10Report.Lifecycle.EsuStatusHeadline);
        Assert.Contains("BIOS/UEFI", win10Report.Lifecycle.RecommendationText);

        var legacyCpuFacts = win10BiosOnlyFacts with
        {
            Sse42Supported = false,
            PopcntSupported = false,
            IsSecureBootEnabled = true,
            TpmPresent = true,
            TpmSpecVersion = "2.0"
        };
        var legacyReport = Windows11ReadinessEvaluator.Evaluate(legacyCpuFacts);
        Assert.False(legacyReport.IsFullyCompatible);
        var cpuCheck = legacyReport.Checks.Single(c => c.CheckId == "cpu");
        Assert.False(cpuCheck.Passed);
        Assert.False(cpuCheck.CanEnableWithoutNewHardware);
    }

    [Fact]
    public async Task AppsAndAutomationService_RunsAutoMaintenancePersistsSummaryAndExportsSupportZipBundle()
    {
        var stateDir = Path.Combine(_tempDir, "state");
        var hw = new HardwareStudioService(_vault);
        var drv = new OfficialDriverService(_vault);
        var cln = new VaultSafeCleanerService(_vault);
        var rep = new SystemRepairService(_vault);
        var opt = new SmartOptimizerService(_vault);
        var sec = new AntiMinerSecurityService(_vault);
        var smart = new SmartSystemAuditOrchestrator(hw, drv, cln, rep, opt, sec);

        var apps = new AppsAndAutomationService(
            _vault,
            new NullAppsPlatformBridge(),
            hw,
            drv,
            cln,
            rep,
            sec,
            smart,
            stateDirectory: stateDir);

        var run = await apps.RunAutoMaintenanceNowAsync(cleanTempCache: false, checkDrives: true, checkSecurity: true);
        Assert.Contains("Очищено кэша", run.Headline);

        var schedule = await apps.GetMaintenanceScheduleAsync();
        Assert.Equal(run.Headline, schedule.LastRunSummary);

        var zipPath = Path.Combine(_tempDir, "DiagBundle.zip");
        var bundle = await apps.ExportSupportBundleAsync(zipPath);

        Assert.True(File.Exists(bundle.ArchivePath));
        Assert.True(bundle.FileSizeBytes > 512);
        Assert.Equal(3, bundle.IncludedFiles.Count);

        using var zip = ZipFile.OpenRead(bundle.ArchivePath);
        Assert.NotNull(zip.GetEntry("01-DiagnosticSummary.html"));
        Assert.NotNull(zip.GetEntry("02-HardwarePassport.html"));
        Assert.NotNull(zip.GetEntry("03-DiagnosticData.json"));
    }

    [Fact]
    public async Task AppsAndAutomationService_UsesMockWingetBridgeForScanAndInstall()
    {
        var mock = new FakeWingetBridge();
        var apps = new AppsAndAutomationService(_vault, mock, stateDirectory: _tempDir);

        var (avail, ver, upgrades) = await apps.ScanAvailableUpgradesAsync();
        Assert.True(avail);
        Assert.Equal("v1.9.25200", ver);
        Assert.Single(upgrades);
        Assert.Equal("7zip.7zip", upgrades[0].PackageId);

        var upgRes = await apps.UpgradePackageAsync("7zip.7zip", "7-Zip");
        Assert.True(upgRes.Succeeded);
        Assert.Contains(mock.RecordedInvocations, args => args.Contains("upgrade") && args.Contains("7zip.7zip"));

        var vlc = EssentialSoftwareCatalog.GetAll().Single(e => e.Id == "vlc");
        var instRes = await apps.InstallEssentialAppAsync(vlc);
        Assert.True(instRes.Succeeded);
        Assert.Contains(mock.RecordedInvocations, args => args.Contains("install") && args.Contains("VideoLAN.VLC"));
    }

    private sealed class FakeWingetBridge : IAppsPlatformBridge
    {
        private readonly NullAppsPlatformBridge _inner = new();
        public List<IReadOnlyList<string>> RecordedInvocations { get; } = new();

        public Task<(bool Available, string VersionText)> ProbeWingetAsync(CancellationToken ct = default) =>
            Task.FromResult((true, "v1.9.25200"));

        public Task<(int ExitCode, string StdOut, string StdErr)> RunWingetRawAsync(
            IReadOnlyList<string> arguments,
            TimeSpan timeout,
            CancellationToken ct = default)
        {
            RecordedInvocations.Add(arguments);
            if (arguments.Count > 0 && arguments[0] == "upgrade" && !arguments.Contains("--id"))
            {
                var table = """
                    Name              Id             Version    Available   Source
                    --------------------------------------------------------------
                    7-Zip 23.01       7zip.7zip      23.01      24.08       winget
                    """;
                return Task.FromResult((0, table, string.Empty));
            }

            return Task.FromResult((0, "Successfully installed", string.Empty));
        }

        public Task<IReadOnlyList<InstalledApplicationInfo>> GetInstalledWin32AppsAsync(CancellationToken ct = default) =>
            _inner.GetInstalledWin32AppsAsync(ct);

        public Task<bool> RunNativeUninstallerAndWaitAsync(InstalledApplicationInfo app, TimeSpan timeout, CancellationToken ct = default) =>
            _inner.RunNativeUninstallerAndWaitAsync(app, timeout, ct);

        public IReadOnlyList<(AppLeftoverKind Kind, string RootDirectory)> GetCandidateLeftoverRoots() =>
            _inner.GetCandidateLeftoverRoots();

        public IReadOnlyList<string> EnumerateRegistrySoftwareKeys() =>
            _inner.EnumerateRegistrySoftwareKeys();

        public Task<CleanUninstallResult> QuarantineAndRemoveLeftoversAsync(
            string appDisplayName,
            InstalledApplicationInfo? forceRemoveUninstallEntry,
            IReadOnlyList<AppLeftoverItem> leftovers,
            IVaultService vaultService,
            CancellationToken ct = default) =>
            _inner.QuarantineAndRemoveLeftoversAsync(appDisplayName, forceRemoveUninstallEntry, leftovers, vaultService, ct);

        public Task<Win11RawHardwareFacts> ProbeWin11HardwareFactsAsync(CancellationToken ct = default) =>
            _inner.ProbeWin11HardwareFactsAsync(ct);

        public Task<PowerSleepAndRamReport> ProbePowerSleepAndRamAsync(CancellationToken ct = default) =>
            _inner.ProbePowerSleepAndRamAsync(ct);

        public Task<string?> GenerateBatteryHtmlReportAsync(string destinationPath, CancellationToken ct = default) =>
            _inner.GenerateBatteryHtmlReportAsync(destinationPath, ct);

        public Task<bool> LaunchWindowsMemoryDiagnosticAsync(CancellationToken ct = default) =>
            _inner.LaunchWindowsMemoryDiagnosticAsync(ct);

        public Task<MaintenanceScheduleProfile> GetMaintenanceScheduleAsync(string? persistedLastRunSummary, CancellationToken ct = default) =>
            _inner.GetMaintenanceScheduleAsync(persistedLastRunSummary, ct);

        public Task<MaintenanceScheduleProfile> ApplyMaintenanceScheduleAsync(
            MaintenanceScheduleProfile desiredProfile,
            string cliExecutablePath,
            IVaultService vaultService,
            CancellationToken ct = default) =>
            _inner.ApplyMaintenanceScheduleAsync(desiredProfile, cliExecutablePath, vaultService, ct);
    }
}
