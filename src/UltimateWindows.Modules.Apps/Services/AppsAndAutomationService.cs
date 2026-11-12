using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using UltimateWindows.Core.Contracts;
using UltimateWindows.Modules.Apps.Catalog;
using UltimateWindows.Modules.Apps.Contracts;
using UltimateWindows.Modules.Apps.Models;
using UltimateWindows.Modules.Apps.Readiness;
using UltimateWindows.Modules.Apps.Support;
using UltimateWindows.Modules.Apps.Uninstaller;
using UltimateWindows.Modules.Apps.Winget;
using UltimateWindows.Modules.Cleaner.Models;
using UltimateWindows.Modules.Cleaner.Services;
using UltimateWindows.Modules.Drivers.Orchestration;
using UltimateWindows.Modules.Drivers.Services;
using UltimateWindows.Modules.Hardware.Services;
using UltimateWindows.Modules.Optimizer.Models;
using UltimateWindows.Modules.Repair.Services;
using UltimateWindows.Modules.Security.Services;

namespace UltimateWindows.Modules.Apps.Services;

/// <summary>
/// Главный сервис Этапа 7 («Программы, Автоматизация, Готовность к Windows 11 и Выпуск»):
/// объединяет центр обновлений и каталог winget, чистый деинсталлятор с поиском хвостов и карантином,
/// аудит Windows 11 / ESU / питания и сна, фоновое расписание автообслуживания и сборку диагностического архива.
/// </summary>
public sealed class AppsAndAutomationService
{
    private readonly IVaultService _vaultService;
    private readonly IAppsPlatformBridge _bridge;
    private readonly HardwareStudioService? _hardwareService;
    private readonly OfficialDriverService? _driverService;
    private readonly VaultSafeCleanerService? _cleanerService;
    private readonly SystemRepairService? _repairService;
    private readonly AntiMinerSecurityService? _securityService;
    private readonly SmartSystemAuditOrchestrator? _smartAuditOrchestrator;
    private readonly string _stateDirectory;

    public AppsAndAutomationService(
        IVaultService vaultService,
        IAppsPlatformBridge? bridge = null,
        HardwareStudioService? hardwareService = null,
        OfficialDriverService? driverService = null,
        VaultSafeCleanerService? cleanerService = null,
        SystemRepairService? repairService = null,
        AntiMinerSecurityService? securityService = null,
        SmartSystemAuditOrchestrator? smartAuditOrchestrator = null,
        string? stateDirectory = null)
    {
        _vaultService = vaultService ?? throw new ArgumentNullException(nameof(vaultService));
        _bridge = bridge ?? new NullAppsPlatformBridge();
        _hardwareService = hardwareService;
        _driverService = driverService;
        _cleanerService = cleanerService;
        _repairService = repairService;
        _securityService = securityService;
        _smartAuditOrchestrator = smartAuditOrchestrator;
        _stateDirectory = string.IsNullOrWhiteSpace(stateDirectory)
            ? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "UltimateWindows")
            : stateDirectory;
    }

    // ==================== 1. WINGET: ПРОВЕРКА ОБНОВЛЕНИЙ И КАТАЛОГ ====================

    public Task<(bool Available, string VersionText)> ProbeWingetAsync(CancellationToken ct = default) =>
        _bridge.ProbeWingetAsync(ct);

    public async Task<(bool WingetAvailable, string WingetVersion, IReadOnlyList<WingetUpgradablePackage> Packages)> ScanAvailableUpgradesAsync(
        CancellationToken ct = default)
    {
        var (available, version) = await _bridge.ProbeWingetAsync(ct).ConfigureAwait(false);
        if (!available)
        {
            return (false, version, Array.Empty<WingetUpgradablePackage>());
        }

        var (_, stdout, _) = await _bridge.RunWingetRawAsync(
            ["upgrade", "--include-unknown", "--accept-source-agreements", "--disable-interactivity"],
            TimeSpan.FromSeconds(75),
            ct).ConfigureAwait(false);

        var parsed = WingetOutputParser.ParseUpgradeTable(stdout);
        return (true, version, parsed);
    }

    public async Task<WingetOperationResult> UpgradePackageAsync(
        string packageId,
        string? displayName = null,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(packageId))
        {
            throw new ArgumentException("Идентификатор пакета winget не задан.", nameof(packageId));
        }

        var title = string.IsNullOrWhiteSpace(displayName) ? packageId : displayName;
        var (exitCode, stdout, stderr) = await _bridge.RunWingetRawAsync(
            [
                "upgrade",
                "--id", packageId,
                "--exact",
                "--silent",
                "--accept-package-agreements",
                "--accept-source-agreements",
                "--disable-interactivity"
            ],
            TimeSpan.FromMinutes(6),
            ct).ConfigureAwait(false);

        var combined = string.IsNullOrWhiteSpace(stderr) ? stdout : $"{stdout}\n{stderr}".Trim();
        var succeeded = exitCode == 0 ||
                        combined.Contains("No applicable upgrade", StringComparison.OrdinalIgnoreCase) ||
                        combined.Contains("No newer package versions", StringComparison.OrdinalIgnoreCase);

        var summary = succeeded
            ? $"Пакет «{title}» успешно обновлён."
            : $"Не удалось обновить «{title}» (код возврата {exitCode}).";

        return new WingetOperationResult(succeeded, exitCode, packageId, title, summary, combined);
    }

    public async Task<WingetOperationResult> InstallEssentialAppAsync(
        EssentialAppEntry entry,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(entry);

        var (exitCode, stdout, stderr) = await _bridge.RunWingetRawAsync(
            [
                "install",
                "--id", entry.WingetId,
                "--exact",
                "--silent",
                "--accept-package-agreements",
                "--accept-source-agreements",
                "--disable-interactivity"
            ],
            TimeSpan.FromMinutes(8),
            ct).ConfigureAwait(false);

        var combined = string.IsNullOrWhiteSpace(stderr) ? stdout : $"{stdout}\n{stderr}".Trim();
        var alreadyInstalled = combined.Contains("Found an existing package already installed", StringComparison.OrdinalIgnoreCase) ||
                               combined.Contains("уже установлен", StringComparison.OrdinalIgnoreCase);
        var succeeded = exitCode == 0 || alreadyInstalled;

        var summary = succeeded
            ? (alreadyInstalled
                ? $"«{entry.DisplayName}» уже установлен в системе."
                : $"«{entry.DisplayName}» официально установлен без навязанного ПО.")
            : $"Не удалось установить «{entry.DisplayName}» (код возврата {exitCode}).";

        return new WingetOperationResult(succeeded, exitCode, entry.WingetId, entry.DisplayName, summary, combined);
    }

    public async Task<IReadOnlyList<EssentialAppStatus>> EvaluateEssentialCatalogAsync(
        bool queryWingetList = false,
        CancellationToken ct = default)
    {
        var win32Apps = await _bridge.GetInstalledWin32AppsAsync(ct).ConfigureAwait(false);
        HashSet<string>? wingetIds = null;

        if (queryWingetList)
        {
            var (available, _) = await _bridge.ProbeWingetAsync(ct).ConfigureAwait(false);
            if (available)
            {
                var (_, stdout, _) = await _bridge.RunWingetRawAsync(
                    ["list", "--accept-source-agreements", "--disable-interactivity"],
                    TimeSpan.FromSeconds(45),
                    ct).ConfigureAwait(false);
                wingetIds = WingetOutputParser.ParseInstalledPackageIds(stdout);
            }
        }

        return EssentialSoftwareCatalog.EvaluateInstalledStates(win32Apps, wingetIds);
    }

    // ==================== 2. ЧИСТЫЙ ДЕИНСТАЛЛЯТОР И ПОИСК ХВОСТОВ ====================

    public Task<IReadOnlyList<InstalledApplicationInfo>> GetInstalledApplicationsAsync(CancellationToken ct = default) =>
        _bridge.GetInstalledWin32AppsAsync(ct);

    public async Task<IReadOnlyList<AppLeftoverItem>> ScanApplicationLeftoversAsync(
        InstalledApplicationInfo targetApp,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(targetApp);

        var allApps = await _bridge.GetInstalledWin32AppsAsync(ct).ConfigureAwait(false);
        var roots = _bridge.GetCandidateLeftoverRoots();
        var regKeys = _bridge.EnumerateRegistrySoftwareKeys();

        return LeftoverScanner.ScanLeftovers(targetApp, allApps, roots, regKeys);
    }

    public async Task<CleanUninstallResult> CleanSelectedLeftoversAsync(
        InstalledApplicationInfo targetApp,
        IReadOnlyList<AppLeftoverItem> selectedLeftovers,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(targetApp);
        ArgumentNullException.ThrowIfNull(selectedLeftovers);

        if (selectedLeftovers.Count == 0)
        {
            return new CleanUninstallResult(
                Succeeded: true,
                SessionId: null,
                AppName: targetApp.DisplayName,
                UninstallerLaunched: false,
                RemovedFileLeftovers: 0,
                RemovedRegistryLeftovers: 0,
                ReclaimedBytes: 0,
                SummaryMessage: "Хвосты для удаления не выбраны.");
        }

        return await _bridge.QuarantineAndRemoveLeftoversAsync(
            targetApp.DisplayName,
            forceRemoveUninstallEntry: null,
            selectedLeftovers,
            _vaultService,
            ct).ConfigureAwait(false);
    }

    public async Task<CleanUninstallResult> UninstallWithLeftoverSweepAsync(
        InstalledApplicationInfo targetApp,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(targetApp);

        var launched = await _bridge.RunNativeUninstallerAndWaitAsync(
            targetApp,
            TimeSpan.FromMinutes(5),
            ct).ConfigureAwait(false);

        if (!launched)
        {
            return new CleanUninstallResult(
                Succeeded: false,
                SessionId: null,
                AppName: targetApp.DisplayName,
                UninstallerLaunched: false,
                RemovedFileLeftovers: 0,
                RemovedRegistryLeftovers: 0,
                ReclaimedBytes: 0,
                SummaryMessage: $"Штатный деинсталлятор «{targetApp.DisplayName}» не запустился или отсутствует. При необходимости используйте принудительное удаление.");
        }

        // После завершения штатного деинсталлятора сканируем и помещаем оставшиеся хвосты в карантин Машины времени
        var remainingLeftovers = await ScanApplicationLeftoversAsync(targetApp, ct).ConfigureAwait(false);
        if (remainingLeftovers.Count == 0)
        {
            return new CleanUninstallResult(
                Succeeded: true,
                SessionId: null,
                AppName: targetApp.DisplayName,
                UninstallerLaunched: true,
                RemovedFileLeftovers: 0,
                RemovedRegistryLeftovers: 0,
                ReclaimedBytes: 0,
                SummaryMessage: $"Штатный деинсталлятор «{targetApp.DisplayName}» завершён, остаточных хвостов не осталось.");
        }

        var cleanup = await _bridge.QuarantineAndRemoveLeftoversAsync(
            targetApp.DisplayName,
            forceRemoveUninstallEntry: null,
            remainingLeftovers,
            _vaultService,
            ct).ConfigureAwait(false);

        return cleanup with { UninstallerLaunched = true };
    }

    public async Task<CleanUninstallResult> ForceRemoveBrokenAppAsync(
        InstalledApplicationInfo targetApp,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(targetApp);

        var leftovers = await ScanApplicationLeftoversAsync(targetApp, ct).ConfigureAwait(false);
        return await _bridge.QuarantineAndRemoveLeftoversAsync(
            targetApp.DisplayName,
            forceRemoveUninstallEntry: targetApp,
            leftovers,
            _vaultService,
            ct).ConfigureAwait(false);
    }

    // ==================== 3. ГОТОВНОСТЬ К WINDOWS 11, СОН, БАТАРЕЯ И ОЗУ ====================

    public async Task<Windows11ReadinessReport> CheckWindows11ReadinessAsync(CancellationToken ct = default)
    {
        var facts = await _bridge.ProbeWin11HardwareFactsAsync(ct).ConfigureAwait(false);
        return Windows11ReadinessEvaluator.Evaluate(facts);
    }

    public Task<PowerSleepAndRamReport> CheckPowerSleepAndRamAsync(CancellationToken ct = default) =>
        _bridge.ProbePowerSleepAndRamAsync(ct);

    public Task<string?> ExportBatteryHtmlReportAsync(string destinationPath, CancellationToken ct = default) =>
        _bridge.GenerateBatteryHtmlReportAsync(destinationPath, ct);

    public Task<bool> LaunchWindowsMemoryDiagnosticAsync(CancellationToken ct = default) =>
        _bridge.LaunchWindowsMemoryDiagnosticAsync(ct);

    // ==================== 4. ФОНОВЫЙ АВТОПИЛОТ И ЕДИНЫЙ ОТЧЁТ ====================

    public async Task<MaintenanceScheduleProfile> GetMaintenanceScheduleAsync(CancellationToken ct = default)
    {
        var lastSummary = TryReadLastMaintenanceHeadline();
        return await _bridge.GetMaintenanceScheduleAsync(lastSummary, ct).ConfigureAwait(false);
    }

    public async Task<MaintenanceScheduleProfile> SaveMaintenanceScheduleAsync(
        MaintenanceScheduleProfile profile,
        string? cliExecutablePath = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(profile);

        var resolvedCli = string.IsNullOrWhiteSpace(cliExecutablePath)
            ? ResolveDefaultCliExecutablePath()
            : cliExecutablePath;

        var updated = await _bridge.ApplyMaintenanceScheduleAsync(profile, resolvedCli, _vaultService, ct).ConfigureAwait(false);
        var lastSummary = TryReadLastMaintenanceHeadline();
        return lastSummary is not null ? updated with { LastRunSummary = lastSummary } : updated;
    }

    public async Task<MaintenanceRunSummary> RunAutoMaintenanceNowAsync(
        bool cleanTempCache = true,
        bool checkDrives = true,
        bool checkSecurity = true,
        CancellationToken ct = default)
    {
        long freedBytes = 0;
        var unhealthyDrives = 0;
        var securityAlerts = 0;
        var compositeScore = 96;

        if (cleanTempCache && _cleanerService is not null)
        {
            var opts = new CleanupOptions
            {
                CleanSystemTempAndShaders = true,
                CleanBrowserCaches = true,
                EmptyRecycleBin = false,
                CleanRegistryOrphans = false,
                PreservePasswordsAndAutofill = true,
                PreserveBrowserSessions = true
            };
            var scan = await _cleanerService.ScanAsync(opts, ct).ConfigureAwait(false);
            if (scan.CandidateFiles.Count > 0)
            {
                var exec = await _cleanerService.ExecuteCleanupAsync(scan, opts, ct).ConfigureAwait(false);
                freedBytes = exec.FreedBytes;
            }
        }

        if (checkDrives && _hardwareService is not null)
        {
            var (snap, audit) = await _hardwareService.CaptureAndAnalyzeAsync(ct).ConfigureAwait(false);
            unhealthyDrives = snap.Drives.Count(d => !d.IsHealthy);
            compositeScore = audit.HardwareHealthScore;
        }

        if (checkSecurity && _securityService is not null)
        {
            var sec = await _securityService.RunFullSecurityScanAsync(enableDropOnInspectProbe: false, ct).ConfigureAwait(false);
            securityAlerts = sec.Threats.Count + sec.SabotageLocks.Count;
            compositeScore = Math.Min(compositeScore, sec.SecurityHealthScore);
        }

        var now = DateTimeOffset.UtcNow;
        var headline =
            $"{now.ToLocalTime():dd.MM.yyyy HH:mm} • Очищено кэша: {UltimateWindows.Core.Models.ByteFormatter.Format(freedBytes)}, " +
            $"проблем S.M.A.R.T.: {unhealthyDrives}, угроз защиты: {securityAlerts}";

        var summary = new MaintenanceRunSummary(
            CompletedAtUtc: now,
            ReclaimedCacheBytes: freedBytes,
            UnhealthyDrivesCount: unhealthyDrives,
            SecurityAlertsCount: securityAlerts,
            CompositeHealthScore: compositeScore,
            Headline: headline);

        TrySaveLastMaintenanceSummary(summary);
        return summary;
    }

    public async Task<SupportBundleResult> ExportSupportBundleAsync(
        string destinationZipPath,
        CancellationToken ct = default)
    {
        if (_hardwareService is null ||
            _driverService is null ||
            _repairService is null ||
            _securityService is null ||
            _smartAuditOrchestrator is null)
        {
            throw new InvalidOperationException("Для сборки сводного диагностического архива необходимы все подсистемы UltimateWindows.");
        }

        var smartAuditTask = _smartAuditOrchestrator.RunOneClickAuditAsync(false, false, ct);
        var hwTask = _hardwareService.CaptureAndAnalyzeAsync(ct);
        var sensorsTask = _hardwareService.QuerySensorsAsync(ct);
        var drvTask = _driverService.AuditDevicesAndDriversAsync(false, ct);
        var bsodTask = _repairService.ScanBsodAndCrashHistoryAsync(15, ct);
        var secTask = _securityService.RunFullSecurityScanAsync(false, ct);
        var win11Task = CheckWindows11ReadinessAsync(ct);
        var powerTask = CheckPowerSleepAndRamAsync(ct);
        var schedTask = GetMaintenanceScheduleAsync(ct);

        await Task.WhenAll(
            smartAuditTask, hwTask, sensorsTask, drvTask,
            bsodTask, secTask, win11Task, powerTask, schedTask).ConfigureAwait(false);

        var (hwSnap, hwAudit) = hwTask.Result;
        var (minidumps, crashEvents) = bsodTask.Result;

        return await SupportBundleExporter.CreateDiagnosticArchiveAsync(
            destinationZipPath,
            smartAuditTask.Result,
            hwSnap,
            hwAudit,
            sensorsTask.Result,
            drvTask.Result,
            minidumps,
            crashEvents,
            secTask.Result,
            win11Task.Result,
            powerTask.Result,
            schedTask.Result,
            ct).ConfigureAwait(false);
    }

    private string GetLastMaintenanceJsonPath() =>
        Path.Combine(_stateDirectory, "last-maintenance.json");

    private string? TryReadLastMaintenanceHeadline()
    {
        try
        {
            var path = GetLastMaintenanceJsonPath();
            if (!File.Exists(path))
            {
                return null;
            }

            var json = File.ReadAllText(path);
            var parsed = JsonSerializer.Deserialize<MaintenanceRunSummary>(json);
            return parsed?.Headline;
        }
        catch
        {
            return null;
        }
    }

    private void TrySaveLastMaintenanceSummary(MaintenanceRunSummary summary)
    {
        try
        {
            var path = GetLastMaintenanceJsonPath();
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrWhiteSpace(dir))
            {
                Directory.CreateDirectory(dir);
            }

            var json = JsonSerializer.Serialize(summary, new JsonSerializerOptions
            {
                WriteIndented = true,
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                Converters = { new JsonStringEnumConverter() }
            });
            File.WriteAllText(path, json);
        }
        catch
        {
            // Ignore write errors in read-only sandboxes
        }
    }

    private static string ResolveDefaultCliExecutablePath()
    {
        var baseDir = AppContext.BaseDirectory;
        var cliCandidate = Path.Combine(baseDir, "UltimateWindows.Cli.exe");
        if (File.Exists(cliCandidate))
        {
            return cliCandidate;
        }

        return Environment.ProcessPath ?? cliCandidate;
    }
}
