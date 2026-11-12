using UltimateWindows.Core.Contracts;
using UltimateWindows.Modules.Apps.Models;
using UltimateWindows.Modules.Optimizer.Models;

namespace UltimateWindows.Modules.Apps.Contracts;

/// <summary>
/// Платформенный мост для работы с пакетным менеджером winget, реестром деинсталляции,
/// проверкой аппаратных требований Windows 11, диагностикой питания/сна и Планировщиком заданий Windows.
/// </summary>
public interface IAppsPlatformBridge
{
    Task<(bool Available, string VersionText)> ProbeWingetAsync(CancellationToken ct = default);

    Task<(int ExitCode, string StdOut, string StdErr)> RunWingetRawAsync(
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        CancellationToken ct = default);

    Task<IReadOnlyList<InstalledApplicationInfo>> GetInstalledWin32AppsAsync(CancellationToken ct = default);

    Task<bool> RunNativeUninstallerAndWaitAsync(
        InstalledApplicationInfo app,
        TimeSpan timeout,
        CancellationToken ct = default);

    IReadOnlyList<(AppLeftoverKind Kind, string RootDirectory)> GetCandidateLeftoverRoots();

    IReadOnlyList<string> EnumerateRegistrySoftwareKeys();

    Task<CleanUninstallResult> QuarantineAndRemoveLeftoversAsync(
        string appDisplayName,
        InstalledApplicationInfo? forceRemoveUninstallEntry,
        IReadOnlyList<AppLeftoverItem> leftovers,
        IVaultService vaultService,
        CancellationToken ct = default);

    Task<Win11RawHardwareFacts> ProbeWin11HardwareFactsAsync(CancellationToken ct = default);

    Task<PowerSleepAndRamReport> ProbePowerSleepAndRamAsync(CancellationToken ct = default);

    Task<string?> GenerateBatteryHtmlReportAsync(string destinationPath, CancellationToken ct = default);

    Task<bool> LaunchWindowsMemoryDiagnosticAsync(CancellationToken ct = default);

    Task<MaintenanceScheduleProfile> GetMaintenanceScheduleAsync(
        string? persistedLastRunSummary,
        CancellationToken ct = default);

    Task<MaintenanceScheduleProfile> ApplyMaintenanceScheduleAsync(
        MaintenanceScheduleProfile desiredProfile,
        string cliExecutablePath,
        IVaultService vaultService,
        CancellationToken ct = default);
}

/// <summary>
/// Безопасная заглушка моста для модульных тестов и сред без Windows API.
/// </summary>
public sealed class NullAppsPlatformBridge : IAppsPlatformBridge
{
    public Task<(bool Available, string VersionText)> ProbeWingetAsync(CancellationToken ct = default) =>
        Task.FromResult((false, "недоступен в тестовой среде"));

    public Task<(int ExitCode, string StdOut, string StdErr)> RunWingetRawAsync(
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        CancellationToken ct = default) =>
        Task.FromResult((-1, string.Empty, "winget не подключён"));

    public Task<IReadOnlyList<InstalledApplicationInfo>> GetInstalledWin32AppsAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<InstalledApplicationInfo>>(Array.Empty<InstalledApplicationInfo>());

    public Task<bool> RunNativeUninstallerAndWaitAsync(
        InstalledApplicationInfo app,
        TimeSpan timeout,
        CancellationToken ct = default) =>
        Task.FromResult(false);

    public IReadOnlyList<(AppLeftoverKind Kind, string RootDirectory)> GetCandidateLeftoverRoots() =>
        Array.Empty<(AppLeftoverKind, string)>();

    public IReadOnlyList<string> EnumerateRegistrySoftwareKeys() =>
        Array.Empty<string>();

    public Task<CleanUninstallResult> QuarantineAndRemoveLeftoversAsync(
        string appDisplayName,
        InstalledApplicationInfo? forceRemoveUninstallEntry,
        IReadOnlyList<AppLeftoverItem> leftovers,
        IVaultService vaultService,
        CancellationToken ct = default) =>
        Task.FromResult(new CleanUninstallResult(
            Succeeded: true,
            SessionId: null,
            AppName: appDisplayName,
            UninstallerLaunched: false,
            RemovedFileLeftovers: leftovers.Count(x => x.Kind != AppLeftoverKind.RegistrySubKey),
            RemovedRegistryLeftovers: leftovers.Count(x => x.Kind == AppLeftoverKind.RegistrySubKey),
            ReclaimedBytes: leftovers.Sum(x => x.EstimatedSizeBytes),
            SummaryMessage: "Тестовая очистка завершена."));

    public Task<Win11RawHardwareFacts> ProbeWin11HardwareFactsAsync(CancellationToken ct = default) =>
        Task.FromResult(new Win11RawHardwareFacts(
            OsCaption: "Windows 11 Pro",
            OsMajorVersion: 10,
            OsBuildNumber: 26100,
            Is64BitArchitecture: true,
            CpuBrand: "64-bit x86_64 CPU",
            CpuCores: 8,
            CpuMaxClockMhz: 3800,
            Sse42Supported: true,
            PopcntSupported: true,
            TotalRamBytes: 16L * 1024 * 1024 * 1024,
            SystemDriveTotalBytes: 512L * 1024 * 1024 * 1024,
            IsUefiBoot: true,
            IsSystemDiskGpt: true,
            IsSecureBootEnabled: true,
            TpmPresent: true,
            TpmSpecVersion: "2.0",
            DirectX12AndWddm2Ready: true,
            HasConsumerEsuMarker: false));

    public Task<PowerSleepAndRamReport> ProbePowerSleepAndRamAsync(CancellationToken ct = default) =>
        Task.FromResult(new PowerSleepAndRamReport(
            HasBattery: false,
            BatteryDesignCapacityMwh: 0,
            BatteryFullChargeCapacityMwh: 0,
            BatteryWearPercent: 0,
            BatteryStatusHeadline: "Стационарный ПК (аккумулятор не обнаружен)",
            LastWakeSource: "Кнопка питания / таймер не зафиксирован",
            ActivePowerBlockers: Array.Empty<string>(),
            LastRamDiagnosticSummary: "Проверка памяти ещё не запускалась",
            LastRamDiagnosticHadErrors: false));

    public Task<string?> GenerateBatteryHtmlReportAsync(string destinationPath, CancellationToken ct = default) =>
        Task.FromResult<string?>(null);

    public Task<bool> LaunchWindowsMemoryDiagnosticAsync(CancellationToken ct = default) =>
        Task.FromResult(false);

    public Task<MaintenanceScheduleProfile> GetMaintenanceScheduleAsync(
        string? persistedLastRunSummary,
        CancellationToken ct = default) =>
        Task.FromResult(new MaintenanceScheduleProfile(
            IsEnabled: false,
            Frequency: MaintenanceFrequency.Disabled,
            RunHourLocal: 12,
            CleanSafeTempCache: true,
            CheckDriveSmartHealth: true,
            AuditSecurityAndStartup: true,
            TaskSchedulerPath: @"\UltimateWindows\AutoMaintenance",
            NextRunDisplay: "Не запланировано",
            LastRunSummary: persistedLastRunSummary ?? "Фоновый прогон ещё не выполнялся"));

    public Task<MaintenanceScheduleProfile> ApplyMaintenanceScheduleAsync(
        MaintenanceScheduleProfile desiredProfile,
        string cliExecutablePath,
        IVaultService vaultService,
        CancellationToken ct = default) =>
        Task.FromResult(desiredProfile with
        {
            NextRunDisplay = desiredProfile.IsEnabled ? desiredProfile.FrequencyDisplay : "Не запланировано"
        });
}
