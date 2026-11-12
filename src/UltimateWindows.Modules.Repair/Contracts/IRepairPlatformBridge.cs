using UltimateWindows.Modules.Repair.Diagnostics;
using UltimateWindows.Modules.Repair.Models;

namespace UltimateWindows.Modules.Repair.Contracts;

/// <summary>
/// Платформенный мост Этапа 3 (Ремонт и DLL 2.0):
/// чтение/запись реестра и служб для диагностического движка, проверка подписи WinVerifyTrust,
/// чтение журналов событий Windows и CBS.log, прямая загрузка подписанных сред выполнения Microsoft
/// и перечисление установленных программ.
/// </summary>
public interface IRepairPlatformBridge
{
    string GetSystem64Directory();

    string GetSysWow64Directory();

    string GetMinidumpDirectory();

    string GetCbsLogPath();

    int GetWindowsBuildNumber();

    bool IsRunningAsAdministrator();

    /// <summary>
    /// Проверяет цифровую подпись Authenticode (WinVerifyTrust) указанного файла.
    /// </summary>
    bool VerifyAuthenticodeSignature(string filePath);

    /// <summary>
    /// Читает последние критические сбои программ (Event 1000, 1002, 1026, SideBySide, AppModel-Runtime) и железа/драйверов (TDR 4101, WHEA, Kernel-Power 41).
    /// </summary>
    Task<IReadOnlyList<SystemCrashEventEntry>> ReadRecentCrashEventsAsync(
        int maxEntries = 20,
        CancellationToken ct = default);

    /// <summary>
    /// Устанавливает официальный подписанный пакет среды выполнения через пакетный менеджер Windows (winget).
    /// </summary>
    Task<(bool Succeeded, string OutputLog)> InstallOfficialRuntimeViaWingetAsync(
        OfficialRuntimePackage package,
        CancellationToken ct = default);

    /// <summary>
    /// Скачивает пакет напрямую с официального HTTPS-адреса издателя, проверяет цифровую подпись WinVerifyTrust
    /// и запускает тихую установку (с откатом на winget или DISM для компонентов ОС).
    /// </summary>
    Task<(bool Succeeded, string OutputLog)> InstallOfficialRuntimeDirectOrWingetAsync(
        OfficialRuntimePackage package,
        CancellationToken ct = default);

    /// <summary>
    /// Проверяет, какие официальные пакеты сред выполнения уже установлены в системе.
    /// </summary>
    Task<IReadOnlyList<OfficialRuntimeStatusReport>> DetectInstalledRuntimesAsync(
        IReadOnlyList<OfficialRuntimePackage> catalog,
        CancellationToken ct = default);

    /// <summary>
    /// Перечисляет установленные на компьютере программы и их главные исполняемые файлы .exe.
    /// </summary>
    Task<IReadOnlyList<InstalledProgramInfo>> EnumerateInstalledProgramsAsync(
        CancellationToken ct = default);

    /// <summary>
    /// Выполняет системный рецепт восстановления (DISM/SFC, сброс сети, кэша значков, Центра обновлений, Spooler, WMI).
    /// </summary>
    Task<(bool Succeeded, string OutputLog)> ExecutePlaybookNativeStepsAsync(
        RepairPlaybookId playbookId,
        CancellationToken ct = default);

    RepairRegistryValueState ReadRegistryValue(string hive, string subKey, string valueName);

    (bool Succeeded, string? CreatedKeyPath, string? Error) WriteRegistryValue(
        string hive,
        string subKey,
        string valueName,
        RepairRegistryValueKind kind,
        string? stringValue,
        int? dwordValue);

    (bool Succeeded, string? Error) DeleteRegistryValue(string hive, string subKey, string valueName);

    RepairServiceState QueryServiceState(string serviceName);

    Task<(bool Succeeded, string? Error)> RepairServiceAsync(
        string serviceName,
        RepairServiceStartupKind targetStartup,
        bool startIfStopped,
        CancellationToken ct = default);

    Task<RepairCustomProbeResult> RunCustomProbeAsync(string customProbeId, CancellationToken ct = default);

    Task<(bool Succeeded, bool RequiresReboot, string OutputLog, string? RollbackTarget, string? RollbackPreviousJson)> ExecuteCustomFixAsync(
        string customProbeId,
        CancellationToken ct = default);

    InPlaceReinstallReadiness GetInPlaceReinstallReadiness();

    bool OpenRecoverySettingsOrUrl(string uri);
}
