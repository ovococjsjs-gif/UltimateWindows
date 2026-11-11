using UltimateWindows.Modules.Optimizer.Models;

namespace UltimateWindows.Modules.Optimizer.Contracts;

/// <summary>
/// Платформенный мост Фазы 4 для безопасного чтения/записи реестра твиков,
/// управления флагами StartupApproved и Shell Extensions\Blocked, разблокировки файлов через Restart Manager,
/// настройки DNS, редактирования hosts, управления UWP-приложениями и деинсталляции программ.
/// </summary>
public interface IOptimizerPlatformBridge
{
    bool IsRunningAsAdministrator();

    /// <summary>
    /// Сведения о компьютере для проверки применимости твиков: сборка Windows, тип системного диска, наличие батареи.
    /// Факт, который не удалось выяснить, возвращается как null.
    /// </summary>
    SystemFacts GetSystemFacts();

    (bool Exists, int ValueKindCode, string? SerializedValue) ReadRegistryValue(
        string hive,
        string subKeyPath,
        string valueName);

    bool WriteRegistryValue(
        string hive,
        string subKeyPath,
        string valueName,
        RegistryTweakValueKind kind,
        string serializedValue);

    Task<IReadOnlyList<StartupEntryInfo>> GetStartupEntriesAsync(CancellationToken ct = default);

    Task<(bool Succeeded, string PreviousStartupApprovedBase64)> SetStartupEntryEnabledAsync(
        StartupEntryInfo entry,
        bool enabled,
        CancellationToken ct = default);

    Task<IReadOnlyList<ShellContextMenuHandlerInfo>> GetThirdPartyShellExtensionsAsync(CancellationToken ct = default);

    Task<bool> SetShellExtensionBlockedAsync(
        string clsid,
        string handlerName,
        bool blocked,
        CancellationToken ct = default);

    Task<IReadOnlyList<LockingProcessInfo>> FindLockingProcessesAsync(
        string fileOrDirectoryPath,
        CancellationToken ct = default);

    Task<bool> TryPoliteCloseProcessAsync(int processId, CancellationToken ct = default);

    Task<(bool Succeeded, string AdapterName, string PreviousDnsStateJson)> ApplyDnsPresetAsync(
        DnsPresetDescriptor preset,
        CancellationToken ct = default);

    Task<bool> FlushDnsCacheAsync(CancellationToken ct = default);

    string GetHostsFilePath();

    Task<IReadOnlyList<InstalledApplicationInfo>> GetInstalledApplicationsAsync(CancellationToken ct = default);

    Task<bool> LaunchApplicationUninstallerAsync(InstalledApplicationInfo app, CancellationToken ct = default);

    Task<IReadOnlyList<UwpPackageInfo>> GetInstalledUwpPackagesAsync(CancellationToken ct = default);

    Task<(int RemovedCount, string ErrorSummary)> RemoveUwpPackagesAsync(
        IReadOnlyList<UwpPackageInfo> packages,
        CancellationToken ct = default);
}
