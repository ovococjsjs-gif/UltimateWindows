using UltimateWindows.Modules.Drivers.Models;

namespace UltimateWindows.Modules.Drivers.Contracts;

/// <summary>
/// Платформенный мост Фазы 6 для чтения дерева устройств CfgMgr32,
/// поиска подписанных WHQL-драйверов в каталоге Windows Update (WUApiLib) и селективного экспорта oemXX.inf.
/// </summary>
public interface IDriverPlatformBridge
{
    bool IsRunningAsAdministrator();

    Task<IReadOnlyList<SystemDeviceNode>> EnumerateDevicesAsync(CancellationToken ct = default);

    Task<IReadOnlyList<OfficialDriverCandidate>> SearchWindowsUpdateDriversAsync(
        IReadOnlyList<SystemDeviceNode> devices,
        CancellationToken ct = default);

    /// <summary>
    /// Экспортирует ТОЛЬКО указанный пакет драйвера (oemXX.inf) во временную директорию через pnputil /export-driver
    /// для последующего компактного сжатия в Zero-Bloat Vault (без раздувания диска копией всего DriverStore).
    /// </summary>
    Task<(bool Succeeded, IReadOnlyList<string> ExportedFiles, string ErrorMessage)> ExportSingleOemInfAsync(
        string oemInfName,
        string destinationDirectory,
        CancellationToken ct = default);

    Task<(bool Succeeded, bool RebootRequired, string ErrorMessage)> InstallWindowsUpdateDriverAsync(
        string updateIdentityId,
        CancellationToken ct = default);
}
