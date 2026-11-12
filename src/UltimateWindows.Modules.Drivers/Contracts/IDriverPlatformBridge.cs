using UltimateWindows.Modules.Drivers.Models;

namespace UltimateWindows.Modules.Drivers.Contracts;

/// <summary>
/// Платформенный мост Этапа 5 («Драйверы 2.0»):
/// CfgMgr32, Windows Update (WUApiLib), проверка цифровых подписей (Authenticode + CatRoot),
/// распаковка .cab (expand.exe), управление DriverStore (pnputil.exe) и аудит драйверов ядра (BYOVD / HVCI).
/// </summary>
public interface IDriverPlatformBridge
{
    bool IsRunningAsAdministrator();

    bool VerifyFileAuthenticodeSignature(string filePath);

    Task<IReadOnlyList<SystemDeviceNode>> EnumerateDevicesAsync(CancellationToken ct = default);

    Task<IReadOnlyList<OfficialDriverCandidate>> SearchWindowsUpdateDriversAsync(
        IReadOnlyList<SystemDeviceNode> devices,
        CancellationToken ct = default);

    Task<(bool Succeeded, IReadOnlyList<string> ExportedFiles, string ErrorMessage)> ExportSingleOemInfAsync(
        string oemInfName,
        string destinationDirectory,
        CancellationToken ct = default);

    Task<(bool Succeeded, int ExportedPackageCount, string ErrorMessage)> ExportAllDriversAsync(
        string destinationDirectory,
        CancellationToken ct = default);

    Task<(bool Succeeded, bool RebootRequired, string ErrorMessage)> InstallWindowsUpdateDriverAsync(
        string updateIdentityId,
        CancellationToken ct = default);

    Task<(bool Succeeded, IReadOnlyList<string> ExtractedFiles, string ErrorMessage)> ExtractCabArchiveAsync(
        string cabFilePath,
        string destinationDirectory,
        CancellationToken ct = default);

    Task<(bool Succeeded, int AddedCount, string OutputMessage)> AddAndInstallDriverFolderAsync(
        string infDirectory,
        bool installOnDevices = true,
        CancellationToken ct = default);

    Task<(bool Succeeded, int ExitCode, string ErrorMessage)> RunSignedInstallerAsync(
        string installerPath,
        string? arguments,
        CancellationToken ct = default);

    Task<IReadOnlyList<DriverStoreEntry>> EnumerateDriverStoreAsync(
        IReadOnlyList<SystemDeviceNode> activeDevices,
        CancellationToken ct = default);

    Task<(bool Succeeded, string ErrorMessage)> DeleteDriverStorePackageAsync(
        string publishedInfName,
        CancellationToken ct = default);

    Task<IReadOnlyList<KernelDriverInventoryEntry>> EnumerateKernelDriversAsync(
        CancellationToken ct = default);

    (bool IsHvciEnabled, bool IsMicrosoftBlocklistEnabled) ReadCodeIntegrityPosture();

    (bool Succeeded, int? PreviousValue, string ErrorMessage) SetMicrosoftVulnerableDriverBlocklist(bool enabled);

    (bool Succeeded, int PreviousStartType, string ErrorMessage) DisableKernelDriverService(string serviceName);
}
