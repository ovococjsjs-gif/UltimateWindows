using UltimateWindows.Core.Enums;

namespace UltimateWindows.Modules.Drivers.Models;

public enum DriverSourceKind
{
    WindowsUpdateWhqlCatalog = 0,
    OfficialVendorWhqlPortal = 1
}

/// <summary>
/// Разобранный 4-компонентный аппаратный идентификатор устройства (например, PCI\VEN_10DE&amp;DEV_2684&amp;SUBSYS_16A11043&amp;REV_A1).
/// </summary>
public sealed record HardwareIdParts(
    string RawHardwareId,
    string BusEnumerator,
    string VendorId,
    string DeviceId,
    string? SubsystemId,
    string? RevisionId)
{
    public bool HasFullFourPartPciId =>
        !string.IsNullOrWhiteSpace(VendorId) &&
        !string.IsNullOrWhiteSpace(DeviceId) &&
        !string.IsNullOrWhiteSpace(SubsystemId);
}

/// <summary>
/// Узел устройства из дерева диспетчера устройств Windows (CfgMgr32).
/// </summary>
public sealed record SystemDeviceNode(
    string InstanceId,
    string FriendlyName,
    string DeviceClass,
    string Manufacturer,
    IReadOnlyList<string> HardwareIds,
    int ConfigManagerProblemCode,
    string DriverVersion,
    string DriverDate,
    string InfName,
    bool IsPresent = true)
{
    public bool HasProblem => ConfigManagerProblemCode != 0;

    public bool IsThirdPartyOemInf =>
        !string.IsNullOrWhiteSpace(InfName) &&
        InfName.StartsWith("oem", StringComparison.OrdinalIgnoreCase) &&
        InfName.EndsWith(".inf", StringComparison.OrdinalIgnoreCase);

    public bool IsBasicDisplayFallback =>
        string.Equals(DeviceClass, "Display", StringComparison.OrdinalIgnoreCase) &&
        (string.Equals(InfName, "display.inf", StringComparison.OrdinalIgnoreCase) ||
         FriendlyName.Contains("Basic Display", StringComparison.OrdinalIgnoreCase) ||
         FriendlyName.Contains("Базовый видеоадаптер", StringComparison.OrdinalIgnoreCase));
}

/// <summary>
/// Официальный WHQL-кандидат драйвера из каталога Windows Update (WUApiLib) или официального портала производителя чипа.
/// </summary>
public sealed record OfficialDriverCandidate(
    string UpdateIdentityId,
    string Title,
    string DriverModel,
    string ProviderName,
    string DriverVersion,
    string DriverVerDate,
    string MatchedHardwareId,
    int HardwareIdMatchRank,
    DriverSourceKind SourceKind,
    string OfficialVendorPortalUrl,
    bool IsWhqlVerified)
{
    public string SourceBadge => SourceKind == DriverSourceKind.WindowsUpdateWhqlCatalog
        ? "Подписано Microsoft WHQL (Windows Update)"
        : "Официальный сайт производителя";
}

/// <summary>
/// Диагностическая находка по проблемному устройству, базовому видеодрайверу или доступному WHQL-обновлению.
/// </summary>
public sealed record DriverAuditFinding(
    string FindingId,
    RiskLevel Severity,
    SystemDeviceNode Device,
    string SimpleTitle,
    string SimpleExplanation,
    string ExpertTechnicalDetails,
    OfficialDriverCandidate? RecommendedWhqlUpdate,
    string? OfficialVendorUrl)
{
    public bool CanInstallViaWindowsUpdate =>
        RecommendedWhqlUpdate is { SourceKind: DriverSourceKind.WindowsUpdateWhqlCatalog, IsWhqlVerified: true };

    public bool CanBackupOemInf => Device.IsThirdPartyOemInf;
}

/// <summary>
/// Сводный отчет Фазы 6 по состоянию всех устройств и драйверов ПК.
/// </summary>
public sealed record DriverAuditReport(
    DateTimeOffset AuditedAtUtc,
    int DriverHealthScore,
    int TotalDevicesScanned,
    int ProblemDeviceCount,
    int BasicFallbackDisplayCount,
    int WhqlUpdatesAvailableCount,
    string SummaryHeadline,
    IReadOnlyList<DriverAuditFinding> Findings,
    IReadOnlyList<SystemDeviceNode> AllDevices);

/// <summary>
/// Результат селективного бэкапа или установки официального WHQL-драйвера.
/// </summary>
public sealed record DriverOperationResult(
    bool Succeeded,
    string UserFriendlyMessage,
    string TechnicalDetails = "",
    Guid? RollbackSessionId = null);
