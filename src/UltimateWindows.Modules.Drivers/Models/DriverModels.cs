using UltimateWindows.Core.Enums;
using UltimateWindows.Core.Models;

namespace UltimateWindows.Modules.Drivers.Models;

public enum DriverSourceKind
{
    WindowsUpdateWhqlCatalog = 0,
    OfficialVendorWhqlPortal = 1,
    MicrosoftUpdateCatalogDirectCab = 2,
    OfficialVendorDirectHttps = 3
}

public enum EssentialDriverDeliveryKind
{
    DirectHttps = 0,
    MicrosoftCatalogWhql = 1
}

public enum EssentialDriverCategory
{
    EthernetLan = 0,
    WiFiWireless = 1,
    BluetoothAndTethering = 2,
    GpuAndAssistants = 3,
    ChipsetAndMotherboard = 4,
    StorageNvmeRaid = 5,
    AudioSound = 6,
    UsbSerialIoT = 7,
    VirtualizationVm = 8,
    InputAndSensors = 9
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

    public string TwoPartQuery => $"{BusEnumerator}\\{(BusEnumerator.Equals("USB", StringComparison.OrdinalIgnoreCase) ? "VID_" : "VEN_")}{VendorId}&{(BusEnumerator.Equals("USB", StringComparison.OrdinalIgnoreCase) ? "PID_" : "DEV_")}{DeviceId}";
}

/// <summary>
/// Узел устройства из дерева диспетчера устройств Windows (CfgMgr32) с расширенной телеметрией драйвера Этапа 5.
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
    bool IsPresent = true,
    string ProviderName = "",
    IReadOnlyList<string>? CompatibleIds = null,
    string ServiceName = "",
    string ServiceImagePath = "",
    bool? IsDigitallySigned = null,
    string MatchingDeviceId = "",
    string LocationInfo = "")
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

    public string EffectiveProvider =>
        !string.IsNullOrWhiteSpace(ProviderName) ? ProviderName :
        (!string.IsNullOrWhiteSpace(Manufacturer) ? Manufacturer : "Microsoft / Стандартный");

    public string PrimaryHardwareId => HardwareIds.FirstOrDefault() ?? InstanceId;

    public string StatusBadge =>
        HasProblem ? $"Код ошибки {ConfigManagerProblemCode}" :
        IsBasicDisplayFallback ? "Базовый видеодрайвер" :
        string.IsNullOrWhiteSpace(DriverVersion) ? "Системный / Без драйвера" : "Исправен";

    public string SignatureBadge => IsDigitallySigned switch
    {
        true => "Подписан",
        false => "Без подписи",
        null => IsThirdPartyOemInf ? "Сторонний INF" : "Штатный ОС"
    };
}

/// <summary>
/// Официальный WHQL-кандидат драйвера из каталога Windows Update (WUApiLib), Microsoft Update Catalog или официального портала производителя.
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
    bool IsWhqlVerified,
    string? DirectCabDownloadUrl = null,
    long SizeBytes = 0)
{
    public string SourceBadge => SourceKind switch
    {
        DriverSourceKind.WindowsUpdateWhqlCatalog => "Подписано Microsoft WHQL (Windows Update)",
        DriverSourceKind.MicrosoftUpdateCatalogDirectCab => "Прямой WHQL CAB (Каталог Microsoft)",
        DriverSourceKind.OfficialVendorDirectHttps => "Официальный сервер производителя (HTTPS)",
        _ => "Официальный сайт производителя"
    };
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
/// Сводный отчет по состоянию всех устройств и драйверов ПК.
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
    IReadOnlyList<SystemDeviceNode> AllDevices,
    int ThirdPartyOemDeviceCount = 0,
    int UnsignedDriverDeviceCount = 0);

/// <summary>
/// Результат селективного бэкапа, скачивания с сервера или установки официального драйвера.
/// </summary>
public sealed record DriverOperationResult(
    bool Succeeded,
    string UserFriendlyMessage,
    string TechnicalDetails = "",
    Guid? RollbackSessionId = null,
    string? OutputPath = null);

// ==================== MICROSOFT UPDATE CATALOG (ПРЯМОЙ ПОИСК И СКАЧИВАНИЕ .CAB) ====================

public sealed record MicrosoftCatalogDriverEntry(
    string UpdateId,
    string Title,
    string Products,
    string Classification,
    string LastUpdatedText,
    DateTimeOffset? LastUpdated,
    string Version,
    string SizeText,
    long SizeBytes,
    string MatchedQuery)
{
    public string FormattedSize => SizeBytes > 0 ? ByteFormatter.Format(SizeBytes) : SizeText;
}

public sealed record MicrosoftCatalogDownloadLink(
    string UpdateId,
    string FileName,
    string DownloadUrl,
    string? DigestBase64,
    string? Architectures);

// ==================== КАТАЛОГ ОСНОВНЫХ ДРАЙВЕРОВ С СЕРВЕРОВ НА ВСЕ СЛУЧАИ ЖИЗНИ ====================

public sealed record EssentialDriverPackage(
    string Id,
    string Title,
    EssentialDriverCategory Category,
    string CategoryLabel,
    string Vendor,
    string ScenarioSummary,
    EssentialDriverDeliveryKind DeliveryKind,
    string? DirectDownloadUrl,
    string? CatalogSearchQuery,
    string OfficialPortalUrl,
    string? WingetPackageId,
    string? SilentInstallArgs,
    IReadOnlyList<string> HardwareIdPrefixes,
    bool IncludeInUniversalNetworkRescuePack,
    string EstimatedSizeLabel)
{
    public string DeliveryBadge => DeliveryKind == EssentialDriverDeliveryKind.DirectHttps
        ? "Прямой HTTPS вендора"
        : "Сервер Microsoft (.cab)";

    public string ShortCategoryLabel => Category switch
    {
        EssentialDriverCategory.EthernetLan => "Сеть LAN",
        EssentialDriverCategory.WiFiWireless => "Wi-Fi 5/6/7",
        EssentialDriverCategory.BluetoothAndTethering => "BT / Модемы",
        EssentialDriverCategory.GpuAndAssistants => "Видео и DSA",
        EssentialDriverCategory.ChipsetAndMotherboard => "Чипсет / I2C",
        EssentialDriverCategory.StorageNvmeRaid => "NVMe / VMD",
        EssentialDriverCategory.AudioSound => "Аудио",
        EssentialDriverCategory.UsbSerialIoT => "USB-COM",
        EssentialDriverCategory.VirtualizationVm => "VirtIO (ВМ)",
        EssentialDriverCategory.InputAndSensors => "PawnIO / Ввод",
        _ => CategoryLabel
    };
}

public sealed record EssentialDriverEvaluatedItem(
    EssentialDriverPackage Package,
    bool MatchesCurrentPcHardware,
    bool NeedsAttentionOnCurrentPc,
    string? MatchedDeviceSummary)
{
    public string PcRelevanceBadge =>
        NeedsAttentionOnCurrentPc ? "Требуется этому ПК!" :
        MatchesCurrentPcHardware ? "Есть в этом ПК" : "В копилку / офлайн";
}

// ==================== ХРАНИЛИЩЕ DRIVERSTORE (PNPUTIL / FILEREPOSITORY) И ОФЛАЙН-СПАСЕНИЕ ====================

public sealed record DriverStoreEntry(
    string PublishedInfName,
    string OriginalInfName,
    string ProviderName,
    string ClassName,
    string ClassGuid,
    string DriverVersion,
    string DriverDate,
    string SignerName,
    string RepositoryFolderPath,
    long SizeBytes,
    bool IsInUseByDevice,
    string? BoundDeviceName,
    bool IsSupersededDuplicate,
    string? SupersededByVersion)
{
    public string FormattedSize => SizeBytes > 0 ? ByteFormatter.Format(SizeBytes) : "—";

    public string StateBadge =>
        IsInUseByDevice ? "Активен" :
        IsSupersededDuplicate ? $"Дубль (есть {SupersededByVersion})" :
        "Резерв";
}

public sealed record DriverStoreAuditSummary(
    IReadOnlyList<DriverStoreEntry> Entries,
    long TotalStoreSizeBytes,
    int DuplicateOldCount,
    long ReclaimableDuplicateBytes,
    string Headline)
{
    public string FormattedTotalSize => ByteFormatter.Format(TotalStoreSizeBytes);
    public string FormattedReclaimableSize => ByteFormatter.Format(ReclaimableDuplicateBytes);
}

public sealed record OfflineRescuePackResult(
    bool Succeeded,
    string TargetDirectory,
    int ExportedOrDownloadedCount,
    long TotalBytes,
    string InstallScriptPath,
    string UserFriendlyMessage,
    IReadOnlyList<string> Details)
{
    public string FormattedTotalSize => ByteFormatter.Format(TotalBytes);
}

// ==================== АУДИТ УЯЗВИМЫХ И ЗАБЛОКИРОВАННЫХ ДРАЙВЕРОВ ЯДРА (BYOVD) ====================

public sealed record VulnerableDriverCatalogEntry(
    string Id,
    string FamilyName,
    IReadOnlyList<string> FileNamesLower,
    IReadOnlyList<string> KnownVulnerableSha256,
    string VendorOrOrigin,
    string CveOrAdvisory,
    RiskLevel Severity,
    string AbuseExplanation,
    string SafeAlternative,
    bool BlockedByMicrosoftList);

public sealed record KernelDriverInventoryEntry(
    string ServiceName,
    string DisplayName,
    string BinaryPath,
    string FileName,
    bool FileExists,
    string FileVersion,
    string CompanyName,
    string Sha256Hex,
    bool IsRunning,
    int StartType,
    bool IsSigned);

public sealed record VulnerableDriverFinding(
    string FindingId,
    KernelDriverInventoryEntry InstalledDriver,
    VulnerableDriverCatalogEntry MatchedRule,
    string MatchReason,
    bool CanSafelyNeutralize)
{
    public string StateText => InstalledDriver.IsRunning ? "Загружен в ядро!" : "Установлен (не активен)";
}

public sealed record VulnerableDriverAuditReport(
    bool IsHvciEnabled,
    bool IsMicrosoftBlocklistEnabled,
    int TotalKernelDriversScanned,
    IReadOnlyList<VulnerableDriverFinding> Findings,
    string SummaryHeadline);
