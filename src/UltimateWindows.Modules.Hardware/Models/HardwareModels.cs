using UltimateWindows.Core.Models;

namespace UltimateWindows.Modules.Hardware.Models;

public enum AdvisorySeverity
{
    Info = 0,
    PerformanceGain = 1,
    Warning = 2,
    Critical = 3
}

public enum AdvisoryCode
{
    MonitorRefreshSuboptimal = 1,
    MemoryXmpOrExpoDisabled = 2,
    MemorySingleChannelMisplaced = 3,
    GpuPcieLinkDegraded = 4,
    ResizableBarDisabled = 5,
    ThermalHotspotOrThrottling = 6,
    StorageSmartWarning = 7,
    PowerPlanThrottling = 8,
    BatteryWearHigh = 9
}

public enum StorageBusKind
{
    Unknown = 0,
    Nvme = 1,
    SataSsd = 2,
    HardDiskDrive = 3,
    UsbExternal = 4
}

public sealed record CpuHardwareInfo(
    string Vendor,
    string BrandName,
    int Family,
    int Model,
    int Stepping,
    int PhysicalCores,
    int LogicalProcessors,
    int PerformanceCores,
    int EfficientCores,
    long L1CacheBytes,
    long L2CacheBytes,
    long L3CacheBytes,
    int BaseClockMhz,
    int CurrentClockMhz,
    double? PackageTemperatureC,
    double? TotalLoadPercent,
    IReadOnlyList<string> InstructionSets);

public sealed record MotherboardBiosInfo(
    string BoardManufacturer,
    string BoardProduct,
    string BoardVersion,
    string BiosVendor,
    string BiosVersion,
    string BiosReleaseDate,
    string SystemManufacturer,
    string SystemProductName,
    int SmbiosMajorVersion,
    int SmbiosMinorVersion);

public sealed record MemoryModuleSlotInfo(
    string DeviceLocator,
    string BankLocator,
    string MemoryType,
    long CapacityBytes,
    int RatedSpeedMtPerSec,
    int ConfiguredSpeedMtPerSec,
    string Manufacturer,
    string PartNumber)
{
    public bool IsPopulated => CapacityBytes > 0;
    public string FormattedCapacity => ByteFormatter.Format(CapacityBytes);
}

public sealed record MemorySubsystemInfo(
    long TotalPhysicalBytes,
    long AvailablePhysicalBytes,
    int ConfiguredSpeedMtPerSec,
    int MaxRatedSpeedMtPerSec,
    string MemoryGeneration,
    int PopulatedSlotsCount,
    int TotalSlotsCount,
    bool IsDualOrMultiChannelActive,
    IReadOnlyList<MemoryModuleSlotInfo> Modules)
{
    public string FormattedTotal => ByteFormatter.Format(TotalPhysicalBytes);
}

public sealed record GpuHardwareInfo(
    int Index,
    string Name,
    string Vendor,
    long DedicatedVramBytes,
    string DriverVersion,
    int? CurrentPcieGen,
    int? MaxPcieGen,
    int? CurrentPcieLanes,
    int? MaxPcieLanes,
    bool? IsResizableBarEnabled,
    double? CoreTemperatureC,
    double? HotspotTemperatureC,
    double? MemoryTemperatureC,
    int? FanSpeedPercent,
    double? PowerDrawWatts,
    int? CoreLoadPercent)
{
    public string FormattedVram => ByteFormatter.Format(DedicatedVramBytes);
}

public sealed record StorageDriveSmartInfo(
    int DriveIndex,
    string Model,
    string SerialNumber,
    string FirmwareRevision,
    StorageBusKind BusKind,
    long CapacityBytes,
    bool IsHealthy,
    int? RemainingLifePercent,
    int? TemperatureC,
    double? TotalHostReadsTb,
    double? TotalBytesWrittenTb,
    long? PowerOnHours,
    long? PowerCycles,
    long? UnsafeShutdowns,
    long? MediaIntegrityErrors,
    long? ReallocatedSectors,
    long? UltraDmaCrcErrors)
{
    public string FormattedCapacity => ByteFormatter.Format(CapacityBytes);
}

public sealed record DisplayMonitorInfo(
    string GdiDeviceName,
    string FriendlyModelName,
    string ManufacturerCode,
    int? ManufactureYear,
    int NativeWidthPx,
    int NativeHeightPx,
    int CurrentRefreshHz,
    int MaxSupportedRefreshHz,
    int? ColorBitDepth,
    double? DiagonalInches);

public sealed record BatteryHealthInfo(
    bool IsPresent,
    bool IsOnAcPower,
    int ChargePercent,
    long? DesignCapacityMwh,
    long? FullChargeCapacityMwh)
{
    public double? WearLevelPercent =>
        DesignCapacityMwh is > 0 && FullChargeCapacityMwh is >= 0 && FullChargeCapacityMwh <= DesignCapacityMwh
            ? Math.Round((1.0 - (double)FullChargeCapacityMwh.Value / DesignCapacityMwh.Value) * 100.0, 1)
            : null;
}

public sealed record PowerPlanInfo(
    Guid SchemeGuid,
    string FriendlyName,
    bool IsPowerSaver,
    bool IsHighOrUltimatePerformance);

public sealed record HardwareSnapshot(
    DateTimeOffset CapturedAtUtc,
    CpuHardwareInfo Cpu,
    MotherboardBiosInfo Motherboard,
    MemorySubsystemInfo Memory,
    IReadOnlyList<GpuHardwareInfo> Gpus,
    IReadOnlyList<StorageDriveSmartInfo> Drives,
    IReadOnlyList<DisplayMonitorInfo> Monitors,
    BatteryHealthInfo Battery,
    PowerPlanInfo ActivePowerPlan);

/// <summary>
/// Рекомендация Умного советника по железу (с простым объяснением для пользователя и тех. данными для эксперта).
/// </summary>
public sealed record HardwareAdvisoryFinding(
    AdvisoryCode Code,
    AdvisorySeverity Severity,
    string SimpleTitle,
    string SimpleExplanation,
    string ExpertTelemetryDetails,
    string EstimatedImpactBadge,
    bool CanAutoFixInOneClick,
    string? AutoFixActionLabel,
    string? TargetDeviceId = null,
    int? TargetValue = null);

public sealed record StressTestProgress(
    TimeSpan Elapsed,
    long TotalMatrixOperations,
    double MillionsOpsPerSecond,
    double? PeakCpuTempC,
    double? PeakGpuTempC,
    bool WasAbortedByThermalCutoff,
    string StatusMessage);
