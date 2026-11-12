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

public enum SensorCategory
{
    Temperature = 0,
    Voltage = 1,
    Fan = 2,
    Power = 3,
    Clock = 4,
    Load = 5,
    Data = 6,
    Control = 7
}

public enum PawnIoBackendState
{
    UserModeOnly = 0,
    PawnIoActive = 1
}

public enum FanCoolingPreset
{
    BiosAuto = 0,
    Quiet = 1,
    Balanced = 2,
    MaxCooling = 3
}

public enum HardwareReportFormat
{
    Html = 0,
    Json = 1,
    Txt = 2
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
    IReadOnlyList<string> InstructionSets,
    double? PackagePowerWatts = null,
    double? CoreVoltageVolts = null);

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
    string PartNumber,
    string FormFactor = "",
    int? ConfiguredVoltageMillivolts = null,
    int? DataWidthBits = null,
    int? TotalWidthBits = null,
    string SerialNumber = "",
    int? Ranks = null)
{
    public bool IsPopulated => CapacityBytes > 0;
    public string FormattedCapacity => ByteFormatter.Format(CapacityBytes);

    public bool HasEcc =>
        DataWidthBits is > 0 && TotalWidthBits is > 0 && TotalWidthBits.Value > DataWidthBits.Value;

    public string FormattedVoltage => ConfiguredVoltageMillivolts is > 0
        ? $"{ConfiguredVoltageMillivolts.Value / 1000.0:F2} В"
        : "—";

    public string ProfileAndSpecBadge
    {
        get
        {
            var parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(FormFactor)) parts.Add(FormFactor);
            if (Ranks is > 0) parts.Add($"{Ranks}R");
            if (ConfiguredVoltageMillivolts is > 0)
            {
                var v = ConfiguredVoltageMillivolts.Value / 1000.0;
                var ocTag = (MemoryType == "DDR4" && v >= 1.32) || (MemoryType == "DDR5" && v >= 1.24)
                    ? " (XMP/EXPO)"
                    : "";
                parts.Add($"{v:F2} В{ocTag}");
            }

            if (HasEcc) parts.Add("ECC");
            return parts.Count > 0 ? string.Join(" • ", parts) : MemoryType;
        }
    }
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
    public string FormattedAvailable => ByteFormatter.Format(AvailablePhysicalBytes);
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
    int? CoreLoadPercent,
    int? CoreClockMhz = null,
    int? MemoryClockMhz = null,
    int? FanSpeedRpm = null)
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
    bool IsHighOrUltimatePerformance,
    bool IsActive = true);

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
/// Единичное показание аппаратного датчика (LibreHardwareMonitor 0.9.6 + опциональный PawnIO / NVML / SMART).
/// </summary>
public sealed record HardwareSensorReading(
    string HardwareGroup,
    string SensorName,
    SensorCategory Category,
    double CurrentValue,
    double? MinValue,
    double? MaxValue,
    string Unit)
{
    public string CategoryBadge => Category switch
    {
        SensorCategory.Temperature => "Температура",
        SensorCategory.Voltage => "Напряжение",
        SensorCategory.Fan => "Вентилятор",
        SensorCategory.Power => "Мощность",
        SensorCategory.Clock => "Частота",
        SensorCategory.Load => "Загрузка",
        SensorCategory.Control => "ШИМ (PWM)",
        _ => "Данные"
    };

    public string FormattedCurrent => FormatMetric(CurrentValue, Unit);
    public string FormattedMin => MinValue.HasValue ? FormatMetric(MinValue.Value, Unit) : "—";
    public string FormattedMax => MaxValue.HasValue ? FormatMetric(MaxValue.Value, Unit) : "—";

    private static string FormatMetric(double v, string unit) => unit switch
    {
        "В" => $"{v:F3} В",
        "Вт" => $"{v:F1} Вт",
        "°C" => $"{v:F1} °C",
        "об/мин" => $"{v:F0} об/мин",
        "МГц" => $"{v:F0} МГц",
        "%" => $"{v:F0} %",
        _ => $"{v:F1} {unit}".Trim()
    };
}

public sealed record ControllableFanChannel(
    string ChannelId,
    string HardwareName,
    string FanName,
    int? CurrentDutyPercent,
    int? CurrentRpm);

public sealed record HardwareSensorInventory(
    DateTimeOffset SampledAtUtc,
    PawnIoBackendState BackendState,
    string BackendHeadline,
    IReadOnlyList<HardwareSensorReading> Readings,
    IReadOnlyList<ControllableFanChannel> ControllableFans);

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

public sealed record StressTelemetryPoint(
    double ElapsedSeconds,
    double MillionsOpsPerSecond,
    double? CpuTempC,
    double? GpuTempC);

public sealed record StressTestProgress(
    TimeSpan Elapsed,
    long TotalMatrixOperations,
    double MillionsOpsPerSecond,
    double? PeakCpuTempC,
    double? PeakGpuTempC,
    bool WasAbortedByThermalCutoff,
    string StatusMessage,
    int IntegrityErrorCount = 0,
    IReadOnlyList<StressTelemetryPoint>? History = null);

// ==================== ЛЁГКИЕ БЫСТРЫЕ БЕНЧМАРКИ (CPU / GPU / ПАМЯТЬ / ДИСК) ====================

public sealed record CpuBenchmarkResult(
    int SingleCoreScore,
    int MultiCoreScore,
    double SingleCoreCryptoMbPerSec,
    double MultiCoreSimdGflops,
    double MultiThreadScaling,
    int LogicalThreadsUsed,
    TimeSpan Duration,
    string TierBadge)
{
    public string SummaryLine =>
        $"1 ядро: {SingleCoreScore} балл. ({SingleCoreCryptoMbPerSec:F0} МБ/с) • Все потоки ({LogicalThreadsUsed}): {MultiCoreScore} балл. ({MultiCoreSimdGflops:F1} ГФЛОПС, x{MultiThreadScaling:F1})";
}

public sealed record GpuBenchmarkResult(
    string AdapterName,
    string BackendName,
    bool IsHardwareAccelerated,
    int ComputeScore,
    double ShaderAluGflops,
    double VramBandwidthGbPerSec,
    TimeSpan Duration,
    string TierBadge)
{
    public string SummaryLine =>
        $"{AdapterName}: {ComputeScore} балл. • Шейдеры ALU: {ShaderAluGflops:F1} ГФЛОПС • Память: {VramBandwidthGbPerSec:F1} ГБ/с ({BackendName})";
}

public sealed record MemoryBenchmarkResult(
    int MemoryScore,
    double BandwidthGbPerSec,
    double LatencyNanoseconds,
    TimeSpan Duration,
    string TierBadge)
{
    public string SummaryLine =>
        $"{MemoryScore} балл. • Пропускная способность: {BandwidthGbPerSec:F1} ГБ/с • Задержка (L3/DRAM): {LatencyNanoseconds:F1} нс";
}

public sealed record StorageBenchmarkResult(
    string TargetVolume,
    int StorageScore,
    double SeqWriteMbPerSec,
    double SeqReadMbPerSec,
    double Random4kIops,
    TimeSpan Duration,
    string TierBadge)
{
    public string SummaryLine =>
        $"{TargetVolume} — {StorageScore} балл. • Чтение: {SeqReadMbPerSec:F0} МБ/с • Запись: {SeqWriteMbPerSec:F0} МБ/с • 4K: {Random4kIops:F0} IOPS";
}

public sealed record HardwareBenchmarkSuiteReport(
    DateTimeOffset CompletedAtUtc,
    int CompositeScore,
    string OverallTierBadge,
    CpuBenchmarkResult? Cpu,
    GpuBenchmarkResult? Gpu,
    MemoryBenchmarkResult? Memory,
    StorageBenchmarkResult? Storage,
    TimeSpan TotalDuration);
