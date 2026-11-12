using System.Text.Json;
using UltimateWindows.Core.Contracts;
using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Hardware.Analysis;
using UltimateWindows.Modules.Hardware.Benchmarks;
using UltimateWindows.Modules.Hardware.Contracts;
using UltimateWindows.Modules.Hardware.Models;
using UltimateWindows.Modules.Hardware.Probes;
using UltimateWindows.Modules.Hardware.Reporting;
using UltimateWindows.Modules.Hardware.Stress;

namespace UltimateWindows.Modules.Hardware.Services;

/// <summary>
/// Безопасный кроссплатформенный провайдер по умолчанию (использует CPUID и базовые метрики среды, если запущен вне Windows).
/// На Windows подменяется на полноценный WindowsHardwarePlatformProvider из UltimateWindows.NativeInterop.
/// </summary>
public sealed class FallbackHardwarePlatformProvider : IHardwarePlatformProvider
{
    public Task<HardwareSnapshot> CaptureSnapshotAsync(CancellationToken ct = default)
    {
        var cpuid = CpuIdProbe.QueryCurrentProcessor();
        var logical = Environment.ProcessorCount;
        var cpu = new CpuHardwareInfo(
            Vendor: cpuid.Vendor,
            BrandName: cpuid.BrandString,
            Family: cpuid.Family,
            Model: cpuid.Model,
            Stepping: cpuid.Stepping,
            PhysicalCores: Math.Max(1, logical / 2),
            LogicalProcessors: logical,
            PerformanceCores: Math.Max(1, logical / 2),
            EfficientCores: 0,
            L1CacheBytes: 0,
            L2CacheBytes: 0,
            L3CacheBytes: 0,
            BaseClockMhz: 0,
            CurrentClockMhz: 0,
            PackageTemperatureC: null,
            TotalLoadPercent: null,
            InstructionSets: cpuid.InstructionSets);

        var gcMem = GC.GetGCMemoryInfo();
        var totalRam = gcMem.TotalAvailableMemoryBytes > 0 ? gcMem.TotalAvailableMemoryBytes : 16L * 1024 * 1024 * 1024;

        var snapshot = new HardwareSnapshot(
            CapturedAtUtc: DateTimeOffset.UtcNow,
            Cpu: cpu,
            Motherboard: new MotherboardBiosInfo("Generic", "System Board", "1.0", "UEFI", "1.0", "", "Generic", "PC", 3, 4),
            Memory: new MemorySubsystemInfo(totalRam, totalRam / 2, 0, 0, "DRAM", 1, 2, false, []),
            Gpus: [],
            Drives: [],
            Monitors: [],
            Battery: new BatteryHealthInfo(false, true, 100, null, null),
            ActivePowerPlan: new PowerPlanInfo(Guid.Empty, "Сбалансированная", IsPowerSaver: false, IsHighOrUltimatePerformance: false));

        return Task.FromResult(snapshot);
    }

    public Task<(double? CpuTempC, double? GpuTempC)> PollThermalSensorsAsync(CancellationToken ct = default)
        => Task.FromResult<(double?, double?)>((null, null));

    public Task<(bool Success, int PreviousHz, string Message)> TrySetDisplayRefreshRateAsync(
        string gdiDeviceName,
        int targetRefreshHz,
        CancellationToken ct = default)
        => Task.FromResult((false, 60, "Управление частотой монитора доступно только в среде Windows."));

    public Task<(bool Success, Guid PreviousSchemeGuid, string Message)> TrySetActivePowerSchemeAsync(
        Guid targetSchemeGuid,
        CancellationToken ct = default)
        => Task.FromResult((false, Guid.Empty, "Управление схемами электропитания доступно только в среде Windows."));
}

/// <summary>
/// Фасад Аппаратной студии AIDA64-класса (Этап 6):
/// связывает паспорт железа, датчики LibreHardwareMonitor/PawnIO, планы питания, управление вентиляторами,
/// лёгкие бенчмарки CPU/GPU/RAM/Диска, стресс-тест стабильности с проверкой ошибок и экспорт отчётов HTML/JSON/TXT.
/// </summary>
public sealed class HardwareStudioService
{
    private readonly IHardwarePlatformProvider _platformProvider;
    private readonly IVaultService _vaultService;
    private readonly ThermalSafeStressRunner _stressRunner;
    private readonly LightweightBenchmarkRunner _benchmarkRunner;

    public HardwareStudioService(
        IVaultService vaultService,
        IHardwarePlatformProvider? platformProvider = null)
    {
        _vaultService = vaultService ?? throw new ArgumentNullException(nameof(vaultService));
        _platformProvider = platformProvider ?? new FallbackHardwarePlatformProvider();
        _stressRunner = new ThermalSafeStressRunner(_platformProvider);
        _benchmarkRunner = new LightweightBenchmarkRunner(_platformProvider);
    }

    public async Task<(HardwareSnapshot Snapshot, HardwareAuditSummary Audit)> CaptureAndAnalyzeAsync(
        CancellationToken ct = default)
    {
        var snapshot = await _platformProvider.CaptureSnapshotAsync(ct).ConfigureAwait(false);
        var audit = HardwareBottleneckAdvisor.Analyze(snapshot);
        return (snapshot, audit);
    }

    public Task<HardwareSensorInventory> QuerySensorsAsync(CancellationToken ct = default) =>
        _platformProvider.QuerySensorInventoryAsync(ct);

    public Task<IReadOnlyList<PowerPlanInfo>> GetPowerPlansAsync(CancellationToken ct = default) =>
        _platformProvider.EnumeratePowerPlansAsync(ct);

    public async Task<(bool Success, string UserMessage)> SwitchPowerPlanAsync(
        Guid targetSchemeGuid,
        string friendlyName,
        CancellationToken ct = default)
    {
        var (ok, prevGuid, msg) = await _platformProvider.TrySetActivePowerSchemeAsync(targetSchemeGuid, ct).ConfigureAwait(false);
        if (!ok)
        {
            return (false, msg);
        }

        await using var tx = _vaultService.BeginTransaction(
            SystemDomain.HardwareAndDrivers,
            friendlyTitle: $"Переключение схемы электропитания на «{friendlyName}»",
            friendlySummary: $"Активирована схема «{friendlyName}». Прежнюю схему можно вернуть в 1 клик.",
            technicalDetails: $"PowrProf PowerSetActiveScheme: {prevGuid} -> {targetSchemeGuid}");

        tx.RecordStateDelta(
            StateTargetKind.SystemSetting,
            "PowerActiveScheme",
            previousStateJson: JsonSerializer.Serialize(new { SchemeGuid = prevGuid }),
            newStateJson: JsonSerializer.Serialize(new { SchemeGuid = targetSchemeGuid }));

        await tx.CommitAsync(ct: ct).ConfigureAwait(false);
        return (true, $"Активирована схема питания «{friendlyName}» (точка отката сохранена в Машине времени).");
    }

    public Task<(bool Success, Guid? SchemeGuid, string Message)> UnlockUltimatePerformancePlanAsync(CancellationToken ct = default) =>
        _platformProvider.UnlockUltimatePerformancePlanAsync(ct);

    public Task<(bool Success, int AffectedFanCount, string Message)> ApplyFanCoolingPresetAsync(
        FanCoolingPreset preset,
        CancellationToken ct = default) =>
        _platformProvider.ApplyFanCoolingPresetAsync(preset, ct);

    public Task<CpuBenchmarkResult> RunCpuBenchmarkAsync(CancellationToken ct = default) =>
        _benchmarkRunner.RunCpuBenchmarkAsync(ct: ct);

    public Task<GpuBenchmarkResult> RunGpuBenchmarkAsync(CancellationToken ct = default) =>
        _benchmarkRunner.RunGpuBenchmarkAsync(ct: ct);

    public Task<MemoryBenchmarkResult> RunMemoryBenchmarkAsync(CancellationToken ct = default) =>
        _benchmarkRunner.RunMemoryBenchmarkAsync(ct: ct);

    public Task<StorageBenchmarkResult> RunStorageBenchmarkAsync(string? targetDirectory = null, CancellationToken ct = default) =>
        _benchmarkRunner.RunStorageBenchmarkAsync(targetDirectory, testSizeMegabytes: 32, ct: ct);

    public Task<HardwareBenchmarkSuiteReport> RunFullQuickBenchmarkSuiteAsync(
        IProgress<string>? statusProgress = null,
        CancellationToken ct = default) =>
        _benchmarkRunner.RunFullQuickSuiteAsync(statusProgress, ct);

    public async Task<string> ExportHardwareReportAsync(
        string filePath,
        HardwareReportFormat format,
        HardwareSnapshot? cachedSnapshot = null,
        HardwareAuditSummary? cachedAudit = null,
        HardwareSensorInventory? cachedSensors = null,
        HardwareBenchmarkSuiteReport? cachedBenchmarks = null,
        CancellationToken ct = default)
    {
        var snap = cachedSnapshot ?? await _platformProvider.CaptureSnapshotAsync(ct).ConfigureAwait(false);
        var audit = cachedAudit ?? HardwareBottleneckAdvisor.Analyze(snap);
        var sensors = cachedSensors ?? await _platformProvider.QuerySensorInventoryAsync(ct).ConfigureAwait(false);
        return await HardwareReportExporter.ExportToFileAsync(filePath, format, snap, audit, sensors, cachedBenchmarks, ct).ConfigureAwait(false);
    }

    public Task<StressTestProgress> RunThermalSafeStressTestAsync(
        TimeSpan duration,
        double maxSafeCpuTempC = 92.0,
        double maxSafeGpuTempC = 88.0,
        IProgress<StressTestProgress>? progress = null,
        CancellationToken ct = default)
        => _stressRunner.RunStabilityTestAsync(duration, maxSafeCpuTempC, maxSafeGpuTempC, progress, ct);

    /// <summary>
    /// Выполняет автоматическое безопасное исправление найденного узкого места (герцовка экрана / профиль питания)
    /// с обязательной записью точки отката в Zero-Bloat Vault!
    /// </summary>
    public async Task<(bool Success, string UserMessage)> ApplyAdvisoryAutoFixAsync(
        HardwareAdvisoryFinding finding,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(finding);
        if (!finding.CanAutoFixInOneClick)
        {
            return (false, "Для данной рекомендации требуется настройка в BIOS или физическая проверка комплектующих.");
        }

        switch (finding.Code)
        {
            case AdvisoryCode.MonitorRefreshSuboptimal when
                !string.IsNullOrWhiteSpace(finding.TargetDeviceId) && finding.TargetValue is > 0:
            {
                var targetHz = finding.TargetValue.Value;
                var (ok, prevHz, msg) = await _platformProvider
                    .TrySetDisplayRefreshRateAsync(finding.TargetDeviceId, targetHz, ct)
                    .ConfigureAwait(false);

                if (!ok)
                {
                    return (false, msg);
                }

                await using var tx = _vaultService.BeginTransaction(
                    SystemDomain.HardwareAndDrivers,
                    friendlyTitle: $"Переключение частоты монитора с {prevHz} Гц на {targetHz} Гц",
                    friendlySummary: $"Включена максимальная плавность экрана ({targetHz} Гц). Можно вернуть {prevHz} Гц в 1 клик.",
                    technicalDetails: $"Display={finding.TargetDeviceId}, dmDisplayFrequency: {prevHz} -> {targetHz}");

                tx.RecordStateDelta(
                    StateTargetKind.SystemSetting,
                    $"DisplayRefreshRate:{finding.TargetDeviceId}",
                    previousStateJson: JsonSerializer.Serialize(new { Device = finding.TargetDeviceId, RefreshHz = prevHz }),
                    newStateJson: JsonSerializer.Serialize(new { Device = finding.TargetDeviceId, RefreshHz = targetHz }));

                await tx.CommitAsync(ct: ct).ConfigureAwait(false);
                return (true, $"Готово! Частота экрана переключена на {targetHz} Гц (точка отката сохранена в Машине времени).");
            }

            case AdvisoryCode.PowerPlanThrottling when
                Guid.TryParse(finding.TargetDeviceId, out var targetGuid):
            {
                return await SwitchPowerPlanAsync(targetGuid, "Оптимальная производительность", ct).ConfigureAwait(false);
            }

            default:
                return (false, "Автоисправление для данного типа рекомендации не поддерживается.");
        }
    }
}
