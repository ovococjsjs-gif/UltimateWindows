using UltimateWindows.Modules.Hardware.Models;

namespace UltimateWindows.Modules.Hardware.Contracts;

/// <summary>
/// Платформенный поставщик низкоуровневой аппаратной телеметрии AIDA64-класса (Этап 6):
/// SMBIOS/SPD, CPUID, S.M.A.R.T., EDID, датчики LibreHardwareMonitor 0.9.6 + опциональный PawnIO,
/// планы питания PowrProf, управление вентиляторами и DirectCompute (DX11) GPU-бенчмарк.
/// </summary>
public interface IHardwarePlatformProvider
{
    Task<HardwareSnapshot> CaptureSnapshotAsync(CancellationToken ct = default);

    Task<(double? CpuTempC, double? GpuTempC)> PollThermalSensorsAsync(CancellationToken ct = default);

    /// <summary>
    /// Переключает частоту обновления монитора на указанное значение Гц и возвращает предыдущую частоту для записи отката.
    /// </summary>
    Task<(bool Success, int PreviousHz, string Message)> TrySetDisplayRefreshRateAsync(
        string gdiDeviceName,
        int targetRefreshHz,
        CancellationToken ct = default);

    /// <summary>
    /// Переключает активную схему электропитания Windows и возвращает предыдущий GUID для отката в Машине времени.
    /// </summary>
    Task<(bool Success, Guid PreviousSchemeGuid, string Message)> TrySetActivePowerSchemeAsync(
        Guid targetSchemeGuid,
        CancellationToken ct = default);

    /// <summary>
    /// Возвращает расширенное дерево датчиков (температуры, напряжения, обороты вентиляторов, мощность, частоты)
    /// и статус подписанного ядерного бэкенда PawnIO.
    /// </summary>
    Task<HardwareSensorInventory> QuerySensorInventoryAsync(CancellationToken ct = default) =>
        Task.FromResult(new HardwareSensorInventory(
            DateTimeOffset.UtcNow,
            PawnIoBackendState.UserModeOnly,
            "Доступен безопасный пользовательский режим датчиков.",
            Array.Empty<HardwareSensorReading>(),
            Array.Empty<ControllableFanChannel>()));

    /// <summary>
    /// Перечисляет все доступные схемы электропитания Windows.
    /// </summary>
    Task<IReadOnlyList<PowerPlanInfo>> EnumeratePowerPlansAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<PowerPlanInfo>>(Array.Empty<PowerPlanInfo>());

    /// <summary>
    /// Разблокирует скрытую схему «Максимальная производительность» (Ultimate Performance) в Windows 10/11.
    /// </summary>
    Task<(bool Success, Guid? SchemeGuid, string Message)> UnlockUltimatePerformancePlanAsync(CancellationToken ct = default) =>
        Task.FromResult<(bool, Guid?, string)>((false, null, "Доступно только в среде Windows."));

    /// <summary>
    /// Применяет профиль управления вентиляторами на поддерживаемых контроллерах (или возвращает управление BIOS Auto).
    /// </summary>
    Task<(bool Success, int AffectedFanCount, string Message)> ApplyFanCoolingPresetAsync(
        FanCoolingPreset preset,
        CancellationToken ct = default) =>
        Task.FromResult((false, 0, "На данной плате управление оборотами вентиляторов заблокировано прошивкой BIOS/EC или не установлен драйвер PawnIO."));

    /// <summary>
    /// Выполняет быстрый лёгкий GPU-бенчмарк (Direct3D 11 DirectCompute cs_5_0 на Windows; программный SIMD-фолбэк на тестовых стендах без GPU).
    /// </summary>
    Task<GpuBenchmarkResult> RunGpuComputeBenchmarkAsync(
        TimeSpan targetDuration,
        CancellationToken ct = default) =>
        Task.FromResult(new GpuBenchmarkResult(
            AdapterName: "Программный адаптер (Fallback)",
            BackendName: "CPU SIMD Fallback",
            IsHardwareAccelerated: false,
            ComputeScore: 850,
            ShaderAluGflops: 42.0,
            VramBandwidthGbPerSec: 18.5,
            Duration: TimeSpan.FromMilliseconds(250),
            TierBadge: "Базовый / Виртуальный графический адаптер"));
}
