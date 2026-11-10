using UltimateWindows.Modules.Hardware.Models;

namespace UltimateWindows.Modules.Hardware.Contracts;

/// <summary>
/// Платформенный поставщик низкоуровневой аппаратной телеметрии и безопасных системных настроек.
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
}
