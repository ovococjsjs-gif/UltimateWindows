using LibreHardwareMonitor.Hardware;
using Microsoft.Win32;
using UltimateWindows.Modules.Hardware.Models;

namespace UltimateWindows.NativeInterop.Hardware;

/// <summary>
/// Потокобезопасный мост к LibreHardwareMonitorLib 0.9.6 (MPL-2.0, без WinRing0, с нативной поддержкой подписанного PawnIO):
/// - собирает температуры, напряжения, обороты вентиляторов, мощности и частоты CPU, материнской платы, ОЗУ, дисков и GPU (AMD, Intel, NVIDIA);
/// - без установленного PawnIO работает строго в безопасном пользовательском режиме (HVCI-совместимо);
/// - при наличии установленного пользователем PawnIO автоматически раскрывает датчики ядер CPU и SuperIO вентиляторов платы.
/// </summary>
internal static class LibreHardwareSensorBridge
{
    private static readonly object SyncLock = new();

    internal sealed record GpuLhmTelemetry(
        string Name,
        HardwareType Type,
        double? CoreTempC,
        double? HotspotTempC,
        double? MemoryTempC,
        int? FanPercent,
        int? FanRpm,
        double? PowerWatts,
        int? CoreLoadPercent,
        int? CoreClockMhz,
        int? MemClockMhz);

    internal sealed record LhmSnapshotSummary(
        PawnIoBackendState BackendState,
        string BackendHeadline,
        double? CpuPackageTempC,
        double? CpuTotalLoadPercent,
        int? CpuMaxClockMhz,
        double? CpuPackagePowerWatts,
        double? CpuCoreVoltageVolts,
        long? BatteryDesignMwh,
        long? BatteryFullChargeMwh,
        IReadOnlyList<GpuLhmTelemetry> Gpus,
        IReadOnlyList<HardwareSensorReading> AllReadings,
        IReadOnlyList<ControllableFanChannel> ControllableFans);

    public static bool IsPawnIoServiceActive()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\PawnIO");
            if (key is null)
            {
                return false;
            }

            var start = Convert.ToInt32(key.GetValue("Start") ?? 4);
            return start is 0 or 1 or 2 or 3;
        }
        catch
        {
            return false;
        }
    }

    public static LhmSnapshotSummary CaptureTelemetry(bool includeAllSensorRows)
    {
        if (!OperatingSystem.IsWindows())
        {
            return EmptySummary();
        }

        bool pawnIo = IsPawnIoServiceActive();
        lock (SyncLock)
        {
            Computer? computer = null;
            try
            {
                computer = new Computer
                {
                    IsCpuEnabled = true,
                    IsGpuEnabled = true,
                    IsMemoryEnabled = true,
                    IsStorageEnabled = true,
                    IsBatteryEnabled = true,
                    // Датчики SuperIO платы и контроллеров опрашиваем при установленном PawnIO
                    IsMotherboardEnabled = pawnIo,
                    IsControllerEnabled = pawnIo
                };

                computer.Open();

                double? cpuTemp = null;
                double? cpuLoad = null;
                int? cpuMaxClock = null;
                double? cpuPower = null;
                double? cpuVolt = null;
                long? batDesign = null;
                long? batFull = null;

                var gpus = new List<GpuLhmTelemetry>();
                var readings = new List<HardwareSensorReading>();
                var fans = new List<ControllableFanChannel>();

                foreach (var hw in computer.Hardware)
                {
                    SafeUpdateHardware(hw);
                    CollectFromHardwareNode(
                        hw,
                        pawnIo,
                        includeAllSensorRows,
                        ref cpuTemp,
                        ref cpuLoad,
                        ref cpuMaxClock,
                        ref cpuPower,
                        ref cpuVolt,
                        ref batDesign,
                        ref batFull,
                        gpus,
                        readings,
                        fans);

                    foreach (var sub in hw.SubHardware)
                    {
                        SafeUpdateHardware(sub);
                        CollectFromHardwareNode(
                            sub,
                            pawnIo,
                            includeAllSensorRows,
                            ref cpuTemp,
                            ref cpuLoad,
                            ref cpuMaxClock,
                            ref cpuPower,
                            ref cpuVolt,
                            ref batDesign,
                            ref batFull,
                            gpus,
                            readings,
                            fans);
                    }
                }

                var state = pawnIo ? PawnIoBackendState.PawnIoActive : PawnIoBackendState.UserModeOnly;
                var headline = pawnIo
                    ? $"Активен подписанный драйвер PawnIO (HVCI-совместимый) • Считано датчиков: {readings.Count}"
                    : $"Безопасный пользовательский режим (без ядерного драйвера) • Считано датчиков: {readings.Count}. Для температур ядер CPU и вентиляторов платы можно установить опциональный PawnIO.";

                return new LhmSnapshotSummary(
                    BackendState: state,
                    BackendHeadline: headline,
                    CpuPackageTempC: cpuTemp,
                    CpuTotalLoadPercent: cpuLoad,
                    CpuMaxClockMhz: cpuMaxClock,
                    CpuPackagePowerWatts: cpuPower,
                    CpuCoreVoltageVolts: cpuVolt,
                    BatteryDesignMwh: batDesign,
                    BatteryFullChargeMwh: batFull,
                    Gpus: gpus,
                    AllReadings: readings,
                    ControllableFans: fans);
            }
            catch
            {
                return EmptySummary();
            }
            finally
            {
                try { computer?.Close(); } catch { }
            }
        }
    }

    public static (bool Success, int AffectedCount, string Message) ApplyFanPreset(FanCoolingPreset preset)
    {
        if (!OperatingSystem.IsWindows())
        {
            return (false, 0, "Управление охлаждением доступно только на Windows.");
        }

        bool pawnIo = IsPawnIoServiceActive();
        lock (SyncLock)
        {
            Computer? computer = null;
            try
            {
                computer = new Computer
                {
                    IsGpuEnabled = true,
                    IsMotherboardEnabled = pawnIo,
                    IsControllerEnabled = pawnIo
                };
                computer.Open();

                int affected = 0;
                float targetDuty = preset switch
                {
                    FanCoolingPreset.Quiet => 38f,
                    FanCoolingPreset.Balanced => 62f,
                    FanCoolingPreset.MaxCooling => 100f,
                    _ => 0f
                };

                foreach (var hw in EnumerateAllNodes(computer))
                {
                    SafeUpdateHardware(hw);
                    foreach (var sensor in hw.Sensors)
                    {
                        if (sensor.SensorType != SensorType.Control || sensor.Control is null)
                        {
                            continue;
                        }

                        try
                        {
                            if (preset == FanCoolingPreset.BiosAuto)
                            {
                                sensor.Control.SetDefault();
                            }
                            else
                            {
                                sensor.Control.SetSoftware(targetDuty);
                            }

                            affected++;
                        }
                        catch { }
                    }
                }

                if (affected == 0)
                {
                    var hint = pawnIo
                        ? "На этой плате управление вентиляторами управляется автономно прошивкой BIOS/EC и закрыто от программной записи."
                        : "Контроллеры ШИМ не обнаружены: для управления вентиляторами платы требуется подписанный драйвер PawnIO (либо настройте кривую Q-Fan / Smart Fan в BIOS).";
                    return (false, 0, hint);
                }

                var label = preset switch
                {
                    FanCoolingPreset.BiosAuto => "Автоматический режим BIOS/драйвера",
                    FanCoolingPreset.Quiet => $"Тихий режим ({targetDuty:F0}% ШИМ)",
                    FanCoolingPreset.Balanced => $"Сбалансированный режим ({targetDuty:F0}% ШИМ)",
                    _ => "Максимальный обдув (100% ШИМ)"
                };

                return (true, affected, $"Профиль охлаждения «{label}» применён к каналам вентиляторов: {affected}.");
            }
            catch (Exception ex)
            {
                return (false, 0, $"Не удалось изменить профиль вентиляторов: {ex.Message}");
            }
            finally
            {
                try { computer?.Close(); } catch { }
            }
        }
    }

    private static IEnumerable<IHardware> EnumerateAllNodes(IComputer computer)
    {
        foreach (var hw in computer.Hardware)
        {
            yield return hw;
            foreach (var sub in hw.SubHardware)
            {
                yield return sub;
            }
        }
    }

    private static void SafeUpdateHardware(IHardware hw)
    {
        try { hw.Update(); } catch { }
    }

    private static void CollectFromHardwareNode(
        IHardware hw,
        bool pawnIoActive,
        bool includeAllRows,
        ref double? cpuTemp,
        ref double? cpuLoad,
        ref int? cpuMaxClock,
        ref double? cpuPower,
        ref double? cpuVolt,
        ref long? batDesignMwh,
        ref long? batFullMwh,
        List<GpuLhmTelemetry> gpus,
        List<HardwareSensorReading> readings,
        List<ControllableFanChannel> fans)
    {
        bool isCpu = hw.HardwareType == HardwareType.Cpu;
        bool isGpu = hw.HardwareType is HardwareType.GpuNvidia or HardwareType.GpuAmd or HardwareType.GpuIntel;
        bool isBattery = hw.HardwareType == HardwareType.Battery;
        string hwTitle = string.IsNullOrWhiteSpace(hw.Name) ? "Устройство" : hw.Name;

        double? gCoreTemp = null, gHotspot = null, gMemTemp = null, gPower = null;
        int? gFanPct = null, gFanRpm = null, gLoad = null, gCoreClk = null, gMemClk = null;

        var fanRpmsByIndex = new Dictionary<int, int>();
        int rpmCounter = 0;
        foreach (var s in hw.Sensors)
        {
            if (s.SensorType == SensorType.Fan && s.Value is > 0f)
            {
                fanRpmsByIndex[rpmCounter++] = (int)Math.Round(s.Value.Value);
            }
        }

        int ctrlCounter = 0;
        foreach (var sensor in hw.Sensors)
        {
            var sName = string.IsNullOrWhiteSpace(sensor.Name) ? "Датчик" : sensor.Name;

            if (sensor.SensorType == SensorType.Control)
            {
                if (sensor.Control is not null)
                {
                    fanRpmsByIndex.TryGetValue(ctrlCounter, out var pairedRpm);
                    fans.Add(new ControllableFanChannel(
                        ChannelId: sensor.Identifier.ToString(),
                        HardwareName: hwTitle,
                        FanName: sName,
                        CurrentDutyPercent: sensor.Value.HasValue ? (int)Math.Round(sensor.Value.Value) : null,
                        CurrentRpm: pairedRpm > 0 ? pairedRpm : null));
                    ctrlCounter++;
                }
            }

            if (sensor.Value is null || float.IsNaN(sensor.Value.Value) || float.IsInfinity(sensor.Value.Value))
            {
                continue;
            }

            double val = Math.Round(sensor.Value.Value, 3);

            // Без установленного PawnIO MSR-регистры CPU (температура, мощность, частота ядер) возвращают нулевые заглушки — не показываем фиктивные нули
            if (isCpu && !pawnIoActive && val <= 0.001 &&
                sensor.SensorType is SensorType.Temperature or SensorType.Power or SensorType.Clock)
            {
                continue;
            }

            if (isCpu)
            {
                if (sensor.SensorType == SensorType.Temperature && val is > 5 and < 125)
                {
                    if (!cpuTemp.HasValue ||
                        sName.Contains("Package", StringComparison.OrdinalIgnoreCase) ||
                        sName.Contains("Tctl", StringComparison.OrdinalIgnoreCase) ||
                        sName.Contains("Core Average", StringComparison.OrdinalIgnoreCase))
                    {
                        cpuTemp = Math.Round(val, 1);
                    }
                }
                else if (sensor.SensorType == SensorType.Load && sName.Contains("Total", StringComparison.OrdinalIgnoreCase))
                {
                    cpuLoad = Math.Round(val, 1);
                }
                else if (sensor.SensorType == SensorType.Clock && !sName.Contains("Bus", StringComparison.OrdinalIgnoreCase) && val > 200)
                {
                    int mhz = (int)Math.Round(val);
                    if (!cpuMaxClock.HasValue || mhz > cpuMaxClock.Value) cpuMaxClock = mhz;
                }
                else if (sensor.SensorType == SensorType.Power &&
                         (sName.Contains("Package", StringComparison.OrdinalIgnoreCase) || !cpuPower.HasValue))
                {
                    cpuPower = Math.Round(val, 1);
                }
                else if (sensor.SensorType == SensorType.Voltage && val is > 0.3 and < 2.2)
                {
                    cpuVolt = Math.Round(val, 3);
                }
            }
            else if (isGpu)
            {
                if (sensor.SensorType == SensorType.Temperature && val is > 5 and < 130)
                {
                    if (sName.Contains("Hot Spot", StringComparison.OrdinalIgnoreCase) || sName.Contains("HotSpot", StringComparison.OrdinalIgnoreCase))
                        gHotspot = Math.Round(val, 1);
                    else if (sName.Contains("Memory", StringComparison.OrdinalIgnoreCase))
                        gMemTemp = Math.Round(val, 1);
                    else if (!gCoreTemp.HasValue || sName.Contains("Core", StringComparison.OrdinalIgnoreCase))
                        gCoreTemp = Math.Round(val, 1);
                }
                else if (sensor.SensorType == SensorType.Fan && val >= 0)
                {
                    gFanRpm = (int)Math.Round(val);
                }
                else if (sensor.SensorType == SensorType.Control && val >= 0)
                {
                    gFanPct = (int)Math.Round(val);
                }
                else if (sensor.SensorType == SensorType.Power && val > 0)
                {
                    if (!gPower.HasValue || val > gPower.Value) gPower = Math.Round(val, 1);
                }
                else if (sensor.SensorType == SensorType.Load &&
                         (sName.Contains("Core", StringComparison.OrdinalIgnoreCase) || sName.Contains("D3D 3D", StringComparison.OrdinalIgnoreCase)))
                {
                    int ld = (int)Math.Round(val);
                    if (!gLoad.HasValue || ld > gLoad.Value) gLoad = ld;
                }
                else if (sensor.SensorType == SensorType.Clock && val > 50)
                {
                    if (sName.Contains("Memory", StringComparison.OrdinalIgnoreCase))
                        gMemClk = (int)Math.Round(val);
                    else if (sName.Contains("Core", StringComparison.OrdinalIgnoreCase) || !gCoreClk.HasValue)
                        gCoreClk = (int)Math.Round(val);
                }
            }
            else if (isBattery && sensor.SensorType == SensorType.Energy)
            {
                if (sName.Contains("Designed", StringComparison.OrdinalIgnoreCase))
                    batDesignMwh = (long)Math.Round(val);
                else if (sName.Contains("Full", StringComparison.OrdinalIgnoreCase))
                    batFullMwh = (long)Math.Round(val);
            }

            if (includeAllRows && TryMapSensorCategory(sensor.SensorType, out var cat, out var unit))
            {
                double? minV = sensor.Min is { } mn && !float.IsNaN(mn) ? Math.Round(mn, 3) : null;
                double? maxV = sensor.Max is { } mx && !float.IsNaN(mx) ? Math.Round(mx, 3) : null;
                readings.Add(new HardwareSensorReading(
                    HardwareGroup: hwTitle,
                    SensorName: sName,
                    Category: cat,
                    CurrentValue: val,
                    MinValue: minV,
                    MaxValue: maxV,
                    Unit: unit));
            }
        }

        if (isGpu)
        {
            gpus.Add(new GpuLhmTelemetry(
                Name: hwTitle,
                Type: hw.HardwareType,
                CoreTempC: gCoreTemp,
                HotspotTempC: gHotspot,
                MemoryTempC: gMemTemp,
                FanPercent: gFanPct,
                FanRpm: gFanRpm,
                PowerWatts: gPower,
                CoreLoadPercent: gLoad,
                CoreClockMhz: gCoreClk,
                MemClockMhz: gMemClk));
        }
    }

    private static bool TryMapSensorCategory(SensorType lhmType, out SensorCategory category, out string unit)
    {
        switch (lhmType)
        {
            case SensorType.Temperature:
                category = SensorCategory.Temperature;
                unit = "°C";
                return true;
            case SensorType.Voltage:
                category = SensorCategory.Voltage;
                unit = "В";
                return true;
            case SensorType.Fan:
                category = SensorCategory.Fan;
                unit = "об/мин";
                return true;
            case SensorType.Power:
                category = SensorCategory.Power;
                unit = "Вт";
                return true;
            case SensorType.Clock:
                category = SensorCategory.Clock;
                unit = "МГц";
                return true;
            case SensorType.Load:
                category = SensorCategory.Load;
                unit = "%";
                return true;
            case SensorType.Control:
                category = SensorCategory.Control;
                unit = "%";
                return true;
            default:
                category = SensorCategory.Data;
                unit = "";
                return false;
        }
    }

    private static LhmSnapshotSummary EmptySummary() => new(
        BackendState: PawnIoBackendState.UserModeOnly,
        BackendHeadline: "Датчики недоступны в текущей среде.",
        CpuPackageTempC: null,
        CpuTotalLoadPercent: null,
        CpuMaxClockMhz: null,
        CpuPackagePowerWatts: null,
        CpuCoreVoltageVolts: null,
        BatteryDesignMwh: null,
        BatteryFullChargeMwh: null,
        Gpus: Array.Empty<GpuLhmTelemetry>(),
        AllReadings: Array.Empty<HardwareSensorReading>(),
        ControllableFans: Array.Empty<ControllableFanChannel>());
}
