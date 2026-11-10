using UltimateWindows.Modules.Hardware.Models;

namespace UltimateWindows.Modules.Hardware.Analysis;

public sealed record HardwareAuditSummary(
    int HardwareHealthScore,
    IReadOnlyList<HardwareAdvisoryFinding> Findings);

/// <summary>
/// Интеллектуальный анализатор конфигурации железа (Hardware Bottleneck &amp; Misconfiguration Advisor).
/// Превращает сотни сырых параметров AIDA64/SMBIOS/EDID/S.M.A.R.T. в понятные пользователю советы и авто-исправления.
/// </summary>
public static class HardwareBottleneckAdvisor
{
    public static HardwareAuditSummary Analyze(HardwareSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        var findings = new List<HardwareAdvisoryFinding>();
        var score = 100;

        // 1. Проверка герцовки мониторов (например, 144/165/240 Гц матрица заблокирована на 60 Гц)
        foreach (var mon in snapshot.Monitors)
        {
            if (mon.MaxSupportedRefreshHz >= 90 && mon.CurrentRefreshHz <= mon.MaxSupportedRefreshHz - 25)
            {
                score -= 10;
                findings.Add(new HardwareAdvisoryFinding(
                    Code: AdvisoryCode.MonitorRefreshSuboptimal,
                    Severity: AdvisorySeverity.PerformanceGain,
                    SimpleTitle: $"Монитор «{mon.FriendlyModelName}» работает на {mon.CurrentRefreshHz} Гц вместо {mon.MaxSupportedRefreshHz} Гц",
                    SimpleExplanation: $"Ваш экран поддерживает плавную частоту {mon.MaxSupportedRefreshHz} Гц, но в настройках системы сейчас выбрано {mon.CurrentRefreshHz} Гц. Нажмите кнопку ниже, чтобы мгновенно включить максимальную плавность изображения.",
                    ExpertTelemetryDetails: $"Device={mon.GdiDeviceName}, Resolution={mon.NativeWidthPx}x{mon.NativeHeightPx}, Current={mon.CurrentRefreshHz}Hz, MaxSupported(EDID/GDI)={mon.MaxSupportedRefreshHz}Hz",
                    EstimatedImpactBadge: $"Плавность +{mon.MaxSupportedRefreshHz - mon.CurrentRefreshHz} Гц",
                    CanAutoFixInOneClick: true,
                    AutoFixActionLabel: $"Включить {mon.MaxSupportedRefreshHz} Гц в 1 клик",
                    TargetDeviceId: mon.GdiDeviceName,
                    TargetValue: mon.MaxSupportedRefreshHz));
            }
        }

        // 2. Проверка профиля памяти XMP / EXPO (заниженная частота ОЗУ)
        var mem = snapshot.Memory;
        if (mem.ConfiguredSpeedMtPerSec > 0 && mem.MaxRatedSpeedMtPerSec > mem.ConfiguredSpeedMtPerSec + 200)
        {
            score -= 8;
            findings.Add(new HardwareAdvisoryFinding(
                Code: AdvisoryCode.MemoryXmpOrExpoDisabled,
                Severity: AdvisorySeverity.PerformanceGain,
                SimpleTitle: $"Оперативная память работает не в полную силу ({mem.ConfiguredSpeedMtPerSec} вместо {mem.MaxRatedSpeedMtPerSec} МГц)",
                SimpleExplanation: "Ваши модули памяти способны работать быстрее, но в BIOS материнской платы не включен профиль разгона по паспорту (XMP для Intel / EXPO или DOCP для AMD). Включение этого пункта в BIOS ускорит игры и программы на 10–20%.",
                ExpertTelemetryDetails: $"SMBIOS Type 17: Generation={mem.MemoryGeneration}, ConfiguredMemorySpeed={mem.ConfiguredSpeedMtPerSec} MT/s < RatedSpeed={mem.MaxRatedSpeedMtPerSec} MT/s",
                EstimatedImpactBadge: "+10..20% к скорости CPU/игр",
                CanAutoFixInOneClick: false,
                AutoFixActionLabel: null));
        }

        // 3. Проверка двухканального режима ОЗУ (неправильные слоты или 1 планка)
        if (mem.PopulatedSlotsCount >= 2 && !mem.IsDualOrMultiChannelActive)
        {
            score -= 12;
            var occupied = string.Join(", ", mem.Modules.Where(m => m.IsPopulated).Select(m => m.DeviceLocator));
            findings.Add(new HardwareAdvisoryFinding(
                Code: AdvisoryCode.MemorySingleChannelMisplaced,
                Severity: AdvisorySeverity.Warning,
                SimpleTitle: "Планки памяти установлены в соседние слоты одного канала (потеря скорости!)",
                SimpleExplanation: $"У вас установлено несколько модулей памяти ({occupied}), но они стоят в одном канале вместо двухканального режима. Обычно планки нужно ставить через один слот (в разъемы A2 и B2 на плате) — это удваивает пропускную способность памяти.",
                ExpertTelemetryDetails: $"PopulatedSlots={mem.PopulatedSlotsCount}/{mem.TotalSlotsCount}, Locators=[{occupied}], DualChannelInferred=False",
                EstimatedImpactBadge: "Удвоение шины ОЗУ",
                CanAutoFixInOneClick: false,
                AutoFixActionLabel: null));
        }

        // 4. Проверка видеокарт: урезанные линии PCIe, Resizable BAR и перегрев Hotspot (высохшая термопаста)
        foreach (var gpu in snapshot.Gpus)
        {
            if (gpu.MaxPcieLanes is >= 16 && gpu.CurrentPcieLanes is > 0 and <= 8)
            {
                score -= 7;
                findings.Add(new HardwareAdvisoryFinding(
                    Code: AdvisoryCode.GpuPcieLinkDegraded,
                    Severity: AdvisorySeverity.Warning,
                    SimpleTitle: $"Видеокарта {gpu.Name} работает в урезанном режиме разъема (PCIe x{gpu.CurrentPcieLanes} вместо x{gpu.MaxPcieLanes})",
                    SimpleExplanation: "Видеокарта использует не все линии связи с процессором. Проверьте, что она установлена в самый верхний разъем материнской платы ближе к процессору, либо убедитесь, что линии не делятся с лишним накопителем M.2.",
                    ExpertTelemetryDetails: $"GPU#{gpu.Index}: CurrentLink=Gen{gpu.CurrentPcieGen ?? 0} x{gpu.CurrentPcieLanes}, MaxSupported=Gen{gpu.MaxPcieGen ?? 0} x{gpu.MaxPcieLanes}",
                    EstimatedImpactBadge: "Полная пропускная способность GPU",
                    CanAutoFixInOneClick: false,
                    AutoFixActionLabel: null));
            }

            if (gpu.IsResizableBarEnabled == false && gpu.DedicatedVramBytes >= 6L * 1024 * 1024 * 1024)
            {
                score -= 4;
                findings.Add(new HardwareAdvisoryFinding(
                    Code: AdvisoryCode.ResizableBarDisabled,
                    Severity: AdvisorySeverity.PerformanceGain,
                    SimpleTitle: $"Для видеокарты {gpu.Name} не активна функция Resizable BAR",
                    SimpleExplanation: "Современные видеокарты позволяют процессору обращаться сразу ко всей видеопамяти целиком. Включите в BIOS пункты «Above 4G Decoding» и «Re-Size BAR Support» для бесплатной прибавки кадров в современных играх.",
                    ExpertTelemetryDetails: $"GPU={gpu.Name}, VRAM={gpu.FormattedVram}, ResizableBAR=Disabled",
                    EstimatedImpactBadge: "+3..12% FPS в играх",
                    CanAutoFixInOneClick: false,
                    AutoFixActionLabel: null));
            }

            if (gpu.CoreTemperatureC.HasValue && gpu.HotspotTemperatureC.HasValue)
            {
                var delta = gpu.HotspotTemperatureC.Value - gpu.CoreTemperatureC.Value;
                if (gpu.HotspotTemperatureC.Value >= 98.0 || delta >= 23.0)
                {
                    score -= 15;
                    findings.Add(new HardwareAdvisoryFinding(
                        Code: AdvisoryCode.ThermalHotspotOrThrottling,
                        Severity: AdvisorySeverity.Critical,
                        SimpleTitle: $"Высокий нагрев кристалла видеокарты {gpu.Name} (Hotspot {gpu.HotspotTemperatureC.Value:F0}°C)",
                        SimpleExplanation: $"Разница между общей температурой чипа ({gpu.CoreTemperatureC.Value:F0}°C) и самой горячей точкой ({gpu.HotspotTemperatureC.Value:F0}°C) составляет {delta:F0}°C. Это классический признак высохшей термопасты или забитого пылью радиатора.",
                        ExpertTelemetryDetails: $"GPU Core={gpu.CoreTemperatureC.Value:F1}°C, Hotspot={gpu.HotspotTemperatureC.Value:F1}°C, Delta={delta:F1}°C (норма <= 15..18°C)",
                        EstimatedImpactBadge: "Защита от перегрева",
                        CanAutoFixInOneClick: false,
                        AutoFixActionLabel: null));
                }
            }
            else if (gpu.CoreTemperatureC is >= 86.0)
            {
                score -= 12;
                findings.Add(new HardwareAdvisoryFinding(
                    Code: AdvisoryCode.ThermalHotspotOrThrottling,
                    Severity: AdvisorySeverity.Warning,
                    SimpleTitle: $"Повышенная температура видеокарты {gpu.Name} ({gpu.CoreTemperatureC.Value:F0}°C)",
                    SimpleExplanation: "Видеокарта нагревается близко к порогу сброса частот. Рекомендуется продуть систему охлаждения от пыли и проверить работу корпусных вентиляторов.",
                    ExpertTelemetryDetails: $"GPU CoreTemp={gpu.CoreTemperatureC.Value:F1}°C >= 86°C",
                    EstimatedImpactBadge: "Снижение шума и нагрева",
                    CanAutoFixInOneClick: false,
                    AutoFixActionLabel: null));
            }
        }

        if (snapshot.Cpu.PackageTemperatureC is >= 90.0)
        {
            score -= 14;
            findings.Add(new HardwareAdvisoryFinding(
                Code: AdvisoryCode.ThermalHotspotOrThrottling,
                Severity: AdvisorySeverity.Critical,
                SimpleTitle: $"Перегрев процессора ({snapshot.Cpu.PackageTemperatureC.Value:F0}°C)",
                SimpleExplanation: "Процессор работает на грани теплового троттлинга и принудительно снижает скорость. Проверьте прижим кулера, работу помпы СЖО и состояние термопасты.",
                ExpertTelemetryDetails: $"CPU Package={snapshot.Cpu.PackageTemperatureC.Value:F1}°C >= 90°C",
                EstimatedImpactBadge: "Критично для стабильности",
                CanAutoFixInOneClick: false,
                AutoFixActionLabel: null));
        }

        // 5. Проверка здоровья накопителей S.M.A.R.T. и кабелей SATA
        foreach (var drive in snapshot.Drives)
        {
            if (!drive.IsHealthy || drive.MediaIntegrityErrors is > 0 || drive.ReallocatedSectors is > 0 || drive.RemainingLifePercent is < 15)
            {
                score -= 22;
                findings.Add(new HardwareAdvisoryFinding(
                    Code: AdvisoryCode.StorageSmartWarning,
                    Severity: AdvisorySeverity.Critical,
                    SimpleTitle: $"Тревога S.M.A.R.T. на накопителе «{drive.Model}» — сохраните важные файлы!",
                    SimpleExplanation: "Датчики самодиагностики диска зафиксировали износ ячеек или поврежденные сектора. Настоятельно рекомендуем скопировать ценные документы и фото на другой носитель.",
                    ExpertTelemetryDetails: $"Drive#{drive.DriveIndex} ({drive.BusKind}): Healthy={drive.IsHealthy}, Life={drive.RemainingLifePercent?.ToString() ?? "N/A"}%, MediaErrors={drive.MediaIntegrityErrors ?? 0}, Reallocated={drive.ReallocatedSectors ?? 0}",
                    EstimatedImpactBadge: "Сохранность данных!",
                    CanAutoFixInOneClick: false,
                    AutoFixActionLabel: null));
            }
            else if (drive.UltraDmaCrcErrors is >= 10)
            {
                score -= 8;
                findings.Add(new HardwareAdvisoryFinding(
                    Code: AdvisoryCode.StorageSmartWarning,
                    Severity: AdvisorySeverity.Warning,
                    SimpleTitle: $"Ошибки передачи данных по кабелю диска «{drive.Model}» ({drive.UltraDmaCrcErrors} ошибок CRC)",
                    SimpleExplanation: "Сам диск исправен, но при передаче данных по SATA-проводу возникают помехи (зависания системы). Достаточно плотнее вставить или заменить недорогой кабель SATA.",
                    ExpertTelemetryDetails: $"ATA SMART Attr 0xC7 (UltraDMA CRC Error Count) = {drive.UltraDmaCrcErrors}",
                    EstimatedImpactBadge: "Устранение микрофризов",
                    CanAutoFixInOneClick: false,
                    AutoFixActionLabel: null));
            }
        }

        // 6. Проверка задушенной схемы электропитания при работе от розетки
        var onAcPower = !snapshot.Battery.IsPresent || snapshot.Battery.IsOnAcPower;
        if (onAcPower && snapshot.ActivePowerPlan.IsPowerSaver)
        {
            score -= 10;
            // Стандартный GUID сбалансированной / высокопроизводительной схемы Windows: 381b4222-f694-41f0-9685-ff5bb260df2e (Balanced) / 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c (High Performance)
            findings.Add(new HardwareAdvisoryFinding(
                Code: AdvisoryCode.PowerPlanThrottling,
                Severity: AdvisorySeverity.PerformanceGain,
                SimpleTitle: "Компьютер подключен к сети, но зажат режимом «Экономия энергии»",
                SimpleExplanation: "Режим жесткой экономии батареи принудительно режет частоту процессора и отклик программ, хотя ПК сейчас питается от розетки. Переключите профиль питания в 1 клик (с возможностью отката).",
                ExpertTelemetryDetails: $"ActiveScheme={snapshot.ActivePowerPlan.SchemeGuid} ({snapshot.ActivePowerPlan.FriendlyName}), OnACPower=True",
                EstimatedImpactBadge: "Полная частота Turbo Boost",
                CanAutoFixInOneClick: true,
                AutoFixActionLabel: "Включить оптимальный режим питания",
                TargetDeviceId: "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"));
        }

        // 7. Проверка сильного износа батареи ноутбука
        if (snapshot.Battery.IsPresent && snapshot.Battery.WearLevelPercent is >= 35.0)
        {
            score -= 6;
            findings.Add(new HardwareAdvisoryFinding(
                Code: AdvisoryCode.BatteryWearHigh,
                Severity: AdvisorySeverity.Info,
                SimpleTitle: $"Аккумулятор ноутбука изношен на {snapshot.Battery.WearLevelPercent.Value:F0}%",
                SimpleExplanation: $"Текущая реальная емкость батареи ({snapshot.Battery.FullChargeCapacityMwh} мВт·ч) заметно ниже заводской ({snapshot.Battery.DesignCapacityMwh} мВт·ч). Это естественно для возраста аккумулятора и объясняет быструю разрядку без розетки.",
                ExpertTelemetryDetails: $"DesignCapacity={snapshot.Battery.DesignCapacityMwh} mWh, FullChargeCapacity={snapshot.Battery.FullChargeCapacityMwh} mWh, Wear={snapshot.Battery.WearLevelPercent.Value:F1}%",
                EstimatedImpactBadge: "Справка о ресурсе АКБ",
                CanAutoFixInOneClick: false,
                AutoFixActionLabel: null));
        }

        var boundedScore = Math.Clamp(score, 15, 100);
        var ordered = findings
            .OrderByDescending(f => f.Severity)
            .ThenByDescending(f => f.CanAutoFixInOneClick)
            .ToList();

        return new HardwareAuditSummary(boundedScore, ordered);
    }
}
