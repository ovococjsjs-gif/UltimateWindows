using System.Net;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using UltimateWindows.Core.Models;
using UltimateWindows.Modules.Hardware.Analysis;
using UltimateWindows.Modules.Hardware.Models;

namespace UltimateWindows.Modules.Hardware.Reporting;

/// <summary>
/// Генератор полных инженерных отчётов о железе, датчиках и бенчмарках уровня AIDA64
/// в трёх автономных форматах: HTML (тёмная адаптивная верстка без внешних зависимостей), JSON и TXT.
/// </summary>
public static class HardwareReportExporter
{
    public static string BuildReportContent(
        HardwareReportFormat format,
        HardwareSnapshot snapshot,
        HardwareAuditSummary audit,
        HardwareSensorInventory? sensors = null,
        HardwareBenchmarkSuiteReport? benchmarks = null) =>
        format switch
        {
            HardwareReportFormat.Json => BuildJsonReport(snapshot, audit, sensors, benchmarks),
            HardwareReportFormat.Txt => BuildPlainTextReport(snapshot, audit, sensors, benchmarks),
            _ => BuildHtmlReport(snapshot, audit, sensors, benchmarks)
        };

    public static async Task<string> ExportToFileAsync(
        string filePath,
        HardwareReportFormat format,
        HardwareSnapshot snapshot,
        HardwareAuditSummary audit,
        HardwareSensorInventory? sensors = null,
        HardwareBenchmarkSuiteReport? benchmarks = null,
        CancellationToken ct = default)
    {
        var fullPath = Path.GetFullPath(filePath);
        var dir = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(dir))
        {
            Directory.CreateDirectory(dir);
        }

        var content = BuildReportContent(format, snapshot, audit, sensors, benchmarks);
        await File.WriteAllTextAsync(fullPath, content, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), ct).ConfigureAwait(false);
        return fullPath;
    }

    private static string BuildJsonReport(
        HardwareSnapshot snapshot,
        HardwareAuditSummary audit,
        HardwareSensorInventory? sensors,
        HardwareBenchmarkSuiteReport? benchmarks)
    {
        var payload = new
        {
            GeneratedBy = "UltimateWindows v2.0 Hardware Studio",
            GeneratedAtUtc = DateTimeOffset.UtcNow,
            HealthScore = audit.HardwareHealthScore,
            Advisories = audit.Findings,
            Snapshot = snapshot,
            Sensors = sensors,
            Benchmarks = benchmarks
        };

        return JsonSerializer.Serialize(payload, new JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            Converters = { new JsonStringEnumConverter() }
        });
    }

    private static string BuildPlainTextReport(
        HardwareSnapshot s,
        HardwareAuditSummary audit,
        HardwareSensorInventory? sensors,
        HardwareBenchmarkSuiteReport? bench)
    {
        var sb = new StringBuilder(8192);
        sb.AppendLine("================================================================================");
        sb.AppendLine("  ULTIMATE WINDOWS v2.0 — ПОЛНЫЙ АППАРАТНЫЙ ПАСПОРТ И ОТЧЁТ ДАТЧИКОВ ПК");
        sb.AppendLine($"  Дата формирования (UTC): {s.CapturedAtUtc:yyyy-MM-dd HH:mm:ss} | Индекс железа: {audit.HardwareHealthScore}/100");
        sb.AppendLine("================================================================================");
        sb.AppendLine();

        sb.AppendLine("[ПРОЦЕССОР (CPU)]");
        sb.AppendLine($"  Модель           : {s.Cpu.BrandName} ({s.Cpu.Vendor})");
        sb.AppendLine($"  Топология        : {s.Cpu.PhysicalCores} физ. ядер / {s.Cpu.LogicalProcessors} потоков (P={s.Cpu.PerformanceCores}, E={s.Cpu.EfficientCores})");
        sb.AppendLine($"  Семейство/Степ.  : Family {s.Cpu.Family}, Model {s.Cpu.Model}, Stepping {s.Cpu.Stepping}");
        sb.AppendLine($"  Кэш L1 / L2 / L3 : {ByteFormatter.Format(s.Cpu.L1CacheBytes)} / {ByteFormatter.Format(s.Cpu.L2CacheBytes)} / {ByteFormatter.Format(s.Cpu.L3CacheBytes)}");
        sb.AppendLine($"  Частота / Нарев  : Базовая {s.Cpu.BaseClockMhz} МГц, Текущая {s.Cpu.CurrentClockMhz} МГц, Темп.: {(s.Cpu.PackageTemperatureC?.ToString("F1") ?? "н/д")} °C");
        sb.AppendLine($"  Инструкции ISA   : {string.Join(", ", s.Cpu.InstructionSets)}");
        sb.AppendLine();

        sb.AppendLine("[МАТЕРИНСКАЯ ПЛАТА И BIOS (SMBIOS)]");
        sb.AppendLine($"  Плата            : {s.Motherboard.BoardManufacturer} {s.Motherboard.BoardProduct} ({s.Motherboard.BoardVersion})");
        sb.AppendLine($"  BIOS / UEFI      : {s.Motherboard.BiosVendor} {s.Motherboard.BiosVersion} ({s.Motherboard.BiosReleaseDate}) | SMBIOS {s.Motherboard.SmbiosMajorVersion}.{s.Motherboard.SmbiosMinorVersion}");
        sb.AppendLine($"  Схема питания    : {s.ActivePowerPlan.FriendlyName} ({s.ActivePowerPlan.SchemeGuid})");
        sb.AppendLine();

        sb.AppendLine("[ОПЕРАТИВНАЯ ПАМЯТЬ (RAM / SPD)]");
        sb.AppendLine($"  Объём            : {s.Memory.FormattedTotal} (доступно {s.Memory.FormattedAvailable})");
        sb.AppendLine($"  Режим и частота  : {s.Memory.MemoryGeneration} @ {s.Memory.ConfiguredSpeedMtPerSec} МТ/с (паспорт {s.Memory.MaxRatedSpeedMtPerSec} МТ/с) | Двухканал: {(s.Memory.IsDualOrMultiChannelActive ? "Да" : "Нет")}");
        foreach (var m in s.Memory.Modules.Where(x => x.IsPopulated))
        {
            sb.AppendLine($"    - Слот {m.DeviceLocator} ({m.BankLocator}): {m.FormattedCapacity} {m.MemoryType} @ {m.ConfiguredSpeedMtPerSec} МТ/с | {m.Manufacturer} {m.PartNumber} | {m.ProfileAndSpecBadge}");
        }
        sb.AppendLine();

        sb.AppendLine("[ВИДЕОКАРТЫ (GPU)]");
        foreach (var g in s.Gpus)
        {
            sb.AppendLine($"  #{g.Index} {g.Name} ({g.Vendor}) | VRAM: {g.FormattedVram} | Драйвер: {g.DriverVersion}");
            sb.AppendLine($"      PCIe: Gen{g.CurrentPcieGen?.ToString() ?? "?"} x{g.CurrentPcieLanes?.ToString() ?? "?"} | ReBAR: {(g.IsResizableBarEnabled switch { true => "ВКЛ", false => "выкл", null => "н/д" })} | Темп.: {(g.CoreTemperatureC?.ToString("F0") ?? "н/д")}°C | Мощность: {(g.PowerDrawWatts?.ToString("F1") ?? "н/д")} Вт");
        }
        sb.AppendLine();

        sb.AppendLine("[НАКОПИТЕЛИ (S.M.A.R.T.)]");
        foreach (var d in s.Drives)
        {
            sb.AppendLine($"  #{d.DriveIndex} {d.Model} ({d.FormattedCapacity}, {d.BusKind}) | Здоровье: {(d.IsHealthy ? "OK" : "ТРЕВОГА")} | Ресурс: {d.RemainingLifePercent?.ToString() ?? "—"}% | Темп.: {d.TemperatureC?.ToString() ?? "—"}°C | Запись: {d.TotalBytesWrittenTb?.ToString("F1") ?? "—"} ТБ");
        }
        sb.AppendLine();

        sb.AppendLine("[МОНИТОРЫ (EDID)]");
        foreach (var mon in s.Monitors)
        {
            sb.AppendLine($"  {mon.FriendlyModelName} ({mon.ManufacturerCode}) — {mon.NativeWidthPx}x{mon.NativeHeightPx} @ {mon.CurrentRefreshHz} Гц (макс. {mon.MaxSupportedRefreshHz} Гц)");
        }
        sb.AppendLine();

        if (audit.Findings.Count > 0)
        {
            sb.AppendLine("[РЕКОМЕНДАЦИИ УМНОГО СОВЕТНИКА]");
            foreach (var f in audit.Findings)
            {
                sb.AppendLine($"  * [{f.Severity}] {f.SimpleTitle} ({f.EstimatedImpactBadge})");
                sb.AppendLine($"      {f.SimpleExplanation}");
            }
            sb.AppendLine();
        }

        if (sensors is not null && sensors.Readings.Count > 0)
        {
            sb.AppendLine($"[ДАТЧИКИ В РЕАЛЬНОМ ВРЕМЕНИ — {sensors.BackendHeadline}]");
            foreach (var r in sensors.Readings)
            {
                sb.AppendLine($"  [{r.CategoryBadge,-11}] {r.HardwareGroup,-28} | {r.SensorName,-28} : {r.FormattedCurrent,12} (мин {r.FormattedMin}, макс {r.FormattedMax})");
            }
            sb.AppendLine();
        }

        if (bench is not null)
        {
            sb.AppendLine($"[РЕЗУЛЬТАТЫ ЭКСПРЕСС-БЕНЧМАРКА ПК — ОБЩИЙ ИНДЕКС: {bench.CompositeScore} БАЛЛ. ({bench.OverallTierBadge})]");
            if (bench.Cpu is not null) sb.AppendLine($"  CPU    : {bench.Cpu.SummaryLine}");
            if (bench.Gpu is not null) sb.AppendLine($"  GPU    : {bench.Gpu.SummaryLine}");
            if (bench.Memory is not null) sb.AppendLine($"  RAM    : {bench.Memory.SummaryLine}");
            if (bench.Storage is not null) sb.AppendLine($"  Диск   : {bench.Storage.SummaryLine}");
            sb.AppendLine();
        }

        return sb.ToString();
    }

    private static string BuildHtmlReport(
        HardwareSnapshot s,
        HardwareAuditSummary audit,
        HardwareSensorInventory? sensors,
        HardwareBenchmarkSuiteReport? bench)
    {
        static string H(string? text) => WebUtility.HtmlEncode(text ?? "");

        var sb = new StringBuilder(16384);
        sb.AppendLine("<!DOCTYPE html><html lang=\"ru\"><head><meta charset=\"utf-8\">");
        sb.AppendLine($"<title>Аппаратный отчёт ПК — {H(s.Cpu.BrandName)}</title>");
        sb.AppendLine("""
            <style>
              body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #e6edf3; margin: 0; padding: 24px; line-height: 1.5; }
              .wrap { max-width: 1180px; margin: 0 auto; }
              .hdr { background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 18px 22px; margin-bottom: 18px; display: flex; justify-content: space-between; align-items: center; }
              .score { background: #1f6feb22; border: 1px solid #58a6ff; color: #58a6ff; padding: 8px 16px; border-radius: 8px; font-weight: 700; font-size: 18px; }
              .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; margin-bottom: 18px; }
              .card { background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 14px 16px; }
              .card h3 { margin: 0 0 6px 0; font-size: 12px; text-transform: uppercase; color: #58a6ff; letter-spacing: 0.5px; }
              .card .val { font-size: 14px; font-weight: 600; margin-bottom: 4px; }
              .card .sub { font-size: 12px; color: #8b949e; font-family: Consolas, monospace; }
              h2 { font-size: 16px; margin: 20px 0 8px 0; color: #c9d1d9; }
              table { width: 100%; border-collapse: collapse; background: #161b22; border: 1px solid #30363d; border-radius: 8px; overflow: hidden; margin-bottom: 16px; font-size: 13px; }
              th { background: #21262d; color: #8b949e; text-align: left; padding: 8px 12px; font-weight: 600; }
              td { padding: 8px 12px; border-top: 1px solid #21262d; }
              .adv { background: #1c2128; border-left: 4px solid #d29922; padding: 10px 14px; border-radius: 6px; margin-bottom: 8px; }
            </style></head><body><div class="wrap">
            """);

        sb.AppendLine($"<div class=\"hdr\"><div><h1 style=\"margin:0;font-size:20px;\">UltimateWindows — Аппаратный паспорт и телеметрия ПК</h1><div style=\"color:#8b949e;font-size:12.5px;\">Сформировано: {s.CapturedAtUtc:yyyy-MM-dd HH:mm:ss} UTC • Схема питания: {H(s.ActivePowerPlan.FriendlyName)}</div></div><div class=\"score\">Индекс железа: {audit.HardwareHealthScore} / 100</div></div>");

        if (audit.Findings.Count > 0)
        {
            sb.AppendLine("<h2>Рекомендации Умного советника</h2>");
            foreach (var f in audit.Findings)
            {
                sb.AppendLine($"<div class=\"adv\"><strong>{H(f.SimpleTitle)}</strong> <span style=\"color:#58a6ff;\">({H(f.EstimatedImpactBadge)})</span><div style=\"color:#8b949e;font-size:12.5px;margin-top:3px;\">{H(f.SimpleExplanation)}</div></div>");
            }
        }

        sb.AppendLine("<div class=\"grid\">");
        sb.AppendLine($"<div class=\"card\"><h3>Процессор (CPU)</h3><div class=\"val\">{H(s.Cpu.BrandName)}</div><div class=\"sub\">{s.Cpu.PhysicalCores}C / {s.Cpu.LogicalProcessors}T • L3 {H(ByteFormatter.Format(s.Cpu.L3CacheBytes))} • {s.Cpu.CurrentClockMhz} МГц</div></div>");
        sb.AppendLine($"<div class=\"card\"><h3>Плата и BIOS</h3><div class=\"val\">{H(s.Motherboard.BoardManufacturer)} {H(s.Motherboard.BoardProduct)}</div><div class=\"sub\">BIOS {H(s.Motherboard.BiosVersion)} ({H(s.Motherboard.BiosReleaseDate)})</div></div>");
        sb.AppendLine($"<div class=\"card\"><h3>Память (RAM)</h3><div class=\"val\">{H(s.Memory.FormattedTotal)} {H(s.Memory.MemoryGeneration)} @ {s.Memory.ConfiguredSpeedMtPerSec} МТ/с</div><div class=\"sub\">Каналов: {(s.Memory.IsDualOrMultiChannelActive ? "2+" : "1")} • Слотов: {s.Memory.PopulatedSlotsCount}/{s.Memory.TotalSlotsCount}</div></div>");
        sb.AppendLine("</div>");

        if (bench is not null)
        {
            sb.AppendLine($"<h2>Результаты экспресс-бенчмарка (Индекс: {bench.CompositeScore} балл. — {H(bench.OverallTierBadge)})</h2>");
            sb.AppendLine("<table><tr><th>Подсистема</th><th>Результат и пропускная способность</th><th>Класс</th></tr>");
            if (bench.Cpu is not null) sb.AppendLine($"<tr><td>Процессор (CPU)</td><td>{H(bench.Cpu.SummaryLine)}</td><td>{H(bench.Cpu.TierBadge)}</td></tr>");
            if (bench.Gpu is not null) sb.AppendLine($"<tr><td>Видеокарта (GPU)</td><td>{H(bench.Gpu.SummaryLine)}</td><td>{H(bench.Gpu.TierBadge)}</td></tr>");
            if (bench.Memory is not null) sb.AppendLine($"<tr><td>Память (RAM)</td><td>{H(bench.Memory.SummaryLine)}</td><td>{H(bench.Memory.TierBadge)}</td></tr>");
            if (bench.Storage is not null) sb.AppendLine($"<tr><td>Накопитель</td><td>{H(bench.Storage.SummaryLine)}</td><td>{H(bench.Storage.TierBadge)}</td></tr>");
            sb.AppendLine("</table>");
        }

        sb.AppendLine("<h2>Модули оперативной памяти (SMBIOS / SPD)</h2><table><tr><th>Слот</th><th>Объём и тип</th><th>Частота (тек. / паспорт)</th><th>Производитель и модуль</th><th>Профиль и напряжение</th></tr>");
        foreach (var m in s.Memory.Modules.Where(x => x.IsPopulated))
        {
            sb.AppendLine($"<tr><td>{H(m.DeviceLocator)}</td><td>{H(m.FormattedCapacity)} {H(m.MemoryType)}</td><td>{m.ConfiguredSpeedMtPerSec} / {m.RatedSpeedMtPerSec} МТ/с</td><td>{H(m.Manufacturer)} {H(m.PartNumber)}</td><td>{H(m.ProfileAndSpecBadge)}</td></tr>");
        }
        sb.AppendLine("</table>");

        sb.AppendLine("<h2>Видеокарты и накопители S.M.A.R.T.</h2><table><tr><th>Узел</th><th>Характеристики</th><th>Температура / Ресурс</th></tr>");
        foreach (var g in s.Gpus)
        {
            sb.AppendLine($"<tr><td>GPU #{g.Index}: {H(g.Name)}</td><td>VRAM {H(g.FormattedVram)} • Драйвер {H(g.DriverVersion)} • PCIe Gen{g.CurrentPcieGen?.ToString() ?? "?"} x{g.CurrentPcieLanes?.ToString() ?? "?"}</td><td>{(g.CoreTemperatureC?.ToString("F0") ?? "—")} °C • {(g.PowerDrawWatts?.ToString("F1") ?? "—")} Вт</td></tr>");
        }
        foreach (var d in s.Drives)
        {
            sb.AppendLine($"<tr><td>Диск #{d.DriveIndex}: {H(d.Model)}</td><td>{H(d.FormattedCapacity)} ({d.BusKind}) • FW {H(d.FirmwareRevision)}</td><td>{(d.TemperatureC?.ToString() ?? "—")} °C • Ресурс {(d.RemainingLifePercent?.ToString() ?? "—")}% • Запись {(d.TotalBytesWrittenTb?.ToString("F1") ?? "—")} ТБ</td></tr>");
        }
        sb.AppendLine("</table>");

        if (sensors is not null && sensors.Readings.Count > 0)
        {
            sb.AppendLine($"<h2>Датчики ({H(sensors.BackendHeadline)})</h2><table><tr><th>Тип</th><th>Узел</th><th>Датчик</th><th>Текущее</th><th>Мин</th><th>Макс</th></tr>");
            foreach (var r in sensors.Readings)
            {
                sb.AppendLine($"<tr><td>{H(r.CategoryBadge)}</td><td>{H(r.HardwareGroup)}</td><td>{H(r.SensorName)}</td><td><strong>{H(r.FormattedCurrent)}</strong></td><td>{H(r.FormattedMin)}</td><td>{H(r.FormattedMax)}</td></tr>");
            }
            sb.AppendLine("</table>");
        }

        sb.AppendLine("</div></body></html>");
        return sb.ToString();
    }
}
