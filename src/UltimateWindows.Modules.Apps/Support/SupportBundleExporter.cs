using System.IO.Compression;
using System.Net;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using UltimateWindows.Modules.Apps.Models;
using UltimateWindows.Modules.Drivers.Models;
using UltimateWindows.Modules.Drivers.Orchestration;
using UltimateWindows.Modules.Hardware.Analysis;
using UltimateWindows.Modules.Hardware.Models;
using UltimateWindows.Modules.Hardware.Reporting;
using UltimateWindows.Modules.Repair.Models;
using UltimateWindows.Modules.Security.Models;

namespace UltimateWindows.Modules.Apps.Support;

/// <summary>
/// Сборщик единого диагностического архива одним файлом (.zip) для отправки специалисту или в техподдержку.
/// Не включает ни одного личного файла, куки, пароля, истории браузера или переменных окружения с секретами.
/// </summary>
public static class SupportBundleExporter
{
    public static async Task<SupportBundleResult> CreateDiagnosticArchiveAsync(
        string destinationZipPath,
        SmartSystemAuditSummary smartAudit,
        HardwareSnapshot hardwareSnapshot,
        HardwareAuditSummary hardwareAudit,
        HardwareSensorInventory sensorInventory,
        DriverAuditReport driverAudit,
        IReadOnlyList<BsodMinidumpReport> minidumps,
        IReadOnlyList<SystemCrashEventEntry> crashEvents,
        SecurityScanReport securityReport,
        Windows11ReadinessReport win11Report,
        PowerSleepAndRamReport powerReport,
        MaintenanceScheduleProfile scheduleProfile,
        CancellationToken ct = default)
    {
        var fullZipPath = Path.GetFullPath(destinationZipPath);
        var parentDir = Path.GetDirectoryName(fullZipPath);
        if (!string.IsNullOrWhiteSpace(parentDir))
        {
            Directory.CreateDirectory(parentDir);
        }

        if (File.Exists(fullZipPath))
        {
            File.Delete(fullZipPath);
        }

        var includedFiles = new List<string>();
        var summaryHtml = BuildMasterSummaryHtml(
            smartAudit,
            hardwareSnapshot,
            driverAudit,
            minidumps,
            crashEvents,
            securityReport,
            win11Report,
            powerReport,
            scheduleProfile);

        var hardwareHtml = HardwareReportExporter.BuildReportContent(
            HardwareReportFormat.Html,
            hardwareSnapshot,
            hardwareAudit,
            sensorInventory);

        var jsonPayload = new
        {
            GeneratedAtUtc = DateTimeOffset.UtcNow,
            Product = "UltimateWindows v2.0",
            PrivacyGuarantee = "Архив не содержит паролей, куки, личных документов и ключей.",
            SmartAudit = smartAudit,
            Win11Readiness = win11Report,
            PowerAndSleep = powerReport,
            MaintenanceSchedule = scheduleProfile,
            Hardware = new
            {
                Cpu = hardwareSnapshot.Cpu,
                Motherboard = hardwareSnapshot.Motherboard,
                Memory = hardwareSnapshot.Memory,
                Gpus = hardwareSnapshot.Gpus,
                Drives = hardwareSnapshot.Drives,
                Monitors = hardwareSnapshot.Monitors,
                SensorsBackend = sensorInventory.BackendHeadline,
                SensorsCount = sensorInventory.Readings.Count
            },
            Drivers = new
            {
                driverAudit.DriverHealthScore,
                driverAudit.TotalDevicesScanned,
                driverAudit.ProblemDeviceCount,
                Findings = driverAudit.Findings.Take(25).Select(f => new
                {
                    f.SimpleTitle,
                    f.SimpleExplanation,
                    DeviceName = f.Device.FriendlyName,
                    f.Device.ConfigManagerProblemCode
                })
            },
            Stability = new
            {
                MinidumpCount = minidumps.Count,
                CrashEventsCount = crashEvents.Count,
                RecentMinidumps = minidumps.Take(10),
                RecentCrashEvents = crashEvents.Take(15)
            },
            Security = new
            {
                securityReport.SecurityHealthScore,
                ThreatsCount = securityReport.Threats.Count,
                SabotageCount = securityReport.SabotageLocks.Count,
                PostureHeadline = securityReport.HeadlineSummary
            }
        };

        var jsonOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            Converters = { new JsonStringEnumConverter() }
        };
        var jsonText = JsonSerializer.Serialize(jsonPayload, jsonOptions);

        await using (var fs = new FileStream(fullZipPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        using (var archive = new ZipArchive(fs, ZipArchiveMode.Create, leaveOpen: false))
        {
            await WriteEntryTextAsync(archive, "01-DiagnosticSummary.html", summaryHtml, includedFiles, ct).ConfigureAwait(false);
            await WriteEntryTextAsync(archive, "02-HardwarePassport.html", hardwareHtml, includedFiles, ct).ConfigureAwait(false);
            await WriteEntryTextAsync(archive, "03-DiagnosticData.json", jsonText, includedFiles, ct).ConfigureAwait(false);
        }

        var sizeBytes = new FileInfo(fullZipPath).Length;
        return new SupportBundleResult(
            ArchivePath: fullZipPath,
            FileSizeBytes: sizeBytes,
            IncludedFiles: includedFiles,
            SummaryMessage: $"Диагностический архив сохранён: {fullZipPath}");
    }

    private static async Task WriteEntryTextAsync(
        ZipArchive archive,
        string entryName,
        string content,
        List<string> manifest,
        CancellationToken ct)
    {
        var entry = archive.CreateEntry(entryName, CompressionLevel.SmallestSize);
        await using var stream = entry.Open();
        var bytes = Encoding.UTF8.GetBytes(content);
        await stream.WriteAsync(bytes, ct).ConfigureAwait(false);
        manifest.Add(entryName);
    }

    private static string BuildMasterSummaryHtml(
        SmartSystemAuditSummary smartAudit,
        HardwareSnapshot hw,
        DriverAuditReport drivers,
        IReadOnlyList<BsodMinidumpReport> minidumps,
        IReadOnlyList<SystemCrashEventEntry> crashes,
        SecurityScanReport security,
        Windows11ReadinessReport win11,
        PowerSleepAndRamReport power,
        MaintenanceScheduleProfile schedule)
    {
        static string H(string? s) => WebUtility.HtmlEncode(s ?? string.Empty);

        var sb = new StringBuilder(8192);
        sb.AppendLine("<!DOCTYPE html><html lang=\"ru\"><head><meta charset=\"utf-8\">");
        sb.AppendLine("<title>Сводный диагностический паспорт ПК — UltimateWindows v2.0</title>");
        sb.AppendLine("<style>");
        sb.AppendLine("body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:24px;line-height:1.5}");
        sb.AppendLine(".wrap{max-width:1040px;margin:0 auto}.card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:18px 20px;margin-bottom:16px}");
        sb.AppendLine("h1{margin:0 0 6px 0;font-size:22px;color:#f8fafc}h2{margin:0 0 10px 0;font-size:16px;color:#38bdf8}");
        sb.AppendLine(".kpi{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px}.kpi div{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:12px}");
        sb.AppendLine(".val{font-size:20px;font-weight:700;color:#f8fafc}.lbl{font-size:12px;color:#94a3b8}");
        sb.AppendLine("table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid #334155}th{color:#94a3b8}");
        sb.AppendLine(".ok{color:#4ade80;font-weight:600}.warn{color:#fbbf24;font-weight:600}");
        sb.AppendLine("</style></head><body><div class=\"wrap\">");

        sb.AppendLine("<div class=\"card\">");
        sb.AppendLine("<h1>Сводный диагностический отчёт UltimateWindows v2.0</h1>");
        sb.AppendLine($"<div class=\"lbl\">Сформирован: {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz} • Пароли, куки и личные документы не включены</div>");
        sb.AppendLine($"<p style=\"margin:10px 0 0 0\">{H(smartAudit.ExecutiveHeadline)}</p>");
        sb.AppendLine("</div>");

        sb.AppendLine("<div class=\"kpi\">");
        sb.AppendLine($"<div><div class=\"lbl\">Индекс здоровья ПК</div><div class=\"val\">{smartAudit.CompositeHealthScore} / 100</div></div>");
        sb.AppendLine($"<div><div class=\"lbl\">Защита и майнеры</div><div class=\"val\">{security.SecurityHealthScore} / 100</div></div>");
        sb.AppendLine($"<div><div class=\"lbl\">Драйверы (проблемных)</div><div class=\"val\">{drivers.ProblemDeviceCount}</div></div>");
        sb.AppendLine($"<div><div class=\"lbl\">Готовность к Win 11</div><div class=\"val\">{win11.PassedCount} / {win11.TotalCount}</div></div>");
        sb.AppendLine("</div>");

        sb.AppendLine("<div class=\"card\"><h2>Конфигурация оборудования</h2><table>");
        sb.AppendLine($"<tr><th>Процессор</th><td>{H(hw.Cpu.BrandName)} ({hw.Cpu.PhysicalCores}C / {hw.Cpu.LogicalProcessors}T)</td></tr>");
        sb.AppendLine($"<tr><th>Плата и BIOS</th><td>{H(hw.Motherboard.BoardManufacturer)} {H(hw.Motherboard.BoardProduct)} • BIOS {H(hw.Motherboard.BiosVersion)}</td></tr>");
        sb.AppendLine($"<tr><th>Память (ОЗУ)</th><td>{H(hw.Memory.FormattedTotal)} {hw.Memory.MemoryGeneration} @ {hw.Memory.ConfiguredSpeedMtPerSec} MT/s</td></tr>");
        foreach (var gpu in hw.Gpus)
        {
            sb.AppendLine($"<tr><th>Видеоадаптер</th><td>{H(gpu.Name)} ({H(gpu.FormattedVram)}, драйвер {H(gpu.DriverVersion)})</td></tr>");
        }
        foreach (var disk in hw.Drives)
        {
            sb.AppendLine($"<tr><th>Накопитель #{disk.DriveIndex}</th><td>{H(disk.Model)} ({H(disk.FormattedCapacity)}, {disk.BusKind}, S.M.A.R.T.: {(disk.IsHealthy ? "Норма" : "Внимание")})</td></tr>");
        }
        sb.AppendLine("</table></div>");

        sb.AppendLine("<div class=\"card\"><h2>Готовность к Windows 11 и жизненный цикл ОС</h2>");
        sb.AppendLine($"<p><strong>{H(win11.OverallHeadline)}</strong><br/><span class=\"lbl\">{H(win11.Lifecycle.SupportDeadlineText)} — {H(win11.Lifecycle.EsuStatusHeadline)}</span></p>");
        sb.AppendLine("<table><tr><th>Критерий</th><th>Фактически</th><th>Статус</th><th>Рекомендация</th></tr>");
        foreach (var c in win11.Checks)
        {
            var cls = c.Passed ? "ok" : "warn";
            sb.AppendLine($"<tr><td>{H(c.Title)}</td><td>{H(c.CurrentValue)}</td><td class=\"{cls}\">{H(c.StatusBadge)}</td><td>{H(c.ActionHint)}</td></tr>");
        }
        sb.AppendLine("</table></div>");

        sb.AppendLine("<div class=\"card\"><h2>Стабильность (BSOD), Питание, Сон и Автопилот</h2><table>");
        sb.AppendLine($"<tr><th>Минидампы BSOD / критические сбои</th><td>Дампов: {minidumps.Count} • Событий журнала: {crashes.Count}</td></tr>");
        sb.AppendLine($"<tr><th>Аккумулятор</th><td>{H(power.BatteryStatusHeadline)}</td></tr>");
        sb.AppendLine($"<tr><th>Последнее пробуждение из сна</th><td>{H(power.LastWakeSource)}</td></tr>");
        sb.AppendLine($"<tr><th>Проверка памяти Windows</th><td>{H(power.LastRamDiagnosticSummary)}</td></tr>");
        sb.AppendLine($"<tr><th>Расписание автообслуживания</th><td>{H(schedule.FrequencyDisplay)} (последний прогон: {H(schedule.LastRunSummary)})</td></tr>");
        sb.AppendLine("</table></div>");

        sb.AppendLine("</div></body></html>");
        return sb.ToString();
    }
}
