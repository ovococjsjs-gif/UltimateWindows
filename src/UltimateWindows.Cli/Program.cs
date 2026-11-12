using System.Text;
using System.Text.Json;
using UltimateWindows.Core.Guards;
using UltimateWindows.Modules.Apps.Catalog;
using UltimateWindows.Modules.Apps.Models;
using UltimateWindows.Modules.Apps.Services;
using UltimateWindows.Modules.Cleaner.Browsers;
using UltimateWindows.Modules.Cleaner.Models;
using UltimateWindows.Modules.Cleaner.Rules;
using UltimateWindows.Modules.Cleaner.Services;
using UltimateWindows.Modules.Drivers.Catalog;
using UltimateWindows.Modules.Drivers.Orchestration;
using UltimateWindows.Modules.Drivers.Services;
using UltimateWindows.Modules.Hardware.Models;
using UltimateWindows.Modules.Hardware.Services;
using UltimateWindows.Modules.Optimizer.Models;
using UltimateWindows.Modules.Optimizer.Services;
using UltimateWindows.Modules.Repair.Catalog;
using UltimateWindows.Modules.Repair.Diagnostics;
using UltimateWindows.Modules.Repair.ErrorCodes;
using UltimateWindows.Modules.Repair.Models;
using UltimateWindows.Modules.Repair.Services;
using UltimateWindows.Modules.Safety.Services;
using UltimateWindows.Modules.Security.Models;
using UltimateWindows.Modules.Security.Services;
using UltimateWindows.NativeInterop.Cleaner;
using UltimateWindows.NativeInterop.Apps;
using UltimateWindows.NativeInterop.Drivers;
using UltimateWindows.NativeInterop.Hardware;
using UltimateWindows.NativeInterop.Optimizer;
using UltimateWindows.NativeInterop.Repair;
using UltimateWindows.NativeInterop.Restore;
using UltimateWindows.NativeInterop.Security;
using UltimateWindows.NativeInterop.SecurityHunter;

Console.OutputEncoding = Encoding.UTF8;

var vault = new ZeroBloatVaultService(stateApplier: new WindowsSystemStateApplier());
var hardware = new HardwareStudioService(vault, new WindowsHardwarePlatformProvider());
var cleaner = new VaultSafeCleanerService(vault, new WindowsCleanerPlatformBridge());
var repair = new SystemRepairService(vault, new WindowsRepairPlatformBridge());
var optimizer = new SmartOptimizerService(vault, new WindowsOptimizerPlatformBridge());
var security = new AntiMinerSecurityService(vault, new WindowsSecurityPlatformBridge());
var drivers = new OfficialDriverService(vault, new WindowsDriverPlatformBridge());
var smartAudit = new SmartSystemAuditOrchestrator(hardware, drivers, cleaner, repair, optimizer, security);
var appsService = new AppsAndAutomationService(
    vault,
    new WindowsAppsPlatformBridge(),
    hardware,
    drivers,
    cleaner,
    repair,
    security,
    smartAudit);
var command = args.Length > 0 ? args[0].ToLowerInvariant() : "status";

switch (command)
{
    case "status":
    {
        var stats = await vault.GetStorageStatsAsync();
        var isAdmin = ElevationChecker.IsRunningAsAdministrator();
        Console.WriteLine("=== UltimateWindows — Статус системы и хранилища ===");
        Console.WriteLine($"Права администратора : {(isAdmin ? "Да (полный доступ)" : "Нет (режим чтения / пользовательский)")}");
        Console.WriteLine($"Каталог хранилища    : {vault.VaultDirectory}");
        Console.WriteLine($"Использование диска  : {stats.FormattedUsage} ({stats.UsagePercentage:F1}%)");
        Console.WriteLine($"Активных точек отката: {stats.ActiveTransactionCount} (отменено: {stats.RevertedTransactionCount})");
        Console.WriteLine($"Файлов в карантине   : {stats.BlobCount} (автоочистка через {vault.CurrentPolicy.FileBlobRetentionDays} дн.)");
        break;
    }

    case "hardware-audit":
    {
        var (snap, audit) = await hardware.CaptureAndAnalyzeAsync();
        Console.WriteLine("=== UltimateWindows Phase 1 — Аппаратный паспорт и Аудит ===");
        Console.WriteLine($"Индекс железа        : {audit.HardwareHealthScore} / 100");
        Console.WriteLine($"Процессор            : {snap.Cpu.BrandName} ({snap.Cpu.PhysicalCores}C/{snap.Cpu.LogicalProcessors}T)");
        Console.WriteLine($"Плата / BIOS         : {snap.Motherboard.BoardManufacturer} {snap.Motherboard.BoardProduct} | BIOS {snap.Motherboard.BiosVersion}");
        Console.WriteLine($"Оперативная память   : {snap.Memory.FormattedTotal} {snap.Memory.MemoryGeneration} @ {snap.Memory.ConfiguredSpeedMtPerSec} MT/s (DualChannel={snap.Memory.IsDualOrMultiChannelActive})");
        foreach (var gpu in snap.Gpus)
        {
            Console.WriteLine($"Видеокарта #{gpu.Index}        : {gpu.Name} ({gpu.FormattedVram})");
        }
        foreach (var disk in snap.Drives)
        {
            Console.WriteLine($"Накопитель #{disk.DriveIndex}        : {disk.Model} ({disk.FormattedCapacity}, {disk.BusKind}, Healthy={disk.IsHealthy})");
        }
        foreach (var mon in snap.Monitors)
        {
            Console.WriteLine($"Монитор              : {mon.FriendlyModelName} {mon.NativeWidthPx}x{mon.NativeHeightPx} @ {mon.CurrentRefreshHz} Гц (макс. {mon.MaxSupportedRefreshHz} Гц)");
        }

        if (audit.Findings.Count == 0)
        {
            Console.WriteLine("\n[OK] Скрытых потерь производительности не обнаружено.");
        }
        else
        {
            Console.WriteLine($"\nНайдено рекомендаций Умного советника ({audit.Findings.Count}):");
            foreach (var f in audit.Findings)
            {
                Console.WriteLine($"  - [{f.Severity}] {f.SimpleTitle} ({f.EstimatedImpactBadge})");
            }
        }
        break;
    }

    case "stress-test":
    {
        var seconds = args.Length > 1 && int.TryParse(args[1], out var s) ? Math.Clamp(s, 2, 300) : 5;
        Console.WriteLine($"Запуск безопасного стресс-теста на {seconds} сек (Thermal Cutoff = 90°C, с контролем эталонных сумм)...");
        var res = await hardware.RunThermalSafeStressTestAsync(TimeSpan.FromSeconds(seconds), maxSafeCpuTempC: 90, maxSafeGpuTempC: 88);
        Console.WriteLine($"{res.StatusMessage} | Ошибок целостности расчёта: {res.IntegrityErrorCount}");
        break;
    }

    case "hardware-sensors":
    {
        var inv = await hardware.QuerySensorsAsync();
        Console.WriteLine("=== Железо 2.0 — Сквозные датчики оборудования ===");
        Console.WriteLine($"Режим телеметрии : {inv.BackendHeadline}");
        if (inv.ControllableFans.Count > 0)
        {
            Console.WriteLine($"Каналов ШИМ      : {inv.ControllableFans.Count}");
        }

        foreach (var s in inv.Readings)
        {
            Console.WriteLine($"  [{s.Category,-11}] {s.HardwareGroup,-30} | {s.SensorName,-28} : {s.FormattedCurrent,12} (мин {s.FormattedMin}, макс {s.FormattedMax})");
        }
        break;
    }

    case "hardware-bench":
    {
        var mode = args.Length > 1 ? args[1].ToLowerInvariant() : "all";
        Console.WriteLine($"=== Железо 2.0 — Лёгкий экспресс-бенчмарк ({mode}) ===");
        switch (mode)
        {
            case "cpu":
            {
                var cpu = await hardware.RunCpuBenchmarkAsync();
                Console.WriteLine(cpu.SummaryLine);
                break;
            }
            case "gpu":
            {
                var gpu = await hardware.RunGpuBenchmarkAsync();
                Console.WriteLine(gpu.SummaryLine);
                break;
            }
            case "ram":
            {
                var ram = await hardware.RunMemoryBenchmarkAsync();
                Console.WriteLine(ram.SummaryLine);
                break;
            }
            case "disk":
            {
                var dsk = await hardware.RunStorageBenchmarkAsync();
                Console.WriteLine(dsk.SummaryLine);
                break;
            }
            default:
            {
                var suite = await hardware.RunFullQuickBenchmarkSuiteAsync(new Progress<string>(msg => Console.WriteLine("  > " + msg)));
                Console.WriteLine($"\nОбщий индекс ПК : {suite.CompositeScore:N0} pts ({suite.OverallTierBadge}, за {suite.TotalDuration.TotalSeconds:F1} сек)");
                if (suite.Cpu is not null) Console.WriteLine($"  CPU  : {suite.Cpu.SummaryLine}");
                if (suite.Gpu is not null) Console.WriteLine($"  GPU  : {suite.Gpu.SummaryLine}");
                if (suite.Memory is not null) Console.WriteLine($"  ОЗУ  : {suite.Memory.SummaryLine}");
                if (suite.Storage is not null) Console.WriteLine($"  Диск : {suite.Storage.SummaryLine}");
                break;
            }
        }
        break;
    }

    case "hardware-report":
    {
        var fmtRaw = args.Length > 1 && !args[1].StartsWith("--", StringComparison.Ordinal) ? args[1].ToLowerInvariant() : "html";
        var format = fmtRaw switch
        {
            "json" => HardwareReportFormat.Json,
            "txt" => HardwareReportFormat.Txt,
            _ => HardwareReportFormat.Html
        };
        var ext = format == HardwareReportFormat.Json ? "json" : format == HardwareReportFormat.Txt ? "txt" : "html";
        var outPath = GetOptionValue(args, "--out") ?? Path.Combine(Path.GetTempPath(), $"UltimateWindows-Report-{DateTime.Now:yyyyMMdd-HHmmss}.{ext}");

        var (snap, audit) = await hardware.CaptureAndAnalyzeAsync();
        var sensors = await hardware.QuerySensorsAsync();
        var bench = HasFlag(args, "--bench") ? await hardware.RunFullQuickBenchmarkSuiteAsync() : null;
        var saved = await hardware.ExportHardwareReportAsync(outPath, format, snap, audit, sensors, bench);
        Console.WriteLine($"Отчёт о системе ({ext.ToUpperInvariant()}) успешно сохранён: {saved}");
        break;
    }

    case "hardware-power":
    {
        var sub = args.Length > 1 ? args[1].ToLowerInvariant() : "list";
        if (sub == "unlock-ultimate")
        {
            var (ok, schemeGuid, msg) = await hardware.UnlockUltimatePerformancePlanAsync();
            if (ok && schemeGuid.HasValue)
            {
                var (_, swMsg) = await hardware.SwitchPowerPlanAsync(schemeGuid.Value, "Максимальная производительность");
                msg = swMsg;
            }
            Console.WriteLine(msg);
        }
        else if (sub == "set" && args.Length > 2 && Guid.TryParse(args[2], out var targetGuid))
        {
            var (_, msg) = await hardware.SwitchPowerPlanAsync(targetGuid, targetGuid.ToString());
            Console.WriteLine(msg);
        }
        else
        {
            var plans = await hardware.GetPowerPlansAsync();
            Console.WriteLine("=== Схемы электропитания Windows ===");
            foreach (var p in plans)
            {
                Console.WriteLine($"  {(p.IsActive ? "[АКТИВНА]" : "[       ]")} {p.SchemeGuid} | {p.FriendlyName}");
            }
        }
        break;
    }

    case "clean-scan":
    {
        var options = new CleanupOptions { PreservePasswordsAndAutofill = true };
        var report = await cleaner.ScanAsync(options);
        Console.WriteLine("=== UltimateWindows Phase 2 — Бережный анализ мусора (без удаления) ===");
        Console.WriteLine($"Защита паролей и форм : {(report.PasswordsAndAutofillProtected ? "ВКЛЮЧЕНА 🔒" : "Отключена")}");
        Console.WriteLine($"Доступно к очистке    : {report.FormattedTotalReclaimable} ({report.TotalFilesCount:N0} файлов)");
        Console.WriteLine($"Сирот реестра найдено : {report.TotalRegistryOrphansCount}");
        foreach (var cat in report.Categories)
        {
            Console.WriteLine($"  - {cat.IconGlyph} {cat.FriendlyTitle}: {cat.FormattedSize} ({cat.ItemCount} эл.)");
        }
        break;
    }

    case "clean-run":
    {
        var options = new CleanupOptions { PreservePasswordsAndAutofill = true };
        var report = await cleaner.ScanAsync(options);
        var exec = await cleaner.ExecuteCleanupAsync(report, options);
        Console.WriteLine("=== UltimateWindows Phase 2 — Результат бережной очистки ===");
        Console.WriteLine(exec.UserSummaryMessage);
        break;
    }

    case "clean-apps-scan":
    case "clean-apps-run":
    {
        var winapp2Path = GetOptionValue(args, "--winapp2");
        if (!string.IsNullOrWhiteSpace(winapp2Path))
        {
            var imported = cleaner.ImportExternalWinapp2File(winapp2Path);
            Console.WriteLine($"Подключён файл правил «{imported.SourceName}»: правил {imported.Rules.Count:N0}, пропущено {imported.Skipped.Count:N0}.");
        }

        var scan = await cleaner.ScanAppRulesAsync();
        var present = scan.Findings.Where(f => f.IsPresent && f.HasAnythingToClean).OrderByDescending(f => f.TotalBytes).ToList();
        Console.WriteLine($"=== Очистка 2.0 — Каталог программ ({scan.Elapsed.TotalSeconds:F2} сек) ===");
        Console.WriteLine($"Всего найдено : {scan.FormattedTotal} (безопасных по умолчанию: {scan.FormattedSelectedByDefault})");
        foreach (var f in present)
        {
            var mark = f.Rule.SelectedByDefault ? "[по умолч.]" : "[вручную ]";
            Console.WriteLine($"  {mark} {f.FormattedSize,10} | {f.Application,-26} | {f.Rule.Title} ({f.Rule.Id})");
        }

        if (command == "clean-apps-run")
        {
            var explicitRuleId = GetOptionValue(args, "--rule");
            var chosen = !string.IsNullOrWhiteSpace(explicitRuleId)
                ? scan.Findings.Where(f => f.CanCleanNow && (string.Equals(f.Rule.Id, explicitRuleId, StringComparison.OrdinalIgnoreCase) || string.Equals(f.Key, explicitRuleId, StringComparison.OrdinalIgnoreCase))).ToList()
                : scan.Findings.Where(f => f.Rule.SelectedByDefault && f.CanCleanNow).ToList();

            var exec = await cleaner.ExecuteAppRulesAsync(chosen);
            Console.WriteLine(exec.UserSummaryMessage);
        }

        break;
    }

    case "browser-scan":
    case "browser-clean":
    {
        var keepRaw = GetOptionValue(args, "--keep-cookies");
        var keepDomains = BrowserDataCleaner.ParseKeepCookieDomains(keepRaw);
        var details = await cleaner.ScanBrowserDataDetailsAsync(keepDomains);
        Console.WriteLine("=== Очистка 2.0 — Браузеры по пунктам (пароли и закладки под защитой) ===");
        foreach (var warn in details.Warnings)
        {
            Console.WriteLine($"  [!] {warn}");
        }
        foreach (var it in details.Items)
        {
            Console.WriteLine($"  - {it.FriendlyTitle,-48} : {it.FormattedAmount}");
        }

        if (command == "browser-clean")
        {
            var sel = new BrowserCleanupSelection
            {
                CleanCache = false,
                CleanHistory = HasFlag(args, "--history"),
                CleanDownloads = HasFlag(args, "--downloads"),
                CleanCookies = HasFlag(args, "--cookies"),
                CleanSessions = HasFlag(args, "--sessions"),
                KeepCookieDomains = keepDomains
            };
            var res = await cleaner.CleanBrowserDataDetailsAsync(sel);
            Console.WriteLine(res.UserSummaryMessage);
        }

        break;
    }

    case "disk-map":
    {
        var targetPath = args.Length > 1
            ? args[1]
            : Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var diskReport = await cleaner.AnalyzeDiskSpaceAsync(targetPath, topDirectoryLimit: 10, largestFilesLimit: 10);
        Console.WriteLine($"=== Карта диска: {diskReport.RootPath} ===");
        Console.WriteLine($"Способ чтения  : {diskReport.ScanMethodDescription}");
        Console.WriteLine($"Просканировано : {diskReport.FormattedTotalScanned} ({diskReport.TotalFilesCount:N0} файлов) за {diskReport.Elapsed.TotalSeconds:F2} сек");
        Console.WriteLine("\nТоп объемных папок:");
        foreach (var dir in diskReport.TopDirectories)
        {
            Console.WriteLine($"  [{dir.ShareLabel,6}] {dir.FormattedSize,10} | {dir.Name} ({dir.FilesCountLabel})");
        }
        Console.WriteLine("\nСамые крупные файлы:");
        foreach (var file in diskReport.LargestFiles)
        {
            Console.WriteLine($"  [{file.ShareLabel,6}] {file.FormattedSize,10} | {file.FullPath}");
        }
        break;
    }

    case "pe-doctor":
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Использование: UltimateWindows.Cli pe-doctor \"<путь к .exe файлу>\"");
            return 1;
        }

        var diag = repair.DiagnoseExecutable(args[1]);
        Console.WriteLine("=== UltimateWindows Phase 3 — Доктор зависимостей PE и ошибки 0xC000007B ===");
        Console.WriteLine($"Файл         : {diag.TargetExecutablePath}");
        Console.WriteLine($"Архитектура  : {diag.BinaryHeader.ArchitectureDisplay} (прямых импортов: {diag.TotalDirectImportsCount})");
        Console.WriteLine($"Вердикт      : {diag.HeadlineVerdict}");
        foreach (var iss in diag.Issues)
        {
            Console.WriteLine($"  - [{iss.Kind}] {iss.ImportedDllName}: {iss.SimpleExplanation}");
        }
        break;
    }

    case "bsod-scan":
    {
        var scan = await repair.ScanCrashHistoryDetailedAsync(15);
        Console.WriteLine("=== UltimateWindows — анализ дампов синих экранов и журнала сбоев ===");
        Console.WriteLine($"Найдено дампов: {scan.Minidumps.Count} | Событий в журнале: {scan.CrashEvents.Count}");
        if (scan.FolderNote is not null)
        {
            Console.WriteLine($"Внимание: {scan.FolderNote}");
        }
        foreach (var d in scan.Minidumps)
        {
            PrintDumpReport(d);
        }
        foreach (var ev in scan.CrashEvents)
        {
            Console.WriteLine($"  [{ev.TimeLocalDisplay}] {ev.EventBadge}: {ev.SimpleSummary}");
        }
        break;
    }

    case "bsod-file":
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Использование: UltimateWindows.Cli bsod-file \"<путь к файлу .dmp>\"");
            return 1;
        }

        var report = await repair.AnalyzeDumpFileAsync(args[1]);
        if (report is null)
        {
            Console.WriteLine("Файл не найден либо это не дамп ядра Windows и не дамп программы.");
            return 1;
        }

        PrintDumpReport(report);
        break;
    }

    case "repair-list":
    {
        Console.WriteLine("=== Доступные рецепты безопасного ремонта Windows ===");
        foreach (var pb in repair.GetAvailablePlaybooks())
        {
            Console.WriteLine($"  - {pb.Id,-32} | {pb.IconGlyph} {pb.FriendlyTitle} ({pb.AccessBadge})");
        }
        break;
    }

    case "repair-run":
    {
        if (args.Length < 2 || !Enum.TryParse<RepairPlaybookId>(args[1], ignoreCase: true, out var pbId))
        {
            Console.WriteLine("Использование: UltimateWindows.Cli repair-run <PlaybookId> (список: repair-list)");
            return 1;
        }

        var res = await repair.ExecutePlaybookAsync(pbId);
        Console.WriteLine(res.UserFriendlySummary);
        if (!string.IsNullOrWhiteSpace(res.TechnicalLogOutput))
        {
            Console.WriteLine(res.TechnicalLogOutput);
        }
        break;
    }

    case "repair-scan":
    {
        var onlyIssues = HasFlag(args, "--issues");
        var secArg = args.Skip(1).FirstOrDefault(a => !a.StartsWith("--", StringComparison.Ordinal));
        RepairSectionId? sectionFilter = null;
        if (!string.IsNullOrWhiteSpace(secArg) && Enum.TryParse<RepairSectionId>(secArg, ignoreCase: true, out var parsedSec))
        {
            sectionFilter = parsedSec;
        }

        var findings = await repair.ScanSystemHealthAsync(sectionFilter);
        var issues = findings.Count(f => f.State == RepairHealthState.IssueDetected);
        var healthy = findings.Count(f => f.State == RepairHealthState.Healthy);
        Console.WriteLine($"=== Ремонт и DLL 2.0 — Диагностика ОС: проверено {findings.Count} правил (найдено отклонений: {issues}, в норме: {healthy}) ===");

        foreach (var f in findings.Where(f => !onlyIssues || f.State == RepairHealthState.IssueDetected))
        {
            Console.WriteLine($"  [{f.StateBadge,-18}] {f.Rule.Id,-34} | {f.Rule.Title}");
            if (f.State == RepairHealthState.IssueDetected)
            {
                Console.WriteLine($"      Обнаружено : {f.Evidence}");
                Console.WriteLine($"      Исправление: {f.Rule.FixSummary}");
            }
        }
        break;
    }

    case "repair-fix":
    {
        var force = HasFlag(args, "--force");
        var allFound = HasFlag(args, "--all-found");
        List<string> targetIds;

        if (allFound)
        {
            var findings = await repair.ScanSystemHealthAsync();
            targetIds = findings
                .Where(f => f.State == RepairHealthState.IssueDetected && (force || !f.Rule.RequiresExplicitConfirmation))
                .Select(f => f.Rule.Id)
                .ToList();
            if (targetIds.Count == 0)
            {
                Console.WriteLine("Отклонений для автоматического исправления не обнаружено.");
                break;
            }
        }
        else
        {
            targetIds = args.Skip(1).Where(a => !a.StartsWith("--", StringComparison.Ordinal)).ToList();
            if (targetIds.Count == 0)
            {
                Console.WriteLine("Использование: UltimateWindows.Cli repair-fix <rule-id...> [--force] | repair-fix --all-found [--force]");
                return 1;
            }
        }

        var batch = await repair.FixIssuesAsync(targetIds, allowRiskyConfirmed: force);
        foreach (var o in batch.Outcomes)
        {
            var tag = o.VerifiedHealthyAfterFix ? "ПРОВЕРЕНО" : o.FixSucceeded ? "ВЫПОЛНЕНО" : "ОШИБКА";
            Console.WriteLine($"  [{tag,-9}] {o.RuleId,-34} | {o.Message}");
        }
        Console.WriteLine(batch.SummaryHeadline);
        if (batch.RollbackSessionId is { } rbId)
        {
            Console.WriteLine($"Откат в 1 команду: UltimateWindows.Cli rollback {rbId}");
        }
        break;
    }

    case "error-lookup":
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Использование: UltimateWindows.Cli error-lookup <код или ключевое слово> (например 0xC000007B, 0x80070005, -2147024891, 1603)");
            return 1;
        }

        var query = string.Join(' ', args.Skip(1));
        var matches = repair.SearchErrorCodes(query, maxResults: 12);
        if (matches.Count == 0)
        {
            Console.WriteLine($"По запросу «{query}» совпадений не найдено.");
            break;
        }

        Console.WriteLine($"=== Справочник кодов ошибок Windows: найдено {matches.Count} ===");
        foreach (var e in matches)
        {
            Console.WriteLine($"\n[{e.DisplayCode}] {e.SymbolicName} ({e.FamilyTitle})");
            Console.WriteLine($"  Суть   : {e.ShortTitle}");
            Console.WriteLine($"  Причина: {e.DetailedExplanation}");
            Console.WriteLine($"  Решение: {e.RecommendedFixSteps}");
            if (e.RelatedRepairRuleIds.Count > 0)
            {
                Console.WriteLine($"  Правила: {string.Join(", ", e.RelatedRepairRuleIds)}");
            }
            if (e.RelatedRuntimePackageKeys.Count > 0)
            {
                Console.WriteLine($"  Пакеты : {string.Join(", ", e.RelatedRuntimePackageKeys)}");
            }
        }
        break;
    }

    case "runtime-list":
    {
        var statuses = await repair.GetOfficialRuntimeStatusesAsync();
        Console.WriteLine($"=== Официальные среды выполнения ({statuses.Count(s => s.IsInstalled)} из {statuses.Count} установлены) ===");
        foreach (var st in statuses)
        {
            Console.WriteLine($"  [{st.StatusBadge,-24}] {st.Package.PackageKey,-26} | {st.Package.FriendlyName}");
        }
        break;
    }

    case "runtime-install":
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Использование: UltimateWindows.Cli runtime-install <package-key> (список: runtime-list)");
            return 1;
        }

        var pkg = OfficialRuntimeCatalog.GetByKey(args[1]);
        if (pkg is null)
        {
            Console.WriteLine($"Неизвестный пакет «{args[1]}». Выполните runtime-list для просмотра ключей.");
            return 1;
        }

        var res = await repair.InstallOfficialRuntimeAsync(pkg);
        Console.WriteLine(res.UserFriendlySummary);
        if (!res.Succeeded && !string.IsNullOrWhiteSpace(res.TechnicalLogOutput))
        {
            Console.WriteLine(res.TechnicalLogOutput);
            return 1;
        }
        break;
    }

    case "deps-scan-installed":
    {
        var scan = await repair.ScanInstalledProgramsDependenciesAsync();
        Console.WriteLine($"=== Проверка DLL установленных программ: проверено {scan.ExecutablesInspected} из {scan.TotalProgramsFound} ({scan.Elapsed.TotalSeconds:F2} сек) ===");
        if (scan.BrokenPrograms.Count == 0)
        {
            Console.WriteLine("[OK] Конфликтов 0xC000007B и отсутствующих библиотек сред выполнения не обнаружено.");
        }
        else
        {
            foreach (var b in scan.BrokenPrograms)
            {
                Console.WriteLine($"  [!] {b.Program.DisplayName} ({b.Program.ExecutablePath})");
                Console.WriteLine($"      DLL   : {b.MissingOrConflictingDllsSummary}");
                Console.WriteLine($"      Пакеты: {b.RecommendedPackagesSummary}");
            }
        }
        break;
    }

    case "cbs-scan":
    {
        var cbs = repair.AnalyzeCbsLog();
        var rec = repair.GetInPlaceReinstallReadiness();
        Console.WriteLine("=== Анализ CBS.log и готовности восстановления ОС ===");
        Console.WriteLine($"Вердикт CBS.log : {cbs.HumanVerdict}");
        if (cbs.UnrepairableFiles.Count > 0)
        {
            Console.WriteLine($"Невосстановлено : {string.Join(", ", cbs.UnrepairableFiles.Take(10))}");
        }
        Console.WriteLine($"Крайняя мера    : {rec.RecommendedMethodTitle}");
        Console.WriteLine($"Свободно на C:\\ : {rec.FreeSystemDriveGb:F1} ГБ (достаточно >= 20 ГБ: {(rec.HasEnoughDiskSpace ? "Да" : "Нет")})");
        break;
    }

    case "tweak-list":
    {
        // tweak-list [раздел] [--on | --off]
        var onlyOn = HasFlag(args, "--on");
        var onlyOff = HasFlag(args, "--off");
        var categoryFilter = args.Skip(1).FirstOrDefault(a => !a.StartsWith("--", StringComparison.Ordinal));

        var states = optimizer.EvaluateAllTweaks()
            .Where(st => categoryFilter is null ||
                         st.Rule.Category.ToString().Contains(categoryFilter, StringComparison.OrdinalIgnoreCase) ||
                         st.Rule.CategoryDisplayName.Contains(categoryFilter, StringComparison.OrdinalIgnoreCase))
            .Where(st => (!onlyOn || st.IsCurrentlyApplied) && (!onlyOff || !st.IsCurrentlyApplied))
            .ToList();

        Console.WriteLine($"=== Настройки Windows: {states.Count} (включено {states.Count(st => st.IsCurrentlyApplied)}) ===");
        foreach (var group in states.GroupBy(st => st.Rule.Category).OrderBy(g => TweakCategoryInfo.GetOrder(g.Key)))
        {
            Console.WriteLine();
            Console.WriteLine($"[{TweakCategoryInfo.GetTitle(group.Key)}]");
            foreach (var st in group)
            {
                var mark = st.State switch
                {
                    TweakStateKind.Applied => "[ВКЛ ]",
                    TweakStateKind.Partial => $"[{st.AppliedActionCount}/{st.PresentActionCount} ]",
                    TweakStateKind.Unavailable => "[НЕТ ]",
                    _ => "[    ]"
                };

                Console.WriteLine($"  {mark} {st.Rule.TweakId,-42} | {st.Rule.FriendlyTitle}");
                if (st.Rule.IsDangerous)
                {
                    Console.WriteLine("         ! Опасная настройка: включается только с ключом --force");
                }

                if (!st.Applicability.IsApplicable)
                {
                    var kind = st.Applicability.Status == TweakApplicabilityStatus.NotApplicable ? "Не подходит" : "Не рекомендуется";
                    Console.WriteLine($"         ! {kind}: {st.Applicability.Reason}");
                }
            }
        }

        break;
    }

    case "tweak-info":
    {
        var state = args.Length > 1 ? optimizer.EvaluateTweak(args[1]) : null;
        if (state is null)
        {
            Console.WriteLine("Использование: UltimateWindows.Cli tweak-info <tweak-id>");
            return 1;
        }

        var rule = state.Rule;
        Console.WriteLine($"{rule.FriendlyTitle}  ({rule.TweakId})");
        Console.WriteLine($"  Раздел : {rule.CategoryDisplayName}");
        Console.WriteLine($"  Риск   : {rule.RiskDisplayName}");
        Console.WriteLine($"  Права  : {(rule.RequiresAdministrator ? "нужны права администратора" : "обычный пользователь")}");
        if (rule.Restart != TweakRestartKind.None)
        {
            Console.WriteLine($"  Вступает в силу {rule.RestartDisplayName}");
        }

        Console.WriteLine($"  {rule.FriendlyExplanation}");
        Console.WriteLine();
        foreach (var action in optimizer.DescribeTweakActions(rule.TweakId))
        {
            var mark = !action.TargetExists ? "нет " : action.IsInDesiredState ? "ВКЛ " : "    ";
            Console.WriteLine($"  [{mark}] {action.KindLabel}: {action.TargetDisplay}");
            Console.WriteLine($"         сейчас: {action.CurrentDisplay} | настройка: {action.DesiredDisplay} | стандарт Windows: {action.DefaultDisplay}");
        }

        break;
    }

    case "tweak-enable":
    case "tweak-disable":
    {
        if (args.Length < 2)
        {
            Console.WriteLine($"Использование: UltimateWindows.Cli {command} <tweak-id> [--force]");
            return 1;
        }

        var enable = command == "tweak-enable";

        // Ключ --force — явное согласие включить опасную или не рекомендуемую этому компьютеру настройку
        var res = await optimizer.SetTweakStateAsync(
            args[1],
            enable,
            options: HasFlag(args, "--force") ? TweakApplyOptions.AcceptAll : TweakApplyOptions.Default);

        Console.WriteLine(res.UserFriendlyMessage);
        if (res.ConfirmationRequired != TweakConfirmationKind.None)
        {
            Console.WriteLine("Чтобы всё равно включить настройку, повторите команду с ключом --force.");
        }

        if (!res.Succeeded)
        {
            return 1;
        }

        break;
    }

    case "preset-list":
    {
        var states = optimizer.EvaluateAllTweaks().ToDictionary(st => st.Rule.TweakId, StringComparer.OrdinalIgnoreCase);
        Console.WriteLine("=== Готовые наборы настроек ===");
        foreach (var preset in optimizer.GetPresets())
        {
            var applied = preset.TweakIds.Count(id => states.TryGetValue(id, out var st) && st.IsCurrentlyApplied);
            Console.WriteLine();
            Console.WriteLine($"{preset.Key,-12} | {preset.Title}: включено {applied} из {preset.TweakIds.Count}");
            Console.WriteLine($"  {preset.Description}");
        }

        Console.WriteLine();
        Console.WriteLine("Применить: UltimateWindows.Cli preset-apply <набор> [--dry-run] [--force]");
        break;
    }

    case "preset-apply":
    {
        // Тихий режим для сценариев: без вопросов; код возврата 0 — всё применено, 1 — были ошибки
        var preset = args.Length > 1 ? optimizer.GetPresets().FirstOrDefault(p => string.Equals(p.Key, args[1], StringComparison.OrdinalIgnoreCase)) : null;
        if (preset is null)
        {
            Console.WriteLine("Использование: UltimateWindows.Cli preset-apply <набор> [--dry-run] [--force]");
            Console.WriteLine($"Наборы: {string.Join(", ", optimizer.GetPresets().Select(p => p.Key))}");
            return 1;
        }

        if (HasFlag(args, "--dry-run"))
        {
            PrintBatchPlan(optimizer, preset.TweakIds, $"Набор «{preset.Title}»");
            break;
        }

        var batch = await optimizer.ApplyTweakBatchAsync(
            preset.TweakIds,
            $"Набор «{preset.Title}»",
            HasFlag(args, "--force") ? TweakApplyOptions.AcceptAll : TweakApplyOptions.Default);

        PrintBatchResult(batch);
        if (!batch.Succeeded)
        {
            return 1;
        }

        break;
    }

    case "tweak-export":
    {
        var outPath = args.Length > 1 ? args[1] : "ultimatewindows-profile.yaml";
        var yaml = optimizer.ExportActiveTweaksToYaml(Path.GetFileNameWithoutExtension(outPath));
        await File.WriteAllTextAsync(outPath, yaml);
        Console.WriteLine($"Профиль включённых настроек сохранён в: {Path.GetFullPath(outPath)}");
        break;
    }

    case "tweak-import":
    {
        if (args.Length < 2 || !File.Exists(args[1]))
        {
            Console.WriteLine("Использование: UltimateWindows.Cli tweak-import <путь-к-файлу.yaml> [--dry-run] [--force]");
            return 1;
        }

        var yaml = await File.ReadAllTextAsync(args[1]);
        var profile = optimizer.ReadProfile(yaml);
        foreach (var unknown in profile.UnknownTweakIds)
        {
            Console.WriteLine($"  ? {unknown}: такой настройки нет в этой версии программы");
        }

        if (profile.KnownTweakIds.Count == 0)
        {
            Console.WriteLine("В профиле нет ни одной известной настройки.");
            return 1;
        }

        if (HasFlag(args, "--dry-run"))
        {
            PrintBatchPlan(optimizer, profile.KnownTweakIds, $"Профиль «{profile.Name}»");
            break;
        }

        var batch = await optimizer.ApplyTweakBatchAsync(
            profile.KnownTweakIds,
            $"Профиль «{profile.Name}»",
            HasFlag(args, "--force") ? TweakApplyOptions.AcceptAll : TweakApplyOptions.Default);

        PrintBatchResult(batch);
        if (!batch.Succeeded)
        {
            return 1;
        }

        break;
    }

    case "service-list":
    {
        // service-list [--third-party] [--running]
        var services = await optimizer.GetServicesAsync();
        var shown = services
            .Where(sv => !HasFlag(args, "--third-party") || !sv.IsMicrosoft)
            .Where(sv => !HasFlag(args, "--running") || sv.IsRunning)
            .ToList();

        Console.WriteLine($"=== Службы Windows: {shown.Count} из {services.Count} ===");
        foreach (var sv in shown)
        {
            var protection = optimizer.GetServiceProtection(sv.ServiceName) switch
            {
                SystemObjectProtection.Critical => " [защищена]",
                SystemObjectProtection.WeakensProtection => " [защита Windows]",
                _ => ""
            };

            Console.WriteLine($"  {sv.StateDisplay,-12} | {sv.StartupDisplay,-34} | {sv.ServiceName,-34} | {sv.DisplayName}{protection}");
        }

        break;
    }

    case "service-set":
    {
        ServiceStartupMode? mode = args.Length > 2
            ? args[2].ToLowerInvariant() switch
            {
                "auto" or "automatic" => ServiceStartupMode.Automatic,
                "delayed" => ServiceStartupMode.AutomaticDelayed,
                "manual" => ServiceStartupMode.Manual,
                "disabled" => ServiceStartupMode.Disabled,
                _ => null
            }
            : null;

        if (mode is null)
        {
            Console.WriteLine("Использование: UltimateWindows.Cli service-set <имя-службы> <auto|delayed|manual|disabled> [--force]");
            return 1;
        }

        var res = await optimizer.SetServiceStartupAsync(args[1], mode.Value, acceptDangerous: HasFlag(args, "--force"));
        Console.WriteLine(res.UserFriendlyMessage);
        if (res.ConfirmationRequired != TweakConfirmationKind.None)
        {
            Console.WriteLine("Чтобы всё равно изменить службу, повторите команду с ключом --force.");
        }

        if (!res.Succeeded)
        {
            return 1;
        }

        break;
    }

    case "task-list":
    {
        // task-list [--third-party] [--enabled]
        var tasks = await optimizer.GetScheduledTasksAsync();
        var shown = tasks
            .Where(t => !HasFlag(args, "--third-party") || !t.IsMicrosoft)
            .Where(t => !HasFlag(args, "--enabled") || t.Enabled)
            .ToList();

        Console.WriteLine($"=== Задания планировщика: {shown.Count} из {tasks.Count} ===");
        foreach (var t in shown)
        {
            Console.WriteLine($"  {t.StateDisplay,-11} | {t.TaskPath}");
            if (!string.IsNullOrWhiteSpace(t.ActionSummary))
            {
                Console.WriteLine($"              {t.ActionSummary}");
            }
        }

        break;
    }

    case "task-enable":
    case "task-disable":
    {
        if (args.Length < 2)
        {
            Console.WriteLine($"Использование: UltimateWindows.Cli {command} \"<путь задания>\" [--force]");
            return 1;
        }

        var res = await optimizer.SetScheduledTaskEnabledAsync(
            args[1],
            enabled: command == "task-enable",
            acceptDangerous: HasFlag(args, "--force"));

        Console.WriteLine(res.UserFriendlyMessage);
        if (res.ConfirmationRequired != TweakConfirmationKind.None)
        {
            Console.WriteLine("Чтобы всё равно изменить задание, повторите команду с ключом --force.");
        }

        if (!res.Succeeded)
        {
            return 1;
        }

        break;
    }

    case "startup-list":
    {
        var startups = await optimizer.GetStartupEntriesAsync();
        Console.WriteLine($"=== Автозагрузка Windows ({startups.Count} эл.) ===");
        foreach (var s in startups)
        {
            Console.WriteLine($"  [{(s.IsEnabled ? "ВКЛ " : "ВЫКЛ")}] {s.DisplayName,-28} | {s.LocationSource} | {s.SignatureBadge}");
        }
        break;
    }

    case "unlock-check":
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Использование: UltimateWindows.Cli unlock-check \"<путь к файлу или папке>\"");
            return 1;
        }

        var lockers = await optimizer.FindLockingProcessesAsync(args[1]);
        if (lockers.Count == 0)
        {
            Console.WriteLine("Путь не заблокирован ни одним процессом.");
        }
        else
        {
            foreach (var lp in lockers)
            {
                Console.WriteLine($"  - {lp.DisplayHeadline} | {lp.ProcessKindLabel} | {lp.ExecutablePath}");
            }
        }
        break;
    }

    case "security-scan":
    case "miner-scan":
    {
        var probe = !HasFlag(args, "--fast");
        var report = await security.RunFullSecurityScanAsync(probe);
        if (HasFlag(args, "--json"))
        {
            Console.WriteLine(JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
            break;
        }

        Console.WriteLine($"=== Анти-майнер и Защита 2.0 — Полный аудит безопасности (Индекс: {report.SecurityHealthScore}/100) ===");
        Console.WriteLine(report.HeadlineSummary);
        Console.WriteLine($"Проверено зон закрепления: {report.PersistenceZonesAuditedCount} (записей: {report.SafePersistenceEntries.Count}) | Исключений Defender: {report.SafeDefenderExclusions.Count} | Процессов: {report.SafeProcessSnapshots.Count}");

        if (report.Threats.Count > 0)
        {
            Console.WriteLine($"\nОбнаружено угроз ({report.Threats.Count}):");
            foreach (var t in report.Threats)
            {
                Console.WriteLine($"  - [{t.ConfidenceBadge}] [{t.EffectiveCategoryLabel}] {t.SimpleTitle}");
                Console.WriteLine($"      {t.SimpleExplanation}");
                Console.WriteLine($"      Доказательство: {t.ExpertTechnicalEvidence}");
            }
        }

        if (report.SabotageLocks.Count > 0)
        {
            Console.WriteLine($"\nОбнаружено блокировок ОС после майнера ({report.SabotageLocks.Count}):");
            foreach (var s in report.SabotageLocks)
            {
                Console.WriteLine($"  - {s.SimpleTitle}: {s.SimpleExplanation}");
            }
        }
        break;
    }

    case "persistence-audit":
    {
        var onlyAnomalies = HasFlag(args, "--anomalies");
        var report = await security.RunFullSecurityScanAsync(enableDropOnInspectProbe: false);
        var entries = onlyAnomalies
            ? report.SafePersistenceEntries.Where(e => e.IsAnomaly).ToList()
            : report.SafePersistenceEntries.ToList();

        Console.WriteLine($"=== Ревизия 18 зон автозакрепления Windows (показано: {entries.Count} из {report.SafePersistenceEntries.Count}) ===");
        foreach (var e in entries)
        {
            Console.WriteLine($"  [{e.StatusBadge,-14}] {e.ZoneTitle,-36} | {e.EntryName,-28} | {e.PayloadCommandOrPath}");
        }
        break;
    }

    case "defender-audit":
    {
        var report = await security.RunFullSecurityScanAsync(enableDropOnInspectProbe: false);
        Console.WriteLine($"=== Аудит исключений Microsoft Defender (всего: {report.SafeDefenderExclusions.Count}) ===");
        if (report.SafeDefenderExclusions.Count == 0)
        {
            Console.WriteLine("Исключений Защитника Windows не обнаружено (или требуется запуск от имени администратора).");
            break;
        }

        foreach (var ex in report.SafeDefenderExclusions)
        {
            Console.WriteLine($"  [{ex.RiskBadge,-20}] {ex.KindLabel,-13} | {ex.Value,-36} | {ex.Reason}");
        }
        break;
    }

    case "defender-clean-exclusions":
    {
        var report = await security.RunFullSecurityScanAsync(enableDropOnInspectProbe: false);
        var res = await security.RemoveDangerousDefenderExclusionsAsync(report.SafeDefenderExclusions);
        Console.WriteLine(res.UserFriendlyMessage);
        return res.Succeeded ? 0 : 1;
    }

    case "defender-scan":
    {
        var targetPath = GetOptionValue(args, "--path");
        var mode = !string.IsNullOrWhiteSpace(targetPath) ? DefenderScanMode.CustomPathScan : DefenderScanMode.QuickScan;
        var (ok, msg) = await security.StartDefenderScanAsync(mode, targetPath);
        Console.WriteLine(msg);
        return ok ? 0 : 1;
    }

    case "quarantine-list":
    {
        var list = await security.GetQuarantineHistoryAsync();
        Console.WriteLine($"=== Журнал карантина .uwq раздела Анти-майнер ({list.Count}) ===");
        foreach (var q in list)
        {
            var status = q.IsReverted ? "[ВОССТАНОВЛЕНО]" : "[В КАРАНТИНЕ ]";
            Console.WriteLine($"  {q.TimestampLocalText} {status} {q.SessionId} | {q.FriendlyTitle} | {q.PrimaryPath}");
        }
        break;
    }

    case "quarantine-restore":
    {
        if (args.Length < 2 || !Guid.TryParse(args[1], out var qId))
        {
            Console.WriteLine("Использование: UltimateWindows.Cli quarantine-restore <GUID-транзакции>");
            return 1;
        }

        var res = await security.RestoreFromQuarantineAsync(qId);
        Console.WriteLine(res.UserFriendlyMessage);
        return res.Succeeded ? 0 : 1;
    }

    case "security-heal":
    case "miner-heal-os":
    {
        var report = await security.RunFullSecurityScanAsync(enableDropOnInspectProbe: false);
        var res = await security.HealAllSabotageLocksAsync(report.SabotageLocks);
        Console.WriteLine(res.UserFriendlyMessage);
        return res.Succeeded ? 0 : 1;
    }

    case "drivers-audit":
    {
        var online = HasFlag(args, "--online");
        var showAll = HasFlag(args, "--all");
        var report = await drivers.AuditDevicesAndDriversAsync(online);
        Console.WriteLine($"=== UltimateWindows Stage 5 — Аудит устройств и WHQL-драйверов ({report.DriverHealthScore}/100) ===");
        Console.WriteLine(report.SummaryHeadline);
        foreach (var f in report.Findings)
        {
            Console.WriteLine($"  - [{f.Severity}] {f.SimpleTitle}");
            Console.WriteLine($"      {f.SimpleExplanation}");
            Console.WriteLine($"      {f.ExpertTechnicalDetails}");
        }

        if (showAll)
        {
            Console.WriteLine($"\nВсе опрошенные устройства ({report.AllDevices.Count}):");
            foreach (var d in report.AllDevices)
            {
                Console.WriteLine($"  [{d.DeviceClass,-12}] {d.FriendlyName,-42} | {d.EffectiveProvider,-22} | {d.DriverVersion,-16} | {d.DriverDate,-10} | {d.InfName,-10} | {d.PrimaryHardwareId}");
            }
        }
        break;
    }

    case "drivers-catalog-search":
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Использование: UltimateWindows.Cli drivers-catalog-search \"<Hardware ID или запрос>\"");
            return 1;
        }

        var query = string.Join(' ', args.Skip(1));
        var entries = await drivers.SearchMicrosoftCatalogAsync(query);
        Console.WriteLine($"=== Каталог Microsoft Update — найдено пакетов: {entries.Count} по запросу «{query}» ===");
        foreach (var e in entries)
        {
            Console.WriteLine($"  [{e.LastUpdatedText}] {e.Title} | v{e.Version} | {e.FormattedSize} | {e.Products} | ID={e.UpdateId}");
        }
        break;
    }

    case "drivers-essential-list":
    {
        var onlyMatched = HasFlag(args, "--matched");
        var items = await drivers.GetEvaluatedEssentialDriversAsync();
        if (onlyMatched)
        {
            items = items.Where(x => x.MatchesCurrentPcHardware).ToList();
        }

        Console.WriteLine($"=== Каталог основных драйверов с серверов ({items.Count} пакетов) ===");
        foreach (var item in items)
        {
            var p = item.Package;
            Console.WriteLine($"  {p.Id,-34} | {p.CategoryLabel,-26} | {item.PcRelevanceBadge,-20} | {p.DeliveryBadge,-22} | {p.Title}");
        }
        break;
    }

    case "drivers-essential-download":
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Использование: UltimateWindows.Cli drivers-essential-download <package-id> [--dir <папка>] [--install]");
            return 1;
        }

        var pkg = EssentialDriverCatalog.FindById(args[1]);
        if (pkg is null)
        {
            Console.WriteLine($"Пакет «{args[1]}» не найден. Выполните drivers-essential-list для просмотра ID.");
            return 1;
        }

        var targetDir = GetOptionValue(args, "--dir") ?? OfficialDriverService.GetDefaultDownloadRootDirectory();
        var installNow = HasFlag(args, "--install");
        var progress = new Progress<string>(msg => Console.WriteLine($"  -> {msg}"));
        var res = await drivers.DownloadOrInstallEssentialPackageAsync(pkg, targetDir, installNow, progress);
        Console.WriteLine(res.UserFriendlyMessage);
        return res.Succeeded ? 0 : 1;
    }

    case "driverstore-audit":
    {
        var summary = await drivers.AuditDriverStoreAsync();
        Console.WriteLine("=== Ревизия хранилища DriverStore (FileRepository) ===");
        Console.WriteLine(summary.Headline);
        foreach (var e in summary.Entries)
        {
            Console.WriteLine($"  {e.PublishedInfName,-10} | {e.OriginalInfName,-24} | {e.ProviderName,-22} | v{e.DriverVersion,-16} | {e.FormattedSize,9} | {e.StateBadge}");
        }
        break;
    }

    case "driverstore-clean":
    {
        var summary = await drivers.AuditDriverStoreAsync();
        var res = await drivers.CleanOldDriverStoreDuplicatesAsync(summary.Entries);
        Console.WriteLine(res.UserFriendlyMessage);
        return res.Succeeded ? 0 : 1;
    }

    case "drivers-backup-all":
    {
        var dir = args.Length >= 2 ? args[1] : Path.Combine(OfficialDriverService.GetDefaultDownloadRootDirectory(), $"FullBackup-{DateTime.Now:yyyyMMdd-HHmm}");
        var res = await drivers.BackupAllThirdPartyDriversAsync(dir);
        Console.WriteLine(res.UserFriendlyMessage);
        return res.Succeeded ? 0 : 1;
    }

    case "drivers-restore-folder":
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Использование: UltimateWindows.Cli drivers-restore-folder \"<папка с INF>\"");
            return 1;
        }

        var res = await drivers.RestoreDriversFromFolderAsync(args[1]);
        Console.WriteLine(res.UserFriendlyMessage);
        return res.Succeeded ? 0 : 1;
    }

    case "drivers-rescue-pack":
    {
        var dir = GetOptionValue(args, "--dir") ?? Path.Combine(OfficialDriverService.GetDefaultDownloadRootDirectory(), "Offline-Network-Rescue");
        var fromServers = HasFlag(args, "--universal-servers");
        var progress = new Progress<string>(msg => Console.WriteLine($"  -> {msg}"));
        var res = await drivers.BuildOfflineNetworkRescuePackAsync(dir, fromServers, progress);
        Console.WriteLine(res.UserFriendlyMessage);
        foreach (var line in res.Details)
        {
            Console.WriteLine($"  {line}");
        }
        return res.Succeeded ? 0 : 1;
    }

    case "drivers-byovd-audit":
    {
        var report = await drivers.AuditVulnerableKernelDriversAsync();
        Console.WriteLine("=== Аудит уязвимых и заблокированных драйверов ядра (BYOVD / LOLDrivers) ===");
        Console.WriteLine(report.SummaryHeadline);
        foreach (var f in report.Findings)
        {
            Console.WriteLine($"  [{f.StateText}] {f.InstalledDriver.ServiceName} ({f.InstalledDriver.BinaryPath})");
            Console.WriteLine($"    Семейство : {f.MatchedRule.FamilyName} ({f.MatchedRule.CveOrAdvisory})");
            Console.WriteLine($"    Риск      : {f.MatchedRule.AbuseExplanation}");
            Console.WriteLine($"    Замена    : {f.MatchedRule.SafeAlternative}");
        }
        break;
    }

    case "drivers-blocklist-enable":
    {
        var res = await drivers.EnableMicrosoftVulnerableDriverBlocklistAsync();
        Console.WriteLine(res.UserFriendlyMessage);
        return res.Succeeded ? 0 : 1;
    }

    case "driver-backup":
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Использование: UltimateWindows.Cli driver-backup <oemXX.inf>");
            return 1;
        }

        var targetInf = args[1];
        var report = await drivers.AuditDevicesAndDriversAsync(queryWindowsUpdateCatalog: false);
        var match = report.AllDevices.FirstOrDefault(d => string.Equals(d.InfName, targetInf, StringComparison.OrdinalIgnoreCase));
        if (match is null)
        {
            Console.WriteLine($"Устройство с пакетом {targetInf} не найдено.");
            return 1;
        }

        var res = await drivers.BackupDeviceDriverToVaultAsync(match);
        Console.WriteLine(res.UserFriendlyMessage);
        return res.Succeeded ? 0 : 1;
    }

    case "smart-audit":
    {
        var summary = await smartAudit.RunOneClickAuditAsync(
            includeStealthMinerDecoyProbe: false,
            queryOnlineDriverCatalog: false);
        Console.WriteLine($"=== UltimateWindows v1.0 — Комплексный Умный Аудит ПК ({summary.CompositeHealthScore}/100) ===");
        Console.WriteLine(summary.ExecutiveHeadline);
        Console.WriteLine($"  Безопасность / Анти-майнер : {summary.SecurityScore}/100");
        Console.WriteLine($"  Железо                     : {summary.HardwareScore}/100");
        Console.WriteLine($"  Драйверы WHQL              : {summary.DriversScore}/100");
        Console.WriteLine($"  Стабильность / BSOD        : {summary.StabilityRepairScore}/100");
        Console.WriteLine($"  Бережная очистка           : {summary.CleanerScore}/100 (доступно: {summary.FormattedReclaimableSpace})");
        Console.WriteLine($"  Оптимизация и автозапуск   : {summary.OptimizerScore}/100");

        if (summary.TopActionItems.Count > 0)
        {
            Console.WriteLine("\nТочки быстрого улучшения:");
            foreach (var item in summary.TopActionItems)
            {
                Console.WriteLine($"  - [{item.DomainBadge}] {item.SimpleTitle} — {item.SimpleRecommendation}");
            }
        }
        break;
    }

    case "history":
    {
        var history = await vault.GetHistoryAsync(25);
        if (history.Count == 0)
        {
            Console.WriteLine("История изменений пуста.");
            break;
        }

        foreach (var item in history)
        {
            var state = item.IsReverted ? "[ОТМЕНЕНО]" : "[АКТИВНО]";
            var pin = item.IsPinned ? " 📌" : "";
            Console.WriteLine($"{item.CreatedDisplayLocal} {state}{pin} {item.SessionId} | {item.FriendlyTitle} ({item.FormattedStoredSize})");
        }
        break;
    }

    case "cleanup-blobs":
    {
        var removed = await vault.PurgeAllUnpinnedBlobsAsync();
        var stats = await vault.GetStorageStatsAsync();
        Console.WriteLine($"Удалено незакрепленных файловых блобов: {removed}. Занято сейчас: {stats.FormattedUsage}.");
        break;
    }

    case "rollback":
    {
        if (args.Length < 2 || !Guid.TryParse(args[1], out var sessionId))
        {
            Console.WriteLine("Использование: UltimateWindows.Cli rollback <GUID-транзакции>");
            return 1;
        }

        try
        {
            await vault.RollbackTransactionAsync(sessionId);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Не удалось отменить изменения: {ex.Message}");
            return 1;
        }

        Console.WriteLine($"Изменения записи {sessionId} отменены.");
        break;
    }

    case "check-path":
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Использование: UltimateWindows.Cli check-path \"<путь к файлу браузера>\"");
            return 1;
        }

        var verdict = BrowserVaultGuard.EvaluatePath(args[1]);
        Console.WriteLine($"Путь: {args[1]} -> Вердикт защиты: {verdict}");
        break;
    }

    case "apps-upgrades":
    {
        var (avail, ver, pkgs) = await appsService.ScanAvailableUpgradesAsync();
        Console.WriteLine($"=== Этап 7 — Центр обновлений программ (winget {ver}) ===");
        if (!avail)
        {
            Console.WriteLine("Пакетный менеджер winget не обнаружен в системе.");
            return 1;
        }

        if (pkgs.Count == 0)
        {
            Console.WriteLine("[OK] Все установленные программы актуальны.");
            break;
        }

        Console.WriteLine($"Доступно обновлений: {pkgs.Count}");
        foreach (var p in pkgs)
        {
            Console.WriteLine($"  {p.PackageId,-36} | {p.Name,-30} | {p.VersionTransitionDisplay,-24} | {p.Source}");
        }
        break;
    }

    case "apps-upgrade":
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Использование: UltimateWindows.Cli apps-upgrade <package-id | --all>");
            return 1;
        }

        if (HasFlag(args, "--all"))
        {
            var (_, _, pkgs) = await appsService.ScanAvailableUpgradesAsync();
            foreach (var p in pkgs)
            {
                var r = await appsService.UpgradePackageAsync(p.PackageId, p.Name);
                Console.WriteLine($"  [{(r.Succeeded ? "OK" : "ERR")}] {r.Summary}");
            }
        }
        else
        {
            var r = await appsService.UpgradePackageAsync(args[1]);
            Console.WriteLine(r.Summary);
            return r.Succeeded ? 0 : 1;
        }
        break;
    }

    case "apps-catalog":
    {
        var presetArg = GetOptionValue(args, "--preset");
        var statuses = await appsService.EvaluateEssentialCatalogAsync(queryWingetList: HasFlag(args, "--winget"));
        IEnumerable<EssentialAppStatus> filtered = statuses;

        if (!string.IsNullOrWhiteSpace(presetArg))
        {
            var preset = presetArg.ToLowerInvariant() switch
            {
                "gamer" => EssentialAppBundlePreset.GamerPc,
                "dev" => EssentialAppBundlePreset.PowerUserAndDev,
                _ => EssentialAppBundlePreset.FreshHomeInstall
            };
            filtered = statuses.Where(s => s.Entry.Presets.Contains(preset));
        }

        var list = filtered.ToList();
        Console.WriteLine($"=== Каталог программ первой необходимости ({list.Count} пакетов) ===");
        foreach (var s in list)
        {
            Console.WriteLine($"  [{s.StatusBadge,-18}] {s.Entry.Id,-16} | {s.Entry.WingetId,-34} | {s.Entry.DisplayName}");
        }
        break;
    }

    case "apps-install":
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Использование: UltimateWindows.Cli apps-install <id | winget-id | --preset home|gamer|dev>");
            return 1;
        }

        var presetName = GetOptionValue(args, "--preset");
        List<EssentialAppEntry> targets;
        if (!string.IsNullOrWhiteSpace(presetName))
        {
            var preset = presetName.ToLowerInvariant() switch
            {
                "gamer" => EssentialAppBundlePreset.GamerPc,
                "dev" => EssentialAppBundlePreset.PowerUserAndDev,
                _ => EssentialAppBundlePreset.FreshHomeInstall
            };
            targets = EssentialSoftwareCatalog.GetByPreset(preset).ToList();
        }
        else
        {
            var targetId = args[1];
            var found = EssentialSoftwareCatalog.GetAll().FirstOrDefault(e =>
                string.Equals(e.Id, targetId, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(e.WingetId, targetId, StringComparison.OrdinalIgnoreCase));
            if (found is null)
            {
                Console.WriteLine($"Пакет «{targetId}» не найден во встроенном каталоге.");
                return 1;
            }
            targets = [found];
        }

        foreach (var entry in targets)
        {
            var res = await appsService.InstallEssentialAppAsync(entry);
            Console.WriteLine($"  [{(res.Succeeded ? "OK" : "ERR")}] {res.Summary}");
        }
        break;
    }

    case "apps-leftovers":
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Использование: UltimateWindows.Cli apps-leftovers \"<часть названия установленной программы>\"");
            return 1;
        }

        var query = args[1];
        var allApps = await appsService.GetInstalledApplicationsAsync();
        var match = allApps.FirstOrDefault(a => a.DisplayName.Contains(query, StringComparison.OrdinalIgnoreCase));
        if (match is null)
        {
            Console.WriteLine($"Установленная программа по запросу «{query}» не найдена.");
            return 1;
        }

        var leftovers = await appsService.ScanApplicationLeftoversAsync(match);
        Console.WriteLine($"=== Поиск хвостов для «{match.DisplayName}» ({leftovers.Count}) ===");
        foreach (var item in leftovers)
        {
            Console.WriteLine($"  [{item.KindBadge,-22}] {item.TargetPath} ({item.FormattedSize})");
        }
        break;
    }

    case "win11-check":
    {
        var rep = await appsService.CheckWindows11ReadinessAsync();
        Console.WriteLine("=== Готовность к Windows 11 (24H2/25H2) и статус поддержки ОС ===");
        Console.WriteLine($"Итог         : {rep.OverallHeadline}");
        Console.WriteLine($"Поддержка ОС : {rep.Lifecycle.SupportDeadlineText}");
        Console.WriteLine($"Статус ESU   : {rep.Lifecycle.EsuStatusHeadline}");
        Console.WriteLine($"Рекомендация : {rep.Lifecycle.RecommendationText}\n");
        foreach (var c in rep.Checks)
        {
            Console.WriteLine($"  [{(c.Passed ? "OK " : "ВНИМ")}] {c.Title,-42} | {c.CurrentValue}");
        }
        break;
    }

    case "power-sleep":
    {
        var p = await appsService.CheckPowerSleepAndRamAsync();
        Console.WriteLine("=== Диагностика батареи, сна и оперативной памяти ===");
        Console.WriteLine($"Аккумулятор  : {p.BatteryStatusHeadline}");
        Console.WriteLine($"Пробуждение  : {p.LastWakeSource}");
        Console.WriteLine($"Блокировщики : {(p.ActivePowerBlockers.Count == 0 ? "нет" : string.Join("; ", p.ActivePowerBlockers))}");
        Console.WriteLine($"Память (ОЗУ) : {p.LastRamDiagnosticSummary}");
        break;
    }

    case "auto-maintenance":
    {
        var cleanCache = !HasFlag(args, "--no-cache");
        var checkSmart = !HasFlag(args, "--no-smart");
        var checkSec = !HasFlag(args, "--no-security");
        var run = await appsService.RunAutoMaintenanceNowAsync(cleanCache, checkSmart, checkSec);
        Console.WriteLine($"[Автопилот] {run.Headline}");
        break;
    }

    case "schedule-maintenance":
    {
        if (args.Length < 2)
        {
            var cur = await appsService.GetMaintenanceScheduleAsync();
            Console.WriteLine($"Текущее расписание: {cur.FrequencyDisplay} | Статус: {cur.NextRunDisplay} | Последний прогон: {cur.LastRunSummary}");
            break;
        }

        var mode = args[1].ToLowerInvariant();
        var freq = mode switch
        {
            "daily" => MaintenanceFrequency.Daily,
            "weekly" => MaintenanceFrequency.Weekly,
            "monthly" => MaintenanceFrequency.Monthly,
            _ => MaintenanceFrequency.Disabled
        };
        var hourStr = GetOptionValue(args, "--hour");
        var hour = int.TryParse(hourStr, out var h) ? Math.Clamp(h, 0, 23) : 12;

        var updated = await appsService.SaveMaintenanceScheduleAsync(new MaintenanceScheduleProfile(
            IsEnabled: freq != MaintenanceFrequency.Disabled,
            Frequency: freq,
            RunHourLocal: hour,
            CleanSafeTempCache: !HasFlag(args, "--no-cache"),
            CheckDriveSmartHealth: !HasFlag(args, "--no-smart"),
            AuditSecurityAndStartup: !HasFlag(args, "--no-security"),
            TaskSchedulerPath: @"\UltimateWindows\AutoMaintenance",
            NextRunDisplay: string.Empty,
            LastRunSummary: string.Empty));
        Console.WriteLine($"Расписание обновлено: {updated.NextRunDisplay}");
        break;
    }

    case "support-bundle":
    {
        var outPath = GetOptionValue(args, "--out")
            ?? Path.Combine(Environment.CurrentDirectory, $"UltimateWindows-Diagnostics-{DateTime.Now:yyyyMMdd-HHmmss}.zip");
        var bundle = await appsService.ExportSupportBundleAsync(outPath);
        Console.WriteLine($"{bundle.SummaryMessage} ({bundle.FormattedSize}, файлов внутри: {bundle.IncludedFiles.Count})");
        break;
    }

    default:
    {
        Console.WriteLine("Доступные команды: status | smart-audit | hardware-audit | hardware-sensors | hardware-bench [all|cpu|gpu|ram|disk] | hardware-report [html|json|txt] [--bench] [--out <файл>] | hardware-power [list|unlock-ultimate|set <guid>] | stress-test [сек] | drivers-audit [--online] [--all] | drivers-catalog-search <запрос> | drivers-essential-list [--matched] | drivers-essential-download <id> [--dir <папка>] [--install] | driverstore-audit | driverstore-clean | drivers-backup-all [папка] | drivers-restore-folder <папка> | drivers-rescue-pack [--dir <папка>] [--universal-servers] | drivers-byovd-audit | drivers-blocklist-enable | driver-backup <oemXX.inf> | apps-upgrades | apps-upgrade <id|--all> | apps-catalog [--preset home|gamer|dev] | apps-install <id|--preset ...> | apps-leftovers <имя> | win11-check | power-sleep | auto-maintenance [--no-cache] [--no-smart] [--no-security] | schedule-maintenance [daily|weekly|monthly|off] [--hour <0..23>] | support-bundle [--out <файл.zip>] | clean-scan | clean-run | clean-apps-scan [--winapp2 <ini>] | clean-apps-run [--rule <id>] [--winapp2 <ini>] | browser-scan [--keep-cookies <домены>] | browser-clean [--history] [--downloads] [--cookies] [--sessions] [--keep-cookies <домены>] | disk-map [путь] | pe-doctor <exe> | deps-scan-installed | runtime-list | runtime-install <key> | repair-scan [раздел] [--issues] | repair-fix <id|--all-found> [--force] | error-lookup <код> | cbs-scan | bsod-scan | bsod-file <dmp> | repair-list | repair-run <id> | tweak-list [раздел] [--on|--off] | tweak-info <id> | tweak-enable <id> [--force] | tweak-disable <id> | preset-list | preset-apply <набор> [--dry-run] [--force] | tweak-export [yaml] | tweak-import <yaml> [--dry-run] [--force] | service-list [--third-party] [--running] | service-set <имя> <auto|delayed|manual|disabled> | task-list [--third-party] [--enabled] | task-enable <путь> | task-disable <путь> | startup-list | unlock-check <path> | security-scan [--fast] [--json] | persistence-audit [--anomalies] | defender-audit | defender-clean-exclusions | defender-scan [--path <путь>] | quarantine-list | quarantine-restore <id> | security-heal | history | cleanup-blobs | rollback <id> | check-path <path>");
        break;
    }
}

return 0;

static bool HasFlag(string[] arguments, string flag) =>
    arguments.Any(a => string.Equals(a, flag, StringComparison.OrdinalIgnoreCase));

static string? GetOptionValue(string[] arguments, string optionName)
{
    for (int i = 0; i < arguments.Length - 1; i++)
    {
        if (string.Equals(arguments[i], optionName, StringComparison.OrdinalIgnoreCase))
        {
            return arguments[i + 1];
        }
    }

    return null;
}

static void PrintBatchPlan(SmartOptimizerService optimizerService, IReadOnlyList<string> tweakIds, string title)
{
    Console.WriteLine($"{title}: что будет сделано (ничего не меняется)");
    foreach (var id in tweakIds)
    {
        var state = optimizerService.EvaluateTweak(id);
        if (state is null)
        {
            continue;
        }

        var plan = state.State == TweakStateKind.Applied
            ? "уже включено"
            : state.Applicability.Status switch
            {
                TweakApplicabilityStatus.NotApplicable => $"пропуск: {state.Applicability.Reason}",
                TweakApplicabilityStatus.NotRecommended => $"пропуск без --force: {state.Applicability.Reason}",
                _ => state.Rule.IsDangerous ? "пропуск без --force: опасная настройка" : "будет включено"
            };

        Console.WriteLine($"  {state.Rule.TweakId,-42} | {plan}");
    }
}

static void PrintBatchResult(TweakBatchResult batch)
{
    foreach (var item in batch.Items.Where(i => i.Outcome is TweakBatchItemOutcome.Skipped or TweakBatchItemOutcome.Failed))
    {
        var mark = item.Outcome == TweakBatchItemOutcome.Failed ? "ОШИБКА " : "пропуск";
        Console.WriteLine($"  [{mark}] {item.TweakId}: {item.Note}");
    }

    Console.WriteLine(batch.UserFriendlyMessage);
    if (batch.RollbackSessionId is { } sessionId)
    {
        Console.WriteLine($"Отменить всё разом: UltimateWindows.Cli rollback {sessionId}");
    }
}

static void PrintDumpReport(BsodMinidumpReport d)
{
    Console.WriteLine($"  [{d.CrashLocalDisplay}] {d.BugCheckName} ({d.BugCheckHex}) | {d.CulpritBadge}");
    Console.WriteLine($"    Файл     : {d.DumpFilePath}");
    Console.WriteLine($"    Система  : {d.OsBuildSummary}");
    if (d.ParametersDisplay.Length > 0)
    {
        Console.WriteLine($"    Параметры: {d.ParametersDisplay}");
    }
    Console.WriteLine($"    Причина  : {d.SimpleHumanExplanation}");
    Console.WriteLine($"    Решение  : {d.RecommendedUserAction}");
    if (!string.IsNullOrEmpty(d.TechnicalEvidence))
    {
        Console.WriteLine($"    Основание: {d.TechnicalEvidence}");
    }
}
