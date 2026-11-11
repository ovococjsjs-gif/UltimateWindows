using System.Text;
using UltimateWindows.Core.Guards;
using UltimateWindows.Modules.Cleaner.Models;
using UltimateWindows.Modules.Cleaner.Services;
using UltimateWindows.Modules.Drivers.Orchestration;
using UltimateWindows.Modules.Drivers.Services;
using UltimateWindows.Modules.Hardware.Services;
using UltimateWindows.Modules.Optimizer.Models;
using UltimateWindows.Modules.Optimizer.Services;
using UltimateWindows.Modules.Repair.Models;
using UltimateWindows.Modules.Repair.Services;
using UltimateWindows.Modules.Safety.Services;
using UltimateWindows.Modules.Security.Services;
using UltimateWindows.NativeInterop.Cleaner;
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
        Console.WriteLine($"Запуск безопасного стресс-теста на {seconds} сек (Thermal Cutoff = 90°C)...");
        var res = await hardware.RunThermalSafeStressTestAsync(TimeSpan.FromSeconds(seconds), maxSafeCpuTempC: 90, maxSafeGpuTempC: 88);
        Console.WriteLine(res.StatusMessage);
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

    case "disk-map":
    {
        var targetPath = args.Length > 1
            ? args[1]
            : Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var diskReport = await cleaner.AnalyzeDiskSpaceAsync(targetPath, topDirectoryLimit: 10, largestFilesLimit: 10);
        Console.WriteLine($"=== Карта диска: {diskReport.RootPath} ===");
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

    case "miner-scan":
    {
        var probe = args.Length < 2 || !string.Equals(args[1], "--fast", StringComparison.OrdinalIgnoreCase);
        var report = await security.RunFullSecurityScanAsync(probe);
        Console.WriteLine($"=== UltimateWindows Phase 5 — Охотник на майнеры (Индекс: {report.SecurityHealthScore}/100) ===");
        Console.WriteLine(report.HeadlineSummary);

        if (report.Threats.Count > 0)
        {
            Console.WriteLine($"\nОбнаружено угроз ({report.Threats.Count}):");
            foreach (var t in report.Threats)
            {
                Console.WriteLine($"  - [{t.ConfidenceBadge}] {t.SimpleTitle}");
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

    case "miner-heal-os":
    {
        var report = await security.RunFullSecurityScanAsync(enableDropOnInspectProbe: false);
        var res = await security.HealAllSabotageLocksAsync(report.SabotageLocks);
        Console.WriteLine(res.UserFriendlyMessage);
        return res.Succeeded ? 0 : 1;
    }

    case "drivers-audit":
    {
        var online = args.Length >= 2 && string.Equals(args[1], "--online", StringComparison.OrdinalIgnoreCase);
        var report = await drivers.AuditDevicesAndDriversAsync(online);
        Console.WriteLine($"=== UltimateWindows Phase 6 — Аудит устройств и WHQL-драйверов ({report.DriverHealthScore}/100) ===");
        Console.WriteLine(report.SummaryHeadline);
        foreach (var f in report.Findings)
        {
            Console.WriteLine($"  - [{f.Severity}] {f.SimpleTitle}");
            Console.WriteLine($"      {f.SimpleExplanation}");
            Console.WriteLine($"      {f.ExpertTechnicalDetails}");
        }
        break;
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

    default:
    {
        Console.WriteLine("Доступные команды: status | smart-audit | hardware-audit | stress-test [сек] | drivers-audit [--online] | driver-backup <oemXX.inf> | clean-scan | clean-run | disk-map [путь] | pe-doctor <exe> | bsod-scan | bsod-file <dmp> | repair-list | repair-run <id> | tweak-list [раздел] [--on|--off] | tweak-info <id> | tweak-enable <id> [--force] | tweak-disable <id> | preset-list | preset-apply <набор> [--dry-run] [--force] | tweak-export [yaml] | tweak-import <yaml> [--dry-run] [--force] | service-list [--third-party] [--running] | service-set <имя> <auto|delayed|manual|disabled> | task-list [--third-party] [--enabled] | task-enable <путь> | task-disable <путь> | startup-list | unlock-check <path> | miner-scan [--fast] | miner-heal-os | history | cleanup-blobs | rollback <id> | check-path <path>");
        break;
    }
}

return 0;

static bool HasFlag(string[] arguments, string flag) =>
    arguments.Any(a => string.Equals(a, flag, StringComparison.OrdinalIgnoreCase));

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
