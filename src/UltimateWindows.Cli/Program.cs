using System.Text;
using UltimateWindows.Core.Guards;
using UltimateWindows.Modules.Cleaner.Models;
using UltimateWindows.Modules.Cleaner.Services;
using UltimateWindows.Modules.Hardware.Services;
using UltimateWindows.Modules.Safety.Services;
using UltimateWindows.NativeInterop.Cleaner;
using UltimateWindows.NativeInterop.Hardware;
using UltimateWindows.NativeInterop.Restore;
using UltimateWindows.NativeInterop.Security;

Console.OutputEncoding = Encoding.UTF8;

var vault = new ZeroBloatVaultService(stateApplier: new WindowsSystemStateApplier());
var hardware = new HardwareStudioService(vault, new WindowsHardwarePlatformProvider());
var cleaner = new VaultSafeCleanerService(vault, new WindowsCleanerPlatformBridge());
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

        await vault.RollbackTransactionAsync(sessionId);
        Console.WriteLine($"Транзакция {sessionId} успешно возвращена в исходное состояние.");
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
        Console.WriteLine("Доступные команды: status | hardware-audit | stress-test [сек] | clean-scan | clean-run | disk-map [путь] | history | cleanup-blobs | rollback <id> | check-path <path>");
        break;
    }
}

return 0;
