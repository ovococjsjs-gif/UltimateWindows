using System.Diagnostics;
using UltimateWindows.Modules.Cleaner.Models;

namespace UltimateWindows.Modules.Cleaner.DiskMap;

/// <summary>
/// Инспектор и освободитель крупных системных резервов на диске C:\ (особенно актуально для SSD 120–256 ГБ):
/// hiberfil.sys (гибернация — часто 6–13 ГБ на ПК с 32 ГБ ОЗУ!), Windows.old, кэш загрузок Windows Update и сжатие WinSxS.
/// </summary>
public sealed class SystemSpaceReclaimer
{
    public Task<IReadOnlyList<SystemSpaceReserveItem>> InspectSystemReservesAsync(CancellationToken ct = default)
    {
        return Task.Run<IReadOnlyList<SystemSpaceReserveItem>>(() =>
        {
            var sysRoot = Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\";
            var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (string.IsNullOrWhiteSpace(winDir)) winDir = Path.Combine(sysRoot, "Windows");

            var items = new List<SystemSpaceReserveItem>();

            // 1. Файл гибернации hiberfil.sys
            var hiberPath = Path.Combine(sysRoot, "hiberfil.sys");
            var hiberBytes = TryGetAnyFileLength(hiberPath);
            items.Add(new SystemSpaceReserveItem(
                Kind: SystemReserveKind.HibernationFile,
                Title: "Файл спящего режима гибернации (hiberfil.sys)",
                Description: hiberBytes > 0
                    ? "Резервирует часть объема ОЗУ на системном диске. На настольном ПК гибернацию можно безопасно отключить и мгновенно вернуть гигабайты!"
                    : "Гибернация сейчас отключена (файл hiberfil.sys не занимает место на C:\\). Можно включить обратно в 1 клик.",
                PathDisplay: hiberPath,
                SizeBytes: hiberBytes,
                CanActionReclaim: true,
                RequiresAdmin: true,
                ActionButtonLabel: hiberBytes > 0 ? "Отключить гибернацию и освободить" : "Включить гибернацию обратно"));

            // 2. Старая копия системы Windows.old
            var winOldPath = Path.Combine(sysRoot, "Windows.old");
            var winOldBytes = Directory.Exists(winOldPath) ? TrySumDirectoryQuick(winOldPath, maxSeconds: 2, ct) : 0;
            items.Add(new SystemSpaceReserveItem(
                Kind: SystemReserveKind.WindowsOldFolder,
                Title: "Резервная папка прошлого крупного обновления (Windows.old)",
                Description: "Остается после обновления сборки Windows. Если система работает стабильно, её удаление освобождает 10–25 ГБ.",
                PathDisplay: winOldPath,
                SizeBytes: winOldBytes,
                CanActionReclaim: winOldBytes > 0,
                RequiresAdmin: true,
                ActionButtonLabel: "Очистить Windows.old"));

            // 3. Кэш скачанных пакетов Центра обновления SoftwareDistribution\Download
            var wuDownload = Path.Combine(winDir, "SoftwareDistribution", "Download");
            var wuBytes = Directory.Exists(wuDownload) ? TrySumDirectoryQuick(wuDownload, maxSeconds: 2, ct) : 0;
            items.Add(new SystemSpaceReserveItem(
                Kind: SystemReserveKind.WindowsUpdateDownloadCache,
                Title: "Скачанные пакеты Центра обновления (SoftwareDistribution\\Download)",
                Description: "Установочные архивы уже поставленных обновлений Windows, которые больше не нужны.",
                PathDisplay: wuDownload,
                SizeBytes: wuBytes,
                CanActionReclaim: wuBytes > 0,
                RequiresAdmin: true,
                ActionButtonLabel: "Очистить кэш обновлений"));

            // 3б. Кэш оптимизации доставки (Delivery Optimization)
            var doCachePath = Path.Combine(winDir, "ServiceProfiles", "NetworkService", "AppData", "Local", "Microsoft", "Windows", "DeliveryOptimization", "Cache");
            var doBytes = Directory.Exists(doCachePath) ? TrySumDirectoryQuick(doCachePath, maxSeconds: 2, ct) : 0;
            items.Add(new SystemSpaceReserveItem(
                Kind: SystemReserveKind.DeliveryOptimizationCache,
                Title: "Кэш оптимизации доставки обновлений (Delivery Optimization)",
                Description: "Части скачанных обновлений и приложений Store, хранящиеся для раздачи другим ПК в локальной сети.",
                PathDisplay: doCachePath,
                SizeBytes: doBytes,
                CanActionReclaim: doBytes > 0,
                RequiresAdmin: true,
                ActionButtonLabel: "Очистить кэш доставки"));

            // 3в. Системные дампы памяти ядра (MEMORY.DMP, Minidump, LiveKernelReports)
            var fullDumpPath = Path.Combine(winDir, "MEMORY.DMP");
            var minidumpDir = Path.Combine(winDir, "Minidump");
            var liveKernelDir = Path.Combine(winDir, "LiveKernelReports");
            var dumpBytes = TryGetAnyFileLength(fullDumpPath)
                + (Directory.Exists(minidumpDir) ? TrySumDirectoryQuick(minidumpDir, maxSeconds: 1, ct) : 0)
                + (Directory.Exists(liveKernelDir) ? TrySumDirectoryQuick(liveKernelDir, maxSeconds: 1, ct) : 0);
            items.Add(new SystemSpaceReserveItem(
                Kind: SystemReserveKind.SystemMemoryDumps,
                Title: "Системные дампы памяти после сбоев (MEMORY.DMP / Minidump)",
                Description: "Снимки памяти прошлых синих экранов. Удаляйте, только если разбор прошлых сбоев уже не нужен.",
                PathDisplay: $"{fullDumpPath}; {minidumpDir}",
                SizeBytes: dumpBytes,
                CanActionReclaim: dumpBytes > 0,
                RequiresAdmin: true,
                ActionButtonLabel: "Удалить дампы сбоев"));

            // 3г. Архивные журналы установки и обслуживания (CBS / DISM / Panther)
            var logsDir = Path.Combine(winDir, "Logs");
            var pantherDir = Path.Combine(winDir, "Panther");
            var logsBytes = (Directory.Exists(logsDir) ? TrySumDirectoryQuick(logsDir, maxSeconds: 1, ct) : 0)
                + (Directory.Exists(pantherDir) ? TrySumDirectoryQuick(pantherDir, maxSeconds: 1, ct) : 0);
            items.Add(new SystemSpaceReserveItem(
                Kind: SystemReserveKind.WindowsSetupAndCbsLogs,
                Title: "Журналы установки и обслуживания Windows (Logs\\CBS, DISM, Panther)",
                Description: "Накопленные текстовые журналы прошлых обновлений и проверок целостности старше суток.",
                PathDisplay: logsDir,
                SizeBytes: logsBytes,
                CanActionReclaim: logsBytes > 0,
                RequiresAdmin: true,
                ActionButtonLabel: "Очистить старые журналы"));

            // 4. Хранилище компонентов WinSxS (штатная очистка DISM StartComponentCleanup)
            var winSxsPath = Path.Combine(winDir, "WinSxS");
            var winSxsBytes = Directory.Exists(winSxsPath) ? TrySumDirectoryQuick(winSxsPath, maxSeconds: 2, ct) : 0;
            items.Add(new SystemSpaceReserveItem(
                Kind: SystemReserveKind.WinSxSComponentStore,
                Title: "Хранилище системных компонентов (Windows\\WinSxS)",
                Description: "Штатное сжатие устаревших версий системных библиотек через официальный инструмент DISM StartComponentCleanup (безопасно для ОС).",
                PathDisplay: winSxsPath,
                SizeBytes: winSxsBytes,
                CanActionReclaim: OperatingSystem.IsWindows(),
                RequiresAdmin: true,
                ActionButtonLabel: "Сжать устаревшие версии (DISM)"));

            // 5. Файл подкачки pagefile.sys (только информирование — удалять его вредно для игр!)
            var pagePath = Path.Combine(sysRoot, "pagefile.sys");
            var pageBytes = TryGetAnyFileLength(pagePath);
            items.Add(new SystemSpaceReserveItem(
                Kind: SystemReserveKind.PageFileInfo,
                Title: "Файл виртуальной памяти (pagefile.sys — справка)",
                Description: "Необходим для стабильной работы игр и тяжелых редакторов даже при 32 ГБ ОЗУ. Полное отключение не рекомендуется.",
                PathDisplay: pagePath,
                SizeBytes: pageBytes,
                CanActionReclaim: false,
                RequiresAdmin: false,
                ActionButtonLabel: "Системный резерв"));

            return items;
        }, ct);
    }

    public async Task<(bool Succeeded, string Message)> ExecuteReserveActionAsync(
        SystemSpaceReserveItem item,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return (false, "Операция доступна только в среде Windows.");
        }

        switch (item.Kind)
        {
            case SystemReserveKind.HibernationFile:
            {
                var turnOff = item.SizeBytes > 0;
                var ok = await RunSystemToolAsync("powercfg.exe", ["/hibernate", turnOff ? "off" : "on"], ct).ConfigureAwait(false);
                return ok
                    ? (true, turnOff
                        ? $"Гибернация отключена — файл hiberfil.sys удален, освобождено {item.FormattedSize}!"
                        : "Гибернация успешно включена обратно.")
                    : (false, "Не удалось изменить режим гибернации (запустите программу от имени Администратора).");
            }

            case SystemReserveKind.WindowsUpdateDownloadCache:
            {
                if (!Directory.Exists(item.PathDisplay))
                {
                    return (true, "Папка кэша обновлений уже пуста.");
                }

                _ = await RunSystemToolAsync("net.exe", ["stop", "wuauserv"], ct).ConfigureAwait(false);
                int deleted = 0;
                try
                {
                    foreach (var entry in Directory.EnumerateFileSystemEntries(item.PathDisplay))
                    {
                        try
                        {
                            if (Directory.Exists(entry)) Directory.Delete(entry, recursive: true);
                            else File.Delete(entry);
                            deleted++;
                        }
                        catch
                        {
                            // Пропускаем занятый элемент
                        }
                    }
                }
                finally
                {
                    _ = await RunSystemToolAsync("net.exe", ["start", "wuauserv"], ct).ConfigureAwait(false);
                }

                return (true, $"Очищено элементов кэша Центра обновления: {deleted}.");
            }

            case SystemReserveKind.WindowsOldFolder:
            {
                if (!Directory.Exists(item.PathDisplay))
                {
                    return (true, "Папка Windows.old отсутствует.");
                }

                var ok = await RunSystemToolAsync("cmd.exe", ["/c", $"rd /s /q \"{item.PathDisplay}\""], ct).ConfigureAwait(false);
                return ok || !Directory.Exists(item.PathDisplay)
                    ? (true, "Старая копия Windows.old успешно очищена.")
                    : (false, "Часть файлов Windows.old защищена TrustedInstaller — используйте штатную «Очистку системных файлов» или права Администратора.");
            }

            case SystemReserveKind.DeliveryOptimizationCache:
            {
                _ = await RunSystemToolAsync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", "Delete-DeliveryOptimizationCache -Force -ErrorAction SilentlyContinue"], ct).ConfigureAwait(false);
                int deleted = DeleteDirectoryContentsBestEffort(item.PathDisplay);
                return (true, $"Кэш оптимизации доставки очищен (удалено элементов: {deleted}).");
            }

            case SystemReserveKind.SystemMemoryDumps:
            {
                var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                int deleted = 0;
                var memoryDmp = Path.Combine(winDir, "MEMORY.DMP");
                try { if (File.Exists(memoryDmp)) { File.Delete(memoryDmp); deleted++; } } catch { }
                deleted += DeleteFilesByExtensionBestEffort(Path.Combine(winDir, "Minidump"), ".dmp", minAgeHours: 0);
                deleted += DeleteFilesByExtensionBestEffort(Path.Combine(winDir, "LiveKernelReports"), ".dmp", minAgeHours: 0);
                return (true, $"Удалено файлов дампов памяти: {deleted}.");
            }

            case SystemReserveKind.WindowsSetupAndCbsLogs:
            {
                var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                int deleted = 0;
                deleted += DeleteFilesByExtensionBestEffort(Path.Combine(winDir, "Logs", "CBS"), ".log", minAgeHours: 24, prefixFilter: "CbsPersist_");
                deleted += DeleteFilesByExtensionBestEffort(Path.Combine(winDir, "Logs", "DISM"), ".log", minAgeHours: 24);
                deleted += DeleteFilesByExtensionBestEffort(Path.Combine(winDir, "Panther"), ".log", minAgeHours: 24);
                return (true, $"Удалено старых журналов обслуживания: {deleted}.");
            }

            case SystemReserveKind.WinSxSComponentStore:
            {
                var ok = await RunSystemToolAsync("Dism.exe", ["/Online", "/Cleanup-Image", "/StartComponentCleanup"], ct).ConfigureAwait(false);
                return ok
                    ? (true, "Штатная очистка устаревших компонентов WinSxS (DISM StartComponentCleanup) успешно завершена!")
                    : (false, "Не удалось завершить DISM StartComponentCleanup (требуются права Администратора).");
            }

            default:
                return (false, "Этот системный файл защищен от удаления для стабильности ОС.");
        }
    }

    private static int DeleteDirectoryContentsBestEffort(string dirPath)
    {
        if (string.IsNullOrWhiteSpace(dirPath) || !Directory.Exists(dirPath)) return 0;
        int deleted = 0;
        try
        {
            foreach (var entry in Directory.EnumerateFileSystemEntries(dirPath))
            {
                try
                {
                    if (Directory.Exists(entry)) Directory.Delete(entry, recursive: true);
                    else File.Delete(entry);
                    deleted++;
                }
                catch { }
            }
        }
        catch { }
        return deleted;
    }

    private static int DeleteFilesByExtensionBestEffort(string dirPath, string extension, int minAgeHours, string? prefixFilter = null)
    {
        if (string.IsNullOrWhiteSpace(dirPath) || !Directory.Exists(dirPath)) return 0;
        int deleted = 0;
        var cutoff = DateTime.UtcNow.AddHours(-Math.Max(0, minAgeHours));
        var opts = new EnumerationOptions { IgnoreInaccessible = true, RecurseSubdirectories = true, AttributesToSkip = FileAttributes.ReparsePoint };
        try
        {
            foreach (var file in Directory.EnumerateFiles(dirPath, "*" + extension, opts))
            {
                try
                {
                    var name = Path.GetFileName(file);
                    if (prefixFilter is not null && !name.StartsWith(prefixFilter, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    var fi = new FileInfo(file);
                    if (minAgeHours > 0 && fi.LastWriteTimeUtc > cutoff)
                    {
                        continue;
                    }

                    fi.Delete();
                    deleted++;
                }
                catch { }
            }
        }
        catch { }
        return deleted;
    }

    private static long TryGetAnyFileLength(string path)
    {
        try
        {
            // FileInfo.Length читает метаданные каталога даже для заблокированных системных файлов hiberfil.sys / pagefile.sys!
            var fi = new FileInfo(path);
            return fi.Exists ? fi.Length : 0L;
        }
        catch
        {
            return 0L;
        }
    }

    private static long TrySumDirectoryQuick(string path, int maxSeconds, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        long sum = 0;
        var opts = new EnumerationOptions
        {
            IgnoreInaccessible = true,
            RecurseSubdirectories = true,
            AttributesToSkip = FileAttributes.ReparsePoint
        };

        try
        {
            foreach (var fi in new DirectoryInfo(path).EnumerateFiles("*", opts))
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    sum += fi.Length;
                }
                catch
                {
                    // Игнорируем
                }

                if (sw.Elapsed.TotalSeconds >= maxSeconds)
                {
                    break;
                }
            }
        }
        catch
        {
            // Игнорируем
        }

        return sum;
    }

    private static async Task<bool> RunSystemToolAsync(string exeName, IReadOnlyList<string> args, CancellationToken ct)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = exeName,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            foreach (var a in args) psi.ArgumentList.Add(a);

            using var proc = Process.Start(psi);
            if (proc is null) return false;
            await proc.WaitForExitAsync(ct).ConfigureAwait(false);
            return proc.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }
}
