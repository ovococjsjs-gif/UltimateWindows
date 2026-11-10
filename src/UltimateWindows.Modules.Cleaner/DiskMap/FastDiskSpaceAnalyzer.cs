using System.Collections.Concurrent;
using System.Diagnostics;
using UltimateWindows.Modules.Cleaner.Models;

namespace UltimateWindows.Modules.Cleaner.DiskMap;

/// <summary>
/// Высокоскоростной анализатор занятого места на диске с параллельным обходом без блокировок
/// и пропуском символических ссылок / точек соединения NTFS (ReparsePoint), исключающим двойной подсчет.
/// </summary>
public sealed class FastDiskSpaceAnalyzer
{
    public async Task<DiskSpaceAnalysisReport> AnalyzeDirectoryOrDriveAsync(
        string rootPath,
        int topDirectoryLimit = 12,
        int largestFilesLimit = 15,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootPath);
        var fullRoot = Path.GetFullPath(rootPath);
        if (!Directory.Exists(fullRoot))
        {
            throw new DirectoryNotFoundException($"Путь '{fullRoot}' не найден.");
        }

        var sw = Stopwatch.StartNew();

        long rootDirectBytes = 0;
        long rootDirectFiles = 0;
        var largestBag = new ConcurrentBag<(string Path, long Bytes)>();

        // 1. Считаем файлы, лежащие прямо в корне выбранного пути
        var rootNonRecursive = new EnumerationOptions
        {
            IgnoreInaccessible = true,
            RecurseSubdirectories = false,
            AttributesToSkip = FileAttributes.ReparsePoint
        };

        var rootMinHeap = new PriorityQueue<string, long>(largestFilesLimit + 1);
        try
        {
            foreach (var file in Directory.EnumerateFiles(fullRoot, "*", rootNonRecursive))
            {
                ct.ThrowIfCancellationRequested();
                if (TryGetFileSize(file, out var len))
                {
                    rootDirectBytes += len;
                    rootDirectFiles++;
                    if (rootMinHeap.Count < largestFilesLimit)
                    {
                        rootMinHeap.Enqueue(file, len);
                    }
                    else if (rootMinHeap.TryPeek(out _, out var smallestTop) && len > smallestTop)
                    {
                        rootMinHeap.DequeueEnqueue(file, len);
                    }
                }
            }
        }
        catch
        {
            // Продолжаем при ограничении прав на корень
        }

        while (rootMinHeap.TryDequeue(out var rootFile, out var rootSize))
        {
            largestBag.Add((rootFile, rootSize));
        }

        // 2. Параллельный подсчет всех подкаталогов верхнего уровня без пересечений и ReparsePoint-петель
        string[] subDirs;
        try
        {
            subDirs = Directory.EnumerateDirectories(fullRoot, "*", rootNonRecursive).ToArray();
        }
        catch
        {
            subDirs = [];
        }

        var dirTotals = new ConcurrentBag<(string Name, string FullPath, long Bytes, long Count)>();
        var parallelOpts = new ParallelOptions
        {
            MaxDegreeOfParallelism = Math.Clamp(Environment.ProcessorCount, 2, 16),
            CancellationToken = ct
        };

        await Parallel.ForEachAsync(subDirs, parallelOpts, (subDir, token) =>
        {
            var (bytes, files, localLargest) = ScanSubtreeSync(subDir, largestFilesLimit, token);
            dirTotals.Add((Path.GetFileName(subDir), subDir, bytes, files));
            foreach (var lf in localLargest)
            {
                largestBag.Add(lf);
            }

            return ValueTask.CompletedTask;
        }).ConfigureAwait(false);

        sw.Stop();

        var totalBytes = rootDirectBytes + dirTotals.Sum(d => d.Bytes);
        var totalFiles = rootDirectFiles + dirTotals.Sum(d => d.Count);
        var safeDenominator = Math.Max(1L, totalBytes);

        var topDirs = dirTotals
            .Where(d => d.Bytes > 0)
            .OrderByDescending(d => d.Bytes)
            .Take(topDirectoryLimit)
            .Select(d => new DiskSpaceItem(
                Name: d.Name,
                FullPath: d.FullPath,
                SizeBytes: d.Bytes,
                FileCount: d.Count,
                ShareOfScannedPercent: Math.Round((double)d.Bytes / safeDenominator * 100.0, 1)))
            .ToList();

        var topFiles = largestBag
            .OrderByDescending(f => f.Bytes)
            .Take(largestFilesLimit)
            .Select(f => new DiskSpaceItem(
                Name: Path.GetFileName(f.Path),
                FullPath: f.Path,
                SizeBytes: f.Bytes,
                FileCount: 1,
                ShareOfScannedPercent: Math.Round((double)f.Bytes / safeDenominator * 100.0, 1)))
            .ToList();

        return new DiskSpaceAnalysisReport(
            RootPath: fullRoot,
            ScanMethodDescription: $"Параллельный многопоточный сканер файловой таблицы ({parallelOpts.MaxDegreeOfParallelism} потоков, защита от Reparse-петель)",
            Elapsed: sw.Elapsed,
            TotalScannedBytes: totalBytes,
            TotalFilesCount: totalFiles,
            TopDirectories: topDirs,
            LargestFiles: topFiles);
    }

    private static (long Bytes, long Files, List<(string Path, long Bytes)> TopLocalFiles) ScanSubtreeSync(
        string subDir,
        int keepTopCount,
        CancellationToken ct)
    {
        var recursiveOpts = new EnumerationOptions
        {
            IgnoreInaccessible = true,
            RecurseSubdirectories = true,
            AttributesToSkip = FileAttributes.ReparsePoint
        };

        long totalBytes = 0;
        long totalFiles = 0;
        // Мини-куча (PriorityQueue) удерживает только N самых крупных файлов ветки без расхода ОЗУ!
        var minHeap = new PriorityQueue<string, long>(keepTopCount + 1);

        try
        {
            foreach (var file in Directory.EnumerateFiles(subDir, "*", recursiveOpts))
            {
                ct.ThrowIfCancellationRequested();
                if (!TryGetFileSize(file, out var len))
                {
                    continue;
                }

                totalBytes += len;
                totalFiles++;

                if (minHeap.Count < keepTopCount)
                {
                    minHeap.Enqueue(file, len);
                }
                else if (minHeap.TryPeek(out _, out var smallestTop) && len > smallestTop)
                {
                    minHeap.DequeueEnqueue(file, len);
                }
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            // Игнорируем системные закрытые ветки вроде System Volume Information
        }

        var localTop = new List<(string Path, long Bytes)>(minHeap.Count);
        while (minHeap.TryDequeue(out var path, out var size))
        {
            localTop.Add((path, size));
        }

        return (totalBytes, totalFiles, localTop);
    }

    private static bool TryGetFileSize(string filePath, out long length)
    {
        try
        {
            var fi = new FileInfo(filePath);
            if (fi.Exists)
            {
                length = fi.Length;
                return true;
            }
        }
        catch
        {
            // Игнорируем удаленные на лету файлы
        }

        length = 0;
        return false;
    }
}
