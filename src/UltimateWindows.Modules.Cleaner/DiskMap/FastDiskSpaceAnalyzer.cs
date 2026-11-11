using System.Collections.Concurrent;
using System.Diagnostics;
using UltimateWindows.Modules.Cleaner.Models;

namespace UltimateWindows.Modules.Cleaner.DiskMap;

/// <summary>
/// Высокоскоростной многопоточный анализатор диска класса WizTree:
/// за один параллельный проход строит иерархическое дерево папок с долями и счетчиками,
/// таблицу расширений файлов с цветовой кодировкой и рейтинг крупнейших файлов без зависаний UI.
/// </summary>
public sealed class FastDiskSpaceAnalyzer
{
    private const int PrebuiltTreeDepth = 3;

    public static IReadOnlyList<DiskVolumeSummary> GetReadyVolumes()
    {
        var list = new List<DiskVolumeSummary>();
        try
        {
            foreach (var d in DriveInfo.GetDrives())
            {
                if (!d.IsReady) continue;
                try
                {
                    list.Add(new DiskVolumeSummary(
                        RootPath: d.RootDirectory.FullName,
                        VolumeLabel: SafeRead(() => d.VolumeLabel, ""),
                        FileSystem: SafeRead(() => d.DriveFormat, "NTFS"),
                        TotalBytes: d.TotalSize,
                        FreeBytes: d.AvailableFreeSpace));
                }
                catch
                {
                    // Пропускаем недоступный том
                }
            }
        }
        catch
        {
            // Fallback
        }

        return list;
    }

    public static (string ColorHex, string Description) ClassifyExtension(string ext)
    {
        var lower = ext.ToLowerInvariant();
        return lower switch
        {
            ".dll" or ".ocx" or ".mun" => ("#D97706", "Динамическая библиотека"),
            ".exe" or ".msi" or ".msix" or ".cmd" or ".bat" => ("#10B981", "Программа / установщик"),
            ".sys" or ".cat" or ".inf" => ("#6366F1", "Драйвер / компонент ядра"),
            ".mp4" or ".mkv" or ".avi" or ".mov" or ".webm" or ".wmv" => ("#A855F7", "Видеофайл"),
            ".mp3" or ".flac" or ".wav" or ".ogg" or ".m4a" => ("#14B8A6", "Аудиофайл"),
            ".jpg" or ".jpeg" or ".png" or ".webp" or ".gif" or ".bmp" or ".psd" or ".raw" => ("#EC4899", "Изображение / графика"),
            ".zip" or ".7z" or ".rar" or ".tar" or ".gz" or ".cab" => ("#06B6D4", "Сжатый архив"),
            ".pak" or ".ba2" or ".vpk" or ".cas" or ".asar" or ".assets" or ".bundle" or ".rpf" => ("#3B82F6", "Игровой архив ресурсов"),
            ".iso" or ".wim" or ".esd" or ".vhdx" or ".vhd" or ".vmdk" => ("#EF4444", "Образ диска / системы"),
            ".pdf" or ".docx" or ".xlsx" or ".pptx" or ".txt" or ".md" or ".rtf" => ("#84CC16", "Документ / текст"),
            ".db" or ".sqlite" or ".sqlite3" or ".mdf" or ".ldf" or ".dat" => ("#F59E0B", "База данных / кэш"),
            ".log" or ".dmp" or ".tmp" or ".etl" or ".old" or ".bak" => ("#64748B", "Временный файл / дамп / лог"),
            ".ttc" or ".ttf" or ".otf" or ".woff2" => ("#0EA5E9", "Шрифт системы"),
            "(без расширения)" => ("#78716C", "Файл без расширения"),
            _ => ("#8B5CF6", $"Файлы {lower}")
        };
    }

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

        var extAggregator = new ConcurrentDictionary<string, (long Bytes, long Count)>(StringComparer.OrdinalIgnoreCase);
        var largestBag = new ConcurrentBag<(string Path, long Bytes)>();

        long rootDirectBytes = 0;
        long rootDirectFiles = 0;
        DateTime rootLastWrite = DateTime.MinValue;

        var nonRecursive = new EnumerationOptions
        {
            IgnoreInaccessible = true,
            RecurseSubdirectories = false,
            AttributesToSkip = FileAttributes.ReparsePoint
        };

        var keepPerBranch = Math.Max(largestFilesLimit, 50);
        var rootMinHeap = new PriorityQueue<string, long>(keepPerBranch + 1);

        try
        {
            var rootDirInfo = new DirectoryInfo(fullRoot);
            rootLastWrite = SafeRead(() => rootDirInfo.LastWriteTime, DateTime.MinValue);

            foreach (var fi in rootDirInfo.EnumerateFiles("*", nonRecursive))
            {
                ct.ThrowIfCancellationRequested();
                var len = SafeRead(() => fi.Length, -1L);
                if (len < 0) continue;

                rootDirectBytes += len;
                rootDirectFiles++;
                AddExtensionSample(extAggregator, fi.Extension, len);

                if (rootMinHeap.Count < keepPerBranch)
                {
                    rootMinHeap.Enqueue(fi.FullName, len);
                }
                else if (rootMinHeap.TryPeek(out _, out var smallest) && len > smallest)
                {
                    rootMinHeap.DequeueEnqueue(fi.FullName, len);
                }
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            // Продолжаем при ограничении прав на корень
        }

        while (rootMinHeap.TryDequeue(out var rf, out var rs))
        {
            largestBag.Add((rf, rs));
        }

        DirectoryInfo[] topSubDirs;
        try
        {
            topSubDirs = new DirectoryInfo(fullRoot).EnumerateDirectories("*", nonRecursive).ToArray();
        }
        catch
        {
            topSubDirs = [];
        }

        var rawTrees = new ConcurrentBag<RawDirAccum>();
        var parallelOpts = new ParallelOptions
        {
            MaxDegreeOfParallelism = Math.Clamp(Environment.ProcessorCount, 2, 16),
            CancellationToken = ct
        };

        await Parallel.ForEachAsync(topSubDirs, parallelOpts, (subDirInfo, token) =>
        {
            var localExt = new Dictionary<string, (long Bytes, long Count)>(StringComparer.OrdinalIgnoreCase);
            var localMinHeap = new PriorityQueue<string, long>(keepPerBranch + 1);

            var rawNode = ScanDirectoryRecursive(
                subDirInfo,
                currentDepth: 1,
                maxTreeDepth: PrebuiltTreeDepth,
                keepTopFiles: keepPerBranch,
                localExt,
                localMinHeap,
                token);

            rawTrees.Add(rawNode);

            foreach (var kv in localExt)
            {
                extAggregator.AddOrUpdate(
                    kv.Key,
                    kv.Value,
                    (_, existing) => (existing.Bytes + kv.Value.Bytes, existing.Count + kv.Value.Count));
            }

            while (localMinHeap.TryDequeue(out var p, out var s))
            {
                largestBag.Add((p, s));
            }

            return ValueTask.CompletedTask;
        }).ConfigureAwait(false);

        sw.Stop();

        var orderedRawTop = rawTrees.OrderByDescending(x => x.TotalBytes).ToList();
        var totalBytes = rootDirectBytes + orderedRawTop.Sum(d => d.TotalBytes);
        var totalFiles = rootDirectFiles + orderedRawTop.Sum(d => d.TotalFiles);
        var totalFolders = orderedRawTop.Count + orderedRawTop.Sum(d => d.TotalFolders);
        var safeDenom = Math.Max(1L, totalBytes);

        // 1. Топ папок верхнего уровня (обратная совместимость + быстрые сводки)
        var topDirs = orderedRawTop
            .Where(d => d.TotalBytes > 0)
            .Take(topDirectoryLimit)
            .Select(d => new DiskSpaceItem(
                Name: d.Name,
                FullPath: d.FullPath,
                SizeBytes: d.TotalBytes,
                FileCount: d.TotalFiles,
                ShareOfScannedPercent: Math.Round((double)d.TotalBytes / safeDenom * 100.0, 1)))
            .ToList();

        // 2. Крупнейшие файлы
        var topFiles = largestBag
            .OrderByDescending(f => f.Bytes)
            .Take(largestFilesLimit)
            .Select(f => new DiskSpaceItem(
                Name: Path.GetFileName(f.Path),
                FullPath: f.Path,
                SizeBytes: f.Bytes,
                FileCount: 1,
                ShareOfScannedPercent: Math.Round((double)f.Bytes / safeDenom * 100.0, 1)))
            .ToList();

        // 3. Таблица расширений файлов (как правая панель в WizTree)
        var extStats = extAggregator
            .Select(kv =>
            {
                var (color, desc) = ClassifyExtension(kv.Key);
                return new DiskExtensionStat(
                    Extension: kv.Key,
                    FileTypeDescription: desc,
                    ColorHex: color,
                    SizeBytes: kv.Value.Bytes,
                    FileCount: kv.Value.Count,
                    SharePercent: Math.Round((double)kv.Value.Bytes / safeDenom * 100.0, 1));
            })
            .OrderByDescending(e => e.SizeBytes)
            .Take(100)
            .ToList();

        // 4. Иерархическое дерево WizTree с узлом [N файлов в корне]
        var rootChildren = new List<DiskTreeNode>(orderedRawTop.Count + 1);
        int paletteIdx = 0;
        string[] folderPalette =
        [
            "#3B82F6", "#8B5CF6", "#10B981", "#F59E0B", "#EC4899",
            "#06B6D4", "#6366F1", "#14B8A6", "#F97316", "#84CC16"
        ];

        foreach (var raw in orderedRawTop)
        {
            var color = folderPalette[paletteIdx++ % folderPalette.Length];
            rootChildren.Add(MaterializeTreeNode(raw, safeDenom, safeDenom, color));
        }

        if (rootDirectFiles > 0)
        {
            var rootLabel = fullRoot.TrimEnd(Path.DirectorySeparatorChar);
            if (string.IsNullOrEmpty(rootLabel)) rootLabel = fullRoot;
            rootChildren.Add(new DiskTreeNode(
                Name: $"[{rootDirectFiles:N0} файл(ов) в {rootLabel}]",
                FullPath: fullRoot,
                IsDirectory: false,
                IsDirectFilesBucket: true,
                SizeBytes: rootDirectBytes,
                FileCount: rootDirectFiles,
                FolderCount: 0,
                ShareOfRootPercent: Math.Round((double)rootDirectBytes / safeDenom * 100.0, 1),
                ShareOfParentPercent: Math.Round((double)rootDirectBytes / safeDenom * 100.0, 1),
                LastModifiedLocal: rootLastWrite,
                ColorHex: "#EAB308",
                Children: []));
        }

        rootChildren.Sort((a, b) => b.SizeBytes.CompareTo(a.SizeBytes));

        var rootDisplayName = Path.GetFileName(fullRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        if (string.IsNullOrWhiteSpace(rootDisplayName))
        {
            rootDisplayName = $"[{fullRoot.TrimEnd('\\')}] Локальный диск";
        }

        var rootTreeNode = new DiskTreeNode(
            Name: rootDisplayName,
            FullPath: fullRoot,
            IsDirectory: true,
            IsDirectFilesBucket: false,
            SizeBytes: totalBytes,
            FileCount: totalFiles,
            FolderCount: totalFolders,
            ShareOfRootPercent: 100.0,
            ShareOfParentPercent: 100.0,
            LastModifiedLocal: rootLastWrite,
            ColorHex: "#6366F1",
            Children: rootChildren);

        return new DiskSpaceAnalysisReport(
            RootPath: fullRoot,
            ScanMethodDescription: $"Многопоточный сканер UltimateWindows ({parallelOpts.MaxDegreeOfParallelism} потоков, без Reparse-петель)",
            Elapsed: sw.Elapsed,
            TotalScannedBytes: totalBytes,
            TotalFilesCount: totalFiles,
            TopDirectories: topDirs,
            LargestFiles: topFiles,
            RootTreeNodes: [rootTreeNode],
            ExtensionStats: extStats,
            TotalFoldersCount: totalFolders);
    }

    private sealed class RawDirAccum
    {
        public required string Name { get; init; }
        public required string FullPath { get; init; }
        public DateTime LastModified { get; init; }
        public long DirectBytes { get; set; }
        public long DirectFiles { get; set; }
        public long TotalBytes { get; set; }
        public long TotalFiles { get; set; }
        public long TotalFolders { get; set; }
        public bool TruncatedDeeperChildren { get; set; }
        public List<RawDirAccum> Children { get; } = [];
    }

    private static RawDirAccum ScanDirectoryRecursive(
        DirectoryInfo dir,
        int currentDepth,
        int maxTreeDepth,
        int keepTopFiles,
        Dictionary<string, (long Bytes, long Count)> extMap,
        PriorityQueue<string, long> minHeap,
        CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var accum = new RawDirAccum
        {
            Name = dir.Name,
            FullPath = dir.FullName,
            LastModified = SafeRead(() => dir.LastWriteTime, DateTime.MinValue)
        };

        var nonRecOpts = new EnumerationOptions
        {
            IgnoreInaccessible = true,
            RecurseSubdirectories = false,
            AttributesToSkip = FileAttributes.ReparsePoint
        };

        // 1. Прямые файлы этого каталога
        try
        {
            foreach (var fi in dir.EnumerateFiles("*", nonRecOpts))
            {
                ct.ThrowIfCancellationRequested();
                var len = SafeRead(() => fi.Length, -1L);
                if (len < 0) continue;

                accum.DirectBytes += len;
                accum.DirectFiles++;
                AddExtensionSampleLocal(extMap, fi.Extension, len);

                if (minHeap.Count < keepTopFiles)
                {
                    minHeap.Enqueue(fi.FullName, len);
                }
                else if (minHeap.TryPeek(out _, out var smallest) && len > smallest)
                {
                    minHeap.DequeueEnqueue(fi.FullName, len);
                }
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            // Недоступная системная ветка
        }

        accum.TotalBytes = accum.DirectBytes;
        accum.TotalFiles = accum.DirectFiles;

        // 2. Подкаталоги: до maxTreeDepth строим узлы дерева, глубже — быстро суммируем без аллокации узлов!
        if (currentDepth < maxTreeDepth)
        {
            DirectoryInfo[] subDirs;
            try
            {
                subDirs = dir.EnumerateDirectories("*", nonRecOpts).ToArray();
            }
            catch
            {
                subDirs = [];
            }

            foreach (var sub in subDirs)
            {
                var child = ScanDirectoryRecursive(sub, currentDepth + 1, maxTreeDepth, keepTopFiles, extMap, minHeap, ct);
                accum.TotalBytes += child.TotalBytes;
                accum.TotalFiles += child.TotalFiles;
                accum.TotalFolders += 1 + child.TotalFolders;
                if (child.TotalBytes > 0 || child.TotalFiles > 0)
                {
                    accum.Children.Add(child);
                }
            }

            // Оставляем до 60 крупнейших подпапок на каждом уровне, чтобы дерево раскрывалось мгновенно без лагов WPF
            if (accum.Children.Count > 60)
            {
                accum.Children.Sort((a, b) => b.TotalBytes.CompareTo(a.TotalBytes));
                accum.Children.RemoveRange(60, accum.Children.Count - 60);
            }
        }
        else
        {
            var deepOpts = new EnumerationOptions
            {
                IgnoreInaccessible = true,
                RecurseSubdirectories = true,
                AttributesToSkip = FileAttributes.ReparsePoint
            };

            try
            {
                // Проверяем наличие хотя бы одной подпапки
                foreach (var sub in dir.EnumerateDirectories("*", deepOpts))
                {
                    ct.ThrowIfCancellationRequested();
                    accum.TotalFolders++;
                    accum.TruncatedDeeperChildren = true;
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                // Игнорируем
            }

            try
            {
                foreach (var sub in dir.EnumerateDirectories("*", nonRecOpts))
                {
                    foreach (var fi in sub.EnumerateFiles("*", deepOpts))
                    {
                        ct.ThrowIfCancellationRequested();
                        var len = SafeRead(() => fi.Length, -1L);
                        if (len < 0) continue;

                        accum.TotalBytes += len;
                        accum.TotalFiles++;
                        AddExtensionSampleLocal(extMap, fi.Extension, len);

                        if (minHeap.Count < keepTopFiles)
                        {
                            minHeap.Enqueue(fi.FullName, len);
                        }
                        else if (minHeap.TryPeek(out _, out var smallest) && len > smallest)
                        {
                            minHeap.DequeueEnqueue(fi.FullName, len);
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                // Игнорируем
            }
        }

        return accum;
    }

    private static DiskTreeNode MaterializeTreeNode(
        RawDirAccum raw,
        long rootTotalBytes,
        long parentBytes,
        string colorHex)
    {
        var safeRoot = Math.Max(1L, rootTotalBytes);
        var safeParent = Math.Max(1L, parentBytes);
        var safeSelf = Math.Max(1L, raw.TotalBytes);

        var children = new List<DiskTreeNode>(raw.Children.Count + 1);
        foreach (var ch in raw.Children.OrderByDescending(c => c.TotalBytes))
        {
            children.Add(MaterializeTreeNode(ch, safeRoot, safeSelf, colorHex));
        }

        if (raw.DirectFiles > 0 && raw.Children.Count > 0)
        {
            children.Add(new DiskTreeNode(
                Name: $"[{raw.DirectFiles:N0} файл(ов) в {raw.Name}]",
                FullPath: raw.FullPath,
                IsDirectory: false,
                IsDirectFilesBucket: true,
                SizeBytes: raw.DirectBytes,
                FileCount: raw.DirectFiles,
                FolderCount: 0,
                ShareOfRootPercent: Math.Round((double)raw.DirectBytes / safeRoot * 100.0, 1),
                ShareOfParentPercent: Math.Round((double)raw.DirectBytes / safeSelf * 100.0, 1),
                LastModifiedLocal: raw.LastModified,
                ColorHex: "#EAB308",
                Children: []));
            children.Sort((a, b) => b.SizeBytes.CompareTo(a.SizeBytes));
        }

        return new DiskTreeNode(
            Name: raw.Name,
            FullPath: raw.FullPath,
            IsDirectory: true,
            IsDirectFilesBucket: false,
            SizeBytes: raw.TotalBytes,
            FileCount: raw.TotalFiles,
            FolderCount: raw.TotalFolders,
            ShareOfRootPercent: Math.Round((double)raw.TotalBytes / safeRoot * 100.0, 1),
            ShareOfParentPercent: Math.Round((double)raw.TotalBytes / safeParent * 100.0, 1),
            LastModifiedLocal: raw.LastModified,
            ColorHex: colorHex,
            Children: children,
            MayHaveDeeperSubfolders: raw.TruncatedDeeperChildren);
    }

    private static void AddExtensionSample(
        ConcurrentDictionary<string, (long Bytes, long Count)> dict,
        string? rawExt,
        long size)
    {
        var key = NormalizeExt(rawExt);
        dict.AddOrUpdate(key, (size, 1), (_, prev) => (prev.Bytes + size, prev.Count + 1));
    }

    private static void AddExtensionSampleLocal(
        Dictionary<string, (long Bytes, long Count)> dict,
        string? rawExt,
        long size)
    {
        var key = NormalizeExt(rawExt);
        if (dict.TryGetValue(key, out var prev))
        {
            dict[key] = (prev.Bytes + size, prev.Count + 1);
        }
        else
        {
            dict[key] = (size, 1);
        }
    }

    private static string NormalizeExt(string? rawExt) =>
        string.IsNullOrWhiteSpace(rawExt) || rawExt == "."
            ? "(без расширения)"
            : rawExt.ToLowerInvariant();

    private static T SafeRead<T>(Func<T> getter, T fallback)
    {
        try
        {
            return getter();
        }
        catch
        {
            return fallback;
        }
    }
}
