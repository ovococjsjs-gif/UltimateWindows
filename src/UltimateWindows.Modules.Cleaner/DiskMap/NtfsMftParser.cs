using System.Buffers.Binary;
using System.Diagnostics;
using UltimateWindows.Modules.Cleaner.Models;

namespace UltimateWindows.Modules.Cleaner.DiskMap;

/// <summary>
/// Запись о файле или папке, прочитанная из таблицы файлов NTFS (<c>$MFT</c>).
/// Номера записей 48-битные (младшие 6 байт из 64-битной ссылки NTFS).
/// </summary>
public readonly record struct NtfsMftEntry(
    ulong RecordNumber,
    ulong ParentRecordNumber,
    string Name,
    long SizeBytes,
    long LastWriteFileTimeUtc,
    bool IsDirectory,
    bool IsReparsePoint);

/// <summary>
/// Потоковый разборщик записей NTFS Master File Table (<c>$MFT</c>) и сборщик дерева диска по ним.
/// <para>
/// Зачем он нужен: при обычном обходе через <c>DirectoryInfo</c> операционная система открывает каждую папку
/// отдельным системным вызовом — на сотнях тысяч файлов это десятки секунд. Чтение <c>$MFT</c> большими блоками
/// (по несколько мегабайт за вызов) отдаёт имена, родителей и размеры всех файлов тома за доли секунды — секунды.
/// </para>
/// <para>
/// Вся логика разбора бинарных записей <c>FILE</c>, применения маркеров целостности секторов (Update Sequence Array),
/// выбора длинного имени Win32 вместо короткого DOS <c>8.3</c> и выбора точного размера из неподписанного потока
/// <c>$DATA</c> написана на чистом C# без Win32-зависимостей, поэтому проверяется обычными модульными тестами.
/// </para>
/// </summary>
public static class NtfsMftParser
{
    public const uint FileSignature = 0x454C4946; // 'FILE' в little-endian
    public const ushort FlagInUse = 0x0001;
    public const ushort FlagIsDirectory = 0x0002;

    public const uint AttrStandardInformation = 0x10;
    public const uint AttrFileName = 0x30;
    public const uint AttrData = 0x80;
    public const uint AttrEnd = 0xFFFFFFFF;

    public const uint FileAttrReparsePoint = 0x00000400;

    // Пространства имён атрибута $FILE_NAME: 0 = POSIX, 1 = Win32, 2 = DOS 8.3, 3 = Win32+DOS
    public const byte NamespacePosix = 0;
    public const byte NamespaceWin32 = 1;
    public const byte NamespaceDos = 2;
    public const byte NamespaceWin32AndDos = 3;

    public const ulong RootDirectoryRecordNumber = 5;
    private const int BytesPerSector = 512;
    private const int PrebuiltTreeDepth = 3;

    /// <summary>
    /// Разбирает одну запись MFT (обычно 1024 или 4096 байт) после применения маркеров целостности секторов.
    /// Возвращает <c>true</c> для живых пользовательских записей с валидным именем.
    /// Системные метафайлы NTFS (записи 0..15, кроме корня 5, и имена с ведущим «$» в корне) пропускаются.
    /// </summary>
    public static bool TryParseRecord(
        Span<byte> recordBuffer,
        ulong recordNumber,
        out NtfsMftEntry entry)
    {
        entry = default;

        if (recordBuffer.Length < 48)
        {
            return false;
        }

        if (BinaryPrimitives.ReadUInt32LittleEndian(recordBuffer) != FileSignature)
        {
            return false;
        }

        var flags = BinaryPrimitives.ReadUInt16LittleEndian(recordBuffer[22..]);
        if ((flags & FlagInUse) == 0)
        {
            return false;
        }

        if (!ApplyUpdateSequenceFixup(recordBuffer))
        {
            return false;
        }

        var isDir = (flags & FlagIsDirectory) != 0;
        var attrOffset = (int)BinaryPrimitives.ReadUInt16LittleEndian(recordBuffer[20..]);
        var bytesInUse = (int)BinaryPrimitives.ReadUInt32LittleEndian(recordBuffer[24..]);
        var limit = Math.Min(recordBuffer.Length, bytesInUse > 0 ? bytesInUse : recordBuffer.Length);

        if (attrOffset < 24 || attrOffset >= limit)
        {
            return false;
        }

        string? bestName = null;
        int bestNamespaceRank = -1;
        ulong bestParent = 0;
        long fnSize = 0;
        long fnWriteTime = 0;
        uint fnFlags = 0;

        long stdWriteTime = 0;
        uint stdFlags = 0;
        bool hasDataAttr = false;
        long primaryDataSize = 0;

        int pos = attrOffset;
        while (pos + 8 <= limit)
        {
            var type = BinaryPrimitives.ReadUInt32LittleEndian(recordBuffer[pos..]);
            if (type == AttrEnd || type == 0)
            {
                break;
            }

            var attrLen = (int)BinaryPrimitives.ReadUInt32LittleEndian(recordBuffer[(pos + 4)..]);
            if (attrLen < 16 || pos + attrLen > limit)
            {
                break;
            }

            var nonResident = recordBuffer[pos + 8];
            var nameLenChars = recordBuffer[pos + 9];

            if (type == AttrStandardInformation && nonResident == 0 && pos + 24 <= limit)
            {
                var valueLen = (int)BinaryPrimitives.ReadUInt32LittleEndian(recordBuffer[(pos + 16)..]);
                var valueOff = (int)BinaryPrimitives.ReadUInt16LittleEndian(recordBuffer[(pos + 20)..]);
                if (valueLen >= 36 && pos + valueOff + 36 <= pos + attrLen)
                {
                    var val = recordBuffer.Slice(pos + valueOff, valueLen);
                    stdWriteTime = BinaryPrimitives.ReadInt64LittleEndian(val[8..]);
                    stdFlags = BinaryPrimitives.ReadUInt32LittleEndian(val[32..]);
                }
            }
            else if (type == AttrFileName && nonResident == 0 && pos + 24 <= limit)
            {
                var valueLen = (int)BinaryPrimitives.ReadUInt32LittleEndian(recordBuffer[(pos + 16)..]);
                var valueOff = (int)BinaryPrimitives.ReadUInt16LittleEndian(recordBuffer[(pos + 20)..]);
                if (valueLen >= 66 && pos + valueOff + valueLen <= pos + attrLen)
                {
                    var val = recordBuffer.Slice(pos + valueOff, valueLen);
                    var parentRef = BinaryPrimitives.ReadUInt64LittleEndian(val) & 0x0000FFFFFFFFFFFFUL;
                    var charCount = val[64];
                    var ns = val[65];
                    var nameBytes = charCount * 2;
                    if (66 + nameBytes <= val.Length && charCount > 0)
                    {
                        var rank = RankNamespace(ns);
                        if (rank > bestNamespaceRank)
                        {
                            bestNamespaceRank = rank;
                            bestParent = parentRef;
                            bestName = System.Text.Encoding.Unicode.GetString(val.Slice(66, nameBytes));
                            fnWriteTime = BinaryPrimitives.ReadInt64LittleEndian(val[16..]);
                            fnSize = BinaryPrimitives.ReadInt64LittleEndian(val[48..]);
                            fnFlags = BinaryPrimitives.ReadUInt32LittleEndian(val[56..]);
                        }
                    }
                }
            }
            else if (type == AttrData && nameLenChars == 0)
            {
                // Неподписанный поток $DATA — основной размер файла (без альтернативных ADS-потоков Zone.Identifier и т.п.)
                if (nonResident == 0 && pos + 24 <= limit)
                {
                    primaryDataSize = BinaryPrimitives.ReadUInt32LittleEndian(recordBuffer[(pos + 16)..]);
                    hasDataAttr = true;
                }
                else if (nonResident != 0 && pos + 56 <= pos + attrLen)
                {
                    // Для фрагментированных файлов первый отрезок (LowestVcn == 0) хранит общий логический размер
                    var lowestVcn = BinaryPrimitives.ReadInt64LittleEndian(recordBuffer[(pos + 16)..]);
                    if (lowestVcn == 0)
                    {
                        var realSize = BinaryPrimitives.ReadInt64LittleEndian(recordBuffer[(pos + 48)..]);
                        if (realSize >= 0)
                        {
                            primaryDataSize = realSize;
                            hasDataAttr = true;
                        }
                    }
                }
            }

            pos += attrLen;
        }

        if (recordNumber == RootDirectoryRecordNumber)
        {
            entry = new NtfsMftEntry(
                RecordNumber: RootDirectoryRecordNumber,
                ParentRecordNumber: RootDirectoryRecordNumber,
                Name: "",
                SizeBytes: 0,
                LastWriteFileTimeUtc: stdWriteTime != 0 ? stdWriteTime : fnWriteTime,
                IsDirectory: true,
                IsReparsePoint: false);
            return true;
        }

        // Метафайлы файловой системы ($MFT, $LogFile, $Bitmap, $UsnJrnl и резервные слоты 0..23) не включаем в карту пользователя
        if (recordNumber < 24 && bestParent == RootDirectoryRecordNumber &&
            bestName is not null && bestName.StartsWith('$'))
        {
            return false;
        }

        if (string.IsNullOrEmpty(bestName) || bestName is "." or "..")
        {
            return false;
        }

        var combinedFlags = stdFlags | fnFlags;
        var isReparse = (combinedFlags & FileAttrReparsePoint) != 0;
        var size = isDir ? 0L : (hasDataAttr ? primaryDataSize : Math.Max(0L, fnSize));
        var writeTime = stdWriteTime != 0 ? stdWriteTime : fnWriteTime;

        entry = new NtfsMftEntry(
            RecordNumber: recordNumber,
            ParentRecordNumber: bestParent,
            Name: bestName,
            SizeBytes: size,
            LastWriteFileTimeUtc: writeTime,
            IsDirectory: isDir,
            IsReparsePoint: isReparse);
        return true;
    }

    /// <summary>
    /// Собирает отчёт <see cref="DiskSpaceAnalysisReport"/> из набора записей MFT.
    /// Можно строить как от корня тома (запись 5), так и от любой вложенной папки тома по её пути.
    /// </summary>
    public static DiskSpaceAnalysisReport? BuildReportFromEntries(
        IReadOnlyList<NtfsMftEntry> entries,
        string volumeRoot,
        string targetFullPath,
        string methodDescription,
        TimeSpan elapsed,
        int topDirectoryLimit,
        int largestFilesLimit,
        CancellationToken ct = default)
    {
        if (entries.Count == 0)
        {
            return null;
        }

        var normVolRoot = Path.GetFullPath(volumeRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var normTarget = Path.GetFullPath(targetFullPath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

        // 1. Индексируем все папки (без reparse-точек соединения) по номеру записи MFT
        var dirs = new Dictionary<ulong, DirSlot>(capacity: Math.Max(64, entries.Count / 8));
        dirs[RootDirectoryRecordNumber] = new DirSlot(RootDirectoryRecordNumber, RootDirectoryRecordNumber, "", 0);

        foreach (var e in entries)
        {
            if (!e.IsDirectory || e.IsReparsePoint)
            {
                continue;
            }

            dirs[e.RecordNumber] = new DirSlot(e.RecordNumber, e.ParentRecordNumber, e.Name, e.LastWriteFileTimeUtc);
        }

        // Связываем дочерние папки с родительскими (защита от циклов: корень не добавляем к самому себе)
        foreach (var slot in dirs.Values)
        {
            if (slot.RecordNumber == RootDirectoryRecordNumber)
            {
                continue;
            }

            if (dirs.TryGetValue(slot.ParentRecordNumber, out var parent))
            {
                parent.SubDirs.Add(slot);
            }
        }

        // 2. Находим стартовую папку (корень тома или запрошенную подпапку)
        var startRecord = ResolveTargetDirectoryRecord(dirs, normVolRoot, normTarget);
        if (startRecord is null || !dirs.TryGetValue(startRecord.Value, out var rootSlot))
        {
            return null;
        }

        // Помечаем поддерево выбранной папки, чтобы файлы вне её игнорировались за O(1)
        MarkReachableSubtree(rootSlot);

        // 3. Раскладываем файлы по папкам, собираем статистику расширений и крупнейшие файлы
        var extMap = new Dictionary<string, (long Bytes, long Count)>(StringComparer.OrdinalIgnoreCase);
        var keepLargest = Math.Max(largestFilesLimit, 50);
        var minHeap = new PriorityQueue<(ulong ParentRec, string Name, long Size), long>(keepLargest + 1);

        foreach (var e in entries)
        {
            ct.ThrowIfCancellationRequested();
            if (e.IsDirectory || e.IsReparsePoint || e.SizeBytes < 0)
            {
                continue;
            }

            if (!dirs.TryGetValue(e.ParentRecordNumber, out var parentDir) || !parentDir.InTargetSubtree)
            {
                continue;
            }

            parentDir.DirectBytes += e.SizeBytes;
            parentDir.DirectFiles++;

            var ext = NormalizeExt(Path.GetExtension(e.Name));
            if (extMap.TryGetValue(ext, out var prev))
            {
                extMap[ext] = (prev.Bytes + e.SizeBytes, prev.Count + 1);
            }
            else
            {
                extMap[ext] = (e.SizeBytes, 1);
            }

            if (minHeap.Count < keepLargest)
            {
                minHeap.Enqueue((e.ParentRecordNumber, e.Name, e.SizeBytes), e.SizeBytes);
            }
            else if (minHeap.TryPeek(out _, out var smallest) && e.SizeBytes > smallest)
            {
                minHeap.DequeueEnqueue((e.ParentRecordNumber, e.Name, e.SizeBytes), e.SizeBytes);
            }
        }

        // 4. Снизу вверх суммируем размеры и счётчики папок без рекурсии стека
        AccumulateTotalsBottomUp(rootSlot);

        var totalBytes = rootSlot.TotalBytes;
        var totalFiles = rootSlot.TotalFiles;
        var totalFolders = rootSlot.TotalFolders;
        var safeDenom = Math.Max(1L, totalBytes);
        var rootPathWithSlash = normTarget.Length == 2 && normTarget[1] == ':'
            ? normTarget + Path.DirectorySeparatorChar
            : normTarget;

        // 5. Топ папок первого уровня
        var orderedTop = rootSlot.SubDirs
            .Where(d => d.TotalBytes > 0 || d.TotalFiles > 0)
            .OrderByDescending(d => d.TotalBytes)
            .ToList();

        var topDirs = orderedTop
            .Where(d => d.TotalBytes > 0)
            .Take(topDirectoryLimit)
            .Select(d => new DiskSpaceItem(
                Name: d.Name,
                FullPath: Path.Combine(rootPathWithSlash, d.Name),
                SizeBytes: d.TotalBytes,
                FileCount: d.TotalFiles,
                ShareOfScannedPercent: Math.Round((double)d.TotalBytes / safeDenom * 100.0, 1)))
            .ToList();

        // 6. Крупнейшие файлы — восстанавливаем полный путь только для отобранной верхушки
        var largestRaw = new List<(ulong ParentRec, string Name, long Size)>(minHeap.Count);
        while (minHeap.TryDequeue(out var item, out _))
        {
            largestRaw.Add(item);
        }

        var topFiles = largestRaw
            .OrderByDescending(x => x.Size)
            .Take(largestFilesLimit)
            .Select(x =>
            {
                var dirPath = ReconstructPath(dirs, x.ParentRec, rootSlot.RecordNumber, rootPathWithSlash);
                return new DiskSpaceItem(
                    Name: x.Name,
                    FullPath: Path.Combine(dirPath, x.Name),
                    SizeBytes: x.Size,
                    FileCount: 1,
                    ShareOfScannedPercent: Math.Round((double)x.Size / safeDenom * 100.0, 1));
            })
            .ToList();

        // 7. Расширения
        var extStats = extMap
            .Select(kv =>
            {
                var (color, desc) = FastDiskSpaceAnalyzer.ClassifyExtension(kv.Key);
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

        // 8. Иерархическое дерево до глубины PrebuiltTreeDepth
        string[] palette =
        [
            "#3B82F6", "#8B5CF6", "#10B981", "#F59E0B", "#EC4899",
            "#06B6D4", "#6366F1", "#14B8A6", "#F97316", "#84CC16"
        ];

        var rootChildren = new List<DiskTreeNode>(Math.Min(orderedTop.Count, 60) + 1);
        int pIdx = 0;
        foreach (var sub in orderedTop.Take(60))
        {
            var color = palette[pIdx++ % palette.Length];
            rootChildren.Add(MaterializeNode(sub, Path.Combine(rootPathWithSlash, sub.Name), 1, safeDenom, safeDenom, color));
        }

        if (rootSlot.DirectFiles > 0)
        {
            var label = rootPathWithSlash.TrimEnd(Path.DirectorySeparatorChar);
            if (string.IsNullOrEmpty(label)) label = rootPathWithSlash;
            rootChildren.Add(new DiskTreeNode(
                Name: $"[{rootSlot.DirectFiles:N0} файл(ов) в {label}]",
                FullPath: rootPathWithSlash,
                IsDirectory: false,
                IsDirectFilesBucket: true,
                SizeBytes: rootSlot.DirectBytes,
                FileCount: rootSlot.DirectFiles,
                FolderCount: 0,
                ShareOfRootPercent: Math.Round((double)rootSlot.DirectBytes / safeDenom * 100.0, 1),
                ShareOfParentPercent: Math.Round((double)rootSlot.DirectBytes / safeDenom * 100.0, 1),
                LastModifiedLocal: FileTimeToLocal(rootSlot.LastWriteFileTimeUtc),
                ColorHex: "#EAB308",
                Children: []));
        }

        rootChildren.Sort((a, b) => b.SizeBytes.CompareTo(a.SizeBytes));

        var rootDisplay = Path.GetFileName(rootPathWithSlash.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        if (string.IsNullOrWhiteSpace(rootDisplay))
        {
            rootDisplay = $"[{rootPathWithSlash.TrimEnd('\\')}] Локальный диск";
        }

        var rootNode = new DiskTreeNode(
            Name: rootDisplay,
            FullPath: rootPathWithSlash,
            IsDirectory: true,
            IsDirectFilesBucket: false,
            SizeBytes: totalBytes,
            FileCount: totalFiles,
            FolderCount: totalFolders,
            ShareOfRootPercent: 100.0,
            ShareOfParentPercent: 100.0,
            LastModifiedLocal: FileTimeToLocal(rootSlot.LastWriteFileTimeUtc),
            ColorHex: "#6366F1",
            Children: rootChildren);

        return new DiskSpaceAnalysisReport(
            RootPath: rootPathWithSlash,
            ScanMethodDescription: methodDescription,
            Elapsed: elapsed,
            TotalScannedBytes: totalBytes,
            TotalFilesCount: totalFiles,
            TopDirectories: topDirs,
            LargestFiles: topFiles,
            RootTreeNodes: [rootNode],
            ExtensionStats: extStats,
            TotalFoldersCount: totalFolders);
    }

    /// <summary>
    /// Проверяет и восстанавливает последние 2 байта каждого 512-байтного сектора записи MFT
    /// по массиву Update Sequence Array (защита NTFS от неполной записи сектора).
    /// </summary>
    public static bool ApplyUpdateSequenceFixup(Span<byte> recordBuffer)
    {
        var usaOffset = (int)BinaryPrimitives.ReadUInt16LittleEndian(recordBuffer[4..]);
        var usaCount = (int)BinaryPrimitives.ReadUInt16LittleEndian(recordBuffer[6..]);

        if (usaCount < 2 || usaOffset < 40 || usaOffset + usaCount * 2 > recordBuffer.Length)
        {
            return false;
        }

        var checkValue = BinaryPrimitives.ReadUInt16LittleEndian(recordBuffer[usaOffset..]);
        var sectors = usaCount - 1;
        if (sectors * BytesPerSector > recordBuffer.Length)
        {
            return false;
        }

        for (int i = 0; i < sectors; i++)
        {
            var sectorTail = (i + 1) * BytesPerSector - 2;
            var actual = BinaryPrimitives.ReadUInt16LittleEndian(recordBuffer[sectorTail..]);
            if (actual != checkValue)
            {
                return false;
            }

            var originalWord = BinaryPrimitives.ReadUInt16LittleEndian(recordBuffer[(usaOffset + (i + 1) * 2)..]);
            BinaryPrimitives.WriteUInt16LittleEndian(recordBuffer[sectorTail..], originalWord);
        }

        return true;
    }

    private static int RankNamespace(byte ns) => ns switch
    {
        NamespaceWin32AndDos => 3,
        NamespaceWin32 => 2,
        NamespacePosix => 1,
        NamespaceDos => 0,
        _ => 0
    };

    private static ulong? ResolveTargetDirectoryRecord(
        Dictionary<ulong, DirSlot> dirs,
        string normVolRoot,
        string normTarget)
    {
        if (string.Equals(normVolRoot, normTarget, StringComparison.OrdinalIgnoreCase))
        {
            return RootDirectoryRecordNumber;
        }

        if (!normTarget.StartsWith(normVolRoot, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var rel = normTarget[normVolRoot.Length..].Trim(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (rel.Length == 0)
        {
            return RootDirectoryRecordNumber;
        }

        var cur = dirs[RootDirectoryRecordNumber];
        foreach (var seg in rel.Split([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar], StringSplitOptions.RemoveEmptyEntries))
        {
            var next = cur.SubDirs.FirstOrDefault(s => string.Equals(s.Name, seg, StringComparison.OrdinalIgnoreCase));
            if (next is null)
            {
                return null;
            }

            cur = next;
        }

        return cur.RecordNumber;
    }

    private static void MarkReachableSubtree(DirSlot root)
    {
        var stack = new Stack<DirSlot>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var cur = stack.Pop();
            if (cur.InTargetSubtree)
            {
                continue;
            }

            cur.InTargetSubtree = true;
            foreach (var sub in cur.SubDirs)
            {
                stack.Push(sub);
            }
        }
    }

    private static void AccumulateTotalsBottomUp(DirSlot root)
    {
        var order = new List<DirSlot>();
        var stack = new Stack<DirSlot>();
        stack.Push(root);
        var visited = new HashSet<ulong>();

        while (stack.Count > 0)
        {
            var cur = stack.Pop();
            if (!visited.Add(cur.RecordNumber))
            {
                continue;
            }

            order.Add(cur);
            foreach (var sub in cur.SubDirs)
            {
                stack.Push(sub);
            }
        }

        for (int i = order.Count - 1; i >= 0; i--)
        {
            var node = order[i];
            var bytes = node.DirectBytes;
            var files = node.DirectFiles;
            long folders = 0;

            foreach (var sub in node.SubDirs)
            {
                if (!visited.Contains(sub.RecordNumber))
                {
                    continue;
                }

                bytes += sub.TotalBytes;
                files += sub.TotalFiles;
                folders += 1 + sub.TotalFolders;
            }

            node.TotalBytes = bytes;
            node.TotalFiles = files;
            node.TotalFolders = folders;
        }
    }

    private static string ReconstructPath(
        Dictionary<ulong, DirSlot> dirs,
        ulong recordNumber,
        ulong stopAtRecord,
        string stopBasePath)
    {
        var segments = new List<string>();
        var cur = recordNumber;
        int guard = 0;
        while (cur != stopAtRecord && cur != RootDirectoryRecordNumber && guard++ < 256)
        {
            if (!dirs.TryGetValue(cur, out var slot))
            {
                break;
            }

            if (!string.IsNullOrEmpty(slot.Name))
            {
                segments.Add(slot.Name);
            }

            cur = slot.ParentRecordNumber;
        }

        segments.Reverse();
        var path = stopBasePath;
        foreach (var seg in segments)
        {
            path = Path.Combine(path, seg);
        }

        return path;
    }

    private static DiskTreeNode MaterializeNode(
        DirSlot slot,
        string fullPath,
        int depth,
        long rootBytes,
        long parentBytes,
        string colorHex)
    {
        var safeRoot = Math.Max(1L, rootBytes);
        var safeParent = Math.Max(1L, parentBytes);
        var safeSelf = Math.Max(1L, slot.TotalBytes);

        var children = new List<DiskTreeNode>();
        var truncated = false;

        if (depth < PrebuiltTreeDepth)
        {
            var orderedSubs = slot.SubDirs
                .Where(s => s.TotalBytes > 0 || s.TotalFiles > 0)
                .OrderByDescending(s => s.TotalBytes)
                .Take(60);

            foreach (var sub in orderedSubs)
            {
                children.Add(MaterializeNode(
                    sub,
                    Path.Combine(fullPath, sub.Name),
                    depth + 1,
                    safeRoot,
                    safeSelf,
                    colorHex));
            }

            if (slot.DirectFiles > 0 && children.Count > 0)
            {
                children.Add(new DiskTreeNode(
                    Name: $"[{slot.DirectFiles:N0} файл(ов) в {slot.Name}]",
                    FullPath: fullPath,
                    IsDirectory: false,
                    IsDirectFilesBucket: true,
                    SizeBytes: slot.DirectBytes,
                    FileCount: slot.DirectFiles,
                    FolderCount: 0,
                    ShareOfRootPercent: Math.Round((double)slot.DirectBytes / safeRoot * 100.0, 1),
                    ShareOfParentPercent: Math.Round((double)slot.DirectBytes / safeSelf * 100.0, 1),
                    LastModifiedLocal: FileTimeToLocal(slot.LastWriteFileTimeUtc),
                    ColorHex: "#EAB308",
                    Children: []));
                children.Sort((a, b) => b.SizeBytes.CompareTo(a.SizeBytes));
            }
        }
        else
        {
            truncated = slot.SubDirs.Count > 0;
        }

        return new DiskTreeNode(
            Name: slot.Name,
            FullPath: fullPath,
            IsDirectory: true,
            IsDirectFilesBucket: false,
            SizeBytes: slot.TotalBytes,
            FileCount: slot.TotalFiles,
            FolderCount: slot.TotalFolders,
            ShareOfRootPercent: Math.Round((double)slot.TotalBytes / safeRoot * 100.0, 1),
            ShareOfParentPercent: Math.Round((double)slot.TotalBytes / safeParent * 100.0, 1),
            LastModifiedLocal: FileTimeToLocal(slot.LastWriteFileTimeUtc),
            ColorHex: colorHex,
            Children: children,
            MayHaveDeeperSubfolders: truncated);
    }

    private static DateTime FileTimeToLocal(long fileTimeUtc)
    {
        if (fileTimeUtc <= 0)
        {
            return DateTime.MinValue;
        }

        try
        {
            return DateTime.FromFileTimeUtc(fileTimeUtc).ToLocalTime();
        }
        catch
        {
            return DateTime.MinValue;
        }
    }

    private static string NormalizeExt(string? rawExt) =>
        string.IsNullOrWhiteSpace(rawExt) || rawExt == "."
            ? "(без расширения)"
            : rawExt.ToLowerInvariant();

    private sealed class DirSlot(ulong recordNumber, ulong parentRecordNumber, string name, long lastWriteFileTimeUtc)
    {
        public ulong RecordNumber { get; } = recordNumber;
        public ulong ParentRecordNumber { get; } = parentRecordNumber;
        public string Name { get; } = name;
        public long LastWriteFileTimeUtc { get; } = lastWriteFileTimeUtc;
        public bool InTargetSubtree { get; set; }
        public long DirectBytes { get; set; }
        public long DirectFiles { get; set; }
        public long TotalBytes { get; set; }
        public long TotalFiles { get; set; }
        public long TotalFolders { get; set; }
        public List<DirSlot> SubDirs { get; } = [];
    }
}
