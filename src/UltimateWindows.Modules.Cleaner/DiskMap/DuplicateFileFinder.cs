using System.Diagnostics;
using System.Security.Cryptography;
using UltimateWindows.Modules.Cleaner.Models;

namespace UltimateWindows.Modules.Cleaner.DiskMap;

/// <summary>
/// Трехступенчатый сверхбыстрый поиск полных дубликатов файлов (в стиле CCleaner Duplicate Finder):
/// 1) отсев уникальных размеров без чтения диска,
/// 2) 8-КБ отпечаток начала и конца файла,
/// 3) криптографический SHA-256 только для совпавших кандидатов.
/// Системный каталог Windows исключен для 100% безопасности ОС.
/// </summary>
public sealed class DuplicateFileFinder
{
    private static readonly string[] ProtectedDirectoryNames =
    [
        "Windows", "WinSxS", "$Recycle.Bin", "System Volume Information", ".git", "Program Files", "Program Files (x86)"
    ];

    public async Task<DuplicateScanReport> FindExactDuplicatesAsync(
        string rootPath,
        long minFileSizeBytes = 1024 * 1024,
        int maxGroups = 150,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootPath);
        var fullRoot = Path.GetFullPath(rootPath);
        if (!Directory.Exists(fullRoot))
        {
            throw new DirectoryNotFoundException($"Путь '{fullRoot}' не найден.");
        }

        minFileSizeBytes = Math.Max(1024L, minFileSizeBytes);
        var sw = Stopwatch.StartNew();

        return await Task.Run(() =>
        {
            var sizeBuckets = new Dictionary<long, List<FileInfo>>();
            long scannedCount = 0;

            CollectCandidateFiles(new DirectoryInfo(fullRoot), minFileSizeBytes, isRootCall: true, sizeBuckets, ref scannedCount, ct);

            // Этап 2: быстрый 8-КБ отпечаток (4 КБ начало + 4 КБ конец) для корзин с >= 2 файлами одинакового размера
            var partialBuckets = new Dictionary<(long Size, string QuickHash), List<FileInfo>>();
            foreach (var (size, candidates) in sizeBuckets)
            {
                ct.ThrowIfCancellationRequested();
                if (candidates.Count < 2) continue;

                foreach (var fi in candidates)
                {
                    ct.ThrowIfCancellationRequested();
                    var qHash = TryComputeEdgeHashHex(fi.FullName, size);
                    if (qHash is null) continue;

                    var key = (size, qHash);
                    if (!partialBuckets.TryGetValue(key, out var list))
                    {
                        list = [];
                        partialBuckets[key] = list;
                    }

                    list.Add(fi);
                }
            }

            // Этап 3: полный SHA-256 только для файлов, совпавших и по размеру, и по краям
            var groups = new List<DuplicateFileGroup>();
            foreach (var ((size, _), candidates) in partialBuckets)
            {
                ct.ThrowIfCancellationRequested();
                if (candidates.Count < 2) continue;

                var fullHashBuckets = new Dictionary<string, List<FileInfo>>(StringComparer.OrdinalIgnoreCase);
                foreach (var fi in candidates)
                {
                    ct.ThrowIfCancellationRequested();
                    var fullHash = TryComputeFullSha256Hex(fi.FullName);
                    if (fullHash is null) continue;

                    if (!fullHashBuckets.TryGetValue(fullHash, out var list))
                    {
                        list = [];
                        fullHashBuckets[fullHash] = list;
                    }

                    list.Add(fi);
                }

                foreach (var (sha, exactMatches) in fullHashBuckets)
                {
                    if (exactMatches.Count < 2) continue;

                    // Самый ранний по времени изменения файл помечаем как оригинал (оставлять!)
                    var ordered = exactMatches
                        .OrderBy(f => SafeTime(f))
                        .ThenBy(f => f.FullName.Length)
                        .ToList();

                    var entries = new List<DuplicateFileEntry>(ordered.Count);
                    for (int i = 0; i < ordered.Count; i++)
                    {
                        var item = ordered[i];
                        entries.Add(new DuplicateFileEntry(
                            FullPath: item.FullName,
                            FileName: item.Name,
                            DirectoryPath: item.DirectoryName ?? "",
                            SizeBytes: size,
                            LastModifiedLocal: SafeTime(item),
                            IsOriginalKeepSuggested: i == 0));
                    }

                    groups.Add(new DuplicateFileGroup(sha, size, entries));
                }
            }

            sw.Stop();

            var topGroups = groups
                .OrderByDescending(g => g.ReclaimableBytes)
                .Take(maxGroups)
                .ToList();

            var reclaimable = topGroups.Sum(g => g.ReclaimableBytes);
            return new DuplicateScanReport(fullRoot, sw.Elapsed, scannedCount, reclaimable, topGroups);
        }, ct).ConfigureAwait(false);
    }

    private static void CollectCandidateFiles(
        DirectoryInfo dir,
        long minSize,
        bool isRootCall,
        Dictionary<long, List<FileInfo>> sizeBuckets,
        ref long scannedCount,
        CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (!isRootCall && ProtectedDirectoryNames.Any(p => string.Equals(p, dir.Name, StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        var nonRec = new EnumerationOptions
        {
            IgnoreInaccessible = true,
            RecurseSubdirectories = false,
            AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.System
        };

        try
        {
            foreach (var fi in dir.EnumerateFiles("*", nonRec))
            {
                ct.ThrowIfCancellationRequested();
                scannedCount++;
                long len;
                try
                {
                    len = fi.Length;
                }
                catch
                {
                    continue;
                }

                if (len < minSize) continue;

                if (!sizeBuckets.TryGetValue(len, out var list))
                {
                    list = [];
                    sizeBuckets[len] = list;
                }

                list.Add(fi);
            }

            foreach (var sub in dir.EnumerateDirectories("*", nonRec))
            {
                CollectCandidateFiles(sub, minSize, isRootCall: false, sizeBuckets, ref scannedCount, ct);
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            // Пропускаем закрытые папки
        }
    }

    private static string? TryComputeEdgeHashHex(string filePath, long fileSize)
    {
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            const int chunk = 4096;
            if (fileSize <= chunk * 2)
            {
                Span<byte> all = stackalloc byte[(int)fileSize];
                var read = fs.Read(all);
                return Convert.ToHexString(SHA256.HashData(all[..read]));
            }

            Span<byte> buf = stackalloc byte[chunk * 2];
            var r1 = fs.Read(buf[..chunk]);
            fs.Seek(-chunk, SeekOrigin.End);
            var r2 = fs.Read(buf.Slice(chunk, chunk));
            return Convert.ToHexString(SHA256.HashData(buf[..(r1 + r2)]));
        }
        catch
        {
            return null;
        }
    }

    private static string? TryComputeFullSha256Hex(string filePath)
    {
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, bufferSize: 65536);
            Span<byte> digest = stackalloc byte[32];
            SHA256.HashData(fs, digest);
            return Convert.ToHexString(digest);
        }
        catch
        {
            return null;
        }
    }

    private static DateTime SafeTime(FileInfo fi)
    {
        try
        {
            return fi.LastWriteTime;
        }
        catch
        {
            return DateTime.MinValue;
        }
    }
}
