using System.Diagnostics;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using UltimateWindows.Modules.Hardware.Contracts;
using UltimateWindows.Modules.Hardware.Models;

namespace UltimateWindows.Modules.Hardware.Benchmarks;

/// <summary>
/// Лёгкий и быстрый набор бенчмарков Этапа 6 (CPU 1T/MT, GPU DirectCompute, RAM ГБ/с + нс, Диск без износа SSD).
/// Спроектирован так, чтобы каждый тест укладывался в 1–2 секунды, не вешал интерфейс (BelowNormal)
/// и не расходовал ресурс записи накопителя (всего 32 МБ во временном буфере).
/// </summary>
public sealed class LightweightBenchmarkRunner
{
    private readonly IHardwarePlatformProvider _platformProvider;

    public LightweightBenchmarkRunner(IHardwarePlatformProvider platformProvider)
    {
        _platformProvider = platformProvider ?? throw new ArgumentNullException(nameof(platformProvider));
    }

    public async Task<CpuBenchmarkResult> RunCpuBenchmarkAsync(
        TimeSpan? singlePhaseDuration = null,
        TimeSpan? multiPhaseDuration = null,
        CancellationToken ct = default)
    {
        var singleDur = singlePhaseDuration ?? TimeSpan.FromMilliseconds(750);
        var multiDur = multiPhaseDuration ?? TimeSpan.FromMilliseconds(1100);
        var totalSw = Stopwatch.StartNew();

        // 1. Однопоточный тест (целочисленный конвейер + SHA-256 + скалярная физика FP64)
        var (singleBytes, singleElapsedSec) = await Task.Factory.StartNew(
            () =>
            {
                Thread.CurrentThread.Priority = ThreadPriority.BelowNormal;
                return ExecuteSingleCoreWorkload(singleDur, ct);
            },
            ct,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default).ConfigureAwait(false);

        double singleMbPerSec = Math.Round((singleBytes / (1024.0 * 1024.0)) / Math.Max(0.001, singleElapsedSec), 1);
        int singleScore = Math.Max(100, (int)Math.Round(singleMbPerSec * 2.4));

        // 2. Многопоточный SIMD-тест (все логические потоки, FMA Vector4)
        int threads = Math.Max(1, Environment.ProcessorCount);
        long totalFlops = 0;
        var mtSw = Stopwatch.StartNew();
        using var mtCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        mtCts.CancelAfter(multiDur);
        var mtToken = mtCts.Token;

        var workers = new Task[threads];
        for (int w = 0; w < threads; w++)
        {
            int seed = w + 1;
            workers[w] = Task.Factory.StartNew(
                () =>
                {
                    Thread.CurrentThread.Priority = ThreadPriority.BelowNormal;
                    long localFlops = ExecuteSimdFlopsKernel(seed, mtToken);
                    Interlocked.Add(ref totalFlops, localFlops);
                },
                CancellationToken.None,
                TaskCreationOptions.LongRunning,
                TaskScheduler.Default);
        }

        await Task.WhenAll(workers).ConfigureAwait(false);
        mtSw.Stop();
        ct.ThrowIfCancellationRequested();

        double mtSec = Math.Max(0.001, mtSw.Elapsed.TotalSeconds);
        double gflops = Math.Round((totalFlops / mtSec) / 1_000_000_000.0, 1);
        int multiScore = Math.Max(singleScore, (int)Math.Round(gflops * 38.0 + singleScore * 0.65));
        double scaling = Math.Round(Math.Clamp((double)multiScore / Math.Max(1, singleScore), 1.0, threads * 1.15), 2);

        totalSw.Stop();
        string tier = multiScore switch
        {
            >= 14000 => "Топовый многоядерный CPU / Рабочая станция",
            >= 7500 => "Производительный игровой процессор",
            >= 3500 => "Универсальный домашний / офисный CPU",
            _ => "Базовый / энергоэффективный CPU"
        };

        return new CpuBenchmarkResult(
            SingleCoreScore: singleScore,
            MultiCoreScore: multiScore,
            SingleCoreCryptoMbPerSec: singleMbPerSec,
            MultiCoreSimdGflops: gflops,
            MultiThreadScaling: scaling,
            LogicalThreadsUsed: threads,
            Duration: totalSw.Elapsed,
            TierBadge: tier);
    }

    public Task<GpuBenchmarkResult> RunGpuBenchmarkAsync(
        TimeSpan? duration = null,
        CancellationToken ct = default)
    {
        var dur = duration ?? TimeSpan.FromMilliseconds(1400);
        return _platformProvider.RunGpuComputeBenchmarkAsync(dur, ct);
    }

    public Task<MemoryBenchmarkResult> RunMemoryBenchmarkAsync(
        TimeSpan? duration = null,
        CancellationToken ct = default)
    {
        var budget = duration ?? TimeSpan.FromMilliseconds(900);
        return Task.Factory.StartNew(() =>
        {
            Thread.CurrentThread.Priority = ThreadPriority.BelowNormal;
            var swTotal = Stopwatch.StartNew();

            // 1. Многопоточная пропускная способность чтения/записи ОЗУ (32 МБ суммарно)
            int threads = Math.Clamp(Environment.ProcessorCount, 1, 16);
            int intsPerThread = (32 * 1024 * 1024) / (sizeof(ulong) * threads);
            intsPerThread = Math.Max(65536, intsPerThread);

            long totalBytesTransferred = 0;
            var bwBudgetMs = Math.Max(200, (int)(budget.TotalMilliseconds * 0.55));
            var bwSw = Stopwatch.StartNew();

            Parallel.For(0, threads, new ParallelOptions { MaxDegreeOfParallelism = threads, CancellationToken = ct }, t =>
            {
                var src = GC.AllocateUninitializedArray<ulong>(intsPerThread);
                var dst = GC.AllocateUninitializedArray<ulong>(intsPerThread);
                for (int i = 0; i < src.Length; i++) src[i] = (ulong)(i + t + 1) * 0x9E3779B97F4A7C15UL;

                long localBytes = 0;
                ulong sink = 0;
                while (bwSw.ElapsedMilliseconds < bwBudgetMs && !ct.IsCancellationRequested)
                {
                    Buffer.BlockCopy(src, 0, dst, 0, src.Length * sizeof(ulong));
                    for (int i = 0; i < dst.Length; i += 8)
                    {
                        sink ^= dst[i] + dst[i + 4];
                    }

                    localBytes += (long)src.Length * sizeof(ulong) * 2;
                }

                if (sink == 0xFFFFFFFFFFFFFFFFUL) GC.KeepAlive(dst);
                Interlocked.Add(ref totalBytesTransferred, localBytes);
            });
            bwSw.Stop();

            double bwGbPerSec = Math.Round(
                (totalBytesTransferred / (1024.0 * 1024.0 * 1024.0)) / Math.Max(0.001, bwSw.Elapsed.TotalSeconds),
                1);

            // 2. Латентность случайного обхода указателей (16 МБ — выходит за пределы L1/L2)
            const int ringLen = 4 * 1024 * 1024; // 4 млн int = 16 МБ
            var ring = GC.AllocateUninitializedArray<int>(ringLen);
            for (int i = 0; i < ringLen; i++) ring[i] = i;

            // Псевдослучайная одноцикловая перестановка Саттоло (гарантированно обходит весь буфер без предвыборки кэша)
            uint rng = 0xC0FFEE42u;
            for (int i = ringLen - 1; i > 0; i--)
            {
                rng ^= rng << 13;
                rng ^= rng >> 17;
                rng ^= rng << 5;
                int j = (int)(rng % (uint)i);
                (ring[i], ring[j]) = (ring[j], ring[i]);
            }

            const int steps = 2_000_000;
            int idx = 0;
            var latSw = Stopwatch.StartNew();
            for (int s = 0; s < steps; s++)
            {
                idx = ring[idx];
            }
            latSw.Stop();
            if (idx == -1) GC.KeepAlive(ring);

            double latencyNs = Math.Round((latSw.Elapsed.TotalNanoseconds) / steps, 1);
            swTotal.Stop();

            int memScore = Math.Max(
                200,
                (int)Math.Round(bwGbPerSec * 95.0 + Math.Max(0, 160.0 - latencyNs) * 18.0));

            string tier = bwGbPerSec switch
            {
                >= 55.0 => "Высокоскоростная DDR5 Dual-Channel",
                >= 28.0 => "Оптимальная двухканальная память",
                >= 15.0 => "Стандартная память / Одноканал",
                _ => "Базовая пропускная способность ОЗУ"
            };

            return new MemoryBenchmarkResult(
                MemoryScore: memScore,
                BandwidthGbPerSec: bwGbPerSec,
                LatencyNanoseconds: latencyNs,
                Duration: swTotal.Elapsed,
                TierBadge: tier);
        }, ct, TaskCreationOptions.LongRunning, TaskScheduler.Default);
    }

    public async Task<StorageBenchmarkResult> RunStorageBenchmarkAsync(
        string? targetDirectory = null,
        int testSizeMegabytes = 32,
        CancellationToken ct = default)
    {
        int clampedMb = Math.Clamp(testSizeMegabytes, 8, 64); // Бережём ресурс записи SSD!
        string workDir = string.IsNullOrWhiteSpace(targetDirectory) ? Path.GetTempPath() : targetDirectory;
        Directory.CreateDirectory(workDir);

        string volumeLabel = Path.GetPathRoot(Path.GetFullPath(workDir)) ?? workDir;
        string tempFile = Path.Combine(workDir, $"uw-quick-bench-{Guid.NewGuid():N}.tmp");
        long totalBytes = (long)clampedMb * 1024L * 1024L;
        const int seqBlockSize = 1024 * 1024; // 1 МБ
        const int rndBlockSize = 4096;        // 4 КБ

        var swTotal = Stopwatch.StartNew();
        try
        {
            var block = new byte[seqBlockSize];
            RandomNumberGenerator.Fill(block.AsSpan(0, 4096));
            for (int off = 4096; off < block.Length; off += 4096)
            {
                Buffer.BlockCopy(block, 0, block, off, 4096);
            }

            // 1. Последовательная запись с WriteThrough
            var writeSw = Stopwatch.StartNew();
            await using (var fsWrite = new FileStream(
                tempFile,
                FileMode.Create,
                FileAccess.Write,
                FileShare.None,
                seqBlockSize,
                FileOptions.WriteThrough | FileOptions.Asynchronous))
            {
                for (int m = 0; m < clampedMb; m++)
                {
                    ct.ThrowIfCancellationRequested();
                    await fsWrite.WriteAsync(block, ct).ConfigureAwait(false);
                }

                await fsWrite.FlushAsync(ct).ConfigureAwait(false);
            }
            writeSw.Stop();

            // 2. Последовательное чтение
            var readBuf = new byte[seqBlockSize];
            var readSw = Stopwatch.StartNew();
            await using (var fsRead = new FileStream(
                tempFile,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                seqBlockSize,
                FileOptions.SequentialScan | FileOptions.Asynchronous))
            {
                while (await fsRead.ReadAsync(readBuf, ct).ConfigureAwait(false) > 0)
                {
                    ct.ThrowIfCancellationRequested();
                }
            }
            readSw.Stop();

            // 3. Случайное чтение блоками 4 КБ (~350 мс)
            int maxPages = (int)(totalBytes / rndBlockSize);
            var pageBuf = new byte[rndBlockSize];
            long ioOps = 0;
            uint rng = 0x9A71B305u;
            var iopsSw = Stopwatch.StartNew();

            await using (var fsRnd = new FileStream(
                tempFile,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                rndBlockSize,
                FileOptions.RandomAccess | FileOptions.Asynchronous))
            {
                while (iopsSw.ElapsedMilliseconds < 350 && ioOps < 25000)
                {
                    ct.ThrowIfCancellationRequested();
                    rng = rng * 1664525u + 1013904223u;
                    long pageOffset = (rng % (uint)maxPages) * (long)rndBlockSize;
                    fsRnd.Position = pageOffset;
                    _ = await fsRnd.ReadAsync(pageBuf, ct).ConfigureAwait(false);
                    ioOps++;
                }
            }
            iopsSw.Stop();
            swTotal.Stop();

            double writeMbPerSec = Math.Round(clampedMb / Math.Max(0.001, writeSw.Elapsed.TotalSeconds), 0);
            double readMbPerSec = Math.Round(clampedMb / Math.Max(0.001, readSw.Elapsed.TotalSeconds), 0);
            double iops = Math.Round(ioOps / Math.Max(0.001, iopsSw.Elapsed.TotalSeconds), 0);

            int diskScore = Math.Max(100, (int)Math.Round(readMbPerSec * 0.75 + writeMbPerSec * 0.95 + iops * 0.04));
            string tier = Math.Max(readMbPerSec, writeMbPerSec) switch
            {
                >= 2200 => "Быстрый NVMe PCIe Gen4 / Gen5 SSD",
                >= 900 => "Твердотельный NVMe PCIe SSD",
                >= 350 => "Твердотельный SATA SSD",
                _ => "Жёсткий диск HDD / Сетевой том"
            };

            return new StorageBenchmarkResult(
                TargetVolume: volumeLabel,
                StorageScore: diskScore,
                SeqWriteMbPerSec: writeMbPerSec,
                SeqReadMbPerSec: readMbPerSec,
                Random4kIops: iops,
                Duration: swTotal.Elapsed,
                TierBadge: tier);
        }
        finally
        {
            try { if (File.Exists(tempFile)) File.Delete(tempFile); } catch { }
        }
    }

    public async Task<HardwareBenchmarkSuiteReport> RunFullQuickSuiteAsync(
        IProgress<string>? statusProgress = null,
        CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();

        statusProgress?.Report("Шаг 1/4: Тестирование однопоточной и многопоточной скорости CPU (SIMD)...");
        var cpu = await RunCpuBenchmarkAsync(ct: ct).ConfigureAwait(false);

        statusProgress?.Report("Шаг 2/4: Лёгкий шейдерный тест видеокарты (GPU DirectCompute)...");
        var gpu = await RunGpuBenchmarkAsync(ct: ct).ConfigureAwait(false);

        statusProgress?.Report("Шаг 3/4: Замер пропускной способности и латентности ОЗУ...");
        var mem = await RunMemoryBenchmarkAsync(ct: ct).ConfigureAwait(false);

        statusProgress?.Report("Шаг 4/4: Бережный экспресс-тест скорости диска (32 МБ без износа SSD)...");
        var disk = await RunStorageBenchmarkAsync(ct: ct).ConfigureAwait(false);

        sw.Stop();

        int composite = (int)Math.Round(
            cpu.MultiCoreScore * 0.38 +
            gpu.ComputeScore * 0.34 +
            mem.MemoryScore * 0.16 +
            disk.StorageScore * 0.12);

        string overallTier = composite switch
        {
            >= 9500 => "Высокопроизводительный игровой ПК / Рабочая станция",
            >= 5200 => "Сбалансированный современный ПК для игр и работы",
            >= 2400 => "Бодрый домашний / офисный компьютер",
            _ => "Базовая система / Виртуальная среда"
        };

        statusProgress?.Report($"Комплексный экспресс-бенчмарк завершён за {sw.Elapsed.TotalSeconds:F1} сек — общий индекс: {composite} балл. ({overallTier})");

        return new HardwareBenchmarkSuiteReport(
            CompletedAtUtc: DateTimeOffset.UtcNow,
            CompositeScore: composite,
            OverallTierBadge: overallTier,
            Cpu: cpu,
            Gpu: gpu,
            Memory: mem,
            Storage: disk,
            TotalDuration: sw.Elapsed);
    }

    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static (long BytesProcessed, double ElapsedSeconds) ExecuteSingleCoreWorkload(
        TimeSpan duration,
        CancellationToken ct)
    {
        var buf = new byte[65536];
        for (int i = 0; i < buf.Length; i++) buf[i] = (byte)((i * 31 + 17) & 0xFF);
        Span<byte> digest = stackalloc byte[32];

        long processed = 0;
        double acc = 0.1234567;
        var sw = Stopwatch.StartNew();

        while (sw.Elapsed < duration && !ct.IsCancellationRequested)
        {
            SHA256.HashData(buf, digest);
            buf[0] ^= digest[0];
            buf[1024] ^= digest[15];

            // Дополняем криптохеширование плотной ветвящейся скалярной математикой FP64
            for (int k = 0; k < 2048; k++)
            {
                double cx = -0.743643887037151 + (k & 15) * 1e-7;
                double cy = 0.131825904205330;
                double zx = cx, zy = cy;
                for (int it = 0; it < 6; it++)
                {
                    double nx = zx * zx - zy * zy + cx;
                    zy = 2.0 * zx * zy + cy;
                    zx = nx;
                }

                acc += zx * 1e-6;
            }

            processed += buf.Length * 3L;
        }

        sw.Stop();
        if (acc == -999999.0) buf[0] = 1;
        return (processed, sw.Elapsed.TotalSeconds);
    }

    private static long ExecuteSimdFlopsKernel(int seed, CancellationToken ct)
    {
        var a = new Vector4(1.0001f, 1.0002f, 1.0003f, 1.0004f) * (1.0f + seed * 0.0001f);
        var b = new Vector4(0.9999f, 0.9998f, 0.9997f, 0.9996f);
        var c = new Vector4(0.5f, 0.25f, 0.75f, 0.125f);
        var d = new Vector4(0.1f, 0.2f, 0.3f, 0.4f);
        var bias = new Vector4(0.00001f);

        long totalFlops = 0;
        while (!ct.IsCancellationRequested)
        {
            for (int i = 0; i < 4096; i++)
            {
                // 4 независимых FMA-цепочки по 4 float = 32 FLOP на итерацию без простоев конвейера
                a = (a * b) + bias;
                c = (c * b) + bias;
                d = (d * b) + bias;
                b = (b * 0.999999f) + new Vector4(0.000001f);
            }

            if (a.X > 1e5f || a.X < -1e5f)
            {
                a = new Vector4(1.0001f, 1.0002f, 1.0003f, 1.0004f);
                c = new Vector4(0.5f, 0.25f, 0.75f, 0.125f);
                d = new Vector4(0.1f, 0.2f, 0.3f, 0.4f);
            }

            totalFlops += 4096L * 32L;
        }

        if (a.Y == -999999f && c.Z == -999999f && d.W == -999999f) totalFlops++;
        return totalFlops;
    }
}
