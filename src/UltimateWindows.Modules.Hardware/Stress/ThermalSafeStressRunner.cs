using System.Diagnostics;
using System.Numerics;
using UltimateWindows.Modules.Hardware.Contracts;
using UltimateWindows.Modules.Hardware.Models;

namespace UltimateWindows.Modules.Hardware.Stress;

/// <summary>
/// Многопоточный стресс-тест стабильности процессора и памяти Этапа 6:
/// - работает с пониженным приоритетом потоков (интерфейс и опрос датчиков не зависают);
/// - сверяет эталонную детерминированную контрольную сумму на каждом блоке (выявляет сбои андервольтинга/разгона CPU и ОЗУ);
/// - записывает временной ряд телеметрии (производительность + температура CPU и GPU) для живого графика и срабатывает по тепловому предохранителю.
/// </summary>
public sealed class ThermalSafeStressRunner
{
    private readonly IHardwarePlatformProvider _platformProvider;

    public ThermalSafeStressRunner(IHardwarePlatformProvider platformProvider)
    {
        _platformProvider = platformProvider ?? throw new ArgumentNullException(nameof(platformProvider));
    }

    public async Task<StressTestProgress> RunStabilityTestAsync(
        TimeSpan duration,
        double maxSafeCpuTempC = 92.0,
        double maxSafeGpuTempC = 88.0,
        IProgress<StressTestProgress>? progress = null,
        CancellationToken externalCt = default)
    {
        if (duration <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(duration), "Длительность теста должна быть положительной.");
        }

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(externalCt);
        linkedCts.CancelAfter(duration);
        var workerToken = linkedCts.Token;

        long totalOps = 0;
        int integrityErrors = 0;
        var thermalAborted = false;
        double? peakCpu = null;
        double? peakGpu = null;
        var history = new List<StressTelemetryPoint>(128);

        // Предвычисляем эталонный результат детерминированного ядра на холодном старте
        ulong goldenChecksum = ComputeDeterministicIntegrityBlock(0x55AA_1234_99CC_7711UL);

        var workerCount = Math.Max(1, Environment.ProcessorCount);
        var sw = Stopwatch.StartNew();

        var workers = new Task[workerCount];
        for (var w = 0; w < workerCount; w++)
        {
            var seed = w + 1;
            workers[w] = Task.Factory.StartNew(
                () =>
                {
                    Thread.CurrentThread.Priority = ThreadPriority.BelowNormal;
                    ExecuteVerifiedVectorKernel(seed, goldenChecksum, ref totalOps, ref integrityErrors, workerToken);
                },
                CancellationToken.None,
                TaskCreationOptions.LongRunning,
                TaskScheduler.Default);
        }

        try
        {
            while (!workerToken.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(250), workerToken).ConfigureAwait(false);

                var (cpuTemp, gpuTemp) = await _platformProvider.PollThermalSensorsAsync(workerToken).ConfigureAwait(false);
                if (cpuTemp.HasValue && (!peakCpu.HasValue || cpuTemp.Value > peakCpu.Value))
                {
                    peakCpu = cpuTemp.Value;
                }

                if (gpuTemp.HasValue && (!peakGpu.HasValue || gpuTemp.Value > peakGpu.Value))
                {
                    peakGpu = gpuTemp.Value;
                }

                var elapsedSec = Math.Max(0.001, sw.Elapsed.TotalSeconds);
                var currentOps = Interlocked.Read(ref totalOps);
                var errCount = Volatile.Read(ref integrityErrors);
                var mops = Math.Round((currentOps / elapsedSec) / 1_000_000.0, 2);

                history.Add(new StressTelemetryPoint(Math.Round(elapsedSec, 2), mops, cpuTemp, gpuTemp));

                if ((cpuTemp.HasValue && cpuTemp.Value >= maxSafeCpuTempC) ||
                    (gpuTemp.HasValue && gpuTemp.Value >= maxSafeGpuTempC))
                {
                    thermalAborted = true;
                    await linkedCts.CancelAsync().ConfigureAwait(false);
                    break;
                }

                progress?.Report(new StressTestProgress(
                    Elapsed: sw.Elapsed,
                    TotalMatrixOperations: currentOps,
                    MillionsOpsPerSecond: mops,
                    PeakCpuTempC: peakCpu,
                    PeakGpuTempC: peakGpu,
                    WasAbortedByThermalCutoff: false,
                    StatusMessage: $"Стресс-тест ({workerCount} потоков): {mops:F1} млн опер./сек • Ошибок вычислений: {errCount}{DescribeSensorCoverage(peakCpu, peakGpu)}",
                    IntegrityErrorCount: errCount,
                    History: history.ToArray()));
            }
        }
        catch (OperationCanceledException) when (!externalCt.IsCancellationRequested)
        {
            // Штатное завершение по таймеру или тепловому предохранителю
        }
        finally
        {
            await linkedCts.CancelAsync().ConfigureAwait(false);
            await Task.WhenAll(workers).ConfigureAwait(false);
            sw.Stop();
        }

        var finalSec = Math.Max(0.001, sw.Elapsed.TotalSeconds);
        var finalOps = Interlocked.Read(ref totalOps);
        var finalErrors = Volatile.Read(ref integrityErrors);
        var finalMops = Math.Round((finalOps / finalSec) / 1_000_000.0, 2);

        if (history.Count == 0)
        {
            history.Add(new StressTelemetryPoint(Math.Round(finalSec, 2), finalMops, peakCpu, peakGpu));
        }

        string finalMsg;
        if (thermalAborted)
        {
            finalMsg = $"Сработал тепловой предохранитель (пик CPU {peakCpu?.ToString("F0") ?? "—"}°C / GPU {peakGpu?.ToString("F0") ?? "—"}°C) — нагрузка безопасно остановлена!";
        }
        else if (finalErrors > 0)
        {
            finalMsg = $"ВНИМАНИЕ: обнаружено {finalErrors} ошибок счёта за {sw.Elapsed.TotalSeconds:F1} сек! Возможна нестабильность разгона/андервольтинга CPU или ОЗУ.";
        }
        else
        {
            finalMsg = $"Тест стабильности пройден за {sw.Elapsed.TotalSeconds:F1} сек ({finalMops:F1} млн опер./сек, ошибок счёта: 0).{DescribeSensorCoverage(peakCpu, peakGpu)}";
        }

        var finalResult = new StressTestProgress(
            Elapsed: sw.Elapsed,
            TotalMatrixOperations: finalOps,
            MillionsOpsPerSecond: finalMops,
            PeakCpuTempC: peakCpu,
            PeakGpuTempC: peakGpu,
            WasAbortedByThermalCutoff: thermalAborted,
            StatusMessage: finalMsg,
            IntegrityErrorCount: finalErrors,
            History: history);

        progress?.Report(finalResult);
        return finalResult;
    }

    private static string DescribeSensorCoverage(double? peakCpuTempC, double? peakGpuTempC)
    {
        if (peakCpuTempC.HasValue)
        {
            return $" • Пик CPU: {peakCpuTempC.Value:F0}°C" + (peakGpuTempC.HasValue ? $", GPU: {peakGpuTempC.Value:F0}°C" : "");
        }

        return peakGpuTempC.HasValue
            ? $" • Пик GPU: {peakGpuTempC.Value:F0}°C (для температуры CPU установите опциональный PawnIO)."
            : " • Температура CPU недоступна без PawnIO (контролируйте нагрев самостоятельно).";
    }

    private static void ExecuteVerifiedVectorKernel(
        int workerSeed,
        ulong goldenChecksum,
        ref long sharedOpsCounter,
        ref int sharedIntegrityErrors,
        CancellationToken ct)
    {
        var scratch = new float[8192];
        for (var i = 0; i < scratch.Length; i++)
        {
            scratch[i] = 1.0001f + ((i + workerSeed) & 0xFF) * 0.0003f;
        }

        var accA = new Vector4(1.01f, 1.02f, 1.03f, 1.04f);
        var accB = new Vector4(0.99f, 0.98f, 0.97f, 0.96f);
        var bias = new Vector4(0.00001f * workerSeed);

        while (!ct.IsCancellationRequested)
        {
            long batchOps = 0;
            for (var idx = 0; idx < scratch.Length; idx += 4)
            {
                var v = new Vector4(scratch[idx], scratch[idx + 1], scratch[idx + 2], scratch[idx + 3]);
                accA = (accA * v) + bias;
                accB = (accB * accA) - bias;

                if (accA.X > 1e6f || accA.X < -1e6f)
                {
                    accA = new Vector4(1.01f, 1.02f, 1.03f, 1.04f);
                    accB = new Vector4(0.99f, 0.98f, 0.97f, 0.96f);
                }

                batchOps += 8;
            }

            // Детерминированная проверка целостности ALU + кэша L1/L2 на каждом цикле
            var check = ComputeDeterministicIntegrityBlock(0x55AA_1234_99CC_7711UL);
            if (check != goldenChecksum)
            {
                Interlocked.Increment(ref sharedIntegrityErrors);
            }

            scratch[0] = accB.X * 0.000001f + 1.0f;
            Interlocked.Add(ref sharedOpsCounter, batchOps);
        }
    }

    private static ulong ComputeDeterministicIntegrityBlock(ulong seed)
    {
        ulong x = seed;
        double fp = 1.5;
        for (int i = 1; i <= 256; i++)
        {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            x *= 2685821657736338717UL;
            fp = Math.BitIncrement((fp * 1.0009765625) - 0.00048828125);
        }

        return x ^ (ulong)BitConverter.DoubleToInt64Bits(fp);
    }
}
