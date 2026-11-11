using System.Diagnostics;
using System.Numerics;
using UltimateWindows.Modules.Hardware.Contracts;
using UltimateWindows.Modules.Hardware.Models;

namespace UltimateWindows.Modules.Hardware.Stress;

/// <summary>
/// Многопоточная вычислительная нагрузка на процессор с тепловым предохранителем.
///
/// Ограничения, о которых тест честно сообщает в итоговом сообщении:
/// 1) предохранитель срабатывает только по тем датчикам, которые удалось прочитать; если температура процессора
///    недоступна, защита для процессора не работает;
/// 2) тест нагружает процессор, но не сверяет результаты вычислений, поэтому ошибок счёта он не находит.
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
        var thermalAborted = false;
        double? peakCpu = null;
        double? peakGpu = null;

        var workerCount = Math.Max(1, Environment.ProcessorCount);
        var sw = Stopwatch.StartNew();

        var workers = new Task[workerCount];
        for (var w = 0; w < workerCount; w++)
        {
            var seed = w + 1;
            workers[w] = Task.Run(() => ExecuteVectorKernel(seed, ref totalOps, workerToken), CancellationToken.None);
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

                if ((cpuTemp.HasValue && cpuTemp.Value >= maxSafeCpuTempC) ||
                    (gpuTemp.HasValue && gpuTemp.Value >= maxSafeGpuTempC))
                {
                    thermalAborted = true;
                    await linkedCts.CancelAsync().ConfigureAwait(false);
                    break;
                }

                var elapsedSec = Math.Max(0.001, sw.Elapsed.TotalSeconds);
                var currentOps = Interlocked.Read(ref totalOps);
                var mops = Math.Round((currentOps / elapsedSec) / 1_000_000.0, 2);

                progress?.Report(new StressTestProgress(
                    Elapsed: sw.Elapsed,
                    TotalMatrixOperations: currentOps,
                    MillionsOpsPerSecond: mops,
                    PeakCpuTempC: peakCpu,
                    PeakGpuTempC: peakGpu,
                    WasAbortedByThermalCutoff: false,
                    StatusMessage: $"Стресс-тест выполняется ({workerCount} потоков): {mops:F1} млн опер./сек{DescribeSensorCoverage(peakCpu, peakGpu)}"));
            }
        }
        catch (OperationCanceledException) when (!externalCt.IsCancellationRequested)
        {
            // Штатное завершение по таймеру длительности или тепловому предохранителю
        }
        finally
        {
            await linkedCts.CancelAsync().ConfigureAwait(false);
            await Task.WhenAll(workers).ConfigureAwait(false);
            sw.Stop();
        }

        var finalSec = Math.Max(0.001, sw.Elapsed.TotalSeconds);
        var finalOps = Interlocked.Read(ref totalOps);
        var finalMops = Math.Round((finalOps / finalSec) / 1_000_000.0, 2);

        var finalMsg = thermalAborted
            ? $"Сработал тепловой предохранитель (пик CPU {peakCpu?.ToString("F0") ?? "-"}°C / GPU {peakGpu?.ToString("F0") ?? "-"}°C) — нагрузка безопасно остановлена!"
            : $"Нагрузочный прогон завершён за {sw.Elapsed.TotalSeconds:F1} сек ({finalMops:F1} млн векторных опер./сек). Ошибки вычислений этот тест не проверяет.{DescribeSensorCoverage(peakCpu, peakGpu)}";

        var finalResult = new StressTestProgress(
            Elapsed: sw.Elapsed,
            TotalMatrixOperations: finalOps,
            MillionsOpsPerSecond: finalMops,
            PeakCpuTempC: peakCpu,
            PeakGpuTempC: peakGpu,
            WasAbortedByThermalCutoff: thermalAborted,
            StatusMessage: finalMsg);

        progress?.Report(finalResult);
        return finalResult;
    }

    /// <summary>
    /// Предупреждение о том, за какими датчиками тепловая защита на самом деле следила.
    /// Пустая строка, если температура процессора читается.
    /// </summary>
    private static string DescribeSensorCoverage(double? peakCpuTempC, double? peakGpuTempC)
    {
        if (peakCpuTempC.HasValue)
        {
            return "";
        }

        return peakGpuTempC.HasValue
            ? " Температура процессора недоступна: тепловая защита следит только за видеокартой."
            : " Датчики температуры недоступны: тепловая защита не работает, следите за температурой сами.";
    }

    private static void ExecuteVectorKernel(int workerSeed, ref long sharedOpsCounter, CancellationToken ct)
    {
        // Комбинированная нагрузка SIMD Vector4 (FMA/FPU) + кэш L1/L2 (буфер 32 КБ на поток)
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

                // Защита от переполнения float в Infinity/NaN на длительных прогонах
                if (accA.X > 1e6f || accA.X < -1e6f)
                {
                    accA = new Vector4(1.01f, 1.02f, 1.03f, 1.04f);
                    accB = new Vector4(0.99f, 0.98f, 0.97f, 0.96f);
                }

                scratch[idx] = accA.X * 0.5f + 0.5f;
                batchOps += 8; // 2 векторные операции по 4 float элемента
            }

            Interlocked.Add(ref sharedOpsCounter, batchOps);
        }
    }
}
