using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using UltimateWindows.Modules.Security.Catalog;
using UltimateWindows.Modules.Security.Models;
using UltimateWindows.Modules.Security.Services;
using UltimateWindows.NativeInterop.Security;

namespace UltimateWindows.NativeInterop.SecurityHunter;

/// <summary>
/// Полноценный нативный мост Этапа 4 «Анти-майнер и Защита 2.0» для Windows 10 и Windows 11:
/// - двухфазный поведенческий детектор Drop-on-Inspect по CPU + GPU (pdh.dll \GPU Engine(*)\Utilization Percentage)
///   с окнами-приманками и реальным кратковременным запуском системного монитора;
/// - извлечение командной строки и родительского PID через NtQueryInformationProcess без WMI;
/// - нативная проверка приватных исполняемых регионов памяти (VirtualQueryEx) на Process Hollowing;
/// - таблица TCP-соединений IPv4 + IPv6 (GetExtendedTcpTable) и аудит DNS-кэша;
/// - ревизия всех 18 зон автозакрепления, исключений Microsoft Defender, правил брандмауэра, скрытых пользователей и staging-папок.
/// </summary>
public sealed partial class WindowsSecurityPlatformBridge : DefaultSecurityPlatformBridge
{
    private readonly ConcurrentDictionary<string, bool> _signatureCache = new(StringComparer.OrdinalIgnoreCase);

    public override bool IsRunningAsAdministrator() => ElevationChecker.IsRunningAsAdministrator();

    public override async Task<IReadOnlyList<ProcessTelemetrySample>> CaptureDropOnInspectSamplesAsync(
        bool runDecoyTrigger,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return [];
        }

        _signatureCache.Clear();
        var logicalCores = Math.Max(1, Environment.ProcessorCount);

        using var gpuSampler = NativeGpuEngineSampler.TryOpen();

        // 1. Тихий фоновый замер нагрузки CPU и GPU (T0 -> T1, 600 мс)
        var t0 = SampleProcessCpuTimes();
        gpuSampler?.PrimeBaseline();
        var swQuiet = Stopwatch.StartNew();
        await Task.Delay(600, ct).ConfigureAwait(false);
        swQuiet.Stop();
        var t1 = SampleProcessCpuTimes();
        var quietGpuByPid = gpuSampler?.CollectUtilizationByPid() ?? [];

        if (!runDecoyTrigger)
        {
            return BuildProcessSamples(
                t0, t1, swQuiet.Elapsed.TotalMilliseconds,
                t1, t1, swQuiet.Elapsed.TotalMilliseconds,
                quietGpuByPid, quietGpuByPid,
                logicalCores);
        }

        // 2. Фаза активного мониторинга: окна-приманки + реальный системный монитор (если доступен интерактивный рабочий стол)
        using var decoy = DecoyInspectionWindow.CreateDecoys();
        using var realMonitor = RealSystemMonitorProbe.TryLaunchMinimizedIfSafe();

        await Task.Delay(180, ct).ConfigureAwait(false); // Даём сторожевому потоку майнера заметить процесс/окно монитора

        var i0 = SampleProcessCpuTimes();
        gpuSampler?.PrimeBaseline();
        var swInspect = Stopwatch.StartNew();
        await Task.Delay(650, ct).ConfigureAwait(false);
        swInspect.Stop();
        var i1 = SampleProcessCpuTimes();
        var inspectGpuByPid = gpuSampler?.CollectUtilizationByPid() ?? [];

        return BuildProcessSamples(
            t0, t1, Math.Max(1.0, swQuiet.Elapsed.TotalMilliseconds),
            i0, i1, Math.Max(1.0, swInspect.Elapsed.TotalMilliseconds),
            quietGpuByPid, inspectGpuByPid,
            logicalCores);
    }

    public override Task<IReadOnlyList<ProcessTcpConnectionInfo>> GetActiveTcpConnectionsAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult<IReadOnlyList<ProcessTcpConnectionInfo>>([]);
        }

        return Task.Run<IReadOnlyList<ProcessTcpConnectionInfo>>(() =>
        {
            var list = new List<ProcessTcpConnectionInfo>();
            ReadIpv4TcpTable(list);
            ReadIpv6TcpTable(list);
            return list;
        }, ct);
    }

    public override async Task<IReadOnlyList<string>> ScanDnsCacheMiningPoolDomainsAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return [];
        }

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.SystemDirectory, "ipconfig.exe"),
                Arguments = "/displaydns",
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using var proc = Process.Start(psi);
            if (proc is null) return [];

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(4));

            var output = await proc.StandardOutput.ReadToEndAsync(timeoutCts.Token).ConfigureAwait(false);
            await proc.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);

            var catalog = ThreatIndicatorCatalog.Shared;
            var matched = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var rawLine in output.Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries))
            {
                if (catalog.MatchesMiningPoolDomain(rawLine, out var domain))
                {
                    matched.Add(domain);
                }
            }

            return matched.OrderBy(d => d, StringComparer.OrdinalIgnoreCase).ToList();
        }
        catch
        {
            return [];
        }
    }

    public override async Task<bool> TerminateSuspectProcessAsync(int processId, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows() || processId <= 4 || processId == Environment.ProcessId)
        {
            return false;
        }

        try
        {
            using var proc = Process.GetProcessById(processId);
            var cleanName = proc.ProcessName;
            if (cleanName.Equals("csrss", StringComparison.OrdinalIgnoreCase) ||
                cleanName.Equals("lsass", StringComparison.OrdinalIgnoreCase) ||
                cleanName.Equals("wininit", StringComparison.OrdinalIgnoreCase) ||
                cleanName.Equals("smss", StringComparison.OrdinalIgnoreCase) ||
                cleanName.Equals("services", StringComparison.OrdinalIgnoreCase) ||
                cleanName.Equals("winlogon", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            proc.Kill(entireProcessTree: true);
            using var waitCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            waitCts.CancelAfter(TimeSpan.FromSeconds(3));
            await proc.WaitForExitAsync(waitCts.Token).ConfigureAwait(false);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private List<ProcessTelemetrySample> BuildProcessSamples(
        Dictionary<int, (string Name, TimeSpan CpuTime, long WorkingSet)> q0,
        Dictionary<int, (string Name, TimeSpan CpuTime, long WorkingSet)> q1,
        double quietWindowMs,
        Dictionary<int, (string Name, TimeSpan CpuTime, long WorkingSet)> i0,
        Dictionary<int, (string Name, TimeSpan CpuTime, long WorkingSet)> i1,
        double inspectWindowMs,
        Dictionary<int, double> quietGpuByPid,
        Dictionary<int, double> inspectGpuByPid,
        int logicalCores)
    {
        var samples = new List<ProcessTelemetrySample>(q1.Count);
        var quietDenom = Math.Max(1.0, quietWindowMs * logicalCores);
        var inspectDenom = Math.Max(1.0, inspectWindowMs * logicalCores);
        var hollowTargets = ThreatIndicatorCatalog.Shared.HollowTargetBinaries;

        foreach (var (pid, endQuiet) in q1)
        {
            if (pid <= 4 || pid == Environment.ProcessId || !q0.TryGetValue(pid, out var startQuiet))
            {
                continue;
            }

            var quietCpuMs = Math.Max(0.0, (endQuiet.CpuTime - startQuiet.CpuTime).TotalMilliseconds);
            var baselineCpuPct = Math.Clamp(quietCpuMs / quietDenom * 100.0, 0.0, 100.0);

            bool exitedDuringInspect = !i1.ContainsKey(pid);
            double inspectCpuPct = 0.0;
            if (!exitedDuringInspect && i0.TryGetValue(pid, out var startInsp) && i1.TryGetValue(pid, out var endInsp))
            {
                var inspCpuMs = Math.Max(0.0, (endInsp.CpuTime - startInsp.CpuTime).TotalMilliseconds);
                inspectCpuPct = Math.Clamp(inspCpuMs / inspectDenom * 100.0, 0.0, 100.0);
            }

            double baselineGpuPct = quietGpuByPid.TryGetValue(pid, out var qGpu) ? Math.Clamp(qGpu, 0.0, 100.0) : 0.0;
            double inspectGpuPct = !exitedDuringInspect && inspectGpuByPid.TryGetValue(pid, out var iGpu)
                ? Math.Clamp(iGpu, 0.0, 100.0)
                : 0.0;

            var (exePath, commandLine, parentPid) = QueryProcessExtendedMetadata(pid);
            string parentName = parentPid > 4 && q1.TryGetValue(parentPid, out var pEntry) ? pEntry.Name : "";
            bool signed = !string.IsNullOrWhiteSpace(exePath) && VerifySignedCached(exePath);

            var exeFileName = !string.IsNullOrWhiteSpace(exePath) ? Path.GetFileName(exePath) : endQuiet.Name + ".exe";
            int privateExecRegions = 0;
            if (hollowTargets.Contains(exeFileName) || baselineCpuPct >= 15.0 || baselineGpuPct >= 15.0)
            {
                privateExecRegions = CountPrivateExecutableRegions(pid);
            }

            samples.Add(new ProcessTelemetrySample(
                ProcessId: pid,
                ProcessName: endQuiet.Name,
                ExecutablePath: exePath,
                CommandLine: commandLine,
                BaselineCpuPercent: Math.Round(baselineCpuPct, 1),
                DuringInspectCpuPercent: Math.Round(inspectCpuPct, 1),
                ExitedDuringInspect: exitedDuringInspect,
                IsAuthenticodeSigned: signed,
                BaselineGpuPercent: Math.Round(baselineGpuPct, 1),
                DuringInspectGpuPercent: Math.Round(inspectGpuPct, 1),
                ParentProcessId: parentPid,
                ParentProcessName: parentName,
                PrivateExecutableRegionCount: privateExecRegions,
                WorkingSetBytes: endQuiet.WorkingSet));
        }

        return samples;
    }

    private bool VerifySignedCached(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            return false;
        }

        return _signatureCache.GetOrAdd(filePath, static p => AuthenticodeVerifier.IsFileTrustedSigned(p));
    }

    private static Dictionary<int, (string Name, TimeSpan CpuTime, long WorkingSet)> SampleProcessCpuTimes()
    {
        var map = new Dictionary<int, (string Name, TimeSpan CpuTime, long WorkingSet)>(256);
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                if (p.Id > 4)
                {
                    map[p.Id] = (p.ProcessName, p.TotalProcessorTime, p.WorkingSet64);
                }
            }
            catch
            {
                // Защищённые системные процессы пропускаются без исключений
            }
            finally
            {
                p.Dispose();
            }
        }

        return map;
    }

    private static (string ExePath, string CommandLine, int ParentPid) QueryProcessExtendedMetadata(int pid)
    {
        var hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, bInheritHandle: false, (uint)pid);
        if (hProcess == IntPtr.Zero)
        {
            return ("", "", 0);
        }

        try
        {
            var sb = new StringBuilder(512);
            uint size = (uint)sb.Capacity;
            string exePath = QueryFullProcessImageNameW(hProcess, 0, sb, ref size) ? sb.ToString() : "";

            int parentPid = 0;
            var pbi = new PROCESS_BASIC_INFORMATION();
            if (NtQueryInformationProcess(hProcess, ProcessBasicInformationClass, ref pbi, Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(), out _) == 0)
            {
                parentPid = (int)pbi.InheritedFromUniqueProcessId.ToInt64();
            }

            string cmdLine = QueryProcessCommandLineNative(hProcess);
            return (exePath, cmdLine, parentPid);
        }
        finally
        {
            _ = CloseHandle(hProcess);
        }
    }

    private static string QueryProcessCommandLineNative(IntPtr hProcess)
    {
        int status = NtQueryInformationProcessBuffer(hProcess, ProcessCommandLineInformationClass, IntPtr.Zero, 0, out int returnLength);
        if (returnLength <= 0 || returnLength > 65536)
        {
            return "";
        }

        var buffer = Marshal.AllocHGlobal(returnLength);
        try
        {
            status = NtQueryInformationProcessBuffer(hProcess, ProcessCommandLineInformationClass, buffer, returnLength, out _);
            if (status != 0)
            {
                return "";
            }

            var unicode = Marshal.PtrToStructure<UNICODE_STRING>(buffer);
            if (unicode.Length == 0 || unicode.Buffer == IntPtr.Zero)
            {
                return "";
            }

            return Marshal.PtrToStringUni(unicode.Buffer, unicode.Length / 2) ?? "";
        }
        catch
        {
            return "";
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>
    /// Нативный поиск не привязанных к файлам на диске исполняемых регионов памяти (MEM_PRIVATE + PAGE_EXECUTE_*) >= 64 КБ.
    /// Позволяет обнаруживать распакованные в память пейлоады XMRig и Process Hollowing даже без внешнего pe-sieve.
    /// </summary>
    private static int CountPrivateExecutableRegions(int pid)
    {
        var hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, bInheritHandle: false, (uint)pid);
        if (hProcess == IntPtr.Zero)
        {
            return 0;
        }

        try
        {
            int suspectRegions = 0;
            nuint address = 0;
            int mbiSize = Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();

            for (int step = 0; step < 3072; step++)
            {
                if (VirtualQueryEx(hProcess, (IntPtr)address, out var mbi, (nuint)mbiSize) == 0)
                {
                    break;
                }

                if (mbi.State == MEM_COMMIT &&
                    mbi.Type == MEM_PRIVATE &&
                    mbi.RegionSize >= 64 * 1024 &&
                    (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0 &&
                    (mbi.Protect & PAGE_GUARD) == 0)
                {
                    suspectRegions++;
                }

                nuint next = (nuint)mbi.BaseAddress + mbi.RegionSize;
                if (next <= address)
                {
                    break;
                }

                address = next;
            }

            return suspectRegions;
        }
        catch
        {
            return 0;
        }
        finally
        {
            _ = CloseHandle(hProcess);
        }
    }

    private static void ReadIpv4TcpTable(List<ProcessTcpConnectionInfo> sink)
    {
        uint buffSize = 0;
        _ = GetExtendedTcpTable(IntPtr.Zero, ref buffSize, sort: false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (buffSize == 0 || buffSize > 16 * 1024 * 1024)
        {
            return;
        }

        var buffer = Marshal.AllocHGlobal((int)buffSize);
        try
        {
            if (GetExtendedTcpTable(buffer, ref buffSize, sort: false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != 0)
            {
                return;
            }

            int rowCount = Marshal.ReadInt32(buffer);
            var rowPtr = buffer + 4;
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

            for (int i = 0; i < rowCount && i < 16384; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                rowPtr += rowSize;

                if (row.dwState is not (3u or 5u) || row.dwRemoteAddr == 0)
                {
                    continue;
                }

                var localIp = new IPAddress(row.dwLocalAddr).ToString();
                var remoteIp = new IPAddress(row.dwRemoteAddr).ToString();
                var localPort = BinaryPrimitives.ReverseEndianness((ushort)(row.dwLocalPort & 0xFFFF));
                var remotePort = BinaryPrimitives.ReverseEndianness((ushort)(row.dwRemotePort & 0xFFFF));

                sink.Add(new ProcessTcpConnectionInfo(
                    ProcessId: (int)row.dwOwningPid,
                    LocalAddress: localIp,
                    LocalPort: localPort,
                    RemoteAddress: remoteIp,
                    RemotePort: remotePort,
                    IsIpv6: false));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static unsafe void ReadIpv6TcpTable(List<ProcessTcpConnectionInfo> sink)
    {
        uint buffSize = 0;
        _ = GetExtendedTcpTable(IntPtr.Zero, ref buffSize, sort: false, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
        if (buffSize == 0 || buffSize > 16 * 1024 * 1024)
        {
            return;
        }

        var buffer = Marshal.AllocHGlobal((int)buffSize);
        try
        {
            if (GetExtendedTcpTable(buffer, ref buffSize, sort: false, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) != 0)
            {
                return;
            }

            int rowCount = Marshal.ReadInt32(buffer);
            var rowPtr = buffer + 4;
            int rowSize = Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>();

            for (int i = 0; i < rowCount && i < 16384; i++)
            {
                var row = *(MIB_TCP6ROW_OWNER_PID*)rowPtr;
                rowPtr += rowSize;

                if (row.dwState is not (3u or 5u))
                {
                    continue;
                }

                var localSpan = new ReadOnlySpan<byte>(row.ucLocalAddr, 16);
                var remoteSpan = new ReadOnlySpan<byte>(row.ucRemoteAddr, 16);
                var remoteAddr = new IPAddress(remoteSpan, row.dwRemoteScopeId);
                if (IPAddress.IsLoopback(remoteAddr) || remoteAddr.Equals(IPAddress.IPv6Any) || remoteAddr.Equals(IPAddress.IPv6None))
                {
                    continue;
                }

                var localAddr = new IPAddress(localSpan, row.dwLocalScopeId);
                var localPort = BinaryPrimitives.ReverseEndianness((ushort)(row.dwLocalPort & 0xFFFF));
                var remotePort = BinaryPrimitives.ReverseEndianness((ushort)(row.dwRemotePort & 0xFFFF));

                sink.Add(new ProcessTcpConnectionInfo(
                    ProcessId: (int)row.dwOwningPid,
                    LocalAddress: localAddr.ToString(),
                    LocalPort: localPort,
                    RemoteAddress: remoteAddr.ToString(),
                    RemotePort: remotePort,
                    IsIpv6: true));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>
    /// Нативный PDH-сэмплер загрузки GPU по процессам (\GPU Engine(*)\Utilization Percentage).
    /// Использует английское имя счётчика (PdhAddEnglishCounterW), поэтому одинаково работает на русской и английской Windows 10/11.
    /// </summary>
    private sealed class NativeGpuEngineSampler : IDisposable
    {
        private IntPtr _hQuery;
        private IntPtr _hCounter;

        private NativeGpuEngineSampler(IntPtr hQuery, IntPtr hCounter)
        {
            _hQuery = hQuery;
            _hCounter = hCounter;
        }

        public static NativeGpuEngineSampler? TryOpen()
        {
            try
            {
                if (PdhOpenQueryW(IntPtr.Zero, IntPtr.Zero, out var query) != 0 || query == IntPtr.Zero)
                {
                    return null;
                }

                if (PdhAddEnglishCounterW(query, @"\GPU Engine(*)\Utilization Percentage", IntPtr.Zero, out var counter) != 0 || counter == IntPtr.Zero)
                {
                    _ = PdhCloseQuery(query);
                    return null;
                }

                return new NativeGpuEngineSampler(query, counter);
            }
            catch
            {
                return null;
            }
        }

        public void PrimeBaseline()
        {
            if (_hQuery != IntPtr.Zero)
            {
                _ = PdhCollectQueryData(_hQuery);
            }
        }

        public Dictionary<int, double> CollectUtilizationByPid()
        {
            var result = new Dictionary<int, double>();
            if (_hQuery == IntPtr.Zero || _hCounter == IntPtr.Zero)
            {
                return result;
            }

            if (PdhCollectQueryData(_hQuery) != 0)
            {
                return result;
            }

            uint bufferSize = 0;
            uint itemCount = 0;
            uint status = PdhGetFormattedCounterArrayW(_hCounter, PDH_FMT_DOUBLE, ref bufferSize, ref itemCount, IntPtr.Zero);
            if (status != PDH_MORE_DATA || bufferSize == 0 || bufferSize > 8 * 1024 * 1024)
            {
                return result;
            }

            var buffer = Marshal.AllocHGlobal((int)bufferSize);
            try
            {
                status = PdhGetFormattedCounterArrayW(_hCounter, PDH_FMT_DOUBLE, ref bufferSize, ref itemCount, buffer);
                if (status != 0 || itemCount == 0)
                {
                    return result;
                }

                int itemSize = Marshal.SizeOf<PDH_FMT_COUNTERVALUE_ITEM_DOUBLE>();
                var ptr = buffer;
                for (uint i = 0; i < itemCount && i < 16384; i++)
                {
                    var item = Marshal.PtrToStructure<PDH_FMT_COUNTERVALUE_ITEM_DOUBLE>(ptr);
                    ptr += itemSize;

                    if (item.FmtValue.CStatus != 0 || item.FmtValue.DoubleValue <= 0.05 || item.SzName == IntPtr.Zero)
                    {
                        continue;
                    }

                    var instanceName = Marshal.PtrToStringUni(item.SzName);
                    if (string.IsNullOrWhiteSpace(instanceName))
                    {
                        continue;
                    }

                    // Нас интересуют движки вычислений и рендера: 3D, Compute, Cuda, Copy
                    int pid = TryParsePidFromGpuInstance(instanceName);
                    if (pid <= 4)
                    {
                        continue;
                    }

                    result[pid] = result.TryGetValue(pid, out var prev)
                        ? Math.Min(100.0, prev + item.FmtValue.DoubleValue)
                        : Math.Min(100.0, item.FmtValue.DoubleValue);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

            return result;
        }

        private static int TryParsePidFromGpuInstance(string instance)
        {
            const string prefix = "pid_";
            int idx = instance.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return 0;

            int start = idx + prefix.Length;
            int end = start;
            while (end < instance.Length && char.IsAsciiDigit(instance[end]))
            {
                end++;
            }

            return end > start && int.TryParse(instance.AsSpan(start, end - start), out int pid) ? pid : 0;
        }

        public void Dispose()
        {
            if (_hQuery != IntPtr.Zero)
            {
                _ = PdhCloseQuery(_hQuery);
                _hQuery = IntPtr.Zero;
                _hCounter = IntPtr.Zero;
            }
        }
    }

    /// <summary>
    /// Кратковременно запускает настоящий системный монитор Windows в свёрнутом неактивном режиме (только если он ещё не открыт),
    /// чтобы выманить майнеры класса SilentCryptoMiner, проверяющие список процессов через CreateToolhelp32Snapshot.
    /// По завершении 650-мс окна аккуратно закрывает только созданный дочерний процесс.
    /// </summary>
    private sealed class RealSystemMonitorProbe : IDisposable
    {
        private readonly Process? _spawnedProcess;

        private RealSystemMonitorProbe(Process? spawnedProcess)
        {
            _spawnedProcess = spawnedProcess;
        }

        public static RealSystemMonitorProbe TryLaunchMinimizedIfSafe()
        {
            if (!OperatingSystem.IsWindows() || !Environment.UserInteractive)
            {
                return new RealSystemMonitorProbe(null);
            }

            // Не мешаем пользователю, если Диспетчер задач или Монитор ресурсов уже открыт, и не запускаем в автоматических CI-раннерах
            if (!string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("GITHUB_ACTIONS")) ||
                !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("CI")))
            {
                return new RealSystemMonitorProbe(null);
            }

            try
            {
                if (Process.GetProcessesByName("Taskmgr").Length > 0 ||
                    Process.GetProcessesByName("perfmon").Length > 0)
                {
                    return new RealSystemMonitorProbe(null);
                }

                // Когда процесс уже запущен с правами администратора, запускаем свёрнутый taskmgr.exe без запроса UAC;
                // без прав администратора используем штатный свёрнутый perfmon /res (не вызывает UAC).
                string candidateExe = ElevationChecker.IsRunningAsAdministrator()
                    ? Path.Combine(Environment.SystemDirectory, "Taskmgr.exe")
                    : Path.Combine(Environment.SystemDirectory, "systray.exe");

                if (!File.Exists(candidateExe))
                {
                    return new RealSystemMonitorProbe(null);
                }

                var psi = new ProcessStartInfo
                {
                    FileName = candidateExe,
                    UseShellExecute = false,
                    WindowStyle = ProcessWindowStyle.Minimized,
                    CreateNoWindow = true
                };

                return new RealSystemMonitorProbe(Process.Start(psi));
            }
            catch
            {
                return new RealSystemMonitorProbe(null);
            }
        }

        public void Dispose()
        {
            if (_spawnedProcess is null) return;
            try
            {
                if (!_spawnedProcess.HasExited)
                {
                    _spawnedProcess.Kill();
                }
            }
            catch
            {
                // Игнорируем, если уже закрылся
            }
            finally
            {
                _spawnedProcess.Dispose();
            }
        }
    }

    /// <summary>
    /// Невидимые окна-приманки верхнего уровня с заголовками популярных диспетчеров процессов (EN + RU).
    /// </summary>
    private sealed class DecoyInspectionWindow : IDisposable
    {
        private readonly ManualResetEventSlim _ready = new(false);
        private readonly ManualResetEventSlim _stop = new(false);
        private readonly Thread _thread;

        private DecoyInspectionWindow()
        {
            _thread = new Thread(WindowThreadLoop)
            {
                IsBackground = true,
                Name = "UW-DropOnInspect-Decoy"
            };
            _thread.Start();
            _ready.Wait(TimeSpan.FromMilliseconds(300));
        }

        public static DecoyInspectionWindow CreateDecoys() => new();

        private void WindowThreadLoop()
        {
            var titles = new[] { "Task Manager", "Диспетчер задач", "System Informer", "Process Explorer" };
            var handles = new List<IntPtr>(titles.Length);

            foreach (var title in titles)
            {
                var hwnd = CreateWindowExW(
                    WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
                    "STATIC",
                    title,
                    WS_POPUP,
                    -32000, -32000, 1, 1,
                    IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                if (hwnd != IntPtr.Zero)
                {
                    handles.Add(hwnd);
                }
            }

            _ready.Set();
            _stop.Wait(TimeSpan.FromSeconds(4));

            foreach (var hwnd in handles)
            {
                _ = DestroyWindow(hwnd);
            }
        }

        public void Dispose()
        {
            _stop.Set();
            _thread.Join(millisecondsTimeout: 300);
            _ready.Dispose();
            _stop.Dispose();
        }
    }

    // ==================== WIN32 / NTAPI / PDH P/INVOKE ====================
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const int ProcessBasicInformationClass = 0;
    private const int ProcessCommandLineInformationClass = 60;

    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_PRIVATE = 0x20000;
    private const uint PAGE_EXECUTE = 0x10;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    private const uint PAGE_GUARD = 0x100;

    private const uint AF_INET = 2;
    private const uint AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;

    private const uint PDH_FMT_DOUBLE = 0x00000200;
    private const uint PDH_MORE_DATA = 0x800007D2;

    private const uint WS_POPUP = 0x80000000;
    private const uint WS_EX_TOOLWINDOW = 0x00000080;
    private const uint WS_EX_NOACTIVATE = 0x08000000;

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public ushort PartitionId;
        public nuint RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct MIB_TCP6ROW_OWNER_PID
    {
        public fixed byte ucLocalAddr[16];
        public uint dwLocalScopeId;
        public uint dwLocalPort;
        public fixed byte ucRemoteAddr[16];
        public uint dwRemoteScopeId;
        public uint dwRemotePort;
        public uint dwState;
        public uint dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PDH_FMT_COUNTERVALUE_DOUBLE
    {
        public uint CStatus;
        public double DoubleValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PDH_FMT_COUNTERVALUE_ITEM_DOUBLE
    {
        public IntPtr SzName;
        public PDH_FMT_COUNTERVALUE_DOUBLE FmtValue;
    }

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageNameW(IntPtr hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern nuint VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, nuint dwLength);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int NtQueryInformationProcess(
        IntPtr processHandle,
        int processInformationClass,
        ref PROCESS_BASIC_INFORMATION processInformation,
        int processInformationLength,
        out int returnLength);

    [DllImport("ntdll.dll", EntryPoint = "NtQueryInformationProcess", ExactSpelling = true)]
    private static extern int NtQueryInformationProcessBuffer(
        IntPtr processHandle,
        int processInformationClass,
        IntPtr processInformation,
        int processInformationLength,
        out int returnLength);

    [DllImport("iphlpapi.dll", SetLastError = true, ExactSpelling = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref uint pdwSize,
        [MarshalAs(UnmanagedType.Bool)] bool sort,
        uint ulAf,
        int tableClass,
        uint reserved);

    [DllImport("pdh.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint PdhOpenQueryW(IntPtr szDataSource, IntPtr dwUserData, out IntPtr phQuery);

    [DllImport("pdh.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint PdhAddEnglishCounterW(IntPtr hQuery, string szFullCounterPath, IntPtr dwUserData, out IntPtr phCounter);

    [DllImport("pdh.dll", ExactSpelling = true)]
    private static extern uint PdhCollectQueryData(IntPtr hQuery);

    [DllImport("pdh.dll", ExactSpelling = true)]
    private static extern uint PdhGetFormattedCounterArrayW(
        IntPtr hCounter,
        uint dwFormat,
        ref uint lpdwBufferSize,
        ref uint lpdwItemCount,
        IntPtr itemBuffer);

    [DllImport("pdh.dll", ExactSpelling = true)]
    private static extern uint PdhCloseQuery(IntPtr hQuery);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr CreateWindowExW(
        uint dwExStyle,
        string lpClassName,
        string lpWindowName,
        uint dwStyle,
        int x,
        int y,
        int nWidth,
        int nHeight,
        IntPtr hWndParent,
        IntPtr hMenu,
        IntPtr hInstance,
        IntPtr lpParam);

    [DllImport("user32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyWindow(IntPtr hWnd);
}
