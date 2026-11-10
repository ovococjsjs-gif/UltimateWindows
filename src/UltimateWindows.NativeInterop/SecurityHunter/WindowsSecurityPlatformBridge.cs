using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using UltimateWindows.Modules.Cleaner.Utilities;
using UltimateWindows.Modules.Optimizer.Network;
using UltimateWindows.Modules.Security.Models;
using UltimateWindows.Modules.Security.Services;
using UltimateWindows.NativeInterop.Security;

namespace UltimateWindows.NativeInterop.SecurityHunter;

/// <summary>
/// Полноценный нативный мост Фазы 5 для Windows 10/11:
/// двухфазный поведенческий детектор Drop-on-Inspect с невидимым окном-приманкой,
/// таблица соединений GetExtendedTcpTable (iphlpapi.dll), ревизор IFEO/Winlogon/скрытых задач без SD
/// и модуль снятия блокировок майнера.
/// </summary>
public sealed class WindowsSecurityPlatformBridge : DefaultSecurityPlatformBridge
{
    private static readonly string[] CriticalAdminTools =
    [
        "taskmgr.exe", "regedit.exe", "cmd.exe", "mmc.exe", "powershell.exe", "msconfig.exe"
    ];

    public override bool IsRunningAsAdministrator() => ElevationChecker.IsRunningAsAdministrator();

    public override async Task<IReadOnlyList<ProcessTelemetrySample>> CaptureDropOnInspectSamplesAsync(
        bool runDecoyTrigger,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Array.Empty<ProcessTelemetrySample>();
        }

        var logicalCores = Math.Max(1, Environment.ProcessorCount);

        // 1. Тихий фоновый замер нагрузки CPU (T0 -> T1, 650 мс)
        var t0 = SampleProcessCpuTimes();
        var swQuiet = Stopwatch.StartNew();
        await Task.Delay(650, ct).ConfigureAwait(false);
        swQuiet.Stop();
        var t1 = SampleProcessCpuTimes();

        Dictionary<int, (string Name, TimeSpan CpuTime)> t2;
        double inspectElapsedMs = 650;

        if (runDecoyTrigger)
        {
            // 2. Создаем невидимое нулевое окно-приманку с заголовком «Task Manager» для выманивания прячущихся майнеров
            using var decoy = DecoyInspectionWindow.CreateHiddenDecoy();
            await Task.Delay(150, ct).ConfigureAwait(false); // Даем сторожевому потоку майнера заметить окно
            var t1Start = SampleProcessCpuTimes();
            var swInspect = Stopwatch.StartNew();
            await Task.Delay(650, ct).ConfigureAwait(false);
            swInspect.Stop();
            inspectElapsedMs = Math.Max(1.0, swInspect.Elapsed.TotalMilliseconds);
            t2 = SampleProcessCpuTimes();

            // Пересчитываем дельту второй фазы от t1Start
            return BuildProcessSamples(t0, t1, swQuiet.Elapsed.TotalMilliseconds, t1Start, t2, inspectElapsedMs, logicalCores);
        }

        return BuildProcessSamples(t0, t1, swQuiet.Elapsed.TotalMilliseconds, t1, t1, inspectElapsedMs, logicalCores);
    }

    public override Task<IReadOnlyList<ProcessTcpConnectionInfo>> GetActiveTcpConnectionsAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult<IReadOnlyList<ProcessTcpConnectionInfo>>(Array.Empty<ProcessTcpConnectionInfo>());
        }

        return Task.Run<IReadOnlyList<ProcessTcpConnectionInfo>>(() =>
        {
            var list = new List<ProcessTcpConnectionInfo>();
            uint buffSize = 0;
            _ = GetExtendedTcpTable(IntPtr.Zero, ref buffSize, sort: false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (buffSize == 0 || buffSize > 16 * 1024 * 1024)
            {
                return list;
            }

            var buffer = Marshal.AllocHGlobal((int)buffSize);
            try
            {
                if (GetExtendedTcpTable(buffer, ref buffSize, sort: false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != 0)
                {
                    return list;
                }

                var rowCount = Marshal.ReadInt32(buffer);
                var rowPtr = buffer + 4;
                var rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

                for (int i = 0; i < rowCount && i < 16384; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                    rowPtr += rowSize;

                    // Нас интересуют активные исходящие/установленные сессии (SYN_SENT = 3, ESTABLISHED = 5)
                    if (row.dwState is not (3u or 5u) || row.dwRemoteAddr == 0)
                    {
                        continue;
                    }

                    var localIp = new IPAddress(row.dwLocalAddr).ToString();
                    var remoteIp = new IPAddress(row.dwRemoteAddr).ToString();
                    var localPort = BinaryPrimitives.ReverseEndianness((ushort)(row.dwLocalPort & 0xFFFF));
                    var remotePort = BinaryPrimitives.ReverseEndianness((ushort)(row.dwRemotePort & 0xFFFF));

                    list.Add(new ProcessTcpConnectionInfo(
                        ProcessId: (int)row.dwOwningPid,
                        LocalAddress: localIp,
                        LocalPort: localPort,
                        RemoteAddress: remoteIp,
                        RemotePort: remotePort));
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

            return list;
        }, ct);
    }

    public override Task<IReadOnlyList<PersistenceAnomalyRecord>> ScanPersistenceAnomaliesAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult<IReadOnlyList<PersistenceAnomalyRecord>>(Array.Empty<PersistenceAnomalyRecord>());
        }

        return Task.Run<IReadOnlyList<PersistenceAnomalyRecord>>(() =>
        {
            var anomalies = new List<PersistenceAnomalyRecord>();

            // 1. Проверка перехватов запуска Image File Execution Options (IFEO Debugger)
            const string ifeoPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
            try
            {
                using var ifeoRoot = Registry.LocalMachine.OpenSubKey(ifeoPath, writable: false);
                if (ifeoRoot is not null)
                {
                    foreach (var subName in ifeoRoot.GetSubKeyNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        using var sub = ifeoRoot.OpenSubKey(subName, writable: false);
                        var debugger = sub?.GetValue("Debugger")?.ToString()?.Trim();
                        if (string.IsNullOrWhiteSpace(debugger)) continue;

                        // Пропускаем штатный JIT-отладчик Visual Studio, если он явно указан разработчиком
                        if (debugger.Contains("vsjitdebugger.exe", StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }

                        anomalies.Add(new PersistenceAnomalyRecord(
                            Vector: ThreatDetectionVector.IfeoDebuggerHijack,
                            RegistryOrTaskPath: $@"HKLM\{ifeoPath}\{subName}",
                            EntryName: subName,
                            PayloadCommandOrPath: debugger,
                            ReferencedExecutablePath: CommandLinePathExtractor.TryExtractLocalExecutablePath(debugger),
                            IsMissingSecurityDescriptorSd: false,
                            PreviousValueSerialized: debugger));
                    }
                }
            }
            catch
            {
                // Безопасный пропуск
            }

            // 2. Проверка подмены оболочки входа Winlogon (Shell / Userinit)
            const string winlogonPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
            try
            {
                using var wl = Registry.LocalMachine.OpenSubKey(winlogonPath, writable: false);
                if (wl is not null)
                {
                    var shell = wl.GetValue("Shell")?.ToString()?.Trim();
                    if (!string.IsNullOrWhiteSpace(shell) &&
                        !string.Equals(shell, "explorer.exe", StringComparison.OrdinalIgnoreCase) &&
                        !shell.EndsWith(@"\explorer.exe", StringComparison.OrdinalIgnoreCase))
                    {
                        anomalies.Add(new PersistenceAnomalyRecord(
                            Vector: ThreatDetectionVector.WinlogonShellHijack,
                            RegistryOrTaskPath: $@"HKLM\{winlogonPath}",
                            EntryName: "Shell",
                            PayloadCommandOrPath: shell,
                            ReferencedExecutablePath: CommandLinePathExtractor.TryExtractLocalExecutablePath(shell),
                            IsMissingSecurityDescriptorSd: false,
                            PreviousValueSerialized: shell));
                    }
                }
            }
            catch
            {
                // Безопасный пропуск
            }

            // 3. Поиск скрытых задач Планировщика без дескриптора безопасности SD (Ghost Scheduled Tasks)
            const string taskTreePath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree";
            try
            {
                using var treeRoot = Registry.LocalMachine.OpenSubKey(taskTreePath, writable: false);
                if (treeRoot is not null)
                {
                    ScanTaskTreeForMissingSd(treeRoot, "", depth: 0, anomalies, ct);
                }
            }
            catch
            {
                // На части систем ветка TaskCache закрыта для обычного пользователя — безопасно пропускаем
            }

            return anomalies;
        }, ct);
    }

    public override Task<IReadOnlyList<OsSabotageFinding>> ScanOsSabotageLocksAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult<IReadOnlyList<OsSabotageFinding>>(Array.Empty<OsSabotageFinding>());
        }

        return Task.Run<IReadOnlyList<OsSabotageFinding>>(() =>
        {
            var findings = new List<OsSabotageFinding>();

            CheckPolicyIntLock(
                Registry.CurrentUser, "HKCU",
                @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr",
                OsSabotageKind.TaskManagerDisabledByPolicy,
                "Диспетчер задач заблокирован политикой",
                "Майнер установил запрет на открытие Диспетчера задач, чтобы вы не могли увидеть нагрузку на ПК.",
                findings);

            CheckPolicyIntLock(
                Registry.LocalMachine, "HKLM",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr",
                OsSabotageKind.TaskManagerDisabledByPolicy,
                "Диспетчер задач заблокирован на уровне системы",
                "Системная политика запрещает запуск Диспетчера задач.",
                findings);

            CheckPolicyIntLock(
                Registry.CurrentUser, "HKCU",
                @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableRegistryTools",
                OsSabotageKind.RegistryEditorDisabledByPolicy,
                "Редактор реестра (regedit) заблокирован",
                "Установлен запрет на просмотр и редактирование реестра Windows.",
                findings);

            CheckPolicyIntLock(
                Registry.CurrentUser, "HKCU",
                @"Software\Policies\Microsoft\Windows\System", "DisableCMD",
                OsSabotageKind.CommandPromptDisabledByPolicy,
                "Командная строка (cmd.exe) заблокирована",
                "Политика запрещает выполнение диагностических команд в консоли.",
                findings);

            // Проверка блокировки системных утилит через IFEO Debugger
            const string ifeoBase = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
            try
            {
                using var ifeo = Registry.LocalMachine.OpenSubKey(ifeoBase, writable: false);
                if (ifeo is not null)
                {
                    foreach (var tool in CriticalAdminTools)
                    {
                        using var sub = ifeo.OpenSubKey(tool, writable: false);
                        var dbg = sub?.GetValue("Debugger")?.ToString();
                        if (!string.IsNullOrWhiteSpace(dbg))
                        {
                            findings.Add(new OsSabotageFinding(
                                Kind: OsSabotageKind.SystemToolIfeoBlocked,
                                TargetDisplayPath: $@"HKLM\{ifeoBase}\{tool} :: Debugger",
                                Hive: "HKLM",
                                SubKeyPath: $@"{ifeoBase}\{tool}",
                                ValueName: "Debugger",
                                CurrentMaliciousValue: dbg,
                                SimpleTitle: $"Перехвачен запуск системной утилиты «{tool}»",
                                SimpleExplanation: $"При попытке открыть «{tool}» система перенаправляется на «{dbg}»."));
                        }
                    }
                }
            }
            catch
            {
                // Безопасный пропуск
            }

            // Проверка блокировок антивирусов и Центра обновления в файле hosts
            var hostsPath = GetHostsFilePath();
            if (File.Exists(hostsPath))
            {
                try
                {
                    var text = File.ReadAllText(hostsPath);
                    var suspicious = NetworkAndHostsInspector.ParseHostsContent(text)
                        .Where(h => h.IsSuspiciousSecurityBlock)
                        .ToList();

                    if (suspicious.Count > 0)
                    {
                        var sampleDomains = string.Join(", ", suspicious.Take(4).Select(s => s.DomainHost));
                        findings.Add(new OsSabotageFinding(
                            Kind: OsSabotageKind.SecurityDomainsBlockedInHosts,
                            TargetDisplayPath: hostsPath,
                            Hive: "FILE",
                            SubKeyPath: hostsPath,
                            ValueName: "hosts",
                            CurrentMaliciousValue: sampleDomains,
                            SimpleTitle: $"В файле hosts заблокированы сайты антивирусов и обновлений ({suspicious.Count} шт.)",
                            SimpleExplanation: $"Обнаружена блокировка доступа к защитным серверам ({sampleDomains})."));
                    }
                }
                catch
                {
                    // Безопасный пропуск
                }
            }

            return findings;
        }, ct);
    }

    public override async Task<bool> TerminateSuspectProcessAsync(int processId, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows() || processId <= 4)
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
                cleanName.Equals("smss", StringComparison.OrdinalIgnoreCase))
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

    public override Task<(bool Succeeded, string? OriginalHostsBackupContent)> RepairSabotageLockAsync(
        OsSabotageFinding lockFinding,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult((false, (string?)null));
        }

        return Task.Run(() =>
        {
            if (lockFinding.Kind == OsSabotageKind.SecurityDomainsBlockedInHosts)
            {
                try
                {
                    var hostsPath = GetHostsFilePath();
                    if (!File.Exists(hostsPath)) return (false, (string?)null);

                    var original = File.ReadAllText(hostsPath);
                    var suspiciousLines = NetworkAndHostsInspector.ParseHostsContent(original)
                        .Where(h => h.IsSuspiciousSecurityBlock)
                        .Select(h => h.LineNumber)
                        .ToHashSet();

                    var rawLines = original.Split(["\r\n", "\n"], StringSplitOptions.None);
                    var cleaned = new StringBuilder();
                    for (int i = 0; i < rawLines.Length; i++)
                    {
                        if (!suspiciousLines.Contains(i + 1))
                        {
                            cleaned.AppendLine(rawLines[i]);
                        }
                    }

                    File.WriteAllText(hostsPath, cleaned.ToString(), Encoding.UTF8);
                    return (true, original);
                }
                catch
                {
                    return (false, (string?)null);
                }
            }

            try
            {
                var root = string.Equals(lockFinding.Hive, "HKLM", StringComparison.OrdinalIgnoreCase)
                    ? Registry.LocalMachine
                    : Registry.CurrentUser;

                using var key = root.OpenSubKey(lockFinding.SubKeyPath, writable: true);
                key?.DeleteValue(lockFinding.ValueName, throwOnMissingValue: false);
                return (true, (string?)null);
            }
            catch
            {
                return (false, (string?)null);
            }
        }, ct);
    }

    private static List<ProcessTelemetrySample> BuildProcessSamples(
        Dictionary<int, (string Name, TimeSpan CpuTime)> q0,
        Dictionary<int, (string Name, TimeSpan CpuTime)> q1,
        double quietWindowMs,
        Dictionary<int, (string Name, TimeSpan CpuTime)> i0,
        Dictionary<int, (string Name, TimeSpan CpuTime)> i1,
        double inspectWindowMs,
        int logicalCores)
    {
        var samples = new List<ProcessTelemetrySample>();
        var quietDenom = Math.Max(1.0, quietWindowMs * logicalCores);
        var inspectDenom = Math.Max(1.0, inspectWindowMs * logicalCores);

        foreach (var (pid, endQuiet) in q1)
        {
            if (pid <= 4 || !q0.TryGetValue(pid, out var startQuiet))
            {
                continue;
            }

            var quietCpuMs = Math.Max(0.0, (endQuiet.CpuTime - startQuiet.CpuTime).TotalMilliseconds);
            var baselinePct = Math.Clamp(quietCpuMs / quietDenom * 100.0, 0.0, 100.0);

            bool exitedDuringInspect = !i1.ContainsKey(pid);
            double inspectPct = 0.0;
            if (!exitedDuringInspect && i0.TryGetValue(pid, out var startInsp) && i1.TryGetValue(pid, out var endInsp))
            {
                var inspCpuMs = Math.Max(0.0, (endInsp.CpuTime - startInsp.CpuTime).TotalMilliseconds);
                inspectPct = Math.Clamp(inspCpuMs / inspectDenom * 100.0, 0.0, 100.0);
            }

            var exePath = QueryProcessImagePathFast(pid);
            var signed = !string.IsNullOrWhiteSpace(exePath) && AuthenticodeVerifier.IsFileTrustedSigned(exePath);

            samples.Add(new ProcessTelemetrySample(
                ProcessId: pid,
                ProcessName: endQuiet.Name,
                ExecutablePath: exePath,
                CommandLine: "",
                BaselineCpuPercent: Math.Round(baselinePct, 1),
                DuringInspectCpuPercent: Math.Round(inspectPct, 1),
                ExitedDuringInspect: exitedDuringInspect,
                IsAuthenticodeSigned: signed));
        }

        return samples;
    }

    private static Dictionary<int, (string Name, TimeSpan CpuTime)> SampleProcessCpuTimes()
    {
        var map = new Dictionary<int, (string Name, TimeSpan CpuTime)>();
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                if (p.Id > 4)
                {
                    map[p.Id] = (p.ProcessName, p.TotalProcessorTime);
                }
            }
            catch
            {
                // Системные защищенные процессы пропускаются без ошибок
            }
            finally
            {
                p.Dispose();
            }
        }

        return map;
    }

    private static void ScanTaskTreeForMissingSd(
        RegistryKey currentKey,
        string relativeTaskPath,
        int depth,
        List<PersistenceAnomalyRecord> sink,
        CancellationToken ct)
    {
        if (depth > 6) return;

        foreach (var childName in currentKey.GetSubKeyNames())
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var child = currentKey.OpenSubKey(childName, writable: false);
                if (child is null) continue;

                var taskPath = $"{relativeTaskPath}\\{childName}";
                var taskId = child.GetValue("Id")?.ToString();
                var sd = child.GetValue("SD");

                // Если у зарегистрированной задачи есть GUID Id, но намеренно стерт бинарный дескриптор SD — это скрытая задача!
                if (!string.IsNullOrWhiteSpace(taskId) && sd is null)
                {
                    sink.Add(new PersistenceAnomalyRecord(
                        Vector: ThreatDetectionVector.HiddenScheduledTask,
                        RegistryOrTaskPath: $@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree{taskPath}",
                        EntryName: taskPath,
                        PayloadCommandOrPath: $"TaskId={taskId} (отсутствует дескриптор безопасности SD)",
                        ReferencedExecutablePath: null,
                        IsMissingSecurityDescriptorSd: true,
                        PreviousValueSerialized: taskId));
                }

                ScanTaskTreeForMissingSd(child, taskPath, depth + 1, sink, ct);
            }
            catch
            {
                // Пропускаем закрытые ветки
            }
        }
    }

    private static void CheckPolicyIntLock(
        RegistryKey root,
        string hiveName,
        string subKeyPath,
        string valueName,
        OsSabotageKind kind,
        string title,
        string explanation,
        List<OsSabotageFinding> sink)
    {
        try
        {
            using var key = root.OpenSubKey(subKeyPath, writable: false);
            if (key?.GetValue(valueName) is int flag && flag != 0)
            {
                sink.Add(new OsSabotageFinding(
                    Kind: kind,
                    TargetDisplayPath: $@"{hiveName}\{subKeyPath} :: {valueName}",
                    Hive: hiveName,
                    SubKeyPath: subKeyPath,
                    ValueName: valueName,
                    CurrentMaliciousValue: flag.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    SimpleTitle: title,
                    SimpleExplanation: explanation));
            }
        }
        catch
        {
            // Пропускаем
        }
    }

    private static string QueryProcessImagePathFast(int pid)
    {
        var hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, bInheritHandle: false, (uint)pid);
        if (hProcess == IntPtr.Zero)
        {
            return "";
        }

        try
        {
            var sb = new StringBuilder(512);
            uint size = (uint)sb.Capacity;
            return QueryFullProcessImageNameW(hProcess, 0, sb, ref size) ? sb.ToString() : "";
        }
        finally
        {
            _ = CloseHandle(hProcess);
        }
    }

    /// <summary>
    /// Вспомогательное невидимое нулевое окно верхнего уровня с заголовком «Task Manager» для детекта прячущихся майнеров.
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

        public static DecoyInspectionWindow CreateHiddenDecoy() => new();

        private void WindowThreadLoop()
        {
            var hwnd = CreateWindowExW(
                WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
                "STATIC",
                "Task Manager",
                WS_POPUP,
                -32000, -32000, 1, 1,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

            _ready.Set();
            _stop.Wait(TimeSpan.FromSeconds(3));

            if (hwnd != IntPtr.Zero)
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

    // ==================== WIN32 P/INVOKE (KERNEL32 / IPHLPAPI / USER32) ====================
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint AF_INET = 2;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const uint WS_POPUP = 0x80000000;
    private const uint WS_EX_TOOLWINDOW = 0x00000080;
    private const uint WS_EX_NOACTIVATE = 0x08000000;

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

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageNameW(IntPtr hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("iphlpapi.dll", SetLastError = true, ExactSpelling = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref uint pdwSize,
        [MarshalAs(UnmanagedType.Bool)] bool sort,
        uint ulAf,
        int tableClass,
        uint reserved);

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
