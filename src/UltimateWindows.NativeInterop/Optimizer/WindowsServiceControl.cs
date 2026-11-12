using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using UltimateWindows.Modules.Cleaner.Utilities;
using UltimateWindows.Modules.Optimizer.Models;

namespace UltimateWindows.NativeInterop.Optimizer;

/// <summary>
/// Службы Windows через диспетчер управления службами (SCM): список, тип запуска, запуск и остановка.
/// Тип запуска меняется вызовом ChangeServiceConfig, а не правкой реестра: так изменение сразу видит сам диспетчер.
/// </summary>
public static class WindowsServiceControl
{
    private const uint SC_MANAGER_CONNECT = 0x0001;
    private const uint SC_MANAGER_ENUMERATE_SERVICE = 0x0004;

    private const uint SERVICE_QUERY_CONFIG = 0x0001;
    private const uint SERVICE_CHANGE_CONFIG = 0x0002;
    private const uint SERVICE_QUERY_STATUS = 0x0004;
    private const uint SERVICE_START = 0x0010;
    private const uint SERVICE_STOP = 0x0020;

    private const uint SERVICE_NO_CHANGE = 0xFFFFFFFF;
    private const uint SERVICE_WIN32 = 0x00000030;
    private const uint SERVICE_STATE_ALL = 0x00000003;
    private const int SC_ENUM_PROCESS_INFO = 0;
    private const int SC_STATUS_PROCESS_INFO = 0;

    private const uint SERVICE_CONFIG_DESCRIPTION = 1;
    private const uint SERVICE_CONFIG_DELAYED_AUTO_START_INFO = 3;
    private const uint SERVICE_CONTROL_STOP = 1;

    private const uint SERVICE_AUTO_START = 2;
    private const uint SERVICE_DEMAND_START = 3;
    private const uint SERVICE_DISABLED = 4;

    private const int ERROR_ACCESS_DENIED = 5;
    private const int ERROR_INSUFFICIENT_BUFFER = 122;
    private const int ERROR_MORE_DATA = 234;
    private const int ERROR_DEPENDENT_SERVICES_RUNNING = 1051;
    private const int ERROR_INVALID_SERVICE_CONTROL = 1052;
    private const int ERROR_SERVICE_ALREADY_RUNNING = 1056;
    private const int ERROR_SERVICE_DISABLED = 1058;
    private const int ERROR_SERVICE_DOES_NOT_EXIST = 1060;
    private const int ERROR_SERVICE_CANNOT_ACCEPT_CTRL = 1061;
    private const int ERROR_SERVICE_NOT_ACTIVE = 1062;
    private const int ERROR_SERVICE_MARKED_FOR_DELETE = 1072;

    private const uint EnumBufferBytes = 256 * 1024;

    /// <summary>
    /// Тип запуска службы, либо null, если службы нет или её настройки недоступны.
    /// </summary>
    public static ServiceConfigSnapshot? Query(string serviceName)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(serviceName))
        {
            return null;
        }

        var scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
        if (scm == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            var service = OpenServiceW(scm, serviceName, SERVICE_QUERY_CONFIG);
            if (service == IntPtr.Zero)
            {
                return null;
            }

            try
            {
                return TryReadConfig(service, out var config)
                    ? new ServiceConfigSnapshot(serviceName, ToStartupMode(config.StartType, ReadDelayedAutoStart(service)))
                    : null;
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(scm);
        }
    }

    public static ServiceRunState QueryRunState(string serviceName)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(serviceName))
        {
            return ServiceRunState.Unknown;
        }

        var scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
        if (scm == IntPtr.Zero)
        {
            return ServiceRunState.Unknown;
        }

        try
        {
            var service = OpenServiceW(scm, serviceName, SERVICE_QUERY_STATUS);
            if (service == IntPtr.Zero)
            {
                return ServiceRunState.Unknown;
            }

            try
            {
                return ReadState(service);
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(scm);
        }
    }

    public static PlatformActionResult SetStartup(string serviceName, ServiceStartupMode mode)
    {
        if (!OperatingSystem.IsWindows())
        {
            return PlatformActionResult.Fail("управление службами доступно только в Windows");
        }

        uint startType;
        switch (mode)
        {
            case ServiceStartupMode.Automatic:
            case ServiceStartupMode.AutomaticDelayed:
                startType = SERVICE_AUTO_START;
                break;
            case ServiceStartupMode.Manual:
                startType = SERVICE_DEMAND_START;
                break;
            case ServiceStartupMode.Disabled:
                startType = SERVICE_DISABLED;
                break;
            default:
                return PlatformActionResult.Fail("этот тип запуска относится к драйверам");
        }

        var scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
        if (scm == IntPtr.Zero)
        {
            return PlatformActionResult.Fail(DescribeError(Marshal.GetLastWin32Error()));
        }

        try
        {
            var service = OpenServiceW(scm, serviceName, SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG);
            if (service == IntPtr.Zero)
            {
                return PlatformActionResult.Fail(DescribeError(Marshal.GetLastWin32Error()));
            }

            try
            {
                if (!ChangeServiceConfigW(
                        service,
                        SERVICE_NO_CHANGE,
                        startType,
                        SERVICE_NO_CHANGE,
                        null,
                        null,
                        IntPtr.Zero,
                        null,
                        null,
                        null,
                        null))
                {
                    return PlatformActionResult.Fail(DescribeError(Marshal.GetLastWin32Error()));
                }

                if (startType == SERVICE_AUTO_START)
                {
                    var delayed = new SERVICE_DELAYED_AUTO_START_INFO { fDelayedAutostart = mode == ServiceStartupMode.AutomaticDelayed };
                    if (!ChangeServiceConfig2W(service, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, ref delayed) &&
                        mode == ServiceStartupMode.AutomaticDelayed)
                    {
                        // Некоторые службы отложенный запуск не поддерживают; обычный автоматический запуск уже установлен
                        return PlatformActionResult.Fail("служба не поддерживает отложенный запуск: " + DescribeError(Marshal.GetLastWin32Error()));
                    }
                }

                return PlatformActionResult.Ok;
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(scm);
        }
    }

    /// <summary>
    /// Запускает или останавливает службу и ждёт, пока она перейдёт в нужное состояние.
    /// </summary>
    public static Task<PlatformActionResult> ControlAsync(
        string serviceName,
        bool start,
        TimeSpan timeout,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult(PlatformActionResult.Fail("управление службами доступно только в Windows"));
        }

        return Task.Run(() => Control(serviceName, start, timeout, ct), ct);
    }

    private static PlatformActionResult Control(string serviceName, bool start, TimeSpan timeout, CancellationToken ct)
    {
        var scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
        if (scm == IntPtr.Zero)
        {
            return PlatformActionResult.Fail(DescribeError(Marshal.GetLastWin32Error()));
        }

        try
        {
            var service = OpenServiceW(scm, serviceName, SERVICE_QUERY_STATUS | (start ? SERVICE_START : SERVICE_STOP));
            if (service == IntPtr.Zero)
            {
                return PlatformActionResult.Fail(DescribeError(Marshal.GetLastWin32Error()));
            }

            try
            {
                if (start)
                {
                    if (!StartServiceW(service, 0, IntPtr.Zero))
                    {
                        var error = Marshal.GetLastWin32Error();
                        if (error != ERROR_SERVICE_ALREADY_RUNNING)
                        {
                            return PlatformActionResult.Fail(DescribeError(error));
                        }
                    }
                }
                else if (!ControlService(service, SERVICE_CONTROL_STOP, out _))
                {
                    var error = Marshal.GetLastWin32Error();
                    if (error != ERROR_SERVICE_NOT_ACTIVE)
                    {
                        return PlatformActionResult.Fail(DescribeError(error));
                    }
                }

                var target = start ? ServiceRunState.Running : ServiceRunState.Stopped;
                var watch = Stopwatch.StartNew();
                while (true)
                {
                    var state = ReadState(service);
                    if (state == target)
                    {
                        return PlatformActionResult.Ok;
                    }

                    // Служба, которая сразу вернулась в исходное состояние, уже не дойдёт до нужного
                    if (start && state == ServiceRunState.Stopped && watch.Elapsed > TimeSpan.FromSeconds(2))
                    {
                        return PlatformActionResult.Fail("служба запустилась и сразу остановилась");
                    }

                    if (watch.Elapsed > timeout)
                    {
                        return PlatformActionResult.Fail(start
                            ? "служба не успела запуститься за отведённое время"
                            : "служба не успела остановиться за отведённое время");
                    }

                    if (ct.WaitHandle.WaitOne(250))
                    {
                        return PlatformActionResult.Fail("операция отменена");
                    }
                }
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(scm);
        }
    }

    /// <summary>
    /// Все службы Windows (без драйверов) с типом запуска, состоянием, описанием и издателем исполняемого файла.
    /// </summary>
    public static IReadOnlyList<WindowsServiceInfo> List(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return [];
        }

        var scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
        if (scm == IntPtr.Zero)
        {
            return [];
        }

        try
        {
            var result = new List<WindowsServiceInfo>();
            var publishers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            foreach (var (name, displayName, state) in Enumerate(scm))
            {
                ct.ThrowIfCancellationRequested();

                var startup = ServiceStartupMode.Manual;
                var binaryPath = "";
                var account = "";
                var description = "";

                var service = OpenServiceW(scm, name, SERVICE_QUERY_CONFIG);
                if (service != IntPtr.Zero)
                {
                    try
                    {
                        if (TryReadConfig(service, out var config))
                        {
                            startup = ToStartupMode(config.StartType, ReadDelayedAutoStart(service));
                            binaryPath = config.BinaryPath;
                            account = config.Account;
                        }

                        description = ReadDescription(service);
                    }
                    finally
                    {
                        CloseServiceHandle(service);
                    }
                }

                var publisher = ResolvePublisher(name, binaryPath, publishers);
                result.Add(new WindowsServiceInfo(
                    name,
                    string.IsNullOrWhiteSpace(displayName) ? name : displayName,
                    description,
                    startup,
                    state,
                    binaryPath,
                    publisher,
                    IsMicrosoft: publisher.Contains("Microsoft", StringComparison.OrdinalIgnoreCase),
                    account));
            }

            return result
                .OrderBy(s => s.DisplayName, StringComparer.CurrentCultureIgnoreCase)
                .ToList();
        }
        finally
        {
            CloseServiceHandle(scm);
        }
    }

    private static List<(string Name, string DisplayName, ServiceRunState State)> Enumerate(IntPtr scm)
    {
        var items = new List<(string, string, ServiceRunState)>();
        var itemSize = Marshal.SizeOf<ENUM_SERVICE_STATUS_PROCESSW>();
        var buffer = Marshal.AllocHGlobal((int)EnumBufferBytes);
        try
        {
            uint resume = 0;
            while (true)
            {
                var complete = EnumServicesStatusExW(
                    scm,
                    SC_ENUM_PROCESS_INFO,
                    SERVICE_WIN32,
                    SERVICE_STATE_ALL,
                    buffer,
                    EnumBufferBytes,
                    out _,
                    out var returned,
                    ref resume,
                    null);

                if (!complete && Marshal.GetLastWin32Error() != ERROR_MORE_DATA)
                {
                    break;
                }

                for (var i = 0; i < returned; i++)
                {
                    var entry = Marshal.PtrToStructure<ENUM_SERVICE_STATUS_PROCESSW>(buffer + (i * itemSize));
                    var name = PtrToString(entry.lpServiceName);
                    if (name.Length == 0)
                    {
                        continue;
                    }

                    items.Add((name, PtrToString(entry.lpDisplayName), ToRunState(entry.ServiceStatusProcess.dwCurrentState)));
                }

                if (complete)
                {
                    break;
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return items;
    }

    private readonly record struct ServiceConfig(uint StartType, string BinaryPath, string Account);

    private static bool TryReadConfig(IntPtr service, out ServiceConfig config)
    {
        config = default;
        QueryServiceConfigW(service, IntPtr.Zero, 0, out var needed);
        if (needed == 0 || Marshal.GetLastWin32Error() != ERROR_INSUFFICIENT_BUFFER)
        {
            return false;
        }

        var buffer = Marshal.AllocHGlobal((int)needed);
        try
        {
            if (!QueryServiceConfigW(service, buffer, needed, out _))
            {
                return false;
            }

            // Строки структуры лежат в том же буфере, поэтому читаем их до его освобождения
            var raw = Marshal.PtrToStructure<QUERY_SERVICE_CONFIGW>(buffer);
            config = new ServiceConfig(raw.dwStartType, PtrToString(raw.lpBinaryPathName), PtrToString(raw.lpServiceStartName));
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static bool ReadDelayedAutoStart(IntPtr service)
    {
        var buffer = Marshal.AllocHGlobal(sizeof(int));
        try
        {
            return QueryServiceConfig2W(service, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, buffer, sizeof(int), out _) &&
                   Marshal.ReadInt32(buffer) != 0;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static string ReadDescription(IntPtr service)
    {
        QueryServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, IntPtr.Zero, 0, out var needed);
        if (needed == 0 || needed > 64 * 1024)
        {
            return "";
        }

        var buffer = Marshal.AllocHGlobal((int)needed);
        try
        {
            if (!QueryServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, buffer, needed, out _))
            {
                return "";
            }

            return PtrToString(Marshal.ReadIntPtr(buffer));
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static ServiceRunState ReadState(IntPtr service) =>
        QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, out var status, (uint)Marshal.SizeOf<SERVICE_STATUS_PROCESS>(), out _)
            ? ToRunState(status.dwCurrentState)
            : ServiceRunState.Unknown;

    private static string ResolvePublisher(string serviceName, string binaryPath, Dictionary<string, string> cache)
    {
        try
        {
            var file = ResolveServiceFile(serviceName, binaryPath);
            if (string.IsNullOrWhiteSpace(file))
            {
                return "";
            }

            if (cache.TryGetValue(file, out var known))
            {
                return known;
            }

            var publisher = File.Exists(file)
                ? FileVersionInfo.GetVersionInfo(file).CompanyName?.Trim() ?? ""
                : "";
            cache[file] = publisher;
            return publisher;
        }
        catch (Exception)
        {
            return "";
        }
    }

    /// <summary>
    /// Файл, в котором на самом деле живёт служба: для служб внутри svchost.exe это библиотека из параметра ServiceDll.
    /// </summary>
    private static string? ResolveServiceFile(string serviceName, string binaryPath)
    {
        if (binaryPath.Contains("svchost.exe", StringComparison.OrdinalIgnoreCase))
        {
            using var parameters = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}\Parameters");
            var dll = parameters?.GetValue("ServiceDll")?.ToString();
            if (string.IsNullOrWhiteSpace(dll))
            {
                using var root = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}");
                dll = root?.GetValue("ServiceDll")?.ToString();
            }

            if (!string.IsNullOrWhiteSpace(dll))
            {
                return Environment.ExpandEnvironmentVariables(dll.Trim().Trim('"'));
            }
        }

        return CommandLinePathExtractor.TryExtractLocalExecutablePath(binaryPath);
    }

    private static ServiceStartupMode ToStartupMode(uint startType, bool delayed) => startType switch
    {
        0 => ServiceStartupMode.Boot,
        1 => ServiceStartupMode.System,
        SERVICE_AUTO_START => delayed ? ServiceStartupMode.AutomaticDelayed : ServiceStartupMode.Automatic,
        SERVICE_DEMAND_START => ServiceStartupMode.Manual,
        _ => ServiceStartupMode.Disabled
    };

    private static ServiceRunState ToRunState(uint state) => state is >= 1 and <= 7
        ? (ServiceRunState)state
        : ServiceRunState.Unknown;

    private static string PtrToString(IntPtr pointer) =>
        pointer == IntPtr.Zero ? "" : Marshal.PtrToStringUni(pointer) ?? "";

    private static string DescribeError(int error) => error switch
    {
        ERROR_ACCESS_DENIED => "отказано в доступе (служба защищена Windows)",
        ERROR_SERVICE_DOES_NOT_EXIST => "служба не установлена",
        ERROR_SERVICE_MARKED_FOR_DELETE => "служба помечена для удаления",
        ERROR_SERVICE_DISABLED => "служба отключена — сначала измените тип запуска",
        ERROR_DEPENDENT_SERVICES_RUNNING => "от этой службы зависят другие работающие службы",
        ERROR_INVALID_SERVICE_CONTROL or ERROR_SERVICE_CANNOT_ACCEPT_CTRL => "служба не принимает команду остановки",
        _ => $"{new Win32Exception(error).Message} (код {error})"
    };

    [StructLayout(LayoutKind.Sequential)]
    private struct QUERY_SERVICE_CONFIGW
    {
        public uint dwServiceType;
        public uint dwStartType;
        public uint dwErrorControl;
        public IntPtr lpBinaryPathName;
        public IntPtr lpLoadOrderGroup;
        public uint dwTagId;
        public IntPtr lpDependencies;
        public IntPtr lpServiceStartName;
        public IntPtr lpDisplayName;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS_PROCESS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
        public uint dwProcessId;
        public uint dwServiceFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ENUM_SERVICE_STATUS_PROCESSW
    {
        public IntPtr lpServiceName;
        public IntPtr lpDisplayName;
        public SERVICE_STATUS_PROCESS ServiceStatusProcess;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_DELAYED_AUTO_START_INFO
    {
        [MarshalAs(UnmanagedType.Bool)]
        public bool fDelayedAutostart;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr OpenSCManagerW(string? lpMachineName, string? lpDatabaseName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr OpenServiceW(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr hSCObject);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceConfigW(IntPtr hService, IntPtr lpServiceConfig, uint cbBufSize, out uint pcbBytesNeeded);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceConfig2W(IntPtr hService, uint dwInfoLevel, IntPtr lpBuffer, uint cbBufSize, out uint pcbBytesNeeded);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChangeServiceConfigW(
        IntPtr hService,
        uint dwServiceType,
        uint dwStartType,
        uint dwErrorControl,
        string? lpBinaryPathName,
        string? lpLoadOrderGroup,
        IntPtr lpdwTagId,
        string? lpDependencies,
        string? lpServiceStartName,
        string? lpPassword,
        string? lpDisplayName);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChangeServiceConfig2W(IntPtr hService, uint dwInfoLevel, ref SERVICE_DELAYED_AUTO_START_INFO lpInfo);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumServicesStatusExW(
        IntPtr hSCManager,
        int InfoLevel,
        uint dwServiceType,
        uint dwServiceState,
        IntPtr lpServices,
        uint cbBufSize,
        out uint pcbBytesNeeded,
        out uint lpServicesReturned,
        ref uint lpResumeHandle,
        string? pszGroupName);

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(
        IntPtr hService,
        int InfoLevel,
        out SERVICE_STATUS_PROCESS lpBuffer,
        uint cbBufSize,
        out uint pcbBytesNeeded);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool StartServiceW(IntPtr hService, uint dwNumServiceArgs, IntPtr lpServiceArgVectors);

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ControlService(IntPtr hService, uint dwControl, out SERVICE_STATUS lpServiceStatus);
}
