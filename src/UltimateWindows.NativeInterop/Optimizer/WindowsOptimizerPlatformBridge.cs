using System.Diagnostics;
using System.Globalization;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text.Json;
using Microsoft.Win32;
using UltimateWindows.Modules.Cleaner.Utilities;
using UltimateWindows.Modules.Optimizer.Models;
using UltimateWindows.Modules.Optimizer.Services;
using UltimateWindows.NativeInterop.Security;

namespace UltimateWindows.NativeInterop.Optimizer;

/// <summary>
/// Полноценный нативный мост Фазы 4 для Windows 10/11:
/// безопасное чтение/запись реестра твиков, управление StartupApproved и политикой Shell Extensions\Blocked,
/// детектор занятых файлов через Restart Manager (RM_PROCESS_INFO), переключение DNS и список программ.
/// </summary>
public sealed class WindowsOptimizerPlatformBridge : DefaultOptimizerPlatformBridge
{
    private const string StartupApprovedRunSubKey = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
    private const string ShellBlockedSubKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked";

    public override bool IsRunningAsAdministrator() => ElevationChecker.IsRunningAsAdministrator();

    public override (bool Exists, int ValueKindCode, string? SerializedValue) ReadRegistryValue(
        string hive,
        string subKeyPath,
        string valueName)
    {
        if (!OperatingSystem.IsWindows())
        {
            return (false, (int)RegistryValueKind.String, null);
        }

        try
        {
            using var baseKey = OpenHive(hive);
            using var subKey = baseKey.OpenSubKey(subKeyPath, writable: false);
            if (subKey is null)
            {
                return (false, (int)RegistryValueKind.String, null);
            }

            var raw = subKey.GetValue(valueName, defaultValue: null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            if (raw is null)
            {
                return (false, (int)RegistryValueKind.String, null);
            }

            var kind = subKey.GetValueKind(valueName);
            var serialized = kind switch
            {
                RegistryValueKind.DWord => Convert.ToInt32(raw, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture),
                RegistryValueKind.QWord => Convert.ToInt64(raw, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture),
                RegistryValueKind.Binary when raw is byte[] b => Convert.ToBase64String(b),
                RegistryValueKind.MultiString when raw is string[] arr => JsonSerializer.Serialize(arr),
                _ => raw.ToString() ?? ""
            };

            return (true, (int)kind, serialized);
        }
        catch
        {
            return (false, (int)RegistryValueKind.String, null);
        }
    }

    public override bool WriteRegistryValue(
        string hive,
        string subKeyPath,
        string valueName,
        RegistryTweakValueKind kind,
        string serializedValue)
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            using var baseKey = OpenHive(hive);
            if (kind == RegistryTweakValueKind.DeleteValue)
            {
                using var openKey = baseKey.OpenSubKey(subKeyPath, writable: true);
                openKey?.DeleteValue(valueName, throwOnMissingValue: false);
                return true;
            }

            using var writableKey = baseKey.CreateSubKey(subKeyPath, writable: true);
            if (writableKey is null)
            {
                return false;
            }

            switch (kind)
            {
                case RegistryTweakValueKind.DWord:
                    writableKey.SetValue(valueName, int.Parse(serializedValue, CultureInfo.InvariantCulture), RegistryValueKind.DWord);
                    break;
                case RegistryTweakValueKind.BinaryHex:
                    writableKey.SetValue(valueName, Convert.FromBase64String(serializedValue), RegistryValueKind.Binary);
                    break;
                default:
                    writableKey.SetValue(valueName, serializedValue, RegistryValueKind.String);
                    break;
            }

            return true;
        }
        catch
        {
            return false;
        }
    }

    public override Task<IReadOnlyList<StartupEntryInfo>> GetStartupEntriesAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult<IReadOnlyList<StartupEntryInfo>>(Array.Empty<StartupEntryInfo>());
        }

        return Task.Run<IReadOnlyList<StartupEntryInfo>>(() =>
        {
            var list = new List<StartupEntryInfo>();
            CollectRegistryRunScope(Registry.CurrentUser, "HKCU (Текущий пользователь)", requiresAdmin: false, list, ct);
            CollectRegistryRunScope(Registry.LocalMachine, "HKLM (Все пользователи)", requiresAdmin: true, list, ct);
            return list.OrderByDescending(x => x.IsEnabled).ThenBy(x => x.DisplayName, StringComparer.OrdinalIgnoreCase).ToList();
        }, ct);
    }

    public override Task<(bool Succeeded, string PreviousStartupApprovedBase64)> SetStartupEntryEnabledAsync(
        StartupEntryInfo entry,
        bool enabled,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult((false, ""));
        }

        return Task.Run(() =>
        {
            try
            {
                var root = entry.RequiresAdminToToggle ? Registry.LocalMachine : Registry.CurrentUser;
                using var key = root.CreateSubKey(StartupApprovedRunSubKey, writable: true);
                if (key is null)
                {
                    return (false, "");
                }

                var prevBytes = key.GetValue(entry.DisplayName) as byte[];
                var prevBase64 = prevBytes is not null ? Convert.ToBase64String(prevBytes) : "";

                // Штатный 12-байтный формат Диспетчера задач Windows: 0x02 = Включено, 0x03 + FILETIME = Отключено
                var nextBytes = new byte[12];
                if (enabled)
                {
                    nextBytes[0] = 0x02;
                }
                else
                {
                    nextBytes[0] = 0x03;
                    var ft = DateTime.UtcNow.ToFileTimeUtc();
                    BitConverter.GetBytes(ft).CopyTo(nextBytes, 4);
                }

                key.SetValue(entry.DisplayName, nextBytes, RegistryValueKind.Binary);
                return (true, prevBase64);
            }
            catch
            {
                return (false, "");
            }
        }, ct);
    }

    public override Task<IReadOnlyList<ShellContextMenuHandlerInfo>> GetThirdPartyShellExtensionsAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult<IReadOnlyList<ShellContextMenuHandlerInfo>>(Array.Empty<ShellContextMenuHandlerInfo>());
        }

        return Task.Run<IReadOnlyList<ShellContextMenuHandlerInfo>>(() =>
        {
            var blockedSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using var blockedKey = Registry.LocalMachine.OpenSubKey(ShellBlockedSubKey, writable: false);
                if (blockedKey is not null)
                {
                    foreach (var v in blockedKey.GetValueNames())
                    {
                        blockedSet.Add(v.Trim());
                    }
                }
            }
            catch
            {
                // Игнорируем
            }

            var scopes = new (string Label, string SubKey)[]
            {
                ("Все файлы (*)", @"*\shellex\ContextMenuHandlers"),
                ("Папки", @"Directory\shellex\ContextMenuHandlers"),
                ("Фон рабочего стола / папки", @"Directory\Background\shellex\ContextMenuHandlers")
            };

            var winSysPrefix = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var seenClsids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var results = new List<ShellContextMenuHandlerInfo>();

            foreach (var (scopeLabel, subKeyPath) in scopes)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var handlersKey = Registry.ClassesRoot.OpenSubKey(subKeyPath, writable: false);
                    if (handlersKey is null) continue;

                    foreach (var handlerSubName in handlersKey.GetSubKeyNames())
                    {
                        using var hKey = handlersKey.OpenSubKey(handlerSubName, writable: false);
                        var defaultVal = hKey?.GetValue("")?.ToString()?.Trim();
                        var clsid = (handlerSubName.StartsWith('{') ? handlerSubName : defaultVal) ?? "";

                        if (!clsid.StartsWith('{') || !clsid.EndsWith('}') || !seenClsids.Add(clsid))
                        {
                            continue;
                        }

                        var dllPath = ResolveClsidInprocDll(clsid);
                        var isBuiltInMs = !string.IsNullOrWhiteSpace(dllPath) &&
                                          !string.IsNullOrWhiteSpace(winSysPrefix) &&
                                          dllPath.StartsWith(winSysPrefix, StringComparison.OrdinalIgnoreCase);

                        // Показываем именно сторонние расширения, которые чаще всего замедляют правый клик
                        if (isBuiltInMs)
                        {
                            continue;
                        }

                        var signed = !string.IsNullOrWhiteSpace(dllPath) && AuthenticodeVerifier.IsFileTrustedSigned(dllPath);
                        results.Add(new ShellContextMenuHandlerInfo(
                            Clsid: clsid,
                            HandlerName: handlerSubName.StartsWith('{') ? Path.GetFileNameWithoutExtension(dllPath ?? clsid) : handlerSubName,
                            TargetScope: scopeLabel,
                            DllPath: dllPath,
                            IsMicrosoftBuiltIn: false,
                            IsSignedTrusted: signed,
                            IsBlockedByPolicy: blockedSet.Contains(clsid)));
                    }
                }
                catch
                {
                    // Пропускаем недоступные ветки
                }
            }

            return results;
        }, ct);
    }

    public override Task<bool> SetShellExtensionBlockedAsync(
        string clsid,
        string handlerName,
        bool blocked,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult(false);
        }

        return Task.Run(() =>
        {
            try
            {
                using var key = Registry.LocalMachine.CreateSubKey(ShellBlockedSubKey, writable: true);
                if (key is null) return false;

                if (blocked)
                {
                    key.SetValue(clsid, $"Blocked by UltimateWindows ({handlerName})", RegistryValueKind.String);
                }
                else
                {
                    key.DeleteValue(clsid, throwOnMissingValue: false);
                }

                return true;
            }
            catch
            {
                return false;
            }
        }, ct);
    }

    public override Task<IReadOnlyList<LockingProcessInfo>> FindLockingProcessesAsync(
        string fileOrDirectoryPath,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(fileOrDirectoryPath))
        {
            return Task.FromResult<IReadOnlyList<LockingProcessInfo>>(Array.Empty<LockingProcessInfo>());
        }

        return Task.Run<IReadOnlyList<LockingProcessInfo>>(() =>
        {
            var fullTarget = Path.GetFullPath(fileOrDirectoryPath);
            string[] resources;

            if (File.Exists(fullTarget))
            {
                resources = [fullTarget];
            }
            else if (Directory.Exists(fullTarget))
            {
                resources = Directory.EnumerateFiles(fullTarget, "*", new EnumerationOptions
                {
                    IgnoreInaccessible = true,
                    RecurseSubdirectories = true,
                    AttributesToSkip = FileAttributes.ReparsePoint
                }).Take(64).ToArray();

                if (resources.Length == 0)
                {
                    return Array.Empty<LockingProcessInfo>();
                }
            }
            else
            {
                return Array.Empty<LockingProcessInfo>();
            }

            var sessionKey = Guid.NewGuid().ToString("N");
            if (RmStartSession(out var sessionHandle, 0, sessionKey) != 0)
            {
                return Array.Empty<LockingProcessInfo>();
            }

            try
            {
                if (RmRegisterResources(sessionHandle, (uint)resources.Length, resources, 0, IntPtr.Zero, 0, null) != 0)
                {
                    return Array.Empty<LockingProcessInfo>();
                }

                uint procInfoNeeded = 0;
                uint procInfoCount = 0;
                uint rebootReasons = 0;

                var res = RmGetList(sessionHandle, out procInfoNeeded, ref procInfoCount, null, ref rebootReasons);
                if (res != ERROR_MORE_DATA || procInfoNeeded == 0)
                {
                    return Array.Empty<LockingProcessInfo>();
                }

                procInfoCount = procInfoNeeded + 4;
                var rawInfos = new RM_PROCESS_INFO[procInfoCount];
                res = RmGetList(sessionHandle, out procInfoNeeded, ref procInfoCount, rawInfos, ref rebootReasons);
                if (res != 0)
                {
                    return Array.Empty<LockingProcessInfo>();
                }

                var result = new List<LockingProcessInfo>((int)procInfoCount);
                for (int i = 0; i < procInfoCount; i++)
                {
                    var item = rawInfos[i];
                    var pid = item.Process.dwProcessId;
                    var exePath = TryGetProcessExecutablePath(pid);
                    var appName = !string.IsNullOrWhiteSpace(item.strAppName)
                        ? item.strAppName
                        : Path.GetFileName(exePath);

                    var isCritical = item.ApplicationType == RM_APP_TYPE.RmCritical || pid <= 4;
                    var kindLabel = item.ApplicationType switch
                    {
                        RM_APP_TYPE.RmService => $"Служба Windows ({item.strServiceShortName})",
                        RM_APP_TYPE.RmExplorer => "Проводник Windows (Explorer)",
                        RM_APP_TYPE.RmConsole => "Консольное приложение",
                        RM_APP_TYPE.RmCritical => "Критический процесс ядра ОС",
                        _ => "Обычное приложение"
                    };

                    result.Add(new LockingProcessInfo(
                        ProcessId: pid,
                        ApplicationName: string.IsNullOrWhiteSpace(appName) ? $"Process {pid}" : appName,
                        ExecutablePath: exePath,
                        ProcessKindLabel: kindLabel,
                        IsCriticalSystemProcess: isCritical));
                }

                return result;
            }
            finally
            {
                _ = RmEndSession(sessionHandle);
            }
        }, ct);
    }

    public override async Task<bool> TryPoliteCloseProcessAsync(int processId, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows() || processId <= 4)
        {
            return false;
        }

        try
        {
            using var proc = Process.GetProcessById(processId);
            if (proc.HasExited)
            {
                return true;
            }

            // Вежливое закрытие главного окна (чтобы Word/редактор предложил сохранить работу и не потерял данные!)
            if (proc.CloseMainWindow())
            {
                using var waitCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                waitCts.CancelAfter(TimeSpan.FromMilliseconds(2500));
                try
                {
                    await proc.WaitForExitAsync(waitCts.Token).ConfigureAwait(false);
                    return proc.HasExited;
                }
                catch (OperationCanceledException)
                {
                    return proc.HasExited;
                }
            }
        }
        catch
        {
            // Игнорируем системные ограничения
        }

        return false;
    }

    public override async Task<(bool Succeeded, string AdapterName, string PreviousDnsStateJson)> ApplyDnsPresetAsync(
        DnsPresetDescriptor preset,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return (false, "", "");
        }

        var activeNic = NetworkInterface.GetAllNetworkInterfaces()
            .FirstOrDefault(n =>
                n.OperationalStatus == OperationalStatus.Up &&
                n.NetworkInterfaceType is not NetworkInterfaceType.Loopback and not NetworkInterfaceType.Tunnel &&
                n.GetIPProperties().GatewayAddresses.Count > 0);

        if (activeNic is null)
        {
            return (false, "", "");
        }

        var prevDns = activeNic.GetIPProperties().DnsAddresses
            .Where(ip => ip.AddressFamily == AddressFamily.InterNetwork)
            .Select(ip => ip.ToString())
            .ToArray();

        var prevStateJson = JsonSerializer.Serialize(new
        {
            AdapterName = activeNic.Name,
            PreviousIpv4Dns = prevDns
        });

        var ok = await SetAdapterIpv4DnsInternalAsync(
            activeNic.Name,
            preset.Id == DnsPresetId.AutomaticDhcp ? [] : [preset.PrimaryIpv4, preset.SecondaryIpv4],
            ct).ConfigureAwait(false);

        return (ok, activeNic.Name, prevStateJson);
    }

    public static async Task<bool> RestoreDnsSnapshotJsonAsync(string previousStateJson, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(previousStateJson))
        {
            return false;
        }

        using var doc = JsonDocument.Parse(previousStateJson);
        var adapter = doc.RootElement.TryGetProperty("AdapterName", out var aEl) ? aEl.GetString() : null;
        if (string.IsNullOrWhiteSpace(adapter))
        {
            return false;
        }

        var servers = new List<string>();
        if (doc.RootElement.TryGetProperty("PreviousIpv4Dns", out var arrEl) && arrEl.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in arrEl.EnumerateArray())
            {
                var s = item.GetString();
                if (!string.IsNullOrWhiteSpace(s))
                {
                    servers.Add(s);
                }
            }
        }

        return await SetAdapterIpv4DnsInternalAsync(adapter, servers, ct).ConfigureAwait(false);
    }

    public override Task<IReadOnlyList<InstalledApplicationInfo>> GetInstalledApplicationsAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult<IReadOnlyList<InstalledApplicationInfo>>(Array.Empty<InstalledApplicationInfo>());
        }

        return Task.Run<IReadOnlyList<InstalledApplicationInfo>>(() =>
        {
            var apps = new List<InstalledApplicationInfo>();
            var seenNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            var roots = new (RegistryKey Root, string Prefix, string SubKey)[]
            {
                (Registry.LocalMachine, "HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                (Registry.LocalMachine, "HKLM", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                (Registry.CurrentUser, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\Uninstall")
            };

            foreach (var (root, prefix, subPath) in roots)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var baseKey = root.OpenSubKey(subPath, writable: false);
                    if (baseKey is null) continue;

                    foreach (var childName in baseKey.GetSubKeyNames())
                    {
                        using var appKey = baseKey.OpenSubKey(childName, writable: false);
                        if (appKey is null) continue;

                        if (appKey.GetValue("SystemComponent") is int sysComp && sysComp == 1)
                        {
                            continue;
                        }

                        var displayName = appKey.GetValue("DisplayName")?.ToString()?.Trim();
                        if (string.IsNullOrWhiteSpace(displayName) || !seenNames.Add(displayName))
                        {
                            continue;
                        }

                        var version = appKey.GetValue("DisplayVersion")?.ToString()?.Trim() ?? "";
                        var publisher = appKey.GetValue("Publisher")?.ToString()?.Trim() ?? "Неизвестный издатель";
                        var installLoc = appKey.GetValue("InstallLocation")?.ToString()?.Trim();
                        var uninstallCmd = appKey.GetValue("UninstallString")?.ToString()?.Trim();
                        long sizeBytes = 0;
                        if (appKey.GetValue("EstimatedSize") is int kb && kb > 0)
                        {
                            sizeBytes = (long)kb * 1024L;
                        }

                        apps.Add(new InstalledApplicationInfo(
                            RegistryKeyPath: $@"{prefix}\{subPath}\{childName}",
                            DisplayName: displayName,
                            DisplayVersion: version,
                            Publisher: publisher,
                            InstallLocation: installLoc,
                            UninstallString: uninstallCmd,
                            EstimatedSizeBytes: sizeBytes));
                    }
                }
                catch
                {
                    // Безопасный пропуск
                }
            }

            return apps.OrderBy(a => a.DisplayName, StringComparer.OrdinalIgnoreCase).ToList();
        }, ct);
    }

    private static async Task<bool> SetAdapterIpv4DnsInternalAsync(
        string adapterName,
        IReadOnlyList<string> ipv4Servers,
        CancellationToken ct)
    {
        var validServers = ipv4Servers.Where(s => !string.IsNullOrWhiteSpace(s)).ToArray();
        if (validServers.Length == 0)
        {
            return await RunNetshAsync(["interface", "ipv4", "set", "dnsservers", $"name={adapterName}", "source=dhcp"], ct).ConfigureAwait(false);
        }

        var okPrimary = await RunNetshAsync(
            ["interface", "ipv4", "set", "dnsservers", $"name={adapterName}", "static", validServers[0], "primary"],
            ct).ConfigureAwait(false);

        if (okPrimary && validServers.Length > 1)
        {
            _ = await RunNetshAsync(
                ["interface", "ipv4", "add", "dnsservers", $"name={adapterName}", validServers[1], "index=2"],
                ct).ConfigureAwait(false);
        }

        return okPrimary;
    }

    private static async Task<bool> RunNetshAsync(IReadOnlyList<string> args, CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "netsh.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        foreach (var a in args)
        {
            psi.ArgumentList.Add(a);
        }

        try
        {
            using var proc = Process.Start(psi);
            if (proc is null) return false;
            await proc.WaitForExitAsync(ct).ConfigureAwait(false);
            return proc.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    private static void CollectRegistryRunScope(
        RegistryKey root,
        string scopeLabel,
        bool requiresAdmin,
        List<StartupEntryInfo> sink,
        CancellationToken ct)
    {
        const string runSubKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
        try
        {
            var disabledNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            using (var approvedKey = root.OpenSubKey(StartupApprovedRunSubKey, writable: false))
            {
                if (approvedKey is not null)
                {
                    foreach (var vName in approvedKey.GetValueNames())
                    {
                        if (approvedKey.GetValue(vName) is byte[] bytes && bytes.Length >= 1 && (bytes[0] == 0x03 || bytes[0] == 0x01))
                        {
                            disabledNames.Add(vName);
                        }
                    }
                }
            }

            using var runKey = root.OpenSubKey(runSubKey, writable: false);
            if (runKey is null) return;

            foreach (var name in runKey.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                if (string.IsNullOrWhiteSpace(name)) continue;

                var cmd = runKey.GetValue(name)?.ToString() ?? "";
                if (string.IsNullOrWhiteSpace(cmd)) continue;

                var exePath = CommandLinePathExtractor.TryExtractLocalExecutablePath(cmd);
                var isSigned = !string.IsNullOrWhiteSpace(exePath) && AuthenticodeVerifier.IsFileTrustedSigned(exePath);

                sink.Add(new StartupEntryInfo(
                    EntryId: $"{scopeLabel}::{name}",
                    DisplayName: name,
                    CommandOrTarget: cmd,
                    ResolvedExecutablePath: exePath,
                    LocationSource: scopeLabel,
                    IsEnabled: !disabledNames.Contains(name),
                    IsSignedTrusted: isSigned,
                    RequiresAdminToToggle: requiresAdmin));
            }
        }
        catch
        {
            // Пропускаем при отсутствии прав
        }
    }

    private static string? ResolveClsidInprocDll(string clsid)
    {
        try
        {
            using var key = Registry.ClassesRoot.OpenSubKey($@"CLSID\{clsid}\InprocServer32", writable: false);
            var raw = key?.GetValue("")?.ToString();
            if (string.IsNullOrWhiteSpace(raw)) return null;
            return Environment.ExpandEnvironmentVariables(raw.Trim().Trim('"'));
        }
        catch
        {
            return null;
        }
    }

    private static string TryGetProcessExecutablePath(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.MainModule?.FileName ?? "";
        }
        catch
        {
            return "";
        }
    }

    private static RegistryKey OpenHive(string hive) => hive.ToUpperInvariant() switch
    {
        "HKLM" or "HKEY_LOCAL_MACHINE" => RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default),
        "HKCR" or "HKEY_CLASSES_ROOT" => RegistryKey.OpenBaseKey(RegistryHive.ClassesRoot, RegistryView.Default),
        "HKU" or "HKEY_USERS" => RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default),
        _ => RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default)
    };

    // ==================== WIN32 RESTART MANAGER P/INVOKE ====================
    private const int ERROR_MORE_DATA = 234;
    private const int CCH_RM_MAX_APP_NAME = 255;
    private const int CCH_RM_MAX_SVC_NAME = 63;

    private enum RM_APP_TYPE
    {
        RmUnknownApp = 0,
        RmMainWindow = 1,
        RmOtherWindow = 2,
        RmService = 3,
        RmExplorer = 4,
        RmConsole = 5,
        RmCritical = 1000
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RM_UNIQUE_PROCESS
    {
        public int dwProcessId;
        public FILETIME ProcessStartTime;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct RM_PROCESS_INFO
    {
        public RM_UNIQUE_PROCESS Process;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_APP_NAME + 1)]
        public string strAppName;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_SVC_NAME + 1)]
        public string strServiceShortName;

        public RM_APP_TYPE ApplicationType;
        public uint AppStatus;
        public uint TSSessionId;

        [MarshalAs(UnmanagedType.Bool)]
        public bool bRestartable;
    }

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, string strSessionKey);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int RmRegisterResources(
        uint dwSessionHandle,
        uint nFiles,
        string[]? rgsFilenames,
        uint nApplications,
        IntPtr rgApplications,
        uint nServices,
        string[]? rgsServiceNames);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int RmGetList(
        uint dwSessionHandle,
        out uint pnProcInfoNeeded,
        ref uint pnProcInfo,
        [In, Out] RM_PROCESS_INFO[]? rgAffectedApps,
        ref uint lpdwRebootReasons);

    [DllImport("rstrtmgr.dll", ExactSpelling = true)]
    private static extern int RmEndSession(uint dwSessionHandle);
}
