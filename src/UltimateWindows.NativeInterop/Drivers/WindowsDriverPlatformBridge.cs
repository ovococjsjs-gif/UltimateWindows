using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using UltimateWindows.Modules.Drivers.Analyzers;
using UltimateWindows.Modules.Drivers.Models;
using UltimateWindows.Modules.Drivers.Services;
using UltimateWindows.NativeInterop.Security;

namespace UltimateWindows.NativeInterop.Drivers;

/// <summary>
/// Нативный мост Фазы 6 для Windows 10/11:
/// опрос дерева устройств через CfgMgr32.dll (без медленного WMI Win32_PnPEntity!),
/// поиск и установка подписанных WHQL-драйверов через штатный COM-клиент Windows Update (Microsoft.Update.Session)
/// и селективный экспорт одиночного oemXX.inf через pnputil.exe.
/// </summary>
public sealed class WindowsDriverPlatformBridge : DefaultDriverPlatformBridge
{
    private const int CR_SUCCESS = 0x00000000;
    private const int CM_LOCATE_DEVNODE_NORMAL = 0x00000000;
    private const uint DN_HAS_PROBLEM = 0x00000400;

    private const uint CM_DRP_DEVICEDESC = 0x00000001;
    private const uint CM_DRP_HARDWAREID = 0x00000002;
    private const uint CM_DRP_CLASS = 0x00000008;
    private const uint CM_DRP_DRIVER = 0x0000000A;
    private const uint CM_DRP_MFG = 0x0000000C;
    private const uint CM_DRP_FRIENDLYNAME = 0x0000000D;

    public override bool IsRunningAsAdministrator() => ElevationChecker.IsRunningAsAdministrator();

    public override Task<IReadOnlyList<SystemDeviceNode>> EnumerateDevicesAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult<IReadOnlyList<SystemDeviceNode>>(Array.Empty<SystemDeviceNode>());
        }

        return Task.Run<IReadOnlyList<SystemDeviceNode>>(() =>
        {
            var results = new List<SystemDeviceNode>();
            if (CM_Locate_DevNodeW(out var rootDevInst, null, CM_LOCATE_DEVNODE_NORMAL) != CR_SUCCESS)
            {
                return results;
            }

            var stack = new Stack<uint>();
            stack.Push(rootDevInst);

            while (stack.Count > 0)
            {
                ct.ThrowIfCancellationRequested();
                var current = stack.Pop();

                if (CM_Get_Sibling(out var sibling, current, 0) == CR_SUCCESS)
                {
                    stack.Push(sibling);
                }

                if (CM_Get_Child(out var child, current, 0) == CR_SUCCESS)
                {
                    stack.Push(child);
                }

                if (current == rootDevInst)
                {
                    continue;
                }

                var instanceId = GetDeviceInstanceId(current);
                if (string.IsNullOrWhiteSpace(instanceId) ||
                    instanceId.StartsWith("HTREE\\", StringComparison.OrdinalIgnoreCase) ||
                    instanceId.StartsWith("SWD\\", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var hwIds = GetDevNodeMultiStringProperty(current, CM_DRP_HARDWAREID);
                var friendly = GetDevNodeStringProperty(current, CM_DRP_FRIENDLYNAME);
                if (string.IsNullOrWhiteSpace(friendly))
                {
                    friendly = GetDevNodeStringProperty(current, CM_DRP_DEVICEDESC);
                }

                if (string.IsNullOrWhiteSpace(friendly))
                {
                    friendly = instanceId;
                }

                var devClass = GetDevNodeStringProperty(current, CM_DRP_CLASS);
                var mfg = GetDevNodeStringProperty(current, CM_DRP_MFG);
                var driverKey = GetDevNodeStringProperty(current, CM_DRP_DRIVER);

                var problemCode = 0;
                if (CM_Get_DevNode_Status(out var status, out var probNum, current, 0) == CR_SUCCESS &&
                    (status & DN_HAS_PROBLEM) != 0)
                {
                    problemCode = unchecked((int)probNum);
                }

                var (drvVer, drvDate, infName) = ReadDriverClassRegistryMetadata(driverKey);

                results.Add(new SystemDeviceNode(
                    InstanceId: instanceId,
                    FriendlyName: friendly,
                    DeviceClass: devClass,
                    Manufacturer: mfg,
                    HardwareIds: hwIds,
                    ConfigManagerProblemCode: problemCode,
                    DriverVersion: drvVer,
                    DriverDate: drvDate,
                    InfName: infName,
                    IsPresent: true));
            }

            return results;
        }, ct);
    }

    public override Task<IReadOnlyList<OfficialDriverCandidate>> SearchWindowsUpdateDriversAsync(
        IReadOnlyList<SystemDeviceNode> devices,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult<IReadOnlyList<OfficialDriverCandidate>>(Array.Empty<OfficialDriverCandidate>());
        }

        return Task.Run<IReadOnlyList<OfficialDriverCandidate>>(() =>
        {
            var candidates = new List<OfficialDriverCandidate>();
            try
            {
                var sessionType = Type.GetTypeFromProgID("Microsoft.Update.Session", throwOnError: false);
                if (sessionType is null)
                {
                    return candidates;
                }

                var session = Activator.CreateInstance(sessionType);
                if (session is null)
                {
                    return candidates;
                }

                var searcher = ComCall(session, "CreateUpdateSearcher");
                if (searcher is null)
                {
                    return candidates;
                }

                var searchResult = ComCall(searcher, "Search", "IsInstalled=0 and Type='Driver' and IsHidden=0");
                var updates = searchResult is not null ? ComGet(searchResult, "Updates") : null;
                if (updates is null)
                {
                    return candidates;
                }

                var count = Convert.ToInt32(ComGet(updates, "Count") ?? 0);
                for (var i = 0; i < count; i++)
                {
                    ct.ThrowIfCancellationRequested();
                    var upd = ComGetIndexed(updates, "Item", i);
                    if (upd is null) continue;

                    var identity = ComGet(upd, "Identity");
                    var updateId = identity is not null ? Convert.ToString(ComGet(identity, "UpdateID")) ?? "" : "";
                    var title = Convert.ToString(ComGet(upd, "Title")) ?? "Windows Update WHQL Driver";
                    var model = TryReadComString(upd, "DriverModel", title);
                    var provider = TryReadComString(upd, "DriverManufacturer", "Microsoft WHQL");
                    var hwId = TryReadComString(upd, "DriverHardwareID", "");
                    var verDateObj = ComGet(upd, "DriverVerDate");
                    var verDate = verDateObj is DateTime dt ? dt.ToString("yyyy-MM-dd") : "";

                    if (string.IsNullOrWhiteSpace(hwId))
                    {
                        continue;
                    }

                    var vendorPortal = HardwareIdAndProblemAnalyzer.ResolveOfficialVendorPortal([hwId])?.OfficialPortalUrl
                                       ?? "https://www.catalog.update.microsoft.com/";

                    candidates.Add(new OfficialDriverCandidate(
                        UpdateIdentityId: updateId,
                        Title: title,
                        DriverModel: model,
                        ProviderName: provider,
                        DriverVersion: verDate.Length > 0 ? $"WHQL ({verDate})" : "WHQL",
                        DriverVerDate: verDate,
                        MatchedHardwareId: hwId,
                        HardwareIdMatchRank: 90,
                        SourceKind: DriverSourceKind.WindowsUpdateWhqlCatalog,
                        OfficialVendorPortalUrl: vendorPortal,
                        IsWhqlVerified: true));
                }
            }
            catch
            {
                // Offline / disabled Windows Update service returns graceful empty list
            }

            return candidates;
        }, ct);
    }

    public override async Task<(bool Succeeded, IReadOnlyList<string> ExportedFiles, string ErrorMessage)> ExportSingleOemInfAsync(
        string oemInfName,
        string destinationDirectory,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return (false, Array.Empty<string>(), "Доступно только на Windows.");
        }

        if (string.IsNullOrWhiteSpace(oemInfName) ||
            oemInfName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
            !oemInfName.StartsWith("oem", StringComparison.OrdinalIgnoreCase) ||
            !oemInfName.EndsWith(".inf", StringComparison.OrdinalIgnoreCase))
        {
            return (false, Array.Empty<string>(), "Некорректное имя пакета oemXX.inf.");
        }

        Directory.CreateDirectory(destinationDirectory);

        var psi = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "pnputil.exe"),
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        psi.ArgumentList.Add("/export-driver");
        psi.ArgumentList.Add(oemInfName);
        psi.ArgumentList.Add(destinationDirectory);

        using var proc = Process.Start(psi);
        if (proc is null)
        {
            return (false, Array.Empty<string>(), "Не удалось запустить pnputil.exe.");
        }

        var stdOut = await proc.StandardOutput.ReadToEndAsync(ct).ConfigureAwait(false);
        var stdErr = await proc.StandardError.ReadToEndAsync(ct).ConfigureAwait(false);
        await proc.WaitForExitAsync(ct).ConfigureAwait(false);

        var files = Directory.Exists(destinationDirectory)
            ? Directory.GetFiles(destinationDirectory, "*", SearchOption.AllDirectories)
            : Array.Empty<string>();

        if (proc.ExitCode != 0 || files.Length == 0)
        {
            return (false, Array.Empty<string>(), string.IsNullOrWhiteSpace(stdErr) ? stdOut.Trim() : stdErr.Trim());
        }

        return (true, files, "");
    }

    public override Task<(bool Succeeded, bool RebootRequired, string ErrorMessage)> InstallWindowsUpdateDriverAsync(
        string updateIdentityId,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult((false, false, "Доступно только на Windows."));
        }

        if (!IsRunningAsAdministrator())
        {
            return Task.FromResult((false, false, "Для установки драйвера требуются права Администратора."));
        }

        return Task.Run(() =>
        {
            try
            {
                var sessionType = Type.GetTypeFromProgID("Microsoft.Update.Session", throwOnError: false);
                var collType = Type.GetTypeFromProgID("Microsoft.Update.UpdateColl", throwOnError: false);
                if (sessionType is null || collType is null)
                {
                    return (false, false, "Служба Windows Update недоступна.");
                }

                var session = Activator.CreateInstance(sessionType);
                var toInstall = Activator.CreateInstance(collType);
                if (session is null || toInstall is null)
                {
                    return (false, false, "Не удалось инициализировать клиент Windows Update.");
                }

                var searcher = ComCall(session, "CreateUpdateSearcher");
                var searchResult = searcher is not null ? ComCall(searcher, "Search", "IsInstalled=0 and Type='Driver'") : null;
                var updates = searchResult is not null ? ComGet(searchResult, "Updates") : null;
                var count = updates is not null ? Convert.ToInt32(ComGet(updates, "Count") ?? 0) : 0;

                for (var i = 0; i < count; i++)
                {
                    var upd = ComGetIndexed(updates!, "Item", i);
                    if (upd is null) continue;
                    var identity = ComGet(upd, "Identity");
                    var id = identity is not null ? Convert.ToString(ComGet(identity, "UpdateID")) ?? "" : "";
                    if (string.Equals(id, updateIdentityId, StringComparison.OrdinalIgnoreCase))
                    {
                        _ = ComCall(toInstall, "Add", upd);
                        break;
                    }
                }

                if (Convert.ToInt32(ComGet(toInstall, "Count") ?? 0) == 0)
                {
                    return (false, false, "Указанный пакет WHQL-драйвера уже установлен или более не актуален.");
                }

                var downloader = ComCall(session, "CreateUpdateDownloader");
                if (downloader is null)
                {
                    return (false, false, "Не удалось создать загрузчик Windows Update.");
                }

                ComSet(downloader, "Updates", toInstall);
                var dlRes = ComCall(downloader, "Download");
                var dlCode = dlRes is not null ? Convert.ToInt32(ComGet(dlRes, "ResultCode") ?? 0) : 0;
                if (dlCode != 2) // orcSucceeded = 2
                {
                    return (false, false, $"Не удалось скачать пакет драйвера (код {dlCode}).");
                }

                var installer = ComCall(session, "CreateUpdateInstaller");
                if (installer is null)
                {
                    return (false, false, "Не удалось создать установщик Windows Update.");
                }

                ComSet(installer, "Updates", toInstall);
                var instRes = ComCall(installer, "Install");
                var instCode = instRes is not null ? Convert.ToInt32(ComGet(instRes, "ResultCode") ?? 0) : 0;
                var ok = instCode == 2;
                var reboot = instRes is not null && Convert.ToBoolean(ComGet(instRes, "RebootRequired") ?? false);

                return ok
                    ? (true, reboot, "")
                    : (false, reboot, $"Установщик драйверов вернул код {instCode}.");
            }
            catch (Exception ex)
            {
                return (false, false, ex.Message);
            }
        }, ct);
    }

    private static object? ComGet(object comObj, string propertyName)
    {
        try
        {
            return comObj.GetType().InvokeMember(propertyName, BindingFlags.GetProperty, null, comObj, null);
        }
        catch
        {
            return null;
        }
    }

    private static object? ComGetIndexed(object comObj, string propertyName, params object[] indexArgs)
    {
        try
        {
            return comObj.GetType().InvokeMember(propertyName, BindingFlags.GetProperty, null, comObj, indexArgs);
        }
        catch
        {
            return null;
        }
    }

    private static void ComSet(object comObj, string propertyName, object? value) =>
        comObj.GetType().InvokeMember(propertyName, BindingFlags.SetProperty, null, comObj, [value]);

    private static object? ComCall(object comObj, string methodName, params object?[] args) =>
        comObj.GetType().InvokeMember(methodName, BindingFlags.InvokeMethod, null, comObj, args);

    private static string TryReadComString(object comObj, string propertyName, string fallback)
    {
        var val = ComGet(comObj, propertyName);
        var str = Convert.ToString(val);
        return string.IsNullOrWhiteSpace(str) ? fallback : str;
    }

    private static (string DriverVersion, string DriverDate, string InfName) ReadDriverClassRegistryMetadata(string driverSubKey)
    {
        if (string.IsNullOrWhiteSpace(driverSubKey))
        {
            return ("", "", "");
        }

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Control\Class\{driverSubKey.TrimStart('\\')}");
            if (key is null)
            {
                return ("", "", "");
            }

            var ver = Convert.ToString(key.GetValue("DriverVersion")) ?? "";
            var date = Convert.ToString(key.GetValue("DriverDate")) ?? "";
            var inf = Convert.ToString(key.GetValue("InfPath")) ?? "";
            return (ver, date, inf);
        }
        catch
        {
            return ("", "", "");
        }
    }

    private static string GetDeviceInstanceId(uint devInst)
    {
        if (CM_Get_Device_ID_Size(out var len, devInst, 0) != CR_SUCCESS || len == 0)
        {
            return "";
        }

        var buffer = new char[len + 2];
        return CM_Get_Device_IDW(devInst, buffer, (uint)buffer.Length, 0) == CR_SUCCESS
            ? new string(buffer).TrimEnd('\0')
            : "";
    }

    private static string GetDevNodeStringProperty(uint devInst, uint property)
    {
        uint len = 512;
        var buf = new byte[len];
        var cr = CM_Get_DevNode_Registry_PropertyW(devInst, property, out _, buf, ref len, 0);
        if (cr != CR_SUCCESS || len < 2)
        {
            return "";
        }

        return Encoding.Unicode.GetString(buf, 0, (int)len).TrimEnd('\0');
    }

    private static IReadOnlyList<string> GetDevNodeMultiStringProperty(uint devInst, uint property)
    {
        uint len = 2048;
        var buf = new byte[len];
        var cr = CM_Get_DevNode_Registry_PropertyW(devInst, property, out _, buf, ref len, 0);
        if (cr != CR_SUCCESS || len < 2)
        {
            return Array.Empty<string>();
        }

        var raw = Encoding.Unicode.GetString(buf, 0, (int)len);
        return raw.Split('\0', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
    private static extern int CM_Locate_DevNodeW(out uint pdnDevInst, string? pDeviceID, int ulFlags);

    [DllImport("CfgMgr32.dll")]
    private static extern int CM_Get_Child(out uint pdnDevInst, uint dnDevInst, int ulFlags);

    [DllImport("CfgMgr32.dll")]
    private static extern int CM_Get_Sibling(out uint pdnDevInst, uint dnDevInst, int ulFlags);

    [DllImport("CfgMgr32.dll")]
    private static extern int CM_Get_Device_ID_Size(out uint pulLen, uint dnDevInst, int ulFlags);

    [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
    private static extern int CM_Get_Device_IDW(uint dnDevInst, [Out] char[] buffer, uint bufferLen, int ulFlags);

    [DllImport("CfgMgr32.dll")]
    private static extern int CM_Get_DevNode_Status(out uint pulStatus, out uint pulProblemNumber, uint dnDevInst, int ulFlags);

    [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
    private static extern int CM_Get_DevNode_Registry_PropertyW(
        uint dnDevInst,
        uint ulProperty,
        out uint pulRegDataType,
        [Out] byte[] buffer,
        ref uint pulLength,
        int ulFlags);
}
