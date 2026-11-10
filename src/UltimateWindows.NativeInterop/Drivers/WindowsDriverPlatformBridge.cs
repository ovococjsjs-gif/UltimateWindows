using System.Diagnostics;
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

                dynamic? session = Activator.CreateInstance(sessionType);
                if (session is null)
                {
                    return candidates;
                }

                dynamic searcher = session.CreateUpdateSearcher();
                dynamic searchResult = searcher.Search("IsInstalled=0 and Type='Driver' and IsHidden=0");
                int count = (int)searchResult.Updates.Count;

                for (var i = 0; i < count; i++)
                {
                    ct.ThrowIfCancellationRequested();
                    dynamic upd = searchResult.Updates.Item(i);

                    string updateId = Convert.ToString(upd.Identity.UpdateID) ?? "";
                    string title = Convert.ToString(upd.Title) ?? "Windows Update WHQL Driver";
                    string model = TryReadDynamicString(() => upd.DriverModel, title);
                    string provider = TryReadDynamicString(() => upd.DriverManufacturer, "Microsoft WHQL");
                    string hwId = TryReadDynamicString(() => upd.DriverHardwareID, "");
                    string verDate = TryReadDynamicString(() => Convert.ToDateTime(upd.DriverVerDate).ToString("yyyy-MM-dd"), "");

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

                dynamic? session = Activator.CreateInstance(sessionType);
                dynamic? toInstall = Activator.CreateInstance(collType);
                if (session is null || toInstall is null)
                {
                    return (false, false, "Не удалось инициализировать клиент Windows Update.");
                }

                dynamic searcher = session.CreateUpdateSearcher();
                dynamic searchResult = searcher.Search("IsInstalled=0 and Type='Driver'");
                int count = (int)searchResult.Updates.Count;

                for (var i = 0; i < count; i++)
                {
                    dynamic upd = searchResult.Updates.Item(i);
                    string id = Convert.ToString(upd.Identity.UpdateID) ?? "";
                    if (string.Equals(id, updateIdentityId, StringComparison.OrdinalIgnoreCase))
                    {
                        toInstall.Add(upd);
                        break;
                    }
                }

                if ((int)toInstall.Count == 0)
                {
                    return (false, false, "Указанный пакет WHQL-драйвера уже установлен или более не актуален.");
                }

                dynamic downloader = session.CreateUpdateDownloader();
                downloader.Updates = toInstall;
                dynamic dlRes = downloader.Download();
                if ((int)dlRes.ResultCode != 2) // orcSucceeded = 2
                {
                    return (false, false, $"Не удалось скачать пакет драйвера (код {dlRes.ResultCode}).");
                }

                dynamic installer = session.CreateUpdateInstaller();
                installer.Updates = toInstall;
                dynamic instRes = installer.Install();
                bool ok = (int)instRes.ResultCode == 2;
                bool reboot = Convert.ToBoolean(instRes.RebootRequired);

                return ok
                    ? (true, reboot, "")
                    : (false, reboot, $"Установщик драйверов вернул код {instRes.ResultCode}.");
            }
            catch (Exception ex)
            {
                return (false, false, ex.Message);
            }
        }, ct);
    }

    private static string TryReadDynamicString(Func<object?> getter, string fallback)
    {
        try
        {
            return Convert.ToString(getter()) ?? fallback;
        }
        catch
        {
            return fallback;
        }
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
