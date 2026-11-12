using System.Collections.Concurrent;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Microsoft.Win32;
using UltimateWindows.Modules.Drivers.Analyzers;
using UltimateWindows.Modules.Drivers.Models;
using UltimateWindows.Modules.Drivers.Services;
using UltimateWindows.NativeInterop.Security;

namespace UltimateWindows.NativeInterop.Drivers;

/// <summary>
/// Нативный мост Этапа 5 («Драйверы 2.0») для Windows 10/11:
/// - полный опрос дерева устройств через CfgMgr32.dll (версии, даты, поставщики, совместимые ID, подписи драйверов);
/// - поиск и установка WHQL-драйверов через Windows Update Agent (Microsoft.Update.Session);
/// - распаковка подписанных .cab пакетов Microsoft Update Catalog через expand.exe и установка через pnputil.exe;
/// - локаленезависимая ревизия хранилища DriverStore (pnputil XML + INF + FileRepository), бэкап и удаление старых дублей;
/// - аудит драйверов ядра (Type 1/2), проверка HVCI и списка блокировки уязвимых драйверов Microsoft.
/// </summary>
public sealed class WindowsDriverPlatformBridge : DefaultDriverPlatformBridge
{
    private const int CR_SUCCESS = 0x00000000;
    private const int CM_LOCATE_DEVNODE_NORMAL = 0x00000000;
    private const uint DN_HAS_PROBLEM = 0x00000400;

    private const uint CM_DRP_DEVICEDESC = 0x00000001;
    private const uint CM_DRP_HARDWAREID = 0x00000002;
    private const uint CM_DRP_COMPATIBLEIDS = 0x00000003;
    private const uint CM_DRP_SERVICE = 0x00000005;
    private const uint CM_DRP_CLASS = 0x00000008;
    private const uint CM_DRP_DRIVER = 0x0000000A;
    private const uint CM_DRP_MFG = 0x0000000C;
    private const uint CM_DRP_FRIENDLYNAME = 0x0000000D;
    private const uint CM_DRP_LOCATION_INFORMATION = 0x0000000E;

    private static readonly ConcurrentDictionary<string, bool> DriverSignatureCache = new(StringComparer.OrdinalIgnoreCase);

    public override bool IsRunningAsAdministrator() => ElevationChecker.IsRunningAsAdministrator();

    public override bool VerifyFileAuthenticodeSignature(string filePath) =>
        AuthenticodeVerifier.IsFileTrustedSigned(filePath);

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

            var servicePathCache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
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
                var compatIds = GetDevNodeMultiStringProperty(current, CM_DRP_COMPATIBLEIDS);
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
                var serviceName = GetDevNodeStringProperty(current, CM_DRP_SERVICE);
                var driverKey = GetDevNodeStringProperty(current, CM_DRP_DRIVER);
                var locationInfo = GetDevNodeStringProperty(current, CM_DRP_LOCATION_INFORMATION);

                var problemCode = 0;
                if (CM_Get_DevNode_Status(out var status, out var probNum, current, 0) == CR_SUCCESS &&
                    (status & DN_HAS_PROBLEM) != 0)
                {
                    problemCode = unchecked((int)probNum);
                }

                var (drvVer, drvDate, infName, providerName, matchingId) = ReadDriverClassRegistryMetadata(driverKey);

                string serviceImg = "";
                bool? isSigned = null;
                if (!string.IsNullOrWhiteSpace(serviceName))
                {
                    if (!servicePathCache.TryGetValue(serviceName, out var cachedImg))
                    {
                        cachedImg = ReadServiceBinaryPath(serviceName);
                        servicePathCache[serviceName] = cachedImg;
                    }

                    serviceImg = cachedImg;
                    if (!string.IsNullOrWhiteSpace(serviceImg) && File.Exists(serviceImg))
                    {
                        isSigned = DriverSignatureCache.GetOrAdd(serviceImg, AuthenticodeVerifier.IsFileTrustedSigned);
                    }
                }

                results.Add(new SystemDeviceNode(
                    InstanceId: instanceId,
                    FriendlyName: friendly,
                    DeviceClass: devClass,
                    Manufacturer: mfg,
                    HardwareIds: hwIds,
                    ConfigManagerProblemCode: problemCode,
                    DriverVersion: drvVer,
                    DriverDate: DriverVersionComparer.NormalizeDateDisplay(drvDate),
                    InfName: infName,
                    IsPresent: true,
                    ProviderName: providerName,
                    CompatibleIds: compatIds,
                    ServiceName: serviceName,
                    ServiceImagePath: serviceImg,
                    IsDigitallySigned: isSigned,
                    MatchingDeviceId: matchingId,
                    LocationInfo: locationInfo));
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

        if (!IsValidOemInfName(oemInfName))
        {
            return (false, Array.Empty<string>(), "Некорректное имя пакета oemXX.inf.");
        }

        Directory.CreateDirectory(destinationDirectory);
        var (exitCode, stdOut, stdErr) = await RunSystemToolAsync(
            "pnputil.exe",
            ["/export-driver", oemInfName, destinationDirectory],
            ct).ConfigureAwait(false);

        var files = Directory.Exists(destinationDirectory)
            ? Directory.GetFiles(destinationDirectory, "*", SearchOption.AllDirectories)
            : Array.Empty<string>();

        if (exitCode != 0 || files.Length == 0)
        {
            return (false, Array.Empty<string>(), string.IsNullOrWhiteSpace(stdErr) ? stdOut.Trim() : stdErr.Trim());
        }

        return (true, files, "");
    }

    public override async Task<(bool Succeeded, int ExportedPackageCount, string ErrorMessage)> ExportAllDriversAsync(
        string destinationDirectory,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return (false, 0, "Доступно только на Windows.");
        }

        Directory.CreateDirectory(destinationDirectory);
        var (exitCode, stdOut, stdErr) = await RunSystemToolAsync(
            "pnputil.exe",
            ["/export-driver", "*", destinationDirectory],
            ct).ConfigureAwait(false);

        var subDirs = Directory.Exists(destinationDirectory)
            ? Directory.GetDirectories(destinationDirectory)
            : Array.Empty<string>();

        if (exitCode != 0 && subDirs.Length == 0)
        {
            return (false, 0, string.IsNullOrWhiteSpace(stdErr) ? stdOut.Trim() : stdErr.Trim());
        }

        return (true, subDirs.Length, "");
    }

    public override async Task<(bool Succeeded, IReadOnlyList<string> ExtractedFiles, string ErrorMessage)> ExtractCabArchiveAsync(
        string cabFilePath,
        string destinationDirectory,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return (false, Array.Empty<string>(), "Распаковка CAB поддерживается только в среде Windows.");
        }

        Directory.CreateDirectory(destinationDirectory);
        var (exitCode, stdOut, stdErr) = await RunSystemToolAsync(
            "expand.exe",
            ["-F:*", cabFilePath, destinationDirectory],
            ct).ConfigureAwait(false);

        var extracted = Directory.Exists(destinationDirectory)
            ? Directory.GetFiles(destinationDirectory, "*", SearchOption.AllDirectories)
            : Array.Empty<string>();

        if (exitCode != 0 && extracted.Length == 0)
        {
            return (false, Array.Empty<string>(), string.IsNullOrWhiteSpace(stdErr) ? stdOut.Trim() : stdErr.Trim());
        }

        return (true, extracted, "");
    }

    public override async Task<(bool Succeeded, int AddedCount, string OutputMessage)> AddAndInstallDriverFolderAsync(
        string infDirectory,
        bool installOnDevices = true,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return (false, 0, "Доступно только на Windows.");
        }

        var infFiles = Directory.Exists(infDirectory)
            ? Directory.GetFiles(infDirectory, "*.inf", SearchOption.AllDirectories)
            : Array.Empty<string>();

        if (infFiles.Length == 0)
        {
            return (false, 0, "В указанной папке не найдено ни одного .inf файла драйвера.");
        }

        var args = new List<string> { "/add-driver", Path.Combine(infDirectory, "*.inf"), "/subdirs" };
        if (installOnDevices)
        {
            args.Add("/install");
        }

        var (exitCode, stdOut, stdErr) = await RunSystemToolAsync("pnputil.exe", args, ct).ConfigureAwait(false);
        // pnputil возвращает 0 (успешно) или 3010 (успешно, требуется перезагрузка) или 259 (уже установлена лучшая версия)
        bool ok = exitCode is 0 or 3010 or 259;
        var combined = string.IsNullOrWhiteSpace(stdOut) ? stdErr.Trim() : stdOut.Trim();
        return (ok, infFiles.Length, combined);
    }

    public override async Task<(bool Succeeded, int ExitCode, string ErrorMessage)> RunSignedInstallerAsync(
        string installerPath,
        string? arguments,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return (false, -1, "Доступно только на Windows.");
        }

        if (!AuthenticodeVerifier.IsFileTrustedSigned(installerPath))
        {
            return (false, -1, "Файл установщика не имеет доверенной цифровой подписи Authenticode.");
        }

        var ext = Path.GetExtension(installerPath).ToLowerInvariant();
        ProcessStartInfo psi;
        if (ext == ".msi")
        {
            psi = new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.SystemDirectory, "msiexec.exe"),
                Arguments = $"/i \"{installerPath}\" {(string.IsNullOrWhiteSpace(arguments) ? "/qn /norestart" : arguments)}",
                CreateNoWindow = true,
                UseShellExecute = false
            };
        }
        else
        {
            psi = new ProcessStartInfo
            {
                FileName = installerPath,
                Arguments = arguments ?? "",
                CreateNoWindow = true,
                UseShellExecute = false
            };
        }

        using var proc = Process.Start(psi);
        if (proc is null)
        {
            return (false, -1, "Не удалось запустить процесс установщика.");
        }

        await proc.WaitForExitAsync(ct).ConfigureAwait(false);
        bool ok = proc.ExitCode is 0 or 3010 or 1641;
        return (ok, proc.ExitCode, ok ? "" : $"Код завершения: {proc.ExitCode}");
    }

    public override async Task<IReadOnlyList<DriverStoreEntry>> EnumerateDriverStoreAsync(
        IReadOnlyList<SystemDeviceNode> activeDevices,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Array.Empty<DriverStoreEntry>();
        }

        var boundByInf = activeDevices
            .Where(d => d.IsThirdPartyOemInf)
            .GroupBy(d => d.InfName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().FriendlyName, StringComparer.OrdinalIgnoreCase);

        var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var repoRoot = Path.Combine(Environment.SystemDirectory, "DriverStore", "FileRepository");
        var repoFoldersByPrefix = BuildRepositoryFolderIndex(repoRoot);

        // 1. Сначала пробуем локаленезависимый XML-режим pnputil (/enum-drivers /format xml, доступен на Windows 11 / Server 2025)
        var (xmlExit, xmlOut, _) = await RunSystemToolAsync("pnputil.exe", ["/enum-drivers", "/format", "xml"], ct).ConfigureAwait(false);
        if (xmlExit == 0 && xmlOut.Contains("<PnpUtil", StringComparison.OrdinalIgnoreCase))
        {
            var parsedXml = TryParsePnpUtilXml(xmlOut, boundByInf, repoFoldersByPrefix);
            if (parsedXml.Count > 0)
            {
                return parsedXml;
            }
        }

        // 2. Универсальный резервный путь для Windows 10 и любых локалей: прямой разбор C:\Windows\INF\oem*.inf
        return await Task.Run<IReadOnlyList<DriverStoreEntry>>(() =>
        {
            var infDir = Path.Combine(winDir, "INF");
            if (!Directory.Exists(infDir))
            {
                return Array.Empty<DriverStoreEntry>();
            }

            var list = new List<DriverStoreEntry>();
            foreach (var oemPath in Directory.EnumerateFiles(infDir, "oem*.inf"))
            {
                ct.ThrowIfCancellationRequested();
                var publishedName = Path.GetFileName(oemPath);
                if (!IsValidOemInfName(publishedName))
                {
                    continue;
                }

                var meta = ParseInfVersionMetadata(oemPath);
                boundByInf.TryGetValue(publishedName, out var boundDevice);

                string repoFolder = "";
                long folderBytes = 0;
                if (!string.IsNullOrWhiteSpace(meta.CatalogOrOrigPrefix) &&
                    repoFoldersByPrefix.TryGetValue(meta.CatalogOrOrigPrefix, out var candidates) &&
                    candidates.Count > 0)
                {
                    repoFolder = candidates[0].FolderPath;
                    folderBytes = candidates[0].SizeBytes;
                }

                list.Add(new DriverStoreEntry(
                    PublishedInfName: publishedName,
                    OriginalInfName: string.IsNullOrWhiteSpace(meta.OriginalInfGuess) ? publishedName : meta.OriginalInfGuess,
                    ProviderName: meta.Provider,
                    ClassName: meta.ClassName,
                    ClassGuid: meta.ClassGuid,
                    DriverVersion: meta.DriverVersion,
                    DriverDate: meta.DriverDate,
                    SignerName: meta.CatalogFile,
                    RepositoryFolderPath: repoFolder,
                    SizeBytes: folderBytes,
                    IsInUseByDevice: boundDevice is not null,
                    BoundDeviceName: boundDevice,
                    IsSupersededDuplicate: false,
                    SupersededByVersion: null));
            }

            return list;
        }, ct).ConfigureAwait(false);
    }

    public override async Task<(bool Succeeded, string ErrorMessage)> DeleteDriverStorePackageAsync(
        string publishedInfName,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return (false, "Доступно только на Windows.");
        }

        if (!IsValidOemInfName(publishedInfName))
        {
            return (false, "Разрешено удалять только сторонние пакеты формата oemXX.inf.");
        }

        // Намеренно БЕЗ флага /force — Windows откажется удалять драйвер, привязанный к активному устройству
        var (exitCode, stdOut, stdErr) = await RunSystemToolAsync(
            "pnputil.exe",
            ["/delete-driver", publishedInfName],
            ct).ConfigureAwait(false);

        if (exitCode != 0)
        {
            return (false, string.IsNullOrWhiteSpace(stdErr) ? stdOut.Trim() : stdErr.Trim());
        }

        return (true, "");
    }

    public override Task<IReadOnlyList<KernelDriverInventoryEntry>> EnumerateKernelDriversAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult<IReadOnlyList<KernelDriverInventoryEntry>>(Array.Empty<KernelDriverInventoryEntry>());
        }

        return Task.Run<IReadOnlyList<KernelDriverInventoryEntry>>(() =>
        {
            var runningDrivers = QueryRunningKernelDriverServiceNames();
            var list = new List<KernelDriverInventoryEntry>();

            using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (servicesKey is null)
            {
                return list;
            }

            foreach (var svcName in servicesKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var sub = servicesKey.OpenSubKey(svcName);
                    if (sub is null) continue;

                    var typeVal = Convert.ToInt32(sub.GetValue("Type") ?? 0);
                    // 1 = SERVICE_KERNEL_DRIVER, 2 = SERVICE_FILE_SYSTEM_DRIVER
                    if (typeVal is not (1 or 2))
                    {
                        continue;
                    }

                    var startType = Convert.ToInt32(sub.GetValue("Start") ?? 3);
                    var displayName = Convert.ToString(sub.GetValue("DisplayName")) ?? svcName;
                    var rawImg = Convert.ToString(sub.GetValue("ImagePath")) ?? "";
                    var resolvedPath = NormalizeKernelImagePath(rawImg, svcName);
                    var fileName = Path.GetFileName(resolvedPath);
                    bool exists = !string.IsNullOrWhiteSpace(resolvedPath) && File.Exists(resolvedPath);
                    bool isRunning = runningDrivers.Contains(svcName);

                    string fileVer = "";
                    string company = "";
                    string sha256 = "";
                    bool signed = false;

                    if (exists)
                    {
                        try
                        {
                            var fvi = FileVersionInfo.GetVersionInfo(resolvedPath);
                            fileVer = fvi.FileVersion ?? "";
                            company = fvi.CompanyName ?? "";
                            if (string.IsNullOrWhiteSpace(fileName) && !string.IsNullOrWhiteSpace(fvi.OriginalFilename))
                            {
                                fileName = fvi.OriginalFilename;
                            }
                        }
                        catch { }

                        signed = DriverSignatureCache.GetOrAdd(resolvedPath, AuthenticodeVerifier.IsFileTrustedSigned);

                        // Вычисляем SHA-256 для сторонних / небольших .sys драйверов (мгновенно — файлы .sys обычно 20–500 КБ)
                        try
                        {
                            var fi = new FileInfo(resolvedPath);
                            if (fi.Length is > 0 and <= 16 * 1024 * 1024)
                            {
                                using var fs = new FileStream(resolvedPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                                sha256 = Convert.ToHexStringLower(SHA256.HashData(fs));
                            }
                        }
                        catch { }
                    }

                    list.Add(new KernelDriverInventoryEntry(
                        ServiceName: svcName,
                        DisplayName: displayName,
                        BinaryPath: resolvedPath,
                        FileName: fileName,
                        FileExists: exists,
                        FileVersion: fileVer,
                        CompanyName: company,
                        Sha256Hex: sha256,
                        IsRunning: isRunning,
                        StartType: startType,
                        IsSigned: signed));
                }
                catch
                {
                    // Skip inaccessible service key
                }
            }

            return list;
        }, ct);
    }

    public override (bool IsHvciEnabled, bool IsMicrosoftBlocklistEnabled) ReadCodeIntegrityPosture()
    {
        if (!OperatingSystem.IsWindows())
        {
            return (false, false);
        }

        bool hvci = false;
        bool blocklist = true; // В Windows 11 22H2+ по умолчанию включён, если явно не выключен = 0

        try
        {
            using var hvciKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity");
            if (hvciKey?.GetValue("Enabled") is int hvciVal)
            {
                hvci = hvciVal == 1;
            }
        }
        catch { }

        try
        {
            using var ciKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\CI\Config");
            var raw = ciKey?.GetValue("VulnerableDriverBlocklistEnable");
            if (raw is int ciVal)
            {
                blocklist = ciVal != 0;
            }
            else
            {
                // На Windows 10 без ключа блок-лист по умолчанию выключен, если нет HVCI
                blocklist = hvci || Environment.OSVersion.Version.Build >= 22621;
            }
        }
        catch { }

        return (hvci, blocklist);
    }

    public override (bool Succeeded, int? PreviousValue, string ErrorMessage) SetMicrosoftVulnerableDriverBlocklist(bool enabled)
    {
        if (!OperatingSystem.IsWindows())
        {
            return (false, null, "Доступно только на Windows.");
        }

        try
        {
            using var ciKey = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Control\CI\Config", writable: true);
            if (ciKey is null)
            {
                return (false, null, "Не удалось открыть раздел Control\\CI\\Config для записи.");
            }

            int? prev = ciKey.GetValue("VulnerableDriverBlocklistEnable") is int v ? v : null;
            ciKey.SetValue("VulnerableDriverBlocklistEnable", enabled ? 1 : 0, RegistryValueKind.DWord);
            return (true, prev, "");
        }
        catch (Exception ex)
        {
            return (false, null, ex.Message);
        }
    }

    public override (bool Succeeded, int PreviousStartType, string ErrorMessage) DisableKernelDriverService(string serviceName)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(serviceName))
        {
            return (false, 3, "Некорректное имя службы драйвера.");
        }

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}", writable: true);
            if (key is null)
            {
                return (false, 3, $"Служба «{serviceName}» не найдена.");
            }

            int prevStart = Convert.ToInt32(key.GetValue("Start") ?? 3);
            key.SetValue("Start", 4, RegistryValueKind.DWord); // SERVICE_DISABLED = 4

            // Попытка мягко остановить драйвер через sc stop (если он поддерживает выгрузку на лету)
            try
            {
                using var proc = Process.Start(new ProcessStartInfo
                {
                    FileName = Path.Combine(Environment.SystemDirectory, "sc.exe"),
                    Arguments = $"stop \"{serviceName}\"",
                    CreateNoWindow = true,
                    UseShellExecute = false
                });
                proc?.WaitForExit(3000);
            }
            catch { }

            return (true, prevStart, "");
        }
        catch (Exception ex)
        {
            return (false, 3, ex.Message);
        }
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
                if (dlCode != 2)
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

    // ==================== PRIVATE HELPERS ====================

    private static bool IsValidOemInfName(string? name) =>
        !string.IsNullOrWhiteSpace(name) &&
        name.IndexOfAny(Path.GetInvalidFileNameChars()) < 0 &&
        name.StartsWith("oem", StringComparison.OrdinalIgnoreCase) &&
        name.EndsWith(".inf", StringComparison.OrdinalIgnoreCase) &&
        name.Length >= 8 &&
        name[3..^4].All(char.IsDigit);

    private static async Task<(int ExitCode, string StdOut, string StdErr)> RunSystemToolAsync(
        string exeName,
        IReadOnlyList<string> args,
        CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, exeName),
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var a in args) psi.ArgumentList.Add(a);

        using var proc = Process.Start(psi);
        if (proc is null)
        {
            return (-1, "", $"Не удалось запустить {exeName}.");
        }

        var stdOutTask = proc.StandardOutput.ReadToEndAsync(ct);
        var stdErrTask = proc.StandardError.ReadToEndAsync(ct);
        await Task.WhenAll(stdOutTask, stdErrTask, proc.WaitForExitAsync(ct)).ConfigureAwait(false);
        return (proc.ExitCode, stdOutTask.Result, stdErrTask.Result);
    }

    private static Dictionary<string, List<(string FolderPath, long SizeBytes)>> BuildRepositoryFolderIndex(string repoRoot)
    {
        var dict = new Dictionary<string, List<(string, long)>>(StringComparer.OrdinalIgnoreCase);
        if (!Directory.Exists(repoRoot))
        {
            return dict;
        }

        try
        {
            foreach (var dir in Directory.EnumerateDirectories(repoRoot))
            {
                var folderName = Path.GetFileName(dir);
                var infIdx = folderName.IndexOf(".inf_", StringComparison.OrdinalIgnoreCase);
                var origInf = infIdx > 0 ? folderName[..(infIdx + 4)] : folderName;

                long bytes = 0;
                try
                {
                    foreach (var f in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                    {
                        try { bytes += new FileInfo(f).Length; } catch { }
                    }
                }
                catch { }

                if (!dict.TryGetValue(origInf, out var list))
                {
                    list = [];
                    dict[origInf] = list;
                }

                list.Add((dir, bytes));
            }
        }
        catch { }

        return dict;
    }

    private static List<DriverStoreEntry> TryParsePnpUtilXml(
        string xmlText,
        Dictionary<string, string> boundByInf,
        Dictionary<string, List<(string FolderPath, long SizeBytes)>> repoIndex)
    {
        var list = new List<DriverStoreEntry>();
        try
        {
            var startIdx = xmlText.IndexOf('<');
            if (startIdx > 0) xmlText = xmlText[startIdx..];

            var doc = XDocument.Parse(xmlText);
            var usedFolders = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var drvEl in doc.Descendants().Where(e => e.Name.LocalName.Equals("Driver", StringComparison.OrdinalIgnoreCase)))
            {
                var pubName = AttrOrChild(drvEl, "Name") ?? AttrOrChild(drvEl, "PublishedName") ?? "";
                if (!IsValidOemInfName(pubName))
                {
                    continue;
                }

                var origName = AttrOrChild(drvEl, "OriginalName") ?? pubName;
                var provider = AttrOrChild(drvEl, "Provider") ?? AttrOrChild(drvEl, "ProviderName") ?? "";
                var className = AttrOrChild(drvEl, "ClassName") ?? "";
                var classGuid = AttrOrChild(drvEl, "ClassGuid") ?? "";
                var signer = AttrOrChild(drvEl, "SignerName") ?? "";
                var rawVer = AttrOrChild(drvEl, "Version") ?? "";

                // Формат Version в pnputil XML: "10/15/2024 22.250.1.2"
                string datePart = "";
                string verPart = rawVer;
                var sp = rawVer.IndexOf(' ');
                if (sp > 0)
                {
                    datePart = DriverVersionComparer.NormalizeDateDisplay(rawVer[..sp]);
                    verPart = rawVer[(sp + 1)..].Trim();
                }

                boundByInf.TryGetValue(pubName, out var boundDev);

                string folderPath = "";
                long sizeBytes = 0;
                if (repoIndex.TryGetValue(origName, out var matches))
                {
                    var chosen = matches.FirstOrDefault(m => !usedFolders.Contains(m.FolderPath));
                    if (!string.IsNullOrWhiteSpace(chosen.FolderPath))
                    {
                        folderPath = chosen.FolderPath;
                        sizeBytes = chosen.SizeBytes;
                        usedFolders.Add(folderPath);
                    }
                    else if (matches.Count > 0)
                    {
                        folderPath = matches[0].FolderPath;
                        sizeBytes = matches[0].SizeBytes;
                    }
                }

                list.Add(new DriverStoreEntry(
                    PublishedInfName: pubName,
                    OriginalInfName: origName,
                    ProviderName: provider,
                    ClassName: className,
                    ClassGuid: classGuid,
                    DriverVersion: verPart,
                    DriverDate: datePart,
                    SignerName: signer,
                    RepositoryFolderPath: folderPath,
                    SizeBytes: sizeBytes,
                    IsInUseByDevice: boundDev is not null,
                    BoundDeviceName: boundDev,
                    IsSupersededDuplicate: false,
                    SupersededByVersion: null));
            }
        }
        catch
        {
            // Fallback to direct INF scan if XML schema differs
        }

        return list;
    }

    private static string? AttrOrChild(XElement el, string localName)
    {
        var attr = el.Attributes().FirstOrDefault(a => a.Name.LocalName.Equals(localName, StringComparison.OrdinalIgnoreCase));
        if (attr is not null && !string.IsNullOrWhiteSpace(attr.Value))
        {
            return attr.Value.Trim();
        }

        var child = el.Elements().FirstOrDefault(c => c.Name.LocalName.Equals(localName, StringComparison.OrdinalIgnoreCase));
        return child is not null && !string.IsNullOrWhiteSpace(child.Value) ? child.Value.Trim() : null;
    }

    private static (string ClassName, string ClassGuid, string Provider, string DriverDate, string DriverVersion, string CatalogFile, string OriginalInfGuess, string CatalogOrOrigPrefix) ParseInfVersionMetadata(string infPath)
    {
        string className = "";
        string classGuid = "";
        string providerRaw = "";
        string drvDate = "";
        string drvVer = "";
        string catFile = "";
        var stringsMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            string currentSection = "";
            foreach (var rawLine in File.ReadLines(infPath))
            {
                var line = rawLine.Trim();
                if (line.Length == 0 || line.StartsWith(';')) continue;

                if (line.StartsWith('[') && line.EndsWith(']'))
                {
                    currentSection = line[1..^1].Trim();
                    continue;
                }

                var eq = line.IndexOf('=');
                if (eq <= 0) continue;

                var k = line[..eq].Trim();
                var v = line[(eq + 1)..].Split(';', 2)[0].Trim().Trim('"');

                if (currentSection.Equals("Version", StringComparison.OrdinalIgnoreCase))
                {
                    if (k.Equals("Class", StringComparison.OrdinalIgnoreCase)) className = v;
                    else if (k.Equals("ClassGUID", StringComparison.OrdinalIgnoreCase)) classGuid = v;
                    else if (k.Equals("Provider", StringComparison.OrdinalIgnoreCase)) providerRaw = v;
                    else if (k.Equals("CatalogFile", StringComparison.OrdinalIgnoreCase) || k.StartsWith("CatalogFile.", StringComparison.OrdinalIgnoreCase)) catFile = v;
                    else if (k.Equals("DriverVer", StringComparison.OrdinalIgnoreCase))
                    {
                        (drvDate, drvVer) = DriverVersionComparer.ParseInfDriverVerDirective(v);
                    }
                }
                else if (currentSection.StartsWith("Strings", StringComparison.OrdinalIgnoreCase))
                {
                    stringsMap.TryAdd(k, v);
                }
            }
        }
        catch { }

        if (providerRaw.StartsWith('%') && providerRaw.EndsWith('%') && providerRaw.Length > 2)
        {
            var token = providerRaw[1..^1];
            if (stringsMap.TryGetValue(token, out var resolved))
            {
                providerRaw = resolved;
            }
        }

        var guessOrig = !string.IsNullOrWhiteSpace(catFile)
            ? Path.ChangeExtension(catFile, ".inf")
            : "";

        return (className, classGuid, providerRaw, drvDate, drvVer, catFile, guessOrig, guessOrig);
    }

    private static HashSet<string> QueryRunningKernelDriverServiceNames()
    {
        var running = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var scm = OpenSCManagerW(null, null, 0x0004); // SC_MANAGER_ENUMERATE_SERVICE
        if (scm == IntPtr.Zero)
        {
            return running;
        }

        try
        {
            const uint SERVICE_DRIVER = 0x0000000B;
            const uint SERVICE_ACTIVE = 0x00000001;
            uint resumeHandle = 0;

            _ = EnumServicesStatusExW(scm, 0, SERVICE_DRIVER, SERVICE_ACTIVE, IntPtr.Zero, 0, out var bytesNeeded, out _, ref resumeHandle, null);
            if (bytesNeeded == 0)
            {
                return running;
            }

            var buf = Marshal.AllocHGlobal((int)bytesNeeded + 256);
            try
            {
                resumeHandle = 0;
                if (EnumServicesStatusExW(scm, 0, SERVICE_DRIVER, SERVICE_ACTIVE, buf, bytesNeeded + 256, out _, out var count, ref resumeHandle, null))
                {
                    int stride = Marshal.SizeOf<ENUM_SERVICE_STATUS_PROCESSW>();
                    for (int i = 0; i < count; i++)
                    {
                        var entry = Marshal.PtrToStructure<ENUM_SERVICE_STATUS_PROCESSW>(buf + (i * stride));
                        if (!string.IsNullOrWhiteSpace(entry.lpServiceName))
                        {
                            running.Add(entry.lpServiceName);
                        }
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }
        catch { }
        finally
        {
            _ = CloseServiceHandle(scm);
        }

        return running;
    }

    private static string ReadServiceBinaryPath(string serviceName)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}");
            var raw = Convert.ToString(key?.GetValue("ImagePath")) ?? "";
            return NormalizeKernelImagePath(raw, serviceName);
        }
        catch
        {
            return "";
        }
    }

    private static string NormalizeKernelImagePath(string rawImagePath, string serviceName)
    {
        var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrWhiteSpace(rawImagePath))
        {
            var fallback = Path.Combine(Environment.SystemDirectory, "drivers", serviceName + ".sys");
            return File.Exists(fallback) ? fallback : "";
        }

        var path = Environment.ExpandEnvironmentVariables(rawImagePath.Trim().Trim('"'));
        if (path.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase))
        {
            path = path[4..];
        }
        else if (path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
        {
            path = Path.Combine(winDir, path[@"\SystemRoot\".Length..]);
        }
        else if (path.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase) ||
                 path.StartsWith(@"system32\", StringComparison.OrdinalIgnoreCase))
        {
            path = Path.Combine(winDir, path);
        }
        else if (!Path.IsPathRooted(path))
        {
            path = Path.Combine(winDir, path);
        }

        return path;
    }

    private static (string DriverVersion, string DriverDate, string InfName, string ProviderName, string MatchingDeviceId) ReadDriverClassRegistryMetadata(string driverSubKey)
    {
        if (string.IsNullOrWhiteSpace(driverSubKey))
        {
            return ("", "", "", "", "");
        }

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Control\Class\{driverSubKey.TrimStart('\\')}");
            if (key is null)
            {
                return ("", "", "", "", "");
            }

            var ver = Convert.ToString(key.GetValue("DriverVersion")) ?? "";
            var date = Convert.ToString(key.GetValue("DriverDate")) ?? "";
            var inf = Convert.ToString(key.GetValue("InfPath")) ?? "";
            var prov = Convert.ToString(key.GetValue("ProviderName")) ?? "";
            var matchId = Convert.ToString(key.GetValue("MatchingDeviceId")) ?? "";
            return (ver, date, inf, prov, matchId);
        }
        catch
        {
            return ("", "", "", "", "");
        }
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

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManagerW(string? lpMachineName, string? lpDatabaseName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumServicesStatusExW(
        IntPtr hSCManager,
        int infoLevel,
        uint dwServiceType,
        uint dwServiceState,
        IntPtr lpServices,
        uint cbBufSize,
        out uint pcbBytesNeeded,
        out uint lpServicesReturned,
        ref uint lpResumeHandle,
        string? pszGroupName);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr hSCObject);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
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

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ENUM_SERVICE_STATUS_PROCESSW
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string lpServiceName;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string lpDisplayName;
        public SERVICE_STATUS_PROCESS ServiceStatusProcess;
    }
}
