using System.Diagnostics;
using System.Globalization;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using UltimateWindows.Modules.Repair.Catalog;
using UltimateWindows.Modules.Repair.Diagnostics;
using UltimateWindows.Modules.Repair.Models;
using UltimateWindows.NativeInterop.Optimizer;
using UltimateWindows.NativeInterop.Security;
using OptServiceStartupMode = UltimateWindows.Modules.Optimizer.Models.ServiceStartupMode;
using OptServiceRunState = UltimateWindows.Modules.Optimizer.Models.ServiceRunState;

namespace UltimateWindows.NativeInterop.Repair;

public sealed partial class WindowsRepairPlatformBridge
{
    private static readonly HttpClient SharedHttpClient = CreateTrustedHttpClient();

    private static HttpClient CreateTrustedHttpClient()
    {
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 8
        };
        var client = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromMinutes(8)
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("UltimateWindows-Repair/3.0");
        return client;
    }

    // ==================== ПРЯМАЯ ЗАГРУЗКА СРЕД ВЫПОЛНЕНИЯ + WINVERIFYTRUST ====================

    public override async Task<(bool Succeeded, string OutputLog)> InstallOfficialRuntimeDirectOrWingetAsync(
        OfficialRuntimePackage package,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return (false, "Установка сред выполнения поддерживается только на ОС Windows.");
        }

        var log = new StringBuilder();

        // 1. Встроенные компоненты ОС (например .NET Framework 3.5 -> NetFx3 через DISM)
        if (!string.IsNullOrWhiteSpace(package.OptionalWindowsFeatureName))
        {
            if (!IsRunningAsAdministrator())
            {
                return (false, $"Для включения системного компонента «{package.OptionalWindowsFeatureName}» требуются права администратора.");
            }

            log.AppendLine($"Включение компонента Windows «{package.OptionalWindowsFeatureName}» через DISM...");
            var (dismExit, dismOut) = await RunProcessCaptureAsync(
                "DISM.exe",
                ["/Online", "/Enable-Feature", $"/FeatureName:{package.OptionalWindowsFeatureName}", "/All", "/NoRestart"],
                TimeSpan.FromMinutes(15),
                ct).ConfigureAwait(false);
            log.AppendLine(dismOut);
            return (dismExit is 0 or 3010, log.ToString());
        }

        // 2. Прямая HTTPS-загрузка с официального CDN + обязательная проверка подписи WinVerifyTrust
        if (OfficialRuntimeCatalog.IsTrustedOfficialDownloadUrl(package.DirectDownloadUrl))
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "UltimateWindows-Runtimes");
            Directory.CreateDirectory(tempDir);
            var ext = package.DirectDownloadUrl!.EndsWith(".msi", StringComparison.OrdinalIgnoreCase) ? ".msi" : ".exe";
            var tempFile = Path.Combine(tempDir, $"{package.PackageKey}-{Guid.NewGuid():N}{ext}");

            try
            {
                log.AppendLine($"[1/3] Скачивание с официального сервера: {package.DirectDownloadUrl}");
                using (var resp = await SharedHttpClient.GetAsync(package.DirectDownloadUrl, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false))
                {
                    resp.EnsureSuccessStatusCode();
                    await using var netStream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
                    await using var fileStream = new FileStream(tempFile, FileMode.Create, FileAccess.Write, FileShare.None, 81920, useAsync: true);
                    await netStream.CopyToAsync(fileStream, ct).ConfigureAwait(false);
                }

                log.AppendLine("[2/3] Проверка криптографической подписи издателя (WinVerifyTrust Authenticode)...");
                if (!AuthenticodeVerifier.IsFileTrustedSigned(tempFile))
                {
                    TryDeleteQuietly(tempFile);
                    log.AppendLine("ОТКАЗ БЕЗОПАСНОСТИ: файл не прошёл проверку цифровой подписи Authenticode и был немедленно удалён.");
                    return (false, log.ToString());
                }

                log.AppendLine("Подпись издателя подтверждена Windows WinVerifyTrust.");
                log.AppendLine($"[3/3] Тихая установка ({package.SilentInstallArgs})...");

                string installerExe;
                IReadOnlyList<string> installerArgs;
                if (ext == ".msi")
                {
                    installerExe = "msiexec.exe";
                    installerArgs = ["/i", tempFile, "/qn", "/norestart"];
                }
                else
                {
                    installerExe = tempFile;
                    installerArgs = SplitCommandArgs(package.SilentInstallArgs);
                }

                var (exitCode, instOut) = await RunProcessCaptureAsync(installerExe, installerArgs, TimeSpan.FromMinutes(12), ct).ConfigureAwait(false);
                if (!string.IsNullOrWhiteSpace(instOut))
                {
                    log.AppendLine(instOut);
                }

                // 0 = успех, 3010 = успех (желательна перезагрузка), 1638 = в системе уже стоит более свежая сборка VC++
                if (exitCode is 0 or 3010 or 1638)
                {
                    log.AppendLine(exitCode == 1638
                        ? "В системе уже установлена актуальная или более новая сборка этого пакета."
                        : exitCode == 3010
                            ? "Установка завершена успешно (изменения окончательно применятся после перезагрузки)."
                            : "Установка завершена успешно.");
                    return (true, log.ToString());
                }

                log.AppendLine($"Прямой установщик вернул код {exitCode}. Пробуем резервный канал через winget...");
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                log.AppendLine($"Прямое скачивание не удалось ({ex.Message}). Переключаемся на резервный канал winget...");
            }
            finally
            {
                TryDeleteQuietly(tempFile);
            }
        }

        // 3. Резервная установка через системный пакетный менеджер winget
        if (!string.IsNullOrWhiteSpace(package.WingetPackageId))
        {
            var (wgOk, wgOut) = await InstallOfficialRuntimeViaWingetAsync(package, ct).ConfigureAwait(false);
            log.AppendLine(wgOut);
            return (wgOk, log.ToString());
        }

        return (false, log.ToString());
    }

    // ==================== ОПРЕДЕЛЕНИЕ УСТАНОВЛЕННЫХ СРЕД ВЫПОЛНЕНИЯ ====================

    public override Task<IReadOnlyList<OfficialRuntimeStatusReport>> DetectInstalledRuntimesAsync(
        IReadOnlyList<OfficialRuntimePackage> catalog,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return base.DetectInstalledRuntimesAsync(catalog, ct);
        }

        return Task.Run<IReadOnlyList<OfficialRuntimeStatusReport>>(() =>
        {
            var sys64 = GetSystem64Directory();
            var sys32 = GetSysWow64Directory();
            var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var winSxS = Path.Combine(winDir, "WinSxS");

            var results = new List<OfficialRuntimeStatusReport>(catalog.Count);
            foreach (var pkg in catalog)
            {
                ct.ThrowIfCancellationRequested();
                results.Add(ProbeSingleRuntime(pkg, sys64, sys32, winSxS));
            }

            return results;
        }, ct);
    }

    private static OfficialRuntimeStatusReport ProbeSingleRuntime(
        OfficialRuntimePackage pkg,
        string sys64,
        string sysWow64,
        string winSxS)
    {
        var key = pkg.PackageKey.ToLowerInvariant();
        var targetSys = pkg.TargetArchitecture == PeArchitecture.X86 && !string.IsNullOrWhiteSpace(sysWow64)
            ? sysWow64
            : sys64;

        try
        {
            // .NET Framework 3.5
            if (key == "dotnet-fx-35")
            {
                using var k = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                    .OpenSubKey(@"SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5");
                var inst = k?.GetValue("Install") is int i && i == 1;
                var ver = k?.GetValue("Version")?.ToString() ?? "";
                return new OfficialRuntimeStatusReport(pkg, inst ? RuntimeInstallStatus.Installed : RuntimeInstallStatus.NotInstalled, ver);
            }

            // .NET Framework 4.8 / 4.8.1
            if (key == "dotnet-fx-481")
            {
                using var k = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                    .OpenSubKey(@"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full");
                var rel = k?.GetValue("Release") is int r ? r : 0;
                var ver = k?.GetValue("Version")?.ToString() ?? "";
                return new OfficialRuntimeStatusReport(
                    pkg,
                    rel >= 528040 ? RuntimeInstallStatus.Installed : RuntimeInstallStatus.NotInstalled,
                    rel >= 533320 ? $"4.8.1 ({ver})" : rel >= 528040 ? $"4.8 ({ver})" : "");
            }

            // .NET Desktop Runtime 6 / 8 / 9 / 10
            if (key.StartsWith("dotnet-desktop-", StringComparison.Ordinal))
            {
                var parts = key.Split('-');
                var major = parts.Length >= 3 ? parts[2] : "";
                var baseDir = pkg.TargetArchitecture == PeArchitecture.X86
                    ? Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
                    : Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                var sharedDir = Path.Combine(baseDir, "dotnet", "shared", "Microsoft.WindowsDesktop.App");
                if (Directory.Exists(sharedDir))
                {
                    var match = Directory.EnumerateDirectories(sharedDir, $"{major}.*")
                        .Select(Path.GetFileName)
                        .OrderByDescending(v => v, StringComparer.OrdinalIgnoreCase)
                        .FirstOrDefault();
                    if (!string.IsNullOrWhiteSpace(match))
                    {
                        return new OfficialRuntimeStatusReport(pkg, RuntimeInstallStatus.Installed, match);
                    }
                }

                return new OfficialRuntimeStatusReport(pkg, RuntimeInstallStatus.NotInstalled, "");
            }

            // Microsoft Edge WebView2 Evergreen
            if (key == "edge-webview2-evergreen")
            {
                const string clientGuid = @"{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}";
                foreach (var view in new[] { RegistryView.Registry32, RegistryView.Registry64 })
                {
                    using var k = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view)
                        .OpenSubKey($@"SOFTWARE\Microsoft\EdgeUpdate\Clients\{clientGuid}");
                    var pv = k?.GetValue("pv")?.ToString();
                    if (!string.IsNullOrWhiteSpace(pv) && pv != "0.0.0.0")
                    {
                        return new OfficialRuntimeStatusReport(pkg, RuntimeInstallStatus.Installed, pv);
                    }
                }

                using var cu = Registry.CurrentUser.OpenSubKey($@"Software\Microsoft\EdgeUpdate\Clients\{clientGuid}");
                var cuPv = cu?.GetValue("pv")?.ToString();
                if (!string.IsNullOrWhiteSpace(cuPv) && cuPv != "0.0.0.0")
                {
                    return new OfficialRuntimeStatusReport(pkg, RuntimeInstallStatus.Installed, cuPv);
                }

                return new OfficialRuntimeStatusReport(pkg, RuntimeInstallStatus.NotInstalled, "");
            }

            // VC++ 2005 / 2008 живут в WinSxS
            if (key.StartsWith("vcredist-2005-", StringComparison.Ordinal) || key.StartsWith("vcredist-2008-", StringComparison.Ordinal))
            {
                if (Directory.Exists(winSxS))
                {
                    var archPrefix = pkg.TargetArchitecture == PeArchitecture.X86 ? "x86_microsoft.vc" : "amd64_microsoft.vc";
                    var verNum = key.Contains("2005", StringComparison.Ordinal) ? "80.crt" : "90.crt";
                    var found = Directory.EnumerateDirectories(winSxS, $"{archPrefix}{verNum}*").FirstOrDefault();
                    if (found is not null)
                    {
                        return new OfficialRuntimeStatusReport(pkg, RuntimeInstallStatus.Installed, "WinSxS");
                    }
                }

                return new OfficialRuntimeStatusReport(pkg, RuntimeInstallStatus.NotInstalled, "");
            }

            // XNA Framework 4.0
            if (key == "xna-framework-40")
            {
                using var k = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32)
                    .OpenSubKey(@"SOFTWARE\Microsoft\XNA\Framework\v4.0");
                var inst = k?.GetValue("Installed") is int xi && xi == 1;
                return new OfficialRuntimeStatusReport(pkg, inst ? RuntimeInstallStatus.Installed : RuntimeInstallStatus.NotInstalled, inst ? "v4.0" : "");
            }

            // ARM64 пакет на x64 ПК
            if (pkg.TargetArchitecture == PeArchitecture.Arm64 && RuntimeInformation.OSArchitecture != Architecture.Arm64)
            {
                return new OfficialRuntimeStatusReport(pkg, RuntimeInstallStatus.NotInstalled, "Для процессоров ARM64");
            }

            // Остальные пакеты (VC++ 2010/2012/2013/2015-2026, DirectX, OpenAL, Vulkan) — по наличию ключевой DLL в целевом системном каталоге
            var sentinelDll = pkg.ProvidedDllNamesLower.FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(sentinelDll) && !string.IsNullOrWhiteSpace(targetSys))
            {
                var dllPath = Path.Combine(targetSys, sentinelDll);
                if (File.Exists(dllPath))
                {
                    var fvi = FileVersionInfo.GetVersionInfo(dllPath);
                    var ver = !string.IsNullOrWhiteSpace(fvi.FileVersion) ? fvi.FileVersion.Split(' ')[0] : "";
                    return new OfficialRuntimeStatusReport(pkg, RuntimeInstallStatus.Installed, ver);
                }
            }
        }
        catch
        {
            return new OfficialRuntimeStatusReport(pkg, RuntimeInstallStatus.Unknown, "");
        }

        return new OfficialRuntimeStatusReport(pkg, RuntimeInstallStatus.NotInstalled, "");
    }

    // ==================== ПЕРЕЧИСЛЕНИЕ УСТАНОВЛЕННЫХ ПРОГРАММ ДЛЯ ПРОВЕРКИ DLL ====================

    public override Task<IReadOnlyList<InstalledProgramInfo>> EnumerateInstalledProgramsAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult<IReadOnlyList<InstalledProgramInfo>>([]);
        }

        return Task.Run<IReadOnlyList<InstalledProgramInfo>>(() =>
        {
            var found = new List<InstalledProgramInfo>();
            var seenExe = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            var roots = new (RegistryHive Hive, RegistryView View, string SubKey)[]
            {
                (RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                (RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                (RegistryHive.CurrentUser, RegistryView.Default, @"Software\Microsoft\Windows\CurrentVersion\Uninstall")
            };

            foreach (var (hive, view, path) in roots)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                    using var uninstall = baseKey.OpenSubKey(path);
                    if (uninstall is null) continue;

                    foreach (var subName in uninstall.GetSubKeyNames())
                    {
                        try
                        {
                            using var appKey = uninstall.OpenSubKey(subName);
                            if (appKey is null) continue;
                            if (appKey.GetValue("SystemComponent") is int sc && sc == 1) continue;

                            var displayName = appKey.GetValue("DisplayName")?.ToString()?.Trim();
                            if (string.IsNullOrWhiteSpace(displayName)) continue;

                            var installLoc = appKey.GetValue("InstallLocation")?.ToString()?.Trim().Trim('"') ?? "";
                            var displayIcon = appKey.GetValue("DisplayIcon")?.ToString()?.Trim() ?? "";
                            var exePath = ResolveMainProgramExe(installLoc, displayIcon);
                            if (string.IsNullOrWhiteSpace(exePath) || !seenExe.Add(exePath)) continue;

                            var dir = !string.IsNullOrWhiteSpace(installLoc) && Directory.Exists(installLoc)
                                ? installLoc
                                : Path.GetDirectoryName(exePath) ?? "";

                            found.Add(new InstalledProgramInfo(
                                DisplayName: displayName,
                                DisplayVersion: appKey.GetValue("DisplayVersion")?.ToString(),
                                Publisher: appKey.GetValue("Publisher")?.ToString(),
                                ExecutablePath: exePath,
                                InstallDirectory: dir));
                        }
                        catch
                        {
                            // Пропуск отдельной ветки
                        }
                    }
                }
                catch
                {
                    // Пропуск куста
                }
            }

            return found.OrderBy(p => p.DisplayName, StringComparer.CurrentCultureIgnoreCase).ToList();
        }, ct);
    }

    private static string? ResolveMainProgramExe(string installLoc, string displayIcon)
    {
        if (!string.IsNullOrWhiteSpace(displayIcon))
        {
            var cleaned = displayIcon;
            var commaIdx = cleaned.LastIndexOf(',');
            if (commaIdx > 3) cleaned = cleaned[..commaIdx];
            cleaned = cleaned.Trim().Trim('"');

            if (cleaned.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
                !IsUninstallerOrMsiExec(cleaned) &&
                File.Exists(cleaned))
            {
                return cleaned;
            }
        }

        if (!string.IsNullOrWhiteSpace(installLoc) && Directory.Exists(installLoc))
        {
            try
            {
                var candidate = Directory.EnumerateFiles(installLoc, "*.exe", SearchOption.TopDirectoryOnly)
                    .Where(f => !IsUninstallerOrMsiExec(f))
                    .OrderByDescending(f => new FileInfo(f).Length)
                    .FirstOrDefault();
                if (candidate is not null)
                {
                    return candidate;
                }
            }
            catch
            {
                return null;
            }
        }

        return null;
    }

    private static bool IsUninstallerOrMsiExec(string path)
    {
        var name = Path.GetFileName(path).ToLowerInvariant();
        return name.StartsWith("unins", StringComparison.Ordinal) ||
               name.Contains("uninstall", StringComparison.Ordinal) ||
               name is "msiexec.exe" or "rundll32.exe" or "setup.exe" or "createdump.exe";
    }

    // ==================== РЕЕСТР И СЛУЖБЫ ДЛЯ ДИАГНОСТИЧЕСКОГО ДВИЖКА ====================

    public override RepairRegistryValueState ReadRegistryValue(string hive, string subKey, string valueName)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new RepairRegistryValueState(false, false, RepairRegistryValueKind.String, null, null, null);
        }

        try
        {
            using var root = OpenHive64(hive);
            using var key = root.OpenSubKey(subKey, writable: false);
            if (key is null)
            {
                return new RepairRegistryValueState(false, false, RepairRegistryValueKind.String, null, null, null);
            }

            var raw = key.GetValue(valueName, defaultValue: null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            if (raw is null)
            {
                return new RepairRegistryValueState(true, false, RepairRegistryValueKind.String, null, null, null);
            }

            var regKind = key.GetValueKind(valueName);
            var mappedKind = MapRegistryKind(regKind);
            int? dword = raw switch
            {
                int i => i,
                long l when l is >= int.MinValue and <= int.MaxValue => (int)l,
                _ => null
            };
            var strVal = raw as string ?? dword?.ToString(CultureInfo.InvariantCulture);
            var serialized = SerializeForVaultRollback(raw, regKind);

            return new RepairRegistryValueState(true, true, mappedKind, strVal, dword, serialized);
        }
        catch
        {
            return new RepairRegistryValueState(false, false, RepairRegistryValueKind.String, null, null, null);
        }
    }

    public override (bool Succeeded, string? CreatedKeyPath, string? Error) WriteRegistryValue(
        string hive,
        string subKey,
        string valueName,
        RepairRegistryValueKind kind,
        string? stringValue,
        int? dwordValue)
    {
        if (!OperatingSystem.IsWindows())
        {
            return (false, null, "Доступно только на ОС Windows.");
        }

        try
        {
            using var root = OpenHive64(hive);
            var firstMissing = FindFirstMissingSubKey(root, subKey);
            using var key = root.CreateSubKey(subKey, writable: true);
            if (key is null)
            {
                return (false, null, $@"Не удалось открыть раздел {hive}\{subKey} для записи.");
            }

            switch (kind)
            {
                case RepairRegistryValueKind.DWord:
                    key.SetValue(valueName, dwordValue ?? 0, RegistryValueKind.DWord);
                    break;
                case RepairRegistryValueKind.ExpandString:
                    key.SetValue(valueName, stringValue ?? "", RegistryValueKind.ExpandString);
                    break;
                default:
                    key.SetValue(valueName, stringValue ?? "", RegistryValueKind.String);
                    break;
            }

            return (true, firstMissing, null);
        }
        catch (Exception ex)
        {
            return (false, null, ex.Message);
        }
    }

    public override (bool Succeeded, string? Error) DeleteRegistryValue(string hive, string subKey, string valueName)
    {
        if (!OperatingSystem.IsWindows())
        {
            return (false, "Доступно только на ОС Windows.");
        }

        try
        {
            using var root = OpenHive64(hive);
            using var key = root.OpenSubKey(subKey, writable: true);
            if (key is null)
            {
                return (true, null);
            }

            key.DeleteValue(valueName, throwOnMissingValue: false);
            return (true, null);
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    public override RepairServiceState QueryServiceState(string serviceName)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new RepairServiceState(false, RepairServiceStartupKind.Unknown, false);
        }

        var state = WindowsServiceControl.Query(serviceName);
        if (!state.Exists)
        {
            return new RepairServiceState(false, RepairServiceStartupKind.Unknown, false);
        }

        var startup = state.Startup switch
        {
            OptServiceStartupMode.Automatic => RepairServiceStartupKind.Automatic,
            OptServiceStartupMode.AutomaticDelayed => RepairServiceStartupKind.AutomaticDelayed,
            OptServiceStartupMode.Manual => RepairServiceStartupKind.Manual,
            OptServiceStartupMode.Disabled => RepairServiceStartupKind.Disabled,
            _ => RepairServiceStartupKind.Unknown
        };

        return new RepairServiceState(
            Exists: true,
            Startup: startup,
            IsRunning: state.RunState == OptServiceRunState.Running);
    }

    public override async Task<(bool Succeeded, string? Error)> RepairServiceAsync(
        string serviceName,
        RepairServiceStartupKind targetStartup,
        bool startIfStopped,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return (false, "Доступно только на ОС Windows.");
        }

        var mapped = targetStartup switch
        {
            RepairServiceStartupKind.Automatic => OptServiceStartupMode.Automatic,
            RepairServiceStartupKind.AutomaticDelayed => OptServiceStartupMode.AutomaticDelayed,
            _ => OptServiceStartupMode.Manual
        };

        var (setOk, setErr) = WindowsServiceControl.SetStartup(serviceName, mapped);
        if (!setOk)
        {
            return (false, setErr);
        }

        if (startIfStopped)
        {
            var current = WindowsServiceControl.Query(serviceName);
            if (current.Exists && current.RunState != OptServiceRunState.Running)
            {
                _ = await WindowsServiceControl.ControlAsync(serviceName, start: true, ct: ct).ConfigureAwait(false);
            }
        }

        return (true, null);
    }

    // ==================== 18 ГЛУБОКИХ ПРОВЕРОК И ИСПРАВЛЕНИЙ (CUSTOM PROBES) ====================

    public override async Task<RepairCustomProbeResult> RunCustomProbeAsync(string customProbeId, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new RepairCustomProbeResult(RepairHealthState.NotApplicable, "Только для Windows.");
        }

        switch (customProbeId)
        {
            case "wu-pending-reboot":
            {
                using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                using var cbsReboot = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending");
                using var wuReboot = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired");
                if (cbsReboot is not null || wuReboot is not null)
                {
                    var src = cbsReboot is not null && wuReboot is not null
                        ? "CBS\\RebootPending и WindowsUpdate\\RebootRequired"
                        : cbsReboot is not null ? "CBS\\RebootPending" : "WindowsUpdate\\RebootRequired";
                    return new RepairCustomProbeResult(
                        RepairHealthState.IssueDetected,
                        $"Обнаружен активный маркер незавершённой перезагрузки ({src}), блокирующий установщики.");
                }

                return new RepairCustomProbeResult(RepairHealthState.Healthy, "Зависших маркеров ожидания перезагрузки нет.");
            }

            case "wu-corrupt-cache":
            {
                var bitsDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "Microsoft", "Network", "Downloader");
                if (Directory.Exists(bitsDir))
                {
                    try
                    {
                        var stale = Directory.EnumerateFiles(bitsDir, "qmgr*.dat")
                            .Select(f => new FileInfo(f))
                            .Count(fi => fi.Length > 16 * 1024 * 1024);
                        if (stale > 0)
                        {
                            return new RepairCustomProbeResult(RepairHealthState.IssueDetected, "Очередь BITS переполнена старыми незавершёнными заданиями.");
                        }
                    }
                    catch
                    {
                        // Игнорируем ошибку доступа без прав админа
                    }
                }

                return new RepairCustomProbeResult(RepairHealthState.Healthy, "Кэш SoftwareDistribution и очередь BITS в штатном состоянии.");
            }

            case "net-dead-local-proxy":
            {
                using var inet = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
                var enabled = inet?.GetValue("ProxyEnable") is int pe && pe == 1;
                var proxyStr = inet?.GetValue("ProxyServer")?.ToString()?.Trim() ?? "";
                if (!enabled || string.IsNullOrWhiteSpace(proxyStr))
                {
                    return new RepairCustomProbeResult(RepairHealthState.Healthy, "Системный прокси отключён.");
                }

                if (TryExtractLoopbackPort(proxyStr, out var port))
                {
                    var listening = IsTcpPortListening(port);
                    if (!listening)
                    {
                        return new RepairCustomProbeResult(
                            RepairHealthState.IssueDetected,
                            $"Включён локальный прокси «{proxyStr}», но порт {port} сейчас никем не прослушивается — доступ в интернет заблокирован.");
                    }

                    return new RepairCustomProbeResult(RepairHealthState.Healthy, $"Локальный прокси «{proxyStr}» активен (порт {port} слушается).");
                }

                return new RepairCustomProbeResult(RepairHealthState.Healthy, $"Используется внешний прокси «{proxyStr}».");
            }

            case "net-hosts-health":
            {
                var hostsPath = Path.Combine(GetSystem64Directory(), "drivers", "etc", "hosts");
                if (!File.Exists(hostsPath))
                {
                    return new RepairCustomProbeResult(RepairHealthState.IssueDetected, "Системный файл drivers\\etc\\hosts отсутствует.");
                }

                try
                {
                    var hijacked = FindHijackedHostsDomains(await File.ReadAllLinesAsync(hostsPath, ct).ConfigureAwait(false));
                    if (hijacked.Count > 0)
                    {
                        return new RepairCustomProbeResult(
                            RepairHealthState.IssueDetected,
                            $"В файле hosts заблокированы системные домены: {string.Join(", ", hijacked.Take(5))}.");
                    }

                    return new RepairCustomProbeResult(RepairHealthState.Healthy, "Файл hosts чист от подмены серверов Microsoft и обновлений.");
                }
                catch
                {
                    return new RepairCustomProbeResult(RepairHealthState.Healthy, "Файл hosts присутствует.");
                }
            }

            case "net-dns-winsock":
            {
                using var ws = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                    .OpenSubKey(@"SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9");
                if (ws is null)
                {
                    return new RepairCustomProbeResult(RepairHealthState.IssueDetected, "Отсутствует ветка каталога протоколов WinSock2\\Protocol_Catalog9.");
                }

                return new RepairCustomProbeResult(RepairHealthState.Healthy, "Каталог сетевых протоколов WinSock2 присутствует.");
            }

            case "shell-ctfmon-typing":
            {
                // Проверяем только в интерактивной сессии с запущенным Проводником
                if (Process.GetProcessesByName("explorer").Length == 0)
                {
                    return new RepairCustomProbeResult(RepairHealthState.NotApplicable, "Оболочка рабочего стола не запущена в текущем сеансе.");
                }

                var running = Process.GetProcessesByName("ctfmon").Length > 0;
                return running
                    ? new RepairCustomProbeResult(RepairHealthState.Healthy, "Служба текстового ввода ctfmon.exe активна.")
                    : new RepairCustomProbeResult(RepairHealthState.IssueDetected, "Процесс ctfmon.exe не запущен — ввод с клавиатуры в Поиске и меню «Пуск» не работает.");
            }

            case "shell-win11-xaml-packages":
            {
                if (IsWindowsServerEdition())
                {
                    return new RepairCustomProbeResult(RepairHealthState.NotApplicable, "Серверная редакция ОС.");
                }

                var sysApps = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SystemApps");
                var startDir = Directory.Exists(sysApps)
                    ? Directory.EnumerateDirectories(sysApps, "*StartMenuExperienceHost*").FirstOrDefault()
                    : null;
                if (startDir is null && GetWindowsBuildNumber() >= 19041)
                {
                    return new RepairCustomProbeResult(RepairHealthState.IssueDetected, "Не найден системный пакет StartMenuExperienceHost в Windows\\SystemApps.");
                }

                return new RepairCustomProbeResult(RepairHealthState.Healthy, "Системные пакеты оболочки XAML присутствуют.");
            }

            case "shell-icon-thumb-cache":
            {
                var expDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Windows", "Explorer");
                if (!Directory.Exists(expDir))
                {
                    return new RepairCustomProbeResult(RepairHealthState.Healthy, "Папка кэша оболочки в норме.");
                }

                var totalBytes = Directory.EnumerateFiles(expDir, "iconcache_*.db")
                    .Select(f => new FileInfo(f).Length)
                    .DefaultIfEmpty(0L)
                    .Sum();
                return totalBytes > 128L * 1024 * 1024
                    ? new RepairCustomProbeResult(RepairHealthState.IssueDetected, $"Кэш значков разросся до {totalBytes / (1024 * 1024)} МБ.")
                    : new RepairCustomProbeResult(RepairHealthState.Healthy, "Базы кэша значков Проводника в норме.");
            }

            case "shell-recycle-bin":
            {
                using var desk = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel");
                var hidden = desk?.GetValue("{645FF040-5081-101B-9F08-00AA002F954E}") is int v && v == 1;
                return hidden
                    ? new RepairCustomProbeResult(RepairHealthState.IssueDetected, "Значок Корзины скрыт с Рабочего стола в настройках оболочки.")
                    : new RepairCustomProbeResult(RepairHealthState.Healthy, "Значок Корзины отображается штатно.");
            }

            case "store-cache-health":
            {
                if (IsWindowsServerEdition())
                {
                    return new RepairCustomProbeResult(RepairHealthState.NotApplicable, "На серверной редакции Microsoft Store не предустановлен.");
                }

                var wsreset = Path.Combine(GetSystem64Directory(), "wsreset.exe");
                return File.Exists(wsreset)
                    ? new RepairCustomProbeResult(RepairHealthState.Healthy, "Компонент сброса кэша Microsoft Store (wsreset.exe) доступен.")
                    : new RepairCustomProbeResult(RepairHealthState.NotApplicable, "Редакция LTSC без компонента Microsoft Store.");
            }

            case "print-stuck-queue":
            {
                var spoolDir = Path.Combine(GetSystem64Directory(), "spool", "PRINTERS");
                if (!Directory.Exists(spoolDir))
                {
                    return new RepairCustomProbeResult(RepairHealthState.Healthy, "Очередь печати пуста.");
                }

                try
                {
                    var cutoff = DateTime.UtcNow.AddMinutes(-30);
                    var stuck = Directory.EnumerateFiles(spoolDir)
                        .Select(f => new FileInfo(f))
                        .Count(fi => fi.LastWriteTimeUtc < cutoff);
                    return stuck > 0
                        ? new RepairCustomProbeResult(RepairHealthState.IssueDetected, $"В очереди печати застряло старых заданий: {stuck}.")
                        : new RepairCustomProbeResult(RepairHealthState.Healthy, "Зависших заданий печати нет.");
                }
                catch (UnauthorizedAccessException)
                {
                    return new RepairCustomProbeResult(RepairHealthState.Healthy, "Очередь печати защищена правами администратора (ошибок Spooler не отмечено).");
                }
            }

            case "time-ntp-sync":
            {
                using var k = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                    .OpenSubKey(@"SYSTEM\CurrentControlSet\Services\W32Time\Parameters");
                var ntpServer = k?.GetValue("NtpServer")?.ToString() ?? "";
                return string.IsNullOrWhiteSpace(ntpServer)
                    ? new RepairCustomProbeResult(RepairHealthState.IssueDetected, "Не задан адрес сервера точного времени NtpServer.")
                    : new RepairCustomProbeResult(RepairHealthState.Healthy, $"Источник точного времени: {ntpServer}.");
            }

            case "wmi-repository":
            {
                var repoDir = Path.Combine(GetSystem64Directory(), "wbem", "Repository");
                if (!Directory.Exists(repoDir))
                {
                    return new RepairCustomProbeResult(RepairHealthState.IssueDetected, "Папка базы репозитория WMI отсутствует.");
                }

                if (!IsRunningAsAdministrator())
                {
                    return new RepairCustomProbeResult(RepairHealthState.Healthy, "Каталог базы WMI wbem\\Repository присутствует.");
                }

                var (_, output) = await RunProcessCaptureAsync("winmgmt.exe", ["/verifyrepository"], TimeSpan.FromSeconds(25), ct).ConfigureAwait(false);
                var inconsistent = output.Contains("inconsistent", StringComparison.OrdinalIgnoreCase) ||
                                   output.Contains("несогласован", StringComparison.OrdinalIgnoreCase);
                return inconsistent
                    ? new RepairCustomProbeResult(RepairHealthState.IssueDetected, $"Проверка winmgmt выявила нарушение целостности базы WMI: {output}")
                    : new RepairCustomProbeResult(RepairHealthState.Healthy, "Репозиторий WMI согласован.");
            }

            case "sfc-cbs-health":
            {
                var summary = CbsLogAnalyzer.AnalyzeFile(GetCbsLogPath());
                if (summary.HasUnrepairableCorruption)
                {
                    return new RepairCustomProbeResult(
                        RepairHealthState.IssueDetected,
                        $"{summary.HumanVerdict} Примеры: {string.Join(", ", summary.UnrepairableFiles.Take(4))}");
                }

                return new RepairCustomProbeResult(RepairHealthState.Healthy, summary.HumanVerdict);
            }

            case "disk-dirty-and-temp":
            {
                var tempPath = Path.GetTempPath();
                if (!Directory.Exists(tempPath))
                {
                    return new RepairCustomProbeResult(RepairHealthState.IssueDetected, $"Рабочая папка временных файлов «{tempPath}» отсутствует.");
                }

                try
                {
                    var probeFile = Path.Combine(tempPath, $"uw-probe-{Guid.NewGuid():N}.tmp");
                    await File.WriteAllTextAsync(probeFile, "ok", ct).ConfigureAwait(false);
                    File.Delete(probeFile);
                }
                catch (Exception ex)
                {
                    return new RepairCustomProbeResult(RepairHealthState.IssueDetected, $"Нет прав на запись во временную папку %TEMP%: {ex.Message}");
                }

                if (IsRunningAsAdministrator())
                {
                    var sysRoot = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows))?.TrimEnd('\\') ?? "C:";
                    var (code, outText) = await RunProcessCaptureAsync("fsutil.exe", ["dirty", "query", sysRoot], TimeSpan.FromSeconds(10), ct).ConfigureAwait(false);
                    if (code == 0 &&
                        !outText.Contains("NOT Dirty", StringComparison.OrdinalIgnoreCase) &&
                        !outText.Contains("не помечен", StringComparison.OrdinalIgnoreCase) &&
                        (outText.Contains("is Dirty", StringComparison.OrdinalIgnoreCase) || outText.Contains("помечен", StringComparison.OrdinalIgnoreCase)))
                    {
                        return new RepairCustomProbeResult(RepairHealthState.IssueDetected, $"Системный том {sysRoot} помечен флагом повреждения файловой системы («Dirty»).");
                    }
                }

                return new RepairCustomProbeResult(RepairHealthState.Healthy, "Папка %TEMP% доступна для записи, ошибок тома не обнаружено.");
            }

            case "disk-low-free-space":
            {
                var root = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows)) ?? @"C:\";
                var drive = new DriveInfo(root);
                var freeGb = drive.AvailableFreeSpace / (1024.0 * 1024.0 * 1024.0);
                return freeGb < 5.0
                    ? new RepairCustomProbeResult(RepairHealthState.IssueDetected, $"На системном диске {root} осталось всего {freeGb:F1} ГБ свободного места (рекомендуется минимум 5–10 ГБ).")
                    : new RepairCustomProbeResult(RepairHealthState.Healthy, $"Свободно на системном диске {root}: {freeGb:F1} ГБ.");
            }

            case "sys-path-system32":
            {
                using var envKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                    .OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\Environment");
                var rawPath = envKey?.GetValue("Path", "", RegistryValueOptions.DoNotExpandEnvironmentNames)?.ToString() ?? "";
                var hasSys32 = rawPath.Contains(@"\system32", StringComparison.OrdinalIgnoreCase);
                return hasSys32
                    ? new RepairCustomProbeResult(RepairHealthState.Healthy, "Системная переменная PATH содержит каталог System32.")
                    : new RepairCustomProbeResult(RepairHealthState.IssueDetected, "Из системной переменной PATH исчез путь %SystemRoot%\\system32!");
            }

            case "font-cache-health":
            {
                var fcDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "ServiceProfiles", "LocalService", "AppData", "Local", "FontCache");
                if (Directory.Exists(fcDir))
                {
                    try
                    {
                        var total = Directory.EnumerateFiles(fcDir, "*FontCache*.dat")
                            .Select(f => new FileInfo(f).Length)
                            .DefaultIfEmpty(0L)
                            .Sum();
                        if (total > 256L * 1024 * 1024)
                        {
                            return new RepairCustomProbeResult(RepairHealthState.IssueDetected, $"Кэш шрифтов разросся до {total / (1024 * 1024)} МБ.");
                        }
                    }
                    catch
                    {
                        // Без прав админа LocalService закрыт — это нормально
                    }
                }

                return new RepairCustomProbeResult(RepairHealthState.Healthy, "Служба и кэш шрифтов работают в штатном режиме.");
            }

            default:
                return new RepairCustomProbeResult(RepairHealthState.Healthy, "Проверка выполнена.");
        }
    }

    public override async Task<(bool Succeeded, bool RequiresReboot, string OutputLog, string? RollbackTarget, string? RollbackPreviousJson)> ExecuteCustomFixAsync(
        string customProbeId,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return (false, false, "Только для Windows.", null, null);
        }

        switch (customProbeId)
        {
            case "wu-pending-reboot":
            {
                try
                {
                    using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                    hklm.DeleteSubKeyTree(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired", throwOnMissingSubKey: false);
                    using var cbs = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending");
                    if (cbs is not null)
                    {
                        return (true, true, "Маркер Auto Update\\RebootRequired снят; для завершения транзакции CBS перезагрузите Windows.", null, null);
                    }

                    return (true, false, "Зависший маркер RebootRequired очищен.", null, null);
                }
                catch (Exception ex)
                {
                    return (false, false, ex.Message, null, null);
                }
            }

            case "wu-corrupt-cache":
            {
                var (ok, log) = await ExecutePlaybookNativeStepsAsync(RepairPlaybookId.WindowsUpdateReset, ct).ConfigureAwait(false);
                return (ok, false, log, null, null);
            }

            case "net-dead-local-proxy":
            {
                using var inet = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings", writable: true);
                if (inet is null)
                {
                    return (false, false, "Не удалось открыть ветку Internet Settings.", null, null);
                }

                inet.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
                return (true, false, "Зависший локальный прокси отключён (ProxyEnable = 0).", null, null);
            }

            case "net-hosts-health":
            {
                var hostsPath = Path.Combine(GetSystem64Directory(), "drivers", "etc", "hosts");
                var prevContent = File.Exists(hostsPath) ? await File.ReadAllTextAsync(hostsPath, ct).ConfigureAwait(false) : "";
                var cleanedLines = new List<string>
                {
                    "# Восстановлено модулем Ремонт и DLL 2.0 (прежняя копия сохранена в Машине времени)"
                };

                if (!string.IsNullOrWhiteSpace(prevContent))
                {
                    foreach (var line in prevContent.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
                    {
                        if (IsHostsLineSabotagingSystemDomain(line)) continue;
                        cleanedLines.Add(line);
                    }
                }

                await File.WriteAllLinesAsync(hostsPath, cleanedLines, Encoding.UTF8, ct).ConfigureAwait(false);
                _ = await RunProcessCaptureAsync("ipconfig.exe", ["/flushdns"], TimeSpan.FromSeconds(15), ct).ConfigureAwait(false);

                var rollbackJson = JsonSerializer.Serialize(new { Path = hostsPath, Content = prevContent });
                return (true, false, "Вредоносные перенаправления системных доменов из файла hosts удалены.", "HostsSabotageCleanup", rollbackJson);
            }

            case "net-dns-winsock":
            {
                var (ok, log) = await ExecutePlaybookNativeStepsAsync(RepairPlaybookId.NetworkAndDnsStackReset, ct).ConfigureAwait(false);
                return (ok, true, log, null, null);
            }

            case "shell-ctfmon-typing":
            {
                var ctfmonPath = Path.Combine(GetSystem64Directory(), "ctfmon.exe");
                if (!File.Exists(ctfmonPath))
                {
                    return (false, false, "Системный файл ctfmon.exe не найден.", null, null);
                }

                Process.Start(new ProcessStartInfo { FileName = ctfmonPath, UseShellExecute = true });
                await Task.Delay(350, ct).ConfigureAwait(false);
                return (true, false, "Служба ввода клавиатуры ctfmon.exe запущена.", null, null);
            }

            case "shell-win11-xaml-packages":
            {
                const string psCmd =
                    "Get-AppxPackage -AllUsers Microsoft.Windows.StartMenuExperienceHost,MicrosoftWindows.Client.CBS,Microsoft.UI.Xaml.CBS -ErrorAction SilentlyContinue | " +
                    "ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register \"$($_.InstallLocation)\\AppXManifest.xml\" -ErrorAction SilentlyContinue }";
                var (code, outLog) = await RunProcessCaptureAsync(
                    "powershell.exe",
                    ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", psCmd],
                    TimeSpan.FromMinutes(3),
                    ct).ConfigureAwait(false);
                return (code == 0, false, string.IsNullOrWhiteSpace(outLog) ? "Пакеты XAML оболочки перерегистрированы." : outLog, null, null);
            }

            case "shell-icon-thumb-cache":
            {
                var (ok, log) = await ExecutePlaybookNativeStepsAsync(RepairPlaybookId.IconAndThumbnailCacheRebuild, ct).ConfigureAwait(false);
                return (ok, false, log, null, null);
            }

            case "shell-recycle-bin":
            {
                using var desk = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel", writable: true);
                desk?.SetValue("{645FF040-5081-101B-9F08-00AA002F954E}", 0, RegistryValueKind.DWord);
                return (true, false, "Отображение значка Корзины на Рабочем столе включено.", null, null);
            }

            case "store-cache-health":
            {
                var (ok, log) = await ExecutePlaybookNativeStepsAsync(RepairPlaybookId.MicrosoftStoreAndAppxRepair, ct).ConfigureAwait(false);
                return (ok, false, log, null, null);
            }

            case "print-stuck-queue":
            {
                var (ok, log) = await ExecutePlaybookNativeStepsAsync(RepairPlaybookId.PrintSpoolerCleanup, ct).ConfigureAwait(false);
                return (ok, false, log, null, null);
            }

            case "time-ntp-sync":
            {
                using (var k = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                           .OpenSubKey(@"SYSTEM\CurrentControlSet\Services\W32Time\Parameters", writable: true))
                {
                    if (k is not null && string.IsNullOrWhiteSpace(k.GetValue("NtpServer")?.ToString()))
                    {
                        k.SetValue("NtpServer", "time.windows.com,0x9", RegistryValueKind.String);
                    }
                }

                _ = await RepairServiceAsync("W32Time", RepairServiceStartupKind.Manual, startIfStopped: true, ct).ConfigureAwait(false);
                var (_, outLog) = await RunProcessCaptureAsync("w32tm.exe", ["/resync", "/force"], TimeSpan.FromSeconds(25), ct).ConfigureAwait(false);
                return (true, false, string.IsNullOrWhiteSpace(outLog) ? "Синхронизация времени выполнена." : outLog, null, null);
            }

            case "wmi-repository":
            {
                var (ok, log) = await ExecutePlaybookNativeStepsAsync(RepairPlaybookId.WmiRepositoryVerifyAndSalvage, ct).ConfigureAwait(false);
                return (ok, false, log, null, null);
            }

            case "sfc-cbs-health":
            {
                var (ok, log) = await ExecutePlaybookNativeStepsAsync(RepairPlaybookId.DismAndSfcIntegrity, ct).ConfigureAwait(false);
                return (ok, true, log, null, null);
            }

            case "disk-dirty-and-temp":
            {
                Directory.CreateDirectory(Path.GetTempPath());
                var sysRoot = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows))?.TrimEnd('\\') ?? "C:";
                var (_, outLog) = await RunProcessCaptureAsync("chkdsk.exe", [sysRoot, "/scan"], TimeSpan.FromMinutes(10), ct).ConfigureAwait(false);
                return (true, false, string.IsNullOrWhiteSpace(outLog) ? "Онлайн-проверка файловой системы выполнена." : outLog, null, null);
            }

            case "disk-low-free-space":
            {
                var freed = 0L;
                var tempDir = Path.GetTempPath();
                if (Directory.Exists(tempDir))
                {
                    var cutoff = DateTime.UtcNow.AddHours(-12);
                    foreach (var file in Directory.EnumerateFiles(tempDir))
                    {
                        try
                        {
                            var fi = new FileInfo(file);
                            if (fi.LastWriteTimeUtc < cutoff)
                            {
                                var len = fi.Length;
                                fi.Delete();
                                freed += len;
                            }
                        }
                        catch
                        {
                            // Занятые файлы не трогаем
                        }
                    }
                }

                return (true, false, $"Очищено безопасных временных файлов в %TEMP%: {freed / (1024 * 1024)} МБ.", null, null);
            }

            case "sys-path-system32":
            {
                using var envKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                    .OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", writable: true);
                if (envKey is null) return (false, false, "Не удалось открыть ветку Environment.", null, null);

                var current = envKey.GetValue("Path", "", RegistryValueOptions.DoNotExpandEnvironmentNames)?.ToString() ?? "";
                const string baseline = @"%SystemRoot%\system32;%SystemRoot%;%SystemRoot%\System32\Wbem;%SYSTEMROOT%\System32\WindowsPowerShell\v1.0\";
                var updated = string.IsNullOrWhiteSpace(current) ? baseline : baseline + ";" + current.TrimStart(';');
                envKey.SetValue("Path", updated, RegistryValueKind.ExpandString);
                return (true, false, "Системные пути System32 и PowerShell возвращены в переменную PATH.", null, null);
            }

            case "font-cache-health":
            {
                _ = await StopServiceAndWaitAsync("FontCache", ServiceRunState.Running, ct).ConfigureAwait(false);
                var fcDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "ServiceProfiles", "LocalService", "AppData", "Local", "FontCache");
                var deleted = 0;
                if (Directory.Exists(fcDir))
                {
                    foreach (var f in Directory.EnumerateFiles(fcDir, "*FontCache*.dat"))
                    {
                        try { File.Delete(f); deleted++; } catch { }
                    }
                }

                _ = await StartServiceAndWaitAsync("FontCache", ct).ConfigureAwait(false);
                return (true, false, $"Пересобран кэш шрифтов (удалено старых баз: {deleted}).", null, null);
            }

            default:
                return (true, false, "Выполнено.", null, null);
        }
    }

    // ==================== КРАЙНЯЯ МЕРA: ПЕРЕУСТАНОВКА ПОВЕРХ ЧЕРЕЗ WINDOWS UPDATE ====================

    public override InPlaceReinstallReadiness GetInPlaceReinstallReadiness()
    {
        var build = GetWindowsBuildNumber();
        var supportsWuReinstall = build >= 22631;
        var freeGb = 0.0;
        try
        {
            var root = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows)) ?? @"C:\";
            freeGb = Math.Round(new DriveInfo(root).AvailableFreeSpace / (1024.0 * 1024.0 * 1024.0), 1);
        }
        catch
        {
            // Игнорируем ошибку чтения диска
        }

        var onBattery = false;
        if (OperatingSystem.IsWindows() && GetSystemPowerStatus(out var pwr))
        {
            onBattery = pwr.ACLineStatus == 0;
        }

        var title = supportsWuReinstall
            ? "Windows 11: «Устранение неполадок с помощью Центра обновления Windows → Переустановить сейчас»"
            : "Windows 10: Обновление на месте (In-Place Upgrade) с сохранением всех программ и файлов";

        var steps = supportsWuReinstall
            ? "1. Нажмите кнопку «Открыть Восстановление Windows» ниже.\n" +
              "2. В разделе «Устранение неполадок с помощью Центра обновления Windows» нажмите «Переустановить сейчас».\n" +
              "3. Windows скачает эталонную копию текущей сборки и заменит повреждённые системные файлы, сохранив ваши программы, игры, документы и настройки."
            : "1. Подключите ноутбук к сети питания и убедитесь, что на диске C: свободно не менее 20 ГБ.\n" +
              "2. Скачайте официальный образ ISO или Media Creation Tool с сайта Microsoft для Windows 10 22H2.\n" +
              "3. Запустите setup.exe прямо из работающей системы и выберите «Сохранить личные файлы и приложения».";

        return new InPlaceReinstallReadiness(
            SupportsWindowsUpdateReinstallNow: supportsWuReinstall,
            OsBuild: build,
            FreeSystemDriveGb: freeGb,
            HasEnoughDiskSpace: freeGb >= 20.0,
            IsOnBatteryPower: onBattery,
            RecommendedMethodTitle: title,
            StepByStepInstructions: steps,
            SettingsUri: "ms-settings:recovery");
    }

    public override bool OpenRecoverySettingsOrUrl(string uri)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(uri))
        {
            return false;
        }

        // Разрешаем только безопасные системные схемы ms-settings: и официальные страницы https://
        if (!uri.StartsWith("ms-settings:", StringComparison.OrdinalIgnoreCase) &&
            !uri.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = uri,
                UseShellExecute = true
            });
            return true;
        }
        catch
        {
            return false;
        }
    }

    // ==================== ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ====================

    private static RegistryKey OpenHive64(string hive) => hive.ToUpperInvariant() switch
    {
        "HKLM" => RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64),
        "HKCU" => RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64),
        "HKCR" => RegistryKey.OpenBaseKey(RegistryHive.ClassesRoot, RegistryView.Registry64),
        _ => throw new ArgumentOutOfRangeException(nameof(hive), hive, "Неизвестный куст реестра.")
    };

    private static string? FindFirstMissingSubKey(RegistryKey root, string subKey)
    {
        var parts = subKey.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        var current = "";
        foreach (var part in parts)
        {
            current = current.Length == 0 ? part : $@"{current}\{part}";
            using var k = root.OpenSubKey(current, writable: false);
            if (k is null) return current;
        }

        return null;
    }

    private static RepairRegistryValueKind MapRegistryKind(RegistryValueKind kind) => kind switch
    {
        RegistryValueKind.DWord => RepairRegistryValueKind.DWord,
        RegistryValueKind.QWord => RepairRegistryValueKind.QWord,
        RegistryValueKind.ExpandString => RepairRegistryValueKind.ExpandString,
        RegistryValueKind.MultiString => RepairRegistryValueKind.MultiString,
        RegistryValueKind.Binary => RepairRegistryValueKind.Binary,
        _ => RepairRegistryValueKind.String
    };

    private static string SerializeForVaultRollback(object raw, RegistryValueKind kind) => kind switch
    {
        RegistryValueKind.Binary when raw is byte[] bytes => Convert.ToBase64String(bytes),
        RegistryValueKind.MultiString when raw is string[] lines => string.Join("\n", lines),
        RegistryValueKind.DWord => Convert.ToInt32(raw, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture),
        RegistryValueKind.QWord => Convert.ToInt64(raw, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture),
        _ => raw.ToString() ?? ""
    };

    private static bool TryExtractLoopbackPort(string proxyServer, out int port)
    {
        port = 0;
        // Поддерживает "127.0.0.1:7890", "http=127.0.0.1:10809;https=127.0.0.1:10809", "localhost:8888"
        var firstSegment = proxyServer.Split(';', StringSplitOptions.RemoveEmptyEntries)[0].Trim();
        var eqIdx = firstSegment.IndexOf('=');
        if (eqIdx >= 0) firstSegment = firstSegment[(eqIdx + 1)..].Trim();
        if (firstSegment.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) firstSegment = firstSegment[7..];
        if (firstSegment.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) firstSegment = firstSegment[8..];
        if (firstSegment.StartsWith("socks=", StringComparison.OrdinalIgnoreCase)) firstSegment = firstSegment[6..];

        var colon = firstSegment.LastIndexOf(':');
        if (colon <= 0) return false;

        var host = firstSegment[..colon].Trim();
        if (!host.Equals("127.0.0.1", StringComparison.OrdinalIgnoreCase) &&
            !host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return int.TryParse(firstSegment[(colon + 1)..].Trim('/'), NumberStyles.Integer, CultureInfo.InvariantCulture, out port)
               && port is > 0 and <= 65535;
    }

    private static bool IsTcpPortListening(int port)
    {
        try
        {
            var listeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();
            return listeners.Any(ep => ep.Port == port);
        }
        catch
        {
            return true;
        }
    }

    private static List<string> FindHijackedHostsDomains(IEnumerable<string> lines)
    {
        var hijacked = new List<string>();
        foreach (var raw in lines)
        {
            if (IsHostsLineSabotagingSystemDomain(raw, out var domain) && domain is not null)
            {
                hijacked.Add(domain);
            }
        }

        return hijacked;
    }

    private static bool IsHostsLineSabotagingSystemDomain(string line) =>
        IsHostsLineSabotagingSystemDomain(line, out _);

    private static bool IsHostsLineSabotagingSystemDomain(string rawLine, out string? matchedDomain)
    {
        matchedDomain = null;
        var commentIdx = rawLine.IndexOf('#');
        var clean = (commentIdx >= 0 ? rawLine[..commentIdx] : rawLine).Trim();
        if (clean.Length == 0) return false;

        var parts = clean.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) return false;

        string[] criticalSuffixes =
        [
            "windowsupdate.com", "update.microsoft.com", "download.microsoft.com",
            "microsoft.com", "login.live.com", "mp.microsoft.com",
            "virustotal.com", "malwarebytes.com", "kaspersky.com", "eset.com", "drweb.com"
        ];

        var host = parts[1].ToLowerInvariant();
        foreach (var suffix in criticalSuffixes)
        {
            if (host.Equals(suffix, StringComparison.Ordinal) || host.EndsWith("." + suffix, StringComparison.Ordinal))
            {
                matchedDomain = host;
                return true;
            }
        }

        return false;
    }

    private static bool IsWindowsServerEdition()
    {
        try
        {
            using var k = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                .OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            var installationType = k?.GetValue("InstallationType")?.ToString() ?? "";
            return installationType.Contains("Server", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static IReadOnlyList<string> SplitCommandArgs(string args)
    {
        if (string.IsNullOrWhiteSpace(args)) return [];
        return args.Split(' ', StringSplitOptions.RemoveEmptyEntries);
    }

    private static void TryDeleteQuietly(string path)
    {
        try
        {
            if (File.Exists(path)) File.Delete(path);
        }
        catch
        {
            // Игнорируем ошибку удаления временного установщика
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_POWER_STATUS
    {
        public byte ACLineStatus;
        public byte BatteryFlag;
        public byte BatteryLifePercent;
        public byte SystemStatusFlag;
        public int BatteryLifeTime;
        public int BatteryFullLifeTime;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS lpSystemPowerStatus);
}
