using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Microsoft.Win32;
using UltimateWindows.Core.Contracts;
using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Apps.Contracts;
using UltimateWindows.Modules.Apps.Models;
using UltimateWindows.Modules.Apps.Uninstaller;
using UltimateWindows.Modules.Optimizer.Models;
using UltimateWindows.NativeInterop.Security;

namespace UltimateWindows.NativeInterop.Apps;

/// <summary>
/// Реализация платформенного моста Этапа 7 на базе штатных API Windows, реестра, tbs.dll, kernel32.dll,
/// powrprof.dll, пакетного менеджера winget.exe и Планировщика заданий schtasks.exe.
/// </summary>
public sealed class WindowsAppsPlatformBridge : IAppsPlatformBridge
{
    public const string AutoMaintenanceTaskName = @"\UltimateWindows\AutoMaintenance";

    // ==================== 1. WINGET ====================

    public async Task<(bool Available, string VersionText)> ProbeWingetAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return (false, "не Windows");
        }

        var exe = ResolveWingetExecutablePath();
        if (exe is null)
        {
            return (false, "App Installer (winget) не установлен");
        }

        var (code, stdout, _) = await RunProcessCaptureAsync(exe, ["--version"], TimeSpan.FromSeconds(10), ct).ConfigureAwait(false);
        var ver = stdout.Trim();
        if (code == 0 && !string.IsNullOrWhiteSpace(ver))
        {
            return (true, ver.Split('\n')[0].Trim());
        }

        return (false, "winget недоступен");
    }

    public async Task<(int ExitCode, string StdOut, string StdErr)> RunWingetRawAsync(
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return (-1, string.Empty, "Только для Windows");
        }

        var exe = ResolveWingetExecutablePath();
        if (exe is null)
        {
            return (-1, string.Empty, "winget.exe не найден в системе.");
        }

        return await RunProcessCaptureAsync(exe, arguments, timeout, ct).ConfigureAwait(false);
    }

    private static string? ResolveWingetExecutablePath()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (!string.IsNullOrWhiteSpace(localAppData))
        {
            var aliasPath = Path.Combine(localAppData, "Microsoft", "WindowsApps", "winget.exe");
            if (File.Exists(aliasPath))
            {
                return aliasPath;
            }
        }

        var pathEnv = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        foreach (var dir in pathEnv.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            try
            {
                var candidate = Path.Combine(dir, "winget.exe");
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
            catch
            {
                // Ignore malformed PATH entry
            }
        }

        return null;
    }

    // ==================== 2. РЕЕСТР ПРОГРАММ И ЧИСТОЕ УДАЛЕНИЕ ====================

    public Task<IReadOnlyList<InstalledApplicationInfo>> GetInstalledWin32AppsAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult<IReadOnlyList<InstalledApplicationInfo>>(Array.Empty<InstalledApplicationInfo>());
        }

        return Task.Run<IReadOnlyList<InstalledApplicationInfo>>(() =>
        {
            var apps = new List<InstalledApplicationInfo>();
            var seenNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            var views = new (RegistryHive Hive, RegistryView View, string Prefix, string SubPath)[]
            {
                (RegistryHive.LocalMachine, RegistryView.Registry64, "HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                (RegistryHive.LocalMachine, RegistryView.Registry32, "HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                (RegistryHive.CurrentUser, RegistryView.Default, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\Uninstall")
            };

            foreach (var (hive, view, prefix, subPath) in views)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var baseHive = RegistryKey.OpenBaseKey(hive, view);
                    using var uninstallRoot = baseHive.OpenSubKey(subPath, writable: false);
                    if (uninstallRoot is null)
                    {
                        continue;
                    }

                    var recordedSubPath = hive == RegistryHive.LocalMachine && view == RegistryView.Registry32 && Environment.Is64BitOperatingSystem
                        ? @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
                        : subPath;

                    foreach (var childName in uninstallRoot.GetSubKeyNames())
                    {
                        using var appKey = uninstallRoot.OpenSubKey(childName, writable: false);
                        if (appKey is null)
                        {
                            continue;
                        }

                        if (appKey.GetValue("SystemComponent") is int sysComp && sysComp == 1)
                        {
                            continue;
                        }

                        if (!string.IsNullOrWhiteSpace(appKey.GetValue("ParentKeyName")?.ToString()))
                        {
                            continue;
                        }

                        var displayName = appKey.GetValue("DisplayName")?.ToString()?.Trim();
                        if (string.IsNullOrWhiteSpace(displayName) || !seenNames.Add(displayName))
                        {
                            continue;
                        }

                        var version = appKey.GetValue("DisplayVersion")?.ToString()?.Trim() ?? string.Empty;
                        var publisher = appKey.GetValue("Publisher")?.ToString()?.Trim() ?? "Неизвестный издатель";
                        var installLoc = appKey.GetValue("InstallLocation")?.ToString()?.Trim();
                        var quietUninstall = appKey.GetValue("QuietUninstallString")?.ToString()?.Trim();
                        var uninstallCmd = appKey.GetValue("UninstallString")?.ToString()?.Trim() ?? quietUninstall;
                        long sizeBytes = 0;
                        if (appKey.GetValue("EstimatedSize") is int kb && kb > 0)
                        {
                            sizeBytes = (long)kb * 1024L;
                        }

                        apps.Add(new InstalledApplicationInfo(
                            RegistryKeyPath: $@"{prefix}\{recordedSubPath}\{childName}",
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
                    // Ignore restricted hive
                }
            }

            return apps.OrderBy(a => a.DisplayName, StringComparer.OrdinalIgnoreCase).ToList();
        }, ct);
    }

    public async Task<bool> RunNativeUninstallerAndWaitAsync(
        InstalledApplicationInfo app,
        TimeSpan timeout,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(app.UninstallString))
        {
            return false;
        }

        try
        {
            var (exe, args) = SplitUninstallCommand(Environment.ExpandEnvironmentVariables(app.UninstallString.Trim()));
            if (string.IsNullOrWhiteSpace(exe))
            {
                return false;
            }

            var psi = new ProcessStartInfo
            {
                FileName = exe,
                Arguments = args,
                UseShellExecute = true
            };

            using var proc = Process.Start(psi);
            if (proc is null)
            {
                return false;
            }

            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            linkedCts.CancelAfter(timeout);
            try
            {
                await proc.WaitForExitAsync(linkedCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return false;
            }

            return true;
        }
        catch
        {
            return false;
        }
    }

    public IReadOnlyList<(AppLeftoverKind Kind, string RootDirectory)> GetCandidateLeftoverRoots()
    {
        var list = new List<(AppLeftoverKind, string)>();

        void AddIfPresent(AppLeftoverKind kind, Environment.SpecialFolder folder)
        {
            var path = Environment.GetFolderPath(folder);
            if (!string.IsNullOrWhiteSpace(path) && Directory.Exists(path))
            {
                list.Add((kind, path));
            }
        }

        AddIfPresent(AppLeftoverKind.AppDataDirectory, Environment.SpecialFolder.LocalApplicationData);
        AddIfPresent(AppLeftoverKind.AppDataDirectory, Environment.SpecialFolder.ApplicationData);
        AddIfPresent(AppLeftoverKind.ProgramDataDirectory, Environment.SpecialFolder.CommonApplicationData);
        AddIfPresent(AppLeftoverKind.ShortcutFile, Environment.SpecialFolder.DesktopDirectory);
        AddIfPresent(AppLeftoverKind.ShortcutFile, Environment.SpecialFolder.CommonDesktopDirectory);
        AddIfPresent(AppLeftoverKind.ShortcutFile, Environment.SpecialFolder.Programs);
        AddIfPresent(AppLeftoverKind.ShortcutFile, Environment.SpecialFolder.CommonPrograms);

        return list;
    }

    public IReadOnlyList<string> EnumerateRegistrySoftwareKeys()
    {
        if (!OperatingSystem.IsWindows())
        {
            return Array.Empty<string>();
        }

        var keys = new List<string>();
        EnumerateSoftwareHive(Registry.CurrentUser, "HKCU", @"Software", keys);
        EnumerateSoftwareHive(Registry.LocalMachine, "HKLM", @"Software", keys);
        if (Environment.Is64BitOperatingSystem)
        {
            EnumerateSoftwareHive(Registry.LocalMachine, "HKLM", @"Software\WOW6432Node", keys);
        }

        return keys;
    }

    public async Task<CleanUninstallResult> QuarantineAndRemoveLeftoversAsync(
        string appDisplayName,
        InstalledApplicationInfo? forceRemoveUninstallEntry,
        IReadOnlyList<AppLeftoverItem> leftovers,
        IVaultService vaultService,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new CleanUninstallResult(false, null, appDisplayName, false, 0, 0, 0, "Поддерживается только в Windows.");
        }

        var isForced = forceRemoveUninstallEntry is not null;
        var title = isForced
            ? $"Принудительное удаление: {appDisplayName}"
            : $"Зачистка хвостов: {appDisplayName}";

        await using var tx = vaultService.BeginTransaction(
            SystemDomain.AppsAndAutomation,
            title,
            $"Очистка остаточных файлов и ключей реестра программы «{appDisplayName}» с сохранением резервной копии.",
            $"LeftoversCount={leftovers.Count}; Forced={isForced}");

        var removedFiles = 0;
        var removedReg = 0;
        long reclaimedBytes = 0;

        // 1. При принудительном удалении аккуратно завершаем процессы из папки установки и снимаем запись Uninstall
        if (forceRemoveUninstallEntry is not null)
        {
            if (!string.IsNullOrWhiteSpace(forceRemoveUninstallEntry.InstallLocation) &&
                LeftoverSafetyGuard.IsSafeFilesystemLeftoverCandidate(forceRemoveUninstallEntry.InstallLocation))
            {
                TerminateProcessesUnderDirectory(forceRemoveUninstallEntry.InstallLocation);
            }

            if (await BackupAndDeleteRegistryKeyAsync(forceRemoveUninstallEntry.RegistryKeyPath, tx, ct).ConfigureAwait(false))
            {
                removedReg++;
            }
        }

        // 2. Обрабатываем найденные хвосты (файлы, папки, ярлыки и ветки реестра)
        const long maxSingleFileQuarantineBytes = 24L * 1024 * 1024;
        long quarantinedSessionBytes = 0;
        var maxSessionQuarantineBytes = Math.Max(32L * 1024 * 1024, vaultService.CurrentPolicy.MaxVaultBytes / 3);

        foreach (var item in leftovers)
        {
            ct.ThrowIfCancellationRequested();

            if (item.Kind == AppLeftoverKind.RegistrySubKey)
            {
                if (!LeftoverSafetyGuard.IsSafeRegistryLeftoverCandidate(item.TargetPath))
                {
                    continue;
                }

                if (await BackupAndDeleteRegistryKeyAsync(item.TargetPath, tx, ct).ConfigureAwait(false))
                {
                    removedReg++;
                }

                continue;
            }

            if (!LeftoverSafetyGuard.IsSafeFilesystemLeftoverCandidate(item.TargetPath))
            {
                continue;
            }

            if (File.Exists(item.TargetPath))
            {
                var (deleted, bytes) = await QuarantineAndDeleteSingleFileAsync(
                    item.TargetPath,
                    tx,
                    maxSingleFileQuarantineBytes,
                    maxSessionQuarantineBytes - quarantinedSessionBytes,
                    ct).ConfigureAwait(false);

                if (deleted)
                {
                    removedFiles++;
                    reclaimedBytes += bytes;
                    quarantinedSessionBytes += Math.Min(bytes, maxSingleFileQuarantineBytes);
                }
            }
            else if (Directory.Exists(item.TargetPath))
            {
                var (deletedInDir, bytesInDir) = await QuarantineAndDeleteDirectoryAsync(
                    item.TargetPath,
                    tx,
                    maxSingleFileQuarantineBytes,
                    maxSessionQuarantineBytes - quarantinedSessionBytes,
                    ct).ConfigureAwait(false);

                if (deletedInDir > 0)
                {
                    removedFiles++;
                    reclaimedBytes += bytesInDir;
                    quarantinedSessionBytes += Math.Min(bytesInDir, maxSingleFileQuarantineBytes);
                }
            }
        }

        Guid? sessionId = null;
        if (removedFiles > 0 || removedReg > 0)
        {
            var record = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);
            sessionId = record.SessionId;
        }

        var msg = removedFiles == 0 && removedReg == 0
            ? $"Не удалось удалить объекты «{appDisplayName}» (возможно, требуются права администратора)."
            : $"Очищено объектов «{appDisplayName}»: папок/ярлыков {removedFiles}, веток реестра {removedReg} (освобождено {UltimateWindows.Core.Models.ByteFormatter.Format(reclaimedBytes)}).";

        return new CleanUninstallResult(
            Succeeded: removedFiles > 0 || removedReg > 0,
            SessionId: sessionId,
            AppName: appDisplayName,
            UninstallerLaunched: false,
            RemovedFileLeftovers: removedFiles,
            RemovedRegistryLeftovers: removedReg,
            ReclaimedBytes: reclaimedBytes,
            SummaryMessage: msg);
    }

    // ==================== 3. ГОТОВНОСТЬ К WINDOWS 11, БАТАРЕЯ, СОН И ОЗУ ====================

    public Task<Win11RawHardwareFacts> ProbeWin11HardwareFactsAsync(CancellationToken ct = default) =>
        Task.Run(() =>
        {
            var osBuild = Environment.OSVersion.Version.Build;
            var osMajor = Environment.OSVersion.Version.Major;
            var osCaption = ReadOsCaptionFromRegistry(osBuild);
            var (cpuBrand, cpuMhz) = ReadCpuRegistryInfo();

            var is64 = Environment.Is64BitOperatingSystem &&
                       RuntimeInformation.OSArchitecture is Architecture.X64 or Architecture.Arm64;

            var sse42 = RuntimeInformation.ProcessArchitecture == Architecture.Arm64
                ? AdvSimd.IsSupported
                : Sse42.IsSupported;
            var popcnt = RuntimeInformation.ProcessArchitecture == Architecture.Arm64
                ? AdvSimd.IsSupported
                : Popcnt.IsSupported;

            var totalRam = QueryPhysicalMemoryBytes();
            long sysDiskBytes = 0;
            try
            {
                var root = Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\";
                sysDiskBytes = new DriveInfo(root).TotalSize;
            }
            catch
            {
                // Ignore
            }

            var isUefi = IsFirmwareUefi();
            var isGpt = CheckSystemDiskGpt(fallbackIfRestricted: isUefi);
            var secureBoot = ReadSecureBootEnabled();
            var (tpmPresent, tpmSpec) = QueryTpmDeviceInfo();
            var dx12Wddm2 = CheckWddm2OrHigherDisplayDriver();
            var hasEsu = CheckWindows10ConsumerEsuMarker();

            return new Win11RawHardwareFacts(
                OsCaption: osCaption,
                OsMajorVersion: osMajor,
                OsBuildNumber: osBuild,
                Is64BitArchitecture: is64,
                CpuBrand: cpuBrand,
                CpuCores: Math.Max(1, Environment.ProcessorCount / 2 == 0 ? Environment.ProcessorCount : GetPhysicalCoreEstimate()),
                CpuMaxClockMhz: cpuMhz,
                Sse42Supported: sse42,
                PopcntSupported: popcnt,
                TotalRamBytes: totalRam,
                SystemDriveTotalBytes: sysDiskBytes,
                IsUefiBoot: isUefi,
                IsSystemDiskGpt: isGpt,
                IsSecureBootEnabled: secureBoot,
                TpmPresent: tpmPresent,
                TpmSpecVersion: tpmSpec,
                DirectX12AndWddm2Ready: dx12Wddm2,
                HasConsumerEsuMarker: hasEsu);
        }, ct);

    public async Task<PowerSleepAndRamReport> ProbePowerSleepAndRamAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new PowerSleepAndRamReport(false, 0, 0, 0, "Только Windows", "—", Array.Empty<string>(), "—", false);
        }

        var (hasBattery, designMwh, fullMwh, wearPct, batteryHeadline) = await ProbeBatteryWearAsync(ct).ConfigureAwait(false);
        var lastWake = await QueryPowerCfgLastWakeAsync(ct).ConfigureAwait(false);
        var blockers = await QueryPowerCfgRequestsAsync(ct).ConfigureAwait(false);
        var (ramSummary, ramErrors) = await QueryMemoryDiagnosticEventAsync(ct).ConfigureAwait(false);

        return new PowerSleepAndRamReport(
            HasBattery: hasBattery,
            BatteryDesignCapacityMwh: designMwh,
            BatteryFullChargeCapacityMwh: fullMwh,
            BatteryWearPercent: wearPct,
            BatteryStatusHeadline: batteryHeadline,
            LastWakeSource: lastWake,
            ActivePowerBlockers: blockers,
            LastRamDiagnosticSummary: ramSummary,
            LastRamDiagnosticHadErrors: ramErrors);
    }

    public async Task<string?> GenerateBatteryHtmlReportAsync(string destinationPath, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        var fullPath = Path.GetFullPath(destinationPath);
        var dir = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(dir))
        {
            Directory.CreateDirectory(dir);
        }

        var powerCfg = Path.Combine(Environment.SystemDirectory, "powercfg.exe");
        var (code, _, _) = await RunProcessCaptureAsync(
            powerCfg,
            ["/batteryreport", "/output", fullPath],
            TimeSpan.FromSeconds(15),
            ct).ConfigureAwait(false);

        return code == 0 && File.Exists(fullPath) ? fullPath : null;
    }

    public Task<bool> LaunchWindowsMemoryDiagnosticAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult(false);
        }

        try
        {
            var mdsched = Path.Combine(Environment.SystemDirectory, "mdsched.exe");
            if (!File.Exists(mdsched))
            {
                return Task.FromResult(false);
            }

            Process.Start(new ProcessStartInfo
            {
                FileName = mdsched,
                UseShellExecute = true
            });
            return Task.FromResult(true);
        }
        catch
        {
            return Task.FromResult(false);
        }
    }

    // ==================== 4. ПЛАНИРОВЩИК ЗАДАНИЙ WINDOWS (АВТОПИЛОТ) ====================

    public async Task<MaintenanceScheduleProfile> GetMaintenanceScheduleAsync(
        string? persistedLastRunSummary,
        CancellationToken ct = default)
    {
        var fallbackSummary = string.IsNullOrWhiteSpace(persistedLastRunSummary)
            ? "Фоновый прогон ещё не выполнялся"
            : persistedLastRunSummary;

        if (!OperatingSystem.IsWindows())
        {
            return new MaintenanceScheduleProfile(
                false, MaintenanceFrequency.Disabled, 12, true, true, true,
                AutoMaintenanceTaskName, "Не запланировано", fallbackSummary);
        }

        var schtasks = Path.Combine(Environment.SystemDirectory, "schtasks.exe");
        var (code, xmlOut, _) = await RunProcessCaptureAsync(
            schtasks,
            ["/Query", "/TN", AutoMaintenanceTaskName, "/XML"],
            TimeSpan.FromSeconds(10),
            ct).ConfigureAwait(false);

        if (code != 0 || string.IsNullOrWhiteSpace(xmlOut) || !xmlOut.Contains("<Task", StringComparison.OrdinalIgnoreCase))
        {
            return new MaintenanceScheduleProfile(
                IsEnabled: false,
                Frequency: MaintenanceFrequency.Disabled,
                RunHourLocal: 12,
                CleanSafeTempCache: true,
                CheckDriveSmartHealth: true,
                AuditSecurityAndStartup: true,
                TaskSchedulerPath: AutoMaintenanceTaskName,
                NextRunDisplay: "Не запланировано",
                LastRunSummary: fallbackSummary);
        }

        var enabled = !xmlOut.Contains("<Enabled>false</Enabled>", StringComparison.OrdinalIgnoreCase);
        var freq = xmlOut.Contains("<ScheduleByMonth>", StringComparison.OrdinalIgnoreCase)
            ? MaintenanceFrequency.Monthly
            : xmlOut.Contains("<ScheduleByWeek>", StringComparison.OrdinalIgnoreCase)
                ? MaintenanceFrequency.Weekly
                : MaintenanceFrequency.Daily;

        var hour = 12;
        var startIdx = xmlOut.IndexOf("<StartBoundary>", StringComparison.OrdinalIgnoreCase);
        if (startIdx >= 0)
        {
            var endIdx = xmlOut.IndexOf("</StartBoundary>", startIdx, StringComparison.OrdinalIgnoreCase);
            if (endIdx > startIdx)
            {
                var iso = xmlOut[(startIdx + 15)..endIdx].Trim();
                if (DateTimeOffset.TryParse(iso, out var parsedStart))
                {
                    hour = parsedStart.Hour;
                }
            }
        }

        var cleanCache = !xmlOut.Contains("--no-cache", StringComparison.OrdinalIgnoreCase);
        var checkSmart = !xmlOut.Contains("--no-smart", StringComparison.OrdinalIgnoreCase);
        var checkSec = !xmlOut.Contains("--no-security", StringComparison.OrdinalIgnoreCase);

        var profile = new MaintenanceScheduleProfile(
            IsEnabled: enabled,
            Frequency: enabled ? freq : MaintenanceFrequency.Disabled,
            RunHourLocal: hour,
            CleanSafeTempCache: cleanCache,
            CheckDriveSmartHealth: checkSmart,
            AuditSecurityAndStartup: checkSec,
            TaskSchedulerPath: AutoMaintenanceTaskName,
            NextRunDisplay: enabled ? $"Активно ({(freq == MaintenanceFrequency.Daily ? "ежедневно" : freq == MaintenanceFrequency.Weekly ? "еженедельно" : "ежемесячно")} в {hour:00}:00)" : "Приостановлено",
            LastRunSummary: fallbackSummary);

        return profile;
    }

    public async Task<MaintenanceScheduleProfile> ApplyMaintenanceScheduleAsync(
        MaintenanceScheduleProfile desiredProfile,
        string cliExecutablePath,
        IVaultService vaultService,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return desiredProfile;
        }

        var schtasks = Path.Combine(Environment.SystemDirectory, "schtasks.exe");
        var (prevCode, prevXml, _) = await RunProcessCaptureAsync(
            schtasks,
            ["/Query", "/TN", AutoMaintenanceTaskName, "/XML"],
            TimeSpan.FromSeconds(10),
            ct).ConfigureAwait(false);

        var hadExistingTask = prevCode == 0 && prevXml.Contains("<Task", StringComparison.OrdinalIgnoreCase);
        var prevJson = JsonSerializer.Serialize(new
        {
            Existed = hadExistingTask,
            TaskName = AutoMaintenanceTaskName,
            TaskXml = hadExistingTask ? prevXml : null
        });

        await using var tx = vaultService.BeginTransaction(
            SystemDomain.AppsAndAutomation,
            desiredProfile.IsEnabled && desiredProfile.Frequency != MaintenanceFrequency.Disabled
                ? $"Включение автообслуживания ({desiredProfile.FrequencyDisplay})"
                : "Отключение фонового автообслуживания",
            "Настройка штатного задания Планировщика Windows \\UltimateWindows\\AutoMaintenance.",
            $"Frequency={desiredProfile.Frequency}; Hour={desiredProfile.RunHourLocal}");

        if (!desiredProfile.IsEnabled || desiredProfile.Frequency == MaintenanceFrequency.Disabled)
        {
            if (hadExistingTask)
            {
                var (delCode, _, delErr) = await RunProcessCaptureAsync(
                    schtasks,
                    ["/Delete", "/TN", AutoMaintenanceTaskName, "/F"],
                    TimeSpan.FromSeconds(10),
                    ct).ConfigureAwait(false);

                if (delCode != 0)
                {
                    throw new InvalidOperationException($"Не удалось удалить задание планировщика: {delErr.Trim()}");
                }

                tx.RecordStateDelta(
                    StateTargetKind.SystemSetting,
                    "MaintenanceScheduleTask",
                    prevJson,
                    JsonSerializer.Serialize(new { Existed = false }));
                await tx.CommitAsync(false, ct).ConfigureAwait(false);
            }

            return desiredProfile with
            {
                IsEnabled = false,
                Frequency = MaintenanceFrequency.Disabled,
                NextRunDisplay = "Не запланировано"
            };
        }

        var flags = new List<string> { "auto-maintenance" };
        if (!desiredProfile.CleanSafeTempCache) flags.Add("--no-cache");
        if (!desiredProfile.CheckDriveSmartHealth) flags.Add("--no-smart");
        if (!desiredProfile.AuditSecurityAndStartup) flags.Add("--no-security");

        var trCommand = $"\"{cliExecutablePath}\" {string.Join(' ', flags)}";
        var hourClamped = Math.Clamp(desiredProfile.RunHourLocal, 0, 23);
        var createArgs = new List<string>
        {
            "/Create",
            "/TN", AutoMaintenanceTaskName,
            "/TR", trCommand,
            "/ST", $"{hourClamped:00}:00",
            "/F"
        };

        switch (desiredProfile.Frequency)
        {
            case MaintenanceFrequency.Weekly:
                createArgs.AddRange(["/SC", "WEEKLY", "/D", "SUN"]);
                break;
            case MaintenanceFrequency.Monthly:
                createArgs.AddRange(["/SC", "MONTHLY", "/D", "1"]);
                break;
            default:
                createArgs.AddRange(["/SC", "DAILY"]);
                break;
        }

        if (ElevationChecker.IsRunningAsAdministrator())
        {
            createArgs.AddRange(["/RL", "HIGHEST"]);
        }

        var (createCode, _, createErr) = await RunProcessCaptureAsync(
            schtasks,
            createArgs,
            TimeSpan.FromSeconds(15),
            ct).ConfigureAwait(false);

        if (createCode != 0)
        {
            throw new InvalidOperationException($"Не удалось создать задание в Планировщике Windows: {createErr.Trim()}");
        }

        tx.RecordStateDelta(
            StateTargetKind.SystemSetting,
            "MaintenanceScheduleTask",
            prevJson,
            JsonSerializer.Serialize(new { Existed = true, desiredProfile.Frequency, Hour = hourClamped }));
        await tx.CommitAsync(false, ct).ConfigureAwait(false);

        return desiredProfile with
        {
            IsEnabled = true,
            RunHourLocal = hourClamped,
            NextRunDisplay = $"Активно ({desiredProfile.FrequencyDisplay})"
        };
    }

    // ==================== НИЗКОУРОВНЕВЫЕ ПОМОЩНИКИ И P/INVOKE ====================

    private static async Task<(int ExitCode, string StdOut, string StdErr)> RunProcessCaptureAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        CancellationToken ct)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };

            foreach (var arg in arguments)
            {
                psi.ArgumentList.Add(arg);
            }

            using var proc = Process.Start(psi);
            if (proc is null)
            {
                return (-1, string.Empty, "Не удалось запустить процесс.");
            }

            var outTask = proc.StandardOutput.ReadToEndAsync(ct);
            var errTask = proc.StandardError.ReadToEndAsync(ct);

            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
            linked.CancelAfter(timeout);

            try
            {
                await proc.WaitForExitAsync(linked.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                return (-2, await SafeAwaitTextAsync(outTask).ConfigureAwait(false), "Превышено время ожидания процесса.");
            }

            return (
                proc.ExitCode,
                await SafeAwaitTextAsync(outTask).ConfigureAwait(false),
                await SafeAwaitTextAsync(errTask).ConfigureAwait(false));
        }
        catch (Exception ex)
        {
            return (-1, string.Empty, ex.Message);
        }
    }

    private static async Task<string> SafeAwaitTextAsync(Task<string> task)
    {
        try { return await task.ConfigureAwait(false); }
        catch { return string.Empty; }
    }

    private static (string Exe, string Args) SplitUninstallCommand(string cmd)
    {
        if (cmd.StartsWith('"'))
        {
            var closeIdx = cmd.IndexOf('"', 1);
            if (closeIdx > 1)
            {
                return (cmd[1..closeIdx], cmd[(closeIdx + 1)..].Trim());
            }

            return (cmd.Trim('"'), string.Empty);
        }

        if (cmd.StartsWith("MsiExec", StringComparison.OrdinalIgnoreCase))
        {
            var sp = cmd.IndexOf(' ');
            var rawArgs = sp > 0 ? cmd[(sp + 1)..].Trim().Replace("/I", "/X", StringComparison.OrdinalIgnoreCase) : string.Empty;
            return ("msiexec.exe", rawArgs);
        }

        var exePos = cmd.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exePos > 0)
        {
            return (cmd[..(exePos + 4)].Trim(), cmd[(exePos + 4)..].Trim());
        }

        return (cmd, string.Empty);
    }

    private static void EnumerateSoftwareHive(
        RegistryKey root,
        string prefix,
        string subPath,
        List<string> results)
    {
        try
        {
            using var softwareKey = root.OpenSubKey(subPath, writable: false);
            if (softwareKey is null)
            {
                return;
            }

            foreach (var firstLevel in softwareKey.GetSubKeyNames())
            {
                if (string.Equals(firstLevel, "Classes", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(firstLevel, "Policies", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(firstLevel, "WOW6432Node", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var firstPath = $@"{prefix}\{subPath}\{firstLevel}";
                results.Add(firstPath);

                // Проверяем дочерние ключи вендора (например HKCU\Software\Vendor\AppName)
                if (!string.Equals(firstLevel, "Microsoft", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        using var vendorKey = softwareKey.OpenSubKey(firstLevel, writable: false);
                        if (vendorKey is not null)
                        {
                            foreach (var secondLevel in vendorKey.GetSubKeyNames().Take(40))
                            {
                                results.Add($@"{firstPath}\{secondLevel}");
                            }
                        }
                    }
                    catch
                    {
                        // Ignore
                    }
                }
            }
        }
        catch
        {
            // Ignore
        }
    }

    private static void TerminateProcessesUnderDirectory(string installDirectory)
    {
        var normalizedPrefix = Path.GetFullPath(installDirectory).TrimEnd('\\') + "\\";
        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                if (proc.Id == Environment.ProcessId)
                {
                    continue;
                }

                var fileName = proc.MainModule?.FileName;
                if (!string.IsNullOrWhiteSpace(fileName) &&
                    fileName.StartsWith(normalizedPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    proc.Kill(entireProcessTree: true);
                    proc.WaitForExit(2000);
                }
            }
            catch
            {
                // Ignore system / protected processes
            }
            finally
            {
                proc.Dispose();
            }
        }
    }

    private static async Task<bool> BackupAndDeleteRegistryKeyAsync(
        string registryPath,
        ITransactionSession tx,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(registryPath))
        {
            return false;
        }

        var normalized = registryPath.Trim().Replace('/', '\\').TrimEnd('\\');
        var slashIdx = normalized.IndexOf('\\');
        if (slashIdx <= 0)
        {
            return false;
        }

        var hiveToken = normalized[..slashIdx].ToUpperInvariant();
        var subKeyPath = normalized[(slashIdx + 1)..];
        var regExeHive = hiveToken switch
        {
            "HKLM" or "HKEY_LOCAL_MACHINE" => "HKLM",
            "HKCU" or "HKEY_CURRENT_USER" => "HKCU",
            _ => null
        };

        if (regExeHive is null)
        {
            return false;
        }

        // Экспортируем удаляемую ветку в .reg для точного отката в Машине времени
        var tempReg = Path.Combine(Path.GetTempPath(), $"uw-reg-backup-{Guid.NewGuid():N}.reg");
        try
        {
            var regExe = Path.Combine(Environment.SystemDirectory, "reg.exe");
            var (expCode, _, _) = await RunProcessCaptureAsync(
                regExe,
                ["export", $@"{regExeHive}\{subKeyPath}", tempReg, "/y"],
                TimeSpan.FromSeconds(8),
                ct).ConfigureAwait(false);

            string? exportedContent = null;
            if (expCode == 0 && File.Exists(tempReg))
            {
                var info = new FileInfo(tempReg);
                if (info.Length <= 512 * 1024)
                {
                    exportedContent = await File.ReadAllTextAsync(tempReg, ct).ConfigureAwait(false);
                }
            }

            var rootHive = regExeHive == "HKLM" ? Registry.LocalMachine : Registry.CurrentUser;
            rootHive.DeleteSubKeyTree(subKeyPath, throwOnMissingSubKey: false);

            if (!string.IsNullOrWhiteSpace(exportedContent))
            {
                tx.RecordStateDelta(
                    StateTargetKind.SystemSetting,
                    $"AppRegistryExport:{regExeHive}\\{subKeyPath}",
                    JsonSerializer.Serialize(new { RegFileContent = exportedContent }),
                    null);
            }

            return true;
        }
        catch
        {
            return false;
        }
        finally
        {
            try { if (File.Exists(tempReg)) File.Delete(tempReg); } catch { }
        }
    }

    private static async Task<(bool Deleted, long Bytes)> QuarantineAndDeleteSingleFileAsync(
        string filePath,
        ITransactionSession tx,
        long maxSingleFileBytes,
        long remainingBudgetBytes,
        CancellationToken ct)
    {
        try
        {
            var fi = new FileInfo(filePath);
            if (!fi.Exists)
            {
                return (false, 0);
            }

            var len = fi.Length;
            if (len > 0 && len <= maxSingleFileBytes && len <= remainingBudgetBytes)
            {
                await tx.QuarantineFileAsync(filePath, ct).ConfigureAwait(false);
            }

            fi.Attributes = FileAttributes.Normal;
            File.Delete(filePath);
            return (true, len);
        }
        catch
        {
            return (false, 0);
        }
    }

    private static async Task<(int DeletedFiles, long ReclaimedBytes)> QuarantineAndDeleteDirectoryAsync(
        string directoryPath,
        ITransactionSession tx,
        long maxSingleFileBytes,
        long remainingBudgetBytes,
        CancellationToken ct)
    {
        var deletedFiles = 0;
        long reclaimedBytes = 0;
        var budgetLeft = remainingBudgetBytes;

        try
        {
            foreach (var file in Directory.EnumerateFiles(directoryPath, "*", new EnumerationOptions
                     {
                         RecurseSubdirectories = true,
                         IgnoreInaccessible = true,
                         AttributesToSkip = FileAttributes.ReparsePoint
                     }))
            {
                ct.ThrowIfCancellationRequested();
                var (deleted, bytes) = await QuarantineAndDeleteSingleFileAsync(
                    file,
                    tx,
                    maxSingleFileBytes,
                    budgetLeft,
                    ct).ConfigureAwait(false);

                if (deleted)
                {
                    deletedFiles++;
                    reclaimedBytes += bytes;
                    budgetLeft = Math.Max(0, budgetLeft - Math.Min(bytes, maxSingleFileBytes));
                }
            }

            try
            {
                Directory.Delete(directoryPath, recursive: true);
            }
            catch
            {
                // Незакрытые дескрипторы отдельных подкаталогов пропускаем
            }
        }
        catch
        {
            // Ignore
        }

        return (deletedFiles, reclaimedBytes);
    }

    private static string ReadOsCaptionFromRegistry(int buildNumber)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", writable: false);
            var productName = key?.GetValue("ProductName")?.ToString() ?? "Windows";
            var displayVersion = key?.GetValue("DisplayVersion")?.ToString();
            if (buildNumber >= 22000 && productName.Contains("Windows 10", StringComparison.OrdinalIgnoreCase))
            {
                productName = productName.Replace("Windows 10", "Windows 11", StringComparison.OrdinalIgnoreCase);
            }

            return string.IsNullOrWhiteSpace(displayVersion)
                ? productName
                : $"{productName} ({displayVersion})";
        }
        catch
        {
            return buildNumber >= 22000 ? "Windows 11" : "Windows 10";
        }
    }

    private static (string Brand, int Mhz) ReadCpuRegistryInfo()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0", writable: false);
            var brand = key?.GetValue("ProcessorNameString")?.ToString()?.Trim() ?? "Процессор x64";
            var mhz = key?.GetValue("~MHz") is int rawMhz ? rawMhz : 0;
            return (brand, mhz);
        }
        catch
        {
            return ("Процессор x64", 0);
        }
    }

    private static int GetPhysicalCoreEstimate()
    {
        try
        {
            using var cpuRoot = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor", writable: false);
            var logical = cpuRoot?.SubKeyCount ?? Environment.ProcessorCount;
            return Math.Max(2, logical >= 4 ? logical / 2 : logical);
        }
        catch
        {
            return Math.Max(2, Environment.ProcessorCount);
        }
    }

    private static long QueryPhysicalMemoryBytes()
    {
        var mem = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
        return GlobalMemoryStatusEx(ref mem) ? (long)mem.ullTotalPhys : 8L * 1024 * 1024 * 1024;
    }

    private static bool IsFirmwareUefi()
    {
        try
        {
            return GetFirmwareType(out var fwType) && fwType == 2; // FirmwareTypeUefi = 2
        }
        catch
        {
            return Directory.Exists(Path.Combine(Environment.SystemDirectory, "Boot", "EFI"));
        }
    }

    private static bool CheckSystemDiskGpt(bool fallbackIfRestricted)
    {
        const uint GENERIC_NONE = 0;
        const uint FILE_SHARE_READ = 1;
        const uint FILE_SHARE_WRITE = 2;
        const uint OPEN_EXISTING = 3;
        const uint IOCTL_DISK_GET_DRIVE_LAYOUT_EX = 0x00070050;

        var handle = CreateFileW(
            @"\\.\PhysicalDrive0",
            GENERIC_NONE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero,
            OPEN_EXISTING,
            0,
            IntPtr.Zero);

        if (handle == IntPtr.Zero || handle == new IntPtr(-1))
        {
            return fallbackIfRestricted;
        }

        try
        {
            var buffer = new byte[4096];
            if (DeviceIoControl(handle, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, IntPtr.Zero, 0, buffer, (uint)buffer.Length, out var returned, IntPtr.Zero) &&
                returned >= 8)
            {
                var partitionStyle = BitConverter.ToUInt32(buffer, 0);
                return partitionStyle == 1; // PARTITION_STYLE_GPT = 1
            }

            return fallbackIfRestricted;
        }
        finally
        {
            _ = CloseHandle(handle);
        }
    }

    private static bool ReadSecureBootEnabled()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State", writable: false);
            return key?.GetValue("UEFISecureBootEnabled") is int v && v == 1;
        }
        catch
        {
            return false;
        }
    }

    private static (bool Present, string SpecVersion) QueryTpmDeviceInfo()
    {
        try
        {
            var info = new TPM_DEVICE_INFO();
            var rc = Tbsi_GetDeviceInfo((uint)Marshal.SizeOf<TPM_DEVICE_INFO>(), ref info);
            if (rc == 0)
            {
                return info.tpmVersion switch
                {
                    2 => (true, "2.0"),
                    1 => (true, "1.2"),
                    _ => (true, $"{info.tpmVersion}.0")
                };
            }
        }
        catch
        {
            // Fallback to registry check below
        }

        try
        {
            using var tpmKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\TPM\WMI", writable: false);
            if (tpmKey is not null)
            {
                return (true, "2.0");
            }
        }
        catch
        {
            // Ignore
        }

        return (false, "отсутствует");
    }

    private static bool CheckWddm2OrHigherDisplayDriver()
    {
        try
        {
            using var displayClass = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}",
                writable: false);

            if (displayClass is null)
            {
                return true;
            }

            foreach (var sub in displayClass.GetSubKeyNames())
            {
                if (!sub.All(char.IsDigit))
                {
                    continue;
                }

                using var adapter = displayClass.OpenSubKey(sub, writable: false);
                var verStr = adapter?.GetValue("DriverVersion")?.ToString();
                if (!string.IsNullOrWhiteSpace(verStr))
                {
                    var majorText = verStr.Split('.')[0];
                    if (int.TryParse(majorText, out var major) && major >= 20)
                    {
                        // Драйверы WDDM 2.0+ начинаются с мажорной версии 20.x и выше (включая базовый видеодрайвер Win10/11 10.0.2xxxx)
                        return true;
                    }

                    if (verStr.StartsWith("10.0.19", StringComparison.Ordinal) ||
                        verStr.StartsWith("10.0.2", StringComparison.Ordinal))
                    {
                        return true;
                    }
                }
            }
        }
        catch
        {
            // Ignore
        }

        return Environment.OSVersion.Version.Major >= 10;
    }

    private static bool CheckWindows10ConsumerEsuMarker()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform\ESU",
                writable: false);
            if (key is not null && (key.ValueCount > 0 || key.SubKeyCount > 0))
            {
                return true;
            }

            using var wuKey = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows NT\CurrentVersion\Windows10ConsumerESU",
                writable: false);
            return wuKey?.GetValue("ESUEligibility") is int elig && elig >= 2;
        }
        catch
        {
            return false;
        }
    }

    private static async Task<(bool HasBattery, int DesignMwh, int FullMwh, double WearPct, string Headline)> ProbeBatteryWearAsync(
        CancellationToken ct)
    {
        var state = new SYSTEM_BATTERY_STATE();
        var ntStatus = CallNtPowerInformation(
            5, // SystemBatteryState
            IntPtr.Zero,
            0,
            ref state,
            (uint)Marshal.SizeOf<SYSTEM_BATTERY_STATE>());

        if (ntStatus != 0 || state.BatteryPresent == 0)
        {
            return (false, 0, 0, 0, "Стационарный ПК (аккумулятор не обнаружен)");
        }

        var maxCap = (int)state.MaxCapacity;
        var designCap = maxCap;

        // Уточняем паспортную ёмкость DesignCapacity через быстрый XML-отчёт powercfg
        var tempXml = Path.Combine(Path.GetTempPath(), $"uw-bat-{Guid.NewGuid():N}.xml");
        try
        {
            var powerCfg = Path.Combine(Environment.SystemDirectory, "powercfg.exe");
            var (code, _, _) = await RunProcessCaptureAsync(
                powerCfg,
                ["/batteryreport", "/xml", "/output", tempXml],
                TimeSpan.FromSeconds(8),
                ct).ConfigureAwait(false);

            if (code == 0 && File.Exists(tempXml))
            {
                var doc = XDocument.Load(tempXml);
                var batElem = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "Battery");
                if (batElem is not null)
                {
                    var dText = batElem.Elements().FirstOrDefault(e => e.Name.LocalName == "DesignCapacity")?.Value;
                    var fText = batElem.Elements().FirstOrDefault(e => e.Name.LocalName == "FullChargeCapacity")?.Value;
                    if (int.TryParse(dText, out var dVal) && dVal > 0) designCap = dVal;
                    if (int.TryParse(fText, out var fVal) && fVal > 0) maxCap = fVal;
                }
            }
        }
        catch
        {
            // Ignore XML fallback error
        }
        finally
        {
            try { if (File.Exists(tempXml)) File.Delete(tempXml); } catch { }
        }

        var wear = designCap > 0 && maxCap > 0 && maxCap < designCap
            ? Math.Round((1.0 - (double)maxCap / designCap) * 100.0, 1)
            : 0.0;

        var headline = designCap > 0
            ? $"Износ: {wear:F1}% (текущая ёмкость {maxCap:N0} мВт·ч из паспортных {designCap:N0} мВт·ч)"
            : "Аккумулятор обнаружен (паспортная ёмкость не передана контроллером)";

        return (true, designCap, maxCap, wear, headline);
    }

    private static async Task<string> QueryPowerCfgLastWakeAsync(CancellationToken ct)
    {
        var powerCfg = Path.Combine(Environment.SystemDirectory, "powercfg.exe");
        var (code, stdout, _) = await RunProcessCaptureAsync(powerCfg, ["/lastwake"], TimeSpan.FromSeconds(5), ct).ConfigureAwait(false);
        if (code != 0 || string.IsNullOrWhiteSpace(stdout))
        {
            return "Сведения о последнем пробуждении отсутствуют";
        }

        var lines = stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return string.Join(" • ", lines.Take(3));
    }

    private static async Task<IReadOnlyList<string>> QueryPowerCfgRequestsAsync(CancellationToken ct)
    {
        if (!ElevationChecker.IsRunningAsAdministrator())
        {
            return ["Для просмотра активных блокировщиков сна (/requests) нужны права администратора"];
        }

        var powerCfg = Path.Combine(Environment.SystemDirectory, "powercfg.exe");
        var (code, stdout, _) = await RunProcessCaptureAsync(powerCfg, ["/requests"], TimeSpan.FromSeconds(5), ct).ConfigureAwait(false);
        if (code != 0 || string.IsNullOrWhiteSpace(stdout))
        {
            return Array.Empty<string>();
        }

        var active = new List<string>();
        foreach (var raw in stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (raw.EndsWith(':') ||
                string.Equals(raw, "None.", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(raw, "Нет.", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (raw.StartsWith('['))
            {
                active.Add(raw);
            }
        }

        return active;
    }

    private static async Task<(string Summary, bool HadErrors)> QueryMemoryDiagnosticEventAsync(CancellationToken ct)
    {
        var wevtutil = Path.Combine(Environment.SystemDirectory, "wevtutil.exe");
        if (!File.Exists(wevtutil))
        {
            return ("Средство чтения журнала памяти недоступно", false);
        }

        var (code, stdout, _) = await RunProcessCaptureAsync(
            wevtutil,
            [
                "qe", "System",
                "/q:*[System[Provider[@Name='Microsoft-Windows-MemoryDiagnostics-Results']]]",
                "/c:1", "/rd:true", "/f:text"
            ],
            TimeSpan.FromSeconds(6),
            ct).ConfigureAwait(false);

        if (code != 0 || string.IsNullOrWhiteSpace(stdout))
        {
            return ("Проверка оперативной памяти Windows (mdsched.exe) ранее не запускалась", false);
        }

        var hadErrors = stdout.Contains("hardware problems were detected", StringComparison.OrdinalIgnoreCase) ||
                        stdout.Contains("обнаружены неполадки", StringComparison.OrdinalIgnoreCase) ||
                        stdout.Contains("Event ID: 1202", StringComparison.OrdinalIgnoreCase);

        var summary = hadErrors
            ? "ВНИМАНИЕ: последняя диагностика памяти Windows зафиксировала аппаратные ошибки ОЗУ!"
            : "Последняя проверка средства диагностики памяти Windows завершилась успешно (ошибок ОЗУ не обнаружено).";

        return (summary, hadErrors);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORYSTATUSEX
    {
        public uint dwLength;
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TPM_DEVICE_INFO
    {
        public uint structVersion;
        public uint tpmVersion;
        public uint tpmInterfaceType;
        public uint tpmImpRevision;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_BATTERY_STATE
    {
        public byte AcOnLine;
        public byte BatteryPresent;
        public byte Charging;
        public byte Discharging;
        public byte Spare1_0;
        public byte Spare1_1;
        public byte Spare1_2;
        public byte Tag;
        public uint MaxCapacity;
        public uint RemainingCapacity;
        public int Rate;
        public uint EstimatedTime;
        public uint DefaultAlert1;
        public uint DefaultAlert2;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFirmwareType(out uint firmwareType);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(
        IntPtr hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        [Out] byte[] lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("tbs.dll", ExactSpelling = true)]
    private static extern uint Tbsi_GetDeviceInfo(uint Size, ref TPM_DEVICE_INFO pInfo);

    [DllImport("powrprof.dll", ExactSpelling = true)]
    private static extern int CallNtPowerInformation(
        int InformationLevel,
        IntPtr lpInputBuffer,
        uint nInputBufferSize,
        ref SYSTEM_BATTERY_STATE lpOutputBuffer,
        uint nOutputBufferSize);
}
