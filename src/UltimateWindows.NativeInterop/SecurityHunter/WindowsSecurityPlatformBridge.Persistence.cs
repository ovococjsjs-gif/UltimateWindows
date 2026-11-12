using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Optimizer.Models;
using UltimateWindows.Modules.Security.Analyzers;
using UltimateWindows.Modules.Security.Catalog;
using UltimateWindows.Modules.Security.Models;
using UltimateWindows.NativeInterop.Optimizer;

namespace UltimateWindows.NativeInterop.SecurityHunter;

public sealed partial class WindowsSecurityPlatformBridge
{
    private static readonly HashSet<string> StandardLsaPackages = new(StringComparer.OrdinalIgnoreCase)
    {
        "msv1_0", "scecli", "kerberos", "wdigest", "tspkg", "pku2u", "cloudap",
        "negoexts", "schannel", "ncryptprov", "rassfm", "livessp", "wsauth", "\"\""
    };

    public override Task<IReadOnlyList<PersistenceAnomalyRecord>> ScanPersistenceAnomaliesAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult<IReadOnlyList<PersistenceAnomalyRecord>>([]);
        }

        return Task.Run<IReadOnlyList<PersistenceAnomalyRecord>>(() =>
        {
            var records = new List<PersistenceAnomalyRecord>(160);
            var winDir = GetWindowsDirectory();

            // Зона 1: Run / RunOnce / RunOnceEx / RunServices (HKLM 64/32 + HKCU)
            ScanRunKeys(records, winDir, ct);

            // Зона 2: Групповые политики Policies\Explorer\Run (HKLM + HKCU)
            ScanPoliciesRunKeys(records, winDir);

            // Зона 3: Папки Startup + проверка перенаправления User Shell Folders / Shell Folders
            ScanStartupFoldersAndShellRedirection(records, winDir);

            // Зона 4: Winlogon (Shell, Userinit, Taskman, VMApplet)
            ScanWinlogonKeys(records, winDir);

            // Зона 5: IFEO Debugger + SilentProcessExit\*\MonitorProcess
            ScanIfeoAndSilentProcessExit(records, ct);

            // Зона 6: Session Manager (BootExecute, SetupExecute, AppCertDlls)
            ScanSessionManagerAndBootExecute(records, winDir);

            // Зона 7: AppInit_DLLs (HKLM 64/32)
            ScanAppInitDlls(records, winDir);

            // Зона 8: Active Setup\Installed Components\*\StubPath
            ScanActiveSetup(records, winDir, ct);

            // Зона 9: Перехват COM-классов HKCU\Software\Classes\CLSID\*\InprocServer32 & LocalServer32
            ScanHkcuComHijacking(records, winDir, ct);

            // Зона 10: .NET CLR COR_PROFILER / CORECLR_PROFILER / DOTNET_STARTUP_HOOKS (Blue Mockingbird)
            ScanDotNetProfilerEnvironment(records, winDir);

            // Зона 11: LSA Authentication / Notification / Security Packages
            ScanLsaPackages(records);

            // Зона 12: Print\Monitors и NetSh Helper DLLs
            ScanPrintMonitorsAndNetsh(records, winDir);

            // Зона 13: Службы Windows, ServiceDll и злоупотребляемые драйверы (WinRing0, DrvSvc и др.)
            ScanServicesAndDrivers(records, winDir, ct);

            // Зона 14: Планировщик заданий (COM Schedule.Service включая скрытые + TaskCache\Tree без SD)
            ScanScheduledTasksAndGhostSd(records, winDir, ct);

            // Зона 15 & 16: Постоянные подписки WMI (root\subscription) и фоновые задания BITS
            ScanWmiSubscriptionsAndBits(records, ct);

            // Зона 17: Расширения оболочки Explorer (ShellServiceObjectDelayLoad / ShellIconOverlayIdentifiers)
            ScanExplorerShellHooks(records, winDir);

            // Зона 18: Стартовые профили PowerShell ($PROFILE)
            ScanPowerShellProfiles(records);

            return records;
        }, ct);
    }

    public override Task<(bool Succeeded, StateTargetKind? RollbackKind, string? RollbackTarget, string? PreviousStateJson)> RemovePersistenceEntryAsync(
        PersistenceAnomalyRecord record,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows() || !record.CanRemediate)
        {
            return Task.FromResult<(bool, StateTargetKind?, string?, string?)>((false, null, null, null));
        }

        return Task.Run<(bool, StateTargetKind?, string?, string?)>(() =>
        {
            try
            {
                switch (record.RemediationKind)
                {
                    case PersistenceRemediationKind.DeleteRegistryValue:
                    case PersistenceRemediationKind.RestoreRegistryDefault:
                        return RemediateRegistryValue(record);

                    case PersistenceRemediationKind.DeleteRegistrySubKey:
                        return RemediateRegistrySubKey(record);

                    case PersistenceRemediationKind.DisableScheduledTask:
                    {
                        var taskPath = record.RemediationTarget;
                        if (string.IsNullOrWhiteSpace(taskPath)) return (false, null, null, null);
                        var res = WindowsTaskScheduler.SetEnabled(taskPath, enabled: false);
                        if (!res.Succeeded) return (false, null, null, null);
                        var prevJson = JsonSerializer.Serialize(new { TaskPath = taskPath, Enabled = true });
                        return (true, StateTargetKind.ScheduledTask, taskPath, prevJson);
                    }

                    case PersistenceRemediationKind.DeleteScheduledTask:
                    {
                        // Для скрытой задачи без SD удаляем ветку в TaskCache\Tree с сохранением TaskId
                        return RemediateRegistrySubKey(record);
                    }

                    case PersistenceRemediationKind.DisableWindowsService:
                    {
                        var svcName = record.RemediationTarget;
                        if (string.IsNullOrWhiteSpace(svcName)) return (false, null, null, null);
                        var prevCfg = WindowsServiceControl.Query(svcName);
                        _ = WindowsServiceControl.ControlAsync(svcName, start: false, TimeSpan.FromSeconds(4), ct).GetAwaiter().GetResult();
                        var res = WindowsServiceControl.SetStartup(svcName, ServiceStartupMode.Disabled);
                        if (!res.Succeeded) return (false, null, null, null);
                        var prevStartup = (prevCfg?.Startup ?? ServiceStartupMode.Automatic).ToString();
                        var prevJson = JsonSerializer.Serialize(new { ServiceName = svcName, Startup = prevStartup });
                        return (true, StateTargetKind.WindowsService, svcName, prevJson);
                    }

                    case PersistenceRemediationKind.DeleteWmiSubscription:
                    {
                        var ok = RunShortPowerShell(
                            $"Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Filter \"Name='{EscapeWmiSingleQuotes(record.EntryName)}'\" | Remove-CimInstance; " +
                            $"Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer -Filter \"Name='{EscapeWmiSingleQuotes(record.EntryName)}'\" | Remove-CimInstance",
                            timeoutMs: 4000);
                        return (ok, StateTargetKind.SystemSetting, $"WmiSubscription:{record.EntryName}", record.PreviousValueSerialized);
                    }

                    case PersistenceRemediationKind.CancelBitsJob:
                    {
                        var ok = RunShortPowerShell(
                            $"Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | Where-Object {{ $_.DisplayName -eq '{EscapeWmiSingleQuotes(record.EntryName)}' }} | Remove-BitsTransfer",
                            timeoutMs: 4000);
                        return (ok, StateTargetKind.SystemSetting, $"BitsJob:{record.EntryName}", record.PreviousValueSerialized);
                    }

                    case PersistenceRemediationKind.QuarantineStartupFile:
                    {
                        // Сам файл стартапа будет помещён в .uwq основным сервисом QuarantineThreatAsync;
                        // при прямом вызове со вкладки закрепления удаляем ярлык после проверки
                        if (!string.IsNullOrWhiteSpace(record.RemediationTarget) && File.Exists(record.RemediationTarget))
                        {
                            File.SetAttributes(record.RemediationTarget, FileAttributes.Normal);
                            File.Delete(record.RemediationTarget);
                            return (true, null, null, null);
                        }
                        return (false, null, null, null);
                    }
                }
            }
            catch
            {
                // Возврат неудачи без исключения
            }

            return (false, null, null, null);
        }, ct);
    }

    // ==================== 18 ЗОН АВТОЗАКРЕПЛЕНИЯ ====================

    private void ScanRunKeys(List<PersistenceAnomalyRecord> sink, string winDir, CancellationToken ct)
    {
        var specs = new (RegistryHive Hive, RegistryView View, string HiveLabel, string SubKey)[]
        {
            (RegistryHive.LocalMachine, RegistryView.Registry64, "HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (RegistryHive.LocalMachine, RegistryView.Registry64, "HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (RegistryHive.LocalMachine, RegistryView.Registry64, "HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx"),
            (RegistryHive.LocalMachine, RegistryView.Registry32, "HKLM32", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (RegistryHive.LocalMachine, RegistryView.Registry32, "HKLM32", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (RegistryHive.CurrentUser, RegistryView.Default, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\Run"),
            (RegistryHive.CurrentUser, RegistryView.Default, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (RegistryHive.CurrentUser, RegistryView.Default, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\RunServices")
        };

        foreach (var (hive, view, hiveLabel, subKey) in specs)
        {
            ct.ThrowIfCancellationRequested();
            InspectCommandValuesInKey(
                hive, view, hiveLabel, subKey,
                PersistenceZone.RunAndRunOnceKeys,
                ThreatDetectionVector.SuspiciousRegistryAutorun,
                winDir,
                includeHealthyEntries: true,
                sink);
        }
    }

    private void ScanPoliciesRunKeys(List<PersistenceAnomalyRecord> sink, string winDir)
    {
        var specs = new (RegistryHive Hive, string Label, string SubKey)[]
        {
            (RegistryHive.LocalMachine, "HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
            (RegistryHive.CurrentUser, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run")
        };

        foreach (var (hive, label, subKey) in specs)
        {
            InspectCommandValuesInKey(
                hive, RegistryView.Default, label, subKey,
                PersistenceZone.PoliciesExplorerRun,
                ThreatDetectionVector.SuspiciousRegistryAutorun,
                winDir,
                includeHealthyEntries: true,
                sink,
                forceSuspiciousWhenUnsigned: true);
        }
    }

    private void ScanStartupFoldersAndShellRedirection(List<PersistenceAnomalyRecord> sink, string winDir)
    {
        // 1. Проверяем перенаправление User Shell Folders\Startup и Common Startup
        CheckShellFolderRedirection(
            RegistryHive.CurrentUser, "HKCU",
            @"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", "Startup",
            expectedSubstring: @"\Microsoft\Windows\Start Menu\Programs\Startup",
            sink);

        CheckShellFolderRedirection(
            RegistryHive.LocalMachine, "HKLM",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", "Common Startup",
            expectedSubstring: @"\Microsoft\Windows\Start Menu\Programs\Startup",
            sink);

        // 2. Проверяем файлы внутри обеих папок автозагрузки
        var folders = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
        };

        foreach (var dir in folders.Where(d => !string.IsNullOrWhiteSpace(d) && Directory.Exists(d)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir))
                {
                    var name = Path.GetFileName(file);
                    if (name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    var ext = Path.GetExtension(file);
                    string target = ext.Equals(".lnk", StringComparison.OrdinalIgnoreCase)
                        ? ExtractShortcutTargetFast(file) ?? file
                        : file;

                    var exePath = PersistenceZoneCatalog.ExtractExecutablePath(target) ?? target;
                    bool signed = File.Exists(exePath) && VerifySignedCached(exePath);
                    bool isScript = ext.Equals(".vbs", StringComparison.OrdinalIgnoreCase) ||
                                    ext.Equals(".bat", StringComparison.OrdinalIgnoreCase) ||
                                    ext.Equals(".cmd", StringComparison.OrdinalIgnoreCase) ||
                                    ext.Equals(".js", StringComparison.OrdinalIgnoreCase) ||
                                    ext.Equals(".ps1", StringComparison.OrdinalIgnoreCase);

                    bool isAnomaly = isScript ||
                                     PersistenceZoneCatalog.HasSuspiciousScriptOrLolbinCommand(target, out _) ||
                                     (PersistenceZoneCatalog.IsUserWritableOrStagingPath(exePath) && !signed);

                    sink.Add(new PersistenceAnomalyRecord(
                        Vector: ThreatDetectionVector.StartupFolderOrShellRedirect,
                        RegistryOrTaskPath: dir,
                        EntryName: name,
                        PayloadCommandOrPath: target,
                        ReferencedExecutablePath: File.Exists(exePath) && !exePath.StartsWith(winDir, StringComparison.OrdinalIgnoreCase) ? exePath : file,
                        IsMissingSecurityDescriptorSd: false,
                        PreviousValueSerialized: file,
                        Category: PersistenceZone.StartupFoldersAndShellRedirection,
                        IsAnomaly: isAnomaly,
                        IsSigned: signed,
                        PublisherOrNote: isScript ? "Скрипт в папке автозагрузки" : "",
                        RemediationKind: isAnomaly ? PersistenceRemediationKind.QuarantineStartupFile : PersistenceRemediationKind.None,
                        RemediationTarget: file));
                }
            }
            catch
            {
                // Пропуск недоступного каталога
            }
        }
    }

    private static void CheckShellFolderRedirection(
        RegistryHive hive,
        string hiveLabel,
        string subKeyPath,
        string valueName,
        string expectedSubstring,
        List<PersistenceAnomalyRecord> sink)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
            using var sub = baseKey.OpenSubKey(subKeyPath, writable: false);
            var raw = sub?.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames)?.ToString();
            if (string.IsNullOrWhiteSpace(raw)) return;

            var expanded = Environment.ExpandEnvironmentVariables(raw);
            if (!expanded.Contains(expectedSubstring, StringComparison.OrdinalIgnoreCase))
            {
                sink.Add(new PersistenceAnomalyRecord(
                    Vector: ThreatDetectionVector.StartupFolderOrShellRedirect,
                    RegistryOrTaskPath: $@"{hiveLabel}\{subKeyPath}",
                    EntryName: valueName,
                    PayloadCommandOrPath: expanded,
                    ReferencedExecutablePath: null,
                    IsMissingSecurityDescriptorSd: false,
                    PreviousValueSerialized: raw,
                    Category: PersistenceZone.StartupFoldersAndShellRedirection,
                    IsAnomaly: true,
                    IsSigned: false,
                    PublisherOrNote: "Папка Автозагрузки перенаправлена в нестандартный каталог",
                    RemediationKind: PersistenceRemediationKind.DeleteRegistryValue,
                    RemediationTarget: $"{hiveLabel}|{subKeyPath}|{valueName}"));
            }
        }
        catch
        {
            // Пропуск
        }
    }

    private static void ScanWinlogonKeys(List<PersistenceAnomalyRecord> sink, string winDir)
    {
        const string winlogonSubKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        try
        {
            using var wl = Registry.LocalMachine.OpenSubKey(winlogonSubKey, writable: false);
            if (wl is not null)
            {
                var shell = wl.GetValue("Shell")?.ToString()?.Trim();
                if (!string.IsNullOrWhiteSpace(shell))
                {
                    bool shellAnom = !shell.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase) &&
                                     !shell.Equals(Path.Combine(winDir, "explorer.exe"), StringComparison.OrdinalIgnoreCase);

                    sink.Add(new PersistenceAnomalyRecord(
                        Vector: ThreatDetectionVector.WinlogonShellHijack,
                        RegistryOrTaskPath: $@"HKLM\{winlogonSubKey}",
                        EntryName: "Shell",
                        PayloadCommandOrPath: shell,
                        ReferencedExecutablePath: shellAnom ? PersistenceZoneCatalog.ExtractExecutablePath(shell) : null,
                        IsMissingSecurityDescriptorSd: false,
                        PreviousValueSerialized: shell,
                        Category: PersistenceZone.WinlogonShellAndUserinit,
                        IsAnomaly: shellAnom,
                        IsSigned: !shellAnom,
                        RemediationKind: shellAnom ? PersistenceRemediationKind.RestoreRegistryDefault : PersistenceRemediationKind.None,
                        RemediationTarget: $@"HKLM|{winlogonSubKey}|Shell|explorer.exe"));
                }

                var userinit = wl.GetValue("Userinit")?.ToString()?.Trim();
                if (!string.IsNullOrWhiteSpace(userinit))
                {
                    bool uiAnom = PersistenceZoneCatalog.IsWinlogonUserinitAnomalous(userinit, winDir);
                    string defaultUserinit = Path.Combine(winDir, "system32", "userinit.exe") + ",";
                    sink.Add(new PersistenceAnomalyRecord(
                        Vector: ThreatDetectionVector.WinlogonShellHijack,
                        RegistryOrTaskPath: $@"HKLM\{winlogonSubKey}",
                        EntryName: "Userinit",
                        PayloadCommandOrPath: userinit,
                        ReferencedExecutablePath: uiAnom ? ExtractSecondaryUserinitPayload(userinit, winDir) : null,
                        IsMissingSecurityDescriptorSd: false,
                        PreviousValueSerialized: userinit,
                        Category: PersistenceZone.WinlogonShellAndUserinit,
                        IsAnomaly: uiAnom,
                        IsSigned: !uiAnom,
                        RemediationKind: uiAnom ? PersistenceRemediationKind.RestoreRegistryDefault : PersistenceRemediationKind.None,
                        RemediationTarget: $@"HKLM|{winlogonSubKey}|Userinit|{defaultUserinit}"));
                }
            }

            // HKCU Winlogon Shell / Userinit (в чистой системе отсутствуют!)
            using var hkcuWl = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", writable: false);
            if (hkcuWl is not null)
            {
                foreach (var valName in new[] { "Shell", "Userinit", "Taskman" })
                {
                    var v = hkcuWl.GetValue(valName)?.ToString()?.Trim();
                    if (!string.IsNullOrWhiteSpace(v))
                    {
                        sink.Add(new PersistenceAnomalyRecord(
                            Vector: ThreatDetectionVector.WinlogonShellHijack,
                            RegistryOrTaskPath: @"HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
                            EntryName: valName,
                            PayloadCommandOrPath: v,
                            ReferencedExecutablePath: PersistenceZoneCatalog.ExtractExecutablePath(v),
                            IsMissingSecurityDescriptorSd: false,
                            PreviousValueSerialized: v,
                            Category: PersistenceZone.WinlogonShellAndUserinit,
                            IsAnomaly: true,
                            IsSigned: false,
                            RemediationKind: PersistenceRemediationKind.DeleteRegistryValue,
                            RemediationTarget: $@"HKCU|Software\Microsoft\Windows NT\CurrentVersion\Winlogon|{valName}"));
                    }
                }
            }
        }
        catch
        {
            // Пропуск
        }
    }

    private static void ScanIfeoAndSilentProcessExit(List<PersistenceAnomalyRecord> sink, CancellationToken ct)
    {
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
                    if (!string.IsNullOrWhiteSpace(debugger) &&
                        !debugger.Contains("vsjitdebugger.exe", StringComparison.OrdinalIgnoreCase))
                    {
                        sink.Add(new PersistenceAnomalyRecord(
                            Vector: ThreatDetectionVector.IfeoDebuggerHijack,
                            RegistryOrTaskPath: $@"HKLM\{ifeoPath}\{subName}",
                            EntryName: subName,
                            PayloadCommandOrPath: debugger,
                            ReferencedExecutablePath: PersistenceZoneCatalog.ExtractExecutablePath(debugger),
                            IsMissingSecurityDescriptorSd: false,
                            PreviousValueSerialized: debugger,
                            Category: PersistenceZone.IfeoAndSilentProcessExit,
                            IsAnomaly: true,
                            IsSigned: false,
                            RemediationKind: PersistenceRemediationKind.DeleteRegistryValue,
                            RemediationTarget: $@"HKLM|{ifeoPath}\{subName}|Debugger"));
                    }
                }
            }
        }
        catch { }

        const string spePath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit";
        try
        {
            using var speRoot = Registry.LocalMachine.OpenSubKey(spePath, writable: false);
            if (speRoot is not null)
            {
                foreach (var subName in speRoot.GetSubKeyNames())
                {
                    using var sub = speRoot.OpenSubKey(subName, writable: false);
                    var monitorProc = sub?.GetValue("MonitorProcess")?.ToString()?.Trim();
                    if (!string.IsNullOrWhiteSpace(monitorProc))
                    {
                        sink.Add(new PersistenceAnomalyRecord(
                            Vector: ThreatDetectionVector.IfeoSilentProcessExit,
                            RegistryOrTaskPath: $@"HKLM\{spePath}\{subName}",
                            EntryName: subName,
                            PayloadCommandOrPath: monitorProc,
                            ReferencedExecutablePath: PersistenceZoneCatalog.ExtractExecutablePath(monitorProc),
                            IsMissingSecurityDescriptorSd: false,
                            PreviousValueSerialized: monitorProc,
                            Category: PersistenceZone.IfeoAndSilentProcessExit,
                            IsAnomaly: true,
                            IsSigned: false,
                            RemediationKind: PersistenceRemediationKind.DeleteRegistrySubKey,
                            RemediationTarget: $@"HKLM|{spePath}\{subName}"));
                    }
                }
            }
        }
        catch { }
    }

    private void ScanSessionManagerAndBootExecute(List<PersistenceAnomalyRecord> sink, string winDir)
    {
        const string smPath = @"SYSTEM\CurrentControlSet\Control\Session Manager";
        try
        {
            using var sm = Registry.LocalMachine.OpenSubKey(smPath, writable: false);
            if (sm is null) return;

            if (sm.GetValue("BootExecute") is string[] bootExec)
            {
                bool anom = PersistenceZoneCatalog.IsBootExecuteAnomalous(bootExec, out var rogueLine);
                sink.Add(new PersistenceAnomalyRecord(
                    Vector: ThreatDetectionVector.BootExecuteOrSessionManager,
                    RegistryOrTaskPath: $@"HKLM\{smPath}",
                    EntryName: "BootExecute",
                    PayloadCommandOrPath: anom ? rogueLine : string.Join("; ", bootExec),
                    ReferencedExecutablePath: null,
                    IsMissingSecurityDescriptorSd: false,
                    PreviousValueSerialized: JsonSerializer.Serialize(bootExec),
                    Category: PersistenceZone.BootExecuteAndSessionManager,
                    IsAnomaly: anom,
                    IsSigned: !anom,
                    RemediationKind: anom ? PersistenceRemediationKind.RestoreRegistryDefault : PersistenceRemediationKind.None,
                    RemediationTarget: $@"HKLM|{smPath}|BootExecute|MULTI:autocheck autochk *"));
            }

            using var appCert = sm.OpenSubKey("AppCertDlls", writable: false);
            if (appCert is not null)
            {
                foreach (var valName in appCert.GetValueNames())
                {
                    var dllPath = appCert.GetValue(valName)?.ToString()?.Trim();
                    if (string.IsNullOrWhiteSpace(dllPath)) continue;
                    var resolved = PersistenceZoneCatalog.ExtractExecutablePath(dllPath) ?? dllPath;
                    bool signed = File.Exists(resolved) && VerifySignedCached(resolved);
                    sink.Add(new PersistenceAnomalyRecord(
                        Vector: ThreatDetectionVector.BootExecuteOrSessionManager,
                        RegistryOrTaskPath: $@"HKLM\{smPath}\AppCertDlls",
                        EntryName: valName,
                        PayloadCommandOrPath: dllPath,
                        ReferencedExecutablePath: !resolved.StartsWith(winDir, StringComparison.OrdinalIgnoreCase) ? resolved : null,
                        IsMissingSecurityDescriptorSd: false,
                        PreviousValueSerialized: dllPath,
                        Category: PersistenceZone.BootExecuteAndSessionManager,
                        IsAnomaly: !signed || PersistenceZoneCatalog.IsUserWritableOrStagingPath(resolved),
                        IsSigned: signed,
                        RemediationKind: PersistenceRemediationKind.DeleteRegistryValue,
                        RemediationTarget: $@"HKLM|{smPath}\AppCertDlls|{valName}"));
                }
            }
        }
        catch { }
    }

    private void ScanAppInitDlls(List<PersistenceAnomalyRecord> sink, string winDir)
    {
        const string winNtPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
        foreach (var (view, label) in new[] { (RegistryView.Registry64, "HKLM"), (RegistryView.Registry32, "HKLM32") })
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                using var key = baseKey.OpenSubKey(winNtPath, writable: false);
                if (key is null) continue;

                int loadFlag = key.GetValue("LoadAppInit_DLLs") is int f ? f : 0;
                var dlls = key.GetValue("AppInit_DLLs")?.ToString()?.Trim() ?? "";
                if (loadFlag != 0 && !string.IsNullOrWhiteSpace(dlls))
                {
                    var firstDll = PersistenceZoneCatalog.ExtractExecutablePath(dlls);
                    bool signed = !string.IsNullOrWhiteSpace(firstDll) && File.Exists(firstDll) && VerifySignedCached(firstDll);
                    sink.Add(new PersistenceAnomalyRecord(
                        Vector: ThreatDetectionVector.AppInitDllInjection,
                        RegistryOrTaskPath: $@"{label}\{winNtPath}",
                        EntryName: "AppInit_DLLs",
                        PayloadCommandOrPath: dlls,
                        ReferencedExecutablePath: firstDll is not null && !firstDll.StartsWith(winDir, StringComparison.OrdinalIgnoreCase) ? firstDll : null,
                        IsMissingSecurityDescriptorSd: false,
                        PreviousValueSerialized: dlls,
                        Category: PersistenceZone.AppInitDlls,
                        IsAnomaly: true,
                        IsSigned: signed,
                        RemediationKind: PersistenceRemediationKind.RestoreRegistryDefault,
                        RemediationTarget: $@"{label}|{winNtPath}|LoadAppInit_DLLs|DWORD:0"));
                }
            }
            catch { }
        }
    }

    private void ScanActiveSetup(List<PersistenceAnomalyRecord> sink, string winDir, CancellationToken ct)
    {
        const string activeSetupPath = @"SOFTWARE\Microsoft\Active Setup\Installed Components";
        foreach (var (hive, label) in new[] { (RegistryHive.LocalMachine, "HKLM"), (RegistryHive.CurrentUser, "HKCU") })
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                using var root = baseKey.OpenSubKey(activeSetupPath, writable: false);
                if (root is null) continue;

                foreach (var compId in root.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    using var sub = root.OpenSubKey(compId, writable: false);
                    var stub = sub?.GetValue("StubPath")?.ToString()?.Trim();
                    if (string.IsNullOrWhiteSpace(stub)) continue;

                    var exePath = PersistenceZoneCatalog.ExtractExecutablePath(stub);
                    bool inWindows = !string.IsNullOrWhiteSpace(exePath) &&
                                     exePath.StartsWith(winDir, StringComparison.OrdinalIgnoreCase);
                    bool signed = inWindows || (!string.IsNullOrWhiteSpace(exePath) && File.Exists(exePath) && VerifySignedCached(exePath));
                    bool suspicious = PersistenceZoneCatalog.IsUserWritableOrStagingPath(exePath) ||
                                      PersistenceZoneCatalog.HasSuspiciousScriptOrLolbinCommand(stub, out _) ||
                                      (hive == RegistryHive.CurrentUser && !signed);

                    if (suspicious)
                    {
                        sink.Add(new PersistenceAnomalyRecord(
                            Vector: ThreatDetectionVector.ActiveSetupStubHijack,
                            RegistryOrTaskPath: $@"{label}\{activeSetupPath}\{compId}",
                            EntryName: sub?.GetValue("")?.ToString() ?? compId,
                            PayloadCommandOrPath: stub,
                            ReferencedExecutablePath: !inWindows ? exePath : null,
                            IsMissingSecurityDescriptorSd: false,
                            PreviousValueSerialized: stub,
                            Category: PersistenceZone.ActiveSetupInstalledComponents,
                            IsAnomaly: true,
                            IsSigned: signed,
                            RemediationKind: PersistenceRemediationKind.DeleteRegistryValue,
                            RemediationTarget: $@"{label}|{activeSetupPath}\{compId}|StubPath"));
                    }
                }
            }
            catch { }
        }
    }

    private void ScanHkcuComHijacking(List<PersistenceAnomalyRecord> sink, string winDir, CancellationToken ct)
    {
        const string clsidRootPath = @"Software\Classes\CLSID";
        try
        {
            using var clsidRoot = Registry.CurrentUser.OpenSubKey(clsidRootPath, writable: false);
            if (clsidRoot is null) return;

            int checkedCount = 0;
            foreach (var clsid in clsidRoot.GetSubKeyNames())
            {
                if (++checkedCount > 1500) break;
                ct.ThrowIfCancellationRequested();

                foreach (var serverType in new[] { "InprocServer32", "LocalServer32" })
                {
                    using var srv = clsidRoot.OpenSubKey($@"{clsid}\{serverType}", writable: false);
                    var rawTarget = srv?.GetValue("")?.ToString()?.Trim();
                    if (string.IsNullOrWhiteSpace(rawTarget)) continue;

                    var targetPath = PersistenceZoneCatalog.ExtractExecutablePath(rawTarget) ?? rawTarget;
                    bool isScrobj = targetPath.EndsWith("scrobj.dll", StringComparison.OrdinalIgnoreCase);
                    bool isStaging = PersistenceZoneCatalog.IsUserWritableOrStagingPath(targetPath);
                    bool signed = !isScrobj && File.Exists(targetPath) && VerifySignedCached(targetPath);

                    // Легитимные приложения вроде OneDrive/Teams подписывают свои локальные COM-серверы цифровой подписью
                    bool isAnomaly = isScrobj || (!signed && (isStaging || !File.Exists(targetPath))) ||
                                     PersistenceZoneCatalog.HasSuspiciousScriptOrLolbinCommand(rawTarget, out _);

                    if (isAnomaly)
                    {
                        sink.Add(new PersistenceAnomalyRecord(
                            Vector: ThreatDetectionVector.ComClassHijack,
                            RegistryOrTaskPath: $@"HKCU\{clsidRootPath}\{clsid}\{serverType}",
                            EntryName: $"{clsid} ({serverType})",
                            PayloadCommandOrPath: rawTarget,
                            ReferencedExecutablePath: !isScrobj && !targetPath.StartsWith(winDir, StringComparison.OrdinalIgnoreCase) ? targetPath : null,
                            IsMissingSecurityDescriptorSd: false,
                            PreviousValueSerialized: rawTarget,
                            Category: PersistenceZone.ComInprocAndLocalServerHijack,
                            IsAnomaly: true,
                            IsSigned: signed,
                            PublisherOrNote: isScrobj ? "Скриптовый моникер scrobj.dll" : "Неподписанный COM-сервер в профиле пользователя",
                            RemediationKind: PersistenceRemediationKind.DeleteRegistrySubKey,
                            RemediationTarget: $@"HKCU|{clsidRootPath}\{clsid}"));
                    }
                }
            }
        }
        catch { }
    }

    private void ScanDotNetProfilerEnvironment(List<PersistenceAnomalyRecord> sink, string winDir)
    {
        var envLocations = new (RegistryKey Root, string Label, string SubKey)[]
        {
            (Registry.LocalMachine, "HKLM", @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
            (Registry.CurrentUser, "HKCU", @"Environment")
        };

        var profilerVars = new[]
        {
            "COR_PROFILER_PATH", "CORECLR_PROFILER_PATH", "DOTNET_STARTUP_HOOKS", "COR_PROFILER", "CORECLR_PROFILER"
        };

        foreach (var (root, label, subKey) in envLocations)
        {
            try
            {
                using var env = root.OpenSubKey(subKey, writable: false);
                if (env is null) continue;

                var corEnabled = env.GetValue("COR_ENABLE_PROFILING")?.ToString()?.Trim();
                var coreEnabled = env.GetValue("CORECLR_ENABLE_PROFILING")?.ToString()?.Trim();

                foreach (var varName in profilerVars)
                {
                    var val = env.GetValue(varName)?.ToString()?.Trim();
                    if (string.IsNullOrWhiteSpace(val)) continue;

                    // Для COR_PROFILER / CORECLR_PROFILER без _PATH срабатываем, если профилирование активно (=1)
                    if (varName is "COR_PROFILER" or "CORECLR_PROFILER" && corEnabled != "1" && coreEnabled != "1")
                    {
                        continue;
                    }

                    var pathCandidate = PersistenceZoneCatalog.ExtractExecutablePath(val);
                    bool signed = !string.IsNullOrWhiteSpace(pathCandidate) && File.Exists(pathCandidate) && VerifySignedCached(pathCandidate);

                    sink.Add(new PersistenceAnomalyRecord(
                        Vector: ThreatDetectionVector.DotNetProfilerHijack,
                        RegistryOrTaskPath: $@"{label}\{subKey}",
                        EntryName: varName,
                        PayloadCommandOrPath: val,
                        ReferencedExecutablePath: pathCandidate is not null && !pathCandidate.StartsWith(winDir, StringComparison.OrdinalIgnoreCase) ? pathCandidate : null,
                        IsMissingSecurityDescriptorSd: false,
                        PreviousValueSerialized: val,
                        Category: PersistenceZone.DotNetCorProfilerEnvironment,
                        IsAnomaly: !signed,
                        IsSigned: signed,
                        RemediationKind: !signed ? PersistenceRemediationKind.DeleteRegistryValue : PersistenceRemediationKind.None,
                        RemediationTarget: $@"{label}|{subKey}|{varName}"));
                }
            }
            catch { }
        }
    }

    private static void ScanLsaPackages(List<PersistenceAnomalyRecord> sink)
    {
        const string lsaPath = @"SYSTEM\CurrentControlSet\Control\Lsa";
        try
        {
            using var lsa = Registry.LocalMachine.OpenSubKey(lsaPath, writable: false);
            if (lsa is null) return;

            foreach (var valName in new[] { "Authentication Packages", "Notification Packages", "Security Packages" })
            {
                if (lsa.GetValue(valName) is not string[] pkgs) continue;

                foreach (var pkg in pkgs)
                {
                    var clean = pkg?.Trim();
                    if (string.IsNullOrWhiteSpace(clean) || StandardLsaPackages.Contains(clean))
                    {
                        continue;
                    }

                    sink.Add(new PersistenceAnomalyRecord(
                        Vector: ThreatDetectionVector.LsaOrSecurityProviderHijack,
                        RegistryOrTaskPath: $@"HKLM\{lsaPath}",
                        EntryName: $"{valName}: {clean}",
                        PayloadCommandOrPath: clean,
                        ReferencedExecutablePath: clean.Contains('\\') ? clean : null,
                        IsMissingSecurityDescriptorSd: false,
                        PreviousValueSerialized: JsonSerializer.Serialize(pkgs),
                        Category: PersistenceZone.LsaAndSecurityPackages,
                        IsAnomaly: true,
                        IsSigned: false,
                        PublisherOrNote: "Нестандартный пакет безопасности в LSA",
                        RemediationKind: PersistenceRemediationKind.None));
                }
            }
        }
        catch { }
    }

    private void ScanPrintMonitorsAndNetsh(List<PersistenceAnomalyRecord> sink, string winDir)
    {
        const string monitorsPath = @"SYSTEM\CurrentControlSet\Control\Print\Monitors";
        try
        {
            using var monRoot = Registry.LocalMachine.OpenSubKey(monitorsPath, writable: false);
            if (monRoot is not null)
            {
                foreach (var monName in monRoot.GetSubKeyNames())
                {
                    using var sub = monRoot.OpenSubKey(monName, writable: false);
                    var drv = sub?.GetValue("Driver")?.ToString()?.Trim();
                    if (string.IsNullOrWhiteSpace(drv)) continue;

                    string fullDll = drv.Contains('\\') ? drv : Path.Combine(winDir, "System32", drv);
                    bool inSys32 = fullDll.StartsWith(Path.Combine(winDir, "System32"), StringComparison.OrdinalIgnoreCase);
                    bool signed = File.Exists(fullDll) && VerifySignedCached(fullDll);

                    if (!inSys32 || (!signed && PersistenceZoneCatalog.IsUserWritableOrStagingPath(fullDll)))
                    {
                        sink.Add(new PersistenceAnomalyRecord(
                            Vector: ThreatDetectionVector.PrintMonitorOrNetshDll,
                            RegistryOrTaskPath: $@"HKLM\{monitorsPath}\{monName}",
                            EntryName: monName,
                            PayloadCommandOrPath: fullDll,
                            ReferencedExecutablePath: !inSys32 ? fullDll : null,
                            IsMissingSecurityDescriptorSd: false,
                            PreviousValueSerialized: drv,
                            Category: PersistenceZone.PrintMonitorsAndNetshHelpers,
                            IsAnomaly: true,
                            IsSigned: signed,
                            RemediationKind: PersistenceRemediationKind.DeleteRegistrySubKey,
                            RemediationTarget: $@"HKLM|{monitorsPath}\{monName}"));
                    }
                }
            }
        }
        catch { }

        const string netshPath = @"SOFTWARE\Microsoft\NetSh";
        try
        {
            using var netsh = Registry.LocalMachine.OpenSubKey(netshPath, writable: false);
            if (netsh is not null)
            {
                foreach (var valName in netsh.GetValueNames())
                {
                    var dll = netsh.GetValue(valName)?.ToString()?.Trim();
                    if (string.IsNullOrWhiteSpace(dll)) continue;

                    string fullDll = dll.Contains('\\') ? Environment.ExpandEnvironmentVariables(dll) : Path.Combine(winDir, "System32", dll);
                    bool inSys32 = fullDll.StartsWith(Path.Combine(winDir, "System32"), StringComparison.OrdinalIgnoreCase);
                    if (!inSys32)
                    {
                        bool signed = File.Exists(fullDll) && VerifySignedCached(fullDll);
                        if (!signed || PersistenceZoneCatalog.IsUserWritableOrStagingPath(fullDll))
                        {
                            sink.Add(new PersistenceAnomalyRecord(
                                Vector: ThreatDetectionVector.PrintMonitorOrNetshDll,
                                RegistryOrTaskPath: $@"HKLM\{netshPath}",
                                EntryName: $"NetSh: {valName}",
                                PayloadCommandOrPath: fullDll,
                                ReferencedExecutablePath: fullDll,
                                IsMissingSecurityDescriptorSd: false,
                                PreviousValueSerialized: dll,
                                Category: PersistenceZone.PrintMonitorsAndNetshHelpers,
                                IsAnomaly: true,
                                IsSigned: signed,
                                RemediationKind: PersistenceRemediationKind.DeleteRegistryValue,
                                RemediationTarget: $@"HKLM|{netshPath}|{valName}"));
                        }
                    }
                }
            }
        }
        catch { }
    }

    private void ScanServicesAndDrivers(List<PersistenceAnomalyRecord> sink, string winDir, CancellationToken ct)
    {
        const string servicesRootPath = @"SYSTEM\CurrentControlSet\Services";
        var catalog = ThreatIndicatorCatalog.Shared;
        var winPrefix = winDir.TrimEnd('\\') + @"\";

        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(servicesRootPath, writable: false);
            if (root is null) return;

            foreach (var svcName in root.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                using var svc = root.OpenSubKey(svcName, writable: false);
                if (svc is null) continue;

                int start = svc.GetValue("Start") is int s ? s : 4;
                if (start == 4) continue; // Отключенные службы не активны

                var rawImagePath = svc.GetValue("ImagePath")?.ToString()?.Trim();
                if (string.IsNullOrWhiteSpace(rawImagePath)) continue;

                var exePath = PersistenceZoneCatalog.ExtractExecutablePath(rawImagePath) ?? rawImagePath;
                var fileName = Path.GetFileName(exePath);
                bool inWindows = exePath.StartsWith(winPrefix, StringComparison.OrdinalIgnoreCase);

                // Проверяем подмену Parameters\ServiceDll у хост-служб
                using var parms = svc.OpenSubKey("Parameters", writable: false);
                var serviceDll = parms?.GetValue("ServiceDll")?.ToString()?.Trim();
                if (!string.IsNullOrWhiteSpace(serviceDll))
                {
                    var resolvedDll = PersistenceZoneCatalog.ExtractExecutablePath(serviceDll) ?? Environment.ExpandEnvironmentVariables(serviceDll);
                    bool dllInWin = resolvedDll.StartsWith(winPrefix, StringComparison.OrdinalIgnoreCase);
                    if (!dllInWin)
                    {
                        bool dllSigned = File.Exists(resolvedDll) && VerifySignedCached(resolvedDll);
                        if (!dllSigned || PersistenceZoneCatalog.IsUserWritableOrStagingPath(resolvedDll))
                        {
                            sink.Add(new PersistenceAnomalyRecord(
                                Vector: ThreatDetectionVector.SuspiciousServiceOrDriver,
                                RegistryOrTaskPath: $@"HKLM\{servicesRootPath}\{svcName}\Parameters",
                                EntryName: $"{svcName} (ServiceDll)",
                                PayloadCommandOrPath: resolvedDll,
                                ReferencedExecutablePath: resolvedDll,
                                IsMissingSecurityDescriptorSd: false,
                                PreviousValueSerialized: serviceDll,
                                Category: PersistenceZone.WindowsServicesAndDrivers,
                                IsAnomaly: true,
                                IsSigned: dllSigned,
                                PublisherOrNote: "(подмена библиотеки ServiceDll)",
                                RemediationKind: PersistenceRemediationKind.DisableWindowsService,
                                RemediationTarget: svcName));
                        }
                    }
                }

                if (inWindows && !PersistenceZoneCatalog.HasSuspiciousScriptOrLolbinCommand(rawImagePath, out _))
                {
                    continue;
                }

                bool isKnownRogueName = catalog.KnownRogueServiceAndTaskNames.Contains(svcName);
                bool isAbusedDriver = catalog.AbusedDriverFileNames.Contains(fileName) && PersistenceZoneCatalog.IsUserWritableOrStagingPath(exePath);
                bool hasMinerOrScriptCmd = PersistenceZoneCatalog.HasSuspiciousScriptOrLolbinCommand(rawImagePath, out var cmdMarker);
                bool isStaging = PersistenceZoneCatalog.IsUserWritableOrStagingPath(exePath);
                bool signed = File.Exists(exePath) && VerifySignedCached(exePath);

                bool isAnomaly = isKnownRogueName || isAbusedDriver || hasMinerOrScriptCmd || (isStaging && !signed);
                if (isAnomaly)
                {
                    string note = isAbusedDriver
                        ? "(уязвимый MSR-драйвер в пользовательской папке — типично для XMRig/SilentCryptoMiner)"
                        : hasMinerOrScriptCmd ? $"(признак: {cmdMarker})" : "";

                    sink.Add(new PersistenceAnomalyRecord(
                        Vector: ThreatDetectionVector.SuspiciousServiceOrDriver,
                        RegistryOrTaskPath: $@"HKLM\{servicesRootPath}\{svcName}",
                        EntryName: svcName,
                        PayloadCommandOrPath: rawImagePath,
                        ReferencedExecutablePath: !inWindows && File.Exists(exePath) ? exePath : null,
                        IsMissingSecurityDescriptorSd: false,
                        PreviousValueSerialized: rawImagePath,
                        Category: PersistenceZone.WindowsServicesAndDrivers,
                        IsAnomaly: true,
                        IsSigned: signed,
                        PublisherOrNote: note,
                        RemediationKind: PersistenceRemediationKind.DisableWindowsService,
                        RemediationTarget: svcName));
                }
            }
        }
        catch { }
    }

    private void ScanScheduledTasksAndGhostSd(List<PersistenceAnomalyRecord> sink, string winDir, CancellationToken ct)
    {
        // 1. Поиск призрачных задач без дескриптора безопасности SD в TaskCache\Tree
        const string taskTreePath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree";
        try
        {
            using var treeRoot = Registry.LocalMachine.OpenSubKey(taskTreePath, writable: false);
            if (treeRoot is not null)
            {
                ScanTaskTreeForMissingSd(treeRoot, "", depth: 0, sink, ct);
            }
        }
        catch { }

        // 2. Проверка всех задач планировщика (включая скрытые TASK_ENUM_HIDDEN) через нативный COM Schedule.Service
        var catalog = ThreatIndicatorCatalog.Shared;
        var winPrefix = winDir.TrimEnd('\\') + @"\";
        try
        {
            foreach (var task in WindowsTaskScheduler.List(ct))
            {
                if (!task.Enabled || string.IsNullOrWhiteSpace(task.ActionSummary))
                {
                    continue;
                }

                bool knownRogue = catalog.KnownRogueServiceAndTaskNames.Contains(task.Name);
                bool hasScriptOrPool = PersistenceZoneCatalog.HasSuspiciousScriptOrLolbinCommand(task.ActionSummary, out var marker);
                var exePath = PersistenceZoneCatalog.ExtractExecutablePath(task.ActionSummary);
                bool inWindows = !string.IsNullOrWhiteSpace(exePath) && exePath.StartsWith(winPrefix, StringComparison.OrdinalIgnoreCase);
                bool isStaging = PersistenceZoneCatalog.IsUserWritableOrStagingPath(exePath);
                bool signed = inWindows || (!string.IsNullOrWhiteSpace(exePath) && File.Exists(exePath) && VerifySignedCached(exePath));

                bool isAnomaly = knownRogue || hasScriptOrPool || (isStaging && !signed);
                if (isAnomaly || !task.IsMicrosoft)
                {
                    sink.Add(new PersistenceAnomalyRecord(
                        Vector: ThreatDetectionVector.SuspiciousScheduledTask,
                        RegistryOrTaskPath: task.TaskPath,
                        EntryName: task.Name,
                        PayloadCommandOrPath: task.ActionSummary,
                        ReferencedExecutablePath: isAnomaly && !inWindows ? exePath : null,
                        IsMissingSecurityDescriptorSd: false,
                        PreviousValueSerialized: task.ActionSummary,
                        Category: PersistenceZone.ScheduledTasksAndGhostSd,
                        IsAnomaly: isAnomaly,
                        IsSigned: signed,
                        PublisherOrNote: hasScriptOrPool ? $"Признак: {marker}" : task.Author,
                        RemediationKind: isAnomaly ? PersistenceRemediationKind.DisableScheduledTask : PersistenceRemediationKind.None,
                        RemediationTarget: task.TaskPath));
                }
            }
        }
        catch { }
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

                if (!string.IsNullOrWhiteSpace(taskId) && sd is null)
                {
                    var regSubPath = $@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree{taskPath}";
                    sink.Add(new PersistenceAnomalyRecord(
                        Vector: ThreatDetectionVector.HiddenScheduledTask,
                        RegistryOrTaskPath: $@"HKLM\{regSubPath}",
                        EntryName: taskPath,
                        PayloadCommandOrPath: $"TaskId={taskId} (стёрт дескриптор безопасности SD)",
                        ReferencedExecutablePath: null,
                        IsMissingSecurityDescriptorSd: true,
                        PreviousValueSerialized: taskId,
                        Category: PersistenceZone.ScheduledTasksAndGhostSd,
                        IsAnomaly: true,
                        IsSigned: false,
                        PublisherOrNote: "Скрытая задача (Ghost Task)",
                        RemediationKind: PersistenceRemediationKind.DeleteScheduledTask,
                        RemediationTarget: $"HKLM|{regSubPath}"));
                }

                ScanTaskTreeForMissingSd(child, taskPath, depth + 1, sink, ct);
            }
            catch { }
        }
    }

    private static void ScanWmiSubscriptionsAndBits(List<PersistenceAnomalyRecord> sink, CancellationToken ct)
    {
        const string script =
            "$out = @(); " +
            "Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue | ForEach-Object { " +
            "  $out += [pscustomobject]@{ Kind='WMI'; Name=$_.Name; Payload=($_.ExecutablePath + ' ' + $_.CommandLineTemplate).Trim() } " +
            "}; " +
            "Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue | ForEach-Object { " +
            "  $out += [pscustomobject]@{ Kind='WMI'; Name=$_.Name; Payload=($_.ScriptingEngine + ': ' + $_.ScriptText).Trim() } " +
            "}; " +
            "Get-BitsTransfer -ErrorAction SilentlyContinue | Where-Object { $_.JobState -ne 'Transferred' -and $_.JobState -ne 'Cancelled' } | ForEach-Object { " +
            "  $out += [pscustomobject]@{ Kind='BITS'; Name=$_.DisplayName; Payload=($_.FileList | Select-Object -First 1 -ExpandProperty RemoteName) } " +
            "}; " +
            "$out | ConvertTo-Json -Compress";

        try
        {
            var json = QueryPowerShellJson(script, timeoutMs: 3500, ct);
            if (string.IsNullOrWhiteSpace(json)) return;

            using var doc = JsonDocument.Parse(json);
            var elements = doc.RootElement.ValueKind == JsonValueKind.Array
                ? doc.RootElement.EnumerateArray().ToList()
                : [doc.RootElement];

            foreach (var el in elements)
            {
                var kind = el.TryGetProperty("Kind", out var k) ? k.GetString() ?? "" : "";
                var name = el.TryGetProperty("Name", out var n) ? n.GetString() ?? "" : "";
                var payload = el.TryGetProperty("Payload", out var p) ? p.GetString() ?? "" : "";
                if (string.IsNullOrWhiteSpace(name) && string.IsNullOrWhiteSpace(payload)) continue;

                if (kind == "WMI")
                {
                    // Пропускаем стандартный пустой SCM Event Log Consumer от самой Windows
                    if (name.Equals("SCM Event Log Consumer", StringComparison.OrdinalIgnoreCase) && string.IsNullOrWhiteSpace(payload))
                    {
                        continue;
                    }

                    sink.Add(new PersistenceAnomalyRecord(
                        Vector: ThreatDetectionVector.WmiPermanentSubscription,
                        RegistryOrTaskPath: @"WMI::root\subscription",
                        EntryName: name,
                        PayloadCommandOrPath: payload,
                        ReferencedExecutablePath: PersistenceZoneCatalog.ExtractExecutablePath(payload),
                        IsMissingSecurityDescriptorSd: false,
                        PreviousValueSerialized: payload,
                        Category: PersistenceZone.WmiPermanentSubscriptions,
                        IsAnomaly: true,
                        IsSigned: false,
                        RemediationKind: PersistenceRemediationKind.DeleteWmiSubscription,
                        RemediationTarget: name));
                }
                else if (kind == "BITS" && !string.IsNullOrWhiteSpace(payload))
                {
                    bool trustedMicrosoft = payload.Contains(".microsoft.com/", StringComparison.OrdinalIgnoreCase) ||
                                            payload.Contains(".windowsupdate.com/", StringComparison.OrdinalIgnoreCase) ||
                                            payload.Contains(".delivery.mp.microsoft.com/", StringComparison.OrdinalIgnoreCase);

                    if (!trustedMicrosoft)
                    {
                        sink.Add(new PersistenceAnomalyRecord(
                            Vector: ThreatDetectionVector.BitsPersistenceJob,
                            RegistryOrTaskPath: "BITS::TransferQueue",
                            EntryName: name,
                            PayloadCommandOrPath: payload,
                            ReferencedExecutablePath: null,
                            IsMissingSecurityDescriptorSd: false,
                            PreviousValueSerialized: payload,
                            Category: PersistenceZone.BitsPersistentJobs,
                            IsAnomaly: true,
                            IsSigned: false,
                            RemediationKind: PersistenceRemediationKind.CancelBitsJob,
                            RemediationTarget: name));
                    }
                }
            }
        }
        catch { }
    }

    private void ScanExplorerShellHooks(List<PersistenceAnomalyRecord> sink, string winDir)
    {
        const string delayLoadPath = @"Software\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjectDelayLoad";
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(delayLoadPath, writable: false);
            if (key is null) return;

            foreach (var name in key.GetValueNames())
            {
                var clsid = key.GetValue(name)?.ToString()?.Trim();
                if (string.IsNullOrWhiteSpace(clsid)) continue;

                using var srv = Registry.CurrentUser.OpenSubKey($@"Software\Classes\CLSID\{clsid}\InprocServer32", writable: false);
                var dll = srv?.GetValue("")?.ToString()?.Trim() ?? clsid;
                var resolved = PersistenceZoneCatalog.ExtractExecutablePath(dll) ?? dll;
                bool signed = File.Exists(resolved) && VerifySignedCached(resolved);

                sink.Add(new PersistenceAnomalyRecord(
                    Vector: ThreatDetectionVector.SuspiciousRegistryAutorun,
                    RegistryOrTaskPath: $@"HKCU\{delayLoadPath}",
                    EntryName: name,
                    PayloadCommandOrPath: dll,
                    ReferencedExecutablePath: !resolved.StartsWith(winDir, StringComparison.OrdinalIgnoreCase) && File.Exists(resolved) ? resolved : null,
                    IsMissingSecurityDescriptorSd: false,
                    PreviousValueSerialized: clsid,
                    Category: PersistenceZone.ShellExtensionsAndBrowserHooks,
                    IsAnomaly: !signed,
                    IsSigned: signed,
                    RemediationKind: !signed ? PersistenceRemediationKind.DeleteRegistryValue : PersistenceRemediationKind.None,
                    RemediationTarget: $@"HKCU|{delayLoadPath}|{name}"));
            }
        }
        catch { }
    }

    private static void ScanPowerShellProfiles(List<PersistenceAnomalyRecord> sink)
    {
        var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

        var candidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(docs))
        {
            candidates.Add(Path.Combine(docs, "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1"));
            candidates.Add(Path.Combine(docs, "WindowsPowerShell", "profile.ps1"));
            candidates.Add(Path.Combine(docs, "PowerShell", "Microsoft.PowerShell_profile.ps1"));
        }

        if (!string.IsNullOrWhiteSpace(winDir))
        {
            candidates.Add(Path.Combine(winDir, "System32", "WindowsPowerShell", "v1.0", "profile.ps1"));
        }

        foreach (var profilePath in candidates.Where(File.Exists))
        {
            try
            {
                var info = new FileInfo(profilePath);
                if (info.Length > 512 * 1024) continue;
                var content = File.ReadAllText(profilePath);
                bool suspicious = PersistenceZoneCatalog.HasSuspiciousScriptOrLolbinCommand(content, out var marker);

                sink.Add(new PersistenceAnomalyRecord(
                    Vector: ThreatDetectionVector.PowerShellProfileHijack,
                    RegistryOrTaskPath: profilePath,
                    EntryName: Path.GetFileName(profilePath),
                    PayloadCommandOrPath: suspicious ? $"Обнаружена подозрительная команда ({marker})" : profilePath,
                    ReferencedExecutablePath: suspicious && !profilePath.StartsWith(winDir, StringComparison.OrdinalIgnoreCase) ? profilePath : null,
                    IsMissingSecurityDescriptorSd: false,
                    PreviousValueSerialized: null,
                    Category: PersistenceZone.PowerShellProfiles,
                    IsAnomaly: suspicious,
                    IsSigned: false,
                    RemediationKind: suspicious ? PersistenceRemediationKind.QuarantineStartupFile : PersistenceRemediationKind.None,
                    RemediationTarget: profilePath));
            }
            catch { }
        }
    }

    // ==================== ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ РЕЕСТРА И ОТКАТА ====================

    private void InspectCommandValuesInKey(
        RegistryHive hive,
        RegistryView view,
        string hiveLabel,
        string subKeyPath,
        PersistenceZone zone,
        ThreatDetectionVector vector,
        string winDir,
        bool includeHealthyEntries,
        List<PersistenceAnomalyRecord> sink,
        bool forceSuspiciousWhenUnsigned = false)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, view);
            using var sub = baseKey.OpenSubKey(subKeyPath, writable: false);
            if (sub is null) return;

            var winPrefix = winDir.TrimEnd('\\') + @"\";
            foreach (var valName in sub.GetValueNames())
            {
                var cmd = sub.GetValue(valName)?.ToString()?.Trim();
                if (string.IsNullOrWhiteSpace(cmd)) continue;

                var exePath = PersistenceZoneCatalog.ExtractExecutablePath(cmd);
                bool inWin = !string.IsNullOrWhiteSpace(exePath) && exePath.StartsWith(winPrefix, StringComparison.OrdinalIgnoreCase);
                bool exists = !string.IsNullOrWhiteSpace(exePath) && File.Exists(exePath);
                bool signed = inWin || (exists && VerifySignedCached(exePath!));

                bool hasBadCmd = PersistenceZoneCatalog.HasSuspiciousScriptOrLolbinCommand(cmd, out var marker);
                bool inStaging = PersistenceZoneCatalog.IsUserWritableOrStagingPath(exePath);
                bool isAnomaly = hasBadCmd || (inStaging && !signed) || (forceSuspiciousWhenUnsigned && !signed);

                if (!isAnomaly && !includeHealthyEntries)
                {
                    continue;
                }

                sink.Add(new PersistenceAnomalyRecord(
                    Vector: vector,
                    RegistryOrTaskPath: $@"{hiveLabel}\{subKeyPath}",
                    EntryName: string.IsNullOrWhiteSpace(valName) ? "(По умолчанию)" : valName,
                    PayloadCommandOrPath: cmd,
                    ReferencedExecutablePath: isAnomaly && !inWin && exists ? exePath : null,
                    IsMissingSecurityDescriptorSd: false,
                    PreviousValueSerialized: cmd,
                    Category: zone,
                    IsAnomaly: isAnomaly,
                    IsSigned: signed,
                    PublisherOrNote: hasBadCmd ? $"Признак: {marker}" : "",
                    RemediationKind: isAnomaly ? PersistenceRemediationKind.DeleteRegistryValue : PersistenceRemediationKind.None,
                    RemediationTarget: $"{hiveLabel}|{subKeyPath}|{valName}"));
            }
        }
        catch { }
    }

    private static (bool Succeeded, StateTargetKind? RollbackKind, string? RollbackTarget, string? PreviousStateJson) RemediateRegistryValue(
        PersistenceAnomalyRecord record)
    {
        var parts = record.RemediationTarget.Split('|');
        if (parts.Length < 3) return (false, null, null, null);

        var hiveLabel = parts[0];
        var subKeyPath = parts[1];
        var valueName = parts[2];
        var (hive, view, normalizedHive) = ParseHiveAndView(hiveLabel);

        using var baseKey = RegistryKey.OpenBaseKey(hive, view);
        using var key = baseKey.OpenSubKey(subKeyPath, writable: true);
        if (key is null) return (false, null, null, null);

        var prevVal = key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        if (prevVal is null) return (false, null, null, null);

        var prevKind = key.GetValueKind(valueName);
        string serializedPrev = prevKind switch
        {
            RegistryValueKind.MultiString when prevVal is string[] arr => JsonSerializer.Serialize(arr),
            RegistryValueKind.Binary when prevVal is byte[] bytes => Convert.ToBase64String(bytes),
            _ => Convert.ToString(prevVal, CultureInfo.InvariantCulture) ?? ""
        };

        if (record.RemediationKind == PersistenceRemediationKind.RestoreRegistryDefault && parts.Length >= 4)
        {
            var defaultSpec = parts[3];
            if (defaultSpec.StartsWith("DWORD:", StringComparison.OrdinalIgnoreCase) &&
                int.TryParse(defaultSpec[6..], NumberStyles.Integer, CultureInfo.InvariantCulture, out int dw))
            {
                key.SetValue(valueName, dw, RegistryValueKind.DWord);
            }
            else if (defaultSpec.StartsWith("MULTI:", StringComparison.OrdinalIgnoreCase))
            {
                key.SetValue(valueName, new[] { defaultSpec[6..] }, RegistryValueKind.MultiString);
            }
            else
            {
                key.SetValue(valueName, defaultSpec, RegistryValueKind.String);
            }
        }
        else
        {
            key.DeleteValue(valueName, throwOnMissingValue: false);
        }

        var snapshotJson = JsonSerializer.Serialize(new
        {
            Hive = normalizedHive,
            SubKey = subKeyPath,
            ValueName = valueName,
            ExistedBefore = true,
            ValueKind = (int)prevKind,
            SerializedData = serializedPrev
        });

        return (true, StateTargetKind.RegistryValue, $@"{normalizedHive}\{subKeyPath}::{valueName}", snapshotJson);
    }

    private static (bool Succeeded, StateTargetKind? RollbackKind, string? RollbackTarget, string? PreviousStateJson) RemediateRegistrySubKey(
        PersistenceAnomalyRecord record)
    {
        var parts = record.RemediationTarget.Split('|');
        if (parts.Length < 2) return (false, null, null, null);

        var (hive, view, normalizedHive) = ParseHiveAndView(parts[0]);
        var subKeyPath = parts[1];

        using var baseKey = RegistryKey.OpenBaseKey(hive, view);
        baseKey.DeleteSubKeyTree(subKeyPath, throwOnMissingSubKey: false);

        return (true, StateTargetKind.SystemSetting, $"DeletedRegistryKey:{normalizedHive}\\{subKeyPath}", record.PreviousValueSerialized ?? "{}");
    }

    private static (RegistryHive Hive, RegistryView View, string NormalizedHive) ParseHiveAndView(string label) =>
        label.ToUpperInvariant() switch
        {
            "HKLM32" => (RegistryHive.LocalMachine, RegistryView.Registry32, "HKLM"),
            "HKLM" => (RegistryHive.LocalMachine, RegistryView.Default, "HKLM"),
            _ => (RegistryHive.CurrentUser, RegistryView.Default, "HKCU")
        };

    private static string? ExtractSecondaryUserinitPayload(string userinit, string winDir)
    {
        var expected = Path.Combine(winDir, "system32", "userinit.exe");
        foreach (var part in userinit.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var p = PersistenceZoneCatalog.ExtractExecutablePath(part);
            if (!string.IsNullOrWhiteSpace(p) &&
                !p.Equals("userinit.exe", StringComparison.OrdinalIgnoreCase) &&
                !p.Equals(expected, StringComparison.OrdinalIgnoreCase))
            {
                return p;
            }
        }

        return null;
    }

    /// <summary>
    /// Быстрое извлечение целевого пути из бинарного файла ярлыка .lnk без создания COM-объектов WScript.Shell.
    /// </summary>
    private static string? ExtractShortcutTargetFast(string lnkPath)
    {
        try
        {
            var bytes = File.ReadAllBytes(lnkPath);
            if (bytes.Length < 76 || bytes[0] != 0x4C) return null;

            // Ищем UTF-16LE и ASCII-пути вида X:\... внутри тела ярлыка
            var uniText = Encoding.Unicode.GetString(bytes);
            var candidate = ScanDrivePathInText(uniText) ?? ScanDrivePathInText(Encoding.ASCII.GetString(bytes));
            return candidate;
        }
        catch
        {
            return null;
        }
    }

    private static string? ScanDrivePathInText(string raw)
    {
        for (int i = 0; i < raw.Length - 6; i++)
        {
            if (char.IsAsciiLetter(raw[i]) && raw[i + 1] == ':' && raw[i + 2] == '\\')
            {
                int end = i;
                while (end < raw.Length && raw[end] >= 32 && raw[end] != '\0' && raw[end] != '"' && raw[end] != '<' && raw[end] != '>')
                {
                    end++;
                }

                var slice = raw[i..end].Trim();
                if (slice.Length >= 7 && (slice.Contains(".exe", StringComparison.OrdinalIgnoreCase) ||
                                          slice.Contains(".bat", StringComparison.OrdinalIgnoreCase) ||
                                          slice.Contains(".vbs", StringComparison.OrdinalIgnoreCase) ||
                                          slice.Contains(".cmd", StringComparison.OrdinalIgnoreCase) ||
                                          slice.Contains(".ps1", StringComparison.OrdinalIgnoreCase)))
                {
                    return slice;
                }
            }
        }

        return null;
    }

    internal static string QueryPowerShellJson(string command, int timeoutMs, CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8
        };
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-NonInteractive");
        psi.ArgumentList.Add("-ExecutionPolicy");
        psi.ArgumentList.Add("Bypass");
        psi.ArgumentList.Add("-Command");
        psi.ArgumentList.Add($"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; {command}");

        using var proc = Process.Start(psi);
        if (proc is null) return "";

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);

        try
        {
            var result = proc.StandardOutput.ReadToEndAsync(cts.Token).AsTask().GetAwaiter().GetResult();
            proc.WaitForExit(1000);
            return result.Trim();
        }
        catch
        {
            try { if (!proc.HasExited) proc.Kill(); } catch { }
            return "";
        }
    }

    internal static bool RunShortPowerShell(string command, int timeoutMs)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            psi.ArgumentList.Add("-NoProfile");
            psi.ArgumentList.Add("-NonInteractive");
            psi.ArgumentList.Add("-ExecutionPolicy");
            psi.ArgumentList.Add("Bypass");
            psi.ArgumentList.Add("-Command");
            psi.ArgumentList.Add(command);

            using var proc = Process.Start(psi);
            if (proc is null) return false;
            if (!proc.WaitForExit(timeoutMs))
            {
                try { proc.Kill(); } catch { }
                return false;
            }

            return proc.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    private static string EscapeWmiSingleQuotes(string value) =>
        (value ?? "").Replace("'", "''", StringComparison.Ordinal);
}
