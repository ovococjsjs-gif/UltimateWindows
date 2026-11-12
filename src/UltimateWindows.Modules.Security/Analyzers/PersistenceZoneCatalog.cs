using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Security.Catalog;
using UltimateWindows.Modules.Security.Models;

namespace UltimateWindows.Modules.Security.Analyzers;

/// <summary>
/// Декларативный классификатор 18 зон автозакрепления, исключений Defender и путей пользовательских папок.
/// Работает детерминированно без обращения к ОС, что позволяет на 100% покрыть все эвристики модульными тестами.
/// </summary>
public static class PersistenceZoneCatalog
{
    public static readonly IReadOnlyList<PersistenceZone> AllZones =
    [
        PersistenceZone.RunAndRunOnceKeys,
        PersistenceZone.PoliciesExplorerRun,
        PersistenceZone.StartupFoldersAndShellRedirection,
        PersistenceZone.WinlogonShellAndUserinit,
        PersistenceZone.IfeoAndSilentProcessExit,
        PersistenceZone.BootExecuteAndSessionManager,
        PersistenceZone.AppInitDlls,
        PersistenceZone.ActiveSetupInstalledComponents,
        PersistenceZone.ComInprocAndLocalServerHijack,
        PersistenceZone.DotNetCorProfilerEnvironment,
        PersistenceZone.LsaAndSecurityPackages,
        PersistenceZone.PrintMonitorsAndNetshHelpers,
        PersistenceZone.WindowsServicesAndDrivers,
        PersistenceZone.ScheduledTasksAndGhostSd,
        PersistenceZone.WmiPermanentSubscriptions,
        PersistenceZone.BitsPersistentJobs,
        PersistenceZone.ShellExtensionsAndBrowserHooks,
        PersistenceZone.PowerShellProfiles
    ];

    private static readonly string[] SuspiciousPathSegments =
    [
        @"\appdata\roaming\",
        @"\appdata\local\temp\",
        @"\windows\temp\",
        @"\users\public\",
        @"\programdata\",
        @"\perflogs\",
        @"\$recycle.bin\",
        @"\systemvolumeinformation\"
    ];

    private static readonly string[] HighRiskScriptAndLolbinMarkers =
    [
        "-encodedcommand",
        " -enc ",
        " -e ",
        "frombase64string",
        "downloadstring(",
        "downloadfile(",
        "invoke-expression",
        "iex(",
        "mshta",
        "wscript",
        "cscript",
        "regsvr32 /s /n /u /i:",
        "rundll32 javascript:",
        "certutil -urlcache",
        "bitsadmin /transfer",
        "-windowstyle hidden",
        "-w hidden"
    ];

    private static readonly string[] TrustedProgramDataVendors =
    [
        @"\programdata\microsoft\windows defender\",
        @"\programdata\microsoft\windows\",
        @"\programdata\nvidia corporation\",
        @"\programdata\amd\",
        @"\programdata\intel\",
        @"\programdata\package cache\"
    ];

    private static readonly string[] DangerousDefenderExtensions =
    [
        ".exe", "exe", "*.exe",
        ".dll", "dll", "*.dll",
        ".sys", "sys", "*.sys",
        ".bat", "bat", "*.bat",
        ".cmd", "cmd", "*.cmd",
        ".ps1", "ps1", "*.ps1",
        ".vbs", "vbs", "*.vbs",
        ".js", "js", "*.js",
        ".scr", "scr", "*.scr",
        ".com", "com", "*.com"
    ];

    /// <summary>
    /// Проверяет, лежит ли исполняемый файл во временной или пользовательской папке, характерной для дропперов/майнеров.
    /// </summary>
    public static bool IsUserWritableOrStagingPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var normalized = path.Trim().Trim('"').Replace('/', '\\').ToLowerInvariant();

        foreach (var trusted in TrustedProgramDataVendors)
        {
            if (normalized.Contains(trusted, StringComparison.Ordinal))
            {
                return false;
            }
        }

        foreach (var seg in SuspiciousPathSegments)
        {
            if (normalized.Contains(seg, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Проверяет наличие обфусцированного скрипта, PowerShell -EncodedCommand или опасного LOLBin-однострочника.
    /// </summary>
    public static bool HasSuspiciousScriptOrLolbinCommand(string? commandLine, out string matchedMarker)
    {
        matchedMarker = "";
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return false;
        }

        foreach (var marker in HighRiskScriptAndLolbinMarkers)
        {
            if (commandLine.Contains(marker, StringComparison.OrdinalIgnoreCase))
            {
                matchedMarker = marker.Trim();
                return true;
            }
        }

        var catalog = ThreatIndicatorCatalog.Shared;
        foreach (var cli in catalog.MinerCliMarkers)
        {
            if (commandLine.Contains(cli, StringComparison.OrdinalIgnoreCase))
            {
                matchedMarker = cli;
                return true;
            }
        }

        if (catalog.MatchesMiningPoolDomain(commandLine, out var domain))
        {
            matchedMarker = domain;
            return true;
        }

        return false;
    }

    /// <summary>
    /// Проверяет корректность штатного значения Winlogon Userinit (допускается только C:\Windows\system32\userinit.exe,).
    /// </summary>
    public static bool IsWinlogonUserinitAnomalous(string? userinitValue, string windowsDirectory)
    {
        if (string.IsNullOrWhiteSpace(userinitValue))
        {
            return false;
        }

        var parts = userinitValue.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length == 0)
        {
            return false;
        }

        if (parts.Length > 1)
        {
            return true;
        }

        var single = parts[0].Trim('"');
        if (single.Equals("userinit.exe", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var expectedSys32 = Path.Combine(windowsDirectory, "system32", "userinit.exe");
        return !single.Equals(expectedSys32, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Проверяет корректность штатного значения BootExecute (допускается пусто или autocheck autochk *).
    /// </summary>
    public static bool IsBootExecuteAnomalous(IEnumerable<string>? lines, out string rogueLine)
    {
        rogueLine = "";
        if (lines is null)
        {
            return false;
        }

        foreach (var raw in lines)
        {
            var trimmed = raw?.Trim();
            if (string.IsNullOrWhiteSpace(trimmed))
            {
                continue;
            }

            if (!trimmed.Equals("autocheck autochk *", StringComparison.OrdinalIgnoreCase) &&
                !trimmed.StartsWith("autocheck autochk /", StringComparison.OrdinalIgnoreCase))
            {
                rogueLine = trimmed;
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Классифицирует исключение Microsoft Defender: отделяет безопасные папки проектов разработчика от слепых зон майнеров.
    /// </summary>
    public static DefenderExclusionFinding ClassifyDefenderExclusion(
        DefenderExclusionKind kind,
        string rawValue,
        bool isPolicyEnforced,
        string registryPath,
        string windowsDirectory)
    {
        var val = (rawValue ?? "").Trim();
        var norm = val.TrimEnd('\\', '/').Replace('/', '\\');

        bool dangerous = false;
        var severity = RiskLevel.Low;
        string reason = "Локальное пользовательское исключение.";

        switch (kind)
        {
            case DefenderExclusionKind.Extension:
                if (DangerousDefenderExtensions.Any(e => val.Equals(e, StringComparison.OrdinalIgnoreCase)) ||
                    val is "*" or ".*")
                {
                    dangerous = true;
                    severity = RiskLevel.Critical;
                    reason = $"Исключение исполняемого расширения «{val}» полностью отключает проверку запускаемых программ и дропперов!";
                }
                break;

            case DefenderExclusionKind.Process:
            {
                var fileName = Path.GetFileName(norm);
                if (val is "*" or "*.*" ||
                    ThreatIndicatorCatalog.Shared.CriticalSystemBinaries.Contains(fileName) ||
                    ThreatIndicatorCatalog.Shared.HollowTargetBinaries.Contains(fileName) ||
                    fileName.Equals("powershell.exe", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Equals("pwsh.exe", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Equals("cmd.exe", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Equals("mshta.exe", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Equals("rundll32.exe", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Equals("regsvr32.exe", StringComparison.OrdinalIgnoreCase) ||
                    IsUserWritableOrStagingPath(norm))
                {
                    dangerous = true;
                    severity = RiskLevel.Critical;
                    reason = $"Исключение системного/скриптового процесса «{val}» позволяет майнеру внедряться в него (Process Hollowing) без реакции антивируса.";
                }
                break;
            }

            case DefenderExclusionKind.Path:
            {
                // Корень диска (C:, C:\, D:), вся папка Windows, System32, Users, AppData, ProgramData, Temp
                bool isDriveRoot = norm.Length is 2 or 3 && char.IsLetter(norm[0]) && norm[1] == ':';
                bool isWholeUsers = norm.EndsWith(@":\Users", StringComparison.OrdinalIgnoreCase);
                bool isWindowsRoot = norm.Equals(windowsDirectory.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase) ||
                                     norm.StartsWith(windowsDirectory.TrimEnd('\\') + @"\", StringComparison.OrdinalIgnoreCase);
                bool isStagingTree = norm.EndsWith(@"\AppData", StringComparison.OrdinalIgnoreCase) ||
                                     norm.EndsWith(@"\AppData\Roaming", StringComparison.OrdinalIgnoreCase) ||
                                     norm.EndsWith(@"\AppData\Local", StringComparison.OrdinalIgnoreCase) ||
                                     norm.EndsWith(@"\Temp", StringComparison.OrdinalIgnoreCase) ||
                                     norm.EndsWith(@":\ProgramData", StringComparison.OrdinalIgnoreCase) ||
                                     norm.EndsWith(@"\Users\Public", StringComparison.OrdinalIgnoreCase) ||
                                     IsUserWritableOrStagingPath(norm + @"\probe.exe");

                if (isDriveRoot || isWholeUsers || isWindowsRoot || isStagingTree)
                {
                    dangerous = true;
                    severity = isDriveRoot || isWholeUsers || isWindowsRoot ? RiskLevel.Critical : RiskLevel.High;
                    reason = $"Широкая слепая зона «{val}» типична для загрузчиков SilentCryptoMiner: троян прячет туда своё тело, конфиг пула и драйвер WinRing0.";
                }
                break;
            }
        }

        if (isPolicyEnforced && !dangerous)
        {
            severity = RiskLevel.Attention;
            reason = "Исключение задано через ветку групповых политик (нельзя удалить из обычного окна Защитника Windows).";
            dangerous = true;
        }

        return new DefenderExclusionFinding(
            Kind: kind,
            Value: val,
            IsPolicyEnforced: isPolicyEnforced,
            IsDangerousMinerExclusion: dangerous,
            Severity: severity,
            RegistryPath: registryPath,
            Reason: reason);
    }

    /// <summary>
    /// Извлекает путь к локальному бинарному файлу из строки команды реестра, службы или планировщика.
    /// </summary>
    public static string? ExtractExecutablePath(string? rawCommand)
    {
        if (string.IsNullOrWhiteSpace(rawCommand))
        {
            return null;
        }

        var expanded = Environment.ExpandEnvironmentVariables(rawCommand.Trim());
        if (expanded.StartsWith('"'))
        {
            var closeIdx = expanded.IndexOf('"', 1);
            if (closeIdx > 1)
            {
                return expanded[1..closeIdx].Trim();
            }
        }

        foreach (var ext in new[] { ".exe", ".dll", ".sys", ".bat", ".cmd", ".vbs", ".ps1", ".scr" })
        {
            var idx = expanded.IndexOf(ext, StringComparison.OrdinalIgnoreCase);
            if (idx > 0)
            {
                var candidate = expanded[..(idx + ext.Length)].Trim().Trim('"');
                if (candidate.StartsWith(@"\??\", StringComparison.Ordinal))
                {
                    candidate = candidate[4..];
                }
                else if (candidate.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
                {
                    var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                    if (!string.IsNullOrWhiteSpace(winDir))
                    {
                        candidate = Path.Combine(winDir, candidate[12..]);
                    }
                }

                return candidate;
            }
        }

        var firstToken = expanded.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        return string.IsNullOrWhiteSpace(firstToken) ? null : firstToken.Trim('"');
    }
}
