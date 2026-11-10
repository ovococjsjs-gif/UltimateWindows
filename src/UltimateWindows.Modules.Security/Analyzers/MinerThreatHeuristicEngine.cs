using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Security.Models;

namespace UltimateWindows.Modules.Security.Analyzers;

/// <summary>
/// Детерминированный поведенческий и сетевой анализатор скрытых майнеров (XMRig / GMiner / Trojan.Miner).
/// Не содержит сырых вирусных шеллкодов (не вызывает ложных срабатываний антивируса на саму программу!)
/// и исключает ложные обвинения подписанных браузеров и системных компонентов Microsoft.
/// </summary>
public sealed class MinerThreatHeuristicEngine
{
    private static readonly Dictionary<string, string[]> CanonicalSystemProcessLocations = new(StringComparer.OrdinalIgnoreCase)
    {
        ["svchost.exe"] = [@"\system32\svchost.exe", @"\syswow64\svchost.exe"],
        ["csrss.exe"] = [@"\system32\csrss.exe"],
        ["lsass.exe"] = [@"\system32\lsass.exe"],
        ["services.exe"] = [@"\system32\services.exe"],
        ["wininit.exe"] = [@"\system32\wininit.exe"],
        ["winlogon.exe"] = [@"\system32\winlogon.exe"],
        ["dwm.exe"] = [@"\system32\dwm.exe"],
        ["conhost.exe"] = [@"\system32\conhost.exe"],
        ["taskhostw.exe"] = [@"\system32\taskhostw.exe"],
        ["runtimebroker.exe"] = [@"\system32\runtimebroker.exe"],
        ["dllhost.exe"] = [@"\system32\dllhost.exe", @"\syswow64\dllhost.exe"],
        ["spoolsv.exe"] = [@"\system32\spoolsv.exe"],
        ["explorer.exe"] = [@"\explorer.exe", @"\syswow64\explorer.exe"]
    };

    private static readonly HashSet<int> KnownStratumMiningPorts =
    [
        3333, 4444, 5555, 6666, 7777, 8888, 9999, 14433, 14444, 20535, 45560
    ];

    private static readonly string[] HighConfidenceMinerCliMarkers =
    [
        "stratum+tcp://",
        "stratum+ssl://",
        "--donate-level",
        "--algo=rx/",
        "--algo rx/",
        "--randomx-",
        "--coin=monero",
        "nanopool.org",
        "2miners.com",
        "herominers.com",
        "hashvault.pro",
        "moneroocean.stream",
        "minexmr.com",
        "xmrig"
    ];

    private static readonly HashSet<string> TrustedBrowserProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome", "chrome.exe", "msedge", "msedge.exe", "firefox", "firefox.exe",
        "brave", "brave.exe", "opera", "opera.exe", "vivaldi", "vivaldi.exe", "browser", "browser.exe"
    };

    public IReadOnlyList<SecurityThreatFinding> AnalyzeTelemetry(
        IReadOnlyList<ProcessTelemetrySample> processes,
        IReadOnlyList<ProcessTcpConnectionInfo> tcpConnections,
        IReadOnlyList<PersistenceAnomalyRecord> persistenceAnomalies,
        string windowsDirectory)
    {
        var findings = new List<SecurityThreatFinding>();
        var normWinDir = NormalizeSlashes(windowsDirectory).TrimEnd('\\');
        var connectionsByPid = tcpConnections
            .GroupBy(c => c.ProcessId)
            .ToDictionary(g => g.Key, g => g.ToList());

        foreach (var proc in processes)
        {
            var fileName = ExtractFileName(proc.ExecutablePath, proc.ProcessName);
            var normExe = NormalizeSlashes(proc.ExecutablePath);
            var canQuarantine = !string.IsNullOrWhiteSpace(proc.ExecutablePath) &&
                                !IsInsideGenuineWindowsSystemFolder(normExe, normWinDir);

            // 1. Детект подмены (маскировки) системных процессов Windows (например, C:\ProgramData\Realtek\svchost.exe)
            if (!string.IsNullOrWhiteSpace(normExe) &&
                CanonicalSystemProcessLocations.TryGetValue(fileName, out var allowedSuffixes))
            {
                var matchesGenuine = allowedSuffixes.Any(suffix =>
                    normExe.Equals(normWinDir + suffix, StringComparison.OrdinalIgnoreCase));

                if (!matchesGenuine)
                {
                    findings.Add(new SecurityThreatFinding(
                        FindingId: $"masq-{proc.ProcessId}-{fileName}",
                        Vector: ThreatDetectionVector.ProcessMasquerading,
                        Severity: RiskLevel.High,
                        ConfidenceScorePercent: 98,
                        SuspectProcessId: proc.ProcessId,
                        SuspectFilePath: proc.ExecutablePath,
                        PersistenceKeyPath: null,
                        SimpleTitle: $"Маскировка под системный процесс «{fileName}»!",
                        SimpleExplanation:
                            $"Настоящий «{fileName}» всегда находится строго внутри системной папки Windows, а этот файл запущен из стороннего каталога «{proc.ExecutablePath}». Так прячутся скрытые майнеры.",
                        ExpertTechnicalEvidence:
                            $"PID {proc.ProcessId}: '{proc.ExecutablePath}' != '{normWinDir}\\System32\\{fileName}'. Signed={proc.IsAuthenticodeSigned}.",
                        CanQuarantineFileSafely: canQuarantine));
                }
            }

            // 2. Явные параметры командной строки майнеров (Stratum / RandomX / XMRig)
            if (!string.IsNullOrWhiteSpace(proc.CommandLine))
            {
                var matchedMarker = HighConfidenceMinerCliMarkers.FirstOrDefault(m =>
                    proc.CommandLine.Contains(m, StringComparison.OrdinalIgnoreCase));

                if (matchedMarker is not null)
                {
                    findings.Add(new SecurityThreatFinding(
                        FindingId: $"cli-{proc.ProcessId}",
                        Vector: ThreatDetectionVector.SuspiciousMinerCommandLine,
                        Severity: RiskLevel.High,
                        ConfidenceScorePercent: 99,
                        SuspectProcessId: proc.ProcessId,
                        SuspectFilePath: proc.ExecutablePath,
                        PersistenceKeyPath: null,
                        SimpleTitle: $"Обнаружен активный криптомайнер «{fileName}»",
                        SimpleExplanation:
                            $"Процесс запущен с характерными параметрами майнинг-пула («{matchedMarker}») и тайно расходует ресурсы процессора или видеокарты.",
                        ExpertTechnicalEvidence:
                            $"PID {proc.ProcessId} CLI: {proc.CommandLine}",
                        CanQuarantineFileSafely: canQuarantine));
                }
            }

            // 3. Поведенческий стелс-детект Drop-on-Inspect (майнер резко сбрасывает нагрузку или прячется при появлении окна Диспетчера задач!)
            var isSuspiciousLocationOrUnsigned = !proc.IsAuthenticodeSigned || IsUserWritableMinerHideout(normExe);
            if (isSuspiciousLocationOrUnsigned &&
                proc.BaselineCpuPercent >= 25.0 &&
                (proc.ExitedDuringInspect || proc.DuringInspectCpuPercent <= proc.BaselineCpuPercent * 0.25))
            {
                var dropDesc = proc.ExitedDuringInspect
                    ? $"мгновенно завершился при имитации открытия Диспетчера задач (нагрузка в тишине была {proc.BaselineCpuPercent:F1}%)"
                    : $"резко сбросил нагрузку CPU с {proc.BaselineCpuPercent:F1}% до {proc.DuringInspectCpuPercent:F1}% при проверке";

                findings.Add(new SecurityThreatFinding(
                    FindingId: $"drop-{proc.ProcessId}",
                    Vector: ThreatDetectionVector.DropOnInspectEvasion,
                    Severity: RiskLevel.High,
                    ConfidenceScorePercent: 94,
                    SuspectProcessId: proc.ProcessId,
                    SuspectFilePath: proc.ExecutablePath,
                    PersistenceKeyPath: null,
                    SimpleTitle: $"Пойман прячущийся процесс «{fileName}» (Drop-on-Inspect)",
                    SimpleExplanation:
                        $"Программа {dropDesc}. Именно так ведут себя стелс-майнеры, чтобы вы не заметили их в Диспетчере задач.",
                    ExpertTechnicalEvidence:
                        $"PID {proc.ProcessId} ('{proc.ExecutablePath}'): BaselineCPU={proc.BaselineCpuPercent:F1}%, InspectCPU={proc.DuringInspectCpuPercent:F1}%, Exited={proc.ExitedDuringInspect}, Signed={proc.IsAuthenticodeSigned}.",
                    CanQuarantineFileSafely: canQuarantine));
            }

            // 4. Активное соединение с известными Stratum-портами майнинг-пулов (исключая подписанные браузеры!)
            if (connectionsByPid.TryGetValue(proc.ProcessId, out var procConns) &&
                !(proc.IsAuthenticodeSigned && TrustedBrowserProcessNames.Contains(fileName)))
            {
                var stratumConn = procConns.FirstOrDefault(c =>
                    KnownStratumMiningPorts.Contains(c.RemotePort) &&
                    !c.RemoteAddress.StartsWith("127.", StringComparison.Ordinal) &&
                    c.RemoteAddress != "::1");

                if (stratumConn is not null && isSuspiciousLocationOrUnsigned)
                {
                    findings.Add(new SecurityThreatFinding(
                        FindingId: $"stratum-{proc.ProcessId}-{stratumConn.RemotePort}",
                        Vector: ThreatDetectionVector.StratumMiningPoolConnection,
                        Severity: RiskLevel.High,
                        ConfidenceScorePercent: 92,
                        SuspectProcessId: proc.ProcessId,
                        SuspectFilePath: proc.ExecutablePath,
                        PersistenceKeyPath: null,
                        SimpleTitle: $"Подозрительное соединение с майнинг-портом ({fileName} -> :{stratumConn.RemotePort})",
                        SimpleExplanation:
                            $"Неподписанный процесс держит активное подключение к удаленному узлу {stratumConn.RemoteAddress}:{stratumConn.RemotePort} (типичный порт протокола майнинга Stratum).",
                        ExpertTechnicalEvidence:
                            $"PID {proc.ProcessId} TCP {stratumConn.LocalAddress}:{stratumConn.LocalPort} -> {stratumConn.RemoteAddress}:{stratumConn.RemotePort}.",
                        CanQuarantineFileSafely: canQuarantine));
                }
            }
        }

        // 5. Глубокий анализ аномалий автозакрепления (IFEO, Winlogon, задачи без SD, WMI)
        foreach (var pa in persistenceAnomalies)
        {
            var canQuarantineRef = !string.IsNullOrWhiteSpace(pa.ReferencedExecutablePath) &&
                                   File.Exists(pa.ReferencedExecutablePath) &&
                                   !IsInsideGenuineWindowsSystemFolder(NormalizeSlashes(pa.ReferencedExecutablePath), normWinDir);

            var (title, explain, conf) = pa.Vector switch
            {
                ThreatDetectionVector.IfeoDebuggerHijack => (
                    $"Перехват запуска системной программы ({pa.EntryName})",
                    $"В ветке отладчика IFEO установлена подмена для «{pa.EntryName}» -> «{pa.PayloadCommandOrPath}». Майнеры используют это, чтобы блокировать антивирусные утилиты и Диспетчер задач.",
                    96),

                ThreatDetectionVector.WinlogonShellHijack => (
                    $"Подмена системной оболочки входа Winlogon ({pa.EntryName})",
                    $"К системному параметру входа «{pa.EntryName}» дописан посторонний запуск: «{pa.PayloadCommandOrPath}».",
                    97),

                ThreatDetectionVector.HiddenScheduledTask when pa.IsMissingSecurityDescriptorSd => (
                    $"Скрытая задача-невидимка в Планировщике ({pa.EntryName})",
                    "У задачи намеренно удален дескриптор безопасности (SD) в реестре, чтобы скрыть её от стандартного Планировщика заданий Windows.",
                    95),

                ThreatDetectionVector.HiddenScheduledTask => (
                    $"Подозрительная задача Планировщика из временной папки ({pa.EntryName})",
                    $"Задача скрытно запускает файл из пользовательской/временной директории: «{pa.PayloadCommandOrPath}».",
                    88),

                _ => (
                    $"Подозрительная подписка WMI ({pa.EntryName})",
                    $"Найдена постоянная фоновая команда WMI: «{pa.PayloadCommandOrPath}».",
                    90)
            };

            findings.Add(new SecurityThreatFinding(
                FindingId: $"persist-{pa.Vector}-{pa.EntryName}",
                Vector: pa.Vector,
                Severity: RiskLevel.High,
                ConfidenceScorePercent: conf,
                SuspectProcessId: null,
                SuspectFilePath: pa.ReferencedExecutablePath,
                PersistenceKeyPath: pa.RegistryOrTaskPath,
                SimpleTitle: title,
                SimpleExplanation: explain,
                ExpertTechnicalEvidence: $"{pa.RegistryOrTaskPath} :: {pa.EntryName} = {pa.PayloadCommandOrPath} (MissingSD={pa.IsMissingSecurityDescriptorSd})",
                CanQuarantineFileSafely: canQuarantineRef));
        }

        return findings;
    }

    public static bool IsInsideGenuineWindowsSystemFolder(string normalizedFilePath, string normalizedWinDir)
    {
        if (string.IsNullOrWhiteSpace(normalizedFilePath) || string.IsNullOrWhiteSpace(normalizedWinDir))
        {
            return false;
        }

        return normalizedFilePath.StartsWith(normalizedWinDir + @"\", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsUserWritableMinerHideout(string normalizedPath)
    {
        if (string.IsNullOrWhiteSpace(normalizedPath))
        {
            return false;
        }

        return normalizedPath.Contains(@"\appdata\", StringComparison.OrdinalIgnoreCase) ||
               normalizedPath.Contains(@"\programdata\", StringComparison.OrdinalIgnoreCase) ||
               normalizedPath.Contains(@"\temp\", StringComparison.OrdinalIgnoreCase) ||
               normalizedPath.Contains(@"\users\public\", StringComparison.OrdinalIgnoreCase) ||
               normalizedPath.Contains(@"\downloads\", StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeSlashes(string? raw) =>
        string.IsNullOrWhiteSpace(raw) ? "" : raw.Trim().Replace('/', '\\');

    private static string ExtractFileName(string? exePath, string fallbackProcessName)
    {
        if (!string.IsNullOrWhiteSpace(exePath))
        {
            var idx = exePath.LastIndexOfAny(['\\', '/']);
            var name = idx >= 0 ? exePath[(idx + 1)..] : exePath;
            if (!string.IsNullOrWhiteSpace(name))
            {
                return name;
            }
        }

        return fallbackProcessName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? fallbackProcessName
            : $"{fallbackProcessName}.exe";
    }
}
