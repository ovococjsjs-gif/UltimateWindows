using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Security.Catalog;
using UltimateWindows.Modules.Security.Models;

namespace UltimateWindows.Modules.Security.Analyzers;

/// <summary>
/// Детерминированный многовекторный аналитический движок «Анти-майнер и Защита 2.0»:
/// 1) Маскировка под системные процессы Windows;
/// 2) Индикаторы майнеров и закодированных загрузчиков в командной строке;
/// 3) Двухфазный поведенческий детект Drop-on-Inspect по CPU и GPU (3D/Compute/CUDA);
/// 4) Эвристика Process Hollowing / внедрения приватных исполняемых секций в системные процессы;
/// 5) Сетевые соединения с пулами Stratum (IPv4/IPv6) и следы пулов в DNS-кэше;
/// 6) 18 зон автозакрепления, опасные исключения Defender, правила брандмауэра, скрытые учетные записи и файловые артефакты (WinRing0 / раздутые дропперы >250 МБ).
/// </summary>
public sealed class MinerThreatHeuristicEngine
{
    private static readonly HashSet<string> BenignWebBrowsers = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe", "yandex.exe", "waterfox.exe"
    };

    private static readonly HashSet<string> KnownLegitJitHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe",
        "code.exe", "devenv.exe", "rider64.exe", "dotnet.exe", "pwsh.exe", "powershell.exe",
        "node.exe", "javaw.exe", "java.exe", "steamwebhelper.exe", "discord.exe", "UltimateWindows.App.exe"
    };

    /// <summary>
    /// Базовая перегрузка анализа телеметрии процессов, TCP-сессий и автозакрепления.
    /// </summary>
    public IReadOnlyList<SecurityThreatFinding> AnalyzeTelemetry(
        IReadOnlyList<ProcessTelemetrySample> processes,
        IReadOnlyList<ProcessTcpConnectionInfo> tcpConnections,
        IReadOnlyList<PersistenceAnomalyRecord> persistenceAnomalies,
        string windowsDirectory = @"C:\Windows")
        => AnalyzeFullEcosystem(
            processes,
            tcpConnections,
            persistenceAnomalies,
            defenderExclusions: [],
            firewallAnomalies: [],
            suspiciousUsers: [],
            directoryArtifacts: [],
            dnsCachedPoolDomains: [],
            windowsDirectory: windowsDirectory);

    /// <summary>
    /// Полная корреляция всех подсистем Этапа 4 «Анти-майнер и Защита 2.0».
    /// </summary>
    public IReadOnlyList<SecurityThreatFinding> AnalyzeFullEcosystem(
        IReadOnlyList<ProcessTelemetrySample> processes,
        IReadOnlyList<ProcessTcpConnectionInfo> tcpConnections,
        IReadOnlyList<PersistenceAnomalyRecord> persistenceAnomalies,
        IReadOnlyList<DefenderExclusionFinding> defenderExclusions,
        IReadOnlyList<FirewallRuleAnomaly> firewallAnomalies,
        IReadOnlyList<SuspiciousUserAccountFinding> suspiciousUsers,
        IReadOnlyList<DirectoryThreatArtifact> directoryArtifacts,
        IReadOnlyList<string> dnsCachedPoolDomains,
        string windowsDirectory = @"C:\Windows")
    {
        ArgumentNullException.ThrowIfNull(processes);
        ArgumentNullException.ThrowIfNull(tcpConnections);
        ArgumentNullException.ThrowIfNull(persistenceAnomalies);

        var catalog = ThreatIndicatorCatalog.Shared;
        var findings = new List<SecurityThreatFinding>();
        var winPrefix = NormalizePrefix(windowsDirectory);
        var sys32Prefix = NormalizePrefix(Path.Combine(windowsDirectory, "System32"));
        var sysWowPrefix = NormalizePrefix(Path.Combine(windowsDirectory, "SysWOW64"));
        var winSxsPrefix = NormalizePrefix(Path.Combine(windowsDirectory, "WinSxS"));

        var pidMap = processes
            .GroupBy(p => p.ProcessId)
            .ToDictionary(g => g.Key, g => g.First());

        var connectionsByPid = tcpConnections
            .GroupBy(c => c.ProcessId)
            .ToDictionary(g => g.Key, g => g.ToList());

        foreach (var proc in processes)
        {
            var exeName = NormalizeExeName(proc.ProcessName, proc.ExecutablePath);
            var normPath = (proc.ExecutablePath ?? "").Trim();
            bool hasPath = !string.IsNullOrWhiteSpace(normPath);
            bool isUnderGenuineSystemFolder = hasPath &&
                (normPath.StartsWith(sys32Prefix, StringComparison.OrdinalIgnoreCase) ||
                 normPath.StartsWith(sysWowPrefix, StringComparison.OrdinalIgnoreCase) ||
                 normPath.StartsWith(winSxsPrefix, StringComparison.OrdinalIgnoreCase) ||
                 (exeName.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase) &&
                  normPath.StartsWith(winPrefix, StringComparison.OrdinalIgnoreCase)));

            bool isSafeToQuarantineFile = hasPath && !normPath.StartsWith(winPrefix, StringComparison.OrdinalIgnoreCase);

            // 1. Маскировка под критический процесс Windows вне папки System32 / SysWOW64
            if (hasPath && catalog.CriticalSystemBinaries.Contains(exeName) && !isUnderGenuineSystemFolder)
            {
                int confidence = proc.IsAuthenticodeSigned ? 82 : 98;
                findings.Add(new SecurityThreatFinding(
                    FindingId: $"masq-{proc.ProcessId}",
                    Vector: ThreatDetectionVector.ProcessMasquerading,
                    Severity: RiskLevel.Critical,
                    ConfidenceScorePercent: confidence,
                    SuspectProcessId: proc.ProcessId,
                    SuspectFilePath: normPath,
                    PersistenceRecord: null,
                    SimpleTitle: $"Поддельный системный процесс «{exeName}»",
                    SimpleExplanation: $"Программа выдаёт себя за системную службу Windows «{exeName}», но запущена из посторонней папки «{normPath}».",
                    ExpertTechnicalEvidence: $"PID={proc.ProcessId} | Path='{normPath}' (вне '{sys32Prefix}') | Signed={proc.IsAuthenticodeSigned} | CPU={proc.BaselineCpuPercent:F1}% | GPU={proc.BaselineGpuPercent:F1}%",
                    CanQuarantineFileSafely: isSafeToQuarantineFile,
                    CategoryLabel: "Маскировка процесса"));
            }

            // 2. Индикаторы майнеров и скрытых загрузчиков в аргументах запуска (CLI)
            var matchedMarker = catalog.MinerCliMarkers.FirstOrDefault(m =>
                !string.IsNullOrWhiteSpace(proc.CommandLine) &&
                proc.CommandLine.Contains(m, StringComparison.OrdinalIgnoreCase));

            if (matchedMarker is null &&
                !string.IsNullOrWhiteSpace(proc.CommandLine) &&
                catalog.MatchesMiningPoolDomain(proc.CommandLine, out var cliPoolDomain))
            {
                matchedMarker = cliPoolDomain;
            }

            if (matchedMarker is not null)
            {
                findings.Add(new SecurityThreatFinding(
                    FindingId: $"cli-{proc.ProcessId}",
                    Vector: ThreatDetectionVector.SuspiciousMinerCommandLine,
                    Severity: RiskLevel.Critical,
                    ConfidenceScorePercent: 96,
                    SuspectProcessId: proc.ProcessId,
                    SuspectFilePath: hasPath ? normPath : null,
                    PersistenceRecord: null,
                    SimpleTitle: $"Параметры криптомайнера в процессе «{exeName}»",
                    SimpleExplanation: $"В параметрах запуска процесса обнаружен прямой признак майнинга («{matchedMarker}»).",
                    ExpertTechnicalEvidence: $"PID={proc.ProcessId} | CLI='{proc.CommandLine}' | Matched='{matchedMarker}'",
                    CanQuarantineFileSafely: isSafeToQuarantineFile,
                    CategoryLabel: "Аргументы запуска"));
            }

            // 3A. Поведенческий детект CPU Drop-on-Inspect
            if (proc.BaselineCpuPercent >= 25.0)
            {
                double dropRatio = proc.ExitedDuringInspect
                    ? 1.0
                    : (proc.BaselineCpuPercent - proc.DuringInspectCpuPercent) / Math.Max(1.0, proc.BaselineCpuPercent);

                if (dropRatio >= 0.60 && (!proc.IsAuthenticodeSigned || !isUnderGenuineSystemFolder))
                {
                    int score = proc.ExitedDuringInspect ? 94 : 89;
                    if (!proc.IsAuthenticodeSigned) score = Math.Min(98, score + 5);

                    findings.Add(new SecurityThreatFinding(
                        FindingId: $"drop-cpu-{proc.ProcessId}",
                        Vector: ThreatDetectionVector.DropOnInspectEvasion,
                        Severity: score >= 90 ? RiskLevel.Critical : RiskLevel.High,
                        ConfidenceScorePercent: score,
                        SuspectProcessId: proc.ProcessId,
                        SuspectFilePath: hasPath ? normPath : null,
                        PersistenceRecord: null,
                        SimpleTitle: $"Скрывающийся CPU-майнер «{exeName}» (Drop-on-Inspect)",
                        SimpleExplanation: proc.ExitedDuringInspect
                            ? $"В покое программа нагружала процессор на {proc.BaselineCpuPercent:F0}%, но мгновенно завершилась при открытии системного монитора."
                            : $"В покое программа нагружала процессор на {proc.BaselineCpuPercent:F0}%, но сбросила нагрузку до {proc.DuringInspectCpuPercent:F0}% при открытии мониторинга.",
                        ExpertTechnicalEvidence: $"PID={proc.ProcessId} | QuietCPU={proc.BaselineCpuPercent:F1}% -> InspectCPU={proc.DuringInspectCpuPercent:F1}% | Exited={proc.ExitedDuringInspect} | Signed={proc.IsAuthenticodeSigned}",
                        CanQuarantineFileSafely: isSafeToQuarantineFile,
                        CategoryLabel: "Стелс CPU (Drop-on-Inspect)"));
                }
            }

            // 3B. Поведенческий детект GPU Drop-on-Inspect (видеокарточные майнеры KawPow / Ethash / Autolykos)
            if (proc.BaselineGpuPercent >= 28.0)
            {
                double gpuDropRatio = proc.ExitedDuringInspect
                    ? 1.0
                    : (proc.BaselineGpuPercent - proc.DuringInspectGpuPercent) / Math.Max(1.0, proc.BaselineGpuPercent);

                if (gpuDropRatio >= 0.60 && (!proc.IsAuthenticodeSigned || PersistenceZoneCatalog.IsUserWritableOrStagingPath(normPath)))
                {
                    int gpuScore = proc.ExitedDuringInspect ? 96 : 92;
                    findings.Add(new SecurityThreatFinding(
                        FindingId: $"drop-gpu-{proc.ProcessId}",
                        Vector: ThreatDetectionVector.GpuDropOnInspectEvasion,
                        Severity: RiskLevel.Critical,
                        ConfidenceScorePercent: gpuScore,
                        SuspectProcessId: proc.ProcessId,
                        SuspectFilePath: hasPath ? normPath : null,
                        PersistenceRecord: null,
                        SimpleTitle: $"Скрывающийся GPU-майнер на видеокарте «{exeName}»",
                        SimpleExplanation: $"В тихом режиме процесс загружал видеокарту (3D/Compute) на {proc.BaselineGpuPercent:F0}%, но при появлении системного монитора сбросил нагрузку GPU до {proc.DuringInspectGpuPercent:F0}%.",
                        ExpertTechnicalEvidence: $"PID={proc.ProcessId} | QuietGPU={proc.BaselineGpuPercent:F1}% -> InspectGPU={proc.DuringInspectGpuPercent:F1}% | Signed={proc.IsAuthenticodeSigned} | Path='{normPath}'",
                        CanQuarantineFileSafely: isSafeToQuarantineFile,
                        CategoryLabel: "Стелс GPU (Drop-on-Inspect)"));
                }
            }

            // 4. Эвристика Process Hollowing / внедрения кода в системный процесс-донор (SilentCryptoMiner -> dwm/conhost/RegAsm/MSBuild)
            if (catalog.HollowTargetBinaries.Contains(exeName) &&
                !KnownLegitJitHosts.Contains(exeName))
            {
                bool hasSuspiciousParent = false;
                string parentEvidence = "";
                if (proc.ParentProcessId > 4 && pidMap.TryGetValue(proc.ParentProcessId, out var parentProc))
                {
                    if (!parentProc.IsAuthenticodeSigned && PersistenceZoneCatalog.IsUserWritableOrStagingPath(parentProc.ExecutablePath))
                    {
                        hasSuspiciousParent = true;
                        parentEvidence = $"UnsignedParent='{parentProc.ExecutablePath}' (PID={parentProc.ProcessId})";
                    }
                }

                bool hasActiveMiningLoad = proc.BaselineCpuPercent >= 25.0 || proc.BaselineGpuPercent >= 25.0;
                bool hasUnbackedExecMemory = proc.PrivateExecutableRegionCount >= 2;
                bool isDotNetCompileTool = exeName.Equals("RegAsm.exe", StringComparison.OrdinalIgnoreCase) ||
                                           exeName.Equals("RegSvcs.exe", StringComparison.OrdinalIgnoreCase) ||
                                           exeName.Equals("InstallUtil.exe", StringComparison.OrdinalIgnoreCase) ||
                                           exeName.Equals("AppLaunch.exe", StringComparison.OrdinalIgnoreCase) ||
                                           exeName.Equals("cvtres.exe", StringComparison.OrdinalIgnoreCase);

                if ((hasSuspiciousParent && (hasActiveMiningLoad || isDotNetCompileTool || hasUnbackedExecMemory)) ||
                    (hasUnbackedExecMemory && hasActiveMiningLoad && isUnderGenuineSystemFolder))
                {
                    string? culpritLoaderPath = hasSuspiciousParent && pidMap.TryGetValue(proc.ParentProcessId, out var p)
                        ? p.ExecutablePath
                        : null;
                    bool canQuarantineLoader = !string.IsNullOrWhiteSpace(culpritLoaderPath) &&
                                               !culpritLoaderPath.StartsWith(winPrefix, StringComparison.OrdinalIgnoreCase);

                    findings.Add(new SecurityThreatFinding(
                        FindingId: $"hollow-{proc.ProcessId}",
                        Vector: ThreatDetectionVector.ProcessHollowingOrImplant,
                        Severity: RiskLevel.Critical,
                        ConfidenceScorePercent: hasSuspiciousParent && hasUnbackedExecMemory ? 95 : 88,
                        SuspectProcessId: proc.ProcessId,
                        SuspectFilePath: canQuarantineLoader ? culpritLoaderPath : null,
                        PersistenceRecord: null,
                        SimpleTitle: $"Подозрение на внедрение майнера в процесс «{exeName}» (Process Hollowing)",
                        SimpleExplanation: canQuarantineLoader
                            ? $"Системный файл «{exeName}» (PID {proc.ProcessId}) запущен неподписанным загрузчиком «{culpritLoaderPath}» и используется как ширма для скрытой работы."
                            : $"В памяти штатного процесса «{exeName}» (PID {proc.ProcessId}) обнаружены приватные исполняемые секции ({proc.PrivateExecutableRegionCount} шт.) на фоне высокой нагрузки CPU/GPU.",
                        ExpertTechnicalEvidence: $"HollowTarget='{exeName}' PID={proc.ProcessId} | PrivateRWX/RX={proc.PrivateExecutableRegionCount} | CPU={proc.BaselineCpuPercent:F1}% | GPU={proc.BaselineGpuPercent:F1}% | {parentEvidence}",
                        CanQuarantineFileSafely: canQuarantineLoader,
                        CategoryLabel: "Инжекция в память",
                        RecommendedActionLabel: canQuarantineLoader ? "Обезвредить загрузчик" : "Завершить процесс"));
                }
            }

            // 5. Активные соединения с портами Stratum (IPv4 и IPv6)
            if (!BenignWebBrowsers.Contains(exeName) &&
                connectionsByPid.TryGetValue(proc.ProcessId, out var procConns))
            {
                var poolHit = procConns.FirstOrDefault(c => catalog.StratumPorts.Contains(c.RemotePort));
                if (poolHit is not null)
                {
                    int netScore = proc.IsAuthenticodeSigned && !catalog.HollowTargetBinaries.Contains(exeName) ? 74 : 93;
                    if (proc.BaselineCpuPercent >= 15.0 || proc.BaselineGpuPercent >= 15.0) netScore = Math.Min(99, netScore + 6);

                    findings.Add(new SecurityThreatFinding(
                        FindingId: $"stratum-{proc.ProcessId}-{poolHit.RemotePort}",
                        Vector: ThreatDetectionVector.StratumMiningPoolConnection,
                        Severity: netScore >= 85 ? RiskLevel.Critical : RiskLevel.Attention,
                        ConfidenceScorePercent: netScore,
                        SuspectProcessId: proc.ProcessId,
                        SuspectFilePath: hasPath ? normPath : null,
                        PersistenceRecord: null,
                        SimpleTitle: $"Сетевое подключение «{exeName}» к пулу майнинга",
                        SimpleExplanation: $"Процесс держит активное соединение с внешним узлом {poolHit.RemoteAddress}:{poolHit.RemotePort} по типичному порту протокола майнинга Stratum.",
                        ExpertTechnicalEvidence: $"PID={proc.ProcessId} | Local={poolHit.LocalAddress}:{poolHit.LocalPort} -> Remote={poolHit.RemoteAddress}:{poolHit.RemotePort} (IPv6={poolHit.IsIpv6})",
                        CanQuarantineFileSafely: isSafeToQuarantineFile,
                        CategoryLabel: "Сетевой пул Stratum"));
                }
            }
        }

        // 6. Следы пулов майнинга в системном DNS-кэше (даже если сокет временно разорван)
        foreach (var poolDomain in dnsCachedPoolDomains.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            findings.Add(new SecurityThreatFinding(
                FindingId: $"dnscache-{poolDomain}",
                Vector: ThreatDetectionVector.DnsCacheMiningPool,
                Severity: RiskLevel.High,
                ConfidenceScorePercent: 86,
                SuspectProcessId: null,
                SuspectFilePath: null,
                PersistenceRecord: null,
                SimpleTitle: $"В DNS-кэше Windows найден адрес майнинг-пула «{poolDomain}»",
                SimpleExplanation: $"Компьютер недавно обращался к серверу добычи криптовалюты «{poolDomain}». Даже если майнер сейчас затаился, его сетевой след остался в кэше DNS.",
                ExpertTechnicalEvidence: $"DNS Resolver Cache hit: '{poolDomain}'",
                CanQuarantineFileSafely: false,
                CategoryLabel: "След в DNS-кэше",
                RecommendedActionLabel: "Проверить"));
        }

        // 7. Точки автозакрепления по всем 18 зонам (только аномальные записи превращаются в карточки угроз)
        foreach (var anomaly in persistenceAnomalies.Where(a => a.IsAnomaly))
        {
            bool safeRefFile = !string.IsNullOrWhiteSpace(anomaly.ReferencedExecutablePath) &&
                               !anomaly.ReferencedExecutablePath.StartsWith(winPrefix, StringComparison.OrdinalIgnoreCase);

            var (title, explanation, confidence) = DescribePersistenceAnomaly(anomaly);

            findings.Add(new SecurityThreatFinding(
                FindingId: $"persist-{anomaly.Vector}-{Math.Abs(anomaly.RegistryOrTaskPath.GetHashCode(StringComparison.OrdinalIgnoreCase))}-{Math.Abs(anomaly.EntryName.GetHashCode(StringComparison.OrdinalIgnoreCase))}",
                Vector: anomaly.Vector,
                Severity: confidence >= 90 ? RiskLevel.Critical : RiskLevel.High,
                ConfidenceScorePercent: confidence,
                SuspectProcessId: null,
                SuspectFilePath: safeRefFile ? anomaly.ReferencedExecutablePath : null,
                PersistenceRecord: anomaly,
                SimpleTitle: title,
                SimpleExplanation: explanation,
                ExpertTechnicalEvidence: $"Zone={anomaly.Category} | Path='{anomaly.RegistryOrTaskPath}' | Entry='{anomaly.EntryName}' | Payload='{anomaly.PayloadCommandOrPath}' | MissingSD={anomaly.IsMissingSecurityDescriptorSd}",
                CanQuarantineFileSafely: safeRefFile,
                CategoryLabel: anomaly.ZoneTitle,
                RecommendedActionLabel: safeRefFile ? "Убрать и в карантин" : "Убрать закрепление"));
        }

        // 8. Опасные исключения Microsoft Defender
        foreach (var excl in defenderExclusions.Where(e => e.IsDangerousMinerExclusion))
        {
            findings.Add(new SecurityThreatFinding(
                FindingId: $"def-excl-{excl.Kind}-{excl.Value.GetHashCode(StringComparison.OrdinalIgnoreCase):X8}",
                Vector: ThreatDetectionVector.DangerousDefenderExclusion,
                Severity: excl.Severity,
                ConfidenceScorePercent: excl.Severity == RiskLevel.Critical ? 92 : 84,
                SuspectProcessId: null,
                SuspectFilePath: null,
                PersistenceRecord: null,
                SimpleTitle: $"Опасное исключение Защитника Windows: «{excl.Value}»",
                SimpleExplanation: excl.Reason,
                ExpertTechnicalEvidence: $"Defender Exclusion ({excl.Kind}, Policy={excl.IsPolicyEnforced}): '{excl.Value}' @ '{excl.RegistryPath}'",
                CanQuarantineFileSafely: false,
                CategoryLabel: "Слепая зона Defender",
                RecommendedActionLabel: "Удалить исключение",
                LinkedExclusion: excl));
        }

        // 9. Саботажные правила Брандмауэра Windows
        foreach (var fw in firewallAnomalies)
        {
            findings.Add(new SecurityThreatFinding(
                FindingId: $"fw-{fw.RuleId}",
                Vector: ThreatDetectionVector.MaliciousFirewallRule,
                Severity: RiskLevel.High,
                ConfidenceScorePercent: 90,
                SuspectProcessId: null,
                SuspectFilePath: null,
                PersistenceRecord: null,
                SimpleTitle: $"Подозрительное правило брандмауэра «{fw.DisplayName}»",
                SimpleExplanation: fw.SimpleExplanation,
                ExpertTechnicalEvidence: $"FirewallRule='{fw.RuleId}' | Dir={fw.Direction} | Action={fw.Action} | App='{fw.ApplicationPath}' | Ports='{fw.RemotePorts}'",
                CanQuarantineFileSafely: false,
                CategoryLabel: "Брандмауэр Windows",
                RecommendedActionLabel: "Удалить правило",
                LinkedFirewallRule: fw));
        }

        // 10. Скрытые или подозрительные учетные записи локальных пользователей
        foreach (var user in suspiciousUsers)
        {
            findings.Add(new SecurityThreatFinding(
                FindingId: $"user-{user.UserName}",
                Vector: ThreatDetectionVector.HiddenOrRogueUserAccount,
                Severity: user.IsAdministrator ? RiskLevel.Critical : RiskLevel.High,
                ConfidenceScorePercent: user.IsHiddenInWinlogonSpecialAccounts || user.EndsWithDollarSign ? 93 : 80,
                SuspectProcessId: null,
                SuspectFilePath: null,
                PersistenceRecord: null,
                SimpleTitle: $"Скрытая учётная запись пользователя «{user.UserName}»",
                SimpleExplanation: user.Reason,
                ExpertTechnicalEvidence: $"LocalUser='{user.UserName}' | Admin={user.IsAdministrator} | Enabled={user.IsEnabled} | DollarSuffix={user.EndsWithDollarSign} | HiddenSpecialAccounts={user.IsHiddenInWinlogonSpecialAccounts}",
                CanQuarantineFileSafely: false,
                CategoryLabel: "Учётные записи",
                RecommendedActionLabel: "Проверить"));
        }

        // 11. Файловые артефакты майнеров в staging-папках (config.json пула, WinRing0x64.sys, раздутые дропперы >250 МБ)
        foreach (var art in directoryArtifacts)
        {
            bool safeFile = !art.FilePath.StartsWith(winPrefix, StringComparison.OrdinalIgnoreCase);
            findings.Add(new SecurityThreatFinding(
                FindingId: $"art-{art.FilePath.GetHashCode(StringComparison.OrdinalIgnoreCase):X8}",
                Vector: ThreatDetectionVector.MinerStagingArtifactOrBloatedBinary,
                Severity: art.IsBloatedPaddingSuspect ? RiskLevel.High : RiskLevel.Critical,
                ConfidenceScorePercent: art.IsBloatedPaddingSuspect ? 85 : 95,
                SuspectProcessId: null,
                SuspectFilePath: safeFile ? art.FilePath : null,
                PersistenceRecord: null,
                SimpleTitle: $"Артефакт майнера в пользовательской папке: «{Path.GetFileName(art.FilePath)}»",
                SimpleExplanation: art.SimpleExplanation,
                ExpertTechnicalEvidence: $"Kind='{art.ArtifactKind}' | Path='{art.FilePath}' | Size={art.FileSizeMb:F1} MB | Indicator='{art.MatchedIndicator}' | Bloated={art.IsBloatedPaddingSuspect}",
                CanQuarantineFileSafely: safeFile,
                CategoryLabel: "Файловый артефакт",
                RecommendedActionLabel: "В карантин"));
        }

        return findings
            .OrderByDescending(f => f.ConfidenceScorePercent)
            .ThenByDescending(f => f.Severity)
            .ToList();
    }

    private static (string Title, string Explanation, int Confidence) DescribePersistenceAnomaly(PersistenceAnomalyRecord anomaly)
    {
        return anomaly.Vector switch
        {
            ThreatDetectionVector.HiddenScheduledTask => (
                $"Скрытая задача планировщика «{anomaly.EntryName}» (удалён SD)",
                "У задачи намеренно стёрт дескриптор безопасности SD в реестре TaskCache, чтобы скрыть её из стандартного Планировщика заданий Windows.",
                95),
            ThreatDetectionVector.IfeoDebuggerHijack => (
                $"Перехват запуска программы «{anomaly.EntryName}» (IFEO Debugger)",
                $"Вместо штатной программы система перенаправляет запуск на «{anomaly.PayloadCommandOrPath}».",
                92),
            ThreatDetectionVector.IfeoSilentProcessExit => (
                $"Теневой перезапуск при закрытии «{anomaly.EntryName}» (SilentProcessExit)",
                $"При закрытии процесса «{anomaly.EntryName}» Windows скрытно запускает сторожевой файл «{anomaly.PayloadCommandOrPath}».",
                94),
            ThreatDetectionVector.WinlogonShellHijack => (
                $"Подмена входа в систему Winlogon ({anomaly.EntryName})",
                $"При входе пользователя в Windows вместо штатной оболочки прописан запуск «{anomaly.PayloadCommandOrPath}».",
                95),
            ThreatDetectionVector.BootExecuteOrSessionManager => (
                $"Низкоуровневая вставка в раннюю загрузку ОС ({anomaly.EntryName})",
                $"В ключе Session Manager обнаружена нестандартная команда раннего старта: «{anomaly.PayloadCommandOrPath}».",
                94),
            ThreatDetectionVector.AppInitDllInjection => (
                "Глобальная подгрузка библиотеки через AppInit_DLLs",
                $"Включена принудительная загрузка сторонней DLL «{anomaly.PayloadCommandOrPath}» в пользовательские процессы.",
                92),
            ThreatDetectionVector.ActiveSetupStubHijack => (
                $"Подозрительный сценарий Active Setup «{anomaly.EntryName}»",
                $"При входе в профиль выполняется скрытая команда StubPath: «{anomaly.PayloadCommandOrPath}».",
                89),
            ThreatDetectionVector.ComClassHijack => (
                $"Перехват системного COM-класса в профиле пользователя ({anomaly.EntryName})",
                $"В ветке HKCU\\Software\\Classes\\CLSID зарегистрирована сторонняя библиотека «{anomaly.PayloadCommandOrPath}», подгружаемая проводником без прав администратора.",
                91),
            ThreatDetectionVector.DotNetProfilerHijack => (
                $"Перехват всех .NET-приложений через {anomaly.EntryName}",
                $"Переменная среды принудительно подключает сторонний профилировщик CLR «{anomaly.PayloadCommandOrPath}» ко всем .NET-программам (техника Blue Mockingbird).",
                96),
            ThreatDetectionVector.LsaOrSecurityProviderHijack => (
                $"Сторонний модуль в подсистеме безопасности LSA ({anomaly.EntryName})",
                $"В критической ветке LSA зарегистрирован нестандартный пакет «{anomaly.PayloadCommandOrPath}».",
                93),
            ThreatDetectionVector.PrintMonitorOrNetshDll => (
                $"Сторонняя библиотека в системном хосте ({anomaly.EntryName})",
                $"Зарегистрирована неподписанная или пользовательская DLL «{anomaly.PayloadCommandOrPath}» в мониторе печати или NetSh.",
                90),
            ThreatDetectionVector.SuspiciousServiceOrDriver => (
                $"Подозрительная служба или драйвер майнера «{anomaly.EntryName}»",
                $"Служба запускает неподписанный или временный файл «{anomaly.PayloadCommandOrPath}» {anomaly.PublisherOrNote}".Trim(),
                93),
            ThreatDetectionVector.SuspiciousScheduledTask => (
                $"Подозрительное задание планировщика «{anomaly.EntryName}»",
                $"Задание автоматически запускает скрипт или программу из временной/пользовательской папки: «{anomaly.PayloadCommandOrPath}».",
                89),
            ThreatDetectionVector.WmiPermanentSubscription => (
                $"Бесфайловая постоянная подписка WMI «{anomaly.EntryName}»",
                $"В репозитории WMI (root\\subscription) прописан невидимый триггер автозапуска «{anomaly.PayloadCommandOrPath}».",
                95),
            ThreatDetectionVector.BitsPersistenceJob => (
                $"Постоянное фоновое задание BITS «{anomaly.EntryName}»",
                $"Очередь BITS удерживает подозрительную загрузку или команду уведомления: «{anomaly.PayloadCommandOrPath}».",
                88),
            ThreatDetectionVector.StartupFolderOrShellRedirect => (
                $"Подмена папки Автозагрузки или подозрительный ярлык «{anomaly.EntryName}»",
                $"Обнаружено перенаправление системной папки Startup или запуск подозрительного файла: «{anomaly.PayloadCommandOrPath}».",
                90),
            ThreatDetectionVector.PowerShellProfileHijack => (
                $"Модифицирован профиль автозагрузки PowerShell ({anomaly.EntryName})",
                $"В стартовом сценарии PowerShell обнаружена подозрительная команда: «{anomaly.PayloadCommandOrPath}».",
                87),
            _ => (
                $"Подозрительный автозапуск «{anomaly.EntryName}»",
                $"В ветке «{anomaly.RegistryOrTaskPath}» прописан запуск подозрительного объекта: «{anomaly.PayloadCommandOrPath}».",
                88)
        };
    }

    private static string NormalizePrefix(string path) =>
        path.TrimEnd('\\', '/') + @"\";

    private static string NormalizeExeName(string? processName, string? exePath)
    {
        if (!string.IsNullOrWhiteSpace(exePath))
        {
            return Path.GetFileName(exePath);
        }

        var trimmed = (processName ?? "").Trim();
        return trimmed.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? trimmed
            : trimmed + ".exe";
    }
}
