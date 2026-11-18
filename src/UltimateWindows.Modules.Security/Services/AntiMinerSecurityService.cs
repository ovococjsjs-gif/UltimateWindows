using UltimateWindows.Core.Contracts;
using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Security.Analyzers;
using UltimateWindows.Modules.Security.Models;
using UltimateWindows.Modules.Security.Scanners;

namespace UltimateWindows.Modules.Security.Services;

/// <summary>
/// Оркестратор модуля «Анти-майнер и Защита 2.0»:
/// 1) Полный многовекторный аудит (CPU+GPU Drop-on-Inspect с реальным монитором, 18 зон автозакрепления, Stratum IPv4/IPv6 + DNS-кэш,
///    исключения Защитника Windows, правила брандмауэра, скрытые учетные записи, staging-папки и блокировки ОС);
/// 2) Комплексное обезвреживание в 1 клик (остановка процесса + удаление закрепления + карантин .uwq с журналом подтверждённых изменений);
/// 3) Интеграция с Microsoft Defender (удаление опасных слепых зон, запуск быстрой и выборочной проверки) и опциональными PE-sieve / YARA.
/// </summary>
public sealed partial class AntiMinerSecurityService
{
    private readonly IVaultService _vaultService;
    private readonly ISecurityPlatformBridge _bridge;
    private readonly MinerThreatHeuristicEngine _heuristicEngine;
    private readonly ExternalScannerCoordinator _externalScanners;

    public AntiMinerSecurityService(
        IVaultService vaultService,
        ISecurityPlatformBridge? bridge = null,
        MinerThreatHeuristicEngine? heuristicEngine = null,
        ExternalScannerCoordinator? externalScanners = null)
    {
        _vaultService = vaultService ?? throw new ArgumentNullException(nameof(vaultService));
        _bridge = bridge ?? new DefaultSecurityPlatformBridge();
        _heuristicEngine = heuristicEngine ?? new MinerThreatHeuristicEngine();
        _externalScanners = externalScanners ?? new ExternalScannerCoordinator();
    }

    public ExternalScannerCoordinator ExternalScanners => _externalScanners;

    /// <summary>
    /// Запускает полный многоуровневый аудит безопасности ПК.
    /// </summary>
    public async Task<SecurityScanReport> RunFullSecurityScanAsync(
        bool enableDropOnInspectProbe = true,
        CancellationToken ct = default)
    {
        var isAdmin = _bridge.IsRunningAsAdministrator();
        var winDir = _bridge.GetWindowsDirectory();

        var telemetryTask = _bridge.CaptureDropOnInspectSamplesAsync(enableDropOnInspectProbe, ct);
        var tcpTask = _bridge.GetActiveTcpConnectionsAsync(ct);
        var persistenceTask = _bridge.ScanPersistenceAnomaliesAsync(ct);
        var sabotageTask = _bridge.ScanOsSabotageLocksAsync(ct);
        var defenderExclTask = _bridge.ScanDefenderExclusionsAsync(ct);
        var firewallTask = _bridge.ScanFirewallRuleAnomaliesAsync(ct);
        var usersTask = _bridge.ScanSuspiciousUserAccountsAsync(ct);
        var artifactsTask = _bridge.ScanStagingDirectoriesAsync(ct);
        var dnsCacheTask = _bridge.ScanDnsCacheMiningPoolDomainsAsync(ct);

        await Task.WhenAll(
            telemetryTask, tcpTask, persistenceTask, sabotageTask,
            defenderExclTask, firewallTask, usersTask, artifactsTask, dnsCacheTask).ConfigureAwait(false);

        var processes = telemetryTask.Result;
        var tcpConnections = tcpTask.Result;
        var allPersistence = persistenceTask.Result;
        var sabotageLocks = sabotageTask.Result;
        var defenderExclusions = defenderExclTask.Result;
        var firewallAnomalies = firewallTask.Result;
        var suspiciousUsers = usersTask.Result;
        var directoryArtifacts = artifactsTask.Result;
        var dnsPoolDomains = dnsCacheTask.Result;
        var scannerStatuses = _externalScanners.ProbeAvailableScanners();

        var threats = _heuristicEngine.AnalyzeFullEcosystem(
            processes,
            tcpConnections,
            allPersistence,
            defenderExclusions,
            firewallAnomalies,
            suspiciousUsers,
            directoryArtifacts,
            dnsPoolDomains,
            winDir);

        int penalty = threats.Sum(t => t.Severity switch
        {
            RiskLevel.Critical => 30,
            RiskLevel.High => 18,
            _ => 10
        }) + sabotageLocks.Count * 12;

        int healthScore = Math.Clamp(100 - penalty, 0, 100);
        int dangerousExclusions = defenderExclusions.Count(e => e.IsDangerousMinerExclusion);
        int anomalousPersistence = allPersistence.Count(p => p.IsAnomaly);

        string headline = threats.Count == 0 && sabotageLocks.Count == 0
            ? $"Угроз и скрытых майнеров не обнаружено (проверено 18 зон автозакрепления: {allPersistence.Count} записей, исключений Defender: {defenderExclusions.Count})."
            : $"Найдено угроз: {threats.Count} (аномалий закрепления: {anomalousPersistence}, опасных исключений Defender: {dangerousExclusions}), блокировок ОС: {sabotageLocks.Count}.";

        return new SecurityScanReport(
            ScannedAtUtc: DateTimeOffset.UtcNow,
            RanWithAdministratorPrivileges: isAdmin,
            RanDropOnInspectDecoy: enableDropOnInspectProbe,
            Threats: threats,
            SabotageLocks: sabotageLocks,
            SecurityHealthScore: healthScore,
            HeadlineSummary: headline,
            AllPersistenceEntries: allPersistence,
            DefenderExclusions: defenderExclusions,
            FirewallAnomalies: firewallAnomalies,
            SuspiciousUsers: suspiciousUsers,
            DirectoryArtifacts: directoryArtifacts,
            ProcessSnapshots: processes,
            ExternalScanners: scannerStatuses,
            DnsCachedPoolDomains: dnsPoolDomains,
            PersistenceZonesAuditedCount: PersistenceZoneCatalog.AllZones.Count);
    }

    /// <summary>
    /// Запускает быструю или выборочную проверку Microsoft Defender (MpCmdRun.exe).
    /// </summary>
    public Task<(bool Succeeded, string OutputMessage)> StartDefenderScanAsync(
        DefenderScanMode mode,
        string? customPath = null,
        CancellationToken ct = default)
        => _bridge.StartDefenderScanAsync(mode, customPath, ct);

    /// <summary>
    /// Запускает глубокую проверку памяти подозрительных процессов внешним сканером PE-sieve (если подключён).
    /// </summary>
    public Task<IReadOnlyList<SecurityThreatFinding>> RunPeSieveDeepCheckAsync(
        IEnumerable<int> suspectPids,
        CancellationToken ct = default)
        => _externalScanners.ScanProcessesWithPeSieveAsync(suspectPids, _bridge.GetWindowsDirectory(), ct);

    /// <summary>
    /// Запускает проверку каталога или процесса внешним сканером YARA (если подключён).
    /// </summary>
    public Task<IReadOnlyList<SecurityThreatFinding>> RunYaraScanAsync(
        string targetPath,
        CancellationToken ct = default)
        => _externalScanners.RunYaraScanAsync(targetPath, _bridge.GetWindowsDirectory(), ct);

    /// <summary>
    /// Возвращает список изолированных угроз и действий раздела «Анти-майнер» из хранилища «Машины времени».
    /// </summary>
    public async Task<IReadOnlyList<QuarantinedThreatEntry>> GetQuarantineHistoryAsync(CancellationToken ct = default)
    {
        var history = await _vaultService.GetHistoryAsync(limit: 100, ct).ConfigureAwait(false);
        return history
            .Where(h => h.Domain == SystemDomain.AntiMiner)
            .Select(h => new QuarantinedThreatEntry(
                SessionId: h.SessionId,
                QuarantinedAtUtc: h.CreatedAtUtc,
                FriendlyTitle: h.FriendlyTitle,
                FriendlySummary: h.FriendlySummary,
                QuarantinedPaths: h.Deltas
                    .Where(d => d.TargetKind == StateTargetKind.QuarantinedFile && !d.IsJournalOnly)
                    .Select(d => d.TargetPath)
                    .ToList(),
                StateDeltaCount: h.Deltas.Count,
                IsReverted: h.IsReverted,
                RollbackUnavailableReason: h.RollbackUnavailableReason,
                StepSummary: h.StepSummary, StepOutcomeText: h.StepOutcomeText))
            .ToList();
    }

    /// <summary>
    /// Восстанавливает элемент из карантина (.uwq) и откатывает связанные изменения в один клик.
    /// </summary>
    public async Task<SecurityRemediationResult> RestoreFromQuarantineAsync(Guid sessionId, CancellationToken ct = default)
    {
        try
        {
            var saved = await _vaultService.GetTransactionAsync(sessionId, ct).ConfigureAwait(false);
            if (saved?.Domain != SystemDomain.AntiMiner) return new(false, null, 0, "Запись раздела защиты не найдена.");
            if (saved.IsReverted) return new(true, null, 0, "Доступные изменения уже отменены.");
            if (saved.RollbackUnavailableReason is { } reason) return new(false, null, 0, $"Откат недоступен: {reason}.");
            await _vaultService.RollbackTransactionAsync(sessionId, ct).ConfigureAwait(false);
            return new(true, null, saved.RestorableDeltas.Count(), "Доступные файлы и настройки восстановлены. Остановленные процессы не запускались.");
        }
        catch (Exception ex)
        {
            return new SecurityRemediationResult(
                false,
                null,
                0,
                $"Не удалось восстановить объект из карантина: {ex.Message}");
        }
    }
}
