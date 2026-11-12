using System.Text.Json;
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
/// 2) Комплексное обезвреживание в 1 клик (остановка процесса + удаление закрепления + карантин .uwq с полным откатом в «Машине времени»);
/// 3) Интеграция с Microsoft Defender (удаление опасных слепых зон, запуск быстрой и выборочной проверки) и опциональными PE-sieve / YARA.
/// </summary>
public sealed class AntiMinerSecurityService
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
    /// Комплексно обезвреживает найденную угрозу в один шаг:
    /// 1) Блокирует удаление любых штатных системных бинарников внутри C:\Windows;
    /// 2) При наличии подозрительного процесса завершает его дерево;
    /// 3) При наличии связанной точки автозакрепления, опасного исключения Defender или правила брандмауэра снимает их с записью отката;
    /// 4) Помещает вредоносный исполняемый файл в шифрованный дедуплицированный карантин .uwq.
    /// </summary>
    public async Task<SecurityRemediationResult> QuarantineThreatAsync(
        SecurityThreatFinding finding,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(finding);

        var winPrefix = _bridge.GetWindowsDirectory().TrimEnd('\\', '/') + @"\";
        bool hasFileTarget = !string.IsNullOrWhiteSpace(finding.SuspectFilePath);
        bool isUnderWindows = hasFileTarget &&
                              Path.GetFullPath(finding.SuspectFilePath!).StartsWith(winPrefix, StringComparison.OrdinalIgnoreCase);

        bool hasNonFileAction =
            (finding.PersistenceRecord?.CanRemediate ?? false) ||
            finding.LinkedExclusion is not null ||
            finding.LinkedFirewallRule is not null ||
            finding.Vector is ThreatDetectionVector.ProcessHollowingOrImplant or ThreatDetectionVector.ExternalPeSieveImplant;

        // Строгая защита от самострела: никогда не удаляем и не помещаем в карантин файлы из папки C:\Windows!
        if (isUnderWindows && !hasNonFileAction)
        {
            return new SecurityRemediationResult(
                false,
                null,
                0,
                $"Защита безопасности: файл внутри системного каталога Windows («{finding.SuspectFilePath}») запрещено помещать в карантин.");
        }

        if (!hasFileTarget && !hasNonFileAction && finding.SuspectProcessId is null or <= 4)
        {
            return new SecurityRemediationResult(
                false,
                null,
                0,
                "Для данной находки не требуется автоматическое удаление файла.");
        }

        await using var tx = _vaultService.BeginTransaction(
            SystemDomain.AntiMiner,
            $"Обезвреживание угрозы: {finding.SimpleTitle}",
            finding.SimpleExplanation,
            finding.ExpertTechnicalEvidence);

        int actionsDone = 0;
        var summaryParts = new List<string>();

        // 1. Завершаем активный подозрительный процесс (или донор с имплантом памяти)
        if (finding.SuspectProcessId is int pid and > 4)
        {
            if (await _bridge.TerminateSuspectProcessAsync(pid, ct).ConfigureAwait(false))
            {
                actionsDone++;
                summaryParts.Add($"остановлен процесс PID {pid}");
            }
        }

        // 2. Снимаем точку автозакрепления (реестр / служба / задача / WMI / BITS)
        if (finding.PersistenceRecord is { CanRemediate: true } persistence)
        {
            var (removed, rbKind, rbTarget, prevJson) = await _bridge.RemovePersistenceEntryAsync(persistence, ct).ConfigureAwait(false);
            if (removed)
            {
                if (rbKind.HasValue && !string.IsNullOrWhiteSpace(rbTarget))
                {
                    tx.RecordStateDelta(rbKind.Value, rbTarget, prevJson, null);
                }

                actionsDone++;
                summaryParts.Add($"снято закрепление «{persistence.EntryName}»");
            }
        }

        // 3. Удаляем опасное исключение Защитника Windows
        if (finding.LinkedExclusion is not null)
        {
            if (await _bridge.RemoveDefenderExclusionAsync(finding.LinkedExclusion, ct).ConfigureAwait(false))
            {
                var prevExclJson = JsonSerializer.Serialize(new
                {
                    Kind = finding.LinkedExclusion.Kind.ToString(),
                    finding.LinkedExclusion.Value,
                    finding.LinkedExclusion.IsPolicyEnforced,
                    finding.LinkedExclusion.RegistryPath
                });
                tx.RecordStateDelta(
                    StateTargetKind.SystemSetting,
                    $"DefenderExclusion:{finding.LinkedExclusion.Kind}:{finding.LinkedExclusion.Value}",
                    prevExclJson,
                    null);
                actionsDone++;
                summaryParts.Add($"удалено исключение Defender «{finding.LinkedExclusion.Value}»");
            }
        }

        // 4. Удаляем вредоносное правило Брандмауэра Windows
        if (finding.LinkedFirewallRule is not null)
        {
            if (await _bridge.RemoveFirewallRuleAsync(finding.LinkedFirewallRule, ct).ConfigureAwait(false))
            {
                var prevFwJson = JsonSerializer.Serialize(new
                {
                    finding.LinkedFirewallRule.RuleId,
                    finding.LinkedFirewallRule.RawRegistryValue
                });
                tx.RecordStateDelta(
                    StateTargetKind.SystemSetting,
                    $"FirewallRule:{finding.LinkedFirewallRule.RuleId}",
                    prevFwJson,
                    null);
                actionsDone++;
                summaryParts.Add($"удалено правило брандмауэра «{finding.LinkedFirewallRule.DisplayName}»");
            }
        }

        // 5. Изолируем тело угрозы в шифрованный карантин .uwq (строго вне C:\Windows)
        if (hasFileTarget && !isUnderWindows && finding.CanQuarantineFileSafely)
        {
            var fullPath = Path.GetFullPath(finding.SuspectFilePath!);
            if (File.Exists(fullPath))
            {
                await tx.QuarantineFileAsync(fullPath, ct).ConfigureAwait(false);
                try
                {
                    File.SetAttributes(fullPath, FileAttributes.Normal);
                    File.Delete(fullPath);
                    actionsDone++;
                    summaryParts.Add($"файл «{Path.GetFileName(fullPath)}» изолирован в карантин (.uwq)");
                }
                catch (Exception ex)
                {
                    return new SecurityRemediationResult(
                        false,
                        null,
                        actionsDone,
                        $"Резервная копия создана, но не удалось удалить заблокированный файл «{fullPath}»: {ex.Message}");
                }
            }
            else if (actionsDone == 0)
            {
                return new SecurityRemediationResult(false, null, 0, $"Файл «{fullPath}» уже не существует на диске.");
            }
        }

        if (actionsDone == 0)
        {
            return new SecurityRemediationResult(
                false,
                null,
                0,
                "Не удалось выполнить автоматическое действие (возможно, требуются права администратора).");
        }

        var record = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);
        return new SecurityRemediationResult(
            true,
            record.SessionId,
            actionsDone,
            $"Угроза обезврежена ({string.Join(", ", summaryParts)}). Откат доступен в «Машине времени».");
    }

    /// <summary>
    /// Снимает выбранную точку автозакрепления напрямую со вкладки «Автозакрепление (18 зон)».
    /// </summary>
    public async Task<SecurityRemediationResult> RemovePersistenceAnomalyAsync(
        PersistenceAnomalyRecord anomaly,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(anomaly);
        if (!anomaly.CanRemediate)
        {
            return new SecurityRemediationResult(false, null, 0, "Эта запись является штатной и не требует удаления.");
        }

        await using var tx = _vaultService.BeginTransaction(
            SystemDomain.AntiMiner,
            $"Снятие автозакрепления: {anomaly.EntryName}",
            $"{anomaly.ZoneTitle} — {anomaly.PayloadCommandOrPath}",
            anomaly.RegistryOrTaskPath);

        var (removed, rbKind, rbTarget, prevJson) = await _bridge.RemovePersistenceEntryAsync(anomaly, ct).ConfigureAwait(false);
        if (!removed)
        {
            return new SecurityRemediationResult(
                false,
                null,
                0,
                $"Не удалось снять точку закрепления «{anomaly.EntryName}» (проверьте запуск от имени администратора).");
        }

        if (rbKind.HasValue && !string.IsNullOrWhiteSpace(rbTarget))
        {
            tx.RecordStateDelta(rbKind.Value, rbTarget, prevJson, null);
        }

        var record = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);
        return new SecurityRemediationResult(
            true,
            record.SessionId,
            1,
            $"Точка автозакрепления «{anomaly.EntryName}» отключена. Изменение сохранено в «Машине времени».");
    }

    /// <summary>
    /// Пакетно удаляет опасные слепые зоны (исключения) Microsoft Defender с сохранением отката.
    /// </summary>
    public async Task<SecurityRemediationResult> RemoveDangerousDefenderExclusionsAsync(
        IReadOnlyList<DefenderExclusionFinding> exclusions,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(exclusions);
        var targets = exclusions.Where(e => e.IsDangerousMinerExclusion).ToList();
        if (targets.Count == 0)
        {
            return new SecurityRemediationResult(true, null, 0, "Опасных исключений Защитника Windows не найдено.");
        }

        await using var tx = _vaultService.BeginTransaction(
            SystemDomain.AntiMiner,
            "Очистка опасных исключений Microsoft Defender",
            $"Удаление слепых зон антивируса ({targets.Count} шт.)",
            string.Join("; ", targets.Select(t => $"{t.Kind}:{t.Value}")));

        int removed = 0;
        foreach (var item in targets)
        {
            if (await _bridge.RemoveDefenderExclusionAsync(item, ct).ConfigureAwait(false))
            {
                var prevJson = JsonSerializer.Serialize(new
                {
                    Kind = item.Kind.ToString(),
                    item.Value,
                    item.IsPolicyEnforced,
                    item.RegistryPath
                });
                tx.RecordStateDelta(
                    StateTargetKind.SystemSetting,
                    $"DefenderExclusion:{item.Kind}:{item.Value}",
                    prevJson,
                    null);
                removed++;
            }
        }

        if (removed == 0)
        {
            return new SecurityRemediationResult(
                false,
                null,
                0,
                "Не удалось удалить исключения Защитника Windows (требуются права администратора и отключённая защита от подделки Tamper Protection для некоторых ключей).");
        }

        var record = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);
        return new SecurityRemediationResult(
            true,
            record.SessionId,
            removed,
            $"Удалено опасных исключений Защитника Windows: {removed} из {targets.Count}.");
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
    /// Снимает все послевирусные блокировки (Диспетчер задач, Реестр, CMD, Защитник, MRT, Брандмауэр, hosts).
    /// </summary>
    public async Task<SecurityRemediationResult> HealAllSabotageLocksAsync(
        IReadOnlyList<OsSabotageFinding> locksToHeal,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(locksToHeal);
        if (locksToHeal.Count == 0)
        {
            return new SecurityRemediationResult(true, null, 0, "Активных блокировок системы не обнаружено.");
        }

        await using var tx = _vaultService.BeginTransaction(
            SystemDomain.AntiMiner,
            "Восстановление системы после саботажа майнера",
            $"Снятие блокировок с Диспетчера задач, Реестра, Защитника Windows и файла hosts ({locksToHeal.Count} шт.)",
            "Реабилитация политик безопасности и сетевого доступа");

        int fixedCount = 0;
        foreach (var lockItem in locksToHeal)
        {
            var (ok, origHosts) = await _bridge.RepairSabotageLockAsync(lockItem, ct).ConfigureAwait(false);
            if (!ok) continue;

            if (lockItem.Kind == OsSabotageKind.SecurityDomainsBlockedInHosts && origHosts is not null)
            {
                var prevHostsJson = JsonSerializer.Serialize(new { Path = lockItem.TargetDisplayPath, Content = origHosts });
                tx.RecordStateDelta(StateTargetKind.SystemSetting, "HostsSabotageCleanup", prevHostsJson, null);
            }
            else if (lockItem.Kind == OsSabotageKind.FirewallOutboundSecurityBlock)
            {
                var prevFwJson = JsonSerializer.Serialize(new
                {
                    RuleId = lockItem.ValueName,
                    RawRegistryValue = lockItem.CurrentMaliciousValue
                });
                tx.RecordStateDelta(StateTargetKind.SystemSetting, $"FirewallRule:{lockItem.ValueName}", prevFwJson, null);
            }
            else
            {
                // RegistryValueKind: 1 = String (IFEO Debugger), 4 = DWord (политики)
                int valueKindInt = lockItem.Kind == OsSabotageKind.SystemToolIfeoBlocked ? 1 : 4;
                var prevJson = JsonSerializer.Serialize(new
                {
                    lockItem.Hive,
                    SubKey = lockItem.SubKeyPath,
                    lockItem.ValueName,
                    ExistedBefore = true,
                    ValueKind = valueKindInt,
                    SerializedData = lockItem.CurrentMaliciousValue
                });
                tx.RecordStateDelta(StateTargetKind.RegistryValue, lockItem.TargetDisplayPath, prevJson, null);
            }

            fixedCount++;
        }

        if (fixedCount == 0)
        {
            return new SecurityRemediationResult(
                false,
                null,
                0,
                "Не удалось снять системные блокировки (запустите программу от имени администратора).");
        }

        var record = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);
        return new SecurityRemediationResult(
            true,
            record.SessionId,
            fixedCount,
            $"Успешно снято блокировок системы: {fixedCount} из {locksToHeal.Count}. Доступ к утилитам и обновлениям восстановлен.");
    }

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
                    .Where(d => d.TargetKind == StateTargetKind.QuarantinedFile)
                    .Select(d => d.TargetPath)
                    .ToList(),
                StateDeltaCount: h.Deltas.Count,
                IsReverted: h.IsReverted))
            .ToList();
    }

    /// <summary>
    /// Восстанавливает элемент из карантина (.uwq) и откатывает связанные изменения в один клик.
    /// </summary>
    public async Task<SecurityRemediationResult> RestoreFromQuarantineAsync(Guid sessionId, CancellationToken ct = default)
    {
        try
        {
            await _vaultService.RollbackTransactionAsync(sessionId, ct).ConfigureAwait(false);
            return new SecurityRemediationResult(
                true,
                sessionId,
                1,
                "Объект успешно восстановлен из шифрованного карантина (.uwq) на прежнее место.");
        }
        catch (Exception ex)
        {
            return new SecurityRemediationResult(
                false,
                sessionId,
                0,
                $"Не удалось восстановить объект из карантина: {ex.Message}");
        }
    }
}
