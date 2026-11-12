using System.Globalization;
using System.Text.Json;
using UltimateWindows.Core.Contracts;
using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Repair.Contracts;

namespace UltimateWindows.Modules.Repair.Diagnostics;

/// <summary>
/// Диагностический и ремонтный движок Этапа 3:
/// реализует полный цикл «Обнаружить → Объяснить → Исправить → Проверить» с единой точкой отката в «Машине времени».
/// </summary>
public sealed class RepairDiagnosticEngine
{
    private readonly IVaultService _vaultService;
    private readonly IRepairPlatformBridge _bridge;
    private readonly IReadOnlyList<RepairRuleDefinition> _catalog;

    public RepairDiagnosticEngine(
        IVaultService vaultService,
        IRepairPlatformBridge bridge,
        IReadOnlyList<RepairRuleDefinition>? customCatalog = null)
    {
        _vaultService = vaultService ?? throw new ArgumentNullException(nameof(vaultService));
        _bridge = bridge ?? throw new ArgumentNullException(nameof(bridge));
        _catalog = customCatalog ?? RepairCatalogLoader.LoadBuiltInCatalog();
    }

    public IReadOnlyList<RepairRuleDefinition> Catalog => _catalog;

    /// <summary>
    /// Проверяет все правила каталога (или указанного раздела) на текущей системе.
    /// </summary>
    public async Task<IReadOnlyList<RepairCheckFinding>> ScanAllAsync(
        RepairSectionId? sectionFilter = null,
        CancellationToken ct = default)
    {
        var rules = sectionFilter.HasValue
            ? _catalog.Where(r => r.Section == sectionFilter.Value).ToList()
            : _catalog;

        var findings = new List<RepairCheckFinding>(rules.Count);
        foreach (var rule in rules)
        {
            ct.ThrowIfCancellationRequested();
            findings.Add(await EvaluateRuleAsync(rule, ct).ConfigureAwait(false));
        }

        return findings;
    }

    /// <summary>
    /// Выполняет фазу «Обнаружить» для одного правила.
    /// </summary>
    public async Task<RepairCheckFinding> EvaluateRuleAsync(
        RepairRuleDefinition rule,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(rule);
        var now = DateTimeOffset.UtcNow;

        // 1. Проверка применимости по сборке Windows
        var osBuild = _bridge.GetWindowsBuildNumber();
        if (osBuild > 0)
        {
            if (rule.MinBuild.HasValue && osBuild < rule.MinBuild.Value)
            {
                return new RepairCheckFinding(
                    rule,
                    RepairHealthState.NotApplicable,
                    $"Правило предназначено для Windows со сборкой не ниже {rule.MinBuild.Value} (текущая: {osBuild}).",
                    now);
            }

            if (rule.MaxBuild.HasValue && osBuild > rule.MaxBuild.Value)
            {
                return new RepairCheckFinding(
                    rule,
                    RepairHealthState.NotApplicable,
                    $"Правило предназначено для сборок Windows до {rule.MaxBuild.Value} (текущая: {osBuild}).",
                    now);
            }
        }

        var issues = new List<string>();
        var healthyNotes = new List<string>();
        var allIgnoredMissing = true;

        // 2. Проверки реестра
        foreach (var rc in rule.RegistryChecks)
        {
            var state = _bridge.ReadRegistryValue(rc.Hive, rc.SubKey, rc.ValueName);
            if (!state.KeyExists && rc.OnlyIfKeyExists)
            {
                continue;
            }

            allIgnoredMissing = false;
            var (ok, reason) = EvaluateRegistryCheck(rc, state);
            if (!ok)
            {
                issues.Add(reason);
            }
            else
            {
                healthyNotes.Add(reason);
            }
        }

        // 3. Проверки служб
        foreach (var sc in rule.ServiceChecks)
        {
            var svc = _bridge.QueryServiceState(sc.ServiceName);
            if (!svc.Exists)
            {
                if (sc.IgnoreIfMissing)
                {
                    continue;
                }

                allIgnoredMissing = false;
                issues.Add($"Служба «{sc.ServiceName}» не найдена в диспетчере служб.");
                continue;
            }

            allIgnoredMissing = false;
            if (svc.Startup == RepairServiceStartupKind.Disabled)
            {
                issues.Add($"Служба «{sc.ServiceName}» отключена (Disabled), ожидается {FormatStartup(sc.HealthyStartup)}.");
            }
            else if (sc.RequireRunning && !svc.IsRunning)
            {
                issues.Add($"Служба «{sc.ServiceName}» остановлена (режим: {FormatStartup(svc.Startup)}).");
            }
            else
            {
                healthyNotes.Add($"Служба «{sc.ServiceName}»: {FormatStartup(svc.Startup)}{(svc.IsRunning ? ", работает" : "")}.");
            }
        }

        // 4. Специальная глубокая проверка (customProbe)
        if (!string.IsNullOrWhiteSpace(rule.CustomProbe))
        {
            allIgnoredMissing = false;
            var probe = await _bridge.RunCustomProbeAsync(rule.CustomProbe, ct).ConfigureAwait(false);
            if (probe.State == RepairHealthState.NeedsElevation)
            {
                return new RepairCheckFinding(rule, RepairHealthState.NeedsElevation, probe.Evidence, now);
            }

            if (probe.State == RepairHealthState.NotApplicable)
            {
                return new RepairCheckFinding(rule, RepairHealthState.NotApplicable, probe.Evidence, now);
            }

            if (probe.State == RepairHealthState.ProbeError)
            {
                return new RepairCheckFinding(rule, RepairHealthState.ProbeError, probe.Evidence, now);
            }

            if (probe.State == RepairHealthState.IssueDetected)
            {
                issues.Add(probe.Evidence);
            }
            else
            {
                healthyNotes.Add(probe.Evidence);
            }
        }

        if (allIgnoredMissing && (rule.RegistryChecks.Count > 0 || rule.ServiceChecks.Count > 0))
        {
            return new RepairCheckFinding(
                rule,
                RepairHealthState.NotApplicable,
                "Целевой компонент или служба отсутствует в данной редакции Windows.",
                now);
        }

        if (issues.Count > 0)
        {
            return new RepairCheckFinding(
                rule,
                RepairHealthState.IssueDetected,
                string.Join(" ", issues),
                now);
        }

        var okSummary = healthyNotes.Count > 0
            ? string.Join(" ", healthyNotes.Take(2))
            : "Параметры и службы соответствуют норме.";

        return new RepairCheckFinding(rule, RepairHealthState.Healthy, okSummary, now);
    }

    /// <summary>
    /// Выполняет фазы «Исправить → Проверить» для выбранных правил, записывая прежние состояния в одну транзакцию «Машины времени».
    /// </summary>
    public async Task<RepairBatchFixResult> FixAndVerifyAsync(
        IReadOnlyList<string> ruleIds,
        bool allowRiskyConfirmed = false,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(ruleIds);
        if (ruleIds.Count == 0)
        {
            return new RepairBatchFixResult(0, 0, 0, 0, 0, null, "Не выбрано ни одного правила для исправления.", []);
        }

        var isAdmin = _bridge.IsRunningAsAdministrator();
        var outcomes = new List<RepairRuleFixOutcome>(ruleIds.Count);
        var recordedDeltas = 0;

        var title = ruleIds.Count == 1
            ? $"Ремонт ОС: {_catalog.FirstOrDefault(r => string.Equals(r.Id, ruleIds[0], StringComparison.OrdinalIgnoreCase))?.Title ?? ruleIds[0]}"
            : $"Пакетный ремонт Windows ({ruleIds.Count} правил)";

        await using var tx = _vaultService.BeginTransaction(
            SystemDomain.DllAndRepair,
            friendlyTitle: title,
            friendlySummary: "Автоматическое сохранение прежних значений реестра и режимов служб перед ремонтом.",
            technicalDetails: string.Join(", ", ruleIds));

        foreach (var id in ruleIds)
        {
            ct.ThrowIfCancellationRequested();
            var rule = _catalog.FirstOrDefault(r => string.Equals(r.Id, id, StringComparison.OrdinalIgnoreCase));
            if (rule is null)
            {
                outcomes.Add(new RepairRuleFixOutcome(
                    id, id, false, false, false,
                    $"Правило «{id}» не найдено в каталоге.",
                    RepairHealthState.ProbeError, ""));
                continue;
            }

            if (rule.RequiresAdmin && !isAdmin)
            {
                outcomes.Add(new RepairRuleFixOutcome(
                    rule.Id, rule.Title, false, false, false,
                    "Для исправления требуются права администратора.",
                    RepairHealthState.NeedsElevation, "Запустите программу от имени администратора."));
                continue;
            }

            if (rule.RequiresExplicitConfirmation && !allowRiskyConfirmed)
            {
                outcomes.Add(new RepairRuleFixOutcome(
                    rule.Id, rule.Title, false, false, false,
                    "Правило имеет повышенный уровень риска и требует явного подтверждения (диалог в UI или ключ --force в CLI).",
                    RepairHealthState.IssueDetected, "Ожидается подтверждение пользователя."));
                continue;
            }

            var stepErrors = new List<string>();
            var needsReboot = false;

            // 1. Исправление параметров реестра (с записью точного снимка для отката)
            foreach (var rc in rule.RegistryChecks)
            {
                var before = _bridge.ReadRegistryValue(rc.Hive, rc.SubKey, rc.ValueName);
                if (!before.KeyExists && rc.OnlyIfKeyExists)
                {
                    continue;
                }

                var (alreadyOk, _) = EvaluateRegistryCheck(rc, before);
                if (alreadyOk)
                {
                    continue;
                }

                if (rc.FixKind == RepairRegistryFixKind.DeleteValue)
                {
                    var (delOk, delErr) = _bridge.DeleteRegistryValue(rc.Hive, rc.SubKey, rc.ValueName);
                    if (!delOk)
                    {
                        stepErrors.Add(delErr ?? $"Не удалось удалить {rc.Hive}\\{rc.SubKey}\\{rc.ValueName}");
                        continue;
                    }

                    if (before.ValueExists)
                    {
                        RecordRegistryDelta(tx, rc, before, createdKeyPath: null, newDesc: "Deleted");
                        recordedDeltas++;
                    }
                }
                else
                {
                    var writeKind = rc.FixKind switch
                    {
                        RepairRegistryFixKind.SetDword => RepairRegistryValueKind.DWord,
                        RepairRegistryFixKind.SetExpandString => RepairRegistryValueKind.ExpandString,
                        _ => RepairRegistryValueKind.String
                    };

                    var (wOk, createdKey, wErr) = _bridge.WriteRegistryValue(
                        rc.Hive, rc.SubKey, rc.ValueName, writeKind, rc.FixString, rc.FixDword);
                    if (!wOk)
                    {
                        stepErrors.Add(wErr ?? $"Не удалось записать {rc.Hive}\\{rc.SubKey}\\{rc.ValueName}");
                        continue;
                    }

                    RecordRegistryDelta(tx, rc, before, createdKey, rc.FixString ?? rc.FixDword?.ToString(CultureInfo.InvariantCulture) ?? "");
                    recordedDeltas++;
                }
            }

            // 2. Восстановление служб (с записью прежнего режима запуска в Машину времени)
            foreach (var sc in rule.ServiceChecks)
            {
                var beforeSvc = _bridge.QueryServiceState(sc.ServiceName);
                if (!beforeSvc.Exists)
                {
                    if (!sc.IgnoreIfMissing)
                    {
                        stepErrors.Add($"Служба «{sc.ServiceName}» отсутствует в системе.");
                    }

                    continue;
                }

                var needsChange = beforeSvc.Startup == RepairServiceStartupKind.Disabled ||
                                  (sc.RequireRunning && !beforeSvc.IsRunning) ||
                                  (sc.StartIfStopped && !beforeSvc.IsRunning);
                if (!needsChange)
                {
                    continue;
                }

                var (svcOk, svcErr) = await _bridge.RepairServiceAsync(
                    sc.ServiceName,
                    sc.HealthyStartup,
                    sc.StartIfStopped || sc.RequireRunning,
                    ct).ConfigureAwait(false);

                if (!svcOk)
                {
                    stepErrors.Add(svcErr ?? $"Не удалось восстановить службу «{sc.ServiceName}».");
                    continue;
                }

                if (beforeSvc.Startup != sc.HealthyStartup)
                {
                    tx.RecordStateDelta(
                        StateTargetKind.WindowsService,
                        sc.ServiceName,
                        previousStateJson: JsonSerializer.Serialize(new { ServiceName = sc.ServiceName, Startup = beforeSvc.Startup.ToString() }),
                        newStateJson: JsonSerializer.Serialize(new { ServiceName = sc.ServiceName, Startup = sc.HealthyStartup.ToString() }));
                    recordedDeltas++;
                }
            }

            // 3. Специальный шаг ремонта (customProbe)
            var customLog = string.Empty;
            if (!string.IsNullOrWhiteSpace(rule.CustomProbe))
            {
                var (cOk, cReboot, cLog, rollbackTarget, rollbackJson) =
                    await _bridge.ExecuteCustomFixAsync(rule.CustomProbe, ct).ConfigureAwait(false);
                customLog = cLog;
                if (cReboot) needsReboot = true;

                if (!cOk)
                {
                    stepErrors.Add(string.IsNullOrWhiteSpace(cLog) ? $"Сбой шага {rule.CustomProbe}" : cLog);
                }
                else if (!string.IsNullOrWhiteSpace(rollbackTarget) && !string.IsNullOrWhiteSpace(rollbackJson))
                {
                    tx.RecordStateDelta(
                        StateTargetKind.SystemSetting,
                        rollbackTarget,
                        previousStateJson: rollbackJson,
                        newStateJson: JsonSerializer.Serialize(new { RepairedRule = rule.Id }));
                    recordedDeltas++;
                }
            }

            // 4. Фаза «ПРОВЕРИТЬ»: повторно читаем реальное состояние системы!
            var postCheck = await EvaluateRuleAsync(rule, ct).ConfigureAwait(false);
            var fixSucceeded = stepErrors.Count == 0;
            var verifiedHealthy = fixSucceeded && postCheck.State == RepairHealthState.Healthy;

            string msg;
            if (!fixSucceeded)
            {
                msg = $"Не удалось выполнить исправление: {string.Join("; ", stepErrors)}";
            }
            else if (verifiedHealthy)
            {
                msg = string.IsNullOrWhiteSpace(customLog)
                    ? "Исправлено и подтверждено повторной проверкой."
                    : $"Исправлено и подтверждено проверкой ({customLog}).";
            }
            else if (needsReboot)
            {
                msg = string.IsNullOrWhiteSpace(customLog)
                    ? "Изменения внесены; вступят в силу после перезагрузки Windows."
                    : $"{customLog} Вступит в силу после перезагрузки.";
            }
            else
            {
                msg = $"Действия выполнены, но повторная проверка всё ещё видит отклонение: {postCheck.Evidence}";
            }

            outcomes.Add(new RepairRuleFixOutcome(
                RuleId: rule.Id,
                RuleTitle: rule.Title,
                FixSucceeded: fixSucceeded,
                VerifiedHealthyAfterFix: verifiedHealthy,
                RequiresReboot: needsReboot,
                Message: msg,
                PostFixState: postCheck.State,
                PostFixEvidence: postCheck.Evidence));
        }

        Guid? rollbackId = null;
        var succeededCount = outcomes.Count(o => o.FixSucceeded);
        var verifiedCount = outcomes.Count(o => o.VerifiedHealthyAfterFix);
        var failedCount = outcomes.Count(o => !o.FixSucceeded);
        var rebootCount = outcomes.Count(o => o.RequiresReboot);

        if (recordedDeltas > 0 || succeededCount > 0)
        {
            if (recordedDeltas == 0)
            {
                tx.RecordStateDelta(
                    StateTargetKind.SystemSetting,
                    $"RepairBatch:{DateTimeOffset.UtcNow:yyyyMMddHHmmss}",
                    previousStateJson: JsonSerializer.Serialize(new { Rules = ruleIds }),
                    newStateJson: JsonSerializer.Serialize(new { Succeeded = succeededCount, Verified = verifiedCount }));
            }

            var committed = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);
            rollbackId = committed.SessionId;
        }

        var headline = failedCount == 0
            ? $"Готово: исправлено правил — {succeededCount}, подтверждено проверкой — {verifiedCount}{(rebootCount > 0 ? $" (нужна перезагрузка для {rebootCount})" : "")}."
            : $"Выполнено частично: успешно — {succeededCount}, подтверждено — {verifiedCount}, с ошибкой — {failedCount}.";

        return new RepairBatchFixResult(
            RequestedCount: ruleIds.Count,
            SucceededCount: succeededCount,
            VerifiedHealthyCount: verifiedCount,
            FailedCount: failedCount,
            RequiresRebootCount: rebootCount,
            RollbackSessionId: rollbackId,
            SummaryHeadline: headline,
            Outcomes: outcomes);
    }

    private static (bool IsHealthy, string Note) EvaluateRegistryCheck(
        RepairRegistryCheck rc,
        RepairRegistryValueState state)
    {
        var displayName = string.IsNullOrEmpty(rc.ValueName) ? "(По умолчанию)" : rc.ValueName;
        var loc = $@"{rc.Hive}\{rc.SubKey}\{displayName}";

        switch (rc.Expectation)
        {
            case RepairRegistryExpectation.MustNotExist:
                if (!state.ValueExists)
                {
                    return (true, $"Параметр {displayName} не задан (норма).");
                }

                // Для числовых политик блокировки (DisableTaskMgr=0 и т.п.) значение 0 эквивалентно отсутствию блокировки!
                if (state.Kind == RepairRegistryValueKind.DWord && state.DwordValue == 0)
                {
                    return (true, $"Политика {displayName} равна 0 (не блокирует).");
                }

                var foundVal = state.StringValue ?? state.DwordValue?.ToString(CultureInfo.InvariantCulture) ?? state.RawSerializedData ?? "<задано>";
                return (false, $"Обнаружен блокирующий параметр {loc} = «{foundVal}».");

            case RepairRegistryExpectation.MustEqualDword:
                var expDw = rc.ExpectedDword ?? 0;
                if (state.ValueExists && state.DwordValue == expDw)
                {
                    return (true, $"{displayName} = {expDw} (норма).");
                }

                var curDw = state.ValueExists ? (state.DwordValue?.ToString(CultureInfo.InvariantCulture) ?? state.StringValue ?? "?") : "отсутствует";
                return (false, $"Параметр {loc} имеет значение «{curDw}» вместо ожидаемого {expDw}.");

            case RepairRegistryExpectation.MustNotEqualDword:
                var badDw = rc.ExpectedDword ?? 0;
                if (!state.ValueExists || state.DwordValue != badDw)
                {
                    return (true, $"{displayName} не равен запрещённому {badDw} (норма).");
                }

                return (false, $"Параметр {loc} равен {badDw} (отключено/заблокировано).");

            case RepairRegistryExpectation.MustEqualString:
                var expStr = rc.ExpectedString ?? "";
                if (state.ValueExists && string.Equals(state.StringValue?.Trim(), expStr.Trim(), StringComparison.OrdinalIgnoreCase))
                {
                    return (true, $"{displayName} = «{state.StringValue}» (норма).");
                }

                return (false, $"Параметр {loc} равен «{state.StringValue ?? "отсутствует"}» вместо «{expStr}».");

            case RepairRegistryExpectation.MustContainSubstring:
                var sub = rc.ExpectedString ?? "";
                if (state.ValueExists && !string.IsNullOrEmpty(state.StringValue) &&
                    state.StringValue.Contains(sub, StringComparison.OrdinalIgnoreCase))
                {
                    return (true, $"{displayName} содержит «{sub}» (норма).");
                }

                return (false, $"Параметр {loc} («{state.StringValue ?? "отсутствует"}») не содержит «{sub}».");

            case RepairRegistryExpectation.MustNotEqualString:
                var badStr = rc.ExpectedString ?? "";
                if (!state.ValueExists || !string.Equals(state.StringValue?.Trim(), badStr.Trim(), StringComparison.OrdinalIgnoreCase))
                {
                    return (true, $"{displayName} не равен «{badStr}» (норма).");
                }

                return (false, $"Параметр {loc} установлен в запрещённое значение «{state.StringValue}».");

            default:
                return (true, "Норма.");
        }
    }

    private static void RecordRegistryDelta(
        ITransactionSession tx,
        RepairRegistryCheck rc,
        RepairRegistryValueState before,
        string? createdKeyPath,
        string newDesc)
    {
        // Точно совпадает со структурой RegistryValueSnapshot в WindowsSystemStateApplier
        var prevJson = JsonSerializer.Serialize(new
        {
            Hive = rc.Hive,
            SubKey = rc.SubKey,
            ValueName = rc.ValueName,
            ExistedBefore = before.ValueExists,
            ValueKind = (int)(before.ValueExists ? before.Kind : RepairRegistryValueKind.String),
            SerializedData = before.RawSerializedData,
            CreatedKeyPath = createdKeyPath
        });

        var newJson = JsonSerializer.Serialize(new
        {
            Hive = rc.Hive,
            SubKey = rc.SubKey,
            ValueName = rc.ValueName,
            NewValue = newDesc
        });

        var displayName = string.IsNullOrEmpty(rc.ValueName) ? "(Default)" : rc.ValueName;
        tx.RecordStateDelta(
            StateTargetKind.RegistryValue,
            $@"{rc.Hive}\{rc.SubKey}\{displayName}",
            prevJson,
            newJson);
    }

    private static string FormatStartup(RepairServiceStartupKind kind) => kind switch
    {
        RepairServiceStartupKind.Automatic => "Автоматически",
        RepairServiceStartupKind.AutomaticDelayed => "Автоматически (отложенный)",
        RepairServiceStartupKind.Manual => "Вручную",
        RepairServiceStartupKind.Disabled => "Отключена",
        _ => "Неизвестно"
    };
}
