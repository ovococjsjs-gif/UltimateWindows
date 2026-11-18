using UltimateWindows.Core.Enums;
using UltimateWindows.Core.Models;
using UltimateWindows.Modules.Security.Models;

namespace UltimateWindows.Modules.Security.Services;

public sealed partial class AntiMinerSecurityService
{
    public Task<SecurityRemediationResult> QuarantineThreatAsync(SecurityThreatFinding finding, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(finding);
        return RunReviewedAsync(finding.SimpleTitle, () =>
        {
            var changes = new List<PreparedSecurityChange>();
            var path = string.IsNullOrWhiteSpace(finding.SuspectFilePath) ? null : Path.GetFullPath(finding.SuspectFilePath);
            var protectedPath = path is not null && IsWindowsPath(path);
            var image = finding.ReviewedProcessImage;
            if (finding.CanStopReviewedProcess && finding.SuspectProcessId is int pid && image is not null && !IsWindowsPath(Path.GetFullPath(image)))
                changes.Add(new($"Остановка PID {pid}", StateTargetKind.JournalEntry, $"PID {pid}", null,
                    token => _bridge.TerminateSuspectProcessAsync(pid, image, token)));
            if (finding.PersistenceRecord is { } p) changes.Add(PreparePersistence(p));
            if (finding.LinkedExclusion is { } ex) changes.Add(PrepareExclusion(ex));
            if (finding.LinkedFirewallRule is { } fw) changes.Add(_bridge.PrepareFirewallRule(fw));
            if (finding.CanQuarantineFileSafely && path is not null && !protectedPath &&
                !changes.Any(c => c.Kind == StateTargetKind.QuarantinedFile && string.Equals(c.Target, path, StringComparison.OrdinalIgnoreCase)))
                changes.Add(PrepareFile(path));
            if (changes.Count == 0) throw new InvalidOperationException(protectedPath
                ? "Системный файл Windows и его процесс не изменены." : "Нет доступных автоматических действий.");
            return changes;
        }, ct);
    }

    public Task<SecurityRemediationResult> RemovePersistenceAnomalyAsync(PersistenceAnomalyRecord anomaly, CancellationToken ct = default) =>
        RunReviewedAsync($"Автозакрепление: {anomaly.EntryName}", () => [PreparePersistence(anomaly)], ct);

    public Task<SecurityRemediationResult> RemoveDangerousDefenderExclusionsAsync(IReadOnlyList<DefenderExclusionFinding> exclusions, CancellationToken ct = default) =>
        RunReviewedAsync("Опасные исключения Microsoft Defender", () => exclusions.Where(e => e.IsDangerousMinerExclusion)
            .Distinct().Select(PrepareExclusion).ToList(), ct);

    public Task<SecurityRemediationResult> HealAllSabotageLocksAsync(IReadOnlyList<OsSabotageFinding> locksToHeal, CancellationToken ct = default) =>
        RunReviewedAsync("Восстановление системных настроек", () => locksToHeal.Distinct().Select(_bridge.PrepareSabotageRepair).ToList(), ct);

    private PreparedSecurityChange PrepareExclusion(DefenderExclusionFinding item) => item.IsDangerousMinerExclusion
        ? _bridge.PrepareDefenderExclusion(item) : throw new InvalidOperationException("Штатное исключение не выбрано для очистки.");

    private PreparedSecurityChange PreparePersistence(PersistenceAnomalyRecord p)
    {
        if (!p.CanRemediate) throw new InvalidOperationException("Для этой записи нет проверенного автоматического исправления. Требуется ручная проверка.");
        return p.RemediationKind == PersistenceRemediationKind.QuarantineStartupFile ? PrepareFile(p.RemediationTarget) : _bridge.PreparePersistence(p);
    }

    private PreparedSecurityChange PrepareFile(string path)
    {
        path = Path.GetFullPath(path);
        if (IsWindowsPath(path)) throw new InvalidOperationException("Файл в каталоге Windows защищён.");
        return new($"Карантин: {Path.GetFileName(path)}", StateTargetKind.QuarantinedFile, path, null, null);
    }

    private bool IsWindowsPath(string fullPath)
    {
        var windows = Path.TrimEndingDirectorySeparator(Path.GetFullPath(_bridge.GetWindowsDirectory()));
        return fullPath.Equals(windows, StringComparison.OrdinalIgnoreCase) ||
               fullPath.StartsWith(windows + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private async Task<SecurityRemediationResult> RunReviewedAsync(string title, Func<IReadOnlyList<PreparedSecurityChange>> prepare, CancellationToken ct)
    {
        Guid? journalId = null;
        Guid? preparingId = null;
        var steps = new List<SecurityStepResult>();
        string? problem = null;
        try
        {
            var changes = await Task.Run(prepare, ct).ConfigureAwait(false);
            if (changes.Count == 0) return new(true, null, 0, "Нет выбранных изменений.");
            steps.AddRange(changes.Select(c => new SecurityStepResult(c.Label, StepState.Planned)));
            await using var tx = _vaultService.BeginTransaction(SystemDomain.AntiMiner, title,
                "Откат относится только к подтверждённым обратимым шагам. Процессы заново не запускаются.");
            foreach (var c in changes)
            {
                ct.ThrowIfCancellationRequested();
                if (c.Kind == StateTargetKind.QuarantinedFile) await tx.BackupFileAsync(c.Target, ct).ConfigureAwait(false);
                else tx.RecordStateDelta(c.Kind, c.Target, c.BeforeJson, c.AfterJson);
            }
            preparingId = tx.SessionId;
            var plan = await tx.PrepareRecordedPlanAsync(changes.Select(c => c.Label).ToArray(), ct).ConfigureAwait(false);
            journalId = plan.Snapshot.SessionId;
            for (int i = 0; i < changes.Count; i++)
            {
                ct.ThrowIfCancellationRequested();
                var result = await plan.ExecuteAsync(i, changes[i].Apply, ct).ConfigureAwait(false);
                steps[i] = new(changes[i].Label, result.Applied ? StepState.Applied : StepState.Unconfirmed,
                    result.Applied && result.ReceiptSaved && changes[i].Kind != StateTargetKind.JournalEntry, result.ReceiptSaved, result.Detail);
                if (!result.Applied || !result.ReceiptSaved) { problem = $"{changes[i].Label}: {result.Detail}"; break; }
            }
        }
        catch (OperationCanceledException) { problem = "Операция отменена."; }
        catch (Exception ex) { problem = ex.Message; }

        if (journalId is null && preparingId is { } candidate)
        {
            // Снимки могли попасть в журнал, но не пройти проверку квоты. Не выдавать ID несуществующей записи.
            try { journalId = (await _vaultService.GetTransactionAsync(candidate, CancellationToken.None).ConfigureAwait(false))?.SessionId; }
            catch (Exception ex) { problem += $" Не удалось прочесть журнал: {ex.Message}"; }
        }

        var done = steps.Where(s => s.State == StepState.Applied).ToList();
        var undo = steps.Count(s => s.CanRollback);
        var cancelled = ct.IsCancellationRequested && problem is not null;
        var status = cancelled ? "Остановлено" : problem is null ? "Выполнено" : done.Count > 0 ? "Выполнено частично" : "Операция не завершена";
        var summary = steps.Count > 0 ? $"{status}: {done.Count} из {steps.Count}." : "Изменения не начинались.";
        if (done.Count > 0) summary += " " + string.Join("; ", done.Take(4).Select(s => s.Label + (!s.ReceiptSaved ? " (итог не записан)" : s.CanRollback ? "" : " (без отката)"))) + ".";
        if (problem is not null)
        {
            summary += " " + problem;
            var notStarted = steps.Where(s => s.State == StepState.Planned).ToList();
            if (notStarted.Count > 0) summary += $" Не начато ({notStarted.Count}): {notStarted[0].Label}{(notStarted.Count > 1 ? " и др." : "")}.";
        }
        summary += undo > 0 ? $" Для отката сохранено шагов: {undo}." : " Нет подтверждённых шагов для автоматического отката.";
        return new(problem is null, undo > 0 ? journalId : null, done.Count, summary)
        { Steps = steps, JournalSessionId = journalId, WasCancelled = cancelled };
    }
}
