using UltimateWindows.Core.Enums;

namespace UltimateWindows.Core.Models;

/// <summary>
/// Дельта одного конкретного изменения системы (реестр, служба, задача, файл в карантине или ссылка DriverStore).
/// </summary>
public sealed record StateDeltaRecord(
    Guid DeltaId,
    Guid SessionId,
    int SequenceOrder,
    StateTargetKind TargetKind,
    string TargetPath,
    string? PreviousStateJson,
    string? NewStateJson,
    string? BlobSha256,
    long OriginalSizeBytes)
{
    public StepReceipt? Step { get; init; }
    public bool IsJournalOnly => Step is { State: not StepState.Applied } ||
        TargetKind is StateTargetKind.JournalEntry or StateTargetKind.RegistryValueSnapshot ||
        (TargetKind == StateTargetKind.SystemSetting &&
         (TargetPath.StartsWith("OfficialRuntime:", StringComparison.OrdinalIgnoreCase) ||
          TargetPath.StartsWith("RepairPlaybook:", StringComparison.OrdinalIgnoreCase) ||
          TargetPath.StartsWith("DefenderExclusion:", StringComparison.OrdinalIgnoreCase) ||
          TargetPath.StartsWith("DeletedRegistryKey:", StringComparison.OrdinalIgnoreCase) ||
          TargetPath.StartsWith("WmiSubscription:", StringComparison.OrdinalIgnoreCase) ||
          TargetPath.StartsWith("BitsJob:", StringComparison.OrdinalIgnoreCase) ||
          TargetPath.StartsWith("RepairBatch:", StringComparison.OrdinalIgnoreCase)));

    public bool CopyExpired => !IsJournalOnly && TargetKind == StateTargetKind.QuarantinedFile && BlobSha256 is null;
    public bool HasInverse => !IsJournalOnly && !CopyExpired;
}

/// <summary>
/// Завершенная транзакция изменений в «Машине времени» UltimateWindows.
/// Содержит как дружелюбное описание для обычного пользователя, так и технические детали для эксперта.
/// </summary>
public sealed record TransactionRecord(
    Guid SessionId,
    SystemDomain Domain,
    string FriendlyTitle,
    string FriendlySummary,
    string TechnicalDetails,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? BlobExpiresAtUtc,
    bool IsPinned,
    bool IsReverted,
    DateTimeOffset? RevertedAtUtc,
    long TotalStoredBytes,
    IReadOnlyList<StateDeltaRecord> Deltas)
{
    public bool IsJournalOnly => Deltas.All(d => d.IsJournalOnly);
    public bool HasExpiredFile => Deltas.Any(d => d.CopyExpired);
    public IEnumerable<StateDeltaRecord> RestorableDeltas => Deltas.Where(d => d.HasInverse);
    public string? RollbackUnavailableReason => IsReverted ? "Уже отменено" : IsJournalOnly ? "Только журнал" :
        HasExpiredFile && (!Deltas.Any(d => d.Step is not null) || !RestorableDeltas.Any()) ? "Копия удалена" : null;

    // Описание самой операции не меняется при откате: у частичного результата откатывается только доступная часть.
    public string? StepOutcomeText
    {
        get
        {
            var total = Deltas.Count(d => d.Step is not null);
            if (total == 0) return null; // прежний формат без квитанций
            var applied = Deltas.Count(d => d.Step?.State == StepState.Applied);
            if (applied == total) return $"Выполнено · {applied}/{total}";
            if (applied > 0) return $"Частично · {applied}/{total}";
            return Deltas.All(d => d.Step?.State == StepState.Planned) ? "Не начато" : "Итог не подтверждён";
        }
    }

    public string StepSummary => string.Join(Environment.NewLine, Deltas.Where(d => d.Step is not null).Select(d =>
    {
        var step = d.Step!;
        var undo = step.State != StepState.Applied ? "" : d.IsJournalOnly ? " · без отката" :
            d.CopyExpired ? " · копия удалена, без отката" : IsReverted ? " · откат завершён" : " · доступен откат";
        var target = step.Label.Contains(d.TargetPath, StringComparison.OrdinalIgnoreCase) ? "" : $" — {d.TargetPath}";
        return $"{step.Label}: {step.StatusText}{undo}{target}";
    }));

    public string FormattedStoredSize => ByteFormatter.Format(TotalStoredBytes);

    public string CreatedDisplayLocal =>
        CreatedAtUtc.ToLocalTime().ToString("dd.MM.yyyy HH:mm");
}

/// <summary>
/// Карточка состояния подсистемы для дружелюбного главного экрана и экспертного режима.
/// </summary>
public sealed record HealthSummaryCard(
    SystemDomain Domain,
    string IconGlyph,
    string SimpleTitle,
    string SimpleDescription,
    string ExpertTechnicalNotes,
    string StatusBadge,
    RiskLevel RiskLevel,
    int ScorePoints,
    string PrimaryActionText);
