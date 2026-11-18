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
          TargetPath.StartsWith("DeletedRegistryKey:", StringComparison.OrdinalIgnoreCase) ||
          TargetPath.StartsWith("WmiSubscription:", StringComparison.OrdinalIgnoreCase) ||
          TargetPath.StartsWith("BitsJob:", StringComparison.OrdinalIgnoreCase) ||
          TargetPath.StartsWith("RepairBatch:", StringComparison.OrdinalIgnoreCase)));
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
    public bool HasExpiredFile => Deltas.Any(d => !d.IsJournalOnly && d.TargetKind == StateTargetKind.QuarantinedFile && d.BlobSha256 is null);
    public IEnumerable<StateDeltaRecord> RestorableDeltas => Deltas.Where(d => !d.IsJournalOnly &&
        (d.TargetKind != StateTargetKind.QuarantinedFile || d.BlobSha256 is not null));
    public string StepSummary => string.Join("; ", Deltas.Where(d => d.Step is not null).Select(d =>
        $"{d.Step!.Label}: {d.Step.StatusText}{(d.Step.State == StepState.Applied && d.IsJournalOnly ? " (без отката)" : "")}"));
    public string? RollbackUnavailableReason => IsReverted ? "Уже отменено" : IsJournalOnly ? "Только журнал" :
        HasExpiredFile && (!Deltas.Any(d => d.Step is not null) || !RestorableDeltas.Any()) ? "Копия удалена" : null;

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
