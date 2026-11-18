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
    public bool IsJournalOnly => TargetKind == StateTargetKind.RegistryValueSnapshot ||
        (TargetKind == StateTargetKind.SystemSetting &&
         (TargetPath.StartsWith("OfficialRuntime:", StringComparison.OrdinalIgnoreCase) ||
          TargetPath.StartsWith("RepairPlaybook:", StringComparison.OrdinalIgnoreCase) ||
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
    public bool HasExpiredFile => Deltas.Any(d => d.TargetKind == StateTargetKind.QuarantinedFile && d.BlobSha256 is null);
    public string? RollbackUnavailableReason => IsReverted ? "Уже отменено" : IsJournalOnly ? "Только журнал" :
        HasExpiredFile ? "Копия удалена" : null;

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
