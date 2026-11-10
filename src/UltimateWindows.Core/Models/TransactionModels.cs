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
    long OriginalSizeBytes);

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
