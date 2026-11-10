using UltimateWindows.Core.Enums;

namespace UltimateWindows.Modules.Security.Models;

public enum ThreatDetectionVector
{
    ProcessMasquerading = 0,
    DropOnInspectEvasion = 1,
    StratumMiningPoolConnection = 2,
    SuspiciousMinerCommandLine = 3,
    IfeoDebuggerHijack = 4,
    WinlogonShellHijack = 5,
    HiddenScheduledTask = 6,
    WmiPermanentSubscription = 7
}

public enum OsSabotageKind
{
    TaskManagerDisabledByPolicy = 0,
    RegistryEditorDisabledByPolicy = 1,
    CommandPromptDisabledByPolicy = 2,
    SystemToolIfeoBlocked = 3,
    SecurityDomainsBlockedInHosts = 4
}

/// <summary>
/// Снимок процесса для поведенческого и сигнатурного анализа на скрытые майнеры.
/// </summary>
public sealed record ProcessTelemetrySample(
    int ProcessId,
    string ProcessName,
    string ExecutablePath,
    string CommandLine,
    double BaselineCpuPercent,
    double DuringInspectCpuPercent,
    bool ExitedDuringInspect,
    bool IsAuthenticodeSigned);

/// <summary>
/// Активное исходящее TCP-соединение с привязкой к процессу (из GetExtendedTcpTable).
/// </summary>
public sealed record ProcessTcpConnectionInfo(
    int ProcessId,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort);

/// <summary>
/// Подозрительная точка автозакрепления в системе (IFEO, Winlogon, скрытая задача без SD, WMI).
/// </summary>
public sealed record PersistenceAnomalyRecord(
    ThreatDetectionVector Vector,
    string RegistryOrTaskPath,
    string EntryName,
    string PayloadCommandOrPath,
    string? ReferencedExecutablePath,
    bool IsMissingSecurityDescriptorSd,
    string PreviousValueSerialized);

/// <summary>
/// Обнаруженная угроза скрытого майнера, подмены системного процесса или вредоносного закрепления.
/// </summary>
public sealed record SecurityThreatFinding(
    string FindingId,
    ThreatDetectionVector Vector,
    RiskLevel Severity,
    int ConfidenceScorePercent,
    int? SuspectProcessId,
    string? SuspectFilePath,
    string? PersistenceKeyPath,
    string SimpleTitle,
    string SimpleExplanation,
    string ExpertTechnicalEvidence,
    bool CanQuarantineFileSafely)
{
    public string ConfidenceBadge => $"Точность: {ConfidenceScorePercent}%";
}

/// <summary>
/// Заблокированная майнером системная функция Windows (Диспетчер задач, Реестр, hosts, IFEO).
/// </summary>
public sealed record OsSabotageFinding(
    OsSabotageKind Kind,
    string TargetDisplayPath,
    string Hive,
    string SubKeyPath,
    string ValueName,
    string CurrentMaliciousValue,
    string SimpleTitle,
    string SimpleExplanation);

/// <summary>
/// Сводный отчет проверки безопасности и поиска скрытых майнеров (Фаза 5).
/// </summary>
public sealed record SecurityScanReport(
    DateTimeOffset ScannedAtUtc,
    int SecurityHealthScore,
    bool UsedDropOnInspectProbe,
    string HeadlineSummary,
    IReadOnlyList<SecurityThreatFinding> Threats,
    IReadOnlyList<OsSabotageFinding> SabotageLocks);

/// <summary>
/// Результат обезвреживания в карантин или реабилитации заблокированных настроек ОС.
/// </summary>
public sealed record SecurityRemediationResult(
    bool Succeeded,
    string UserFriendlyMessage,
    string TechnicalDetails = "",
    Guid? RollbackSessionId = null);
