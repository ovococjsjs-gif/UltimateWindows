using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Security.Models;

namespace UltimateWindows.Modules.Security.Services;

/// <summary>
/// Абстракция низкоуровневого платформенного моста для модуля «Анти-майнер и Защита 2.0».
/// </summary>
public interface ISecurityPlatformBridge
{
    bool IsRunningAsAdministrator();

    string GetWindowsDirectory();

    Task<IReadOnlyList<ProcessTelemetrySample>> CaptureDropOnInspectSamplesAsync(
        bool runDecoyTrigger,
        CancellationToken ct = default);

    Task<IReadOnlyList<ProcessTcpConnectionInfo>> GetActiveTcpConnectionsAsync(CancellationToken ct = default);

    Task<IReadOnlyList<PersistenceAnomalyRecord>> ScanPersistenceAnomaliesAsync(CancellationToken ct = default);

    Task<IReadOnlyList<OsSabotageFinding>> ScanOsSabotageLocksAsync(CancellationToken ct = default);

    Task<IReadOnlyList<DefenderExclusionFinding>> ScanDefenderExclusionsAsync(CancellationToken ct = default);

    Task<bool> RemoveDefenderExclusionAsync(DefenderExclusionFinding exclusion, CancellationToken ct = default);

    Task<(bool Succeeded, string OutputMessage)> StartDefenderScanAsync(
        DefenderScanMode mode,
        string? customTargetPath = null,
        CancellationToken ct = default);

    Task<IReadOnlyList<FirewallRuleAnomaly>> ScanFirewallRuleAnomaliesAsync(CancellationToken ct = default);

    Task<bool> RemoveFirewallRuleAsync(FirewallRuleAnomaly rule, CancellationToken ct = default);

    Task<IReadOnlyList<SuspiciousUserAccountFinding>> ScanSuspiciousUserAccountsAsync(CancellationToken ct = default);

    Task<IReadOnlyList<DirectoryThreatArtifact>> ScanStagingDirectoriesAsync(CancellationToken ct = default);

    Task<IReadOnlyList<string>> ScanDnsCacheMiningPoolDomainsAsync(CancellationToken ct = default);

    Task<bool> TerminateSuspectProcessAsync(int processId, CancellationToken ct = default);

    Task<(bool Succeeded, StateTargetKind? RollbackKind, string? RollbackTarget, string? PreviousStateJson)> RemovePersistenceEntryAsync(
        PersistenceAnomalyRecord record,
        CancellationToken ct = default);

    Task<(bool Succeeded, string? OriginalHostsBackupContent)> RepairSabotageLockAsync(
        OsSabotageFinding lockFinding,
        CancellationToken ct = default);
}

/// <summary>
/// Безопасная кроссплатформенная реализация по умолчанию для модульных тестов и сред без Win32.
/// </summary>
public class DefaultSecurityPlatformBridge : ISecurityPlatformBridge
{
    public virtual bool IsRunningAsAdministrator() => false;

    public virtual string GetWindowsDirectory()
    {
        var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        return string.IsNullOrWhiteSpace(win) ? @"C:\Windows" : win;
    }

    public virtual Task<IReadOnlyList<ProcessTelemetrySample>> CaptureDropOnInspectSamplesAsync(
        bool runDecoyTrigger,
        CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<ProcessTelemetrySample>>([]);

    public virtual Task<IReadOnlyList<ProcessTcpConnectionInfo>> GetActiveTcpConnectionsAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<ProcessTcpConnectionInfo>>([]);

    public virtual Task<IReadOnlyList<PersistenceAnomalyRecord>> ScanPersistenceAnomaliesAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<PersistenceAnomalyRecord>>([]);

    public virtual Task<IReadOnlyList<OsSabotageFinding>> ScanOsSabotageLocksAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<OsSabotageFinding>>([]);

    public virtual Task<IReadOnlyList<DefenderExclusionFinding>> ScanDefenderExclusionsAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<DefenderExclusionFinding>>([]);

    public virtual Task<bool> RemoveDefenderExclusionAsync(DefenderExclusionFinding exclusion, CancellationToken ct = default) =>
        Task.FromResult(false);

    public virtual Task<(bool Succeeded, string OutputMessage)> StartDefenderScanAsync(
        DefenderScanMode mode,
        string? customTargetPath = null,
        CancellationToken ct = default) =>
        Task.FromResult((false, "Запуск проверки Microsoft Defender поддерживается только в среде Windows 10/11."));

    public virtual Task<IReadOnlyList<FirewallRuleAnomaly>> ScanFirewallRuleAnomaliesAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<FirewallRuleAnomaly>>([]);

    public virtual Task<bool> RemoveFirewallRuleAsync(FirewallRuleAnomaly rule, CancellationToken ct = default) =>
        Task.FromResult(false);

    public virtual Task<IReadOnlyList<SuspiciousUserAccountFinding>> ScanSuspiciousUserAccountsAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<SuspiciousUserAccountFinding>>([]);

    public virtual Task<IReadOnlyList<DirectoryThreatArtifact>> ScanStagingDirectoriesAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<DirectoryThreatArtifact>>([]);

    public virtual Task<IReadOnlyList<string>> ScanDnsCacheMiningPoolDomainsAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<string>>([]);

    public virtual Task<bool> TerminateSuspectProcessAsync(int processId, CancellationToken ct = default) =>
        Task.FromResult(false);

    public virtual Task<(bool Succeeded, StateTargetKind? RollbackKind, string? RollbackTarget, string? PreviousStateJson)> RemovePersistenceEntryAsync(
        PersistenceAnomalyRecord record,
        CancellationToken ct = default) =>
        Task.FromResult<(bool, StateTargetKind?, string?, string?)>((false, null, null, null));

    public virtual Task<(bool Succeeded, string? OriginalHostsBackupContent)> RepairSabotageLockAsync(
        OsSabotageFinding lockFinding,
        CancellationToken ct = default) =>
        Task.FromResult((false, (string?)null));
}
