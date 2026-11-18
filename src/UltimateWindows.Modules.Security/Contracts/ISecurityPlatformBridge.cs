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

    PreparedSecurityChange PrepareDefenderExclusion(DefenderExclusionFinding exclusion);

    Task<(bool Succeeded, string OutputMessage)> StartDefenderScanAsync(
        DefenderScanMode mode,
        string? customTargetPath = null,
        CancellationToken ct = default);

    Task<IReadOnlyList<FirewallRuleAnomaly>> ScanFirewallRuleAnomaliesAsync(CancellationToken ct = default);

    PreparedSecurityChange PrepareFirewallRule(FirewallRuleAnomaly rule);

    Task<IReadOnlyList<SuspiciousUserAccountFinding>> ScanSuspiciousUserAccountsAsync(CancellationToken ct = default);

    Task<IReadOnlyList<DirectoryThreatArtifact>> ScanStagingDirectoriesAsync(CancellationToken ct = default);

    Task<IReadOnlyList<string>> ScanDnsCacheMiningPoolDomainsAsync(CancellationToken ct = default);

    Task<bool> TerminateSuspectProcessAsync(int processId, string? reviewedPath, CancellationToken ct = default);

    PreparedSecurityChange PreparePersistence(PersistenceAnomalyRecord record);

    PreparedSecurityChange PrepareSabotageRepair(OsSabotageFinding finding);
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

    public virtual PreparedSecurityChange PrepareDefenderExclusion(DefenderExclusionFinding exclusion) =>
        throw new NotSupportedException("Изменение исключений недоступно.");

    public virtual Task<(bool Succeeded, string OutputMessage)> StartDefenderScanAsync(
        DefenderScanMode mode,
        string? customTargetPath = null,
        CancellationToken ct = default) =>
        Task.FromResult((false, "Запуск проверки Microsoft Defender поддерживается только в среде Windows 10/11."));

    public virtual Task<IReadOnlyList<FirewallRuleAnomaly>> ScanFirewallRuleAnomaliesAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<FirewallRuleAnomaly>>([]);

    public virtual PreparedSecurityChange PrepareFirewallRule(FirewallRuleAnomaly rule) =>
        throw new NotSupportedException("Изменение правил недоступно.");

    public virtual Task<IReadOnlyList<SuspiciousUserAccountFinding>> ScanSuspiciousUserAccountsAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<SuspiciousUserAccountFinding>>([]);

    public virtual Task<IReadOnlyList<DirectoryThreatArtifact>> ScanStagingDirectoriesAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<DirectoryThreatArtifact>>([]);

    public virtual Task<IReadOnlyList<string>> ScanDnsCacheMiningPoolDomainsAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<string>>([]);

    public virtual Task<bool> TerminateSuspectProcessAsync(int processId, string? reviewedPath, CancellationToken ct = default) =>
        Task.FromResult(false);

    public virtual PreparedSecurityChange PreparePersistence(PersistenceAnomalyRecord record) =>
        throw new NotSupportedException("Нет проверенного способа снять эту точку закрепления.");

    public virtual PreparedSecurityChange PrepareSabotageRepair(OsSabotageFinding finding) =>
        throw new NotSupportedException("Нет проверенного способа исправить эту настройку.");
}
