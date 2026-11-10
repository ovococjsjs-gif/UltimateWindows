using System.Text.Json;
using UltimateWindows.Core.Contracts;
using UltimateWindows.Core.Enums;
using UltimateWindows.Core.Guards;
using UltimateWindows.Modules.Security.Analyzers;
using UltimateWindows.Modules.Security.Contracts;
using UltimateWindows.Modules.Security.Models;

namespace UltimateWindows.Modules.Security.Services;

/// <summary>
/// Базовый безопасный платформенный мост Фазы 5 (для изолированных модульных тестов и не-Windows окружений).
/// </summary>
public class DefaultSecurityPlatformBridge : ISecurityPlatformBridge
{
    public virtual bool IsRunningAsAdministrator() => false;

    public virtual string GetWindowsDirectory() =>
        Environment.GetFolderPath(Environment.SpecialFolder.Windows) is { Length: > 0 } w ? w : @"C:\Windows";

    public virtual Task<IReadOnlyList<ProcessTelemetrySample>> CaptureDropOnInspectSamplesAsync(
        bool runDecoyTrigger,
        CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<ProcessTelemetrySample>>(Array.Empty<ProcessTelemetrySample>());

    public virtual Task<IReadOnlyList<ProcessTcpConnectionInfo>> GetActiveTcpConnectionsAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<ProcessTcpConnectionInfo>>(Array.Empty<ProcessTcpConnectionInfo>());

    public virtual Task<IReadOnlyList<PersistenceAnomalyRecord>> ScanPersistenceAnomaliesAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<PersistenceAnomalyRecord>>(Array.Empty<PersistenceAnomalyRecord>());

    public virtual Task<IReadOnlyList<OsSabotageFinding>> ScanOsSabotageLocksAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<OsSabotageFinding>>(Array.Empty<OsSabotageFinding>());

    public virtual Task<bool> TerminateSuspectProcessAsync(int processId, CancellationToken ct = default) =>
        Task.FromResult(false);

    public virtual Task<(bool Succeeded, string? OriginalHostsBackupContent)> RepairSabotageLockAsync(
        OsSabotageFinding lockFinding,
        CancellationToken ct = default) =>
        Task.FromResult((false, (string?)null));

    public virtual string GetHostsFilePath() =>
        Path.Combine(GetWindowsDirectory(), "System32", "drivers", "etc", "hosts");
}

/// <summary>
/// Главный сервис Фазы 5: поиск скрытых майнеров (включая прячущиеся от Диспетчера задач процессы),
/// безопасная изоляция угроз в зашифрованный карантин Машины времени (.uwq) и разблокировка заблокированных майнером компонентов ОС.
/// </summary>
public sealed class AntiMinerSecurityService
{
    private readonly IVaultService _vaultService;
    private readonly ISecurityPlatformBridge _platformBridge;
    private readonly MinerThreatHeuristicEngine _heuristicEngine;

    public AntiMinerSecurityService(
        IVaultService vaultService,
        ISecurityPlatformBridge? platformBridge = null,
        MinerThreatHeuristicEngine? heuristicEngine = null)
    {
        _vaultService = vaultService ?? throw new ArgumentNullException(nameof(vaultService));
        _platformBridge = platformBridge ?? new DefaultSecurityPlatformBridge();
        _heuristicEngine = heuristicEngine ?? new MinerThreatHeuristicEngine();
    }

    /// <summary>
    /// Проводит комплексную многовекторную проверку ПК на скрытые майнеры, подмену системных процессов и последствия саботажа.
    /// </summary>
    public async Task<SecurityScanReport> RunFullSecurityScanAsync(
        bool enableDropOnInspectProbe = true,
        CancellationToken ct = default)
    {
        var processesTask = _platformBridge.CaptureDropOnInspectSamplesAsync(enableDropOnInspectProbe, ct);
        var tcpTask = _platformBridge.GetActiveTcpConnectionsAsync(ct);
        var persistenceTask = _platformBridge.ScanPersistenceAnomaliesAsync(ct);
        var sabotageTask = _platformBridge.ScanOsSabotageLocksAsync(ct);

        await Task.WhenAll(processesTask, tcpTask, persistenceTask, sabotageTask).ConfigureAwait(false);

        var threats = _heuristicEngine.AnalyzeTelemetry(
            processesTask.Result,
            tcpTask.Result,
            persistenceTask.Result,
            _platformBridge.GetWindowsDirectory());

        var sabotageLocks = sabotageTask.Result;

        var penalty = (threats.Count * 28) + (sabotageLocks.Count * 12);
        var score = Math.Clamp(100 - penalty, 5, 100);

        string headline;
        if (threats.Count == 0 && sabotageLocks.Count == 0)
        {
            headline = "✅ Скрытых майнеров, маскирующихся процессов и блокировок системы не обнаружено!";
        }
        else
        {
            headline = $"🚨 Обнаружено угроз майнеров/закрепления: {threats.Count} • Блокировок саботажа ОС: {sabotageLocks.Count}. Доступно лечение.";
        }

        return new SecurityScanReport(
            ScannedAtUtc: DateTimeOffset.UtcNow,
            SecurityHealthScore: score,
            UsedDropOnInspectProbe: enableDropOnInspectProbe,
            HeadlineSummary: headline,
            Threats: threats,
            SabotageLocks: sabotageLocks);
    }

    /// <summary>
    /// Останавливает обнаруженный процесс майнера и изолирует его исполняемый файл в сжатый шифрованный карантин (.uwq)
    /// с возможностью 100% возврата одной кнопкой из Машины времени.
    /// </summary>
    public async Task<SecurityRemediationResult> QuarantineThreatAsync(
        SecurityThreatFinding threat,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(threat);

        if (string.IsNullOrWhiteSpace(threat.SuspectFilePath) || !File.Exists(threat.SuspectFilePath))
        {
            return new SecurityRemediationResult(false, "Подозрительный файл уже удален или недоступен на диске.");
        }

        var fullPath = Path.GetFullPath(threat.SuspectFilePath);

        // 1. Жесткая защита настоящей системной папки C:\Windows и баз паролей браузеров!
        var normWin = _platformBridge.GetWindowsDirectory().Replace('/', '\\').TrimEnd('\\');
        if (MinerThreatHeuristicEngine.IsInsideGenuineWindowsSystemFolder(fullPath.Replace('/', '\\'), normWin))
        {
            return new SecurityRemediationResult(
                false,
                "Защитный барьер: карантин никогда не удаляет файлы внутри настоящей системной папки Windows.");
        }

        BrowserVaultGuard.ThrowIfProtected(fullPath);

        // 2. Останавливаем активный процесс майнера перед переносом файла в карантин
        if (threat.SuspectProcessId is int pid and > 4)
        {
            _ = await _platformBridge.TerminateSuspectProcessAsync(pid, ct).ConfigureAwait(false);
        }

        await using var tx = _vaultService.BeginTransaction(
            SystemDomain.AntiMiner,
            friendlyTitle: $"Карантин скрытой угрозы: {Path.GetFileName(fullPath)}",
            friendlySummary: threat.SimpleTitle,
            technicalDetails: threat.ExpertTechnicalEvidence);

        var sha256 = await tx.QuarantineFileAsync(fullPath, ct).ConfigureAwait(false);
        var committed = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);

        return new SecurityRemediationResult(
            Succeeded: true,
            UserFriendlyMessage: $"🛡️ Объект «{Path.GetFileName(fullPath)}» остановлен и изолирован в зашифрованный карантин (.uwq)! При необходимости его можно вернуть из Машины времени.",
            TechnicalDetails: $"SHA-256: {sha256}",
            RollbackSessionId: committed.SessionId);
    }

    /// <summary>
    /// Снимает все обнаруженные блокировки после атаки майнера (разблокирует Диспетчер задач, Редактор реестра,
    /// командную строку, удаляет перехваты IFEO и очищает блокировки антивирусов в файле hosts) с записью отката.
    /// </summary>
    public async Task<SecurityRemediationResult> HealAllSabotageLocksAsync(
        IReadOnlyList<OsSabotageFinding> sabotageLocks,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(sabotageLocks);
        if (sabotageLocks.Count == 0)
        {
            return new SecurityRemediationResult(true, "Активных блокировок системы не обнаружено.");
        }

        await using var tx = _vaultService.BeginTransaction(
            SystemDomain.AntiMiner,
            friendlyTitle: $"Реабилитация системы после майнера ({sabotageLocks.Count} блокировок снято)",
            friendlySummary: "Восстановлен доступ к Диспетчеру задач, Реестру, обновлениям Windows и сайтам антивирусов.",
            technicalDetails: string.Join("; ", sabotageLocks.Select(s => s.TargetDisplayPath)));

        var healed = 0;
        foreach (var item in sabotageLocks)
        {
            ct.ThrowIfCancellationRequested();

            if (item.Kind != OsSabotageKind.SecurityDomainsBlockedInHosts)
            {
                var snapJson = JsonSerializer.Serialize(new
                {
                    Hive = item.Hive,
                    SubKey = item.SubKeyPath,
                    ValueName = item.ValueName,
                    ExistedBefore = true,
                    ValueKind = item.Kind == OsSabotageKind.SystemToolIfeoBlocked ? 1 : 4,
                    SerializedData = item.CurrentMaliciousValue
                });

                tx.RecordStateDelta(StateTargetKind.RegistryValue, item.TargetDisplayPath, snapJson, null);
            }

            var (ok, originalHosts) = await _platformBridge.RepairSabotageLockAsync(item, ct).ConfigureAwait(false);
            if (ok)
            {
                if (originalHosts is not null)
                {
                    tx.RecordStateDelta(
                        StateTargetKind.SystemSetting,
                        "HostsSabotageCleanup",
                        previousStateJson: JsonSerializer.Serialize(new { Path = _platformBridge.GetHostsFilePath(), Content = originalHosts }),
                        newStateJson: null);
                }

                healed++;
            }
        }

        if (healed == 0)
        {
            return new SecurityRemediationResult(
                false,
                "Для снятия системных блокировок политик и очистки hosts требуются права Администратора.");
        }

        var committed = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);
        return new SecurityRemediationResult(
            Succeeded: true,
            UserFriendlyMessage: $"✨ Реабилитация выполнена: снято блокировок системы — {healed} из {sabotageLocks.Count}!",
            RollbackSessionId: committed.SessionId);
    }
}
