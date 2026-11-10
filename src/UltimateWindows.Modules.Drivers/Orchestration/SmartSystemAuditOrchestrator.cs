using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Cleaner.Services;
using UltimateWindows.Modules.Drivers.Models;
using UltimateWindows.Modules.Drivers.Services;
using UltimateWindows.Modules.Hardware.Services;
using UltimateWindows.Modules.Optimizer.Services;
using UltimateWindows.Modules.Repair.Services;
using UltimateWindows.Modules.Security.Services;

namespace UltimateWindows.Modules.Drivers.Orchestration;

/// <summary>
/// Приоритетная карточка рекомендации по итогам «Комплексного Умного Аудита в 1 клик».
/// </summary>
public sealed record SmartAuditActionItem(
    SystemDomain TargetDomain,
    RiskLevel Severity,
    string SimpleTitle,
    string SimpleRecommendation,
    string DomainBadge);

/// <summary>
/// Итоговый сводный паспорт здоровья всего ПК (Фаза 6 v1.0 — 1-Click Smart Audit).
/// </summary>
public sealed record SmartSystemAuditSummary(
    DateTimeOffset CompletedAtUtc,
    int CompositeHealthScore,
    int SecurityScore,
    int HardwareScore,
    int DriversScore,
    int StabilityRepairScore,
    int CleanerScore,
    int OptimizerScore,
    long SafeReclaimableBytes,
    string FormattedReclaimableSpace,
    string ExecutiveHeadline,
    IReadOnlyList<SmartAuditActionItem> TopActionItems);

/// <summary>
/// Флагманский оркестратор Фазы 6 (v1.0): запускает параллельный безопасный аудит по всем 6 подсистемам UltimateWindows
/// (Анти-майнер, Железо, Драйверы, Стабильность/BSOD, Бережная очистка и Оптимизатор) и рассчитывает взвешенный Индекс здоровья ПК (0–100).
/// </summary>
public sealed class SmartSystemAuditOrchestrator
{
    private readonly HardwareStudioService _hardwareService;
    private readonly OfficialDriverService _driverService;
    private readonly VaultSafeCleanerService _cleanerService;
    private readonly SystemRepairService _repairService;
    private readonly SmartOptimizerService _optimizerService;
    private readonly AntiMinerSecurityService _securityService;

    public SmartSystemAuditOrchestrator(
        HardwareStudioService hardwareService,
        OfficialDriverService driverService,
        VaultSafeCleanerService cleanerService,
        SystemRepairService repairService,
        SmartOptimizerService optimizerService,
        AntiMinerSecurityService securityService)
    {
        _hardwareService = hardwareService ?? throw new ArgumentNullException(nameof(hardwareService));
        _driverService = driverService ?? throw new ArgumentNullException(nameof(driverService));
        _cleanerService = cleanerService ?? throw new ArgumentNullException(nameof(cleanerService));
        _repairService = repairService ?? throw new ArgumentNullException(nameof(repairService));
        _optimizerService = optimizerService ?? throw new ArgumentNullException(nameof(optimizerService));
        _securityService = securityService ?? throw new ArgumentNullException(nameof(securityService));
    }

    public async Task<SmartSystemAuditSummary> RunOneClickAuditAsync(
        bool includeStealthMinerDecoyProbe = false,
        bool queryOnlineDriverCatalog = false,
        CancellationToken ct = default)
    {
        var hwTask = _hardwareService.CaptureAndAnalyzeAsync(ct);
        var drvTask = _driverService.AuditDevicesAndDriversAsync(queryOnlineDriverCatalog, ct);
        var cleanTask = _cleanerService.ScanSafeCleanupAsync(includeRegistryHygiene: true, ct);
        var bsodTask = _repairService.ScanCrashAndBsodHistoryAsync(ct);
        var tweakTask = _optimizerService.EvaluateAllTweaksAsync(ct);
        var startupTask = _optimizerService.GetStartupEntriesAsync(ct);
        var secTask = _securityService.RunFullSecurityScanAsync(includeStealthMinerDecoyProbe, ct);

        await Task.WhenAll(hwTask, drvTask, cleanTask, bsodTask, tweakTask, startupTask, secTask).ConfigureAwait(false);

        var (_, hwAudit) = hwTask.Result;
        var drvReport = drvTask.Result;
        var cleanReport = cleanTask.Result;
        var bsodReport = bsodTask.Result;
        var tweaks = tweakTask.Result;
        var startups = startupTask.Result;
        var secReport = secTask.Result;

        var actions = new List<SmartAuditActionItem>();

        // 1. Оценка безопасности и майнеров (вес 30%)
        var securityScore = secReport.SecurityHealthScore;
        foreach (var t in secReport.Threats.Take(3))
        {
            actions.Add(new SmartAuditActionItem(
                SystemDomain.AntiMiner,
                t.Severity,
                t.SimpleTitle,
                t.SimpleExplanation,
                "🛡️ Анти-майнер"));
        }

        foreach (var s in secReport.SabotageLocks.Take(2))
        {
            actions.Add(new SmartAuditActionItem(
                SystemDomain.AntiMiner,
                RiskLevel.Attention,
                s.SimpleTitle,
                s.SimpleExplanation,
                "🚑 Реабилитация ОС"));
        }

        // 2. Оценка железа и драйверов (суммарный вес 25%: 13% железо + 12% драйверы)
        var hardwareScore = hwAudit.HardwareHealthScore;
        var driversScore = drvReport.DriverHealthScore;

        foreach (var hf in hwAudit.Findings.Take(2))
        {
            actions.Add(new SmartAuditActionItem(
                SystemDomain.HardwareAndDrivers,
                hf.Severity,
                hf.SimpleTitle,
                hf.SimpleRecommendation,
                "🖥️ Железо"));
        }

        foreach (var df in drvReport.Findings.Where(f => f.Device.HasProblem || f.Device.IsBasicDisplayFallback).Take(2))
        {
            actions.Add(new SmartAuditActionItem(
                SystemDomain.HardwareAndDrivers,
                df.Severity,
                df.SimpleTitle,
                df.SimpleExplanation,
                "🔌 Драйверы WHQL"));
        }

        // 3. Оценка стабильности ОС и BSOD (вес 20%)
        var stabilityScore = bsodReport.StabilityScore;
        if (bsodReport.Minidumps.Count > 0 || bsodReport.CriticalEvents.Count > 0)
        {
            actions.Add(new SmartAuditActionItem(
                SystemDomain.DllAndRepair,
                RiskLevel.Attention,
                $"Зафиксированы следы сбоев или синих экранов ({bsodReport.Minidumps.Count} дампов)",
                bsodReport.PrimaryPlainVerdict,
                "🧩 Стабильность и BSOD"));
        }

        // 4. Оценка чистоты диска без потери паролей (вес 15%)
        var reclaimGb = cleanReport.TotalReclaimableBytes / (1024.0 * 1024.0 * 1024.0);
        var cleanerScore = reclaimGb switch
        {
            >= 10.0 => 68,
            >= 3.0 => 82,
            >= 0.5 => 92,
            _ => 100
        };

        if (cleanReport.TotalReclaimableBytes >= 128L * 1024 * 1024)
        {
            actions.Add(new SmartAuditActionItem(
                SystemDomain.SmartCleaner,
                RiskLevel.Safe,
                $"Можно безопасно освободить {cleanReport.FormattedTotalBytes} мусора и кэша",
                "Пароли, открытые вкладки и автозаполнение форм надежно защищены фильтром BrowserVaultGuard.",
                "🧹 Бережная очистка"));
        }

        // 5. Оценка автозагрузки и фоновой тишины (вес 10%)
        var activeUnsignedStartups = startups.Count(s => s.IsEnabled && !s.IsAuthenticodeSigned);
        var unappliedSafeTweaks = tweaks.Count(t => !t.IsCurrentlyApplied && t.Rule.Risk == RiskLevel.Safe);
        var optimizerPenalty = (activeUnsignedStartups * 6) + Math.Min(16, unappliedSafeTweaks * 2);
        var optimizerScore = Math.Clamp(100 - optimizerPenalty, 60, 100);

        if (activeUnsignedStartups > 0)
        {
            actions.Add(new SmartAuditActionItem(
                SystemDomain.Optimizer,
                RiskLevel.Attention,
                $"В автозагрузке активно неподписанных программ: {activeUnsignedStartups}",
                "Отключение лишних программ автозапуска ускорит вход в Windows без их удаления с ПК.",
                "⚡ Автозагрузка"));
        }

        var composite = (int)Math.Round(
            (securityScore * 0.30) +
            (hardwareScore * 0.13) +
            (driversScore * 0.12) +
            (stabilityScore * 0.20) +
            (cleanerScore * 0.15) +
            (optimizerScore * 0.10));

        composite = Math.Clamp(composite, 5, 100);

        var orderedActions = actions
            .OrderByDescending(a => a.Severity)
            .Take(8)
            .ToList();

        var headline = orderedActions.Count == 0
            ? $"🌟 Отличное состояние системы ({composite}/100)! Скрытых майнеров, проблем с драйверами и критических сбоев не найдено."
            : $"📊 Комплексный аудит завершен: Индекс здоровья ПК — {composite}/100. Найдено точек быстрого улучшения: {orderedActions.Count}.";

        return new SmartSystemAuditSummary(
            CompletedAtUtc: DateTimeOffset.UtcNow,
            CompositeHealthScore: composite,
            SecurityScore: securityScore,
            HardwareScore: hardwareScore,
            DriversScore: driversScore,
            StabilityRepairScore: stabilityScore,
            CleanerScore: cleanerScore,
            OptimizerScore: optimizerScore,
            SafeReclaimableBytes: cleanReport.TotalReclaimableBytes,
            FormattedReclaimableSpace: cleanReport.FormattedTotalBytes,
            ExecutiveHeadline: headline,
            TopActionItems: orderedActions);
    }
}
