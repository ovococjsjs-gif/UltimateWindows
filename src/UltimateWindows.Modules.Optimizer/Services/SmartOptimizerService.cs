using System.Net;
using System.Text;
using System.Text.Json;
using UltimateWindows.Core.Contracts;
using UltimateWindows.Core.Enums;
using UltimateWindows.Core.Models;
using UltimateWindows.Modules.Optimizer.Catalog;
using UltimateWindows.Modules.Optimizer.Contracts;
using UltimateWindows.Modules.Optimizer.Models;
using UltimateWindows.Modules.Optimizer.Network;

namespace UltimateWindows.Modules.Optimizer.Services;

/// <summary>
/// Базовый безопасный платформенный мост Оптимизатора (для модульных тестов и кроссплатформенного запуска).
/// </summary>
public class DefaultOptimizerPlatformBridge : IOptimizerPlatformBridge
{
    public virtual bool IsRunningAsAdministrator() => false;

    public virtual SystemFacts GetSystemFacts() => SystemFacts.Unknown;

    public virtual (bool Exists, int ValueKindCode, string? SerializedValue) ReadRegistryValue(
        string hive,
        string subKeyPath,
        string valueName) => (false, (int)RegistryTweakValueKind.String, null);

    public virtual bool WriteRegistryValue(
        string hive,
        string subKeyPath,
        string valueName,
        RegistryTweakValueKind kind,
        string serializedValue) => false;

    public virtual bool RegistryKeyExists(string hive, string subKeyPath) => false;

    public virtual string? FindFirstMissingRegistryKey(string hive, string subKeyPath) => null;

    public virtual bool DeleteRegistryKeyIfEmpty(string hive, string subKeyPath) => false;

    public virtual ServiceConfigSnapshot? QueryServiceConfig(string serviceName) => null;

    public virtual PlatformActionResult SetServiceStartup(string serviceName, ServiceStartupMode mode) =>
        PlatformActionResult.Fail("Управление службами доступно только в Windows.");

    public virtual Task<PlatformActionResult> ControlServiceAsync(string serviceName, bool start, CancellationToken ct = default) =>
        Task.FromResult(PlatformActionResult.Fail("Управление службами доступно только в Windows."));

    public virtual Task<IReadOnlyList<WindowsServiceInfo>> GetServicesAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<WindowsServiceInfo>>(Array.Empty<WindowsServiceInfo>());

    public virtual IReadOnlyDictionary<string, ScheduledTaskSnapshot> QueryScheduledTasks(IReadOnlyCollection<string> taskPaths) =>
        new Dictionary<string, ScheduledTaskSnapshot>(StringComparer.OrdinalIgnoreCase);

    public virtual PlatformActionResult SetScheduledTaskEnabled(string taskPath, bool enabled) =>
        PlatformActionResult.Fail("Планировщик заданий доступен только в Windows.");

    public virtual Task<IReadOnlyList<ScheduledTaskInfo>> GetScheduledTasksAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<ScheduledTaskInfo>>(Array.Empty<ScheduledTaskInfo>());

    public virtual Task<IReadOnlyList<StartupEntryInfo>> GetStartupEntriesAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<StartupEntryInfo>>(Array.Empty<StartupEntryInfo>());

    public virtual Task<(bool Succeeded, string PreviousStartupApprovedBase64)> SetStartupEntryEnabledAsync(
        StartupEntryInfo entry,
        bool enabled,
        CancellationToken ct = default) =>
        Task.FromResult((false, ""));

    public virtual Task<IReadOnlyList<ShellContextMenuHandlerInfo>> GetThirdPartyShellExtensionsAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<ShellContextMenuHandlerInfo>>(Array.Empty<ShellContextMenuHandlerInfo>());

    public virtual Task<bool> SetShellExtensionBlockedAsync(string clsid, string handlerName, bool blocked, CancellationToken ct = default) =>
        Task.FromResult(false);

    public virtual Task<IReadOnlyList<LockingProcessInfo>> FindLockingProcessesAsync(string fileOrDirectoryPath, CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<LockingProcessInfo>>(Array.Empty<LockingProcessInfo>());

    public virtual Task<bool> TryPoliteCloseProcessAsync(int processId, CancellationToken ct = default) =>
        Task.FromResult(false);

    public virtual Task<(bool Succeeded, string AdapterName, string PreviousDnsStateJson)> ApplyDnsPresetAsync(
        DnsPresetDescriptor preset,
        CancellationToken ct = default) =>
        Task.FromResult((false, "", ""));

    public virtual Task<bool> FlushDnsCacheAsync(CancellationToken ct = default) =>
        Task.FromResult(false);

    public virtual string GetHostsFilePath() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "drivers", "etc", "hosts");

    public virtual Task<IReadOnlyList<InstalledApplicationInfo>> GetInstalledApplicationsAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<InstalledApplicationInfo>>(Array.Empty<InstalledApplicationInfo>());

    public virtual Task<bool> LaunchApplicationUninstallerAsync(InstalledApplicationInfo app, CancellationToken ct = default) =>
        Task.FromResult(false);

    public virtual Task<IReadOnlyList<UwpPackageInfo>> GetInstalledUwpPackagesAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<UwpPackageInfo>>(Array.Empty<UwpPackageInfo>());

    public virtual Task<(int RemovedCount, string ErrorSummary)> RemoveUwpPackagesAsync(
        IReadOnlyList<UwpPackageInfo> packages,
        CancellationToken ct = default) =>
        Task.FromResult((0, "Доступно только на Windows 10/11."));
}

/// <summary>
/// Сервис Оптимизатора: обратимые твики из каталога (реестр, службы, задания планировщика), готовые наборы и профили,
/// диспетчеры служб и заданий, автозагрузка, контекстное меню Проводника, поиск процессов, держащих файл,
/// переключение DNS, редактор hosts, приложения Windows и удаление программ.
/// Каждое изменение системы сначала снимает прежнее состояние в «Машину времени».
/// </summary>
public sealed class SmartOptimizerService
{
    private static readonly HashSet<string> ProtectedCriticalSystemProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "system", "idle", "registry", "smss", "csrss", "wininit", "services",
        "lsass", "lsaiso", "svchost", "fontdrvhost", "winlogon", "dwm", "sihost", "msmpeng"
    };

    private readonly IVaultService _vaultService;
    private readonly IOptimizerPlatformBridge _platformBridge;
    private readonly TweakEngine _engine;
    private SystemFacts? _cachedSystemFacts;

    public SmartOptimizerService(
        IVaultService vaultService,
        IOptimizerPlatformBridge? platformBridge = null)
    {
        _vaultService = vaultService ?? throw new ArgumentNullException(nameof(vaultService));
        _platformBridge = platformBridge ?? new DefaultOptimizerPlatformBridge();
        _engine = new TweakEngine(_platformBridge);
    }

    public IReadOnlyList<DnsPresetDescriptor> GetDnsPresets() => NetworkAndHostsInspector.GetDnsPresets();

    /// <summary>Работает ли программа с правами администратора: без них доступны только настройки текущего пользователя.</summary>
    public bool IsRunningAsAdministrator => _platformBridge.IsRunningAsAdministrator();

    /// <summary>
    /// Сведения о компьютере для проверки применимости твиков. Запрашиваются один раз за сеанс.
    /// </summary>
    public SystemFacts GetSystemFacts()
    {
        if (_cachedSystemFacts is not null)
        {
            return _cachedSystemFacts;
        }

        SystemFacts facts;
        try
        {
            facts = _platformBridge.GetSystemFacts() ?? SystemFacts.Unknown;
        }
        catch (Exception)
        {
            // Сбой при сборе сведений не должен ломать список твиков: считаем факты неизвестными
            facts = SystemFacts.Unknown;
        }

        _cachedSystemFacts = facts;
        return facts;
    }

    // ==================== ТВИКИ: СОСТОЯНИЕ ====================

    public IReadOnlyList<TweakPresetDescriptor> GetPresets() => DeclarativeTweakCatalog.GetPresets();

    /// <summary>Все твики каталога в порядке показа — без обращения к системе.</summary>
    public IReadOnlyList<DeclarativeTweakRule> GetCatalogRules() => DeclarativeTweakCatalog.GetAllRules();

    public IReadOnlyList<EvaluatedTweakState> EvaluateAllTweaks()
    {
        var rules = DeclarativeTweakCatalog.GetAllRules();
        var states = new List<EvaluatedTweakState>(rules.Count);
        var facts = GetSystemFacts();
        var tasks = _engine.QueryTasks(rules);

        foreach (var rule in rules)
        {
            states.Add(EvaluateRule(rule, facts, tasks));
        }

        return states;
    }

    public EvaluatedTweakState? EvaluateTweak(string tweakId)
    {
        var rule = DeclarativeTweakCatalog.FindById(tweakId);
        return rule is null ? null : EvaluateRule(rule, GetSystemFacts(), _engine.QueryTasks([rule]));
    }

    /// <summary>
    /// Подробности твика: каждая цель, её текущее состояние, желаемое и стандартное.
    /// </summary>
    public IReadOnlyList<TweakActionState> DescribeTweakActions(string tweakId)
    {
        var rule = DeclarativeTweakCatalog.FindById(tweakId);
        if (rule is null)
        {
            return [];
        }

        var tasks = _engine.QueryTasks([rule]);
        return rule.Actions.Select(a => _engine.Describe(a, tasks)).ToArray();
    }

    private EvaluatedTweakState EvaluateRule(
        DeclarativeTweakRule rule,
        SystemFacts facts,
        IReadOnlyDictionary<string, ScheduledTaskSnapshot> tasks)
    {
        var (state, applied, present) = _engine.Evaluate(rule, tasks);
        var applicability = EvaluateApplicability(rule, facts);
        if (state == TweakStateKind.Unavailable && applicability.Status != TweakApplicabilityStatus.NotApplicable)
        {
            applicability = new TweakApplicability(TweakApplicabilityStatus.NotApplicable, NoTargetsReason);
        }

        return new EvaluatedTweakState(rule, state, applicability, applied, present);
    }

    private TweakApplicability EvaluateApplicability(DeclarativeTweakRule rule, SystemFacts facts)
    {
        var requirements = rule.EffectiveRequirements;
        var result = requirements.Evaluate(facts);
        if (result.Status == TweakApplicabilityStatus.NotApplicable)
        {
            return result;
        }

        if (requirements.InstalledAnyRegistryKey is { Count: > 0 } keys && !keys.Any(RegistryKeyExists))
        {
            return new TweakApplicability(
                TweakApplicabilityStatus.NotApplicable,
                requirements.InstalledNote ?? "Программа, к которой относится настройка, не установлена.");
        }

        return result;
    }

    private bool RegistryKeyExists(string hiveAndKey)
    {
        try
        {
            return TweakCatalogLoader.TrySplitRegistryPath(hiveAndKey, out var hive, out var key) &&
                   _platformBridge.RegistryKeyExists(hive, key);
        }
        catch (Exception)
        {
            return false;
        }
    }

    // ==================== ТВИКИ: ПРИМЕНЕНИЕ ====================

    /// <summary>
    /// Включает твик или возвращает стандартное состояние Windows.
    /// Твик, который не подходит этому компьютеру, включить нельзя. Не рекомендуемый для этого компьютера
    /// или опасный твик включается только при явном согласии в <paramref name="options"/>;
    /// без согласия возвращается результат с признаком нужного подтверждения.
    /// Возврат к стандарту разрешён всегда.
    /// Твик применяется целиком: если одно из действий не удалось, остальные возвращаются обратно,
    /// а результат честно сообщает о неудаче.
    /// </summary>
    public async Task<OptimizerOperationResult> SetTweakStateAsync(
        string tweakId,
        bool enableTweak,
        CancellationToken ct = default,
        TweakApplyOptions? options = null)
    {
        var rule = DeclarativeTweakCatalog.FindById(tweakId);
        if (rule is null)
        {
            return new OptimizerOperationResult(false, $"Настройка с идентификатором '{tweakId}' не найдена в каталоге.");
        }

        var blocked = CheckBeforeApply(rule, enableTweak, options ?? TweakApplyOptions.Default);
        if (blocked is not null)
        {
            return blocked;
        }

        ct.ThrowIfCancellationRequested();
        var application = _engine.ApplyRule(rule, enableTweak);
        switch (application.Kind)
        {
            case RuleOutcomeKind.Failed:
                return new OptimizerOperationResult(
                    false,
                    $"Не удалось {(enableTweak ? "включить" : "вернуть к стандарту")} «{rule.FriendlyTitle}»: {application.FailureReason}. Изменения этой настройки отменены.",
                    TechnicalDetails: rule.ExpertMutationsPreview);

            case RuleOutcomeKind.Unavailable:
                return new OptimizerOperationResult(false, $"«{rule.FriendlyTitle}» не подходит этому компьютеру. {NoTargetsReason}");

            case RuleOutcomeKind.AlreadyInState:
                return new OptimizerOperationResult(
                    true,
                    enableTweak
                        ? $"«{rule.FriendlyTitle}» уже включено."
                        : $"«{rule.FriendlyTitle}» уже в стандартном состоянии Windows.",
                    TechnicalDetails: rule.ExpertMutationsPreview);
        }

        TransactionRecord committed;
        try
        {
            await using var tx = _vaultService.BeginTransaction(
                SystemDomain.Optimizer,
                friendlyTitle: $"{(enableTweak ? "Включено" : "Возвращён стандарт")}: {rule.FriendlyTitle}",
                friendlySummary: rule.FriendlyExplanation,
                technicalDetails: rule.ExpertMutationsPreview);

            foreach (var delta in application.Deltas)
            {
                tx.RecordStateDelta(delta.TargetKind, delta.TargetPath, delta.PreviousStateJson, delta.NewStateJson);
            }

            committed = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Без записи в «Машине времени» изменение нельзя будет отменить — возвращаем систему как была
            application.Undo();
            return new OptimizerOperationResult(
                false,
                $"«{rule.FriendlyTitle}»: не удалось сохранить точку отката ({ex.Message}). Изменения отменены.");
        }
        catch (OperationCanceledException)
        {
            application.Undo();
            throw;
        }

        StopDisabledServices(application);

        var restart = rule.Restart;
        var skipped = application.AbsentCount > 0
            ? $" Пропущено целей, которых нет в этой системе: {application.AbsentCount}."
            : "";
        return new OptimizerOperationResult(
            Succeeded: true,
            UserFriendlyMessage: (enableTweak
                ? $"Включено: «{rule.FriendlyTitle}». Точка отката сохранена."
                : $"Возвращён стандарт Windows: «{rule.FriendlyTitle}».") + skipped + DescribeRestart(restart),
            TechnicalDetails: rule.ExpertMutationsPreview,
            RollbackSessionId: committed.SessionId,
            RestartRequired: restart);
    }

    /// <summary>
    /// Включает несколько твиков одной операцией. Всё применённое попадает в одну запись «Машины времени».
    /// Твик, который не подходит компьютеру или требует согласия, которого нет в <paramref name="options"/>, пропускается.
    /// </summary>
    public async Task<TweakBatchResult> ApplyTweakBatchAsync(
        IReadOnlyList<string> tweakIds,
        string batchTitle,
        TweakApplyOptions? options = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(tweakIds);
        options ??= TweakApplyOptions.Default;

        var items = new List<TweakBatchItemResult>(tweakIds.Count);
        var applications = new List<TweakEngine.RuleApplication>();
        var restart = TweakRestartKind.None;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var id in tweakIds)
        {
            if (ct.IsCancellationRequested)
            {
                break;
            }

            if (string.IsNullOrWhiteSpace(id) || !seen.Add(id))
            {
                continue;
            }

            var rule = DeclarativeTweakCatalog.FindById(id);
            if (rule is null)
            {
                items.Add(new TweakBatchItemResult(id, id, TweakBatchItemOutcome.Skipped, "Такой настройки нет в этой версии программы."));
                continue;
            }

            var blocked = CheckBeforeApply(rule, enable: true, options);
            if (blocked is not null)
            {
                items.Add(new TweakBatchItemResult(rule.TweakId, rule.FriendlyTitle, TweakBatchItemOutcome.Skipped, blocked.UserFriendlyMessage));
                continue;
            }

            var application = _engine.ApplyRule(rule, enable: true);
            switch (application.Kind)
            {
                case RuleOutcomeKind.Changed:
                    applications.Add(application);
                    restart = TweakRiskInfo.Strongest(restart, rule.Restart);
                    items.Add(new TweakBatchItemResult(rule.TweakId, rule.FriendlyTitle, TweakBatchItemOutcome.Applied));
                    break;

                case RuleOutcomeKind.AlreadyInState:
                    items.Add(new TweakBatchItemResult(rule.TweakId, rule.FriendlyTitle, TweakBatchItemOutcome.AlreadyInState));
                    break;

                case RuleOutcomeKind.Unavailable:
                    items.Add(new TweakBatchItemResult(rule.TweakId, rule.FriendlyTitle, TweakBatchItemOutcome.Skipped, NoTargetsReason));
                    break;

                default:
                    items.Add(new TweakBatchItemResult(
                        rule.TweakId,
                        rule.FriendlyTitle,
                        TweakBatchItemOutcome.Failed,
                        $"{application.FailureReason}. Изменения этой настройки отменены."));
                    break;
            }
        }

        Guid? sessionId = null;
        if (applications.Count > 0)
        {
            try
            {
                await using var tx = _vaultService.BeginTransaction(
                    SystemDomain.Optimizer,
                    friendlyTitle: $"{batchTitle}: включено настроек — {applications.Count}",
                    friendlySummary: string.Join("; ", applications.Select(a => a.Rule.FriendlyTitle)),
                    technicalDetails: string.Join(Environment.NewLine, applications.Select(a => $"{a.Rule.TweakId}: {a.Rule.ExpertMutationsPreview}")));

                foreach (var delta in applications.SelectMany(a => a.Deltas))
                {
                    tx.RecordStateDelta(delta.TargetKind, delta.TargetPath, delta.PreviousStateJson, delta.NewStateJson);
                }

                // Запись сохраняется даже при отмене операции: изменения уже внесены, и их нужно уметь откатить
                var committed = await tx.CommitAsync(pinTransaction: false, CancellationToken.None).ConfigureAwait(false);
                sessionId = committed.SessionId;
            }
            catch (Exception ex)
            {
                for (var i = applications.Count - 1; i >= 0; i--)
                {
                    applications[i].Undo();
                }

                return new TweakBatchResult(
                    false,
                    $"{batchTitle}: не удалось сохранить точку отката ({ex.Message}). Все изменения отменены.",
                    items.Select(i => i.Outcome == TweakBatchItemOutcome.Applied
                        ? i with { Outcome = TweakBatchItemOutcome.Failed, Note = "Изменение отменено: не сохранилась точка отката." }
                        : i).ToArray());
            }

            foreach (var application in applications)
            {
                StopDisabledServices(application);
            }
        }

        var result = new TweakBatchResult(true, "", items, sessionId, restart);
        var parts = new List<string> { $"включено — {result.AppliedCount}" };
        if (result.AlreadyInStateCount > 0) parts.Add($"уже были включены — {result.AlreadyInStateCount}");
        if (result.SkippedCount > 0) parts.Add($"пропущено — {result.SkippedCount}");
        if (result.FailedCount > 0) parts.Add($"не удалось — {result.FailedCount}");

        var succeeded = result.FailedCount == 0 && result.AppliedCount + result.AlreadyInStateCount > 0;
        var message = $"{batchTitle}: {string.Join(", ", parts)}." +
                      (sessionId is not null ? " Все изменения отменяются одной записью в «Машине времени»." : "") +
                      DescribeRestart(restart);

        return result with { Succeeded = succeeded, UserFriendlyMessage = message };
    }

    public async Task<OptimizerOperationResult> ApplyPresetBatchAsync(
        string presetKey,
        string presetDisplayTitle,
        CancellationToken ct = default)
    {
        var batch = await ApplyTweakBatchAsync(
            DeclarativeTweakCatalog.GetPresetIds(presetKey),
            $"Набор «{presetDisplayTitle}»",
            TweakApplyOptions.Default,
            ct).ConfigureAwait(false);

        return new OptimizerOperationResult(
            batch.Succeeded,
            batch.UserFriendlyMessage,
            RollbackSessionId: batch.RollbackSessionId,
            RestartRequired: batch.RestartRequired);
    }

    // ==================== ПРОФИЛИ ====================

    public string ExportActiveTweaksToYaml(string profileName = "Мой профиль UltimateWindows")
    {
        var activeIds = EvaluateAllTweaks()
            .Where(t => t.IsCurrentlyApplied)
            .Select(t => t.Rule.TweakId);
        return YamlTweakProfileSerializer.ExportProfileToYaml(profileName, activeIds);
    }

    /// <summary>
    /// Разбирает файл профиля, ничего не применяя: какие настройки он включает и какие из них неизвестны.
    /// </summary>
    public TweakProfile ReadProfile(string yamlContent)
    {
        var (profileName, ids) = YamlTweakProfileSerializer.ImportProfileFromYaml(yamlContent);
        var known = new List<string>();
        var unknown = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var id in ids)
        {
            if (!seen.Add(id))
            {
                continue;
            }

            var rule = DeclarativeTweakCatalog.FindById(id);
            if (rule is null)
            {
                unknown.Add(id);
            }
            else
            {
                known.Add(rule.TweakId);
            }
        }

        return new TweakProfile(profileName, known, unknown);
    }

    public async Task<OptimizerOperationResult> ImportAndApplyYamlProfileAsync(
        string yamlContent,
        CancellationToken ct = default,
        TweakApplyOptions? options = null)
    {
        var profile = ReadProfile(yamlContent);
        if (profile.KnownTweakIds.Count == 0)
        {
            return new OptimizerOperationResult(
                false,
                profile.UnknownTweakIds.Count > 0
                    ? $"Профиль «{profile.Name}»: ни одна из его настроек не известна этой версии программы."
                    : "В выбранном профиле не указано ни одной настройки.");
        }

        var batch = await ApplyTweakBatchAsync(profile.KnownTweakIds, $"Профиль «{profile.Name}»", options, ct).ConfigureAwait(false);
        var unknownNote = profile.UnknownTweakIds.Count > 0
            ? $" Неизвестных настроек в профиле: {profile.UnknownTweakIds.Count}."
            : "";

        return new OptimizerOperationResult(
            batch.Succeeded,
            batch.UserFriendlyMessage + unknownNote,
            RollbackSessionId: batch.RollbackSessionId,
            RestartRequired: batch.RestartRequired);
    }

    /// <summary>
    /// Проверки перед применением. Возвращает отказ с пояснением либо null, если применять можно.
    /// </summary>
    private OptimizerOperationResult? CheckBeforeApply(DeclarativeTweakRule rule, bool enable, TweakApplyOptions options)
    {
        TweakSafetyGuard.ThrowIfUnsafeRule(rule);

        var applicability = enable
            ? EvaluateApplicability(rule, GetSystemFacts())
            : TweakApplicability.Applicable;

        if (applicability.Status == TweakApplicabilityStatus.NotApplicable)
        {
            return new OptimizerOperationResult(
                false,
                $"«{rule.FriendlyTitle}» не подходит этому компьютеру. {applicability.Reason}");
        }

        if (rule.RequiresAdministrator && !_platformBridge.IsRunningAsAdministrator())
        {
            return new OptimizerOperationResult(
                false,
                $"Для настройки «{rule.FriendlyTitle}» запустите программу от имени администратора.");
        }

        if (enable && rule.IsDangerous && !options.AcceptDangerous)
        {
            return new OptimizerOperationResult(
                false,
                $"«{rule.FriendlyTitle}» — опасная настройка: она ослабляет защиту или устойчивость Windows. Включайте её, только если понимаете последствия.",
                ConfirmationRequired: TweakConfirmationKind.DangerousTweak);
        }

        if (applicability.Status == TweakApplicabilityStatus.NotRecommended && !options.AcceptNotRecommended)
        {
            return new OptimizerOperationResult(
                false,
                $"«{rule.FriendlyTitle}» не рекомендуется для этого компьютера. {applicability.Reason}",
                ConfirmationRequired: TweakConfirmationKind.NotRecommendedForThisPc);
        }

        return null;
    }

    /// <summary>
    /// Отключённая служба продолжает работать до перезагрузки. Останавливаем её сразу, не дожидаясь результата:
    /// сама настройка уже применена, а остановка — удобство.
    /// </summary>
    private void StopDisabledServices(TweakEngine.RuleApplication application)
    {
        foreach (var serviceName in application.ServicesSwitchedToDisabled)
        {
            try
            {
                _ = _platformBridge.ControlServiceAsync(serviceName, start: false, CancellationToken.None)
                    .ContinueWith(static t => _ = t.Exception, TaskScheduler.Default);
            }
            catch (Exception)
            {
                // Служба остановится при следующей перезагрузке
            }
        }
    }

    private static string DescribeRestart(TweakRestartKind restart)
    {
        var when = TweakRiskInfo.GetRestartTitle(restart);
        return when.Length == 0 ? "" : $" Вступит в силу {when}.";
    }

    // ==================== СЛУЖБЫ WINDOWS ====================

    public Task<IReadOnlyList<WindowsServiceInfo>> GetServicesAsync(CancellationToken ct = default) =>
        _platformBridge.GetServicesAsync(ct);

    public SystemObjectProtection GetServiceProtection(string serviceName) => TweakSafetyGuard.ClassifyService(serviceName);

    /// <summary>
    /// Что о службе знает каталог: названия настроек, которые её отключают. Пустая строка, если служба в каталоге не упоминается.
    /// </summary>
    public string GetServiceHint(string serviceName) =>
        CatalogHints.Value.Services.TryGetValue(serviceName, out var hint) ? hint : "";

    /// <summary>
    /// Меняет тип запуска службы и записывает прежний в «Машину времени».
    /// Жизненно важные службы и службы лицензирования менять нельзя; службы защиты и обновлений — только при
    /// <paramref name="acceptDangerous"/>.
    /// </summary>
    public async Task<OptimizerOperationResult> SetServiceStartupAsync(
        string serviceName,
        ServiceStartupMode mode,
        bool acceptDangerous = false,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(serviceName))
        {
            return new OptimizerOperationResult(false, "Не указано имя службы.");
        }

        if (mode is ServiceStartupMode.Boot or ServiceStartupMode.System)
        {
            return new OptimizerOperationResult(false, "Типы запуска «при загрузке» и «системный» относятся к драйверам, для службы их выбрать нельзя.");
        }

        var refusal = CheckSystemObject(TweakSafetyGuard.ClassifyService(serviceName), $"Служба «{serviceName}»", acceptDangerous);
        if (refusal is not null)
        {
            return refusal;
        }

        var before = _platformBridge.QueryServiceConfig(serviceName);
        if (before is null)
        {
            return new OptimizerOperationResult(false, $"Служба «{serviceName}» не найдена в этой системе.");
        }

        if (before.Startup is ServiceStartupMode.Boot or ServiceStartupMode.System)
        {
            return new OptimizerOperationResult(false, $"«{serviceName}» — драйвер, а не служба. Менять его запуск здесь нельзя.");
        }

        if (before.Startup == mode)
        {
            return new OptimizerOperationResult(true, $"Служба «{serviceName}» уже имеет тип запуска «{ServiceDisplay.GetTitle(mode)}».");
        }

        var changed = _platformBridge.SetServiceStartup(serviceName, mode);
        var after = changed.Succeeded ? _platformBridge.QueryServiceConfig(serviceName) : null;
        if (!changed.Succeeded || after?.Startup != mode)
        {
            if (changed.Succeeded)
            {
                _platformBridge.SetServiceStartup(serviceName, before.Startup);
            }

            return new OptimizerOperationResult(
                false,
                $"Не удалось изменить тип запуска службы «{serviceName}»: {changed.Error ?? "Windows не сохранила изменение (служба защищена системой)"}.");
        }

        await using var tx = _vaultService.BeginTransaction(
            SystemDomain.Optimizer,
            friendlyTitle: $"Служба «{serviceName}»: {ServiceDisplay.GetTitle(before.Startup)} → {ServiceDisplay.GetTitle(mode)}",
            friendlySummary: "Изменён тип запуска службы Windows.",
            technicalDetails: serviceName);

        tx.RecordStateDelta(
            StateTargetKind.WindowsService,
            serviceName,
            previousStateJson: JsonSerializer.Serialize(new { ServiceName = serviceName, Startup = before.Startup.ToString() }),
            newStateJson: JsonSerializer.Serialize(new { Startup = mode.ToString() }));

        var committed = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);
        return new OptimizerOperationResult(
            true,
            $"Служба «{serviceName}»: тип запуска теперь «{ServiceDisplay.GetTitle(mode)}». Точка отката сохранена.",
            RollbackSessionId: committed.SessionId);
    }

    /// <summary>
    /// Запускает или останавливает службу. Остановка подчиняется тем же правилам защиты, что и смена типа запуска.
    /// </summary>
    public async Task<OptimizerOperationResult> ControlServiceAsync(
        string serviceName,
        bool start,
        bool acceptDangerous = false,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(serviceName))
        {
            return new OptimizerOperationResult(false, "Не указано имя службы.");
        }

        if (!start)
        {
            var refusal = CheckSystemObject(TweakSafetyGuard.ClassifyService(serviceName), $"Служба «{serviceName}»", acceptDangerous);
            if (refusal is not null)
            {
                return refusal;
            }
        }
        else if (!_platformBridge.IsRunningAsAdministrator())
        {
            return new OptimizerOperationResult(false, "Для управления службами запустите программу от имени администратора.");
        }

        var result = await _platformBridge.ControlServiceAsync(serviceName, start, ct).ConfigureAwait(false);
        return result.Succeeded
            ? new OptimizerOperationResult(true, start ? $"Служба «{serviceName}» запущена." : $"Служба «{serviceName}» остановлена.")
            : new OptimizerOperationResult(
                false,
                $"Не удалось {(start ? "запустить" : "остановить")} службу «{serviceName}»: {result.Error ?? "нет доступа"}.");
    }

    // ==================== ПЛАНИРОВЩИК ЗАДАНИЙ ====================

    public Task<IReadOnlyList<ScheduledTaskInfo>> GetScheduledTasksAsync(CancellationToken ct = default) =>
        _platformBridge.GetScheduledTasksAsync(ct);

    public SystemObjectProtection GetScheduledTaskProtection(string taskPath) => TweakSafetyGuard.ClassifyScheduledTask(taskPath);

    public string GetScheduledTaskHint(string taskPath) =>
        CatalogHints.Value.Tasks.TryGetValue(taskPath, out var hint) ? hint : "";

    public async Task<OptimizerOperationResult> SetScheduledTaskEnabledAsync(
        string taskPath,
        bool enabled,
        bool acceptDangerous = false,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(taskPath))
        {
            return new OptimizerOperationResult(false, "Не указан путь задания.");
        }

        if (!enabled)
        {
            var refusal = CheckSystemObject(TweakSafetyGuard.ClassifyScheduledTask(taskPath), $"Задание «{taskPath}»", acceptDangerous);
            if (refusal is not null)
            {
                return refusal;
            }
        }
        else if (!_platformBridge.IsRunningAsAdministrator())
        {
            return new OptimizerOperationResult(false, "Для управления заданиями запустите программу от имени администратора.");
        }

        if (!_platformBridge.QueryScheduledTasks([taskPath]).TryGetValue(taskPath, out var before))
        {
            return new OptimizerOperationResult(false, $"Задание «{taskPath}» не найдено в этой системе.");
        }

        var stateWord = TweakScheduledTaskAction.FormatEnabled(enabled).ToLowerInvariant();
        if (before.Enabled == enabled)
        {
            return new OptimizerOperationResult(true, $"Задание «{taskPath}» уже {stateWord}.");
        }

        var changed = _platformBridge.SetScheduledTaskEnabled(taskPath, enabled);
        var verified = changed.Succeeded &&
                       _platformBridge.QueryScheduledTasks([taskPath]).TryGetValue(taskPath, out var after) &&
                       after.Enabled == enabled;
        if (!verified)
        {
            return new OptimizerOperationResult(
                false,
                $"Не удалось изменить задание «{taskPath}»: {changed.Error ?? "Windows не сохранила изменение (задание защищено системой)"}.");
        }

        await using var tx = _vaultService.BeginTransaction(
            SystemDomain.Optimizer,
            friendlyTitle: $"Задание планировщика {stateWord}: {taskPath}",
            friendlySummary: "Изменено состояние задания планировщика Windows.",
            technicalDetails: taskPath);

        tx.RecordStateDelta(
            StateTargetKind.ScheduledTask,
            taskPath,
            previousStateJson: JsonSerializer.Serialize(new { TaskPath = taskPath, Enabled = before.Enabled }),
            newStateJson: JsonSerializer.Serialize(new { Enabled = enabled }));

        var committed = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);
        return new OptimizerOperationResult(
            true,
            $"Задание «{taskPath}» {stateWord}. Точка отката сохранена.",
            RollbackSessionId: committed.SessionId);
    }

    private OptimizerOperationResult? CheckSystemObject(SystemObjectProtection protection, string subject, bool acceptDangerous)
    {
        if (protection == SystemObjectProtection.Critical)
        {
            return new OptimizerOperationResult(false, $"{subject}: {TweakSafetyGuard.DescribeProtection(protection)}");
        }

        if (!_platformBridge.IsRunningAsAdministrator())
        {
            return new OptimizerOperationResult(false, "Для управления службами и заданиями запустите программу от имени администратора.");
        }

        if (protection == SystemObjectProtection.WeakensProtection && !acceptDangerous)
        {
            return new OptimizerOperationResult(
                false,
                $"{subject}: {TweakSafetyGuard.DescribeProtection(protection)}",
                ConfirmationRequired: TweakConfirmationKind.DangerousTweak);
        }

        return null;
    }

    private const string NoTargetsReason = "В этой системе нет служб и заданий, которые меняет настройка.";

    private sealed record CatalogHintIndex(
        IReadOnlyDictionary<string, string> Services,
        IReadOnlyDictionary<string, string> Tasks);

    private static readonly Lazy<CatalogHintIndex> CatalogHints = new(BuildCatalogHints, LazyThreadSafetyMode.ExecutionAndPublication);

    private static CatalogHintIndex BuildCatalogHints()
    {
        var services = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var tasks = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

        foreach (var rule in DeclarativeTweakCatalog.GetAllRules())
        {
            foreach (var action in rule.Actions)
            {
                var (index, key) = action switch
                {
                    TweakServiceAction s => (services, s.ServiceName),
                    TweakScheduledTaskAction t => (tasks, t.TaskPath),
                    _ => (null, null)
                };

                if (index is null || key is null)
                {
                    continue;
                }

                if (!index.TryGetValue(key, out var titles))
                {
                    index[key] = titles = [];
                }

                if (!titles.Contains(rule.FriendlyTitle))
                {
                    titles.Add(rule.FriendlyTitle);
                }
            }
        }

        static IReadOnlyDictionary<string, string> Flatten(Dictionary<string, List<string>> source) =>
            source.ToDictionary(
                kv => kv.Key,
                kv => "Настройка каталога: " + string.Join("; ", kv.Value.Select(t => $"«{t}»")),
                StringComparer.OrdinalIgnoreCase);

        return new CatalogHintIndex(Flatten(services), Flatten(tasks));
    }

    public Task<IReadOnlyList<StartupEntryInfo>> GetStartupEntriesAsync(CancellationToken ct = default) =>
        _platformBridge.GetStartupEntriesAsync(ct);

    public async Task<OptimizerOperationResult> ToggleStartupEntryAsync(
        StartupEntryInfo entry,
        bool enable,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(entry);
        if (entry.RequiresAdminToToggle && !_platformBridge.IsRunningAsAdministrator())
        {
            return new OptimizerOperationResult(false, $"Для изменения системной записи «{entry.DisplayName}» требуются права Администратора.");
        }

        var (ok, prevApprovedBase64) = await _platformBridge.SetStartupEntryEnabledAsync(entry, enable, ct).ConfigureAwait(false);
        if (!ok)
        {
            return new OptimizerOperationResult(false, $"Не удалось переключить автозагрузку для «{entry.DisplayName}».");
        }

        await using var tx = _vaultService.BeginTransaction(
            SystemDomain.Optimizer,
            friendlyTitle: $"{(enable ? "Включена" : "Отключена")} автозагрузка: {entry.DisplayName}",
            friendlySummary: $"Управление флагом StartupApproved для «{entry.DisplayName}».",
            technicalDetails: entry.CommandOrTarget);

        if (!string.IsNullOrEmpty(prevApprovedBase64))
        {
            var hive = entry.RequiresAdminToToggle ? "HKLM" : "HKCU";
            var subKey = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
            var snapJson = JsonSerializer.Serialize(new
            {
                Hive = hive,
                SubKey = subKey,
                ValueName = entry.DisplayName,
                ExistedBefore = true,
                ValueKind = 3,
                SerializedData = prevApprovedBase64
            });

            tx.RecordStateDelta(StateTargetKind.RegistryValue, $@"{hive}\{subKey} :: {entry.DisplayName}", snapJson, null);
        }

        var committed = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);
        return new OptimizerOperationResult(
            Succeeded: true,
            UserFriendlyMessage: enable
                ? $"Программа «{entry.DisplayName}» включена в автозагрузку."
                : $"Программа «{entry.DisplayName}» убрана из автозагрузки.",
            RollbackSessionId: committed.SessionId);
    }

    public Task<IReadOnlyList<ShellContextMenuHandlerInfo>> GetThirdPartyShellExtensionsAsync(CancellationToken ct = default) =>
        _platformBridge.GetThirdPartyShellExtensionsAsync(ct);

    public async Task<OptimizerOperationResult> SetShellExtensionBlockedAsync(
        ShellContextMenuHandlerInfo handler,
        bool blockInContextMenu,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(handler);
        if (!_platformBridge.IsRunningAsAdministrator())
        {
            return new OptimizerOperationResult(
                false,
                "Для управления политикой контекстного меню требуются права Администратора.");
        }

        const string blockedSubKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked";
        var (existedBefore, prevKind, prevVal) = _platformBridge.ReadRegistryValue("HKLM", blockedSubKey, handler.Clsid);

        var ok = await _platformBridge.SetShellExtensionBlockedAsync(handler.Clsid, handler.HandlerName, blockInContextMenu, ct).ConfigureAwait(false);
        if (!ok)
        {
            return new OptimizerOperationResult(false, $"Не удалось изменить состояние пункта меню «{handler.HandlerName}».");
        }

        await using var tx = _vaultService.BeginTransaction(
            SystemDomain.Optimizer,
            friendlyTitle: $"{(blockInContextMenu ? "Скрыто из контекстного меню" : "Возвращено в меню")}: {handler.HandlerName}",
            friendlySummary: "Безопасное переключение через политику Shell Extensions\\Blocked.",
            technicalDetails: $"{handler.Clsid} ({handler.DllPath})");

        var snapJson = JsonSerializer.Serialize(new
        {
            Hive = "HKLM",
            SubKey = blockedSubKey,
            ValueName = handler.Clsid,
            ExistedBefore = existedBefore,
            ValueKind = existedBefore ? prevKind : 1,
            SerializedData = prevVal
        });

        tx.RecordStateDelta(StateTargetKind.RegistryValue, $@"HKLM\{blockedSubKey} :: {handler.Clsid}", snapJson, null);
        var committed = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);

        return new OptimizerOperationResult(
            Succeeded: true,
            UserFriendlyMessage: blockInContextMenu
                ? $"Пункт «{handler.HandlerName}» скрыт из правого клика Проводника."
                : $"Пункт «{handler.HandlerName}» возвращен в контекстное меню.",
            RollbackSessionId: committed.SessionId);
    }

    public Task<IReadOnlyList<LockingProcessInfo>> FindLockingProcessesAsync(
        string fileOrDirectoryPath,
        CancellationToken ct = default) =>
        _platformBridge.FindLockingProcessesAsync(fileOrDirectoryPath, ct);

    public async Task<OptimizerOperationResult> RequestSafeCloseLockingProcessAsync(
        LockingProcessInfo processInfo,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(processInfo);

        var cleanName = Path.GetFileNameWithoutExtension(processInfo.ApplicationName);
        if (processInfo.IsCriticalSystemProcess || ProtectedCriticalSystemProcesses.Contains(cleanName))
        {
            return new OptimizerOperationResult(
                false,
                $"Защитный барьер: системный процесс «{processInfo.ApplicationName}» нельзя завершать.");
        }

        var closed = await _platformBridge.TryPoliteCloseProcessAsync(processInfo.ProcessId, ct).ConfigureAwait(false);
        return closed
            ? new OptimizerOperationResult(true, $"Отправлен запрос закрытия процессу «{processInfo.ApplicationName}» (PID {processInfo.ProcessId}) — файл освобожден.")
            : new OptimizerOperationResult(false, $"Процесс «{processInfo.ApplicationName}» ожидает сохранения данных — закройте его окно вручную.");
    }

    public async Task<OptimizerOperationResult> ApplyDnsPresetAsync(
        DnsPresetId presetId,
        CancellationToken ct = default)
    {
        if (!_platformBridge.IsRunningAsAdministrator())
        {
            return new OptimizerOperationResult(false, "Для изменения DNS-серверов сетевого адаптера требуются права Администратора.");
        }

        var preset = NetworkAndHostsInspector.GetPresetById(presetId);
        var (ok, adapterName, prevDnsJson) = await _platformBridge.ApplyDnsPresetAsync(preset, ct).ConfigureAwait(false);
        if (!ok)
        {
            return new OptimizerOperationResult(false, $"Не удалось применить DNS-профиль «{preset.FriendlyName}».");
        }

        await using var tx = _vaultService.BeginTransaction(
            SystemDomain.Optimizer,
            friendlyTitle: $"Настройка DNS ({adapterName}): {preset.FriendlyName}",
            friendlySummary: preset.FriendlyBenefit,
            technicalDetails: preset.ServersDisplay);

        tx.RecordStateDelta(
            StateTargetKind.SystemSetting,
            $"DnsProfile:{adapterName}",
            previousStateJson: prevDnsJson,
            newStateJson: JsonSerializer.Serialize(new { Preset = preset.Id.ToString(), Primary = preset.PrimaryIpv4 }));

        var committed = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);
        return new OptimizerOperationResult(
            Succeeded: true,
            UserFriendlyMessage: $"Применен DNS «{preset.FriendlyName}» для адаптера «{adapterName}».",
            RollbackSessionId: committed.SessionId);
    }

    public async Task<OptimizerOperationResult> FlushDnsCacheAsync(CancellationToken ct = default)
    {
        var ok = await _platformBridge.FlushDnsCacheAsync(ct).ConfigureAwait(false);
        return ok
            ? new OptimizerOperationResult(true, "Кэш DNS-резолвера Windows успешно очищен (ipconfig /flushdns).")
            : new OptimizerOperationResult(false, "Не удалось очистить кэш DNS.");
    }

    // ==================== HOSTS FILE EDITOR (С БЕКАПОМ В VAULT) ====================

    public string GetHostsFilePath() => _platformBridge.GetHostsFilePath();

    public IReadOnlyList<HostsRedirectEntry> InspectHostsFile()
    {
        var path = _platformBridge.GetHostsFilePath();
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return Array.Empty<HostsRedirectEntry>();
        }

        try
        {
            return NetworkAndHostsInspector.ParseHostsContent(File.ReadAllText(path));
        }
        catch
        {
            return Array.Empty<HostsRedirectEntry>();
        }
    }

    public async Task<OptimizerOperationResult> AddHostsEntryAsync(
        string redirectIp,
        string domainHost,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(redirectIp) || !IPAddress.TryParse(redirectIp.Trim(), out _))
        {
            return new OptimizerOperationResult(false, "Укажите корректный IP-адрес (например, 0.0.0.0 или 127.0.0.1).");
        }

        var cleanDomain = (domainHost ?? "").Trim().ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(cleanDomain) || cleanDomain.Contains(' ') || !cleanDomain.Contains('.'))
        {
            return new OptimizerOperationResult(false, "Укажите корректное доменное имя (например, telemetry.example.com).");
        }

        if (NetworkAndHostsInspector.IsProtectedSecurityDomain(cleanDomain))
        {
            return new OptimizerOperationResult(
                false,
                $"Защитный фильтр заблокировал попытку перенаправить домен безопасности или обновлений «{cleanDomain}».");
        }

        var hostsPath = _platformBridge.GetHostsFilePath();
        try
        {
            var prevText = File.Exists(hostsPath) ? await File.ReadAllTextAsync(hostsPath, ct).ConfigureAwait(false) : "";
            var nextText = NetworkAndHostsInspector.AppendRuleToHostsText(prevText, redirectIp.Trim(), cleanDomain);

            await using var tx = _vaultService.BeginTransaction(
                SystemDomain.Optimizer,
                friendlyTitle: $"Добавлено правило hosts: {redirectIp.Trim()} -> {cleanDomain}",
                friendlySummary: "Изменение системного файла hosts с полной копией предыдущей версии в Машине времени.",
                technicalDetails: hostsPath);

            tx.RecordStateDelta(
                StateTargetKind.SystemSetting,
                "HostsSabotageCleanup",
                previousStateJson: JsonSerializer.Serialize(new { Path = hostsPath, Content = prevText }),
                newStateJson: JsonSerializer.Serialize(new { Path = hostsPath, Added = $"{redirectIp.Trim()} {cleanDomain}" }));

            await File.WriteAllTextAsync(hostsPath, nextText, new UTF8Encoding(false), ct).ConfigureAwait(false);
            var committed = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);
            _ = await _platformBridge.FlushDnsCacheAsync(ct).ConfigureAwait(false);

            return new OptimizerOperationResult(
                true,
                $"Добавлена запись hosts: {redirectIp.Trim()} → {cleanDomain} (бекап сохранен).",
                RollbackSessionId: committed.SessionId);
        }
        catch (UnauthorizedAccessException)
        {
            return new OptimizerOperationResult(false, "Для редактирования системного файла hosts запустите программу от имени Администратора.");
        }
        catch (Exception ex)
        {
            return new OptimizerOperationResult(false, $"Ошибка записи файла hosts: {ex.Message}");
        }
    }

    public async Task<OptimizerOperationResult> RemoveHostsEntryAsync(
        HostsRedirectEntry entry,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(entry);
        var hostsPath = _platformBridge.GetHostsFilePath();
        if (!File.Exists(hostsPath))
        {
            return new OptimizerOperationResult(false, "Файл hosts не найден.");
        }

        try
        {
            var prevText = await File.ReadAllTextAsync(hostsPath, ct).ConfigureAwait(false);
            var nextText = NetworkAndHostsInspector.RemoveDomainFromHostsText(prevText, entry.RedirectIp, entry.DomainHost);

            await using var tx = _vaultService.BeginTransaction(
                SystemDomain.Optimizer,
                friendlyTitle: $"Удалено правило hosts: {entry.RedirectIp} -> {entry.DomainHost}",
                friendlySummary: "Очистка правила перенаправления в файле hosts.",
                technicalDetails: hostsPath);

            tx.RecordStateDelta(
                StateTargetKind.SystemSetting,
                "HostsSabotageCleanup",
                previousStateJson: JsonSerializer.Serialize(new { Path = hostsPath, Content = prevText }),
                newStateJson: JsonSerializer.Serialize(new { Path = hostsPath, Removed = $"{entry.RedirectIp} {entry.DomainHost}" }));

            await File.WriteAllTextAsync(hostsPath, nextText, new UTF8Encoding(false), ct).ConfigureAwait(false);
            var committed = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);
            _ = await _platformBridge.FlushDnsCacheAsync(ct).ConfigureAwait(false);

            return new OptimizerOperationResult(
                true,
                $"Удалена запись hosts: {entry.RedirectIp} → {entry.DomainHost}.",
                RollbackSessionId: committed.SessionId);
        }
        catch (UnauthorizedAccessException)
        {
            return new OptimizerOperationResult(false, "Для изменения системного файла hosts требуются права Администратора.");
        }
        catch (Exception ex)
        {
            return new OptimizerOperationResult(false, $"Ошибка изменения файла hosts: {ex.Message}");
        }
    }

    // ==================== ДЕИНСТАЛЛЯТОР WIN32 И МЕНЕДЖЕР UWP ПРИЛОЖЕНИЙ ====================

    public Task<IReadOnlyList<InstalledApplicationInfo>> GetInstalledApplicationsAsync(CancellationToken ct = default) =>
        _platformBridge.GetInstalledApplicationsAsync(ct);

    public async Task<OptimizerOperationResult> LaunchApplicationUninstallerAsync(
        InstalledApplicationInfo app,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(app);
        if (string.IsNullOrWhiteSpace(app.UninstallString))
        {
            return new OptimizerOperationResult(false, $"У программы «{app.DisplayName}» не указана команда удаления.");
        }

        var ok = await _platformBridge.LaunchApplicationUninstallerAsync(app, ct).ConfigureAwait(false);
        return ok
            ? new OptimizerOperationResult(true, $"Запущен штатный деинсталлятор «{app.DisplayName}».")
            : new OptimizerOperationResult(false, $"Не удалось запустить деинсталлятор «{app.DisplayName}» (проверьте права Администратора).");
    }

    public async Task<IReadOnlyList<UwpPackageInfo>> GetInstalledUwpPackagesAsync(
        bool includeFrameworks = false,
        CancellationToken ct = default)
    {
        var all = await _platformBridge.GetInstalledUwpPackagesAsync(ct).ConfigureAwait(false);
        return includeFrameworks
            ? all
            : all.Where(p => !p.IsFrameworkOrSystem).ToList();
    }

    public async Task<OptimizerOperationResult> RemoveSelectedUwpPackagesAsync(
        IReadOnlyList<UwpPackageInfo> selectedPackages,
        CancellationToken ct = default)
    {
        if (selectedPackages.Count == 0)
        {
            return new OptimizerOperationResult(false, "Отметьте галочками хотя бы одно UWP-приложение для удаления.");
        }

        var removable = selectedPackages.Where(p => p.CanRemoveSafely).ToList();
        if (removable.Count == 0)
        {
            return new OptimizerOperationResult(
                false,
                "Выбранные пакеты являются системными библиотеками (VCLibs / .NET Native / Store) и защищены от удаления.");
        }

        var (removed, err) = await _platformBridge.RemoveUwpPackagesAsync(removable, ct).ConfigureAwait(false);
        var errNote = !string.IsNullOrWhiteSpace(err) ? $" ({err})" : "";
        return new OptimizerOperationResult(
            removed > 0,
            removed > 0
                ? $"Удалено встроенных UWP-приложений: {removed} из {removable.Count}{errNote}."
                : $"Не удалось удалить выбранные UWP-приложения{errNote}.");
    }
}
