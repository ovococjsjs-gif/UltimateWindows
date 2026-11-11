using System.Text.Json;
using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Optimizer.Contracts;
using UltimateWindows.Modules.Optimizer.Models;

namespace UltimateWindows.Modules.Optimizer.Services;

/// <summary>
/// Запись для «Машины времени»: что было у цели до изменения и что стало.
/// </summary>
internal sealed record PendingDelta(
    StateTargetKind TargetKind,
    string TargetPath,
    string PreviousStateJson,
    string NewStateJson);

internal enum RuleOutcomeKind
{
    /// <summary>Хотя бы одно действие изменило систему, и все изменения проверены.</summary>
    Changed = 0,

    /// <summary>Менять нечего: все цели уже в нужном состоянии.</summary>
    AlreadyInState = 1,

    /// <summary>В системе нет ни одной цели твика.</summary>
    Unavailable = 2,

    /// <summary>Одно из действий не удалось; всё, что успели изменить, возвращено обратно.</summary>
    Failed = 3
}

/// <summary>
/// Движок действий твика. Для каждой цели выполняет один и тот же цикл:
/// снять состояние → изменить → прочитать заново и убедиться → при сбое вернуть всё, что уже изменено.
/// Твик применяется целиком или не применяется вовсе; «частично успешных» твиков не бывает.
/// </summary>
internal sealed class TweakEngine
{
    /// <summary>Сколько опустевших разделов подряд можно убрать при возврате к стандарту.</summary>
    private const int MaxPrunedKeyLevels = 2;

    /// <summary>Разделы короче этой глубины (например <c>Software\Classes\CLSID</c>) не удаляются никогда.</summary>
    private const int MinPrunableKeyDepth = 4;

    private static readonly IReadOnlyDictionary<string, ScheduledTaskSnapshot> NoTasks =
        new Dictionary<string, ScheduledTaskSnapshot>(StringComparer.OrdinalIgnoreCase);

    private readonly IOptimizerPlatformBridge _bridge;

    public TweakEngine(IOptimizerPlatformBridge bridge)
    {
        _bridge = bridge;
    }

    /// <summary>
    /// Состояние цели одного действия на момент проверки. Хранит всё нужное, чтобы вернуть цель обратно.
    /// </summary>
    internal sealed record ActionProbe(
        TweakAction Action,
        bool TargetExists,
        bool IsDesired,
        bool IsDefault,
        bool ValueExisted = false,
        int ValueKindCode = 0,
        string? ValueData = null,
        ServiceStartupMode? Startup = null,
        bool? TaskEnabled = null);

    /// <summary>
    /// Применённый твик: какие действия изменили систему и как их вернуть.
    /// </summary>
    internal sealed class RuleApplication
    {
        private readonly TweakEngine _engine;
        private readonly List<AppliedAction> _applied;

        internal RuleApplication(
            TweakEngine engine,
            DeclarativeTweakRule rule,
            RuleOutcomeKind kind,
            List<AppliedAction> applied,
            int absentCount,
            string? failureReason)
        {
            _engine = engine;
            Rule = rule;
            Kind = kind;
            _applied = applied;
            AbsentCount = absentCount;
            FailureReason = failureReason;
        }

        public DeclarativeTweakRule Rule { get; }
        public RuleOutcomeKind Kind { get; }
        public int ChangedCount => _applied.Count;
        public int AbsentCount { get; }
        public string? FailureReason { get; }

        public IEnumerable<PendingDelta> Deltas => _applied.Select(a => a.Delta);

        /// <summary>Службы, которые твик только что отключил: их стоит остановить, не дожидаясь перезагрузки.</summary>
        public IEnumerable<string> ServicesSwitchedToDisabled => _applied
            .Where(a => a.Action is TweakServiceAction && a.NewStartup == ServiceStartupMode.Disabled)
            .Select(a => ((TweakServiceAction)a.Action).ServiceName);

        /// <summary>Возвращает всё изменённое в прежнее состояние, в обратном порядке.</summary>
        public void Undo()
        {
            for (var i = _applied.Count - 1; i >= 0; i--)
            {
                _engine.Restore(_applied[i].Before, _applied[i].CreatedKeyPath);
            }

            _applied.Clear();
        }
    }

    internal sealed record AppliedAction(
        TweakAction Action,
        ActionProbe Before,
        string? CreatedKeyPath,
        ServiceStartupMode? NewStartup,
        PendingDelta Delta);

    // ---------------------------------------------------------------------------------------------
    // Чтение состояния
    // ---------------------------------------------------------------------------------------------

    /// <summary>
    /// Состояние всех заданий планировщика, упомянутых в правилах, за одно подключение к планировщику.
    /// </summary>
    public IReadOnlyDictionary<string, ScheduledTaskSnapshot> QueryTasks(IEnumerable<DeclarativeTweakRule> rules)
    {
        var paths = rules
            .SelectMany(r => r.Actions)
            .OfType<TweakScheduledTaskAction>()
            .Select(t => t.TaskPath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (paths.Length == 0)
        {
            return NoTasks;
        }

        try
        {
            var found = _bridge.QueryScheduledTasks(paths);
            return found.Count == 0
                ? NoTasks
                : new Dictionary<string, ScheduledTaskSnapshot>(found, StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception)
        {
            // Планировщик недоступен: считаем, что заданий нет, и не трогаем их
            return NoTasks;
        }
    }

    public ActionProbe Probe(TweakAction action, IReadOnlyDictionary<string, ScheduledTaskSnapshot> tasks)
    {
        switch (action)
        {
            case TweakRegistryMutation m:
            {
                var (exists, kindCode, data) = _bridge.ReadRegistryValue(m.Hive, m.SubKeyPath, m.ValueName);
                var isDesired = exists && SameData(data, m.DesiredSerializedValue);
                var isDefault = m.ExistedByDefault
                    ? exists && SameData(data, m.DefaultRestoreSerializedValue)
                    : !exists;
                return new ActionProbe(action, TargetExists: true, isDesired, isDefault, exists, kindCode, data);
            }

            case TweakServiceAction s:
            {
                var config = SafeQueryService(s.ServiceName);
                return config is null
                    ? new ActionProbe(action, TargetExists: false, IsDesired: false, IsDefault: false)
                    : new ActionProbe(
                        action,
                        TargetExists: true,
                        IsDesired: config.Startup == s.DesiredStartup,
                        IsDefault: config.Startup == s.DefaultStartup,
                        Startup: config.Startup);
            }

            case TweakScheduledTaskAction t:
            {
                return tasks.TryGetValue(t.TaskPath, out var snapshot)
                    ? new ActionProbe(
                        action,
                        TargetExists: true,
                        IsDesired: snapshot.Enabled == t.DesiredEnabled,
                        IsDefault: snapshot.Enabled == t.DefaultEnabled,
                        TaskEnabled: snapshot.Enabled)
                    : new ActionProbe(action, TargetExists: false, IsDesired: false, IsDefault: false);
            }

            default:
                return new ActionProbe(action, TargetExists: false, IsDesired: false, IsDefault: false);
        }
    }

    public (TweakStateKind State, int Applied, int Present) Evaluate(
        DeclarativeTweakRule rule,
        IReadOnlyDictionary<string, ScheduledTaskSnapshot> tasks)
    {
        var present = 0;
        var applied = 0;
        foreach (var action in rule.Actions)
        {
            var probe = Probe(action, tasks);
            if (!probe.TargetExists)
            {
                continue;
            }

            present++;
            if (probe.IsDesired)
            {
                applied++;
            }
        }

        var state = present == 0
            ? TweakStateKind.Unavailable
            : applied == present
                ? TweakStateKind.Applied
                : applied == 0
                    ? TweakStateKind.NotApplied
                    : TweakStateKind.Partial;

        return (state, applied, present);
    }

    public TweakActionState Describe(TweakAction action, IReadOnlyDictionary<string, ScheduledTaskSnapshot> tasks)
    {
        var probe = Probe(action, tasks);
        switch (action)
        {
            case TweakRegistryMutation m:
            {
                var currentKind = probe.ValueExisted && probe.ValueKindCode == (int)RegistryTweakValueKind.DWord
                    ? RegistryTweakValueKind.DWord
                    : probe.ValueExisted && probe.ValueKindCode == (int)RegistryTweakValueKind.String
                        ? RegistryTweakValueKind.String
                        : RegistryTweakValueKind.BinaryHex;
                return new TweakActionState(
                    action,
                    "Реестр",
                    m.DisplayTarget,
                    TargetExists: true,
                    probe.IsDesired,
                    probe.ValueExisted ? TweakRegistryMutation.FormatData(currentKind, probe.ValueData) : "(нет значения)",
                    TweakRegistryMutation.FormatData(m.ValueKind, m.DesiredSerializedValue),
                    m.ExistedByDefault
                        ? TweakRegistryMutation.FormatData(m.ValueKind, m.DefaultRestoreSerializedValue)
                        : "(нет значения)");
            }

            case TweakServiceAction s:
                return new TweakActionState(
                    action,
                    "Служба",
                    s.ServiceName,
                    probe.TargetExists,
                    probe.IsDesired,
                    probe.Startup is { } startup ? ServiceDisplay.GetTitle(startup) : "(службы нет в этой системе)",
                    ServiceDisplay.GetTitle(s.DesiredStartup),
                    ServiceDisplay.GetTitle(s.DefaultStartup));

            case TweakScheduledTaskAction t:
                return new TweakActionState(
                    action,
                    "Задание",
                    t.TaskPath,
                    probe.TargetExists,
                    probe.IsDesired,
                    probe.TaskEnabled is { } enabled ? TweakScheduledTaskAction.FormatEnabled(enabled) : "(задания нет в этой системе)",
                    TweakScheduledTaskAction.FormatEnabled(t.DesiredEnabled),
                    TweakScheduledTaskAction.FormatEnabled(t.DefaultEnabled));

            default:
                return new TweakActionState(action, "Действие", action.TargetKey, false, false, "—", "—", "—");
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Применение
    // ---------------------------------------------------------------------------------------------

    /// <summary>
    /// Приводит все цели твика к желаемому состоянию (<paramref name="enable"/> = true) или к состоянию чистой Windows.
    /// </summary>
    public RuleApplication ApplyRule(DeclarativeTweakRule rule, bool enable)
    {
        var applied = new List<AppliedAction>();
        var absent = 0;
        var tasks = QueryTasks([rule]);

        foreach (var action in rule.Actions)
        {
            ActionProbe before;
            try
            {
                before = Probe(action, tasks);
            }
            catch (Exception ex)
            {
                return Fail(rule, applied, absent, $"{DescribeTarget(action)}: не удалось прочитать текущее состояние ({ex.Message})");
            }

            if (!before.TargetExists)
            {
                absent++;
                continue;
            }

            if (enable ? before.IsDesired : before.IsDefault)
            {
                continue;
            }

            string? createdKeyPath = null;
            if (action is TweakRegistryMutation registry && enable)
            {
                createdKeyPath = SafeFindFirstMissingKey(registry);
            }

            PlatformActionResult result;
            try
            {
                result = Change(action, enable);
            }
            catch (Exception ex)
            {
                result = PlatformActionResult.Fail(ex.Message);
            }

            var verified = result.Succeeded && IsInTargetState(action, enable);
            if (!verified)
            {
                // Само действие могло успеть изменить цель наполовину — возвращаем и её
                Restore(before, createdKeyPath);
                var reason = result.Succeeded
                    ? "Windows не сохранила изменение (значение защищено системой или политикой организации)"
                    : result.Error ?? "нет доступа";
                return Fail(rule, applied, absent, $"{DescribeTarget(action)}: {reason}");
            }

            applied.Add(new AppliedAction(
                action,
                before,
                createdKeyPath,
                action is TweakServiceAction service ? (enable ? service.DesiredStartup : service.DefaultStartup) : null,
                BuildDelta(action, before, createdKeyPath, enable)));
        }

        var kind = applied.Count > 0
            ? RuleOutcomeKind.Changed
            : absent == rule.Actions.Count
                ? RuleOutcomeKind.Unavailable
                : RuleOutcomeKind.AlreadyInState;

        return new RuleApplication(this, rule, kind, applied, absent, failureReason: null);
    }

    private RuleApplication Fail(DeclarativeTweakRule rule, List<AppliedAction> applied, int absent, string reason)
    {
        for (var i = applied.Count - 1; i >= 0; i--)
        {
            Restore(applied[i].Before, applied[i].CreatedKeyPath);
        }

        return new RuleApplication(this, rule, RuleOutcomeKind.Failed, [], absent, reason);
    }

    private PlatformActionResult Change(TweakAction action, bool enable)
    {
        switch (action)
        {
            case TweakRegistryMutation m when enable:
                return FromBool(
                    _bridge.WriteRegistryValue(m.Hive, m.SubKeyPath, m.ValueName, m.ValueKind, m.DesiredSerializedValue),
                    "нет доступа к разделу реестра");

            case TweakRegistryMutation m when m.ExistedByDefault:
                return FromBool(
                    _bridge.WriteRegistryValue(m.Hive, m.SubKeyPath, m.ValueName, m.ValueKind, m.DefaultRestoreSerializedValue),
                    "нет доступа к разделу реестра");

            case TweakRegistryMutation m:
            {
                var deleted = _bridge.WriteRegistryValue(m.Hive, m.SubKeyPath, m.ValueName, RegistryTweakValueKind.DeleteValue, "");
                if (deleted && m.RemoveEmptyKeyOnRestore)
                {
                    PruneEmptyKeys(m.Hive, m.SubKeyPath);
                }

                return FromBool(deleted, "нет доступа к разделу реестра");
            }

            case TweakServiceAction s:
                return _bridge.SetServiceStartup(s.ServiceName, enable ? s.DesiredStartup : s.DefaultStartup);

            case TweakScheduledTaskAction t:
                return _bridge.SetScheduledTaskEnabled(t.TaskPath, enable ? t.DesiredEnabled : t.DefaultEnabled);

            default:
                return PlatformActionResult.Fail("действие неизвестного вида");
        }
    }

    private bool IsInTargetState(TweakAction action, bool enable)
    {
        try
        {
            var tasks = action is TweakScheduledTaskAction ? QueryTasksFor(action) : NoTasks;
            var probe = Probe(action, tasks);
            return probe.TargetExists && (enable ? probe.IsDesired : probe.IsDefault);
        }
        catch (Exception)
        {
            return false;
        }
    }

    private IReadOnlyDictionary<string, ScheduledTaskSnapshot> QueryTasksFor(TweakAction action)
    {
        if (action is not TweakScheduledTaskAction task)
        {
            return NoTasks;
        }

        var found = _bridge.QueryScheduledTasks([task.TaskPath]);
        return new Dictionary<string, ScheduledTaskSnapshot>(found, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Возвращает цель в состояние, записанное в <paramref name="before"/>. Сбой здесь не бросает исключений:
    /// метод вызывается при отмене, и одна неудача не должна мешать вернуть остальное.
    /// </summary>
    internal void Restore(ActionProbe before, string? createdKeyPath)
    {
        try
        {
            switch (before.Action)
            {
                case TweakRegistryMutation m when before.ValueExisted:
                    _bridge.WriteRegistryValue(
                        m.Hive,
                        m.SubKeyPath,
                        m.ValueName,
                        ToWritableKind(before.ValueKindCode, m.ValueKind),
                        before.ValueData ?? "");
                    break;

                case TweakRegistryMutation m:
                    _bridge.WriteRegistryValue(m.Hive, m.SubKeyPath, m.ValueName, RegistryTweakValueKind.DeleteValue, "");
                    RemoveCreatedKeys(m.Hive, m.SubKeyPath, createdKeyPath);
                    break;

                case TweakServiceAction s when before.Startup is { } startup:
                    _bridge.SetServiceStartup(s.ServiceName, startup);
                    break;

                case TweakScheduledTaskAction t when before.TaskEnabled is { } enabled:
                    _bridge.SetScheduledTaskEnabled(t.TaskPath, enabled);
                    break;
            }
        }
        catch (Exception)
        {
            // Отмена выполняется по принципу «сделать всё возможное»
        }
    }

    private static PendingDelta BuildDelta(TweakAction action, ActionProbe before, string? createdKeyPath, bool enable)
    {
        switch (action)
        {
            case TweakRegistryMutation m:
                return new PendingDelta(
                    StateTargetKind.RegistryValue,
                    $@"{m.Hive}\{m.SubKeyPath} :: {m.ValueName}",
                    JsonSerializer.Serialize(new
                    {
                        Hive = m.Hive,
                        SubKey = m.SubKeyPath,
                        ValueName = m.ValueName,
                        ExistedBefore = before.ValueExisted,
                        ValueKind = before.ValueExisted ? before.ValueKindCode : (int)m.ValueKind,
                        SerializedData = before.ValueData,
                        CreatedKeyPath = createdKeyPath
                    }),
                    JsonSerializer.Serialize(new { Enabled = enable }));

            case TweakServiceAction s:
                return new PendingDelta(
                    StateTargetKind.WindowsService,
                    s.ServiceName,
                    JsonSerializer.Serialize(new
                    {
                        ServiceName = s.ServiceName,
                        Startup = (before.Startup ?? s.DefaultStartup).ToString()
                    }),
                    JsonSerializer.Serialize(new { Startup = (enable ? s.DesiredStartup : s.DefaultStartup).ToString() }));

            case TweakScheduledTaskAction t:
                return new PendingDelta(
                    StateTargetKind.ScheduledTask,
                    t.TaskPath,
                    JsonSerializer.Serialize(new { TaskPath = t.TaskPath, Enabled = before.TaskEnabled ?? t.DefaultEnabled }),
                    JsonSerializer.Serialize(new { Enabled = enable ? t.DesiredEnabled : t.DefaultEnabled }));

            default:
                throw new InvalidOperationException("Действие неизвестного вида нельзя записать в журнал отката.");
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Вспомогательное
    // ---------------------------------------------------------------------------------------------

    public static string DescribeTarget(TweakAction action) => action switch
    {
        TweakRegistryMutation m => $"значение реестра {m.DisplayTarget}",
        TweakServiceAction s => $"служба «{s.ServiceName}»",
        TweakScheduledTaskAction t => $"задание «{t.TaskPath}»",
        _ => "неизвестная цель"
    };

    private void PruneEmptyKeys(string hive, string subKeyPath)
    {
        var path = subKeyPath;
        for (var level = 0; level < MaxPrunedKeyLevels; level++)
        {
            if (KeyDepth(path) < MinPrunableKeyDepth || !SafeDeleteKeyIfEmpty(hive, path))
            {
                return;
            }

            path = ParentKey(path);
        }
    }

    /// <summary>
    /// Убирает разделы, которые создал твик: от самого глубокого вверх до <paramref name="createdKeyPath"/> включительно,
    /// и только пока раздел пуст.
    /// </summary>
    private void RemoveCreatedKeys(string hive, string subKeyPath, string? createdKeyPath)
    {
        if (string.IsNullOrWhiteSpace(createdKeyPath))
        {
            return;
        }

        var path = subKeyPath;
        while (path.Length >= createdKeyPath.Length && path.StartsWith(createdKeyPath, StringComparison.OrdinalIgnoreCase))
        {
            if (!SafeDeleteKeyIfEmpty(hive, path) || path.Length == createdKeyPath.Length)
            {
                return;
            }

            path = ParentKey(path);
        }
    }

    private bool SafeDeleteKeyIfEmpty(string hive, string path)
    {
        try
        {
            return _bridge.DeleteRegistryKeyIfEmpty(hive, path);
        }
        catch (Exception)
        {
            return false;
        }
    }

    private string? SafeFindFirstMissingKey(TweakRegistryMutation m)
    {
        try
        {
            return _bridge.FindFirstMissingRegistryKey(m.Hive, m.SubKeyPath);
        }
        catch (Exception)
        {
            return null;
        }
    }

    private ServiceConfigSnapshot? SafeQueryService(string serviceName)
    {
        try
        {
            return _bridge.QueryServiceConfig(serviceName);
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static int KeyDepth(string path) => path.Split('\\', StringSplitOptions.RemoveEmptyEntries).Length;

    private static string ParentKey(string path)
    {
        var separator = path.LastIndexOf('\\');
        return separator <= 0 ? string.Empty : path[..separator];
    }

    private static bool SameData(string? current, string expected) =>
        string.Equals(current ?? "", expected, StringComparison.OrdinalIgnoreCase);

    private static PlatformActionResult FromBool(bool succeeded, string errorIfFailed) =>
        succeeded ? PlatformActionResult.Ok : PlatformActionResult.Fail(errorIfFailed);

    private static RegistryTweakValueKind ToWritableKind(int kindCode, RegistryTweakValueKind fallback) => kindCode switch
    {
        (int)RegistryTweakValueKind.DWord => RegistryTweakValueKind.DWord,
        (int)RegistryTweakValueKind.String => RegistryTweakValueKind.String,
        (int)RegistryTweakValueKind.BinaryHex => RegistryTweakValueKind.BinaryHex,
        // REG_EXPAND_SZ и прочие строковые виды мост записывает строкой
        2 => RegistryTweakValueKind.String,
        _ => fallback
    };
}
