using System.Globalization;

namespace UltimateWindows.Modules.Optimizer.Models;

public enum TweakActionKind
{
    Registry = 0,
    Service = 1,
    ScheduledTask = 2
}

/// <summary>
/// Одно атомарное действие твика. У каждого действия есть цель (значение реестра, служба, задание),
/// желаемое состояние и состояние чистой Windows, к которому возвращает выключение твика.
/// </summary>
public abstract record TweakAction
{
    public abstract TweakActionKind Kind { get; }

    /// <summary>Однозначное обозначение цели. Два действия одного твика не могут иметь одну цель.</summary>
    public abstract string TargetKey { get; }

    public abstract bool RequiresAdministrator { get; }

    /// <summary>Короткая техническая запись «что и на что меняется» для экспертного режима.</summary>
    public abstract string DescribeForExpert();
}

/// <summary>
/// Значение реестра. Если в чистой Windows значения нет (<see cref="ExistedByDefault"/> = false),
/// возврат к стандарту удаляет его.
/// </summary>
/// <param name="RemoveEmptyKeyOnRestore">
/// При возврате к стандарту удалить и сам раздел, если он опустел. Нужно там, где Windows реагирует
/// на само существование раздела, а не на значение.
/// </param>
public sealed record TweakRegistryMutation(
    string Hive,
    string SubKeyPath,
    string ValueName,
    RegistryTweakValueKind ValueKind,
    string DesiredSerializedValue,
    string DefaultRestoreSerializedValue,
    bool ExistedByDefault = false,
    bool RemoveEmptyKeyOnRestore = false) : TweakAction
{
    private static readonly string[] AdminOnlyUserKeyPrefixes =
    [
        @"Software\Policies\",
        @"Software\Microsoft\Windows\CurrentVersion\Policies\"
    ];

    public override TweakActionKind Kind => TweakActionKind.Registry;

    public override string TargetKey => $"registry|{Hive}|{SubKeyPath}|{ValueName}".ToUpperInvariant();

    /// <summary>
    /// Общие для всех пользователей кусты требуют прав администратора. В кусте пользователя их требуют
    /// разделы политик: обычная учётная запись может их только читать.
    /// </summary>
    public override bool RequiresAdministrator
    {
        get
        {
            if (!string.Equals(Hive, "HKCU", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            foreach (var prefix in AdminOnlyUserKeyPrefixes)
            {
                if ((SubKeyPath + @"\").StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }
    }

    public string DisplayValueName => string.IsNullOrEmpty(ValueName) ? "(По умолчанию)" : ValueName;

    public string DisplayTarget => $@"{Hive}\{SubKeyPath} :: {DisplayValueName}";

    public override string DescribeForExpert() => $"{DisplayTarget} = {FormatData(ValueKind, DesiredSerializedValue)}";

    /// <summary>
    /// Значение в привычном виде: DWORD хранится знаковым числом, а показывается беззнаковым (−1 → 4294967295).
    /// </summary>
    public static string FormatData(RegistryTweakValueKind kind, string? serialized)
    {
        if (serialized is null)
        {
            return "(нет значения)";
        }

        if (kind == RegistryTweakValueKind.DWord &&
            int.TryParse(serialized, NumberStyles.Integer, CultureInfo.InvariantCulture, out var signed))
        {
            return unchecked((uint)signed).ToString(CultureInfo.InvariantCulture);
        }

        return kind == RegistryTweakValueKind.String ? $"\"{serialized}\"" : serialized;
    }
}

/// <summary>
/// Тип запуска службы Windows. Значения 0–4 совпадают с тем, что хранит Windows; 5 — «автоматически, отложенный запуск».
/// </summary>
public enum ServiceStartupMode
{
    Boot = 0,
    System = 1,
    Automatic = 2,
    Manual = 3,
    Disabled = 4,
    AutomaticDelayed = 5
}

public enum ServiceRunState
{
    Unknown = 0,
    Stopped = 1,
    StartPending = 2,
    StopPending = 3,
    Running = 4,
    ContinuePending = 5,
    PausePending = 6,
    Paused = 7
}

public static class ServiceDisplay
{
    public static string GetTitle(ServiceStartupMode mode) => mode switch
    {
        ServiceStartupMode.Automatic => "Автоматически",
        ServiceStartupMode.AutomaticDelayed => "Автоматически (отложенный запуск)",
        ServiceStartupMode.Manual => "Вручную",
        ServiceStartupMode.Disabled => "Отключена",
        ServiceStartupMode.Boot => "При загрузке (драйвер)",
        ServiceStartupMode.System => "Системный (драйвер)",
        _ => "Неизвестно"
    };

    public static string GetTitle(ServiceRunState state) => state switch
    {
        ServiceRunState.Running => "Работает",
        ServiceRunState.Stopped => "Остановлена",
        ServiceRunState.StartPending => "Запускается",
        ServiceRunState.StopPending => "Останавливается",
        ServiceRunState.Paused => "Приостановлена",
        ServiceRunState.PausePending => "Приостанавливается",
        ServiceRunState.ContinuePending => "Возобновляется",
        _ => "Неизвестно"
    };
}

/// <summary>
/// Тип запуска службы. Служба, которой нет в этой системе, пропускается.
/// </summary>
public sealed record TweakServiceAction(
    string ServiceName,
    ServiceStartupMode DesiredStartup,
    ServiceStartupMode DefaultStartup) : TweakAction
{
    public override TweakActionKind Kind => TweakActionKind.Service;

    public override string TargetKey => $"service|{ServiceName}".ToUpperInvariant();

    public override bool RequiresAdministrator => true;

    public override string DescribeForExpert() => $"служба {ServiceName} → {ServiceDisplay.GetTitle(DesiredStartup)}";
}

/// <summary>
/// Включение или отключение задания планировщика. В чистой Windows задание находится в противоположном состоянии.
/// Задание, которого нет в этой системе, пропускается.
/// </summary>
public sealed record TweakScheduledTaskAction(
    string TaskPath,
    bool DesiredEnabled) : TweakAction
{
    public override TweakActionKind Kind => TweakActionKind.ScheduledTask;

    public override string TargetKey => $"task|{TaskPath}".ToUpperInvariant();

    public override bool RequiresAdministrator => true;

    public bool DefaultEnabled => !DesiredEnabled;

    public override string DescribeForExpert() => $"задание {TaskPath} → {FormatEnabled(DesiredEnabled)}";

    public static string FormatEnabled(bool enabled) => enabled ? "Включено" : "Отключено";
}

/// <summary>
/// Текущее состояние цели одного действия — для подробностей твика в интерфейсе и командной строке.
/// </summary>
public sealed record TweakActionState(
    TweakAction Action,
    string KindLabel,
    string TargetDisplay,
    bool TargetExists,
    bool IsInDesiredState,
    string CurrentDisplay,
    string DesiredDisplay,
    string DefaultDisplay);

/// <summary>
/// Готовый набор настроек.
/// </summary>
public sealed record TweakPresetDescriptor(
    string Key,
    string Title,
    string Description,
    IReadOnlyList<string> TweakIds);

public enum TweakBatchItemOutcome
{
    /// <summary>Настройка применена.</summary>
    Applied = 0,

    /// <summary>Настройка уже была в нужном состоянии.</summary>
    AlreadyInState = 1,

    /// <summary>Настройка пропущена: не подходит компьютеру, нужна отдельная отметка согласия или права администратора.</summary>
    Skipped = 2,

    /// <summary>Применить не удалось; изменения этой настройки отменены.</summary>
    Failed = 3
}

public sealed record TweakBatchItemResult(
    string TweakId,
    string Title,
    TweakBatchItemOutcome Outcome,
    string Note = "");

/// <summary>
/// Итог применения нескольких настроек одной операцией (набор, профиль, выбранные вручную).
/// Все применённые настройки попадают в одну запись «Машины времени» и откатываются вместе.
/// </summary>
public sealed record TweakBatchResult(
    bool Succeeded,
    string UserFriendlyMessage,
    IReadOnlyList<TweakBatchItemResult> Items,
    Guid? RollbackSessionId = null,
    TweakRestartKind RestartRequired = TweakRestartKind.None)
{
    public int AppliedCount => Items.Count(i => i.Outcome == TweakBatchItemOutcome.Applied);
    public int AlreadyInStateCount => Items.Count(i => i.Outcome == TweakBatchItemOutcome.AlreadyInState);
    public int SkippedCount => Items.Count(i => i.Outcome == TweakBatchItemOutcome.Skipped);
    public int FailedCount => Items.Count(i => i.Outcome == TweakBatchItemOutcome.Failed);
}

/// <summary>
/// Разобранный файл профиля: какие настройки он включает и какие из них этой версии программы неизвестны.
/// </summary>
public sealed record TweakProfile(
    string Name,
    IReadOnlyList<string> KnownTweakIds,
    IReadOnlyList<string> UnknownTweakIds);

/// <summary>
/// Итог обращения к Windows: удалось ли и, если нет, почему.
/// </summary>
public sealed record PlatformActionResult(bool Succeeded, string? Error = null)
{
    public static PlatformActionResult Ok { get; } = new(true);

    public static PlatformActionResult Fail(string error) => new(false, error);
}

/// <summary>Тип запуска службы в данный момент.</summary>
public sealed record ServiceConfigSnapshot(string ServiceName, ServiceStartupMode Startup);

/// <summary>Состояние задания планировщика в данный момент.</summary>
public sealed record ScheduledTaskSnapshot(string TaskPath, bool Enabled);

/// <summary>
/// Насколько опасно вмешательство в службу или задание.
/// </summary>
public enum SystemObjectProtection
{
    /// <summary>Обычный объект: изменение обратимо и работу Windows не ломает.</summary>
    None = 0,

    /// <summary>Объект защиты, обновлений или восстановления: менять можно только с отдельным подтверждением.</summary>
    WeakensProtection = 1,

    /// <summary>Без объекта Windows не загрузится или перестанет работать; лицензирование. Менять нельзя.</summary>
    Critical = 2
}

public sealed record WindowsServiceInfo(
    string ServiceName,
    string DisplayName,
    string Description,
    ServiceStartupMode Startup,
    ServiceRunState State,
    string BinaryPath,
    string Publisher,
    bool IsMicrosoft,
    string Account)
{
    public string StartupDisplay => ServiceDisplay.GetTitle(Startup);
    public string StateDisplay => ServiceDisplay.GetTitle(State);
    public bool IsRunning => State == ServiceRunState.Running;
}

public sealed record ScheduledTaskInfo(
    string TaskPath,
    string Name,
    string Folder,
    bool Enabled,
    bool IsRunning,
    DateTime? LastRunTime,
    DateTime? NextRunTime,
    string Author,
    string ActionSummary,
    bool IsMicrosoft)
{
    public string StateDisplay => IsRunning ? "Выполняется" : Enabled ? "Включено" : "Отключено";

    public string LastRunDisplay => LastRunTime is { } t ? t.ToString("dd.MM.yyyy HH:mm", CultureInfo.InvariantCulture) : "—";

    public string NextRunDisplay => NextRunTime is { } t ? t.ToString("dd.MM.yyyy HH:mm", CultureInfo.InvariantCulture) : "—";
}
