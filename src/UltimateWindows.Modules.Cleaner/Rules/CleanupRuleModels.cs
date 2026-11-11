using UltimateWindows.Core.Models;

namespace UltimateWindows.Modules.Cleaner.Rules;

/// <summary>
/// Раздел каталога правил очистки. Названия для интерфейса — в <see cref="CleanupRuleDisplay"/>.
/// </summary>
public enum CleanupSection
{
    Windows = 0,
    Browsers = 1,
    Graphics = 2,
    Messengers = 3,
    Games = 4,
    Media = 5,
    Office = 6,
    Development = 7,
    Utilities = 8
}

/// <summary>
/// Что именно удаляет правило. От вида зависит, как о нём рассказать пользователю и какие защиты действуют.
/// </summary>
public enum CleanupDataKind
{
    Cache = 0,
    Temp = 1,
    Logs = 2,
    Dumps = 3,
    Leftovers = 4,
    History = 5,
    Cookies = 6,
    Sessions = 7,
    Other = 8
}

/// <summary>
/// Откуда правило: из встроенного каталога программы или из файла, который подключил пользователь.
/// К внешним правилам защита строже.
/// </summary>
public enum CleanupRuleOrigin
{
    BuiltIn = 0,
    External = 1
}

/// <summary>
/// Папка с файлами, которые удаляет правило.
/// </summary>
/// <param name="PathPattern">Путь, начинающийся с переменной: «%LocalAppData%\Программа\Cache». В частях пути допустимы * и ?.</param>
/// <param name="FilePatterns">Маски имён файлов; «*» — все файлы.</param>
/// <param name="Recurse">Заходить во вложенные папки.</param>
/// <param name="RemoveEmptyFolders">После удаления файлов убрать опустевшие вложенные папки.</param>
/// <param name="RemoveSelf">Убрать и саму папку, если она опустела.</param>
/// <param name="GroupCaptures">Сколько первых звёздочек пути образуют название программы (для общих правил); 0 — не группировать.</param>
public sealed record CleanupFileTarget(
    string PathPattern,
    IReadOnlyList<string> FilePatterns,
    bool Recurse,
    bool RemoveEmptyFolders,
    bool RemoveSelf,
    int GroupCaptures = 0);

/// <summary>
/// Исключение: файлы внутри этой папки, подходящие под маски, правило не трогает. Пустой список масок — вся папка.
/// </summary>
public sealed record CleanupExclusion(string PathPattern, IReadOnlyList<string> FilePatterns);

/// <summary>
/// Раздел или значение реестра, которые очищает правило (например, список недавних файлов программы).
/// </summary>
public sealed record CleanupRegistryTarget(string KeyPath, string? ValueName);

/// <summary>
/// Как понять, что программа есть на компьютере. Достаточно одного совпадения.
/// Если условий нет, программа считается установленной, когда существует хотя бы одна папка правила.
/// </summary>
public sealed record CleanupDetection(
    IReadOnlyList<string> AnyPath,
    IReadOnlyList<string> AnyRegistryKey,
    int? MinWindowsBuild = null,
    int? MaxWindowsBuild = null);

/// <summary>
/// Правило очистки: что удалить, у какой программы и чем это грозит.
/// </summary>
public sealed record CleanupRule(
    string Id,
    CleanupSection Section,
    string Application,
    string Title,
    string Explanation,
    CleanupDataKind Kind,
    bool SelectedByDefault,
    IReadOnlyList<CleanupFileTarget> Files)
{
    private static readonly IReadOnlyDictionary<string, string> NoLabels =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>Предупреждение, которое показывается перед очисткой.</summary>
    public string? Warning { get; init; }

    public CleanupDetection? Detection { get; init; }

    /// <summary>Имена процессов программы без «.exe».</summary>
    public IReadOnlyList<string> Processes { get; init; } = [];

    /// <summary>Не чистить, пока программа запущена. Для истории, cookie и сеансов действует всегда.</summary>
    public bool SkipWhileRunning { get; init; }

    /// <summary>Удалять только файлы, которые не менялись дольше этого срока.</summary>
    public int MinimumAgeHours { get; init; }

    public IReadOnlyList<CleanupExclusion> Exclusions { get; init; } = [];

    public IReadOnlyList<CleanupRegistryTarget> Registry { get; init; } = [];

    /// <summary>Для общих правил: понятные названия программ по именам их папок.</summary>
    public IReadOnlyDictionary<string, string> GroupLabels { get; init; } = NoLabels;

    public CleanupRuleOrigin Origin { get; init; } = CleanupRuleOrigin.BuiltIn;

    /// <summary>Имя файла, из которого прочитано правило.</summary>
    public string SourceName { get; init; } = "";

    public bool IsGrouped => Files.Any(f => f.GroupCaptures > 0);

    public bool MustBeClosed =>
        SkipWhileRunning || Kind is CleanupDataKind.History or CleanupDataKind.Cookies or CleanupDataKind.Sessions;

    public string SectionTitle => CleanupRuleDisplay.GetSectionTitle(Section);

    public string KindTitle => CleanupRuleDisplay.GetKindTitle(Kind);
}

/// <summary>
/// Названия разделов и видов данных для интерфейса и командной строки.
/// </summary>
public static class CleanupRuleDisplay
{
    public static string GetSectionTitle(CleanupSection section) => section switch
    {
        CleanupSection.Windows => "Windows",
        CleanupSection.Browsers => "Браузеры",
        CleanupSection.Graphics => "Видеокарта",
        CleanupSection.Messengers => "Общение и почта",
        CleanupSection.Games => "Игры и лаунчеры",
        CleanupSection.Media => "Мультимедиа",
        CleanupSection.Office => "Офис и документы",
        CleanupSection.Development => "Разработка",
        CleanupSection.Utilities => "Другие программы",
        _ => "Прочее"
    };

    public static string GetKindTitle(CleanupDataKind kind) => kind switch
    {
        CleanupDataKind.Cache => "Кэш",
        CleanupDataKind.Temp => "Временные файлы",
        CleanupDataKind.Logs => "Журналы",
        CleanupDataKind.Dumps => "Отчёты о сбоях",
        CleanupDataKind.Leftovers => "Остатки установки",
        CleanupDataKind.History => "История",
        CleanupDataKind.Cookies => "Cookie",
        CleanupDataKind.Sessions => "Сеансы",
        _ => "Прочее"
    };
}

public sealed record CleanupFoundFile(string FullPath, long SizeBytes);

/// <summary>
/// Папка, в которой после удаления файлов нужно убрать опустевшие вложенные папки.
/// </summary>
public sealed record CleanupPruneRoot(string Directory, bool RemoveEmptyFolders, bool RemoveSelf);

/// <summary>
/// Что нашлось по одному правилу. У общего правила находок несколько — по одной на программу.
/// </summary>
public sealed record CleanupRuleFinding(
    CleanupRule Rule,
    string Key,
    string Application,
    bool IsPresent,
    IReadOnlyList<CleanupFoundFile> Files,
    long TotalBytes,
    IReadOnlyList<CleanupPruneRoot> PruneRoots,
    int BlockedByProtectionCount,
    bool IsApplicationRunning,
    IReadOnlyList<string> Notes)
{
    public int FileCount => Files.Count;

    public bool HasAnythingToClean => Files.Count > 0;

    /// <summary>Есть что чистить, и программа не мешает.</summary>
    public bool CanCleanNow => HasAnythingToClean && !(IsApplicationRunning && Rule.MustBeClosed);

    public string FormattedSize => ByteFormatter.Format(TotalBytes);
}

public sealed record CleanupRuleScanResult(
    DateTimeOffset ScannedAtUtc,
    IReadOnlyList<CleanupRuleFinding> Findings,
    TimeSpan Elapsed)
{
    /// <summary>Находки по программам, которые есть на компьютере.</summary>
    public IEnumerable<CleanupRuleFinding> Present => Findings.Where(f => f.IsPresent);

    public long TotalBytes => Findings.Sum(f => f.TotalBytes);

    /// <summary>Сколько освободит очистка без изменения отметок: только правила, включённые по умолчанию.</summary>
    public long SelectedByDefaultBytes =>
        Findings.Where(f => f.Rule.SelectedByDefault && f.CanCleanNow).Sum(f => f.TotalBytes);

    public string FormattedTotal => ByteFormatter.Format(TotalBytes);

    public string FormattedSelectedByDefault => ByteFormatter.Format(SelectedByDefaultBytes);
}

public sealed record CleanupFindingOutcome(
    string Key,
    long FreedBytes,
    int DeletedFiles,
    int SkippedInUse,
    int BlockedByProtection,
    int RemovedFolders,
    string? Note);

public sealed record CleanupRuleExecutionResult(
    long FreedBytes,
    int DeletedFiles,
    int SkippedInUse,
    int BlockedByProtection,
    int RemovedFolders,
    IReadOnlyList<CleanupFindingOutcome> Outcomes)
{
    public string FormattedFreed => ByteFormatter.Format(FreedBytes);

    public string UserSummaryMessage
    {
        get
        {
            var parts = new List<string> { $"Освобождено {FormattedFreed}, удалено файлов: {DeletedFiles}" };
            if (SkippedInUse > 0)
            {
                parts.Add($"пропущено занятых программами: {SkippedInUse}");
            }

            if (BlockedByProtection > 0)
            {
                parts.Add($"не тронуто защитой: {BlockedByProtection}");
            }

            return string.Join("; ", parts) + ". Пароли, автозаполнение и закладки браузеров не затронуты.";
        }
    }
}
