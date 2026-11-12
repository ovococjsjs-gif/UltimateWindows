using UltimateWindows.Core.Enums;

namespace UltimateWindows.Modules.Repair.Diagnostics;

/// <summary>
/// Разделы диагностического движка Этапа 3 (Ремонт и DLL 2.0).
/// </summary>
public enum RepairSectionId
{
    WindowsUpdate = 10,
    Network = 15,
    StoreAndAppx = 20,
    StartAndSearch = 25,
    ExplorerAndShell = 30,
    SystemToolsAndPolicies = 35,
    FileAssociations = 40,
    AudioAndMedia = 50,
    PrintingAndDevices = 55,
    TimeAndRegion = 60,
    SecurityAndFirewall = 65,
    WmiAndInstaller = 70,
    CriticalServices = 75,
    InputClipboardAndFonts = 80,
    DisplayGamingAndVirtualization = 85,
    SystemFilesAndDisk = 90
}

public static class RepairSectionDisplay
{
    public static string GetTitle(RepairSectionId section) => section switch
    {
        RepairSectionId.WindowsUpdate => "Центр обновления Windows",
        RepairSectionId.Network => "Сеть, DNS и прокси",
        RepairSectionId.StoreAndAppx => "Microsoft Store и AppX",
        RepairSectionId.StartAndSearch => "Меню «Пуск», Поиск и ввод",
        RepairSectionId.ExplorerAndShell => "Проводник, Рабочий стол и Корзина",
        RepairSectionId.SystemToolsAndPolicies => "Заблокированные инструменты и политики",
        RepairSectionId.FileAssociations => "Ассоциации файлов (.exe, .lnk, .msi…)",
        RepairSectionId.AudioAndMedia => "Звук, микрофон и камера",
        RepairSectionId.PrintingAndDevices => "Печать, сканеры и USB-устройства",
        RepairSectionId.TimeAndRegion => "Время и синхронизация часов",
        RepairSectionId.SecurityAndFirewall => "Брандмауэр и защита Windows",
        RepairSectionId.WmiAndInstaller => "WMI, Windows Installer и COM",
        RepairSectionId.CriticalServices => "Базовые системные службы",
        RepairSectionId.InputClipboardAndFonts => "Клавиатура, буфер обмена и шрифты",
        RepairSectionId.DisplayGamingAndVirtualization => "Графика, игры, WSL2 и Песочница",
        RepairSectionId.SystemFilesAndDisk => "Системные файлы, CBS.log и диск",
        _ => section.ToString()
    };
}

public enum RepairHealthState
{
    Healthy = 0,
    IssueDetected = 1,
    NeedsElevation = 2,
    NotApplicable = 3,
    ProbeError = 4
}

public enum RepairSeverity
{
    Info = 0,
    Warning = 1,
    Broken = 2,
    Critical = 3
}

public enum RepairRegistryValueKind
{
    String = 1,
    ExpandString = 2,
    DWord = 4,
    MultiString = 7,
    QWord = 11,
    Binary = 3
}

public enum RepairRegistryExpectation
{
    MustNotExist = 0,
    MustEqualString = 1,
    MustContainSubstring = 2,
    MustEqualDword = 3,
    MustNotEqualDword = 4,
    MustNotEqualString = 5
}

public enum RepairRegistryFixKind
{
    DeleteValue = 0,
    SetString = 1,
    SetExpandString = 2,
    SetDword = 3
}

public enum RepairServiceStartupKind
{
    Unknown = 0,
    Automatic = 1,
    AutomaticDelayed = 2,
    Manual = 3,
    Disabled = 4
}

/// <summary>
/// Типизированная проверка и починка одного параметра реестра Windows (HKLM / HKCU / HKCR).
/// Пустое имя параметра ("") обозначает значение раздела «(По умолчанию)».
/// </summary>
public sealed record RepairRegistryCheck(
    string Hive,
    string SubKey,
    string ValueName,
    RepairRegistryExpectation Expectation,
    RepairRegistryFixKind FixKind,
    string? ExpectedString = null,
    int? ExpectedDword = null,
    string? FixString = null,
    int? FixDword = null,
    bool OnlyIfKeyExists = false);

/// <summary>
/// Типизированная проверка и восстановление режима запуска системной службы Windows.
/// </summary>
public sealed record RepairServiceCheck(
    string ServiceName,
    RepairServiceStartupKind HealthyStartup,
    bool StartIfStopped = false,
    bool RequireRunning = false,
    bool IgnoreIfMissing = true);

/// <summary>
/// Декларативное правило диагностики и ремонта из каталога Diagnostics/Data/*.json.
/// </summary>
public sealed record RepairRuleDefinition(
    string Id,
    RepairSectionId Section,
    string Title,
    string Symptom,
    string Explanation,
    string FixSummary,
    RepairSeverity Severity,
    RiskLevel Risk,
    bool RequiresAdmin,
    bool IsReversible,
    int? MinBuild,
    int? MaxBuild,
    IReadOnlyList<string> RelatedErrorCodes,
    IReadOnlyList<RepairRegistryCheck> RegistryChecks,
    IReadOnlyList<RepairServiceCheck> ServiceChecks,
    string? CustomProbe)
{
    public string SectionTitle => RepairSectionDisplay.GetTitle(Section);

    public string RiskBadge => Risk switch
    {
        RiskLevel.Safe => "Безопасно",
        RiskLevel.Low => "Малый риск",
        RiskLevel.Moderate => "Средний риск",
        RiskLevel.Attention or RiskLevel.Advanced => "С оговорками",
        RiskLevel.High or RiskLevel.Critical => "Опасно",
        _ => "Безопасно"
    };

    public string RollbackBadge => IsReversible
        ? "Откат в «Машине времени»"
        : "Операционный сброс (кэш/перезапуск)";

    public bool RequiresExplicitConfirmation =>
        Risk >= RiskLevel.Attention;
}

/// <summary>
/// Снимок значения реестра для чтения движком и сохранения в транзакцию отката.
/// </summary>
public sealed record RepairRegistryValueState(
    bool KeyExists,
    bool ValueExists,
    RepairRegistryValueKind Kind,
    string? StringValue,
    int? DwordValue,
    string? RawSerializedData);

/// <summary>
/// Снимок состояния службы Windows.
/// </summary>
public sealed record RepairServiceState(
    bool Exists,
    RepairServiceStartupKind Startup,
    bool IsRunning);

/// <summary>
/// Результат фазы «Обнаружить» для специальной (глубокой) системной проверки.
/// </summary>
public sealed record RepairCustomProbeResult(
    RepairHealthState State,
    string Evidence);

/// <summary>
/// Результат выполнения одного правила на текущей системе («Обнаружить + Объяснить»).
/// </summary>
public sealed record RepairCheckFinding(
    RepairRuleDefinition Rule,
    RepairHealthState State,
    string Evidence,
    DateTimeOffset CheckedAtUtc)
{
    public bool IsBroken => State == RepairHealthState.IssueDetected;
    public bool IsHealthy => State == RepairHealthState.Healthy;

    public string StateBadge => State switch
    {
        RepairHealthState.Healthy => "Исправно",
        RepairHealthState.IssueDetected => Rule.Severity switch
        {
            RepairSeverity.Critical => "Критично",
            RepairSeverity.Broken => "Сломано",
            RepairSeverity.Warning => "Отклонение",
            _ => "Найдено"
        },
        RepairHealthState.NeedsElevation => "Нужен Админ",
        RepairHealthState.NotApplicable => "Неприменимо",
        _ => "Ошибка проверки"
    };
}

/// <summary>
/// Итог цикла «Исправить → Проверить» по одному правилу.
/// </summary>
public sealed record RepairRuleFixOutcome(
    string RuleId,
    string RuleTitle,
    bool FixSucceeded,
    bool VerifiedHealthyAfterFix,
    bool RequiresReboot,
    string Message,
    RepairHealthState PostFixState,
    string PostFixEvidence);

/// <summary>
/// Сводный итог пакетного ремонта по списку правил с единой точкой отката в «Машине времени».
/// </summary>
public sealed record RepairBatchFixResult(
    int RequestedCount,
    int SucceededCount,
    int VerifiedHealthyCount,
    int FailedCount,
    int RequiresRebootCount,
    Guid? RollbackSessionId,
    string SummaryHeadline,
    IReadOnlyList<RepairRuleFixOutcome> Outcomes);
