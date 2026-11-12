using UltimateWindows.Core.Enums;
using UltimateWindows.Core.Models;

namespace UltimateWindows.Modules.Optimizer.Models;

/// <summary>
/// Раздел каталога настроек. Порядок показа и названия — в <see cref="TweakCategoryInfo"/>.
/// </summary>
public enum TweakCategory
{
    Privacy = 0,
    AdsAndSuggestions = 1,
    AiFeatures = 2,
    Explorer = 3,
    TaskbarAndStart = 4,
    Performance = 5,
    Gaming = 6,
    DiskAndStorage = 7,
    Network = 8,
    WindowsUpdate = 9,
    Security = 10,
    BackgroundServices = 11,
    Applications = 12
}

/// <summary>
/// Названия и порядок разделов каталога для интерфейса и командной строки.
/// </summary>
public static class TweakCategoryInfo
{
    public static IReadOnlyList<TweakCategory> DisplayOrder { get; } =
    [
        TweakCategory.Privacy,
        TweakCategory.AdsAndSuggestions,
        TweakCategory.AiFeatures,
        TweakCategory.Explorer,
        TweakCategory.TaskbarAndStart,
        TweakCategory.Performance,
        TweakCategory.Gaming,
        TweakCategory.DiskAndStorage,
        TweakCategory.Network,
        TweakCategory.WindowsUpdate,
        TweakCategory.Security,
        TweakCategory.BackgroundServices,
        TweakCategory.Applications
    ];

    public static string GetTitle(TweakCategory category) => category switch
    {
        TweakCategory.Privacy => "Конфиденциальность",
        TweakCategory.AdsAndSuggestions => "Реклама и подсказки",
        TweakCategory.AiFeatures => "Copilot и функции ИИ",
        TweakCategory.Explorer => "Проводник и рабочий стол",
        TweakCategory.TaskbarAndStart => "Панель задач и «Пуск»",
        TweakCategory.Performance => "Система и быстродействие",
        TweakCategory.Gaming => "Игры",
        TweakCategory.DiskAndStorage => "Диск и файловая система",
        TweakCategory.Network => "Сеть",
        TweakCategory.WindowsUpdate => "Обновления Windows",
        TweakCategory.Security => "Защита",
        TweakCategory.BackgroundServices => "Службы и фоновые задачи",
        TweakCategory.Applications => "Программы",
        _ => "Прочее"
    };

    public static int GetOrder(TweakCategory category)
    {
        for (var i = 0; i < DisplayOrder.Count; i++)
        {
            if (DisplayOrder[i] == category)
            {
                return i;
            }
        }

        return DisplayOrder.Count;
    }
}

public enum RegistryTweakValueKind
{
    DWord = 4,
    String = 1,
    BinaryHex = 3,
    DeleteValue = 99
}

public enum DnsPresetId
{
    AutomaticDhcp = 0,
    CloudflareFast = 1,
    CloudflareMalwareShield = 2,
    Quad9Security = 3,
    GooglePublic = 4,
    AdGuardClean = 5,
    YandexBasic = 6
}

/// <summary>
/// Подходит ли твик этому компьютеру.
/// </summary>
public enum TweakApplicabilityStatus
{
    /// <summary>Твик можно применять.</summary>
    Applicable = 0,

    /// <summary>Твик сработает, но на этом компьютере скорее навредит. Нужно явное согласие пользователя.</summary>
    NotRecommended = 1,

    /// <summary>Твик не имеет смысла на этом компьютере: не та версия Windows или нет нужной программы. Включить его нельзя.</summary>
    NotApplicable = 2
}

/// <summary>
/// Какое подтверждение нужно от пользователя, прежде чем твик будет применён.
/// </summary>
public enum TweakConfirmationKind
{
    None = 0,
    NotRecommendedForThisPc = 1,
    DangerousTweak = 2
}

/// <summary>
/// Что нужно сделать, чтобы изменение вступило в силу.
/// </summary>
public enum TweakRestartKind
{
    None = 0,
    ExplorerRestart = 1,
    SignOut = 2,
    Reboot = 3
}

/// <summary>
/// Сведения о компьютере, от которых зависит применимость твиков. Значение null означает «неизвестно»:
/// неизвестный факт никогда не запрещает твик.
/// </summary>
public sealed record SystemFacts(
    int? WindowsBuildNumber = null,
    bool? SystemDriveIsSolidState = null,
    bool? HasBattery = null,
    long? TotalMemoryBytes = null)
{
    public static SystemFacts Unknown { get; } = new();
}

/// <summary>
/// Вывод о применимости твика и пояснение для пользователя.
/// </summary>
public sealed record TweakApplicability(
    TweakApplicabilityStatus Status,
    string? Reason = null)
{
    public static TweakApplicability Applicable { get; } = new(TweakApplicabilityStatus.Applicable);

    public bool IsApplicable => Status == TweakApplicabilityStatus.Applicable;
}

/// <summary>
/// Условия, при которых твик имеет смысл. Пустые условия означают «подходит любой системе».
/// </summary>
/// <param name="MinWindowsBuild">Наименьшая сборка Windows, на которой параметр существует.</param>
/// <param name="MaxWindowsBuild">Наибольшая сборка Windows, на которой параметр ещё действует.</param>
/// <param name="BestOnSolidStateSystemDrive">Твик рассчитан на системный диск SSD; на жёстком диске он вредит.</param>
/// <param name="BatteryWarning">Если задано, на устройствах с батареей твик не рекомендуется; текст объясняет почему.</param>
/// <param name="InstalledAnyRegistryKey">
/// Твик относится к программе, которая может быть не установлена. Перечисляются разделы реестра вида
/// <c>HKLM\SOFTWARE\...</c>; если нет ни одного, твик считается неприменимым. Наличие проверяет сервис,
/// а не <see cref="Evaluate"/>, потому что для этого нужен доступ к реестру.
/// </param>
/// <param name="InstalledNote">Пояснение, какой программы нет (например «Google Chrome не установлен.»).</param>
public sealed record TweakRequirements(
    int? MinWindowsBuild = null,
    int? MaxWindowsBuild = null,
    bool BestOnSolidStateSystemDrive = false,
    string? BatteryWarning = null,
    IReadOnlyList<string>? InstalledAnyRegistryKey = null,
    string? InstalledNote = null)
{
    public static TweakRequirements None { get; } = new();

    public TweakApplicability Evaluate(SystemFacts facts)
    {
        ArgumentNullException.ThrowIfNull(facts);

        if (facts.WindowsBuildNumber is { } build)
        {
            if (MinWindowsBuild is { } min && build < min)
            {
                return new TweakApplicability(
                    TweakApplicabilityStatus.NotApplicable,
                    $"Нужна {DescribeWindowsBuild(min)} или новее.");
            }

            if (MaxWindowsBuild is { } max && build > max)
            {
                return new TweakApplicability(
                    TweakApplicabilityStatus.NotApplicable,
                    $"Параметр действует только до {DescribeWindowsBuild(max)}.");
            }
        }

        if (BestOnSolidStateSystemDrive && facts.SystemDriveIsSolidState == false)
        {
            return new TweakApplicability(
                TweakApplicabilityStatus.NotRecommended,
                "Системный диск — жёсткий (HDD). На нём эта настройка замедлит запуск Windows и программ.");
        }

        if (!string.IsNullOrWhiteSpace(BatteryWarning) && facts.HasBattery == true)
        {
            return new TweakApplicability(TweakApplicabilityStatus.NotRecommended, BatteryWarning);
        }

        return TweakApplicability.Applicable;
    }

    public static string DescribeWindowsBuild(int build) => build switch
    {
        >= 26200 => $"Windows 11 25H2 (сборка {build})",
        >= 26100 => $"Windows 11 24H2 (сборка {build})",
        >= 22631 => $"Windows 11 23H2 (сборка {build})",
        >= 22621 => $"Windows 11 22H2 (сборка {build})",
        >= 22000 => $"Windows 11 (сборка {build})",
        >= 19045 => $"Windows 10 22H2 (сборка {build})",
        >= 19041 => $"Windows 10 версии 2004 (сборка {build})",
        >= 10240 => $"Windows 10 (сборка {build})",
        _ => $"Windows (сборка {build})"
    };
}

/// <summary>
/// Что пользователь явно разрешил при включении твика.
/// </summary>
public sealed record TweakApplyOptions(
    bool AcceptNotRecommended = false,
    bool AcceptDangerous = false)
{
    public static TweakApplyOptions Default { get; } = new();
    public static TweakApplyOptions AcceptAll { get; } = new(AcceptNotRecommended: true, AcceptDangerous: true);
}

/// <summary>
/// Твик каталога: понятное описание и список действий (значения реестра, службы, задания планировщика).
/// </summary>
public sealed record DeclarativeTweakRule(
    string TweakId,
    TweakCategory Category,
    string FriendlyTitle,
    string FriendlyExplanation,
    RiskLevel Risk,
    IReadOnlyList<TweakAction> Actions,
    TweakRequirements? Requirements = null,
    TweakRestartKind Restart = TweakRestartKind.None)
{
    /// <summary>Условия применимости; если не заданы, твик подходит любой системе.</summary>
    public TweakRequirements EffectiveRequirements => Requirements ?? TweakRequirements.None;

    /// <summary>
    /// Опасный твик ослабляет защиту или устойчивость Windows. Он никогда не входит в наборы
    /// и применяется только после отдельного подтверждения.
    /// </summary>
    public bool IsDangerous => Risk >= RiskLevel.High;

    /// <summary>Нужны ли права администратора: да, если их требует хотя бы одно действие.</summary>
    public bool RequiresAdministrator => Actions.Any(a => a.RequiresAdministrator);

    /// <summary>Только действия с реестром — в порядке, заданном в каталоге.</summary>
    public IReadOnlyList<TweakRegistryMutation> Mutations => Actions.OfType<TweakRegistryMutation>().ToArray();

    public string ExpertMutationsPreview => string.Join("  •  ", Actions.Select(a => a.DescribeForExpert()));

    public string CategoryDisplayName => TweakCategoryInfo.GetTitle(Category);

    public string RiskDisplayName => TweakRiskInfo.GetTitle(Risk);

    public string RestartDisplayName => TweakRiskInfo.GetRestartTitle(Restart);
}

/// <summary>
/// Подписи уровней риска и видов перезапуска.
/// </summary>
public static class TweakRiskInfo
{
    public static string GetTitle(RiskLevel risk) => risk switch
    {
        RiskLevel.Safe => "Безопасно",
        RiskLevel.Low => "Есть побочный эффект",
        RiskLevel.Moderate or RiskLevel.Attention or RiskLevel.Advanced => "С оговорками",
        _ => "Опасно"
    };

    public static string GetRestartTitle(TweakRestartKind restart) => restart switch
    {
        TweakRestartKind.ExplorerRestart => "после перезапуска Проводника",
        TweakRestartKind.SignOut => "после повторного входа в Windows",
        TweakRestartKind.Reboot => "после перезагрузки",
        _ => ""
    };

    public static TweakRestartKind Strongest(TweakRestartKind a, TweakRestartKind b) => a >= b ? a : b;
}

/// <summary>
/// В каком состоянии твик на этом компьютере.
/// </summary>
public enum TweakStateKind
{
    /// <summary>Ни одно действие не применено.</summary>
    NotApplied = 0,

    /// <summary>Все действия, цели которых есть в системе, применены.</summary>
    Applied = 1,

    /// <summary>Применена только часть действий.</summary>
    Partial = 2,

    /// <summary>В системе нет ни одной цели твика (например, нет таких служб и заданий).</summary>
    Unavailable = 3
}

public sealed record EvaluatedTweakState(
    DeclarativeTweakRule Rule,
    TweakStateKind State,
    TweakApplicability Applicability,
    int AppliedActionCount = 0,
    int PresentActionCount = 0)
{
    public bool IsCurrentlyApplied => State == TweakStateKind.Applied;

    public bool IsPartiallyApplied => State == TweakStateKind.Partial;
}

public sealed record StartupEntryInfo(
    string EntryId,
    string DisplayName,
    string CommandOrTarget,
    string? ResolvedExecutablePath,
    string LocationSource,
    bool IsEnabled,
    bool IsSignedTrusted,
    bool RequiresAdminToToggle)
{
    public string StatusBadge => IsEnabled ? "Включено" : "Отключено";
    public string SignatureBadge => IsSignedTrusted ? "Подписан" : "Без подписи";
}

public sealed record ShellContextMenuHandlerInfo(
    string Clsid,
    string HandlerName,
    string TargetScope,
    string? DllPath,
    bool IsMicrosoftBuiltIn,
    bool IsSignedTrusted,
    bool IsBlockedByPolicy)
{
    public string StateBadge => IsBlockedByPolicy ? "Скрыто из меню" : "Активно";
}

public sealed record LockingProcessInfo(
    int ProcessId,
    string ApplicationName,
    string ExecutablePath,
    string ProcessKindLabel,
    bool IsCriticalSystemProcess)
{
    public string DisplayHeadline => $"{ApplicationName} (PID {ProcessId})";
    public bool CanCloseSafely => !IsCriticalSystemProcess;
}

public sealed record DnsPresetDescriptor(
    DnsPresetId Id,
    string FriendlyName,
    string PrimaryIpv4,
    string SecondaryIpv4,
    string DohTemplateUrl,
    string FriendlyBenefit)
{
    public string ServersDisplay => Id == DnsPresetId.AutomaticDhcp
        ? "Автоматически от роутера (DHCP)"
        : $"{PrimaryIpv4}  •  {SecondaryIpv4}";
}

public sealed record NetworkLatencyReport(
    string TestedEndpoint,
    double DnsLookupMs,
    double MinRttMs,
    double AvgRttMs,
    double MaxRttMs,
    double JitterMs,
    string QualityGradeBadge,
    string FriendlyInterpretation,
    string ResolvedIp = "",
    int SentCount = 0,
    int ReceivedCount = 0,
    IReadOnlyList<string>? PacketLines = null)
{
    public int LossPercent => SentCount > 0 ? (int)Math.Round((double)(SentCount - ReceivedCount) / SentCount * 100.0) : 0;
}

public sealed record HostsRedirectEntry(
    int LineNumber,
    string RedirectIp,
    string DomainHost,
    bool IsSuspiciousSecurityBlock);

public sealed record InstalledApplicationInfo(
    string RegistryKeyPath,
    string DisplayName,
    string DisplayVersion,
    string Publisher,
    string? InstallLocation,
    string? UninstallString,
    long EstimatedSizeBytes)
{
    public string PublisherAndVersion => string.IsNullOrWhiteSpace(DisplayVersion)
        ? Publisher
        : $"{Publisher} • v{DisplayVersion}";

    public string FormattedSize => EstimatedSizeBytes > 0 ? ByteFormatter.Format(EstimatedSizeBytes) : "—";
    public bool HasUninstaller => !string.IsNullOrWhiteSpace(UninstallString);
}

public sealed record UwpPackageInfo(
    string Name,
    string PackageFullName,
    string Version,
    string Publisher,
    string InstallLocation,
    bool IsFrameworkOrSystem,
    bool NonRemovable)
{
    public bool CanRemoveSafely => !NonRemovable && !IsFrameworkOrSystem;

    public string FriendlyDisplayName => Name switch
    {
        "Microsoft.BingWeather" => "Погода MSN",
        "Microsoft.BingNews" => "Новости Microsoft",
        "Microsoft.GetHelp" => "Техподдержка Get Help",
        "Microsoft.Getstarted" => "Советы Windows",
        "Microsoft.WindowsFeedbackHub" => "Центр отзывов (Feedback Hub)",
        "Microsoft.WindowsMaps" => "Карты Windows",
        "Microsoft.ZuneVideo" => "Кино и ТВ",
        "Microsoft.ZuneMusic" => "Медиаплеер Groove / Музыка",
        "Microsoft.YourPhone" => "Связь с телефоном (Phone Link)",
        "Microsoft.People" => "Контакты Люди",
        "Microsoft.MicrosoftSolitaireCollection" => "Пасьянсы Microsoft Solitaire",
        "Microsoft.MicrosoftOfficeHub" => "Промо-хаб Microsoft 365 (Office Hub)",
        "Microsoft.Todos" => "Microsoft To Do",
        "Microsoft.PowerAutomateDesktop" => "Power Automate",
        "Clipchamp.Clipchamp" => "Видеоредактор Clipchamp",
        "Microsoft.Windows.DevHome" => "Dev Home",
        "Microsoft.WindowsAlarms" => "Будильники и часы",
        "Microsoft.WindowsCamera" => "Камера Windows",
        "Microsoft.WindowsSoundRecorder" => "Запись голоса (Sound Recorder)",
        "Microsoft.WindowsCommunicationsApps" => "Почта и Календарь (Mail & Calendar)",
        "Microsoft.XboxGamingOverlay" => "Оверлей Xbox Game Bar",
        "Microsoft.GamingApp" => "Приложение Xbox",
        _ => Name
    };
}

public sealed record OptimizerOperationResult(
    bool Succeeded,
    string UserFriendlyMessage,
    string TechnicalDetails = "",
    Guid? RollbackSessionId = null,
    TweakConfirmationKind ConfirmationRequired = TweakConfirmationKind.None,
    TweakRestartKind RestartRequired = TweakRestartKind.None);
