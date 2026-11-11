using UltimateWindows.Core.Enums;
using UltimateWindows.Core.Models;

namespace UltimateWindows.Modules.Optimizer.Models;

public enum TweakCategory
{
    SystemAndPerformance = 0,
    DiskAndFileSystem = 1,
    AppTelemetry = 2,
    QuietBackgroundAndAds = 3,
    UiAndResponsiveness = 4,
    GamingAndLatency = 5,
    SecurityAndClarity = 6
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

    /// <summary>Твик не имеет смысла на этой версии Windows. Включить его нельзя.</summary>
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
public sealed record TweakRequirements(
    int? MinWindowsBuild = null,
    int? MaxWindowsBuild = null,
    bool BestOnSolidStateSystemDrive = false,
    string? BatteryWarning = null)
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

public sealed record TweakRegistryMutation(
    string Hive,
    string SubKeyPath,
    string ValueName,
    RegistryTweakValueKind ValueKind,
    string DesiredSerializedValue,
    string DefaultRestoreSerializedValue,
    bool ExistedByDefault = false);

public sealed record DeclarativeTweakRule(
    string TweakId,
    TweakCategory Category,
    string IconGlyph,
    string FriendlyTitle,
    string FriendlyExplanation,
    string ImpactBadge,
    RiskLevel Risk,
    bool RequiresAdministrator,
    IReadOnlyList<TweakRegistryMutation> Mutations,
    TweakRequirements? Requirements = null)
{
    /// <summary>Условия применимости; если не заданы, твик подходит любой системе.</summary>
    public TweakRequirements EffectiveRequirements => Requirements ?? TweakRequirements.None;

    /// <summary>
    /// Опасный твик ослабляет защиту или устойчивость Windows. Он никогда не входит в наборы
    /// и применяется только после отдельного подтверждения.
    /// </summary>
    public bool IsDangerous => Risk >= RiskLevel.High;

    public string ExpertMutationsPreview => string.Join(
        "  •  ",
        Mutations.Select(m => $@"{m.Hive}\{m.SubKeyPath} :: {(string.IsNullOrEmpty(m.ValueName) ? "(Default)" : m.ValueName)} = {m.DesiredSerializedValue}"));

    public string CategoryDisplayName => Category switch
    {
        TweakCategory.SystemAndPerformance => "Система",
        TweakCategory.DiskAndFileSystem => "Дисковый привод и SSD",
        TweakCategory.AppTelemetry => "Телеметрия приложений",
        TweakCategory.QuietBackgroundAndAds => "Конфиденциальность и реклама",
        TweakCategory.UiAndResponsiveness => "Интерфейс Windows 10 / 11",
        TweakCategory.GamingAndLatency => "Игры, мышь и сеть",
        TweakCategory.SecurityAndClarity => "Безопасность и сеть",
        _ => "Система"
    };
}

public sealed record EvaluatedTweakState(
    DeclarativeTweakRule Rule,
    bool IsCurrentlyApplied,
    TweakApplicability Applicability);

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
        "Microsoft.BingWeather" => "Погода MSN (Microsoft.BingWeather)",
        "Microsoft.BingNews" => "Новости Microsoft (Microsoft.BingNews)",
        "Microsoft.GetHelp" => "Техподдержка Get Help (Microsoft.GetHelp)",
        "Microsoft.Getstarted" => "Советы Windows (Microsoft.Getstarted)",
        "Microsoft.WindowsFeedbackHub" => "Центр отзывов (Feedback Hub)",
        "Microsoft.WindowsMaps" => "Карты Windows (Microsoft.WindowsMaps)",
        "Microsoft.ZuneVideo" => "Кино и ТВ (Microsoft.ZuneVideo)",
        "Microsoft.ZuneMusic" => "Медиаплеер Groove / Музыка (Microsoft.ZuneMusic)",
        "Microsoft.YourPhone" => "Связь с телефоном (Phone Link)",
        "Microsoft.People" => "Контакты Люди (Microsoft.People)",
        "Microsoft.MicrosoftSolitaireCollection" => "Пасьянсы Microsoft Solitaire",
        "Microsoft.MicrosoftOfficeHub" => "Промо-хаб Microsoft 365 (Office Hub)",
        "Microsoft.Todos" => "Microsoft To Do",
        "Microsoft.PowerAutomateDesktop" => "Power Automate",
        "Clipchamp.Clipchamp" => "Видеоредактор Clipchamp",
        "Microsoft.Windows.DevHome" => "Dev Home (Microsoft.Windows.DevHome)",
        "Microsoft.WindowsAlarms" => "Будильники и часы (Microsoft.WindowsAlarms)",
        "Microsoft.WindowsCamera" => "Камера Windows (Microsoft.WindowsCamera)",
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
    TweakConfirmationKind ConfirmationRequired = TweakConfirmationKind.None);
