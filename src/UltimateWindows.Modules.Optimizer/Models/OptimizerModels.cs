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
    IReadOnlyList<TweakRegistryMutation> Mutations)
{
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
    bool IsCurrentlyApplied);

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
    Guid? RollbackSessionId = null);
