using UltimateWindows.Core.Models;
using UltimateWindows.Modules.Optimizer.Models;

namespace UltimateWindows.Modules.Apps.Models;

/// <summary>
/// Программа, для которой в официальном источнике winget доступна более свежая версия.
/// </summary>
public sealed record WingetUpgradablePackage(
    string PackageId,
    string Name,
    string InstalledVersion,
    string AvailableVersion,
    string Source,
    bool IsPinned = false)
{
    public string VersionTransitionDisplay => $"{InstalledVersion} → {AvailableVersion}";
}

/// <summary>
/// Итог выполнения операции установки или обновления через winget.
/// </summary>
public sealed record WingetOperationResult(
    bool Succeeded,
    int ExitCode,
    string PackageId,
    string DisplayTitle,
    string Summary,
    string RawOutput);

/// <summary>
/// Категория проверенной программы в каталоге первой необходимости для чистой установки Windows.
/// </summary>
public enum EssentialAppCategory
{
    UtilitiesAndArchivers = 0,
    Browsers = 1,
    MultimediaAndDocs = 2,
    CommunicationAndRemote = 3,
    GamingAndLaunchers = 4,
    DevAndSystemTools = 5
}

/// <summary>
/// Быстрые наборы подбора программ в 1 клик.
/// </summary>
public enum EssentialAppBundlePreset
{
    FreshHomeInstall = 0,
    GamerPc = 1,
    PowerUserAndDev = 2
}

/// <summary>
/// Карточка программы из встроенного каталога первой необходимости (без рекламных сборок и навязанного ПО).
/// </summary>
public sealed record EssentialAppEntry(
    string Id,
    string WingetId,
    string DisplayName,
    EssentialAppCategory Category,
    string Vendor,
    string Summary,
    IReadOnlyList<EssentialAppBundlePreset> Presets,
    string WebsiteUrl,
    bool IsOpenSource,
    IReadOnlyList<string> MatchKeywords)
{
    public string CategoryBadge => Category switch
    {
        EssentialAppCategory.UtilitiesAndArchivers => "Архиваторы и Утилиты",
        EssentialAppCategory.Browsers => "Браузеры",
        EssentialAppCategory.MultimediaAndDocs => "Медиа и Документы",
        EssentialAppCategory.CommunicationAndRemote => "Общение и Доступ",
        EssentialAppCategory.GamingAndLaunchers => "Игры и Стриминг",
        EssentialAppCategory.DevAndSystemTools => "Система и Разработка",
        _ => "Программы"
    };

    public string LicenseBadge => IsOpenSource ? "Открытый код / Бесплатно" : "Официальная бесплатная сборка";
}

/// <summary>
/// Состояние элемента каталога программ на текущем компьютере.
/// </summary>
public sealed record EssentialAppStatus(
    EssentialAppEntry Entry,
    bool IsInstalled,
    string? InstalledVersion)
{
    public string StatusBadge => IsInstalled
        ? (string.IsNullOrWhiteSpace(InstalledVersion) ? "Установлено" : $"Установлено (v{InstalledVersion})")
        : "Не установлено";
}

/// <summary>
/// Тип остаточного «хвоста» удалённой программы.
/// </summary>
public enum AppLeftoverKind
{
    AppDataDirectory = 0,
    ProgramDataDirectory = 1,
    InstallDirectoryResidue = 2,
    ShortcutFile = 3,
    RegistrySubKey = 4
}

/// <summary>
/// Найденный остаточный след удалённой или удаляемой программы.
/// </summary>
public sealed record AppLeftoverItem(
    AppLeftoverKind Kind,
    string TargetPath,
    string Reason,
    long EstimatedSizeBytes)
{
    public string KindBadge => Kind switch
    {
        AppLeftoverKind.AppDataDirectory => "Папка AppData",
        AppLeftoverKind.ProgramDataDirectory => "Папка ProgramData",
        AppLeftoverKind.InstallDirectoryResidue => "Остаток папки установки",
        AppLeftoverKind.ShortcutFile => "Ярлык (.lnk)",
        AppLeftoverKind.RegistrySubKey => "Ветка реестра",
        _ => "Остаток"
    };

    public string FormattedSize => Kind == AppLeftoverKind.RegistrySubKey
        ? "Ключ реестра"
        : ByteFormatter.Format(EstimatedSizeBytes);
}

/// <summary>
/// Результат чистого или принудительного удаления программы с помещением хвостов в карантин Машины времени.
/// </summary>
public sealed record CleanUninstallResult(
    bool Succeeded,
    Guid? SessionId,
    string AppName,
    bool UninstallerLaunched,
    int RemovedFileLeftovers,
    int RemovedRegistryLeftovers,
    long ReclaimedBytes,
    string SummaryMessage)
{
    public string FormattedReclaimed => ByteFormatter.Format(ReclaimedBytes);
}

/// <summary>
/// Сырые аппаратные и системные факты для проверки готовности к Windows 11 (24H2/25H2) и статуса поддержки Windows 10 ESU.
/// </summary>
public sealed record Win11RawHardwareFacts(
    string OsCaption,
    int OsMajorVersion,
    int OsBuildNumber,
    bool Is64BitArchitecture,
    string CpuBrand,
    int CpuCores,
    int CpuMaxClockMhz,
    bool Sse42Supported,
    bool PopcntSupported,
    long TotalRamBytes,
    long SystemDriveTotalBytes,
    bool IsUefiBoot,
    bool IsSystemDiskGpt,
    bool IsSecureBootEnabled,
    bool TpmPresent,
    string TpmSpecVersion,
    bool DirectX12AndWddm2Ready,
    bool HasConsumerEsuMarker);

/// <summary>
/// Один пункт проверки совместимости с Windows 11.
/// </summary>
public sealed record Win11CheckItem(
    string CheckId,
    string Title,
    string CurrentValue,
    string RequirementText,
    bool Passed,
    bool CanEnableWithoutNewHardware,
    string ActionHint)
{
    public string StatusBadge => Passed
        ? "Готово"
        : (CanEnableWithoutNewHardware ? "Включается в BIOS/ОС" : "Ограничение железа");
}

/// <summary>
/// Сведения о жизненном цикле текущей редакции Windows 10 / Windows 11.
/// </summary>
public sealed record WindowsLifecycleStatus(
    string CurrentOsName,
    int BuildNumber,
    bool IsWindows11,
    bool IsMainstreamSupported,
    string SupportDeadlineText,
    string EsuStatusHeadline,
    string RecommendationText);

/// <summary>
/// Полный отчёт готовности компьютера к переходу на Windows 11 и статуса поддержки текущей ОС.
/// </summary>
public sealed record Windows11ReadinessReport(
    bool IsFullyCompatible,
    int PassedCount,
    int TotalCount,
    string OverallHeadline,
    WindowsLifecycleStatus Lifecycle,
    IReadOnlyList<Win11CheckItem> Checks);

/// <summary>
/// Диагностика аккумулятора, источников пробуждения из сна и результатов проверки оперативной памяти.
/// </summary>
public sealed record PowerSleepAndRamReport(
    bool HasBattery,
    int BatteryDesignCapacityMwh,
    int BatteryFullChargeCapacityMwh,
    double BatteryWearPercent,
    string BatteryStatusHeadline,
    string LastWakeSource,
    IReadOnlyList<string> ActivePowerBlockers,
    string LastRamDiagnosticSummary,
    bool LastRamDiagnosticHadErrors);

/// <summary>
/// Периодичность фонового автообслуживания в Планировщике заданий Windows.
/// </summary>
public enum MaintenanceFrequency
{
    Disabled = 0,
    Daily = 1,
    Weekly = 2,
    Monthly = 3
}

/// <summary>
/// Профиль расписания фонового автообслуживания UltimateWindows.
/// </summary>
public sealed record MaintenanceScheduleProfile(
    bool IsEnabled,
    MaintenanceFrequency Frequency,
    int RunHourLocal,
    bool CleanSafeTempCache,
    bool CheckDriveSmartHealth,
    bool AuditSecurityAndStartup,
    string TaskSchedulerPath,
    string NextRunDisplay,
    string LastRunSummary)
{
    public string FrequencyDisplay => Frequency switch
    {
        MaintenanceFrequency.Daily => $"Ежедневно в {RunHourLocal:00}:00",
        MaintenanceFrequency.Weekly => $"Еженедельно (воскресенье, {RunHourLocal:00}:00)",
        MaintenanceFrequency.Monthly => $"Ежемесячно (1-го числа, {RunHourLocal:00}:00)",
        _ => "Отключено"
    };
}

/// <summary>
/// Сводка выполненного прогона бережного автообслуживания.
/// </summary>
public sealed record MaintenanceRunSummary(
    DateTimeOffset CompletedAtUtc,
    long ReclaimedCacheBytes,
    int UnhealthyDrivesCount,
    int SecurityAlertsCount,
    int CompositeHealthScore,
    string Headline)
{
    public string FormattedReclaimed => ByteFormatter.Format(ReclaimedCacheBytes);
}

/// <summary>
/// Итог сборки единого диагностического архива одним файлом (.zip) для обращения за помощью.
/// </summary>
public sealed record SupportBundleResult(
    string ArchivePath,
    long FileSizeBytes,
    IReadOnlyList<string> IncludedFiles,
    string SummaryMessage)
{
    public string FormattedSize => ByteFormatter.Format(FileSizeBytes);
}
