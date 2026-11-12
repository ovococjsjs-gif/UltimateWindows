using UltimateWindows.Core.Enums;

namespace UltimateWindows.Modules.Repair.Models;

public enum PeArchitecture
{
    Unknown = 0,
    X86 = 1,
    X64 = 2,
    Arm64 = 3
}

public enum DependencyIssueKind
{
    HealthyResolved = 0,
    ArchitectureMismatch0xC000007B = 1,
    MissingOfficialRuntimeDll = 2,
    MissingCustomApplicationDll = 3,
    UnsignedTamperedLocalDll = 4
}

public enum SystemCrashEventKind
{
    ApplicationCrash1000 = 0,
    SideBySideManifestError = 1,
    GpuTdrReset4101 = 2,
    UnexpectedKernelPower41 = 3,
    HardwareWheaError = 4,
    BsodBugCheck1001 = 5,
    ApplicationHang1002 = 6,
    DotNetUnhandledException1026 = 7,
    AppxActivationFailure = 8
}

public enum RepairPlaybookId
{
    DismAndSfcIntegrity = 0,
    WindowsUpdateReset = 1,
    NetworkAndDnsStackReset = 2,
    IconAndThumbnailCacheRebuild = 3,
    MicrosoftStoreAndAppxRepair = 4,
    PrintSpoolerCleanup = 5,
    WmiRepositoryVerifyAndSalvage = 6
}

public enum RuntimeInstallStatus
{
    Unknown = 0,
    Installed = 1,
    NotInstalled = 2
}

/// <summary>
/// Описание официального подписанного пакета среды выполнения (VC++ 2005–2026, DirectX, .NET, WebView2, OpenAL, XNA, Vulkan).
/// </summary>
public sealed record OfficialRuntimePackage(
    string PackageKey,
    string WingetPackageId,
    string FriendlyName,
    string PublisherName,
    PeArchitecture TargetArchitecture,
    string SilentInstallArgs,
    string OfficialDownloadPageUrl,
    IReadOnlyList<string> ProvidedDllNamesLower,
    string? DirectDownloadUrl = null,
    string? OptionalWindowsFeatureName = null,
    string Category = "Visual C++",
    bool IsRecommendedBaseline = false)
{
    public string ArchitectureBadge => TargetArchitecture switch
    {
        PeArchitecture.X86 => "32-бит (x86 / SysWOW64)",
        PeArchitecture.X64 => "64-бит (x64 / System32)",
        PeArchitecture.Arm64 => "ARM64",
        _ => "Универсальный"
    };

    public string DeliveryMethodBadge => !string.IsNullOrWhiteSpace(OptionalWindowsFeatureName)
        ? $"Компонент Windows ({OptionalWindowsFeatureName})"
        : !string.IsNullOrWhiteSpace(DirectDownloadUrl)
            ? "Прямая загрузка + проверка подписи"
            : "Пакет WinGet + проверка подписи";
}

/// <summary>
/// Сведения об установленности конкретного пакета среды выполнения на текущем ПК.
/// </summary>
public sealed record OfficialRuntimeStatusReport(
    OfficialRuntimePackage Package,
    RuntimeInstallStatus Status,
    string DetectedDetails)
{
    public bool IsInstalled => Status == RuntimeInstallStatus.Installed;

    public string StatusBadge => Status switch
    {
        RuntimeInstallStatus.Installed => string.IsNullOrWhiteSpace(DetectedDetails) ? "Установлен" : $"Установлен ({DetectedDetails})",
        RuntimeInstallStatus.NotInstalled => "Не установлен",
        _ => "Не определено"
    };
}

/// <summary>
/// Результат бинарного чтения заголовков PE-файла (.exe или .dll).
/// </summary>
public sealed record PeBinaryInspectionResult(
    string FilePath,
    bool IsValidPeFile,
    PeArchitecture Architecture,
    bool Is64BitPlusHeader,
    ushort Subsystem,
    IReadOnlyList<string> ImportedDllNames,
    string? ParseError = null)
{
    public string ArchitectureDisplay => Architecture switch
    {
        PeArchitecture.X86 => "32-бит (x86 / I386, 0x014C)",
        PeArchitecture.X64 => "64-бит (x64 / AMD64, 0x8664)",
        PeArchitecture.Arm64 => "64-бит (ARM64, 0xAA64)",
        _ => "Неизвестная архитектура"
    };
}

/// <summary>
/// Конкретная проблема зависимости импортируемой DLL (например, конфликт разрядности 0xC000007B или нехватка VC++).
/// </summary>
public sealed record PeDependencyIssue(
    DependencyIssueKind Kind,
    string ImportedDllName,
    string? ResolvedFilePath,
    PeArchitecture? ActualDllArchitecture,
    string SimpleExplanation,
    string ExpertTechnicalDetails,
    OfficialRuntimePackage? RecommendedPackage)
{
    public bool CanInstallOfficialRuntime => RecommendedPackage is not null;
    public bool CanQuarantineConflictingLocalDll =>
        Kind == DependencyIssueKind.ArchitectureMismatch0xC000007B &&
        !string.IsNullOrWhiteSpace(ResolvedFilePath);
}

/// <summary>
/// Итоговый диагноз не запускающейся игры или программы (.exe).
/// </summary>
public sealed record ExecutableDiagnosisReport(
    string TargetExecutablePath,
    PeBinaryInspectionResult BinaryHeader,
    bool IsHealthy,
    bool Has0xC000007BConflict,
    string HeadlineVerdict,
    int TotalDirectImportsCount,
    IReadOnlyList<PeDependencyIssue> Issues,
    IReadOnlyList<OfficialRuntimePackage> RecommendedPackages);

/// <summary>
/// Сведения об установленной программе для массовой проверки зависимостей DLL.
/// </summary>
public sealed record InstalledProgramInfo(
    string DisplayName,
    string? DisplayVersion,
    string? Publisher,
    string ExecutablePath,
    string InstallDirectory);

/// <summary>
/// Найденная проблема зависимостей у конкретной установленной программы.
/// </summary>
public sealed record InstalledProgramDependencyFinding(
    InstalledProgramInfo Program,
    ExecutableDiagnosisReport Diagnosis)
{
    public string MissingOrConflictingDllsSummary =>
        string.Join(", ", Diagnosis.Issues.Select(i => i.ImportedDllName).Distinct(StringComparer.OrdinalIgnoreCase));

    public string RecommendedPackagesSummary => Diagnosis.RecommendedPackages.Count == 0
        ? "Локальная DLL программы (переустановите программу)"
        : string.Join("; ", Diagnosis.RecommendedPackages.Select(p => p.FriendlyName));
}

/// <summary>
/// Итог массовой проверки всех установленных программ на ошибки 0xC000007B и отсутствие сред выполнения.
/// </summary>
public sealed record InstalledProgramsScanSummary(
    int TotalProgramsFound,
    int ExecutablesInspected,
    TimeSpan Elapsed,
    IReadOnlyList<InstalledProgramDependencyFinding> BrokenPrograms,
    IReadOnlyList<OfficialRuntimePackage> DistinctRecommendedPackages);

/// <summary>
/// Вид файла дампа: дамп ядра после синего экрана или дамп упавшей программы.
/// </summary>
public enum CrashDumpKind
{
    KernelBugCheck = 0,
    UserModeProcess = 1
}

/// <summary>
/// Насколько надёжно определён виновный драйвер.
/// </summary>
public enum CrashCulpritConfidence
{
    /// <summary>Драйвер не определён.</summary>
    None = 0,

    /// <summary>Драйвер найден в стеке вызовов, но при таких сбоях виновником часто оказывается другой модуль.</summary>
    Low = 1,

    /// <summary>Драйвер найден на вершине стека вызовов ядра.</summary>
    Medium = 2,

    /// <summary>Windows сама передала адрес сбойной инструкции, и он лежит внутри этого драйвера.</summary>
    High = 3
}

/// <summary>
/// Итог обращения к папке с дампами.
/// </summary>
public enum MinidumpFolderStatus
{
    Scanned = 0,
    FolderMissing = 1,
    AccessDenied = 2,
    ReadError = 3
}

/// <summary>
/// Расшифрованный отчёт по одному файлу аварийного дампа (C:\Windows\Minidump\*.dmp).
/// </summary>
public sealed record BsodMinidumpReport(
    string DumpFilePath,
    DateTimeOffset CrashTimestampUtc,
    uint? BugCheckCode,
    string BugCheckName,
    PeArchitecture ProcessorArchitecture,
    string OsBuildSummary,
    string? SuspectedThirdPartyDriver,
    string SimpleHumanExplanation,
    string RecommendedUserAction,
    IReadOnlyList<string> LoadedDriverModulesSample,
    CrashDumpKind DumpKind = CrashDumpKind.KernelBugCheck,
    CrashCulpritConfidence CulpritConfidence = CrashCulpritConfidence.None,
    string? FaultingModule = null,
    string? TechnicalEvidence = null,
    IReadOnlyList<ulong>? BugCheckParameters = null,
    uint? ExceptionCode = null)
{
    public bool HasKnownCrashTime => CrashTimestampUtc != default;

    public string CrashLocalDisplay => HasKnownCrashTime
        ? CrashTimestampUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm")
        : "время неизвестно";

    public string BugCheckHex
    {
        get
        {
            var code = DumpKind == CrashDumpKind.UserModeProcess ? ExceptionCode : BugCheckCode;
            return code.HasValue ? $"0x{code.Value:X8}" : "—";
        }
    }

    public string CulpritBadge
    {
        get
        {
            if (DumpKind == CrashDumpKind.UserModeProcess)
            {
                return string.IsNullOrWhiteSpace(FaultingModule) ? "Сбой программы" : $"Модуль: {FaultingModule}";
            }

            if (!string.IsNullOrWhiteSpace(SuspectedThirdPartyDriver))
            {
                return CulpritConfidence == CrashCulpritConfidence.High
                    ? $"Виновник: {SuspectedThirdPartyDriver}"
                    : $"Вероятно: {SuspectedThirdPartyDriver}";
            }

            return string.IsNullOrWhiteSpace(FaultingModule)
                ? "Драйвер не выявлен"
                : $"Сбой в {FaultingModule}";
        }
    }

    public string ParametersDisplay => BugCheckParameters is { Count: > 0 }
        ? string.Join(", ", BugCheckParameters.Select(p => $"0x{p:X}"))
        : "";

    public string ExpertModulesJoined => LoadedDriverModulesSample.Count == 0
        ? ""
        : "Сторонние модули в памяти: " + string.Join(", ", LoadedDriverModulesSample);
}

/// <summary>
/// Результат разбора папки с дампами: отчёты и сведения о том, удалось ли прочитать папку.
/// </summary>
public sealed record MinidumpScanResult(
    IReadOnlyList<BsodMinidumpReport> Reports,
    MinidumpFolderStatus FolderStatus,
    int UnreadableFileCount);

/// <summary>
/// Полный итог поиска следов сбоев: дампы, записи журнала событий и состояние папки с дампами.
/// </summary>
public sealed record CrashHistoryScanResult(
    IReadOnlyList<BsodMinidumpReport> Minidumps,
    IReadOnlyList<SystemCrashEventEntry> CrashEvents,
    MinidumpFolderStatus FolderStatus,
    int UnreadableDumpCount)
{
    /// <summary>
    /// Пояснение для пользователя, если папку с дампами не удалось прочитать полностью; иначе null.
    /// </summary>
    public string? FolderNote => FolderStatus switch
    {
        MinidumpFolderStatus.AccessDenied =>
            "Папка с дампами доступна только администратору: перезапустите программу с правами администратора, чтобы прочитать дампы синих экранов.",
        MinidumpFolderStatus.FolderMissing =>
            "Папки с малыми дампами нет: Windows ещё не записывала дампы синих экранов либо их запись отключена.",
        MinidumpFolderStatus.ReadError =>
            "Не удалось прочитать папку с дампами.",
        _ => UnreadableDumpCount > 0
            ? $"Не удалось разобрать файлов дампов: {UnreadableDumpCount}."
            : null
    };
}

/// <summary>
/// Критическое событие сбоя программы или подсистемы Windows из системного журнала событий с подсказкой причины.
/// </summary>
public sealed record SystemCrashEventEntry(
    SystemCrashEventKind Kind,
    DateTimeOffset TimestampUtc,
    int EventId,
    string SourceProvider,
    string SimpleSummary,
    string TechnicalRawDetails,
    string? FaultingExecutablePath = null,
    string? FaultingModuleName = null,
    uint? ExceptionCode = null,
    string? RootCauseHint = null,
    string? RecommendedRuntimeKey = null,
    string? RecommendedRepairRuleId = null)
{
    public string TimeLocalDisplay => TimestampUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
    public string EventBadge => $"Event ID {EventId} • {SourceProvider}";
    public string ExceptionHex => ExceptionCode.HasValue ? $"0x{ExceptionCode.Value:X8}" : "—";
    public bool CanInspectExecutableInPeDoctor =>
        !string.IsNullOrWhiteSpace(FaultingExecutablePath) && File.Exists(FaultingExecutablePath);
    public string AdviceDisplay => string.IsNullOrWhiteSpace(RootCauseHint) ? SimpleSummary : RootCauseHint;
}

/// <summary>
/// Итог разбора системного журнала C:\Windows\Logs\CBS\CBS.log после проверок SFC / DISM.
/// </summary>
public sealed record CbsLogSummary(
    bool LogExists,
    bool LogAccessible,
    DateTimeOffset? LastServicingTimestampUtc,
    IReadOnlyList<string> UnrepairableFiles,
    IReadOnlyList<string> RepairedFiles,
    int TotalCorruptMentions,
    string HumanVerdict)
{
    public bool HasUnrepairableCorruption => UnrepairableFiles.Count > 0;
}

/// <summary>
/// Оценка готовности к крайней ступени ремонта: «Устранение неполадок с помощью Центра обновления Windows → Переустановить сейчас»
/// (Windows 11) или обновление на месте с сохранением программ и файлов (Windows 10).
/// </summary>
public sealed record InPlaceReinstallReadiness(
    bool SupportsWindowsUpdateReinstallNow,
    int OsBuild,
    double FreeSystemDriveGb,
    bool HasEnoughDiskSpace,
    bool IsOnBatteryPower,
    string RecommendedMethodTitle,
    string StepByStepInstructions,
    string SettingsUri);

/// <summary>
/// Описание безопасного одно-кликового рецепта ремонта подсистем Windows.
/// </summary>
public sealed record RepairPlaybookDescriptor(
    RepairPlaybookId Id,
    string IconGlyph,
    string FriendlyTitle,
    string FriendlyDescription,
    string ExpertCommandsPreview,
    bool RequiresAdministrator,
    RiskLevel Risk)
{
    public string AccessBadge => RequiresAdministrator ? "Требуются права Админа 🛡️" : "Доступно без прав Админа ✅";
}

/// <summary>
/// Результат выполнения ремонта или установки официального пакета среды выполнения.
/// </summary>
public sealed record RepairOperationResult(
    bool Succeeded,
    string UserFriendlySummary,
    string TechnicalLogOutput,
    Guid? RollbackSessionId = null);
