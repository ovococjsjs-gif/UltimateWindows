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
    BsodBugCheck1001 = 5
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

/// <summary>
/// Описание официального подписанного пакета среды выполнения (VC++, DirectX, .NET, OpenAL, XNA).
/// </summary>
public sealed record OfficialRuntimePackage(
    string PackageKey,
    string WingetPackageId,
    string FriendlyName,
    string PublisherName,
    PeArchitecture TargetArchitecture,
    string SilentInstallArgs,
    string OfficialDownloadPageUrl,
    IReadOnlyList<string> ProvidedDllNamesLower)
{
    public string ArchitectureBadge => TargetArchitecture switch
    {
        PeArchitecture.X86 => "32-бит (x86 / SysWOW64)",
        PeArchitecture.X64 => "64-бит (x64 / System32)",
        PeArchitecture.Arm64 => "ARM64",
        _ => "Универсальный"
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
/// Расшифрованный отчет по одному файлу минидампа синего экрана смерти (C:\Windows\Minidump\*.dmp).
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
    IReadOnlyList<string> LoadedDriverModulesSample)
{
    public string CrashLocalDisplay => CrashTimestampUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
    public string BugCheckHex => BugCheckCode.HasValue ? $"0x{BugCheckCode.Value:X8}" : "Анализ модулей ядра";
    public string CulpritBadge => !string.IsNullOrWhiteSpace(SuspectedThirdPartyDriver)
        ? $"Виновник: {SuspectedThirdPartyDriver}"
        : "Ядро ОС / Питание / ОЗУ";
    public string ExpertModulesJoined => LoadedDriverModulesSample.Count == 0
        ? ""
        : "Загруженные модули ядра: " + string.Join(", ", LoadedDriverModulesSample);
}

/// <summary>
/// Критическое событие сбоя программы или подсистемы Windows из системного журнала событий.
/// </summary>
public sealed record SystemCrashEventEntry(
    SystemCrashEventKind Kind,
    DateTimeOffset TimestampUtc,
    int EventId,
    string SourceProvider,
    string SimpleSummary,
    string TechnicalRawDetails)
{
    public string TimeLocalDisplay => TimestampUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
    public string EventBadge => $"Event ID {EventId} • {SourceProvider}";
}

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
