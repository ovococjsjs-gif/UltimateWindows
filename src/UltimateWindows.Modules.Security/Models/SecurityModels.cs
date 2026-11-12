using UltimateWindows.Core.Enums;

namespace UltimateWindows.Modules.Security.Models;

/// <summary>
/// Вектор обнаружения скрытого майнера, трояна-загрузчика или саботажа системы.
/// </summary>
public enum ThreatDetectionVector
{
    ProcessMasquerading = 0,
    DropOnInspectEvasion = 1,
    StratumMiningPoolConnection = 2,
    SuspiciousMinerCommandLine = 3,
    IfeoDebuggerHijack = 4,
    WinlogonShellHijack = 5,
    HiddenScheduledTask = 6,
    WmiPermanentSubscription = 7,
    GpuDropOnInspectEvasion = 8,
    ProcessHollowingOrImplant = 9,
    SuspiciousRegistryAutorun = 10,
    StartupFolderOrShellRedirect = 11,
    IfeoSilentProcessExit = 12,
    BootExecuteOrSessionManager = 13,
    AppInitDllInjection = 14,
    ActiveSetupStubHijack = 15,
    ComClassHijack = 16,
    DotNetProfilerHijack = 17,
    LsaOrSecurityProviderHijack = 18,
    PrintMonitorOrNetshDll = 19,
    SuspiciousServiceOrDriver = 20,
    SuspiciousScheduledTask = 21,
    BitsPersistenceJob = 22,
    DangerousDefenderExclusion = 23,
    MaliciousFirewallRule = 24,
    HiddenOrRogueUserAccount = 25,
    MinerStagingArtifactOrBloatedBinary = 26,
    DnsCacheMiningPool = 27,
    ExternalPeSieveImplant = 28,
    ExternalYaraMatch = 29,
    PowerShellProfileHijack = 30
}

/// <summary>
/// 18 канонических зон автозакрепления в Windows 10 и Windows 11.
/// </summary>
public enum PersistenceZone
{
    Other = 0,
    RunAndRunOnceKeys = 1,
    PoliciesExplorerRun = 2,
    StartupFoldersAndShellRedirection = 3,
    WinlogonShellAndUserinit = 4,
    IfeoAndSilentProcessExit = 5,
    BootExecuteAndSessionManager = 6,
    AppInitDlls = 7,
    ActiveSetupInstalledComponents = 8,
    ComInprocAndLocalServerHijack = 9,
    DotNetCorProfilerEnvironment = 10,
    LsaAndSecurityPackages = 11,
    PrintMonitorsAndNetshHelpers = 12,
    WindowsServicesAndDrivers = 13,
    ScheduledTasksAndGhostSd = 14,
    WmiPermanentSubscriptions = 15,
    BitsPersistentJobs = 16,
    ShellExtensionsAndBrowserHooks = 17,
    PowerShellProfiles = 18
}

/// <summary>
/// Способ безопасного снятия точки автозакрепления с записью в «Машину времени».
/// </summary>
public enum PersistenceRemediationKind
{
    None = 0,
    DeleteRegistryValue = 1,
    RestoreRegistryDefault = 2,
    DeleteRegistrySubKey = 3,
    DisableScheduledTask = 4,
    DeleteScheduledTask = 5,
    DisableWindowsService = 6,
    DeleteWmiSubscription = 7,
    QuarantineStartupFile = 8,
    CancelBitsJob = 9
}

/// <summary>
/// Тип послевирусной блокировки или саботажа защитных механизмов ОС.
/// </summary>
public enum OsSabotageKind
{
    TaskManagerDisabledByPolicy = 0,
    RegistryEditorDisabledByPolicy = 1,
    CommandPromptDisabledByPolicy = 2,
    SystemToolIfeoBlocked = 3,
    SecurityDomainsBlockedInHosts = 4,
    DefenderDisabledByPolicy = 5,
    DefenderRealtimeDisabledByPolicy = 6,
    MrtBlockedByPolicy = 7,
    WindowsUpdateDisabledByPolicy = 8,
    FirewallOutboundSecurityBlock = 9,
    PowerShellOrMmcDisabledByPolicy = 10
}

/// <summary>
/// Тип исключения Microsoft Defender.
/// </summary>
public enum DefenderExclusionKind
{
    Path = 0,
    Process = 1,
    Extension = 2,
    IpAddress = 3
}

/// <summary>
/// Тип проверки Microsoft Defender.
/// </summary>
public enum DefenderScanMode
{
    QuickScan = 1,
    FullScan = 2,
    CustomPathScan = 3
}

/// <summary>
/// Двухфазный снимок поведения процесса (тихий фон vs активный системный монитор и окно-приманка),
/// включая загрузку CPU, GPU (3D/Compute/CUDA), родительский процесс и приватные исполняемые регионы памяти.
/// </summary>
public sealed record ProcessTelemetrySample(
    int ProcessId,
    string ProcessName,
    string ExecutablePath,
    string CommandLine,
    double BaselineCpuPercent,
    double DuringInspectCpuPercent,
    bool ExitedDuringInspect,
    bool IsAuthenticodeSigned,
    double BaselineGpuPercent = 0,
    double DuringInspectGpuPercent = 0,
    int ParentProcessId = 0,
    string ParentProcessName = "",
    int PrivateExecutableRegionCount = 0,
    long WorkingSetBytes = 0)
{
    public string SignatureBadge => IsAuthenticodeSigned ? "Подписан" : "Без подписи";
    public string CpuSummary => $"{BaselineCpuPercent:F1}% -> {DuringInspectCpuPercent:F1}%";
    public string GpuSummary => $"{BaselineGpuPercent:F1}% -> {DuringInspectGpuPercent:F1}%";
    public double WorkingSetMb => Math.Round(WorkingSetBytes / (1024.0 * 1024.0), 1);
}

/// <summary>
/// Снимок активного исходящего TCP-соединения процесса (IPv4 / IPv6).
/// </summary>
public sealed record ProcessTcpConnectionInfo(
    int ProcessId,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort,
    bool IsIpv6 = false);

/// <summary>
/// Запись ревизии точки автозакрепления в одной из 18 подсистем Windows.
/// </summary>
public sealed record PersistenceAnomalyRecord(
    ThreatDetectionVector Vector,
    string RegistryOrTaskPath,
    string EntryName,
    string PayloadCommandOrPath,
    string? ReferencedExecutablePath,
    bool IsMissingSecurityDescriptorSd,
    string? PreviousValueSerialized,
    PersistenceZone Category = PersistenceZone.Other,
    bool IsAnomaly = true,
    bool IsSigned = false,
    string PublisherOrNote = "",
    PersistenceRemediationKind RemediationKind = PersistenceRemediationKind.None,
    string RemediationTarget = "")
{
    public string ZoneTitle => Category switch
    {
        PersistenceZone.RunAndRunOnceKeys => "Run / RunOnce (HKLM/HKCU/Wow64)",
        PersistenceZone.PoliciesExplorerRun => "Групповые политики Explorer\\Run",
        PersistenceZone.StartupFoldersAndShellRedirection => "Папки Автозагрузки и Shell Folders",
        PersistenceZone.WinlogonShellAndUserinit => "Вход в систему Winlogon (Shell / Userinit)",
        PersistenceZone.IfeoAndSilentProcessExit => "IFEO Debugger и SilentProcessExit",
        PersistenceZone.BootExecuteAndSessionManager => "Ранний старт BootExecute / Session Manager",
        PersistenceZone.AppInitDlls => "Глобальная инжекция AppInit_DLLs",
        PersistenceZone.ActiveSetupInstalledComponents => "Active Setup (StubPath)",
        PersistenceZone.ComInprocAndLocalServerHijack => "Перехват COM-классов (HKCU CLSID)",
        PersistenceZone.DotNetCorProfilerEnvironment => "Перехват .NET CLR (COR_PROFILER)",
        PersistenceZone.LsaAndSecurityPackages => "Пакеты безопасности LSA / SSP",
        PersistenceZone.PrintMonitorsAndNetshHelpers => "Мониторы печати и DLL NetSh",
        PersistenceZone.WindowsServicesAndDrivers => "Службы Windows, ServiceDll и драйверы",
        PersistenceZone.ScheduledTasksAndGhostSd => "Планировщик заданий и скрытые задачи без SD",
        PersistenceZone.WmiPermanentSubscriptions => "Постоянные подписки WMI (root\\subscription)",
        PersistenceZone.BitsPersistentJobs => "Фоновые задания передачи BITS",
        PersistenceZone.ShellExtensionsAndBrowserHooks => "Расширения оболочки Explorer",
        PersistenceZone.PowerShellProfiles => "Автозагрузка профилей PowerShell",
        _ => "Прочие точки закрепления"
    };

    public string StatusBadge => IsAnomaly ? "Подозрительно" : (IsSigned ? "Подписан" : "Штатно");
    public bool CanRemediate => IsAnomaly && RemediationKind != PersistenceRemediationKind.None;
}

/// <summary>
/// Запись исключения Защитника Windows (Microsoft Defender) с оценкой риска.
/// </summary>
public sealed record DefenderExclusionFinding(
    DefenderExclusionKind Kind,
    string Value,
    bool IsPolicyEnforced,
    bool IsDangerousMinerExclusion,
    RiskLevel Severity,
    string RegistryPath,
    string Reason)
{
    public string KindLabel => Kind switch
    {
        DefenderExclusionKind.Path => "Папка / путь",
        DefenderExclusionKind.Process => "Процесс",
        DefenderExclusionKind.Extension => "Расширение",
        DefenderExclusionKind.IpAddress => "IP-адрес",
        _ => "Исключение"
    };

    public string SourceBadge => IsPolicyEnforced ? "Политика (GPO)" : "Настройки Defender";
    public string RiskBadge => IsDangerousMinerExclusion ? "Опасно (слепая зона)" : "Пользовательское";
}

/// <summary>
/// Подозрительное правило Брандмауэра Windows (например, блокировка исходящего трафика антивирусов или Центра обновления).
/// </summary>
public sealed record FirewallRuleAnomaly(
    string RuleId,
    string DisplayName,
    string Direction,
    string Action,
    string ApplicationPath,
    string RemoteAddresses,
    string RemotePorts,
    string RawRegistryValue,
    string SimpleExplanation);

/// <summary>
/// Подозрительная или скрытая локальная учетная запись пользователя Windows.
/// </summary>
public sealed record SuspiciousUserAccountFinding(
    string UserName,
    bool IsAdministrator,
    bool IsEnabled,
    bool EndsWithDollarSign,
    bool IsHiddenInWinlogonSpecialAccounts,
    string Comment,
    string Reason);

/// <summary>
/// Файловый артефакт майнера в пользовательских/временных каталогах (конфиг пула, драйвер WinRing0, раздутый бинарник >250 МБ).
/// </summary>
public sealed record DirectoryThreatArtifact(
    string FilePath,
    string ArtifactKind,
    long FileSizeBytes,
    bool IsBloatedPaddingSuspect,
    string MatchedIndicator,
    string SimpleExplanation)
{
    public double FileSizeMb => Math.Round(FileSizeBytes / (1024.0 * 1024.0), 1);
}

/// <summary>
/// Статус подключаемого внешнего сканера с совместимой лицензией (pe-sieve / YARA).
/// </summary>
public sealed record ExternalScannerStatus(
    string ScannerId,
    string DisplayName,
    bool IsAvailable,
    string ResolvedBinaryPath,
    string LicenseSpdx,
    string StatusText);

/// <summary>
/// Обнаруженная блокировка ОС после майнера или вируса.
/// </summary>
public sealed record OsSabotageFinding(
    OsSabotageKind Kind,
    string TargetDisplayPath,
    string Hive,
    string SubKeyPath,
    string ValueName,
    string CurrentMaliciousValue,
    string SimpleTitle,
    string SimpleExplanation);

/// <summary>
/// Итоговая карточка найденной угрозы с понятным объяснением, оценкой достоверности и действием обезвреживания.
/// </summary>
public sealed record SecurityThreatFinding(
    string FindingId,
    ThreatDetectionVector Vector,
    RiskLevel Severity,
    int ConfidenceScorePercent,
    int? SuspectProcessId,
    string? SuspectFilePath,
    PersistenceAnomalyRecord? PersistenceRecord,
    string SimpleTitle,
    string SimpleExplanation,
    string ExpertTechnicalEvidence,
    bool CanQuarantineFileSafely,
    string CategoryLabel = "",
    string RecommendedActionLabel = "Обезвредить",
    DefenderExclusionFinding? LinkedExclusion = null,
    FirewallRuleAnomaly? LinkedFirewallRule = null)
{
    public string ConfidenceBadge => $"{ConfidenceScorePercent}% ({Severity switch
    {
        RiskLevel.Critical => "Критично",
        RiskLevel.High => "Высокий риск",
        RiskLevel.Attention => "Подозрительно",
        _ => "Проверить"
    }})";

    public string EffectiveCategoryLabel => !string.IsNullOrWhiteSpace(CategoryLabel)
        ? CategoryLabel
        : Vector switch
        {
            ThreatDetectionVector.ProcessMasquerading => "Маскировка процесса",
            ThreatDetectionVector.DropOnInspectEvasion or ThreatDetectionVector.GpuDropOnInspectEvasion => "Стелс-майнер (Drop-on-Inspect)",
            ThreatDetectionVector.StratumMiningPoolConnection or ThreatDetectionVector.DnsCacheMiningPool => "Сеть / Пул майнинга",
            ThreatDetectionVector.ProcessHollowingOrImplant or ThreatDetectionVector.ExternalPeSieveImplant => "Инжекция в память (Hollowing)",
            ThreatDetectionVector.DangerousDefenderExclusion => "Слепая зона Defender",
            ThreatDetectionVector.MaliciousFirewallRule => "Саботаж брандмауэра",
            ThreatDetectionVector.HiddenOrRogueUserAccount => "Скрытая учетная запись",
            ThreatDetectionVector.MinerStagingArtifactOrBloatedBinary or ThreatDetectionVector.ExternalYaraMatch => "Файловый артефакт майнера",
            _ => "Автозакрепление"
        };

    public bool CanRemediateAny =>
        CanQuarantineFileSafely ||
        (PersistenceRecord?.CanRemediate ?? false) ||
        LinkedExclusion is not null ||
        LinkedFirewallRule is not null ||
        SuspectProcessId is > 4;
}

/// <summary>
/// Элемент карантина (.uwq) в «Машине времени» раздела Анти-Майнер.
/// </summary>
public sealed record QuarantinedThreatEntry(
    Guid SessionId,
    DateTimeOffset QuarantinedAtUtc,
    string FriendlyTitle,
    string FriendlySummary,
    IReadOnlyList<string> QuarantinedPaths,
    int StateDeltaCount,
    bool IsReverted)
{
    public string TimestampLocalText => QuarantinedAtUtc.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss");
    public string PrimaryPath => QuarantinedPaths.Count > 0 ? QuarantinedPaths[0] : "Системная запись (реестр / задача / служба)";
}

/// <summary>
/// Сводный отчет проверки модуля «Анти-майнер и Защита 2.0».
/// </summary>
public sealed record SecurityScanReport(
    DateTimeOffset ScannedAtUtc,
    bool RanWithAdministratorPrivileges,
    bool RanDropOnInspectDecoy,
    IReadOnlyList<SecurityThreatFinding> Threats,
    IReadOnlyList<OsSabotageFinding> SabotageLocks,
    int SecurityHealthScore,
    string HeadlineSummary,
    IReadOnlyList<PersistenceAnomalyRecord>? AllPersistenceEntries = null,
    IReadOnlyList<DefenderExclusionFinding>? DefenderExclusions = null,
    IReadOnlyList<FirewallRuleAnomaly>? FirewallAnomalies = null,
    IReadOnlyList<SuspiciousUserAccountFinding>? SuspiciousUsers = null,
    IReadOnlyList<DirectoryThreatArtifact>? DirectoryArtifacts = null,
    IReadOnlyList<ProcessTelemetrySample>? ProcessSnapshots = null,
    IReadOnlyList<ExternalScannerStatus>? ExternalScanners = null,
    IReadOnlyList<string>? DnsCachedPoolDomains = null,
    int PersistenceZonesAuditedCount = 18)
{
    public IReadOnlyList<PersistenceAnomalyRecord> SafePersistenceEntries => AllPersistenceEntries ?? [];
    public IReadOnlyList<DefenderExclusionFinding> SafeDefenderExclusions => DefenderExclusions ?? [];
    public IReadOnlyList<FirewallRuleAnomaly> SafeFirewallAnomalies => FirewallAnomalies ?? [];
    public IReadOnlyList<SuspiciousUserAccountFinding> SafeSuspiciousUsers => SuspiciousUsers ?? [];
    public IReadOnlyList<DirectoryThreatArtifact> SafeDirectoryArtifacts => DirectoryArtifacts ?? [];
    public IReadOnlyList<ProcessTelemetrySample> SafeProcessSnapshots => ProcessSnapshots ?? [];
    public IReadOnlyList<ExternalScannerStatus> SafeExternalScanners => ExternalScanners ?? [];
    public IReadOnlyList<string> SafeDnsCachedPoolDomains => DnsCachedPoolDomains ?? [];
}

/// <summary>
/// Результат операции обезвреживания угрозы, очистки исключений Defender или снятия блокировок.
/// </summary>
public sealed record SecurityRemediationResult(
    bool Succeeded,
    Guid? RollbackSessionId,
    int FixedItemsCount,
    string UserFriendlyMessage);
