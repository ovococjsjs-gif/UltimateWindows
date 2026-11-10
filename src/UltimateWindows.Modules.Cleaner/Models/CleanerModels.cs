using UltimateWindows.Core.Models;

namespace UltimateWindows.Modules.Cleaner.Models;

public enum CleanerCategoryKind
{
    BrowserCache = 0,
    SystemTemp = 1,
    GpuShaderCache = 2,
    WindowsErrorReports = 3,
    WindowsUpdateCache = 4,
    DeveloperPackageCache = 5,
    RecycleBin = 6,
    VerifiedRegistryOrphans = 7
}

public enum RegistryOrphanKind
{
    OrphanedStartupRun = 0,
    StaleAppCompatFlag = 1,
    StaleMuiCache = 2,
    BrokenFirewallRule = 3,
    DeadUninstallEntry = 4
}

/// <summary>
/// Настройки бережной очистки. По умолчанию жестко защищает пароли, автозаполнение форм и сессии.
/// </summary>
public sealed record CleanupOptions
{
    public bool PreservePasswordsAndAutofill { get; init; } = true;
    public bool PreserveBrowserSessions { get; init; } = true;
    public bool CleanBrowserCaches { get; init; } = true;
    public bool CleanSystemTempAndShaders { get; init; } = true;
    public bool CleanRegistryOrphans { get; init; } = true;
    public bool EmptyRecycleBin { get; init; } = false;
    public bool IncludeDeveloperCaches { get; init; } = false;
    public int MinimumTempFileAgeHours { get; init; } = 24;
}

public sealed record DiscoveredBrowserProfile(
    string BrowserName,
    string ProfileName,
    string CacheRootDirectory,
    string ProfileDataDirectory,
    bool IsGeckoFirefox,
    bool IsBrowserCurrentlyRunning);

public sealed record CleanupCandidateFile(
    CleanerCategoryKind Category,
    string SourceLabel,
    string FullPath,
    long SizeBytes);

public sealed record RegistryOrphanCandidate(
    RegistryOrphanKind Kind,
    string HiveName,
    string SubKeyPath,
    string ValueName,
    string MissingReferencedFilePath,
    string PreviousValueSerialized,
    int RegistryValueKindCode,
    string FriendlyReason)
{
    public string FullRegistryDisplayPath => $@"{HiveName}\{SubKeyPath} :: {ValueName}";
}

public sealed record CleanupCategorySummary(
    CleanerCategoryKind Category,
    string IconGlyph,
    string FriendlyTitle,
    string FriendlyDescription,
    long TotalBytes,
    int ItemCount,
    IReadOnlyList<string> SamplePathsForExpert)
{
    public string FormattedSize => Category == CleanerCategoryKind.VerifiedRegistryOrphans
        ? $"{ItemCount} записей"
        : ByteFormatter.Format(TotalBytes);

    public string ExpertSamplesJoined => SamplePathsForExpert.Count == 0
        ? ""
        : "Примеры путей: " + string.Join("  •  ", SamplePathsForExpert);
}

public sealed record CleanupScanReport(
    DateTimeOffset ScannedAtUtc,
    long TotalReclaimableBytes,
    int TotalFilesCount,
    int TotalRegistryOrphansCount,
    bool PasswordsAndAutofillProtected,
    IReadOnlyList<string> RunningBrowserWarnings,
    IReadOnlyList<CleanupCategorySummary> Categories,
    IReadOnlyList<CleanupCandidateFile> CandidateFiles,
    IReadOnlyList<RegistryOrphanCandidate> RegistryOrphans)
{
    public string FormattedTotalReclaimable => ByteFormatter.Format(TotalReclaimableBytes);
}

public sealed record CleanupExecutionResult(
    long FreedBytes,
    int DeletedFilesCount,
    int SkippedLockedFilesCount,
    int CleanedRegistryOrphansCount,
    Guid? RollbackSessionId,
    string UserSummaryMessage)
{
    public string FormattedFreed => ByteFormatter.Format(FreedBytes);
}

public sealed record DiskSpaceItem(
    string Name,
    string FullPath,
    long SizeBytes,
    long FileCount,
    double ShareOfScannedPercent)
{
    public string FormattedSize => ByteFormatter.Format(SizeBytes);
    public string FilesCountLabel => $"{FileCount:N0} файл.";
    public string ShareLabel => $"{ShareOfScannedPercent:F1}%";
}

public sealed record DiskSpaceAnalysisReport(
    string RootPath,
    string ScanMethodDescription,
    TimeSpan Elapsed,
    long TotalScannedBytes,
    long TotalFilesCount,
    IReadOnlyList<DiskSpaceItem> TopDirectories,
    IReadOnlyList<DiskSpaceItem> LargestFiles)
{
    public string FormattedTotalScanned => ByteFormatter.Format(TotalScannedBytes);
}
