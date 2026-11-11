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
    DeadUninstallEntry = 4,
    MissingSharedDll = 5,
    BrokenAppPath = 6,
    MissingHelpFile = 7,
    BrokenSoundEvent = 8,
    StaleExplorerHistory = 9
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
    public IReadOnlySet<RegistryOrphanKind>? EnabledRegistryCategories { get; init; }
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
    long SizeBytes)
{
    public string FormattedSize => ByteFormatter.Format(SizeBytes);
}

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
    public string FullRegistryDisplayPath => $@"{HiveName}\{SubKeyPath} :: {(string.IsNullOrEmpty(ValueName) ? "(По умолчанию)" : ValueName)}";

    public string CategoryTitle => Kind switch
    {
        RegistryOrphanKind.MissingSharedDll => "Отсутствующие общие DLL",
        RegistryOrphanKind.BrokenAppPath => "Пути приложений (App Paths)",
        RegistryOrphanKind.OrphanedStartupRun => "Автозагрузка",
        RegistryOrphanKind.StaleAppCompatFlag => "Совместимость программ",
        RegistryOrphanKind.StaleMuiCache => "Кэш имен MUI",
        RegistryOrphanKind.DeadUninstallEntry => "Устаревшие деинсталляторы",
        RegistryOrphanKind.MissingHelpFile => "Файлы справки",
        RegistryOrphanKind.BrokenFirewallRule => "Правила брандмауэра",
        RegistryOrphanKind.BrokenSoundEvent => "Звуковые события",
        RegistryOrphanKind.StaleExplorerHistory => "Удаленные пути истории",
        _ => "Реестр"
    };
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

// ==================== WIZTREE-CLASS DISK ANALYZER MODELS ====================

public sealed record DiskVolumeSummary(
    string RootPath,
    string VolumeLabel,
    string FileSystem,
    long TotalBytes,
    long FreeBytes)
{
    public long UsedBytes => Math.Max(0L, TotalBytes - FreeBytes);
    public double UsedPercent => TotalBytes > 0 ? Math.Round((double)UsedBytes / TotalBytes * 100.0, 1) : 0;
    public double FreePercent => TotalBytes > 0 ? Math.Round((double)FreeBytes / TotalBytes * 100.0, 1) : 0;
    public bool IsCriticallyFull => UsedPercent >= 90.0;
    public string FormattedTotal => ByteFormatter.Format(TotalBytes);
    public string FormattedUsed => ByteFormatter.Format(UsedBytes);
    public string FormattedFree => ByteFormatter.Format(FreeBytes);

    public string DisplayTitle
    {
        get
        {
            var lbl = string.IsNullOrWhiteSpace(VolumeLabel) ? "Локальный диск" : VolumeLabel;
            return $"[{RootPath.TrimEnd('\\')}] {lbl} — свободно {FormattedFree} из {FormattedTotal} ({UsedPercent:F1}% занято)";
        }
    }
}

public sealed record DiskExtensionStat(
    string Extension,
    string FileTypeDescription,
    string ColorHex,
    long SizeBytes,
    long FileCount,
    double SharePercent)
{
    public string FormattedSize => ByteFormatter.Format(SizeBytes);
    public string ShareLabel => $"{SharePercent:F1} %";
    public string FilesCountFormatted => $"{FileCount:N0}";
}

public sealed record DiskTreeNode(
    string Name,
    string FullPath,
    bool IsDirectory,
    bool IsDirectFilesBucket,
    long SizeBytes,
    long FileCount,
    long FolderCount,
    double ShareOfRootPercent,
    double ShareOfParentPercent,
    DateTime LastModifiedLocal,
    string ColorHex,
    IReadOnlyList<DiskTreeNode> Children,
    bool MayHaveDeeperSubfolders = false)
{
    public string FormattedSize => ByteFormatter.Format(SizeBytes);
    public string ShareLabel => $"{ShareOfRootPercent:F1} %";
    public string FilesFormatted => $"{FileCount:N0}";
    public string FoldersFormatted => IsDirectory ? $"{FolderCount:N0}" : "—";
    public string ModifiedFormatted => LastModifiedLocal.Year > 1980 ? LastModifiedLocal.ToString("dd.MM.yyyy HH:mm") : "—";
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
    IReadOnlyList<DiskSpaceItem> LargestFiles,
    IReadOnlyList<DiskTreeNode>? RootTreeNodes = null,
    IReadOnlyList<DiskExtensionStat>? ExtensionStats = null,
    long TotalFoldersCount = 0)
{
    public string FormattedTotalScanned => ByteFormatter.Format(TotalScannedBytes);
    public IReadOnlyList<DiskTreeNode> SafeTreeNodes => RootTreeNodes ?? [];
    public IReadOnlyList<DiskExtensionStat> SafeExtensionStats => ExtensionStats ?? [];
}

// ==================== DUPLICATE FILE FINDER & SYSTEM RESERVES ====================

public sealed record DuplicateFileEntry(
    string FullPath,
    string FileName,
    string DirectoryPath,
    long SizeBytes,
    DateTime LastModifiedLocal,
    bool IsOriginalKeepSuggested);

public sealed record DuplicateFileGroup(
    string Sha256Hex,
    long FileSizeBytes,
    IReadOnlyList<DuplicateFileEntry> Entries)
{
    public long ReclaimableBytes => Entries.Count > 1 ? FileSizeBytes * (Entries.Count - 1) : 0;
    public string FormattedSingleSize => ByteFormatter.Format(FileSizeBytes);
    public string FormattedReclaimable => ByteFormatter.Format(ReclaimableBytes);
    public string ShortHash => Sha256Hex.Length >= 12 ? Sha256Hex[..12] : Sha256Hex;
}

public sealed record DuplicateScanReport(
    string RootPath,
    TimeSpan Elapsed,
    long ScannedFilesCount,
    long TotalReclaimableBytes,
    IReadOnlyList<DuplicateFileGroup> Groups)
{
    public string FormattedTotalReclaimable => ByteFormatter.Format(TotalReclaimableBytes);
}

public enum SystemReserveKind
{
    HibernationFile = 0,
    WindowsOldFolder = 1,
    WinSxSComponentStore = 2,
    WindowsUpdateDownloadCache = 3,
    DeliveryOptimizationCache = 4,
    PageFileInfo = 5
}

public sealed record SystemSpaceReserveItem(
    SystemReserveKind Kind,
    string Title,
    string Description,
    string PathDisplay,
    long SizeBytes,
    bool CanActionReclaim,
    bool RequiresAdmin,
    string ActionButtonLabel)
{
    public string FormattedSize => SizeBytes > 0 ? ByteFormatter.Format(SizeBytes) : "Не занимает место";
}
