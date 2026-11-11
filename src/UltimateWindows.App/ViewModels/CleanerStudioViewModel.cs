using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;
using UltimateWindows.App.Infrastructure;
using UltimateWindows.Core.Models;
using UltimateWindows.Modules.Cleaner.Browsers;
using UltimateWindows.Modules.Cleaner.Models;
using UltimateWindows.Modules.Cleaner.Rules;
using UltimateWindows.Modules.Cleaner.Services;

namespace UltimateWindows.App.ViewModels;

public sealed class RegistryCategoryFilterViewModel : ObservableObject
{
    private bool _isChecked = true;

    public RegistryCategoryFilterViewModel(RegistryOrphanKind kind, string title)
    {
        Kind = kind;
        Title = title;
    }

    public RegistryOrphanKind Kind { get; }
    public string Title { get; }

    public bool IsChecked
    {
        get => _isChecked;
        set => SetProperty(ref _isChecked, value);
    }
}

public sealed class SelectableRegistryOrphanViewModel : ObservableObject
{
    private bool _isSelected = true;

    public SelectableRegistryOrphanViewModel(RegistryOrphanCandidate candidate)
    {
        Candidate = candidate;
    }

    public RegistryOrphanCandidate Candidate { get; }
    public string CategoryTitle => Candidate.CategoryTitle;
    public string FriendlyReason => Candidate.FriendlyReason;
    public string MissingPath => Candidate.MissingReferencedFilePath;
    public string RegistryLocation => Candidate.FullRegistryDisplayPath;

    public bool IsSelected
    {
        get => _isSelected;
        set => SetProperty(ref _isSelected, value);
    }
}

public sealed class SelectableDuplicateItemViewModel : ObservableObject
{
    private bool _isSelected;

    public SelectableDuplicateItemViewModel(string groupShortHash, DuplicateFileEntry entry)
    {
        GroupShortHash = groupShortHash;
        Entry = entry;
        // Оригинал никогда не отмечаем к удалению автоматически!
        _isSelected = !entry.IsOriginalKeepSuggested;
    }

    public string GroupShortHash { get; }
    public DuplicateFileEntry Entry { get; }
    public string FileName => Entry.FileName;
    public string DirectoryPath => Entry.DirectoryPath;
    public string FullPath => Entry.FullPath;
    public string FormattedSize => ByteFormatter.Format(Entry.SizeBytes);
    public string RoleBadge => Entry.IsOriginalKeepSuggested ? "ОРИГИНАЛ (оставить)" : "Копия-дубликат";
    public string ModifiedDisplay => Entry.LastModifiedLocal.Year > 1980 ? Entry.LastModifiedLocal.ToString("dd.MM.yyyy HH:mm") : "—";

    public bool IsSelected
    {
        get => _isSelected;
        set => SetProperty(ref _isSelected, value);
    }
}

public sealed class SystemReserveItemViewModel : ObservableObject
{
    public SystemReserveItemViewModel(SystemSpaceReserveItem item, ICommand executeCommand)
    {
        Item = item;
        ExecuteCommand = executeCommand;
    }

    public SystemSpaceReserveItem Item { get; }
    public string Title => Item.Title;
    public string Description => Item.Description;
    public string PathDisplay => Item.PathDisplay;
    public string FormattedSize => Item.FormattedSize;
    public bool CanActionReclaim => Item.CanActionReclaim;
    public string ActionButtonLabel => Item.ActionButtonLabel;
    public ICommand ExecuteCommand { get; }
}

/// <summary>
/// Строка находки по правилу каталога программ или внешнего файла Winapp2.ini.
/// </summary>
public sealed class SelectableRuleFindingViewModel : ObservableObject
{
    private readonly Action _onSelectionChanged;
    private bool _isSelected;

    public SelectableRuleFindingViewModel(CleanupRuleFinding finding, Action onSelectionChanged)
    {
        Finding = finding;
        _onSelectionChanged = onSelectionChanged;
        _isSelected = finding.Rule.SelectedByDefault && finding.CanCleanNow;
    }

    public CleanupRuleFinding Finding { get; }
    public string SectionTitle => Finding.Rule.SectionTitle;
    public string Application => Finding.Application;
    public string RuleTitle => Finding.Rule.Title;
    public string KindTitle => Finding.Rule.KindTitle;
    public string Explanation => Finding.Rule.Warning is { Length: > 0 } w
        ? $"{Finding.Rule.Explanation} Внимание: {w}"
        : Finding.Rule.Explanation;
    public string FormattedSize => Finding.FormattedSize;
    public int FileCount => Finding.FileCount;
    public bool CanSelect => Finding.CanCleanNow;
    public string StatusNote => Finding.Notes.Count > 0
        ? Finding.Notes[0]
        : (Finding.Rule.Origin == CleanupRuleOrigin.External ? $"Внешний файл: {Finding.Rule.SourceName}" : "");

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            var next = value && CanSelect;
            if (SetProperty(ref _isSelected, next))
            {
                _onSelectionChanged();
            }
        }
    }
}

/// <summary>
/// Полноценный рабочий комбайн раздела «Диск, Очистка и Реестр»:
/// 0 = WizTree-анализатор диска (Дерево + Расширения + Интерактивный Squarified Treemap),
/// 1 = Стандартная очистка кэша с броней паролей и автозаполнения,
/// 2 = Гранулярная очистка реестра по 10 категориям (в стиле CCleaner) с бекапом,
/// 3 = Поиск дублей файлов (SHA-256) и освобождение системных гигабайт на C:\ (hiberfil.sys / WinSxS / Windows.old).
/// </summary>
public sealed class CleanerStudioViewModel : ObservableObject
{
    private readonly VaultSafeCleanerService _cleanerService;
    private readonly Func<string, Task> _onActionCompletedAsync;

    private CleanupScanReport? _lastScanReport;
    private CancellationTokenSource? _diskCts;
    private DiskTreeNode? _fullScannedRootNode;
    private readonly Stack<DiskTreeNode> _drillHistory = new();

    private int _selectedSubTabIndex;
    private bool _isFilesFlatView;

    // Опции стандартной очистки
    private bool _preservePasswordsAndAutofill = true;
    private bool _preserveBrowserSessions = true;
    private bool _cleanBrowserCaches = true;
    private bool _cleanSystemTempAndShaders = true;
    private bool _cleanRegistryOrphans = false;
    private bool _emptyRecycleBin;
    private bool _includeDeveloperCaches;

    // Пункты браузеров (Этап 2: по умолчанию включён только кэш)
    private bool _cleanBrowserHistory;
    private bool _cleanBrowserDownloads;
    private bool _cleanBrowserCookies;
    private bool _cleanBrowserSessions;
    private string _keepCookieDomainsText = "google.com, youtube.com, github.com, microsoft.com, live.com, ya.ru, yandex.ru, vk.com, mail.ru";

    // Каталог программ и Winapp2.ini
    private readonly List<SelectableRuleFindingViewModel> _allRuleFindings = [];
    private string _appRuleSearchText = "";
    private bool _showOnlyNonEmptyRules = true;
    private bool _isScanningAppRules;
    private bool _isCleaningAppRules;
    private string _appRulesStatusText = "";
    private string _externalWinapp2Badge = "Внешний Winapp2.ini не подключён (работает встроенный каталог программ)";

    private bool _isScanning;
    private bool _isCleaning;
    private bool _isAnalyzingDisk;
    private bool _isScanningRegistry;
    private bool _isScanningDuplicates;

    private string _scanSummaryHeadline = "Отметьте нужные пункты и нажмите «Анализ мусора» — пароли и автозаполнение браузеров защищены.";
    private string _browserWarningBanner = "";
    private string _lastCleanupOutcome = "";

    // WizTree Disk Map
    private DiskVolumeSummary? _selectedVolume;
    private string _diskMapTargetPath;
    private string _diskMapStatusText = "Выберите раздел диска и нажмите «Анализ» для построения дерева папок, типов файлов и визуальной карты блоков.";
    private DiskTreeNode? _selectedTreeNode;

    // Registry Cleaner
    private string _registryStatusText = "Выберите категории слева и нажмите «Поиск проблем реестра». Перед исправлением автоматически создается точка отката.";

    // Duplicate Finder & System Reserves
    private string _duplicateTargetPath;
    private int _selectedMinSizeIndex = 1; // 0=64KB, 1=1MB, 2=10MB, 3=50MB
    private string _duplicateStatusText = "Укажите папку (например, Загрузки или диск D:\\) для поиска 100% одинаковых копий файлов по SHA-256.";
    private string _reserveStatusBanner = "";

    public CleanerStudioViewModel(
        VaultSafeCleanerService cleanerService,
        Func<string, Task> onActionCompletedAsync)
    {
        _cleanerService = cleanerService;
        _onActionCompletedAsync = onActionCompletedAsync;

        var sysDrive = Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\";
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        _diskMapTargetPath = sysDrive;
        _duplicateTargetPath = !string.IsNullOrWhiteSpace(userProfile) && Directory.Exists(userProfile)
            ? userProfile
            : sysDrive;

        MountedVolumes = new ObservableCollection<DiskVolumeSummary>();
        TreeRootNodes = new ObservableCollection<DiskTreeNode>();
        TreemapNodes = new ObservableCollection<DiskTreeNode>();
        ExtensionStats = new ObservableCollection<DiskExtensionStat>();
        TopDirectories = new ObservableCollection<DiskSpaceItem>();
        LargestFiles = new ObservableCollection<DiskSpaceItem>();

        Categories = new ObservableCollection<CleanupCategorySummary>();
        CandidateFilesPreview = new ObservableCollection<CleanupCandidateFile>();

        RegistryCategoryFilters = new ObservableCollection<RegistryCategoryFilterViewModel>
        {
            new(RegistryOrphanKind.MissingSharedDll, "Отсутствующие общие DLL (SharedDlls)"),
            new(RegistryOrphanKind.BrokenAppPath, "Пути приложений (App Paths)"),
            new(RegistryOrphanKind.OrphanedStartupRun, "Автозагрузка (удаленные файлы)"),
            new(RegistryOrphanKind.StaleAppCompatFlag, "Флаги совместимости (AppCompat)"),
            new(RegistryOrphanKind.StaleMuiCache, "Кэш имен программ (MUI Cache)"),
            new(RegistryOrphanKind.DeadUninstallEntry, "Устаревшие записи удаления"),
            new(RegistryOrphanKind.MissingHelpFile, "Файлы справки Windows (Help)"),
            new(RegistryOrphanKind.BrokenFirewallRule, "Правила брандмауэра"),
            new(RegistryOrphanKind.BrokenSoundEvent, "Звуковые события приложений"),
            new(RegistryOrphanKind.StaleExplorerHistory, "Удаленные пути в истории Проводника"),
            new(RegistryOrphanKind.MissingFontReference, "Отсутствующие шрифты (Fonts)"),
            new(RegistryOrphanKind.MissingWindowsInstallerFolder, "Несуществующие папки MSI"),
            new(RegistryOrphanKind.BrokenStartupApprovedEntry, "Сироты флагов автозагрузки")
        };
        RegistryOrphanItems = new ObservableCollection<SelectableRegistryOrphanViewModel>();

        DuplicateItems = new ObservableCollection<SelectableDuplicateItemViewModel>();
        SystemReserves = new ObservableCollection<SystemReserveItemViewModel>();
        BrowserDetailItems = new ObservableCollection<BrowserDataItemSummary>();
        AppRuleFindings = new ObservableCollection<SelectableRuleFindingViewModel>();
        _appRulesStatusText = $"Встроенный каталог: {_cleanerService.GetCatalogRules().Count} правил программ. Нажмите «Найти хвосты программ» для анализа.";

        // Команды вкладок
        SelectSubTabCommand = new RelayCommand(p =>
        {
            if (p is string s && int.TryParse(s, out var idx)) SelectedSubTabIndex = idx;
        });

        // WizTree команды
        RefreshVolumesCommand = new RelayCommand(_ => ReloadVolumes());
        BrowseDiskTargetCommand = new RelayCommand(_ => BrowseFolderFor(isDuplicatePicker: false));
        AnalyzeDiskSpaceCommand = new AsyncRelayCommand(_ => AnalyzeDiskSpaceAsync());
        CancelDiskAnalysisCommand = new RelayCommand(_ => _diskCts?.Cancel());
        DrillDownNodeCommand = new RelayCommand(p =>
        {
            if (p is DiskTreeNode node && node.IsDirectory && node.Children.Count > 0)
            {
                DrillIntoNode(node);
            }
        });
        DrillUpCommand = new RelayCommand(_ => DrillUp(), _ => _drillHistory.Count > 0);
        OpenNodeInExplorerCommand = new RelayCommand(p => OpenInExplorer((p as DiskTreeNode)?.FullPath ?? SelectedTreeNode?.FullPath));
        CopyNodePathCommand = new RelayCommand(p => CopyPathToClipboard((p as DiskTreeNode)?.FullPath ?? SelectedTreeNode?.FullPath));
        RecycleSelectedNodeCommand = new AsyncRelayCommand(p => RecycleDiskNodeAsync((p as DiskTreeNode) ?? SelectedTreeNode));
        SelectDiskPresetCommand = new RelayCommand(p =>
        {
            if (p is string presetKey) ApplyDiskPreset(presetKey);
        });

        // Стандартная очистка
        ScanPreviewCommand = new AsyncRelayCommand(_ => RunScanPreviewAsync());
        ExecuteSafeCleanCommand = new AsyncRelayCommand(_ => ExecuteSafeCleanAsync(), _ => CanExecuteClean);

        // Реестр (CCleaner-стиль)
        ScanRegistryCommand = new AsyncRelayCommand(_ => ScanRegistryIssuesAsync());
        FixSelectedRegistryCommand = new AsyncRelayCommand(_ => FixSelectedRegistryIssuesAsync());
        ToggleAllRegistryCategoriesCommand = new RelayCommand(p =>
        {
            bool state = p as string != "false";
            foreach (var c in RegistryCategoryFilters) c.IsChecked = state;
        });
        ToggleAllRegistryItemsCommand = new RelayCommand(p =>
        {
            bool state = p as string != "false";
            foreach (var it in RegistryOrphanItems) it.IsSelected = state;
        });

        // Поиск дублей и системные резервы C:\
        BrowseDuplicateFolderCommand = new RelayCommand(_ => BrowseFolderFor(isDuplicatePicker: true));
        ScanDuplicatesCommand = new AsyncRelayCommand(_ => RunDuplicateScanAsync());
        RecycleSelectedDuplicatesCommand = new AsyncRelayCommand(_ => RecycleSelectedDuplicatesAsync());
        OpenDuplicateInExplorerCommand = new RelayCommand(p =>
        {
            if (p is SelectableDuplicateItemViewModel dup) OpenInExplorer(dup.FullPath);
        });
        RefreshSystemReservesCommand = new AsyncRelayCommand(_ => RefreshSystemReservesAsync());

        // Каталог правил программ + Winapp2.ini
        ScanAppRulesCommand = new AsyncRelayCommand(_ => ScanAppRulesAsync());
        ExecuteAppRulesCommand = new AsyncRelayCommand(_ => ExecuteSelectedAppRulesAsync(), _ => CanExecuteAppRules);
        ImportWinapp2Command = new RelayCommand(_ => BrowseAndImportWinapp2());
        ClearWinapp2Command = new RelayCommand(_ => ClearImportedWinapp2());
        SelectDefaultAppRulesCommand = new RelayCommand(_ =>
        {
            foreach (var f in _allRuleFindings)
            {
                f.IsSelected = f.Finding.Rule.SelectedByDefault && f.CanSelect;
            }
            UpdateAppRulesSelectionHeadline();
        });
        ClearSelectionAppRulesCommand = new RelayCommand(_ =>
        {
            foreach (var f in _allRuleFindings) f.IsSelected = false;
            UpdateAppRulesSelectionHeadline();
        });

        ReloadVolumes();
    }

    public ObservableCollection<DiskVolumeSummary> MountedVolumes { get; }
    public ObservableCollection<DiskTreeNode> TreeRootNodes { get; }
    public ObservableCollection<DiskTreeNode> TreemapNodes { get; }
    public ObservableCollection<DiskExtensionStat> ExtensionStats { get; }
    public ObservableCollection<DiskSpaceItem> TopDirectories { get; }
    public ObservableCollection<DiskSpaceItem> LargestFiles { get; }

    public ObservableCollection<CleanupCategorySummary> Categories { get; }
    public ObservableCollection<CleanupCandidateFile> CandidateFilesPreview { get; }

    public ObservableCollection<RegistryCategoryFilterViewModel> RegistryCategoryFilters { get; }
    public ObservableCollection<SelectableRegistryOrphanViewModel> RegistryOrphanItems { get; }

    public ObservableCollection<SelectableDuplicateItemViewModel> DuplicateItems { get; }
    public ObservableCollection<SystemReserveItemViewModel> SystemReserves { get; }
    public ObservableCollection<BrowserDataItemSummary> BrowserDetailItems { get; }
    public ObservableCollection<SelectableRuleFindingViewModel> AppRuleFindings { get; }

    public int SelectedSubTabIndex
    {
        get => _selectedSubTabIndex;
        set
        {
            if (SetProperty(ref _selectedSubTabIndex, value))
            {
                OnPropertyChanged(nameof(IsDiskAnalyzerTab));
                OnPropertyChanged(nameof(IsStandardCleanerTab));
                OnPropertyChanged(nameof(IsRegistryTab));
                OnPropertyChanged(nameof(IsDuplicatesAndSpaceTab));
                OnPropertyChanged(nameof(IsAppCatalogTab));
            }
        }
    }

    public bool IsDiskAnalyzerTab => SelectedSubTabIndex == 0;
    public bool IsStandardCleanerTab => SelectedSubTabIndex == 1;
    public bool IsRegistryTab => SelectedSubTabIndex == 2;
    public bool IsDuplicatesAndSpaceTab => SelectedSubTabIndex == 3;
    public bool IsAppCatalogTab => SelectedSubTabIndex == 4;

    public bool IsFilesFlatView
    {
        get => _isFilesFlatView;
        set
        {
            if (SetProperty(ref _isFilesFlatView, value))
            {
                OnPropertyChanged(nameof(IsTreeHierarchyView));
            }
        }
    }

    public bool IsTreeHierarchyView => !IsFilesFlatView;

    public DiskVolumeSummary? SelectedVolume
    {
        get => _selectedVolume;
        set
        {
            if (SetProperty(ref _selectedVolume, value) && value is not null)
            {
                DiskMapTargetPath = value.RootPath;
                OnPropertyChanged(nameof(HasSelectedVolume));
            }
        }
    }

    public bool HasSelectedVolume => SelectedVolume is not null;
    public bool CanDrillUp => _drillHistory.Count > 0;

    public DiskTreeNode? SelectedTreeNode
    {
        get => _selectedTreeNode;
        set
        {
            if (SetProperty(ref _selectedTreeNode, value))
            {
                OnPropertyChanged(nameof(SelectedNodePathDisplay));
            }
        }
    }

    public string SelectedNodePathDisplay => SelectedTreeNode is not null
        ? $"{SelectedTreeNode.FullPath}  •  {SelectedTreeNode.FormattedSize} ({SelectedTreeNode.ShareLabel})"
        : "Кликните по папке в дереве или блоку на карте снизу для просмотра и быстрых действий";

    public bool PreservePasswordsAndAutofill
    {
        get => _preservePasswordsAndAutofill;
        set
        {
            if (SetProperty(ref _preservePasswordsAndAutofill, value))
            {
                OnPropertyChanged(nameof(VaultShieldBadgeText));
            }
        }
    }

    public bool PreserveBrowserSessions { get => _preserveBrowserSessions; set => SetProperty(ref _preserveBrowserSessions, value); }
    public bool CleanBrowserCaches { get => _cleanBrowserCaches; set => SetProperty(ref _cleanBrowserCaches, value); }
    public bool CleanSystemTempAndShaders { get => _cleanSystemTempAndShaders; set => SetProperty(ref _cleanSystemTempAndShaders, value); }
    public bool CleanRegistryOrphans { get => _cleanRegistryOrphans; set => SetProperty(ref _cleanRegistryOrphans, value); }
    public bool EmptyRecycleBin { get => _emptyRecycleBin; set => SetProperty(ref _emptyRecycleBin, value); }
    public bool IncludeDeveloperCaches { get => _includeDeveloperCaches; set => SetProperty(ref _includeDeveloperCaches, value); }

    public bool CleanBrowserHistory
    {
        get => _cleanBrowserHistory;
        set { if (SetProperty(ref _cleanBrowserHistory, value)) RaiseCleanButtonState(); }
    }

    public bool CleanBrowserDownloads
    {
        get => _cleanBrowserDownloads;
        set { if (SetProperty(ref _cleanBrowserDownloads, value)) RaiseCleanButtonState(); }
    }

    public bool CleanBrowserCookies
    {
        get => _cleanBrowserCookies;
        set { if (SetProperty(ref _cleanBrowserCookies, value)) RaiseCleanButtonState(); }
    }

    public bool CleanBrowserSessions
    {
        get => _cleanBrowserSessions;
        set { if (SetProperty(ref _cleanBrowserSessions, value)) RaiseCleanButtonState(); }
    }

    public string KeepCookieDomainsText
    {
        get => _keepCookieDomainsText;
        set => SetProperty(ref _keepCookieDomainsText, value);
    }

    public string AppRuleSearchText
    {
        get => _appRuleSearchText;
        set { if (SetProperty(ref _appRuleSearchText, value)) ApplyAppRulesFilter(); }
    }

    public bool ShowOnlyNonEmptyRules
    {
        get => _showOnlyNonEmptyRules;
        set { if (SetProperty(ref _showOnlyNonEmptyRules, value)) ApplyAppRulesFilter(); }
    }

    public bool IsScanningAppRules
    {
        get => _isScanningAppRules;
        private set
        {
            if (SetProperty(ref _isScanningAppRules, value))
            {
                OnPropertyChanged(nameof(CanExecuteAppRules));
                ExecuteAppRulesCommand.RaiseCanExecuteChanged();
            }
        }
    }

    public bool IsCleaningAppRules
    {
        get => _isCleaningAppRules;
        private set
        {
            if (SetProperty(ref _isCleaningAppRules, value))
            {
                OnPropertyChanged(nameof(CanExecuteAppRules));
                ExecuteAppRulesCommand.RaiseCanExecuteChanged();
            }
        }
    }

    public bool CanExecuteAppRules =>
        !IsScanningAppRules &&
        !IsCleaningAppRules &&
        _allRuleFindings.Any(f => f.IsSelected && f.CanSelect);

    public string AppRulesStatusText { get => _appRulesStatusText; private set => SetProperty(ref _appRulesStatusText, value); }
    public string ExternalWinapp2Badge { get => _externalWinapp2Badge; private set => SetProperty(ref _externalWinapp2Badge, value); }
    public bool HasExternalWinapp2 => _cleanerService.ExternalRules.Count > 0;

    public string VaultShieldBadgeText => PreservePasswordsAndAutofill
        ? "БРОНЯ ПАРОЛЕЙ АКТИВНА: пароли, логины, куки входа и автозаполнение форм заблокированы от удаления"
        : "Внимание: защита паролей снята вручную (рекомендуется держать включенной)";

    public bool IsScanning
    {
        get => _isScanning;
        private set
        {
            if (SetProperty(ref _isScanning, value))
            {
                OnPropertyChanged(nameof(CanExecuteClean));
                ExecuteSafeCleanCommand.RaiseCanExecuteChanged();
            }
        }
    }

    public bool IsCleaning
    {
        get => _isCleaning;
        private set
        {
            if (SetProperty(ref _isCleaning, value))
            {
                OnPropertyChanged(nameof(CanExecuteClean));
                ExecuteSafeCleanCommand.RaiseCanExecuteChanged();
            }
        }
    }

    public bool IsAnalyzingDisk
    {
        get => _isAnalyzingDisk;
        private set => SetProperty(ref _isAnalyzingDisk, value);
    }

    public bool IsScanningRegistry
    {
        get => _isScanningRegistry;
        private set => SetProperty(ref _isScanningRegistry, value);
    }

    public bool IsScanningDuplicates
    {
        get => _isScanningDuplicates;
        private set => SetProperty(ref _isScanningDuplicates, value);
    }

    public bool CanExecuteClean =>
        !IsScanning &&
        !IsCleaning &&
        _lastScanReport is not null &&
        (_lastScanReport.TotalReclaimableBytes > 0 ||
         _lastScanReport.TotalRegistryOrphansCount > 0 ||
         (BrowserDetailItems.Count > 0 && (CleanBrowserHistory || CleanBrowserDownloads || CleanBrowserCookies || CleanBrowserSessions)));

    private void RaiseCleanButtonState()
    {
        OnPropertyChanged(nameof(CanExecuteClean));
        ExecuteSafeCleanCommand.RaiseCanExecuteChanged();
    }

    public string ScanSummaryHeadline { get => _scanSummaryHeadline; private set => SetProperty(ref _scanSummaryHeadline, value); }
    public string BrowserWarningBanner
    {
        get => _browserWarningBanner;
        private set
        {
            if (SetProperty(ref _browserWarningBanner, value)) OnPropertyChanged(nameof(HasBrowserWarnings));
        }
    }
    public bool HasBrowserWarnings => !string.IsNullOrWhiteSpace(BrowserWarningBanner);

    public string LastCleanupOutcome
    {
        get => _lastCleanupOutcome;
        private set
        {
            if (SetProperty(ref _lastCleanupOutcome, value)) OnPropertyChanged(nameof(HasCleanupOutcome));
        }
    }
    public bool HasCleanupOutcome => !string.IsNullOrWhiteSpace(LastCleanupOutcome);

    public string DiskMapTargetPath { get => _diskMapTargetPath; set => SetProperty(ref _diskMapTargetPath, value); }
    public string DiskMapStatusText { get => _diskMapStatusText; private set => SetProperty(ref _diskMapStatusText, value); }
    public string RegistryStatusText { get => _registryStatusText; private set => SetProperty(ref _registryStatusText, value); }
    public string DuplicateTargetPath { get => _duplicateTargetPath; set => SetProperty(ref _duplicateTargetPath, value); }
    public int SelectedMinSizeIndex { get => _selectedMinSizeIndex; set => SetProperty(ref _selectedMinSizeIndex, value); }
    public string DuplicateStatusText { get => _duplicateStatusText; private set => SetProperty(ref _duplicateStatusText, value); }
    public string ReserveStatusBanner
    {
        get => _reserveStatusBanner;
        private set
        {
            if (SetProperty(ref _reserveStatusBanner, value)) OnPropertyChanged(nameof(HasReserveStatusBanner));
        }
    }
    public bool HasReserveStatusBanner => !string.IsNullOrWhiteSpace(ReserveStatusBanner);

    public ICommand SelectSubTabCommand { get; }
    public ICommand RefreshVolumesCommand { get; }
    public ICommand BrowseDiskTargetCommand { get; }
    public ICommand AnalyzeDiskSpaceCommand { get; }
    public ICommand CancelDiskAnalysisCommand { get; }
    public ICommand DrillDownNodeCommand { get; }
    public RelayCommand DrillUpCommand { get; }
    public ICommand OpenNodeInExplorerCommand { get; }
    public ICommand CopyNodePathCommand { get; }
    public ICommand RecycleSelectedNodeCommand { get; }
    public ICommand SelectDiskPresetCommand { get; }

    public ICommand ScanPreviewCommand { get; }
    public AsyncRelayCommand ExecuteSafeCleanCommand { get; }

    public ICommand ScanRegistryCommand { get; }
    public ICommand FixSelectedRegistryCommand { get; }
    public ICommand ToggleAllRegistryCategoriesCommand { get; }
    public ICommand ToggleAllRegistryItemsCommand { get; }

    public ICommand BrowseDuplicateFolderCommand { get; }
    public ICommand ScanDuplicatesCommand { get; }
    public ICommand RecycleSelectedDuplicatesCommand { get; }
    public ICommand OpenDuplicateInExplorerCommand { get; }
    public ICommand RefreshSystemReservesCommand { get; }

    public ICommand ScanAppRulesCommand { get; }
    public AsyncRelayCommand ExecuteAppRulesCommand { get; }
    public ICommand ImportWinapp2Command { get; }
    public ICommand ClearWinapp2Command { get; }
    public ICommand SelectDefaultAppRulesCommand { get; }
    public ICommand ClearSelectionAppRulesCommand { get; }

    public void ReloadVolumes()
    {
        var vols = _cleanerService.GetMountedVolumes();
        MountedVolumes.Clear();
        foreach (var v in vols) MountedVolumes.Add(v);
        if (MountedVolumes.Count > 0 && SelectedVolume is null)
        {
            SelectedVolume = MountedVolumes[0];
        }
    }

    public async Task AnalyzeDiskSpaceAsync()
    {
        if (IsAnalyzingDisk || string.IsNullOrWhiteSpace(DiskMapTargetPath)) return;

        _diskCts?.Cancel();
        _diskCts = new CancellationTokenSource();
        IsAnalyzingDisk = true;
        _drillHistory.Clear();
        OnPropertyChanged(nameof(CanDrillUp));
        DrillUpCommand.RaiseCanExecuteChanged();

        DiskMapStatusText = $"Многопоточное сканирование «{DiskMapTargetPath}»...";

        try
        {
            var report = await _cleanerService.AnalyzeDiskSpaceAsync(
                DiskMapTargetPath,
                topDirectoryLimit: 40,
                largestFilesLimit: 150,
                ct: _diskCts.Token);

            TreeRootNodes.Clear();
            TreemapNodes.Clear();
            if (report.SafeTreeNodes.Count > 0)
            {
                _fullScannedRootNode = report.SafeTreeNodes[0];
                // Показываем дочерние узлы корня прямо на первом уровне (как в WizTree!)
                foreach (var ch in _fullScannedRootNode.Children)
                {
                    TreeRootNodes.Add(ch);
                    TreemapNodes.Add(ch);
                }
            }

            ExtensionStats.Clear();
            foreach (var ext in report.SafeExtensionStats)
            {
                ExtensionStats.Add(ext);
            }

            TopDirectories.Clear();
            foreach (var d in report.TopDirectories) TopDirectories.Add(d);

            LargestFiles.Clear();
            foreach (var f in report.LargestFiles) LargestFiles.Add(f);

            DiskMapStatusText =
                $"{report.ScanMethodDescription} — {report.Elapsed.TotalSeconds:F2} сек  •  Объём: {report.FormattedTotalScanned}  •  Файлов: {report.TotalFilesCount:N0}  •  Папок: {report.TotalFoldersCount:N0}";

            ReloadVolumes();
            await _onActionCompletedAsync($"Карта диска {DiskMapTargetPath} построена за {report.Elapsed.TotalSeconds:F2} сек");
        }
        catch (OperationCanceledException)
        {
            DiskMapStatusText = "Сканирование остановлено пользователем.";
        }
        catch (Exception ex)
        {
            DiskMapStatusText = $"Ошибка анализа пути: {ex.Message}";
        }
        finally
        {
            IsAnalyzingDisk = false;
        }
    }

    private void DrillIntoNode(DiskTreeNode node)
    {
        if (_fullScannedRootNode is not null)
        {
            _drillHistory.Push(_fullScannedRootNode);
        }

        _fullScannedRootNode = node;
        TreeRootNodes.Clear();
        TreemapNodes.Clear();
        foreach (var ch in node.Children)
        {
            TreeRootNodes.Add(ch);
            TreemapNodes.Add(ch);
        }

        DiskMapStatusText = $"Уровень папки: {node.FullPath} ({node.FormattedSize}, файлов: {node.FilesFormatted})";
        OnPropertyChanged(nameof(CanDrillUp));
        DrillUpCommand.RaiseCanExecuteChanged();
    }

    private void DrillUp()
    {
        if (_drillHistory.Count == 0) return;
        var prev = _drillHistory.Pop();
        _fullScannedRootNode = prev;

        TreeRootNodes.Clear();
        TreemapNodes.Clear();
        foreach (var ch in prev.Children)
        {
            TreeRootNodes.Add(ch);
            TreemapNodes.Add(ch);
        }

        DiskMapStatusText = $"Возврат к уровню: {prev.FullPath} ({prev.FormattedSize})";
        OnPropertyChanged(nameof(CanDrillUp));
        DrillUpCommand.RaiseCanExecuteChanged();
    }

    private async Task RecycleDiskNodeAsync(DiskTreeNode? node)
    {
        if (node is null || node.IsDirectFilesBucket) return;
        var confirm = MessageBox.Show(
            $"Переместить «{node.Name}» ({node.FormattedSize}) в Корзину Windows?\n\nПуть: {node.FullPath}",
            "Перемещение в Корзину",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (confirm != MessageBoxResult.Yes) return;

        var (ok, msg) = await _cleanerService.SafeSendToRecycleBinAsync(node.FullPath);
        DiskMapStatusText = msg;
        if (ok)
        {
            await _onActionCompletedAsync(msg);
            await AnalyzeDiskSpaceAsync();
        }
    }

    public async Task RunScanPreviewAsync()
    {
        if (IsScanning || IsCleaning) return;

        IsScanning = true;
        LastCleanupOutcome = "";
        ScanSummaryHeadline = "Сканирование кэша браузеров, временных папок и шейдеров GPU...";

        try
        {
            var options = BuildCleanupOptions();
            var report = await _cleanerService.ScanAsync(options);
            var keepDomains = BrowserDataCleaner.ParseKeepCookieDomains(KeepCookieDomainsText);
            var browserDetails = await _cleanerService.ScanBrowserDataDetailsAsync(keepDomains);
            _lastScanReport = report;

            Categories.Clear();
            foreach (var cat in report.Categories) Categories.Add(cat);

            BrowserDetailItems.Clear();
            foreach (var bd in browserDetails.Items) BrowserDetailItems.Add(bd);

            CandidateFilesPreview.Clear();
            foreach (var f in report.CandidateFiles.OrderByDescending(x => x.SizeBytes).Take(200))
            {
                CandidateFilesPreview.Add(f);
            }

            var allWarnings = report.RunningBrowserWarnings.Concat(browserDetails.Warnings).Distinct().ToList();
            BrowserWarningBanner = allWarnings.Count > 0 ? string.Join("\n", allWarnings) : "";

            ScanSummaryHeadline = report.TotalReclaimableBytes == 0 && report.TotalRegistryOrphansCount == 0 && browserDetails.Items.Count == 0
                ? "Система уже чиста — лишних временных данных не обнаружено."
                : $"Найдено файлов кэша и мусора: {report.FormattedTotalReclaimable} ({report.TotalFilesCount:N0} шт.); пунктов данных браузеров: {browserDetails.Items.Count}. Пароли и автозаполнение под защитой.";
            RaiseCleanButtonState();

            await _onActionCompletedAsync($"Анализ очистки завершен: {report.FormattedTotalReclaimable}");
        }
        catch (Exception ex)
        {
            ScanSummaryHeadline = $"Ошибка сканирования: {ex.Message}";
        }
        finally
        {
            IsScanning = false;
        }
    }

    private async Task ExecuteSafeCleanAsync()
    {
        if (_lastScanReport is null || IsCleaning || IsScanning) return;

        IsCleaning = true;
        try
        {
            var options = BuildCleanupOptions();
            var result = await _cleanerService.ExecuteCleanupAsync(_lastScanReport, options);
            var summary = result.UserSummaryMessage;

            if (CleanBrowserHistory || CleanBrowserDownloads || CleanBrowserCookies || CleanBrowserSessions)
            {
                var browserSelection = new BrowserCleanupSelection
                {
                    CleanCache = CleanBrowserCaches,
                    CleanHistory = CleanBrowserHistory,
                    CleanDownloads = CleanBrowserDownloads,
                    CleanCookies = CleanBrowserCookies,
                    CleanSessions = CleanBrowserSessions,
                    KeepCookieDomains = BrowserDataCleaner.ParseKeepCookieDomains(KeepCookieDomainsText)
                };
                var browserRes = await _cleanerService.CleanBrowserDataDetailsAsync(browserSelection);
                summary = summary + " " + browserRes.UserSummaryMessage;
            }

            LastCleanupOutcome = summary;
            _lastScanReport = null;
            Categories.Clear();
            BrowserDetailItems.Clear();
            CandidateFilesPreview.Clear();
            ScanSummaryHeadline = summary;
            ReloadVolumes();
            await _onActionCompletedAsync(result.UserSummaryMessage);
        }
        catch (Exception ex)
        {
            LastCleanupOutcome = $"Очистка остановлена защитным фильтром: {ex.Message}";
        }
        finally
        {
            IsCleaning = false;
        }
    }

    public async Task ScanRegistryIssuesAsync()
    {
        if (IsScanningRegistry) return;
        IsScanningRegistry = true;
        RegistryStatusText = "Проверка выбранных разделов реестра на ссылки к несуществующим файлам...";

        try
        {
            var selectedKinds = RegistryCategoryFilters
                .Where(c => c.IsChecked)
                .Select(c => c.Kind)
                .ToHashSet();

            var orphans = await _cleanerService.ScanRegistryCategoriesAsync(selectedKinds);
            RegistryOrphanItems.Clear();
            foreach (var o in orphans)
            {
                RegistryOrphanItems.Add(new SelectableRegistryOrphanViewModel(o));
            }

            RegistryStatusText = orphans.Count == 0
                ? "Проблем в выбранных категориях реестра не обнаружено."
                : $"Найдено проверенных устаревших записей реестра: {orphans.Count}. Отметьте нужные и нажмите «Исправить выбранные».";
        }
        catch (Exception ex)
        {
            RegistryStatusText = $"Ошибка проверки реестра: {ex.Message}";
        }
        finally
        {
            IsScanningRegistry = false;
        }
    }

    private async Task FixSelectedRegistryIssuesAsync()
    {
        var chosen = RegistryOrphanItems.Where(x => x.IsSelected).Select(x => x.Candidate).ToList();
        if (chosen.Count == 0)
        {
            RegistryStatusText = "Отметьте галочками записи для исправления.";
            return;
        }

        var (fixedCount, _, msg) = await _cleanerService.FixSelectedRegistryOrphansAsync(chosen);
        RegistryStatusText = msg;
        if (fixedCount > 0)
        {
            await _onActionCompletedAsync(msg);
            await ScanRegistryIssuesAsync();
        }
    }

    public async Task RunDuplicateScanAsync()
    {
        if (IsScanningDuplicates || string.IsNullOrWhiteSpace(DuplicateTargetPath)) return;
        IsScanningDuplicates = true;
        DuplicateStatusText = $"Трехступенчатый поиск точных дублей (SHA-256) в «{DuplicateTargetPath}»...";

        try
        {
            long minBytes = SelectedMinSizeIndex switch
            {
                0 => 64L * 1024,
                2 => 10L * 1024 * 1024,
                3 => 50L * 1024 * 1024,
                _ => 1024L * 1024
            };

            var rep = await _cleanerService.FindExactDuplicatesAsync(DuplicateTargetPath, minBytes, maxGroups: 150);
            DuplicateItems.Clear();
            foreach (var g in rep.Groups)
            {
                foreach (var e in g.Entries)
                {
                    DuplicateItems.Add(new SelectableDuplicateItemViewModel(g.ShortHash, e));
                }
            }

            DuplicateStatusText = rep.Groups.Count == 0
                ? $"Проверено файлов: {rep.ScannedFilesCount:N0} за {rep.Elapsed.TotalSeconds:F2} сек — полных дубликатов не найдено."
                : $"Найдено групп дублей: {rep.Groups.Count} (лишний объем: {rep.FormattedTotalReclaimable}) за {rep.Elapsed.TotalSeconds:F2} сек. Оригиналы сняты с выделения!";
        }
        catch (Exception ex)
        {
            DuplicateStatusText = $"Ошибка поиска дублей: {ex.Message}";
        }
        finally
        {
            IsScanningDuplicates = false;
        }
    }

    private async Task RecycleSelectedDuplicatesAsync()
    {
        var toRecycle = DuplicateItems.Where(d => d.IsSelected && !d.Entry.IsOriginalKeepSuggested).ToList();
        if (toRecycle.Count == 0)
        {
            DuplicateStatusText = "Не выбрано копий-дубликатов для перемещения в Корзину.";
            return;
        }

        int moved = 0;
        long bytes = 0;
        foreach (var item in toRecycle)
        {
            var (ok, _) = await _cleanerService.SafeSendToRecycleBinAsync(item.FullPath);
            if (ok)
            {
                moved++;
                bytes += item.Entry.SizeBytes;
                DuplicateItems.Remove(item);
            }
        }

        var summary = $"Перемещено дублей в Корзину: {moved} ({ByteFormatter.Format(bytes)}).";
        DuplicateStatusText = summary;
        ReloadVolumes();
        await _onActionCompletedAsync(summary);
    }

    public async Task RefreshSystemReservesAsync()
    {
        var items = await _cleanerService.InspectSystemReservesAsync();
        SystemReserves.Clear();
        foreach (var it in items)
        {
            var captured = it;
            SystemReserves.Add(new SystemReserveItemViewModel(
                captured,
                new AsyncRelayCommand(_ => ExecuteReserveItemAsync(captured))));
        }
    }

    private async Task ExecuteReserveItemAsync(SystemSpaceReserveItem item)
    {
        ReserveStatusBanner = $"Выполнение операции «{item.ActionButtonLabel}»...";
        var (ok, msg) = await _cleanerService.ExecuteSystemReserveActionAsync(item);
        ReserveStatusBanner = msg;
        if (ok)
        {
            ReloadVolumes();
            await RefreshSystemReservesAsync();
            await _onActionCompletedAsync(msg);
        }
    }

    public async Task ScanAppRulesAsync()
    {
        if (IsScanningAppRules || IsCleaningAppRules) return;
        IsScanningAppRules = true;
        AppRulesStatusText = "Анализ программ по каталогу правил под защитой BrowserVaultGuard...";

        try
        {
            var scan = await _cleanerService.ScanAppRulesAsync();
            _allRuleFindings.Clear();
            foreach (var finding in scan.Findings.Where(f => f.IsPresent).OrderByDescending(f => f.TotalBytes).ThenBy(f => f.Application))
            {
                _allRuleFindings.Add(new SelectableRuleFindingViewModel(finding, UpdateAppRulesSelectionHeadline));
            }

            ApplyAppRulesFilter();
            UpdateAppRulesSelectionHeadline(scan.Elapsed);
            await _onActionCompletedAsync($"Каталог программ проверен за {scan.Elapsed.TotalSeconds:F2} сек: найдено {scan.FormattedTotal}");
        }
        catch (Exception ex)
        {
            AppRulesStatusText = $"Ошибка анализа правил: {ex.Message}";
        }
        finally
        {
            IsScanningAppRules = false;
        }
    }

    private async Task ExecuteSelectedAppRulesAsync()
    {
        if (IsCleaningAppRules || IsScanningAppRules) return;
        var chosen = _allRuleFindings.Where(f => f.IsSelected && f.CanSelect).Select(f => f.Finding).ToList();
        if (chosen.Count == 0) return;

        IsCleaningAppRules = true;
        try
        {
            var exec = await _cleanerService.ExecuteAppRulesAsync(chosen);
            AppRulesStatusText = exec.UserSummaryMessage;
            ReloadVolumes();
            await _onActionCompletedAsync(exec.UserSummaryMessage);
            await ScanAppRulesAsync();
        }
        catch (Exception ex)
        {
            AppRulesStatusText = $"Очистка правил прервана: {ex.Message}";
        }
        finally
        {
            IsCleaningAppRules = false;
        }
    }

    private void BrowseAndImportWinapp2()
    {
        var dlg = new OpenFileDialog
        {
            Title = "Подключить файл правил формата Winapp2.ini",
            Filter = "Файлы правил Winapp2 (*.ini)|*.ini|Все файлы (*.*)|*.*"
        };

        if (dlg.ShowDialog() != true || string.IsNullOrWhiteSpace(dlg.FileName))
        {
            return;
        }

        ImportWinapp2FromPath(dlg.FileName);
    }

    public void ImportWinapp2FromPath(string filePath)
    {
        try
        {
            var res = _cleanerService.ImportExternalWinapp2File(filePath);
            ExternalWinapp2Badge = $"Подключён «{res.SourceName}»: правил {res.Rules.Count:N0} (пропущено несовместимых: {res.Skipped.Count:N0})";
            OnPropertyChanged(nameof(HasExternalWinapp2));
            AppRulesStatusText = $"Файл «{res.SourceName}» загружен. Все внешние правила по умолчанию сняты и проверяются защитой путей. Нажмите «Найти хвосты программ».";
        }
        catch (Exception ex)
        {
            AppRulesStatusText = $"Не удалось прочитать файл Winapp2.ini: {ex.Message}";
        }
    }

    public void ClearImportedWinapp2()
    {
        _cleanerService.ClearExternalWinapp2Rules();
        ExternalWinapp2Badge = "Внешний Winapp2.ini не подключён (работает встроенный каталог программ)";
        OnPropertyChanged(nameof(HasExternalWinapp2));
        AppRulesStatusText = "Внешние правила отключены — оставлен только встроенный каталог.";
    }

    private void ApplyAppRulesFilter()
    {
        var q = _appRuleSearchText.Trim();
        AppRuleFindings.Clear();
        foreach (var item in _allRuleFindings)
        {
            if (_showOnlyNonEmptyRules && !item.Finding.HasAnythingToClean)
            {
                continue;
            }

            if (q.Length > 0 &&
                !item.Application.Contains(q, StringComparison.OrdinalIgnoreCase) &&
                !item.RuleTitle.Contains(q, StringComparison.OrdinalIgnoreCase) &&
                !item.SectionTitle.Contains(q, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            AppRuleFindings.Add(item);
        }

        OnPropertyChanged(nameof(CanExecuteAppRules));
        ExecuteAppRulesCommand.RaiseCanExecuteChanged();
    }

    private void UpdateAppRulesSelectionHeadline(TimeSpan? elapsed = null)
    {
        var selected = _allRuleFindings.Where(f => f.IsSelected && f.CanSelect).ToList();
        var bytes = selected.Sum(f => f.Finding.TotalBytes);
        var files = selected.Sum(f => f.Finding.FileCount);
        var timePart = elapsed is { } el ? $" за {el.TotalSeconds:F2} сек" : "";
        AppRulesStatusText = _allRuleFindings.Count == 0
            ? "Установленных программ с временными данными из каталога не обнаружено."
            : $"Найдено правил для установленных программ: {_allRuleFindings.Count}{timePart}. Выбрано к очистке: {selected.Count} ({ByteFormatter.Format(bytes)}, файлов: {files:N0}).";
        OnPropertyChanged(nameof(CanExecuteAppRules));
        ExecuteAppRulesCommand.RaiseCanExecuteChanged();
    }

    private CleanupOptions BuildCleanupOptions() => new()
    {
        PreservePasswordsAndAutofill = PreservePasswordsAndAutofill,
        PreserveBrowserSessions = PreserveBrowserSessions && !CleanBrowserSessions,
        CleanBrowserCaches = CleanBrowserCaches,
        CleanSystemTempAndShaders = CleanSystemTempAndShaders,
        CleanRegistryOrphans = CleanRegistryOrphans,
        EmptyRecycleBin = EmptyRecycleBin,
        IncludeDeveloperCaches = IncludeDeveloperCaches,
        CleanBrowserHistory = CleanBrowserHistory,
        CleanBrowserDownloads = CleanBrowserDownloads,
        CleanBrowserCookies = CleanBrowserCookies,
        CleanBrowserSessions = CleanBrowserSessions,
        KeepCookieDomains = BrowserDataCleaner.ParseKeepCookieDomains(KeepCookieDomainsText)
    };

    private void BrowseFolderFor(bool isDuplicatePicker)
    {
        var dlg = new OpenFolderDialog
        {
            Title = isDuplicatePicker
                ? "Выберите папку для поиска дубликатов файлов"
                : "Выберите диск или папку для анализа места"
        };

        if (dlg.ShowDialog() == true && !string.IsNullOrWhiteSpace(dlg.FolderName))
        {
            if (isDuplicatePicker) DuplicateTargetPath = dlg.FolderName;
            else DiskMapTargetPath = dlg.FolderName;
        }
    }

    private void ApplyDiskPreset(string presetKey)
    {
        DiskMapTargetPath = presetKey switch
        {
            "SystemDrive" => Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\",
            "UserProfile" => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "Downloads" => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            "LocalAppData" => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            _ => DiskMapTargetPath
        };
    }

    private static void OpenInExplorer(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return;
        try
        {
            if (File.Exists(path))
            {
                Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true });
            }
            else if (Directory.Exists(path))
            {
                Process.Start(new ProcessStartInfo("explorer.exe", $"\"{path}\"") { UseShellExecute = true });
            }
        }
        catch
        {
            // Ignore
        }
    }

    private static void CopyPathToClipboard(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return;
        try
        {
            Clipboard.SetText(path);
        }
        catch
        {
            // Ignore
        }
    }
}
