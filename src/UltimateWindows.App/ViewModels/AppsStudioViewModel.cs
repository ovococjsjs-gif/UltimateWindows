using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;
using UltimateWindows.App.Infrastructure;
using UltimateWindows.Modules.Apps.Models;
using UltimateWindows.Modules.Apps.Services;
using UltimateWindows.Modules.Optimizer.Models;

namespace UltimateWindows.App.ViewModels;

public sealed class SelectableWingetUpgradeViewModel : ObservableObject
{
    private bool _isSelected = true;

    public SelectableWingetUpgradeViewModel(WingetUpgradablePackage package)
    {
        Package = package;
    }

    public WingetUpgradablePackage Package { get; }
    public bool IsSelected { get => _isSelected; set => SetProperty(ref _isSelected, value); }
    public string Name => Package.Name;
    public string PackageId => Package.PackageId;
    public string InstalledVersion => Package.InstalledVersion;
    public string AvailableVersion => Package.AvailableVersion;
    public string VersionTransitionDisplay => Package.VersionTransitionDisplay;
    public string Source => Package.Source;
}

public sealed class EssentialCatalogItemViewModel : ObservableObject
{
    private bool _isSelected;
    private bool _isInstalled;
    private string? _installedVersion;

    public EssentialCatalogItemViewModel(EssentialAppStatus status)
    {
        Entry = status.Entry;
        _isInstalled = status.IsInstalled;
        _installedVersion = status.InstalledVersion;
    }

    public EssentialAppEntry Entry { get; }

    public bool IsSelected
    {
        get => _isSelected;
        set => SetProperty(ref _isSelected, value);
    }

    public bool IsInstalled
    {
        get => _isInstalled;
        set
        {
            if (SetProperty(ref _isInstalled, value))
            {
                OnPropertyChanged(nameof(StatusBadge));
            }
        }
    }

    public string? InstalledVersion
    {
        get => _installedVersion;
        set
        {
            if (SetProperty(ref _installedVersion, value))
            {
                OnPropertyChanged(nameof(StatusBadge));
            }
        }
    }

    public string DisplayName => Entry.DisplayName;
    public string WingetId => Entry.WingetId;
    public string Vendor => Entry.Vendor;
    public string Summary => Entry.Summary;
    public string CategoryBadge => Entry.CategoryBadge;
    public string LicenseBadge => Entry.LicenseBadge;
    public string StatusBadge => IsInstalled
        ? (string.IsNullOrWhiteSpace(InstalledVersion) ? "Установлено" : $"Установлено (v{InstalledVersion})")
        : "Доступно";
}

public sealed class SelectableLeftoverItemViewModel : ObservableObject
{
    private bool _isSelected = true;

    public SelectableLeftoverItemViewModel(AppLeftoverItem item)
    {
        Item = item;
    }

    public AppLeftoverItem Item { get; }
    public bool IsSelected { get => _isSelected; set => SetProperty(ref _isSelected, value); }
    public string KindBadge => Item.KindBadge;
    public string TargetPath => Item.TargetPath;
    public string Reason => Item.Reason;
    public string FormattedSize => Item.FormattedSize;
}

public sealed class AppsStudioViewModel : ObservableObject
{
    private readonly AppsAndAutomationService _service;
    private readonly Func<string, Task> _notifyParentAsync;

    private int _selectedSubTabIndex;
    private bool _isBusy;
    private string _statusBannerText = "Готово: обновление и каталог программ winget, чистый деинсталлятор, готовность к Windows 11 и автопилот.";

    // Вкладка 0: Обновления winget
    private string _wingetStatusHeadline = "Нажмите «Проверить обновления», чтобы опросить пакетный менеджер winget";
    private bool _isWingetAvailable = true;

    // Вкладка 1: Каталог программ (36 пакетов)
    private string _catalogSearchQuery = string.Empty;
    private int _selectedCategoryFilterIndex; // 0 = Все, 1..6 = EssentialAppCategory + 1
    private string _catalogHeadline = "36 проверенных программ первой необходимости без рекламных сборок";
    private readonly List<EssentialCatalogItemViewModel> _allCatalogItems = new();

    // Вкладка 2: Чистый деинсталлятор
    private string _uninstallerSearchQuery = string.Empty;
    private InstalledApplicationInfo? _selectedInstalledApp;
    private string _leftoverSummaryText = "Выберите программу в списке слева и нажмите «Найти хвосты» для проверки остаточных папок и реестра.";
    private readonly List<InstalledApplicationInfo> _allInstalledApps = new();

    // Вкладка 3: Готовность к Windows 11, батарея, сон и память
    private string _win11Headline = "Проверка соответствия Windows 11 (24H2/25H2) и статуса поддержки Windows 10 ESU...";
    private string _win11LifecycleDeadline = string.Empty;
    private string _win11EsuHeadline = string.Empty;
    private string _win11Recommendation = string.Empty;
    private bool _isWin11FullyCompatible;
    private string _batteryHeadline = "Опрос контроллера питания...";
    private string _lastWakeSourceText = "—";
    private string _powerBlockersText = "Активных блокировщиков сна нет";
    private string _ramDiagnosticText = "Проверка памяти ещё не запускалась";

    // Вкладка 4: Автопилот (Планировщик заданий) и Единый диагностический архив
    private int _scheduleFrequencyIndex; // 0 = Отключено, 1 = Ежедневно, 2 = Еженедельно, 3 = Ежемесячно
    private int _scheduleRunHour = 12;
    private bool _scheduleCleanCache = true;
    private bool _scheduleCheckDrives = true;
    private bool _scheduleCheckSecurity = true;
    private string _scheduleNextRunText = "Не запланировано";
    private string _scheduleLastRunText = "Фоновый прогон ещё не выполнялся";
    private string _supportBundleStatusText = "Собирает в один .zip-архив паспорт железа, датчики, драйверы, дампы BSOD, статус Windows 11 и защиту — без паролей и личных файлов.";

    public AppsStudioViewModel(
        AppsAndAutomationService service,
        Func<string, Task> notifyParentAsync)
    {
        _service = service ?? throw new ArgumentNullException(nameof(service));
        _notifyParentAsync = notifyParentAsync ?? (_ => Task.CompletedTask);

        UpgradablePackages = new ObservableCollection<SelectableWingetUpgradeViewModel>();
        FilteredCatalogItems = new ObservableCollection<EssentialCatalogItemViewModel>();
        FilteredInstalledApps = new ObservableCollection<InstalledApplicationInfo>();
        FoundLeftovers = new ObservableCollection<SelectableLeftoverItemViewModel>();
        Win11Checks = new ObservableCollection<Win11CheckItem>();

        AvailableHours = Enumerable.Range(0, 24).Select(h => $"{h:00}:00").ToList();
        ScheduleFrequencyOptions =
        [
            "Отключено (только вручную)",
            "Ежедневно",
            "Еженедельно (по воскресеньям)",
            "Ежемесячно (1-го числа)"
        ];
        CatalogCategoryOptions =
        [
            "Все категории (36)",
            "Архиваторы и Утилиты",
            "Браузеры",
            "Медиа и Документы",
            "Общение и Доступ",
            "Игры и Стриминг",
            "Система и Разработка"
        ];

        ScanUpgradesCommand = new AsyncRelayCommand(_ => ScanUpgradesAsync(), _ => !IsBusy);
        UpgradeSelectedCommand = new AsyncRelayCommand(_ => UpgradeSelectedPackagesAsync(all: false), _ => !IsBusy);
        UpgradeAllCommand = new AsyncRelayCommand(_ => UpgradeSelectedPackagesAsync(all: true), _ => !IsBusy);

        RefreshCatalogCommand = new AsyncRelayCommand(_ => RefreshCatalogAsync(queryWinget: true), _ => !IsBusy);
        SelectPresetHomeCommand = new RelayCommand(_ => ApplyCatalogPreset(EssentialAppBundlePreset.FreshHomeInstall));
        SelectPresetGamerCommand = new RelayCommand(_ => ApplyCatalogPreset(EssentialAppBundlePreset.GamerPc));
        SelectPresetDevCommand = new RelayCommand(_ => ApplyCatalogPreset(EssentialAppBundlePreset.PowerUserAndDev));
        ClearCatalogSelectionCommand = new RelayCommand(_ => ClearCatalogSelection());
        InstallSelectedCatalogCommand = new AsyncRelayCommand(_ => InstallSelectedCatalogAppsAsync(), _ => !IsBusy);

        RefreshInstalledAppsCommand = new AsyncRelayCommand(_ => RefreshInstalledAppsAsync(), _ => !IsBusy);
        ScanLeftoversCommand = new AsyncRelayCommand(_ => ScanSelectedAppLeftoversAsync(), _ => !IsBusy && SelectedInstalledApp is not null);
        CleanLeftoversOnlyCommand = new AsyncRelayCommand(_ => CleanSelectedLeftoversOnlyAsync(), _ => !IsBusy && SelectedInstalledApp is not null);
        UninstallCleanCommand = new AsyncRelayCommand(_ => RunCleanUninstallAsync(), _ => !IsBusy && SelectedInstalledApp is not null);
        ForceRemoveAppCommand = new AsyncRelayCommand(_ => RunForceRemoveAppAsync(), _ => !IsBusy && SelectedInstalledApp is not null);

        RefreshWin11AndSleepCommand = new AsyncRelayCommand(_ => RefreshWin11AndSleepAsync(), _ => !IsBusy);
        ExportBatteryReportCommand = new AsyncRelayCommand(_ => ExportBatteryReportDialogAsync(), _ => !IsBusy);
        LaunchRamDiagnosticCommand = new AsyncRelayCommand(_ => LaunchMemoryDiagnosticWithPromptAsync(), _ => !IsBusy);

        SaveScheduleCommand = new AsyncRelayCommand(_ => SaveMaintenanceScheduleAsync(), _ => !IsBusy);
        RunMaintenanceNowCommand = new AsyncRelayCommand(_ => RunMaintenanceNowAsync(), _ => !IsBusy);
        ExportSupportBundleCommand = new AsyncRelayCommand(_ => ExportSupportBundleDialogAsync(), _ => !IsBusy);
    }

    public ObservableCollection<SelectableWingetUpgradeViewModel> UpgradablePackages { get; }
    public ObservableCollection<EssentialCatalogItemViewModel> FilteredCatalogItems { get; }
    public ObservableCollection<InstalledApplicationInfo> FilteredInstalledApps { get; }
    public ObservableCollection<SelectableLeftoverItemViewModel> FoundLeftovers { get; }
    public ObservableCollection<Win11CheckItem> Win11Checks { get; }

    public IReadOnlyList<string> AvailableHours { get; }
    public IReadOnlyList<string> ScheduleFrequencyOptions { get; }
    public IReadOnlyList<string> CatalogCategoryOptions { get; }

    public int SelectedSubTabIndex
    {
        get => _selectedSubTabIndex;
        set
        {
            if (SetProperty(ref _selectedSubTabIndex, value))
            {
                OnPropertyChanged(nameof(IsUpgradesTab));
                OnPropertyChanged(nameof(IsCatalogTab));
                OnPropertyChanged(nameof(IsUninstallerTab));
                OnPropertyChanged(nameof(IsWin11AndSleepTab));
                OnPropertyChanged(nameof(IsAutopilotTab));
            }
        }
    }

    public bool IsUpgradesTab => SelectedSubTabIndex == 0;
    public bool IsCatalogTab => SelectedSubTabIndex == 1;
    public bool IsUninstallerTab => SelectedSubTabIndex == 2;
    public bool IsWin11AndSleepTab => SelectedSubTabIndex == 3;
    public bool IsAutopilotTab => SelectedSubTabIndex == 4;

    public bool IsBusy
    {
        get => _isBusy;
        private set
        {
            if (SetProperty(ref _isBusy, value))
            {
                CommandManager.InvalidateRequerySuggested();
            }
        }
    }

    public string StatusBannerText { get => _statusBannerText; private set => SetProperty(ref _statusBannerText, value); }
    public string WingetStatusHeadline { get => _wingetStatusHeadline; private set => SetProperty(ref _wingetStatusHeadline, value); }
    public bool IsWingetAvailable { get => _isWingetAvailable; private set => SetProperty(ref _isWingetAvailable, value); }

    public string CatalogSearchQuery
    {
        get => _catalogSearchQuery;
        set
        {
            if (SetProperty(ref _catalogSearchQuery, value))
            {
                RebuildFilteredCatalog();
            }
        }
    }

    public int SelectedCategoryFilterIndex
    {
        get => _selectedCategoryFilterIndex;
        set
        {
            if (SetProperty(ref _selectedCategoryFilterIndex, value))
            {
                RebuildFilteredCatalog();
            }
        }
    }

    public string CatalogHeadline { get => _catalogHeadline; private set => SetProperty(ref _catalogHeadline, value); }

    public string UninstallerSearchQuery
    {
        get => _uninstallerSearchQuery;
        set
        {
            if (SetProperty(ref _uninstallerSearchQuery, value))
            {
                RebuildFilteredInstalledApps();
            }
        }
    }

    public InstalledApplicationInfo? SelectedInstalledApp
    {
        get => _selectedInstalledApp;
        set
        {
            if (SetProperty(ref _selectedInstalledApp, value))
            {
                FoundLeftovers.Clear();
                LeftoverSummaryText = value is null
                    ? "Выберите программу слева для поиска остаточных хвостов."
                    : $"Выбрана «{value.DisplayName}». Нажмите «Найти хвосты», «Удалить чисто» или «Принудительно».";
                CommandManager.InvalidateRequerySuggested();
            }
        }
    }

    public string LeftoverSummaryText { get => _leftoverSummaryText; private set => SetProperty(ref _leftoverSummaryText, value); }

    public string Win11Headline { get => _win11Headline; private set => SetProperty(ref _win11Headline, value); }
    public string Win11LifecycleDeadline { get => _win11LifecycleDeadline; private set => SetProperty(ref _win11LifecycleDeadline, value); }
    public string Win11EsuHeadline { get => _win11EsuHeadline; private set => SetProperty(ref _win11EsuHeadline, value); }
    public string Win11Recommendation { get => _win11Recommendation; private set => SetProperty(ref _win11Recommendation, value); }
    public bool IsWin11FullyCompatible { get => _isWin11FullyCompatible; private set => SetProperty(ref _isWin11FullyCompatible, value); }
    public string BatteryHeadline { get => _batteryHeadline; private set => SetProperty(ref _batteryHeadline, value); }
    public string LastWakeSourceText { get => _lastWakeSourceText; private set => SetProperty(ref _lastWakeSourceText, value); }
    public string PowerBlockersText { get => _powerBlockersText; private set => SetProperty(ref _powerBlockersText, value); }
    public string RamDiagnosticText { get => _ramDiagnosticText; private set => SetProperty(ref _ramDiagnosticText, value); }

    public int ScheduleFrequencyIndex { get => _scheduleFrequencyIndex; set => SetProperty(ref _scheduleFrequencyIndex, Math.Clamp(value, 0, 3)); }
    public int ScheduleRunHour { get => _scheduleRunHour; set => SetProperty(ref _scheduleRunHour, Math.Clamp(value, 0, 23)); }
    public bool ScheduleCleanCache { get => _scheduleCleanCache; set => SetProperty(ref _scheduleCleanCache, value); }
    public bool ScheduleCheckDrives { get => _scheduleCheckDrives; set => SetProperty(ref _scheduleCheckDrives, value); }
    public bool ScheduleCheckSecurity { get => _scheduleCheckSecurity; set => SetProperty(ref _scheduleCheckSecurity, value); }
    public string ScheduleNextRunText { get => _scheduleNextRunText; private set => SetProperty(ref _scheduleNextRunText, value); }
    public string ScheduleLastRunText { get => _scheduleLastRunText; private set => SetProperty(ref _scheduleLastRunText, value); }
    public string SupportBundleStatusText { get => _supportBundleStatusText; private set => SetProperty(ref _supportBundleStatusText, value); }

    public ICommand ScanUpgradesCommand { get; }
    public ICommand UpgradeSelectedCommand { get; }
    public ICommand UpgradeAllCommand { get; }
    public ICommand RefreshCatalogCommand { get; }
    public ICommand SelectPresetHomeCommand { get; }
    public ICommand SelectPresetGamerCommand { get; }
    public ICommand SelectPresetDevCommand { get; }
    public ICommand ClearCatalogSelectionCommand { get; }
    public ICommand InstallSelectedCatalogCommand { get; }
    public ICommand RefreshInstalledAppsCommand { get; }
    public ICommand ScanLeftoversCommand { get; }
    public ICommand CleanLeftoversOnlyCommand { get; }
    public ICommand UninstallCleanCommand { get; }
    public ICommand ForceRemoveAppCommand { get; }
    public ICommand RefreshWin11AndSleepCommand { get; }
    public ICommand ExportBatteryReportCommand { get; }
    public ICommand LaunchRamDiagnosticCommand { get; }
    public ICommand SaveScheduleCommand { get; }
    public ICommand RunMaintenanceNowCommand { get; }
    public ICommand ExportSupportBundleCommand { get; }

    public async Task InitializeFastAsync()
    {
        await RefreshCatalogAsync(queryWinget: false);
        await RefreshInstalledAppsAsync();
        await RefreshWin11AndSleepAsync();
        await LoadMaintenanceScheduleAsync();

        var (avail, ver) = await _service.ProbeWingetAsync();
        IsWingetAvailable = avail;
        WingetStatusHeadline = avail
            ? $"Пакетный менеджер winget активен ({ver}) • Нажмите «Проверить обновления» для поиска новых версий"
            : $"Пакетный менеджер winget не обнаружен ({ver}) — установите «App Installer» Microsoft";
    }

    // ==================== ДЕЙСТВИЯ ВКЛАДКИ 0: WINGET ОБНОВЛЕНИЯ ====================

    public async Task ScanUpgradesAsync()
    {
        IsBusy = true;
        try
        {
            StatusBannerText = "Опрос официального репозитория winget на наличие новых версий установленных программ...";
            var (available, version, packages) = await _service.ScanAvailableUpgradesAsync();
            IsWingetAvailable = available;

            UpgradablePackages.Clear();
            foreach (var pkg in packages)
            {
                UpgradablePackages.Add(new SelectableWingetUpgradeViewModel(pkg));
            }

            WingetStatusHeadline = !available
                ? $"winget недоступен ({version})"
                : packages.Count == 0
                    ? $"winget {version}: все установленные программы актуальны (обновлений не найдено)"
                    : $"winget {version}: найдено доступных обновлений — {packages.Count}";

            StatusBannerText = WingetStatusHeadline;
            await _notifyParentAsync(WingetStatusHeadline);
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task UpgradeSelectedPackagesAsync(bool all)
    {
        var targets = (all ? UpgradablePackages : UpgradablePackages.Where(x => x.IsSelected)).ToList();
        if (targets.Count == 0)
        {
            StatusBannerText = "Отметьте хотя бы одну программу для обновления.";
            return;
        }

        IsBusy = true;
        try
        {
            var okCount = 0;
            for (var i = 0; i < targets.Count; i++)
            {
                var item = targets[i];
                StatusBannerText = $"Обновление ({i + 1}/{targets.Count}): {item.Name} → {item.AvailableVersion}...";
                var res = await _service.UpgradePackageAsync(item.PackageId, item.Name);
                if (res.Succeeded)
                {
                    okCount++;
                }
            }

            var msg = $"Обновлено программ через winget: {okCount} из {targets.Count}.";
            StatusBannerText = msg;
            await _notifyParentAsync(msg);
            await ScanUpgradesAsync();
        }
        finally
        {
            IsBusy = false;
        }
    }

    // ==================== ДЕЙСТВИЯ ВКЛАДКИ 1: КАТАЛОГ 36 ПРОГРАММ ====================

    public async Task RefreshCatalogAsync(bool queryWinget)
    {
        var evaluated = await _service.EvaluateEssentialCatalogAsync(queryWinget);
        _allCatalogItems.Clear();
        foreach (var st in evaluated)
        {
            _allCatalogItems.Add(new EssentialCatalogItemViewModel(st));
        }

        var installedCount = _allCatalogItems.Count(x => x.IsInstalled);
        CatalogHeadline = $"В каталоге {_allCatalogItems.Count} проверенных программ • Уже установлено на этом ПК: {installedCount}";
        RebuildFilteredCatalog();
    }

    public void ApplyCatalogPreset(EssentialAppBundlePreset preset)
    {
        foreach (var item in _allCatalogItems)
        {
            item.IsSelected = !item.IsInstalled && item.Entry.Presets.Contains(preset);
        }

        var selected = _allCatalogItems.Count(x => x.IsSelected);
        StatusBannerText = $"Отмечено к установке по набору: {selected} (уже установленные программы пропущены).";
    }

    public void ClearCatalogSelection()
    {
        foreach (var item in _allCatalogItems)
        {
            item.IsSelected = false;
        }
    }

    public async Task InstallSelectedCatalogAppsAsync()
    {
        var selected = _allCatalogItems.Where(x => x.IsSelected).ToList();
        if (selected.Count == 0)
        {
            StatusBannerText = "Отметьте галочками нужные программы из каталога или выберите готовый набор.";
            return;
        }

        IsBusy = true;
        try
        {
            var okCount = 0;
            for (var i = 0; i < selected.Count; i++)
            {
                var item = selected[i];
                StatusBannerText = $"Тихая официальная установка ({i + 1}/{selected.Count}): {item.DisplayName} ({item.WingetId})...";
                var res = await _service.InstallEssentialAppAsync(item.Entry);
                if (res.Succeeded)
                {
                    okCount++;
                    item.IsInstalled = true;
                    item.IsSelected = false;
                }
            }

            var msg = $"Установка из каталога завершена: успешно {okCount} из {selected.Count}.";
            StatusBannerText = msg;
            await RefreshInstalledAppsAsync();
            await _notifyParentAsync(msg);
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void RebuildFilteredCatalog()
    {
        FilteredCatalogItems.Clear();
        var query = _catalogSearchQuery.Trim();

        foreach (var item in _allCatalogItems)
        {
            if (_selectedCategoryFilterIndex > 0)
            {
                var expectedCat = (EssentialAppCategory)(_selectedCategoryFilterIndex - 1);
                if (item.Entry.Category != expectedCat)
                {
                    continue;
                }
            }

            if (!string.IsNullOrWhiteSpace(query) &&
                !item.DisplayName.Contains(query, StringComparison.OrdinalIgnoreCase) &&
                !item.Summary.Contains(query, StringComparison.OrdinalIgnoreCase) &&
                !item.WingetId.Contains(query, StringComparison.OrdinalIgnoreCase) &&
                !item.Vendor.Contains(query, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            FilteredCatalogItems.Add(item);
        }
    }

    // ==================== ДЕЙСТВИЯ ВКЛАДКИ 2: ЧИСТЫЙ ДЕИНСТАЛЛЯТОР ====================

    public async Task RefreshInstalledAppsAsync()
    {
        var apps = await _service.GetInstalledApplicationsAsync();
        _allInstalledApps.Clear();
        _allInstalledApps.AddRange(apps);
        RebuildFilteredInstalledApps();
    }

    private void RebuildFilteredInstalledApps()
    {
        FilteredInstalledApps.Clear();
        var q = _uninstallerSearchQuery.Trim();
        foreach (var app in _allInstalledApps)
        {
            if (!string.IsNullOrWhiteSpace(q) &&
                !app.DisplayName.Contains(q, StringComparison.OrdinalIgnoreCase) &&
                !app.Publisher.Contains(q, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            FilteredInstalledApps.Add(app);
        }
    }

    public async Task ScanSelectedAppLeftoversAsync()
    {
        if (SelectedInstalledApp is null)
        {
            return;
        }

        IsBusy = true;
        try
        {
            var target = SelectedInstalledApp;
            var leftovers = await _service.ScanApplicationLeftoversAsync(target);
            FoundLeftovers.Clear();
            foreach (var item in leftovers)
            {
                FoundLeftovers.Add(new SelectableLeftoverItemViewModel(item));
            }

            LeftoverSummaryText = leftovers.Count == 0
                ? $"Для «{target.DisplayName}» отдельных папок AppData/ProgramData и осиротевших ключей не обнаружено."
                : $"Найдено связанных путей и веток реестра для «{target.DisplayName}»: {leftovers.Count}. Все объекты перед удалением сохраняются в Машину времени.";
            StatusBannerText = LeftoverSummaryText;
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task CleanSelectedLeftoversOnlyAsync()
    {
        if (SelectedInstalledApp is null)
        {
            return;
        }

        var chosen = FoundLeftovers.Where(x => x.IsSelected).Select(x => x.Item).ToList();
        if (chosen.Count == 0)
        {
            StatusBannerText = "Нет отмеченных хвостов для зачистки.";
            return;
        }

        IsBusy = true;
        try
        {
            var res = await _service.CleanSelectedLeftoversAsync(SelectedInstalledApp, chosen);
            LeftoverSummaryText = res.SummaryMessage;
            StatusBannerText = res.SummaryMessage;
            await _notifyParentAsync(res.SummaryMessage);
            await ScanSelectedAppLeftoversAsync();
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task RunCleanUninstallAsync()
    {
        if (SelectedInstalledApp is null)
        {
            return;
        }

        IsBusy = true;
        try
        {
            var target = SelectedInstalledApp;
            StatusBannerText = $"Запуск штатного деинсталлятора «{target.DisplayName}» с последующим поиском и карантином хвостов...";
            var res = await _service.UninstallWithLeftoverSweepAsync(target);
            LeftoverSummaryText = res.SummaryMessage;
            StatusBannerText = res.SummaryMessage;
            await RefreshInstalledAppsAsync();
            await _notifyParentAsync(res.SummaryMessage);
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task RunForceRemoveAppAsync()
    {
        if (SelectedInstalledApp is null)
        {
            return;
        }

        var target = SelectedInstalledApp;
        var confirm = MessageBox.Show(
            $"Выполнить принудительное удаление «{target.DisplayName}»?\n\n" +
            "Используйте этот режим, если штатный uninstall.exe повреждён или удалён. " +
            "Запущенные процессы программы будут остановлены, а файлы, хвосты и запись реестра сохранены в карантин Машины времени.",
            "Принудительное удаление программы",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirm != MessageBoxResult.Yes)
        {
            return;
        }

        IsBusy = true;
        try
        {
            var res = await _service.ForceRemoveBrokenAppAsync(target);
            LeftoverSummaryText = res.SummaryMessage;
            StatusBannerText = res.SummaryMessage;
            await RefreshInstalledAppsAsync();
            await _notifyParentAsync(res.SummaryMessage);
        }
        finally
        {
            IsBusy = false;
        }
    }

    // ==================== ДЕЙСТВИЯ ВКЛАДКИ 3: WINDOWS 11, СОН, БАТАРЕЯ И ПАМЯТЬ ====================

    public async Task RefreshWin11AndSleepAsync()
    {
        var win11 = await _service.CheckWindows11ReadinessAsync();
        IsWin11FullyCompatible = win11.IsFullyCompatible;
        Win11Headline = win11.OverallHeadline;
        Win11LifecycleDeadline = win11.Lifecycle.SupportDeadlineText;
        Win11EsuHeadline = win11.Lifecycle.EsuStatusHeadline;
        Win11Recommendation = win11.Lifecycle.RecommendationText;

        Win11Checks.Clear();
        foreach (var check in win11.Checks)
        {
            Win11Checks.Add(check);
        }

        var power = await _service.CheckPowerSleepAndRamAsync();
        BatteryHeadline = power.BatteryStatusHeadline;
        LastWakeSourceText = power.LastWakeSource;
        PowerBlockersText = power.ActivePowerBlockers.Count == 0
            ? "Активных процессов, мешающих переходу в сон, не обнаружено"
            : string.Join(" | ", power.ActivePowerBlockers.Take(4));
        RamDiagnosticText = power.LastRamDiagnosticSummary;
    }

    private async Task ExportBatteryReportDialogAsync()
    {
        var dlg = new SaveFileDialog
        {
            Title = "Сохранить системный HTML-отчёт об износе аккумулятора",
            Filter = "Веб-страница HTML (*.html)|*.html",
            FileName = $"BatteryReport-{DateTime.Now:yyyyMMdd-HHmm}.html"
        };

        if (dlg.ShowDialog() != true)
        {
            return;
        }

        IsBusy = true;
        try
        {
            var saved = await _service.ExportBatteryHtmlReportAsync(dlg.FileName);
            var msg = saved is not null
                ? $"Отчёт о батарее сохранён: {saved}"
                : "Не удалось сформировать отчёт о батарее (возможно, на стационарном ПК отсутствует аккумулятор).";
            StatusBannerText = msg;
            await _notifyParentAsync(msg);
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task LaunchMemoryDiagnosticWithPromptAsync()
    {
        var ok = await _service.LaunchWindowsMemoryDiagnosticAsync();
        var msg = ok
            ? "Открыто штатное средство диагностики оперативной памяти Windows (mdsched.exe)."
            : "Не удалось открыть mdsched.exe (требуются права администратора).";
        StatusBannerText = msg;
        await _notifyParentAsync(msg);
    }

    // ==================== ДЕЙСТВИЯ ВКЛАДКИ 4: АВТОПИЛОТ И ДИАГНОСТИЧЕСКИЙ АРХИВ ====================

    public async Task LoadMaintenanceScheduleAsync()
    {
        var sched = await _service.GetMaintenanceScheduleAsync();
        ScheduleFrequencyIndex = (int)sched.Frequency;
        ScheduleRunHour = sched.RunHourLocal;
        ScheduleCleanCache = sched.CleanSafeTempCache;
        ScheduleCheckDrives = sched.CheckDriveSmartHealth;
        ScheduleCheckSecurity = sched.AuditSecurityAndStartup;
        ScheduleNextRunText = sched.NextRunDisplay;
        ScheduleLastRunText = sched.LastRunSummary;
    }

    public async Task SaveMaintenanceScheduleAsync()
    {
        IsBusy = true;
        try
        {
            var freq = (MaintenanceFrequency)ScheduleFrequencyIndex;
            var desired = new MaintenanceScheduleProfile(
                IsEnabled: freq != MaintenanceFrequency.Disabled,
                Frequency: freq,
                RunHourLocal: ScheduleRunHour,
                CleanSafeTempCache: ScheduleCleanCache,
                CheckDriveSmartHealth: ScheduleCheckDrives,
                AuditSecurityAndStartup: ScheduleCheckSecurity,
                TaskSchedulerPath: @"\UltimateWindows\AutoMaintenance",
                NextRunDisplay: string.Empty,
                LastRunSummary: ScheduleLastRunText);

            var applied = await _service.SaveMaintenanceScheduleAsync(desired);
            ScheduleNextRunText = applied.NextRunDisplay;
            ScheduleLastRunText = applied.LastRunSummary;

            var msg = applied.IsEnabled
                ? $"Расписание автообслуживания включено: {applied.FrequencyDisplay}"
                : "Фоновое автообслуживание в Планировщике Windows отключено.";
            StatusBannerText = msg;
            await _notifyParentAsync(msg);
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task RunMaintenanceNowAsync()
    {
        IsBusy = true;
        try
        {
            StatusBannerText = "Выполняется бережный прогон автообслуживания (временный кэш без паролей, S.M.A.R.T. дисков, защита)...";
            var summary = await _service.RunAutoMaintenanceNowAsync(
                ScheduleCleanCache,
                ScheduleCheckDrives,
                ScheduleCheckSecurity);

            ScheduleLastRunText = summary.Headline;
            StatusBannerText = $"Автообслуживание завершено: {summary.Headline}";
            await _notifyParentAsync(StatusBannerText);
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task<SupportBundleResult> ExportSupportBundleInternalAsync(string zipFilePath)
    {
        IsBusy = true;
        try
        {
            StatusBannerText = "Сборка единого диагностического архива (.zip): железо, датчики, драйверы, BSOD, Windows 11 и защита...";
            var result = await _service.ExportSupportBundleAsync(zipFilePath);
            SupportBundleStatusText = $"{result.SummaryMessage} ({result.FormattedSize})";
            StatusBannerText = SupportBundleStatusText;
            await _notifyParentAsync(SupportBundleStatusText);
            return result;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task ExportSupportBundleDialogAsync()
    {
        var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var dlg = new SaveFileDialog
        {
            Title = "Сохранить единый диагностический архив ПК (.zip)",
            InitialDirectory = Directory.Exists(docs) ? docs : AppContext.BaseDirectory,
            Filter = "ZIP-архив диагностики (*.zip)|*.zip",
            FileName = $"UltimateWindows-Diagnostics-{Environment.MachineName}-{DateTime.Now:yyyyMMdd-HHmm}.zip"
        };

        if (dlg.ShowDialog() != true)
        {
            return;
        }

        await ExportSupportBundleInternalAsync(dlg.FileName);
    }
}
