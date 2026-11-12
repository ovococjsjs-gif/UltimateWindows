using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows.Input;
using Microsoft.Win32;
using UltimateWindows.App.Infrastructure;
using UltimateWindows.Modules.Drivers.Analyzers;
using UltimateWindows.Modules.Drivers.Catalog;
using UltimateWindows.Modules.Drivers.Models;
using UltimateWindows.Modules.Drivers.Services;

namespace UltimateWindows.App.ViewModels;

public sealed record DriverCategoryFilterOption(EssentialDriverCategory? Category, string Title);

public sealed class DriverFindingItemViewModel : ObservableObject
{
    public DriverFindingItemViewModel(
        DriverAuditFinding finding,
        ICommand installWhqlCommand,
        ICommand backupInfCommand,
        ICommand openVendorPortalCommand)
    {
        Finding = finding;
        InstallWhqlCommand = installWhqlCommand;
        BackupInfCommand = backupInfCommand;
        OpenVendorPortalCommand = openVendorPortalCommand;
    }

    public DriverAuditFinding Finding { get; }
    public string SimpleTitle => Finding.SimpleTitle;
    public string SimpleExplanation => Finding.SimpleExplanation;
    public string ExpertTechnicalDetails => Finding.ExpertTechnicalDetails;
    public bool CanInstallViaWindowsUpdate => Finding.CanInstallViaWindowsUpdate;
    public bool CanBackupOemInf => Finding.CanBackupOemInf;
    public bool HasOfficialVendorUrl => !string.IsNullOrWhiteSpace(Finding.OfficialVendorUrl);

    public ICommand InstallWhqlCommand { get; }
    public ICommand BackupInfCommand { get; }
    public ICommand OpenVendorPortalCommand { get; }
}

public sealed class SystemDeviceRowViewModel : ObservableObject
{
    public SystemDeviceRowViewModel(
        SystemDeviceNode device,
        DriverAuditFinding? finding,
        ICommand installWhqlCommand,
        ICommand lookupCatalogCommand,
        ICommand backupInfCommand,
        ICommand openVendorCommand)
    {
        Device = device;
        Finding = finding;
        InstallWhqlCommand = installWhqlCommand;
        LookupCatalogCommand = lookupCatalogCommand;
        BackupInfCommand = backupInfCommand;
        OpenVendorCommand = openVendorCommand;
    }

    public SystemDeviceNode Device { get; }
    public DriverAuditFinding? Finding { get; }

    public string FriendlyName => Device.FriendlyName;
    public string DeviceClass => string.IsNullOrWhiteSpace(Device.DeviceClass) ? "System" : Device.DeviceClass;
    public string ProviderText => Device.EffectiveProvider;
    public string VersionAndDate => string.IsNullOrWhiteSpace(Device.DriverVersion)
        ? "—"
        : (string.IsNullOrWhiteSpace(Device.DriverDate) ? Device.DriverVersion : $"{Device.DriverVersion} ({Device.DriverDate})");
    public string InfAndStatus => string.IsNullOrWhiteSpace(Device.InfName)
        ? Device.StatusBadge
        : $"{Device.InfName} • {Device.SignatureBadge}";
    public string PrimaryHardwareId => Device.PrimaryHardwareId;
    public string StatusBadge => Device.StatusBadge;

    public bool CanInstallViaWindowsUpdate => Finding?.CanInstallViaWindowsUpdate == true;
    public bool CanBackupOemInf => Device.IsThirdPartyOemInf;
    public bool HasVendorUrl => !string.IsNullOrWhiteSpace(Finding?.OfficialVendorUrl ?? HardwareIdAndProblemAnalyzer.ResolveOfficialVendorPortal(Device.HardwareIds)?.OfficialPortalUrl);

    public ICommand InstallWhqlCommand { get; }
    public ICommand LookupCatalogCommand { get; }
    public ICommand BackupInfCommand { get; }
    public ICommand OpenVendorCommand { get; }
}

public sealed class EssentialDriverItemViewModel : ObservableObject
{
    public EssentialDriverItemViewModel(
        EssentialDriverEvaluatedItem item,
        ICommand downloadToFolderCommand,
        ICommand downloadAndInstallCommand,
        ICommand openPortalCommand)
    {
        Item = item;
        DownloadToFolderCommand = downloadToFolderCommand;
        DownloadAndInstallCommand = downloadAndInstallCommand;
        OpenPortalCommand = openPortalCommand;
    }

    public EssentialDriverEvaluatedItem Item { get; }
    public EssentialDriverPackage Package => Item.Package;

    public string CategoryLabel => Package.CategoryLabel;
    public string Title => Package.Title;
    public string Vendor => Package.Vendor;
    public string ScenarioSummary => Item.MatchedDeviceSummary is not null
        ? $"{Item.MatchedDeviceSummary} — {Package.ScenarioSummary}"
        : Package.ScenarioSummary;
    public string PcRelevanceBadge => Item.PcRelevanceBadge;
    public string DeliveryBadge => $"{Package.DeliveryBadge} ({Package.EstimatedSizeLabel})";

    public ICommand DownloadToFolderCommand { get; }
    public ICommand DownloadAndInstallCommand { get; }
    public ICommand OpenPortalCommand { get; }
}

public sealed class LiveCatalogEntryViewModel : ObservableObject
{
    public LiveCatalogEntryViewModel(
        MicrosoftCatalogDriverEntry entry,
        ICommand downloadCabCommand,
        ICommand installCabCommand)
    {
        Entry = entry;
        DownloadCabCommand = downloadCabCommand;
        InstallCabCommand = installCabCommand;
    }

    public MicrosoftCatalogDriverEntry Entry { get; }
    public string Title => Entry.Title;
    public string Products => Entry.Products;
    public string Version => Entry.Version;
    public string LastUpdatedText => Entry.LastUpdatedText;
    public string FormattedSize => Entry.FormattedSize;

    public ICommand DownloadCabCommand { get; }
    public ICommand InstallCabCommand { get; }
}

public sealed class VulnerableDriverItemViewModel : ObservableObject
{
    public VulnerableDriverItemViewModel(
        VulnerableDriverFinding finding,
        ICommand neutralizeCommand)
    {
        Finding = finding;
        NeutralizeCommand = neutralizeCommand;
    }

    public VulnerableDriverFinding Finding { get; }
    public string ServiceAndFile => $"{Finding.InstalledDriver.ServiceName} ({Finding.InstalledDriver.FileName})";
    public string FamilyName => Finding.MatchedRule.FamilyName;
    public string CveAndState => $"{Finding.MatchedRule.CveOrAdvisory} • {Finding.StateText}";
    public string AbuseExplanation => Finding.MatchedRule.AbuseExplanation;
    public string SafeAlternative => Finding.MatchedRule.SafeAlternative;
    public bool CanNeutralize => Finding.CanSafelyNeutralize;

    public ICommand NeutralizeCommand { get; }
}

/// <summary>
/// ViewModel Этапа 5 («Драйверы 2.0 и Каталог основных драйверов с серверов на все случаи жизни»).
/// </summary>
public sealed class DriverStudioViewModel : ObservableObject
{
    private readonly OfficialDriverService _driverService;
    private readonly Func<string, Task> _onActionCompletedAsync;
    private readonly Action? _switchToCatalogTab;

    private readonly List<SystemDeviceRowViewModel> _allDeviceRows = [];
    private readonly List<EssentialDriverItemViewModel> _allEssentialItems = [];

    private bool _queryWindowsUpdateOnline;
    private bool _isBusy;
    private int _driverScore = 100;
    private string _driverSummaryHeadline = "Нажмите «Проверить драйверы», чтобы опросить все устройства CfgMgr32, версии, подписи и обновления WHQL.";
    private string _driverKpiStrip = "Ожидание проверки устройств...";
    private string _lastDriverOperationBanner = "";

    private string _deviceSearchText = "";
    private bool _onlyActionableOrOemDevices;

    private DriverCategoryFilterOption _selectedEssentialCategory;
    private string _essentialSearchText = "";
    private bool _onlyMatchingCurrentPc;
    private string _downloadTargetFolder = OfficialDriverService.GetDefaultDownloadRootDirectory();
    private string _catalogStatusText = "Выберите любой драйвер из 39 проверенных пакетов или выполните живой поиск в Каталоге Microsoft по Hardware ID.";

    private string _catalogLiveQuery = @"PCI\VEN_10EC&DEV_8125";

    private string _driverStoreHeadline = "Нажмите «Обновить DriverStore» для подсчёта объёма и поиска старых дублей драйверов.";
    private bool _hasDuplicateStoreEntries;
    private string _rescueTargetFolder = Path.Combine(OfficialDriverService.GetDefaultDownloadRootDirectory(), "Offline-Network-Rescue");
    private string _rescueStatusText = "Создайте спасательную папку сетевых и NVMe драйверов заранее (с этого ПК или с серверов Microsoft/Google).";

    private string _vulnerableHeadline = "Нажмите «Проверить драйверы ядра» для поиска уязвимых модулей BYOVD (WinRing0, RTCore64, gdrv и др.).";
    private bool _canEnableBlocklist;

    public DriverStudioViewModel(
        OfficialDriverService driverService,
        Func<string, Task> onActionCompletedAsync,
        Action? switchToCatalogTab = null)
    {
        _driverService = driverService;
        _onActionCompletedAsync = onActionCompletedAsync;
        _switchToCatalogTab = switchToCatalogTab;

        DriverFindings = new ObservableCollection<DriverFindingItemViewModel>();
        FilteredDevices = new ObservableCollection<SystemDeviceRowViewModel>();
        EssentialCategoryOptions = new ObservableCollection<DriverCategoryFilterOption>(
            EssentialDriverCatalog.GetCategoryFilterOptions().Select(x => new DriverCategoryFilterOption(x.Category, x.Title)));
        _selectedEssentialCategory = EssentialCategoryOptions[0];

        FilteredEssentialPackages = new ObservableCollection<EssentialDriverItemViewModel>();
        LiveCatalogResults = new ObservableCollection<LiveCatalogEntryViewModel>();
        DriverStoreEntries = new ObservableCollection<DriverStoreEntry>();
        RescuePackLogLines = new ObservableCollection<string>();
        VulnerableFindings = new ObservableCollection<VulnerableDriverItemViewModel>();

        AuditDriversCommand = new AsyncRelayCommand(_ => RunDriverAuditAsync());
        BrowseDownloadFolderCommand = new RelayCommand(_ => BrowseFolder(path => DownloadTargetFolder = path, DownloadTargetFolder));
        SearchLiveCatalogCommand = new AsyncRelayCommand(_ => SearchLiveMicrosoftCatalogAsync());

        RefreshDriverStoreCommand = new AsyncRelayCommand(_ => RefreshDriverStoreAsync());
        CleanOldDriverStoreCommand = new AsyncRelayCommand(_ => CleanOldStoreDuplicatesAsync());
        BackupAllDriversCommand = new AsyncRelayCommand(_ => BackupAllDriversInteractiveAsync());
        RestoreDriversFolderCommand = new AsyncRelayCommand(_ => RestoreDriversInteractiveAsync());

        BrowseRescueFolderCommand = new RelayCommand(_ => BrowseFolder(path => RescueTargetFolder = path, RescueTargetFolder));
        BuildLocalRescuePackCommand = new AsyncRelayCommand(_ => BuildRescuePackAsync(downloadFromServers: false));
        BuildServerRescuePackCommand = new AsyncRelayCommand(_ => BuildRescuePackAsync(downloadFromServers: true));

        AuditVulnerableDriversCommand = new AsyncRelayCommand(_ => RefreshVulnerableDriversAsync());
        EnableMicrosoftBlocklistCommand = new AsyncRelayCommand(_ => EnableMicrosoftBlocklistAsync());
    }

    public ObservableCollection<DriverFindingItemViewModel> DriverFindings { get; }
    public ObservableCollection<SystemDeviceRowViewModel> FilteredDevices { get; }
    public ObservableCollection<DriverCategoryFilterOption> EssentialCategoryOptions { get; }
    public ObservableCollection<EssentialDriverItemViewModel> FilteredEssentialPackages { get; }
    public ObservableCollection<LiveCatalogEntryViewModel> LiveCatalogResults { get; }
    public ObservableCollection<DriverStoreEntry> DriverStoreEntries { get; }
    public ObservableCollection<string> RescuePackLogLines { get; }
    public ObservableCollection<VulnerableDriverItemViewModel> VulnerableFindings { get; }

    public bool QueryWindowsUpdateOnline
    {
        get => _queryWindowsUpdateOnline;
        set => SetProperty(ref _queryWindowsUpdateOnline, value);
    }

    public bool IsBusy
    {
        get => _isBusy;
        private set => SetProperty(ref _isBusy, value);
    }

    public int DriverScore
    {
        get => _driverScore;
        private set
        {
            if (SetProperty(ref _driverScore, value))
            {
                OnPropertyChanged(nameof(DriverScoreBadge));
            }
        }
    }

    public string DriverScoreBadge => $"Драйверы: {DriverScore} / 100";

    public string DriverSummaryHeadline
    {
        get => _driverSummaryHeadline;
        private set => SetProperty(ref _driverSummaryHeadline, value);
    }

    public string DriverKpiStrip
    {
        get => _driverKpiStrip;
        private set => SetProperty(ref _driverKpiStrip, value);
    }

    public string LastDriverOperationBanner
    {
        get => _lastDriverOperationBanner;
        private set
        {
            if (SetProperty(ref _lastDriverOperationBanner, value))
            {
                OnPropertyChanged(nameof(HasDriverOperationBanner));
            }
        }
    }

    public bool HasDriverOperationBanner => !string.IsNullOrWhiteSpace(LastDriverOperationBanner);
    public bool HasDriverFindings => DriverFindings.Count > 0;

    public string DeviceSearchText
    {
        get => _deviceSearchText;
        set
        {
            if (SetProperty(ref _deviceSearchText, value))
            {
                ApplyDeviceFilter();
            }
        }
    }

    public bool OnlyActionableOrOemDevices
    {
        get => _onlyActionableOrOemDevices;
        set
        {
            if (SetProperty(ref _onlyActionableOrOemDevices, value))
            {
                ApplyDeviceFilter();
            }
        }
    }

    public DriverCategoryFilterOption SelectedEssentialCategory
    {
        get => _selectedEssentialCategory;
        set
        {
            if (SetProperty(ref _selectedEssentialCategory, value))
            {
                ApplyEssentialFilter();
            }
        }
    }

    public string EssentialSearchText
    {
        get => _essentialSearchText;
        set
        {
            if (SetProperty(ref _essentialSearchText, value))
            {
                ApplyEssentialFilter();
            }
        }
    }

    public bool OnlyMatchingCurrentPc
    {
        get => _onlyMatchingCurrentPc;
        set
        {
            if (SetProperty(ref _onlyMatchingCurrentPc, value))
            {
                ApplyEssentialFilter();
            }
        }
    }

    public string DownloadTargetFolder
    {
        get => _downloadTargetFolder;
        set => SetProperty(ref _downloadTargetFolder, value);
    }

    public string CatalogStatusText
    {
        get => _catalogStatusText;
        private set => SetProperty(ref _catalogStatusText, value);
    }

    public string CatalogLiveQuery
    {
        get => _catalogLiveQuery;
        set => SetProperty(ref _catalogLiveQuery, value);
    }

    public string DriverStoreHeadline
    {
        get => _driverStoreHeadline;
        private set => SetProperty(ref _driverStoreHeadline, value);
    }

    public bool HasDuplicateStoreEntries
    {
        get => _hasDuplicateStoreEntries;
        private set => SetProperty(ref _hasDuplicateStoreEntries, value);
    }

    public string RescueTargetFolder
    {
        get => _rescueTargetFolder;
        set => SetProperty(ref _rescueTargetFolder, value);
    }

    public string RescueStatusText
    {
        get => _rescueStatusText;
        private set => SetProperty(ref _rescueStatusText, value);
    }

    public string VulnerableHeadline
    {
        get => _vulnerableHeadline;
        private set => SetProperty(ref _vulnerableHeadline, value);
    }

    public bool CanEnableBlocklist
    {
        get => _canEnableBlocklist;
        private set => SetProperty(ref _canEnableBlocklist, value);
    }

    public ICommand AuditDriversCommand { get; }
    public ICommand BrowseDownloadFolderCommand { get; }
    public ICommand SearchLiveCatalogCommand { get; }
    public ICommand RefreshDriverStoreCommand { get; }
    public ICommand CleanOldDriverStoreCommand { get; }
    public ICommand BackupAllDriversCommand { get; }
    public ICommand RestoreDriversFolderCommand { get; }
    public ICommand BrowseRescueFolderCommand { get; }
    public ICommand BuildLocalRescuePackCommand { get; }
    public ICommand BuildServerRescuePackCommand { get; }
    public ICommand AuditVulnerableDriversCommand { get; }
    public ICommand EnableMicrosoftBlocklistCommand { get; }

    /// <summary>
    /// Быстрая стартовая инициализация всех вкладок драйверов (без медленного сетевого опроса Windows Update).
    /// </summary>
    public async Task InitializeFastAsync()
    {
        await RunDriverAuditInternalAsync(queryOnlineWu: false, notifyBanner: false);
        await RefreshDriverStoreAsync(notifyBanner: false);
        await RefreshVulnerableDriversAsync(notifyBanner: false);
    }

    public Task RunDriverAuditAsync() =>
        RunDriverAuditInternalAsync(QueryWindowsUpdateOnline, notifyBanner: true);

    private async Task RunDriverAuditInternalAsync(bool queryOnlineWu, bool notifyBanner)
    {
        if (IsBusy) return;

        IsBusy = true;
        DriverSummaryHeadline = queryOnlineWu
            ? "Опрос дерева устройств CfgMgr32 и поиск подписанных WHQL-обновлений в Windows Update..."
            : "Быстрый опрос дерева устройств CfgMgr32 (версии, даты, поставщики, подписи и ошибки)...";

        try
        {
            var report = await _driverService.AuditDevicesAndDriversAsync(queryOnlineWu);
            DriverScore = report.DriverHealthScore;
            DriverSummaryHeadline = report.SummaryHeadline;
            DriverKpiStrip = $"Всего устройств: {report.TotalDevicesScanned} • Сторонних пакетов (oemXX.inf): {report.ThirdPartyOemDeviceCount} • Ошибок (Код 28/43): {report.ProblemDeviceCount} • WHQL-обновлений: {report.WhqlUpdatesAvailableCount}";

            var findingByInstance = report.Findings.ToDictionary(f => f.Device.InstanceId, StringComparer.OrdinalIgnoreCase);

            DriverFindings.Clear();
            foreach (var f in report.Findings)
            {
                var captured = f;
                DriverFindings.Add(new DriverFindingItemViewModel(
                    captured,
                    new AsyncRelayCommand(_ => InstallWhqlAsync(captured)),
                    new AsyncRelayCommand(_ => BackupOemInfAsync(captured.Device)),
                    new RelayCommand(_ => OpenOfficialVendorUrl(captured.OfficialVendorUrl))));
            }

            _allDeviceRows.Clear();
            foreach (var dev in report.AllDevices
                         .OrderByDescending(d => d.HasProblem)
                         .ThenByDescending(d => d.IsBasicDisplayFallback)
                         .ThenByDescending(d => d.IsThirdPartyOemInf)
                         .ThenBy(d => d.DeviceClass)
                         .ThenBy(d => d.FriendlyName))
            {
                findingByInstance.TryGetValue(dev.InstanceId, out var matchedFinding);
                var capturedDev = dev;
                var capturedFinding = matchedFinding;
                var portalUrl = matchedFinding?.OfficialVendorUrl ?? HardwareIdAndProblemAnalyzer.ResolveOfficialVendorPortal(dev.HardwareIds)?.OfficialPortalUrl;

                _allDeviceRows.Add(new SystemDeviceRowViewModel(
                    capturedDev,
                    capturedFinding,
                    new AsyncRelayCommand(_ => capturedFinding is not null ? InstallWhqlAsync(capturedFinding) : Task.CompletedTask),
                    new AsyncRelayCommand(_ => JumpAndSearchCatalogForDeviceAsync(capturedDev)),
                    new AsyncRelayCommand(_ => BackupOemInfAsync(capturedDev)),
                    new RelayCommand(_ => OpenOfficialVendorUrl(portalUrl))));
            }

            ApplyDeviceFilter();

            var evaluatedEssentials = await _driverService.GetEvaluatedEssentialDriversAsync(report.AllDevices);
            _allEssentialItems.Clear();
            foreach (var item in evaluatedEssentials)
            {
                var capturedPkg = item.Package;
                _allEssentialItems.Add(new EssentialDriverItemViewModel(
                    item,
                    new AsyncRelayCommand(_ => DownloadOrInstallEssentialAsync(capturedPkg, installNow: false)),
                    new AsyncRelayCommand(_ => DownloadOrInstallEssentialAsync(capturedPkg, installNow: true)),
                    new RelayCommand(_ => OpenOfficialVendorUrl(capturedPkg.OfficialPortalUrl))));
            }

            ApplyEssentialFilter();
            var matchedCount = evaluatedEssentials.Count(e => e.MatchesCurrentPcHardware);
            CatalogStatusText = $"Доступно пакетов на все случаи жизни: {evaluatedEssentials.Count} (совпадают с железом этого ПК: {matchedCount}). Скачивание идёт напрямую с серверов вендоров и Microsoft.";

            OnPropertyChanged(nameof(HasDriverFindings));
            if (notifyBanner)
            {
                await _onActionCompletedAsync(report.SummaryHeadline);
            }
        }
        catch (Exception ex)
        {
            DriverSummaryHeadline = $"Ошибка при проверке драйверов: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void ApplyDeviceFilter()
    {
        FilteredDevices.Clear();
        var q = DeviceSearchText?.Trim() ?? "";

        foreach (var row in _allDeviceRows)
        {
            if (OnlyActionableOrOemDevices && !row.Device.HasProblem && !row.Device.IsBasicDisplayFallback && !row.Device.IsThirdPartyOemInf)
            {
                continue;
            }

            if (q.Length > 0 &&
                !row.FriendlyName.Contains(q, StringComparison.OrdinalIgnoreCase) &&
                !row.DeviceClass.Contains(q, StringComparison.OrdinalIgnoreCase) &&
                !row.ProviderText.Contains(q, StringComparison.OrdinalIgnoreCase) &&
                !row.PrimaryHardwareId.Contains(q, StringComparison.OrdinalIgnoreCase) &&
                !row.Device.InfName.Contains(q, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            FilteredDevices.Add(row);
        }
    }

    private void ApplyEssentialFilter()
    {
        FilteredEssentialPackages.Clear();
        var cat = SelectedEssentialCategory?.Category;
        var q = EssentialSearchText?.Trim() ?? "";

        foreach (var item in _allEssentialItems)
        {
            if (cat.HasValue && item.Package.Category != cat.Value)
            {
                continue;
            }

            if (OnlyMatchingCurrentPc && !item.Item.MatchesCurrentPcHardware)
            {
                continue;
            }

            if (q.Length > 0 &&
                !item.Title.Contains(q, StringComparison.OrdinalIgnoreCase) &&
                !item.Vendor.Contains(q, StringComparison.OrdinalIgnoreCase) &&
                !item.ScenarioSummary.Contains(q, StringComparison.OrdinalIgnoreCase) &&
                !item.CategoryLabel.Contains(q, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            FilteredEssentialPackages.Add(item);
        }
    }

    private async Task JumpAndSearchCatalogForDeviceAsync(SystemDeviceNode device)
    {
        CatalogLiveQuery = HardwareIdAndProblemAnalyzer.BuildCatalogSearchQuery(device);
        _switchToCatalogTab?.Invoke();
        await SearchLiveMicrosoftCatalogAsync();
    }

    public async Task SearchLiveMicrosoftCatalogAsync()
    {
        if (string.IsNullOrWhiteSpace(CatalogLiveQuery))
        {
            return;
        }

        CatalogStatusText = $"Запрос к серверу catalog.update.microsoft.com по «{CatalogLiveQuery}»...";
        try
        {
            var entries = await _driverService.SearchMicrosoftCatalogAsync(CatalogLiveQuery);
            LiveCatalogResults.Clear();
            foreach (var entry in entries)
            {
                var captured = entry;
                LiveCatalogResults.Add(new LiveCatalogEntryViewModel(
                    captured,
                    new AsyncRelayCommand(_ => DownloadOrInstallCatalogEntryAsync(captured, installNow: false)),
                    new AsyncRelayCommand(_ => DownloadOrInstallCatalogEntryAsync(captured, installNow: true))));
            }

            CatalogStatusText = entries.Count > 0
                ? $"Найдено подписанных пакетов в Каталоге Microsoft: {entries.Count} по запросу «{CatalogLiveQuery}»."
                : $"По запросу «{CatalogLiveQuery}» пакеты в Каталоге Microsoft не найдены.";
        }
        catch (Exception ex)
        {
            CatalogStatusText = $"Не удалось связаться с Каталогом Microsoft: {ex.Message}";
        }
    }

    private async Task DownloadOrInstallEssentialAsync(EssentialDriverPackage pkg, bool installNow)
    {
        var progress = new Progress<string>(msg => CatalogStatusText = msg);
        var res = await _driverService.DownloadOrInstallEssentialPackageAsync(
            pkg,
            DownloadTargetFolder,
            installOnThisPc: installNow,
            statusProgress: progress);

        CatalogStatusText = res.UserFriendlyMessage;
        LastDriverOperationBanner = res.UserFriendlyMessage;
        await _onActionCompletedAsync(res.UserFriendlyMessage);
    }

    private async Task DownloadOrInstallCatalogEntryAsync(MicrosoftCatalogDriverEntry entry, bool installNow)
    {
        var progress = new Progress<string>(msg => CatalogStatusText = msg);
        var res = await _driverService.DownloadOrInstallCatalogUpdateAsync(
            entry,
            DownloadTargetFolder,
            installOnThisPc: installNow,
            statusProgress: progress);

        CatalogStatusText = res.UserFriendlyMessage;
        LastDriverOperationBanner = res.UserFriendlyMessage;
        await _onActionCompletedAsync(res.UserFriendlyMessage);
    }

    public async Task RefreshDriverStoreAsync(bool notifyBanner = true)
    {
        var summary = await _driverService.AuditDriverStoreAsync();
        DriverStoreHeadline = summary.Headline;
        HasDuplicateStoreEntries = summary.DuplicateOldCount > 0;

        DriverStoreEntries.Clear();
        foreach (var entry in summary.Entries)
        {
            DriverStoreEntries.Add(entry);
        }

        if (notifyBanner)
        {
            await _onActionCompletedAsync(summary.Headline);
        }
    }

    private async Task CleanOldStoreDuplicatesAsync()
    {
        var res = await _driverService.CleanOldDriverStoreDuplicatesAsync(DriverStoreEntries.ToList());
        await RefreshDriverStoreAsync(notifyBanner: false);
        LastDriverOperationBanner = res.UserFriendlyMessage;
        await _onActionCompletedAsync(res.UserFriendlyMessage);
    }

    private async Task BackupAllDriversInteractiveAsync()
    {
        var defaultDir = Path.Combine(DownloadTargetFolder, $"FullDriverBackup-{DateTime.Now:yyyyMMdd-HHmm}");
        var chosen = PickFolderInteractive("Выберите папку для полного бэкапа всех драйверов ПК", defaultDir);
        if (string.IsNullOrWhiteSpace(chosen))
        {
            return;
        }

        DriverStoreHeadline = $"Экспорт всех сторонних драйверов в «{chosen}»...";
        var res = await _driverService.BackupAllThirdPartyDriversAsync(chosen);
        DriverStoreHeadline = res.UserFriendlyMessage;
        await _onActionCompletedAsync(res.UserFriendlyMessage);
    }

    private async Task RestoreDriversInteractiveAsync()
    {
        var chosen = PickFolderInteractive("Выберите папку с резервной копией драйверов (.inf)", DownloadTargetFolder);
        if (string.IsNullOrWhiteSpace(chosen))
        {
            return;
        }

        DriverStoreHeadline = $"Установка драйверов из «{chosen}»...";
        var res = await _driverService.RestoreDriversFromFolderAsync(chosen);
        DriverStoreHeadline = res.UserFriendlyMessage;
        await RefreshDriverStoreAsync(notifyBanner: false);
        await _onActionCompletedAsync(res.UserFriendlyMessage);
    }

    private async Task BuildRescuePackAsync(bool downloadFromServers)
    {
        RescuePackLogLines.Clear();
        var progress = new Progress<string>(msg => RescueStatusText = msg);
        var res = await _driverService.BuildOfflineNetworkRescuePackAsync(
            RescueTargetFolder,
            downloadUniversalFromServers: downloadFromServers,
            statusProgress: progress);

        RescueStatusText = res.UserFriendlyMessage;
        foreach (var line in res.Details)
        {
            RescuePackLogLines.Add(line);
        }

        await _onActionCompletedAsync(res.UserFriendlyMessage);
    }

    public async Task RefreshVulnerableDriversAsync(bool notifyBanner = true)
    {
        var report = await _driverService.AuditVulnerableKernelDriversAsync();
        VulnerableHeadline = report.SummaryHeadline;
        CanEnableBlocklist = !report.IsMicrosoftBlocklistEnabled;

        VulnerableFindings.Clear();
        foreach (var finding in report.Findings)
        {
            var captured = finding;
            VulnerableFindings.Add(new VulnerableDriverItemViewModel(
                captured,
                new AsyncRelayCommand(_ => NeutralizeVulnerableAsync(captured))));
        }

        if (notifyBanner)
        {
            await _onActionCompletedAsync(report.SummaryHeadline);
        }
    }

    private async Task EnableMicrosoftBlocklistAsync()
    {
        var res = await _driverService.EnableMicrosoftVulnerableDriverBlocklistAsync();
        await RefreshVulnerableDriversAsync(notifyBanner: false);
        await _onActionCompletedAsync(res.UserFriendlyMessage);
    }

    private async Task NeutralizeVulnerableAsync(VulnerableDriverFinding finding)
    {
        var res = await _driverService.NeutralizeVulnerableKernelDriverAsync(finding);
        await RefreshVulnerableDriversAsync(notifyBanner: false);
        await _onActionCompletedAsync(res.UserFriendlyMessage);
    }

    private async Task BackupOemInfAsync(SystemDeviceNode device)
    {
        var res = await _driverService.BackupDeviceDriverToVaultAsync(device);
        LastDriverOperationBanner = res.UserFriendlyMessage;
        await _onActionCompletedAsync(res.UserFriendlyMessage);
    }

    private async Task InstallWhqlAsync(DriverAuditFinding finding)
    {
        if (finding.RecommendedWhqlUpdate is null) return;

        var res = await _driverService.InstallOfficialWhqlDriverAsync(finding.Device, finding.RecommendedWhqlUpdate);
        LastDriverOperationBanner = res.UserFriendlyMessage;
        if (res.Succeeded)
        {
            await RunDriverAuditAsync();
        }

        await _onActionCompletedAsync(res.UserFriendlyMessage);
    }

    private static void BrowseFolder(Action<string> setter, string initialFolder)
    {
        var picked = PickFolderInteractive("Выберите целевую папку", initialFolder);
        if (!string.IsNullOrWhiteSpace(picked))
        {
            setter(picked);
        }
    }

    private static string? PickFolderInteractive(string title, string initialFolder)
    {
        try
        {
            var dlg = new OpenFolderDialog
            {
                Title = title
            };
            if (!string.IsNullOrWhiteSpace(initialFolder) && Directory.Exists(initialFolder))
            {
                dlg.InitialDirectory = initialFolder;
            }

            return dlg.ShowDialog() == true ? dlg.FolderName : null;
        }
        catch
        {
            return initialFolder;
        }
    }

    private static void OpenOfficialVendorUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url) || !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = url,
                UseShellExecute = true
            });
        }
        catch
        {
            // Ignore browser launch errors in restricted sessions
        }
    }
}
