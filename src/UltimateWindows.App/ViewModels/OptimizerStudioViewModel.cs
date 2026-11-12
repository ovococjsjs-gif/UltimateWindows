using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows.Input;
using Microsoft.Win32;
using UltimateWindows.App.Infrastructure;
using UltimateWindows.Modules.Optimizer.Models;
using UltimateWindows.Modules.Optimizer.Network;
using UltimateWindows.Modules.Optimizer.Services;

namespace UltimateWindows.App.ViewModels;

public sealed class StartupItemViewModel : ObservableObject
{
    private readonly Func<StartupItemViewModel, bool, Task> _onToggleAsync;
    private bool _isEnabled;
    private bool _suppress;

    public StartupItemViewModel(StartupEntryInfo info, Func<StartupItemViewModel, bool, Task> onToggleAsync)
    {
        Info = info;
        _isEnabled = info.IsEnabled;
        _onToggleAsync = onToggleAsync;
    }

    public StartupEntryInfo Info { get; }
    public string DisplayName => Info.DisplayName;
    public string LocationSource => Info.LocationSource;
    public string CommandOrTarget => Info.CommandOrTarget;
    public string SignatureBadge => Info.SignatureBadge;

    public ChipViewModel SignatureChip => Info.IsSignedTrusted
        ? new ChipViewModel("Подписан", "Safe", "У файла действительная цифровая подпись издателя.")
        : new ChipViewModel("Без подписи", "Caution", "У файла нет действительной цифровой подписи. Это не значит, что он вреден, но издателя проверить нельзя.");

    public bool IsEnabled
    {
        get => _isEnabled;
        set
        {
            if (_isEnabled == value) return;
            _isEnabled = value;
            OnPropertyChanged();
            if (!_suppress)
            {
                _ = _onToggleAsync(this, value);
            }
        }
    }

    public void SetSilently(bool val)
    {
        _suppress = true;
        IsEnabled = val;
        _suppress = false;
    }
}

public sealed class ShellExItemViewModel : ObservableObject
{
    public ShellExItemViewModel(ShellContextMenuHandlerInfo info, ICommand toggleBlockCommand)
    {
        Info = info;
        ToggleBlockCommand = toggleBlockCommand;
    }

    public ShellContextMenuHandlerInfo Info { get; }
    public string HandlerName => Info.HandlerName;
    public string TargetScope => Info.TargetScope;
    public string StateBadge => Info.StateBadge;
    public string TechnicalPathAndClsid => $"{Info.Clsid}  •  {Info.DllPath ?? "путь не определен"}";
    public string ToggleLabel => Info.IsBlockedByPolicy ? "Вернуть в меню" : "Скрыть из меню";
    public ICommand ToggleBlockCommand { get; }
}

public sealed class LockingProcessItemViewModel : ObservableObject
{
    public LockingProcessItemViewModel(LockingProcessInfo info, ICommand closeCommand)
    {
        Info = info;
        CloseCommand = closeCommand;
    }

    public LockingProcessInfo Info { get; }
    public string DisplayHeadline => Info.DisplayHeadline;
    public string ProcessKindLabel => Info.ProcessKindLabel;
    public string ExecutablePath => Info.ExecutablePath;
    public bool CanCloseSafely => Info.CanCloseSafely;
    public ICommand CloseCommand { get; }
}

public sealed class DnsPresetItemViewModel : ObservableObject
{
    public DnsPresetItemViewModel(DnsPresetDescriptor preset, ICommand applyCommand)
    {
        Preset = preset;
        ApplyCommand = applyCommand;
    }

    public DnsPresetDescriptor Preset { get; }
    public string FriendlyName => Preset.FriendlyName;
    public string ServersDisplay => Preset.ServersDisplay;
    public string FriendlyBenefit => Preset.FriendlyBenefit;
    public ICommand ApplyCommand { get; }
}

public sealed class SelectableUwpItemViewModel : ObservableObject
{
    private bool _isSelected;

    public SelectableUwpItemViewModel(UwpPackageInfo package)
    {
        Package = package;
    }

    public UwpPackageInfo Package { get; }
    public string FriendlyName => Package.FriendlyDisplayName;
    public string RawPackageName => Package.Name;
    public string Version => Package.Version;
    public string KindBadge => Package.IsFrameworkOrSystem ? "Системный компонент" : "UWP приложение";
    public bool CanSelect => Package.CanRemoveSafely;

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (CanSelect) SetProperty(ref _isSelected, value);
        }
    }
}

public sealed class InstalledAppItemViewModel : ObservableObject
{
    public InstalledAppItemViewModel(
        InstalledApplicationInfo app,
        ICommand uninstallCommand,
        ICommand openFolderCommand)
    {
        App = app;
        UninstallCommand = uninstallCommand;
        OpenFolderCommand = openFolderCommand;
    }

    public InstalledApplicationInfo App { get; }
    public string DisplayName => App.DisplayName;
    public string Publisher => App.Publisher;
    public string DisplayVersion => App.DisplayVersion;
    public string FormattedSize => App.FormattedSize;
    public bool HasUninstaller => App.HasUninstaller;
    public bool HasInstallFolder => !string.IsNullOrWhiteSpace(App.InstallLocation);
    public ICommand UninstallCommand { get; }
    public ICommand OpenFolderCommand { get; }
}

public sealed class HostsEntryItemViewModel : ObservableObject
{
    public HostsEntryItemViewModel(HostsRedirectEntry entry, ICommand removeCommand)
    {
        Entry = entry;
        RemoveCommand = removeCommand;
    }

    public HostsRedirectEntry Entry { get; }
    public int LineNumber => Entry.LineNumber;
    public string RedirectIp => Entry.RedirectIp;
    public string DomainHost => Entry.DomainHost;
    public bool IsSuspicious => Entry.IsSuspiciousSecurityBlock;
    public string SecurityWarning => IsSuspicious ? "Подозрительно: закрывает доступ к сайту защиты или обновлений" : "Ваше правило";
    public ICommand RemoveCommand { get; }
}

/// <summary>
/// Раздел «Оптимизатор». Вкладки:
/// 0 — настройки Windows (каталог твиков, наборы, профили),
/// 1 — службы, 2 — планировщик заданий, 3 — автозагрузка,
/// 4 — программы и приложения Windows, 5 — сеть (проверка связи, DNS, hosts),
/// 6 — инструменты (кто держит файл, контекстное меню Проводника).
/// </summary>
public sealed class OptimizerStudioViewModel : ObservableObject
{
    private readonly SmartOptimizerService _optimizerService;
    private readonly Func<string, Task> _onActionCompletedAsync;

    private List<InstalledApplicationInfo> _allInstalledApps = [];
    private List<UwpPackageInfo> _allUwpPackages = [];

    private int _selectedSubTabIndex;
    private int _appsMode;
    private bool _hasLoadedLists;
    private string _actionStatusBanner = "";

    // UWP
    private bool _hideUwpFrameworks = true;
    private string _uwpSearchFilter = "";
    private bool _isLoadingUwp;
    private string _uwpStatusText = "Отметьте ненужные встроенные приложения Windows и нажмите «Удалить выбранные».";

    // Win32 Uninstaller & Unlocker
    private string _appSearchFilter = "";
    private string _lockedTargetPath = "";
    private string _lockHunterHeadline = "Укажите файл или папку, которую не даёт удалить открытый процесс.";

    // Pinger & Hosts
    private string _pingTargetHost = "1.1.1.1";
    private int _pingPacketCount = 6;
    private bool _isPinging;
    private string _latencyHeadline = "Введите домен или IP (например, 1.1.1.1, ya.ru, store.steampowered.com) и нажмите «Проверить».";
    private string _latencyBadge = "Готов";
    private string _pingStatsSummary = "Мин: —  |  Сред: —  |  Макс: —  |  Джиттер: —  |  Потери: 0%";

    private string _newHostIp = "0.0.0.0";
    private string _newHostDomain = "";
    private string _hostsStatusSummary = "";

    public OptimizerStudioViewModel(
        SmartOptimizerService optimizerService,
        Func<string, Task> onActionCompletedAsync)
    {
        _optimizerService = optimizerService;
        _onActionCompletedAsync = onActionCompletedAsync;

        Tweaks = new TweakCatalogViewModel(optimizerService, onActionCompletedAsync, ShowBanner);
        Services = new ServiceManagerViewModel(optimizerService, onActionCompletedAsync, ShowBanner);
        Tasks = new TaskManagerViewModel(optimizerService, onActionCompletedAsync, ShowBanner);

        UwpPackages = new ObservableCollection<SelectableUwpItemViewModel>();
        FilteredInstalledApps = new ObservableCollection<InstalledAppItemViewModel>();
        StartupEntries = new ObservableCollection<StartupItemViewModel>();
        ShellExtensions = new ObservableCollection<ShellExItemViewModel>();
        LockingProcesses = new ObservableCollection<LockingProcessItemViewModel>();

        DnsPresets = new ObservableCollection<DnsPresetItemViewModel>();
        PingPacketLines = new ObservableCollection<string>();
        HostsEntries = new ObservableCollection<HostsEntryItemViewModel>();

        SelectSubTabCommand = new RelayCommand(p =>
        {
            if (p is string s && int.TryParse(s, out var idx)) SelectedSubTabIndex = idx;
        });

        RefreshAllOptimizerDataCommand = new AsyncRelayCommand(_ => RefreshListsAsync());
        DismissBannerCommand = new RelayCommand(_ => ActionStatusBanner = "");

        // UWP commands
        RefreshUwpCommand = new AsyncRelayCommand(_ => ReloadUwpPackagesAsync());
        RemoveSelectedUwpCommand = new AsyncRelayCommand(_ => RemoveSelectedUwpAsync());
        ToggleSelectAllUwpCommand = new RelayCommand(p =>
        {
            bool check = p as string != "false";
            foreach (var u in UwpPackages) u.IsSelected = check;
        });

        // Unlocker
        BrowseLockedPathCommand = new RelayCommand(_ => BrowseForLockedFile());
        FindLockersCommand = new AsyncRelayCommand(_ => RunLockHunterAsync());

        // Pinger, DNS, Hosts
        RunLatencyTestCommand = new AsyncRelayCommand(_ => RunNetworkLatencyTestAsync());
        SetQuickPingHostCommand = new RelayCommand(p =>
        {
            if (p is string h) PingTargetHost = h;
        });
        FlushDnsCommand = new AsyncRelayCommand(_ => FlushDnsAsync());
        AddHostEntryCommand = new AsyncRelayCommand(_ => AddHostEntryAsync());
        OpenHostsInNotepadCommand = new RelayCommand(_ => OpenHostsInNotepad());

        foreach (var dns in _optimizerService.GetDnsPresets())
        {
            var capturedDns = dns;
            DnsPresets.Add(new DnsPresetItemViewModel(
                capturedDns,
                new AsyncRelayCommand(_ => ApplyDnsAsync(capturedDns.Id))));
        }

        ReloadHostsList();
    }

    /// <summary>Каталог настроек Windows.</summary>
    public TweakCatalogViewModel Tweaks { get; }

    /// <summary>Диспетчер служб.</summary>
    public ServiceManagerViewModel Services { get; }

    /// <summary>Диспетчер заданий планировщика.</summary>
    public TaskManagerViewModel Tasks { get; }

    public ObservableCollection<SelectableUwpItemViewModel> UwpPackages { get; }
    public ObservableCollection<InstalledAppItemViewModel> FilteredInstalledApps { get; }
    public ObservableCollection<StartupItemViewModel> StartupEntries { get; }
    public ObservableCollection<ShellExItemViewModel> ShellExtensions { get; }
    public ObservableCollection<LockingProcessItemViewModel> LockingProcesses { get; }

    public ObservableCollection<DnsPresetItemViewModel> DnsPresets { get; }
    public ObservableCollection<string> PingPacketLines { get; }
    public ObservableCollection<HostsEntryItemViewModel> HostsEntries { get; }

    public int SelectedSubTabIndex
    {
        get => _selectedSubTabIndex;
        set
        {
            if (!SetProperty(ref _selectedSubTabIndex, value))
            {
                return;
            }

            OnPropertyChanged(nameof(IsTweaksTab));
            OnPropertyChanged(nameof(IsServicesTab));
            OnPropertyChanged(nameof(IsTasksTab));
            OnPropertyChanged(nameof(IsStartupTab));
            OnPropertyChanged(nameof(IsAppsTab));
            OnPropertyChanged(nameof(IsNetworkTab));
            OnPropertyChanged(nameof(IsToolsTab));

            // Тяжёлые списки читаются при первом открытии своей вкладки
            switch (value)
            {
                case 1:
                    _ = Services.EnsureLoadedAsync();
                    break;
                case 2:
                    _ = Tasks.EnsureLoadedAsync();
                    break;
                case 3:
                case 6:
                    if (!_hasLoadedLists)
                    {
                        _ = RefreshListsAsync();
                    }

                    break;
                case 4:
                    if (!_hasLoadedLists)
                    {
                        _ = RefreshListsAsync();
                    }

                    if (IsWindowsAppsMode && _allUwpPackages.Count == 0 && !IsLoadingUwp)
                    {
                        _ = ReloadUwpPackagesAsync();
                    }

                    break;
            }
        }
    }

    public bool IsTweaksTab => SelectedSubTabIndex == 0;
    public bool IsServicesTab => SelectedSubTabIndex == 1;
    public bool IsTasksTab => SelectedSubTabIndex == 2;
    public bool IsStartupTab => SelectedSubTabIndex == 3;
    public bool IsAppsTab => SelectedSubTabIndex == 4;
    public bool IsNetworkTab => SelectedSubTabIndex == 5;
    public bool IsToolsTab => SelectedSubTabIndex == 6;

    /// <summary>На вкладке «Приложения»: 0 — установленные программы, 1 — приложения Windows.</summary>
    public int AppsMode
    {
        get => _appsMode;
        set
        {
            if (!SetProperty(ref _appsMode, value))
            {
                return;
            }

            OnPropertyChanged(nameof(IsProgramsMode));
            OnPropertyChanged(nameof(IsWindowsAppsMode));
            if (IsWindowsAppsMode && _allUwpPackages.Count == 0 && !IsLoadingUwp)
            {
                _ = ReloadUwpPackagesAsync();
            }
        }
    }

    public bool IsProgramsMode => AppsMode == 0;
    public bool IsWindowsAppsMode => AppsMode == 1;

    public int ActiveTweaksCount => Tweaks.ActiveTweaksCount;

    public string ActionStatusBanner
    {
        get => _actionStatusBanner;
        private set
        {
            if (SetProperty(ref _actionStatusBanner, value)) OnPropertyChanged(nameof(HasActionStatusBanner));
        }
    }
    public bool HasActionStatusBanner => !string.IsNullOrWhiteSpace(ActionStatusBanner);

    public bool HideUwpFrameworks
    {
        get => _hideUwpFrameworks;
        set
        {
            if (SetProperty(ref _hideUwpFrameworks, value))
            {
                RebuildFilteredUwp();
            }
        }
    }

    public string UwpSearchFilter
    {
        get => _uwpSearchFilter;
        set
        {
            if (SetProperty(ref _uwpSearchFilter, value))
            {
                RebuildFilteredUwp();
            }
        }
    }

    public bool IsLoadingUwp { get => _isLoadingUwp; private set => SetProperty(ref _isLoadingUwp, value); }
    public string UwpStatusText { get => _uwpStatusText; private set => SetProperty(ref _uwpStatusText, value); }

    public string AppSearchFilter
    {
        get => _appSearchFilter;
        set
        {
            if (SetProperty(ref _appSearchFilter, value)) RebuildFilteredApps();
        }
    }

    public string LockedTargetPath { get => _lockedTargetPath; set => SetProperty(ref _lockedTargetPath, value); }
    public string LockHunterHeadline { get => _lockHunterHeadline; private set => SetProperty(ref _lockHunterHeadline, value); }

    public string PingTargetHost { get => _pingTargetHost; set => SetProperty(ref _pingTargetHost, value); }
    public int PingPacketCount { get => _pingPacketCount; set => SetProperty(ref _pingPacketCount, Math.Clamp(value, 2, 25)); }
    public bool IsPinging { get => _isPinging; private set => SetProperty(ref _isPinging, value); }
    public string LatencyHeadline { get => _latencyHeadline; private set => SetProperty(ref _latencyHeadline, value); }
    public string LatencyBadge { get => _latencyBadge; private set => SetProperty(ref _latencyBadge, value); }
    public string PingStatsSummary { get => _pingStatsSummary; private set => SetProperty(ref _pingStatsSummary, value); }

    public string NewHostIp { get => _newHostIp; set => SetProperty(ref _newHostIp, value); }
    public string NewHostDomain { get => _newHostDomain; set => SetProperty(ref _newHostDomain, value); }
    public string HostsStatusSummary { get => _hostsStatusSummary; private set => SetProperty(ref _hostsStatusSummary, value); }

    public ICommand SelectSubTabCommand { get; }
    public ICommand RefreshAllOptimizerDataCommand { get; }
    public ICommand DismissBannerCommand { get; }

    public ICommand RefreshUwpCommand { get; }
    public ICommand RemoveSelectedUwpCommand { get; }
    public ICommand ToggleSelectAllUwpCommand { get; }

    public ICommand BrowseLockedPathCommand { get; }
    public ICommand FindLockersCommand { get; }

    public ICommand RunLatencyTestCommand { get; }
    public ICommand SetQuickPingHostCommand { get; }
    public ICommand FlushDnsCommand { get; }
    public ICommand AddHostEntryCommand { get; }
    public ICommand OpenHostsInNotepadCommand { get; }

    /// <summary>
    /// Перечитывает всё, что показывает раздел: состояние настроек и списки автозагрузки, меню и программ.
    /// </summary>
    public async Task RefreshAllAsync()
    {
        await Task.WhenAll(Tweaks.RefreshAsync(), RefreshListsAsync());
    }

    /// <summary>
    /// Обновляет раздел после отката в «Машине времени»: откат мог изменить настройки, службы, задания и hosts.
    /// </summary>
    public async Task RefreshAfterRollbackAsync()
    {
        ReloadHostsList();
        await Tweaks.RefreshAsync();
        if (IsServicesTab)
        {
            await Services.RefreshAsync();
        }

        if (IsTasksTab)
        {
            await Tasks.RefreshAsync();
        }
    }

    private void ShowBanner(string message) => ActionStatusBanner = message;

    private async Task RefreshListsAsync()
    {
        _hasLoadedLists = true;
        try
        {
            var startupsTask = _optimizerService.GetStartupEntriesAsync();
            var shellExTask = _optimizerService.GetThirdPartyShellExtensionsAsync();
            var appsTask = _optimizerService.GetInstalledApplicationsAsync();

            await Task.WhenAll(startupsTask, shellExTask, appsTask);

            StartupEntries.Clear();
            foreach (var s in startupsTask.Result)
            {
                StartupEntries.Add(new StartupItemViewModel(s, ToggleStartupAsync));
            }

            ShellExtensions.Clear();
            foreach (var sh in shellExTask.Result)
            {
                var capturedSh = sh;
                ShellExtensions.Add(new ShellExItemViewModel(
                    capturedSh,
                    new AsyncRelayCommand(_ => ToggleShellExAsync(capturedSh))));
            }

            _allInstalledApps = appsTask.Result.ToList();
            RebuildFilteredApps();
            OnPropertyChanged(nameof(StartupSummary));
            OnPropertyChanged(nameof(HasNoShellExtensions));
        }
        catch (Exception ex)
        {
            ActionStatusBanner = $"Не удалось обновить списки автозагрузки и программ: {ex.Message}";
        }
    }

    public string StartupSummary => StartupEntries.Count == 0
        ? "Записей автозагрузки не найдено."
        : $"Записей: {StartupEntries.Count} · включено: {StartupEntries.Count(e => e.IsEnabled)} · без подписи: {StartupEntries.Count(e => !e.Info.IsSignedTrusted)}";

    public bool HasNoShellExtensions => ShellExtensions.Count == 0;

    private void ReloadHostsList()
    {
        HostsEntries.Clear();
        var entries = _optimizerService.InspectHostsFile();
        foreach (var h in entries)
        {
            var captured = h;
            HostsEntries.Add(new HostsEntryItemViewModel(
                captured,
                new AsyncRelayCommand(_ => RemoveHostEntryAsync(captured))));
        }

        var suspiciousCount = entries.Count(x => x.IsSuspiciousSecurityBlock);
        HostsStatusSummary = entries.Count == 0
            ? "Файл hosts чист (только стандартный localhost)."
            : suspiciousCount > 0
                ? $"ВНИМАНИЕ: в hosts активно правил — {entries.Count}, подозрительных блокировок антивирусов/обновлений — {suspiciousCount}!"
                : $"Активных правил перенаправления в файле hosts: {entries.Count}.";
    }

    public async Task ReloadUwpPackagesAsync()
    {
        if (IsLoadingUwp) return;
        IsLoadingUwp = true;
        UwpStatusText = "Чтение списка установленных UWP / Appx пакетов...";

        try
        {
            var list = await _optimizerService.GetInstalledUwpPackagesAsync(includeFrameworks: true);
            _allUwpPackages = list.ToList();
            RebuildFilteredUwp();
        }
        catch (Exception ex)
        {
            UwpStatusText = $"Ошибка загрузки списка UWP: {ex.Message}";
        }
        finally
        {
            IsLoadingUwp = false;
        }
    }

    private void RebuildFilteredUwp()
    {
        UwpPackages.Clear();
        var q = UwpSearchFilter?.Trim() ?? "";

        var query = _allUwpPackages.AsEnumerable();
        if (HideUwpFrameworks)
        {
            query = query.Where(p => !p.IsFrameworkOrSystem);
        }

        if (!string.IsNullOrEmpty(q))
        {
            query = query.Where(p =>
                p.FriendlyDisplayName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                p.Name.Contains(q, StringComparison.OrdinalIgnoreCase));
        }

        foreach (var pkg in query)
        {
            UwpPackages.Add(new SelectableUwpItemViewModel(pkg));
        }

        UwpStatusText = $"Доступно пакетов в списке: {UwpPackages.Count} (всего в системе: {_allUwpPackages.Count}).";
    }

    private async Task RemoveSelectedUwpAsync()
    {
        var chosen = UwpPackages.Where(x => x.IsSelected).Select(x => x.Package).ToList();
        if (chosen.Count == 0)
        {
            UwpStatusText = "Отметьте галочками UWP-приложения для удаления.";
            return;
        }

        IsLoadingUwp = true;
        UwpStatusText = $"Удаление выбранных UWP-приложений ({chosen.Count} шт.)...";
        try
        {
            var res = await _optimizerService.RemoveSelectedUwpPackagesAsync(chosen);
            UwpStatusText = res.UserFriendlyMessage;
            ActionStatusBanner = res.UserFriendlyMessage;
            if (res.Succeeded)
            {
                await _onActionCompletedAsync(res.UserFriendlyMessage);
            }
        }
        finally
        {
            IsLoadingUwp = false;
        }

        await ReloadUwpPackagesAsync();
    }

    private void RebuildFilteredApps()
    {
        FilteredInstalledApps.Clear();
        var q = AppSearchFilter?.Trim() ?? "";
        var matches = string.IsNullOrEmpty(q)
            ? _allInstalledApps
            : _allInstalledApps.Where(a =>
                a.DisplayName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                a.Publisher.Contains(q, StringComparison.OrdinalIgnoreCase));

        foreach (var app in matches.Take(250))
        {
            var captured = app;
            FilteredInstalledApps.Add(new InstalledAppItemViewModel(
                captured,
                new AsyncRelayCommand(_ => UninstallAppAsync(captured)),
                new RelayCommand(_ => OpenInstallDirectory(captured.InstallLocation))));
        }
    }

    private async Task UninstallAppAsync(InstalledApplicationInfo app)
    {
        var res = await _optimizerService.LaunchApplicationUninstallerAsync(app);
        ActionStatusBanner = res.UserFriendlyMessage;
        if (res.Succeeded)
        {
            await _onActionCompletedAsync(res.UserFriendlyMessage);
        }
    }

    private static void OpenInstallDirectory(string? dir)
    {
        if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir)) return;
        try
        {
            Process.Start(new ProcessStartInfo("explorer.exe", $"\"{dir}\"") { UseShellExecute = true });
        }
        catch
        {
            // Ignore
        }
    }

    private async Task ToggleStartupAsync(StartupItemViewModel vm, bool enable)
    {
        var res = await _optimizerService.ToggleStartupEntryAsync(vm.Info, enable);
        ActionStatusBanner = res.UserFriendlyMessage;
        if (!res.Succeeded)
        {
            vm.SetSilently(!enable);
            return;
        }

        OnPropertyChanged(nameof(StartupSummary));
        await _onActionCompletedAsync(res.UserFriendlyMessage);
    }

    private async Task ToggleShellExAsync(ShellContextMenuHandlerInfo handler)
    {
        var res = await _optimizerService.SetShellExtensionBlockedAsync(handler, blockInContextMenu: !handler.IsBlockedByPolicy);
        ActionStatusBanner = res.UserFriendlyMessage;
        if (res.Succeeded)
        {
            await RefreshListsAsync();
            await _onActionCompletedAsync(res.UserFriendlyMessage);
        }
    }

    private void BrowseForLockedFile()
    {
        var dlg = new OpenFileDialog { Title = "Выберите занятый файл для поиска блокирующего процесса" };
        if (dlg.ShowDialog() == true) LockedTargetPath = dlg.FileName;
    }

    private async Task RunLockHunterAsync()
    {
        if (string.IsNullOrWhiteSpace(LockedTargetPath)) return;

        LockHunterHeadline = "Опрос подсистемы Windows Restart Manager...";
        var found = await _optimizerService.FindLockingProcessesAsync(LockedTargetPath);
        LockingProcesses.Clear();
        foreach (var p in found)
        {
            var cap = p;
            LockingProcesses.Add(new LockingProcessItemViewModel(
                cap,
                new AsyncRelayCommand(_ => CloseLockingProcessAsync(cap))));
        }

        LockHunterHeadline = found.Count == 0
            ? "Файл свободен — ни один активный процесс его не удерживает."
            : $"Найдено удерживающих процессов: {found.Count}.";
    }

    private async Task CloseLockingProcessAsync(LockingProcessInfo proc)
    {
        var res = await _optimizerService.RequestSafeCloseLockingProcessAsync(proc);
        ActionStatusBanner = res.UserFriendlyMessage;
        if (res.Succeeded)
        {
            await RunLockHunterAsync();
            await _onActionCompletedAsync(res.UserFriendlyMessage);
        }
    }

    private async Task ApplyDnsAsync(DnsPresetId id)
    {
        var res = await _optimizerService.ApplyDnsPresetAsync(id);
        ActionStatusBanner = res.UserFriendlyMessage;
        if (res.Succeeded)
        {
            await _onActionCompletedAsync(res.UserFriendlyMessage);
        }
    }

    private async Task FlushDnsAsync()
    {
        var res = await _optimizerService.FlushDnsCacheAsync();
        ActionStatusBanner = res.UserFriendlyMessage;
        LatencyHeadline = res.UserFriendlyMessage;
    }

    private async Task RunNetworkLatencyTestAsync()
    {
        if (IsPinging) return;
        IsPinging = true;
        LatencyBadge = "Пинг...";
        LatencyHeadline = $"Отправка {PingPacketCount} пакетов к узлу «{PingTargetHost}»...";
        PingPacketLines.Clear();

        try
        {
            var rep = await NetworkAndHostsInspector.MeasureLatencyAndJitterAsync(
                targetHost: PingTargetHost,
                port: 443,
                sampleCount: PingPacketCount);

            LatencyBadge = rep.QualityGradeBadge;
            LatencyHeadline = $"{rep.TestedEndpoint} [{rep.ResolvedIp}] — {rep.FriendlyInterpretation}";
            PingStatsSummary =
                $"Мин: {rep.MinRttMs:F1} мс  |  Сред: {rep.AvgRttMs:F1} мс  |  Макс: {rep.MaxRttMs:F1} мс  |  Джиттер: {rep.JitterMs:F1} мс  |  DNS: {rep.DnsLookupMs:F1} мс  |  Потери: {rep.LossPercent}%";

            if (rep.PacketLines is not null)
            {
                foreach (var line in rep.PacketLines) PingPacketLines.Add(line);
            }
        }
        catch (Exception ex)
        {
            LatencyBadge = "Ошибка";
            LatencyHeadline = $"Не удалось пропинговать «{PingTargetHost}»: {ex.Message}";
        }
        finally
        {
            IsPinging = false;
        }
    }

    private async Task AddHostEntryAsync()
    {
        var res = await _optimizerService.AddHostsEntryAsync(NewHostIp, NewHostDomain);
        HostsStatusSummary = res.UserFriendlyMessage;
        ActionStatusBanner = res.UserFriendlyMessage;
        if (res.Succeeded)
        {
            NewHostDomain = "";
            ReloadHostsList();
            await _onActionCompletedAsync(res.UserFriendlyMessage);
        }
    }

    private async Task RemoveHostEntryAsync(HostsRedirectEntry entry)
    {
        var res = await _optimizerService.RemoveHostsEntryAsync(entry);
        HostsStatusSummary = res.UserFriendlyMessage;
        ActionStatusBanner = res.UserFriendlyMessage;
        if (res.Succeeded)
        {
            ReloadHostsList();
            await _onActionCompletedAsync(res.UserFriendlyMessage);
        }
    }

    private void OpenHostsInNotepad()
    {
        var path = _optimizerService.GetHostsFilePath();
        if (!File.Exists(path)) return;
        try
        {
            Process.Start(new ProcessStartInfo("notepad.exe", $"\"{path}\"") { UseShellExecute = true });
        }
        catch
        {
            // Ignore
        }
    }
}
