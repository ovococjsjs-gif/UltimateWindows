using System.Collections.ObjectModel;
using System.IO;
using System.Windows.Input;
using Microsoft.Win32;
using UltimateWindows.App.Infrastructure;
using UltimateWindows.Modules.Optimizer.Models;
using UltimateWindows.Modules.Optimizer.Network;
using UltimateWindows.Modules.Optimizer.Services;

namespace UltimateWindows.App.ViewModels;

public sealed class TweakItemViewModel : ObservableObject
{
    public TweakItemViewModel(EvaluatedTweakState state, ICommand toggleCommand)
    {
        Rule = state.Rule;
        IsApplied = state.IsCurrentlyApplied;
        ToggleCommand = toggleCommand;
    }

    public DeclarativeTweakRule Rule { get; }
    public bool IsApplied { get; }
    public string IconGlyph => Rule.IconGlyph;
    public string FriendlyTitle => Rule.FriendlyTitle;
    public string FriendlyExplanation => Rule.FriendlyExplanation;
    public string ImpactBadge => Rule.ImpactBadge;
    public string ExpertMutationsPreview => Rule.ExpertMutationsPreview;
    public string StateBadge => IsApplied ? "Активно ✅" : "Стандарт Windows";
    public string ToggleButtonLabel => IsApplied ? "↩️ Вернуть стандарт" : "✨ Включить улучшение";
    public ICommand ToggleCommand { get; }
}

public sealed class StartupItemViewModel : ObservableObject
{
    public StartupItemViewModel(StartupEntryInfo info, ICommand toggleCommand)
    {
        Info = info;
        ToggleCommand = toggleCommand;
    }

    public StartupEntryInfo Info { get; }
    public string DisplayName => Info.DisplayName;
    public string LocationSource => Info.LocationSource;
    public string CommandOrTarget => Info.CommandOrTarget;
    public string StatusBadge => Info.StatusBadge;
    public string SignatureBadge => Info.SignatureBadge;
    public string ToggleLabel => Info.IsEnabled ? "💤 Убрать из автозапуска" : "⚡ Включить в автозапуск";
    public ICommand ToggleCommand { get; }
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
    public string ToggleLabel => Info.IsBlockedByPolicy ? "↩️ Вернуть в меню" : "🚀 Скрыть из правого клика";
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
    public string DohTemplateUrl => Preset.DohTemplateUrl;
    public ICommand ApplyCommand { get; }
}

/// <summary>
/// ViewModel экрана Фазы 4 «Умный Оптимизатор, Автозагрузка, Контекстное меню, Разблокировка файлов и DNS».
/// </summary>
public sealed class OptimizerStudioViewModel : ObservableObject
{
    private readonly SmartOptimizerService _optimizerService;
    private readonly Func<string, Task> _onActionCompletedAsync;
    private List<InstalledApplicationInfo> _allInstalledApps = [];

    private string _actionStatusBanner = "";
    private string _lockedTargetPath = "";
    private string _lockHunterHeadline = "Укажите файл или папку, которую Windows не дает удалить или переименовать («Файл занят другим процессом»).";
    private string _latencyHeadline = "Нажмите «Проверить стабильность сети», чтобы измерить задержку DNS, средний пинг и джиттер канала.";
    private string _latencyBadge = "Готов к тесту";
    private string _hostsStatusSummary = "Файл hosts еще не проверялся.";
    private string _appSearchFilter = "";

    public OptimizerStudioViewModel(
        SmartOptimizerService optimizerService,
        Func<string, Task> onActionCompletedAsync)
    {
        _optimizerService = optimizerService;
        _onActionCompletedAsync = onActionCompletedAsync;

        Tweaks = new ObservableCollection<TweakItemViewModel>();
        StartupEntries = new ObservableCollection<StartupItemViewModel>();
        ShellExtensions = new ObservableCollection<ShellExItemViewModel>();
        LockingProcesses = new ObservableCollection<LockingProcessItemViewModel>();
        DnsPresets = new ObservableCollection<DnsPresetItemViewModel>();
        HostsEntries = new ObservableCollection<HostsRedirectEntry>();
        FilteredInstalledApps = new ObservableCollection<InstalledApplicationInfo>();

        RefreshAllOptimizerDataCommand = new AsyncRelayCommand(_ => RefreshAllAsync());
        ExportYamlProfileCommand = new RelayCommand(_ => ExportYamlProfile());
        ImportYamlProfileCommand = new AsyncRelayCommand(_ => ImportYamlProfileAsync());
        BrowseLockedPathCommand = new RelayCommand(_ => BrowseForLockedFile());
        FindLockersCommand = new AsyncRelayCommand(_ => RunLockHunterAsync());
        RunLatencyTestCommand = new AsyncRelayCommand(_ => RunNetworkLatencyTestAsync());

        foreach (var dns in _optimizerService.GetDnsPresets())
        {
            var capturedDns = dns;
            DnsPresets.Add(new DnsPresetItemViewModel(
                capturedDns,
                new AsyncRelayCommand(_ => ApplyDnsAsync(capturedDns.Id))));
        }

        ReloadTweaksAndHosts();
    }

    public ObservableCollection<TweakItemViewModel> Tweaks { get; }
    public ObservableCollection<StartupItemViewModel> StartupEntries { get; }
    public ObservableCollection<ShellExItemViewModel> ShellExtensions { get; }
    public ObservableCollection<LockingProcessItemViewModel> LockingProcesses { get; }
    public ObservableCollection<DnsPresetItemViewModel> DnsPresets { get; }
    public ObservableCollection<HostsRedirectEntry> HostsEntries { get; }
    public ObservableCollection<InstalledApplicationInfo> FilteredInstalledApps { get; }

    public string ActionStatusBanner
    {
        get => _actionStatusBanner;
        private set
        {
            if (SetProperty(ref _actionStatusBanner, value))
            {
                OnPropertyChanged(nameof(HasActionStatusBanner));
            }
        }
    }

    public bool HasActionStatusBanner => !string.IsNullOrWhiteSpace(ActionStatusBanner);
    public bool HasLockingProcesses => LockingProcesses.Count > 0;
    public bool HasShellExtensions => ShellExtensions.Count > 0;
    public bool HasHostsEntries => HostsEntries.Count > 0;

    public string LockedTargetPath
    {
        get => _lockedTargetPath;
        set => SetProperty(ref _lockedTargetPath, value);
    }

    public string LockHunterHeadline
    {
        get => _lockHunterHeadline;
        private set => SetProperty(ref _lockHunterHeadline, value);
    }

    public string LatencyHeadline
    {
        get => _latencyHeadline;
        private set => SetProperty(ref _latencyHeadline, value);
    }

    public string LatencyBadge
    {
        get => _latencyBadge;
        private set => SetProperty(ref _latencyBadge, value);
    }

    public string HostsStatusSummary
    {
        get => _hostsStatusSummary;
        private set => SetProperty(ref _hostsStatusSummary, value);
    }

    public string AppSearchFilter
    {
        get => _appSearchFilter;
        set
        {
            if (SetProperty(ref _appSearchFilter, value))
            {
                RebuildFilteredApps();
            }
        }
    }

    public ICommand RefreshAllOptimizerDataCommand { get; }
    public ICommand ExportYamlProfileCommand { get; }
    public ICommand ImportYamlProfileCommand { get; }
    public ICommand BrowseLockedPathCommand { get; }
    public ICommand FindLockersCommand { get; }
    public ICommand RunLatencyTestCommand { get; }

    public void ReloadTweaksAndHosts()
    {
        Tweaks.Clear();
        foreach (var state in _optimizerService.EvaluateAllTweaks())
        {
            var captured = state;
            Tweaks.Add(new TweakItemViewModel(
                captured,
                new AsyncRelayCommand(_ => ToggleTweakAsync(captured.Rule.TweakId, !captured.IsCurrentlyApplied))));
        }

        HostsEntries.Clear();
        var hosts = _optimizerService.InspectHostsFile();
        foreach (var h in hosts)
        {
            HostsEntries.Add(h);
        }

        OnPropertyChanged(nameof(HasHostsEntries));
        var suspiciousCount = hosts.Count(x => x.IsSuspiciousSecurityBlock);
        HostsStatusSummary = hosts.Count == 0
            ? "✅ Системный файл hosts чист — сторонних перенаправлений не обнаружено."
            : suspiciousCount > 0
                ? $"🚨 Внимание: в файле hosts найдено {hosts.Count} записей (из них {suspiciousCount} блокируют антивирусы или обновления!)."
                : $"ℹ️ В файле hosts найдено пользовательских записей: {hosts.Count}.";
    }

    public async Task RefreshAllAsync()
    {
        ReloadTweaksAndHosts();

        var startups = await _optimizerService.GetStartupEntriesAsync();
        StartupEntries.Clear();
        foreach (var s in startups)
        {
            var captured = s;
            StartupEntries.Add(new StartupItemViewModel(
                captured,
                new AsyncRelayCommand(_ => ToggleStartupAsync(captured))));
        }

        var shellEx = await _optimizerService.GetThirdPartyShellExtensionsAsync();
        ShellExtensions.Clear();
        foreach (var sh in shellEx)
        {
            var capturedSh = sh;
            ShellExtensions.Add(new ShellExItemViewModel(
                capturedSh,
                new AsyncRelayCommand(_ => ToggleShellExAsync(capturedSh))));
        }
        OnPropertyChanged(nameof(HasShellExtensions));

        _allInstalledApps = (await _optimizerService.GetInstalledApplicationsAsync()).ToList();
        RebuildFilteredApps();

        await _onActionCompletedAsync($"Обновлены твики, автозагрузка ({StartupEntries.Count}) и список программ ({_allInstalledApps.Count}).");
    }

    private async Task ToggleTweakAsync(string tweakId, bool enable)
    {
        var res = await _optimizerService.SetTweakStateAsync(tweakId, enable);
        ActionStatusBanner = res.UserFriendlyMessage;
        ReloadTweaksAndHosts();
        await _onActionCompletedAsync(res.UserFriendlyMessage);
    }

    private void ExportYamlProfile()
    {
        var dialog = new SaveFileDialog
        {
            Title = "Сохранить профиль настроек UltimateWindows в YAML",
            Filter = "YAML профиль UltimateWindows (*.yaml)|*.yaml",
            FileName = "my-ultimatewindows-profile.yaml"
        };

        if (dialog.ShowDialog() == true)
        {
            var yaml = _optimizerService.ExportActiveTweaksToYaml(Path.GetFileNameWithoutExtension(dialog.FileName));
            File.WriteAllText(dialog.FileName, yaml);
            ActionStatusBanner = $"✅ Декларативный профиль настроек сохранен в «{dialog.FileName}».";
        }
    }

    private async Task ImportYamlProfileAsync()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Импортировать YAML-профиль настроек UltimateWindows",
            Filter = "YAML профиль (*.yaml;*.yml)|*.yaml;*.yml"
        };

        if (dialog.ShowDialog() == true && File.Exists(dialog.FileName))
        {
            var content = await File.ReadAllTextAsync(dialog.FileName);
            var res = await _optimizerService.ImportAndApplyYamlProfileAsync(content);
            ActionStatusBanner = res.UserFriendlyMessage;
            ReloadTweaksAndHosts();
            await _onActionCompletedAsync(res.UserFriendlyMessage);
        }
    }

    private async Task ToggleStartupAsync(StartupEntryInfo entry)
    {
        var res = await _optimizerService.ToggleStartupEntryAsync(entry, !entry.IsEnabled);
        ActionStatusBanner = res.UserFriendlyMessage;
        await RefreshAllAsync();
    }

    private async Task ToggleShellExAsync(ShellContextMenuHandlerInfo handler)
    {
        var res = await _optimizerService.SetShellExtensionBlockedAsync(handler, !handler.IsBlockedByPolicy);
        ActionStatusBanner = res.UserFriendlyMessage;
        await RefreshAllAsync();
    }

    private void BrowseForLockedFile()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Выберите заблокированный файл",
            Filter = "Все файлы (*.*)|*.*",
            CheckFileExists = true
        };

        if (dialog.ShowDialog() == true)
        {
            LockedTargetPath = dialog.FileName;
            _ = RunLockHunterAsync();
        }
    }

    private async Task RunLockHunterAsync()
    {
        if (string.IsNullOrWhiteSpace(LockedTargetPath))
        {
            LockHunterHeadline = "Укажите путь к занятому файлу или папке.";
            return;
        }

        var lockers = await _optimizerService.FindLockingProcessesAsync(LockedTargetPath);
        LockingProcesses.Clear();
        foreach (var lp in lockers)
        {
            var captured = lp;
            LockingProcesses.Add(new LockingProcessItemViewModel(
                captured,
                new AsyncRelayCommand(_ => CloseLockingProcessAsync(captured))));
        }

        OnPropertyChanged(nameof(HasLockingProcesses));
        LockHunterHeadline = lockers.Count == 0
            ? "✅ Ни одна программа сейчас не удерживает блокировку этого пути — файл свободен!"
            : $"🔒 Найдено процессов, удерживающих этот путь: {lockers.Count}.";
    }

    private async Task CloseLockingProcessAsync(LockingProcessInfo info)
    {
        var res = await _optimizerService.RequestSafeCloseLockingProcessAsync(info);
        ActionStatusBanner = res.UserFriendlyMessage;
        await RunLockHunterAsync();
    }

    private async Task ApplyDnsAsync(DnsPresetId presetId)
    {
        var res = await _optimizerService.ApplyDnsPresetAsync(presetId);
        ActionStatusBanner = res.UserFriendlyMessage;
        await _onActionCompletedAsync(res.UserFriendlyMessage);
    }

    private async Task RunNetworkLatencyTestAsync()
    {
        LatencyHeadline = "Замер времени DNS и стабильности TCP-канала (5 пакетов)...";
        try
        {
            var report = await NetworkAndHostsInspector.MeasureLatencyAndJitterAsync("1.1.1.1", 443, 5);
            LatencyBadge = report.QualityGradeBadge;
            LatencyHeadline = $"Средний отклик: {report.AvgRttMs} мс (мин. {report.MinRttMs} мс / макс. {report.MaxRttMs} мс, джиттер {report.JitterMs} мс) • {report.FriendlyInterpretation}";
        }
        catch (Exception ex)
        {
            LatencyBadge = "Нет связи";
            LatencyHeadline = $"Не удалось выполнить тест сети: {ex.Message}";
        }
    }

    private void RebuildFilteredApps()
    {
        FilteredInstalledApps.Clear();
        var query = AppSearchFilter.Trim();
        var source = string.IsNullOrEmpty(query)
            ? _allInstalledApps.Take(60)
            : _allInstalledApps.Where(a =>
                a.DisplayName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                a.Publisher.Contains(query, StringComparison.OrdinalIgnoreCase)).Take(60);

        foreach (var app in source)
        {
            FilteredInstalledApps.Add(app);
        }
    }
}
