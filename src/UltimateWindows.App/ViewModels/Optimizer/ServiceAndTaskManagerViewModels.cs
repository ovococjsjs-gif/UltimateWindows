using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using System.Windows.Input;
using UltimateWindows.App.Infrastructure;
using UltimateWindows.Modules.Optimizer.Models;
using UltimateWindows.Modules.Optimizer.Services;

namespace UltimateWindows.App.ViewModels;

/// <summary>
/// Вариант типа запуска в выпадающем списке.
/// </summary>
public sealed record ServiceStartupChoice(ServiceStartupMode Mode, string Title);

public sealed class ServiceItemViewModel : ObservableObject
{
    private static readonly IReadOnlyList<ServiceStartupChoice> UserChoices =
    [
        new(ServiceStartupMode.Automatic, ServiceDisplay.GetTitle(ServiceStartupMode.Automatic)),
        new(ServiceStartupMode.AutomaticDelayed, ServiceDisplay.GetTitle(ServiceStartupMode.AutomaticDelayed)),
        new(ServiceStartupMode.Manual, ServiceDisplay.GetTitle(ServiceStartupMode.Manual)),
        new(ServiceStartupMode.Disabled, ServiceDisplay.GetTitle(ServiceStartupMode.Disabled))
    ];

    private readonly Func<ServiceItemViewModel, ServiceStartupMode, Task> _onStartupChangedAsync;
    private WindowsServiceInfo _info;
    private ServiceStartupMode _startup;
    private bool _isBusy;

    public ServiceItemViewModel(
        WindowsServiceInfo info,
        SystemObjectProtection protection,
        string catalogHint,
        Func<ServiceItemViewModel, ServiceStartupMode, Task> onStartupChangedAsync,
        ICommand controlCommand)
    {
        _info = info;
        _startup = info.Startup;
        Protection = protection;
        CatalogHint = catalogHint;
        _onStartupChangedAsync = onStartupChangedAsync;
        ControlCommand = controlCommand;
    }

    public WindowsServiceInfo Info => _info;
    public SystemObjectProtection Protection { get; }
    public string CatalogHint { get; }

    public string ServiceName => _info.ServiceName;
    public string DisplayName => _info.DisplayName;
    public string Description => _info.Description;
    public string Publisher => string.IsNullOrWhiteSpace(_info.Publisher) ? "—" : _info.Publisher;
    public bool IsMicrosoft => _info.IsMicrosoft;
    public bool IsRunning => _info.IsRunning;
    public string StateText => _info.StateDisplay;
    public ChipViewModel StateChip => new(_info.StateDisplay, _info.IsRunning ? "Safe" : "Neutral");
    public string StartupText => ServiceDisplay.GetTitle(_startup);
    public bool IsDisabled => _startup == ServiceStartupMode.Disabled;

    public bool IsLocked => Protection == SystemObjectProtection.Critical;

    /// <summary>Пояснение в таблице: защита, подсказка каталога или описание службы из Windows.</summary>
    public string Note => Protection switch
    {
        SystemObjectProtection.Critical => "Защищена: без неё Windows не загрузится или перестанет работать.",
        SystemObjectProtection.WeakensProtection => "Служба защиты, обновлений или восстановления. Изменение требует подтверждения.",
        _ => CatalogHint.Length > 0 ? CatalogHint : Description
    };

    public string NoteToolTip => string.IsNullOrWhiteSpace(Description) ? Note : Description;

    public IReadOnlyList<ServiceStartupChoice> StartupChoices => UserChoices;

    /// <summary>
    /// Тип запуска в выпадающем списке. Пустое значение (список на мгновение теряет выбор) игнорируется.
    /// </summary>
    public ServiceStartupMode? SelectedStartup
    {
        get => _startup;
        set
        {
            if (value is not { } mode || mode == _startup || IsBusy || IsLocked)
            {
                OnPropertyChanged();
                return;
            }

            _ = _onStartupChangedAsync(this, mode);
        }
    }

    public bool IsBusy
    {
        get => _isBusy;
        set
        {
            if (SetProperty(ref _isBusy, value))
            {
                OnPropertyChanged(nameof(CanChange));
                OnPropertyChanged(nameof(CanControl));
            }
        }
    }

    public bool CanChange => !IsBusy && !IsLocked && _startup is not (ServiceStartupMode.Boot or ServiceStartupMode.System);

    public bool CanControl => !IsBusy && (!IsRunning || !IsLocked);

    public string ControlButtonText => IsRunning ? "Остановить" : "Запустить";

    public ICommand ControlCommand { get; }

    public void Update(WindowsServiceInfo info)
    {
        _info = info;
        _startup = info.Startup;
        OnPropertyChanged(string.Empty);
    }

    public void SetStartup(ServiceStartupMode startup)
    {
        _startup = startup;
        _info = _info with { Startup = startup };
        OnPropertyChanged(nameof(SelectedStartup));
        OnPropertyChanged(nameof(StartupText));
        OnPropertyChanged(nameof(IsDisabled));
        OnPropertyChanged(nameof(CanChange));
    }

    public void SetRunning(bool running)
    {
        _info = _info with { State = running ? ServiceRunState.Running : ServiceRunState.Stopped };
        OnPropertyChanged(nameof(IsRunning));
        OnPropertyChanged(nameof(StateText));
        OnPropertyChanged(nameof(StateChip));
        OnPropertyChanged(nameof(ControlButtonText));
        OnPropertyChanged(nameof(CanControl));
    }

    public bool Matches(string search) =>
        search.Length == 0 ||
        DisplayName.Contains(search, StringComparison.CurrentCultureIgnoreCase) ||
        ServiceName.Contains(search, StringComparison.OrdinalIgnoreCase) ||
        Description.Contains(search, StringComparison.CurrentCultureIgnoreCase) ||
        Publisher.Contains(search, StringComparison.CurrentCultureIgnoreCase);
}

/// <summary>
/// Вкладка «Службы»: все службы Windows, смена типа запуска с записью в «Машину времени», запуск и остановка.
/// </summary>
public sealed class ServiceManagerViewModel : ObservableObject
{
    private readonly SmartOptimizerService _service;
    private readonly Func<string, Task> _onActionCompletedAsync;
    private readonly Action<string> _showBanner;

    private string _searchText = "";
    private int _filterMode;
    private bool _isLoading;
    private bool _hasLoaded;
    private string _summaryText = "Список служб загружается при первом открытии вкладки.";

    public ServiceManagerViewModel(
        SmartOptimizerService service,
        Func<string, Task> onActionCompletedAsync,
        Action<string> showBanner)
    {
        _service = service;
        _onActionCompletedAsync = onActionCompletedAsync;
        _showBanner = showBanner;

        Items = new ObservableCollection<ServiceItemViewModel>();
        View = CollectionViewSource.GetDefaultView(Items);
        View.Filter = candidate => candidate is ServiceItemViewModel item && IsVisible(item);
        RefreshCommand = new AsyncRelayCommand(_ => RefreshAsync());
    }

    public ObservableCollection<ServiceItemViewModel> Items { get; }
    public ICollectionView View { get; }
    public ICommand RefreshCommand { get; }

    public bool IsElevated => _service.IsRunningAsAdministrator;
    public bool IsLimited => !IsElevated;

    public string SearchText
    {
        get => _searchText;
        set
        {
            if (SetProperty(ref _searchText, value ?? ""))
            {
                RefreshView();
            }
        }
    }

    /// <summary>0 — все, 1 — сторонние, 2 — работают, 3 — отключены, 4 — упомянуты в каталоге настроек.</summary>
    public int FilterMode
    {
        get => _filterMode;
        set
        {
            if (SetProperty(ref _filterMode, value))
            {
                RefreshView();
            }
        }
    }

    public bool IsLoading
    {
        get => _isLoading;
        private set => SetProperty(ref _isLoading, value);
    }

    public string SummaryText
    {
        get => _summaryText;
        private set => SetProperty(ref _summaryText, value);
    }

    /// <summary>
    /// Загружает список при первом показе вкладки.
    /// </summary>
    public Task EnsureLoadedAsync() => _hasLoaded ? Task.CompletedTask : RefreshAsync();

    public async Task RefreshAsync()
    {
        if (IsLoading)
        {
            return;
        }

        IsLoading = true;
        try
        {
            var services = await _service.GetServicesAsync();
            Items.Clear();
            foreach (var info in services)
            {
                ServiceItemViewModel? item = null;
                item = new ServiceItemViewModel(
                    info,
                    _service.GetServiceProtection(info.ServiceName),
                    _service.GetServiceHint(info.ServiceName),
                    ChangeStartupAsync,
                    new AsyncRelayCommand(_ => ControlAsync(item!)));
                Items.Add(item);
            }

            _hasLoaded = true;
            RefreshView();
        }
        catch (Exception ex)
        {
            SummaryText = $"Не удалось получить список служб: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    private bool IsVisible(ServiceItemViewModel item)
    {
        var passesFilter = FilterMode switch
        {
            1 => !item.IsMicrosoft,
            2 => item.IsRunning,
            3 => item.IsDisabled,
            4 => item.CatalogHint.Length > 0,
            _ => true
        };

        return passesFilter && item.Matches(SearchText.Trim());
    }

    private void RefreshView()
    {
        View.Refresh();
        var shown = Items.Count(IsVisible);
        SummaryText = Items.Count == 0
            ? "Службы не найдены."
            : $"Показано {shown} из {Items.Count} · работают: {Items.Count(i => i.IsRunning)} · сторонних: {Items.Count(i => !i.IsMicrosoft)}";
    }

    private async Task ChangeStartupAsync(ServiceItemViewModel item, ServiceStartupMode mode)
    {
        item.IsBusy = true;
        try
        {
            var name = item.ServiceName;
            var result = await Task.Run(() => _service.SetServiceStartupAsync(name, mode));
            if (!result.Succeeded && result.ConfirmationRequired != TweakConfirmationKind.None)
            {
                var agreed = UserPrompts.Confirm(new ConfirmationRequest(
                    "Служба защиты Windows",
                    $"{result.UserFriendlyMessage}\n\nВсё равно установить тип запуска «{ServiceDisplay.GetTitle(mode)}»? Изменение можно отменить в разделе «Машина времени».",
                    IsWarning: true));

                result = agreed
                    ? await Task.Run(() => _service.SetServiceStartupAsync(name, mode, acceptDangerous: true))
                    : result with { UserFriendlyMessage = $"Служба «{item.DisplayName}» оставлена без изменений." };
            }

            _showBanner(result.UserFriendlyMessage);
            if (result.Succeeded)
            {
                item.SetStartup(mode);
                if (result.RollbackSessionId is not null)
                {
                    await _onActionCompletedAsync(result.UserFriendlyMessage);
                }
            }
            else
            {
                // Возвращаем в списке прежний тип запуска
                item.SetStartup(item.Info.Startup);
            }
        }
        catch (Exception ex)
        {
            item.SetStartup(item.Info.Startup);
            _showBanner($"Служба «{item.DisplayName}»: {ex.Message}");
        }
        finally
        {
            item.IsBusy = false;
        }
    }

    private async Task ControlAsync(ServiceItemViewModel item)
    {
        if (item.IsBusy)
        {
            return;
        }

        item.IsBusy = true;
        try
        {
            var start = !item.IsRunning;
            var name = item.ServiceName;
            var result = await Task.Run(() => _service.ControlServiceAsync(name, start));
            if (!result.Succeeded && result.ConfirmationRequired != TweakConfirmationKind.None)
            {
                var agreed = UserPrompts.Confirm(new ConfirmationRequest(
                    "Служба защиты Windows",
                    $"{result.UserFriendlyMessage}\n\nВсё равно остановить службу?",
                    IsWarning: true));

                result = agreed
                    ? await Task.Run(() => _service.ControlServiceAsync(name, start, acceptDangerous: true))
                    : result with { UserFriendlyMessage = $"Служба «{item.DisplayName}» оставлена без изменений." };
            }

            _showBanner(result.UserFriendlyMessage);
            if (result.Succeeded)
            {
                item.SetRunning(start);
            }
        }
        catch (Exception ex)
        {
            _showBanner($"Служба «{item.DisplayName}»: {ex.Message}");
        }
        finally
        {
            item.IsBusy = false;
        }
    }
}

public sealed class ScheduledTaskItemViewModel : ObservableObject
{
    private readonly Func<ScheduledTaskItemViewModel, bool, Task> _onToggleAsync;
    private ScheduledTaskInfo _info;
    private bool _isEnabled;
    private bool _suppress;
    private bool _isBusy;

    public ScheduledTaskItemViewModel(
        ScheduledTaskInfo info,
        SystemObjectProtection protection,
        string catalogHint,
        Func<ScheduledTaskItemViewModel, bool, Task> onToggleAsync)
    {
        _info = info;
        _isEnabled = info.Enabled;
        Protection = protection;
        CatalogHint = catalogHint;
        _onToggleAsync = onToggleAsync;
    }

    public ScheduledTaskInfo Info => _info;
    public SystemObjectProtection Protection { get; }
    public string CatalogHint { get; }

    public string TaskPath => _info.TaskPath;
    public string Name => _info.Name;
    public string Folder => _info.Folder;
    public bool IsMicrosoft => _info.IsMicrosoft;
    public string Author => string.IsNullOrWhiteSpace(_info.Author) ? "—" : _info.Author;
    public string ActionSummary => string.IsNullOrWhiteSpace(_info.ActionSummary) ? "—" : _info.ActionSummary;
    public string LastRunText => _info.LastRunDisplay;
    public string NextRunText => _isEnabled ? _info.NextRunDisplay : "—";
    public string StateText => _info.IsRunning ? "Выполняется" : _isEnabled ? "Включено" : "Отключено";
    public ChipViewModel StateChip => new(StateText, _info.IsRunning ? "Accent" : _isEnabled ? "Safe" : "Neutral");
    public bool IsLocked => Protection == SystemObjectProtection.Critical;

    public string Note => Protection switch
    {
        SystemObjectProtection.Critical => "Защищено: задание лицензирования Windows.",
        SystemObjectProtection.WeakensProtection => "Задание защиты, обновлений или восстановления. Отключение требует подтверждения.",
        _ => CatalogHint
    };

    public bool HasNote => Note.Length > 0;

    public bool IsEnabled
    {
        get => _isEnabled;
        set
        {
            if (_isEnabled == value)
            {
                return;
            }

            _isEnabled = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(StateText));
            OnPropertyChanged(nameof(StateChip));
            OnPropertyChanged(nameof(NextRunText));
            if (!_suppress)
            {
                _ = _onToggleAsync(this, value);
            }
        }
    }

    public bool IsBusy
    {
        get => _isBusy;
        set
        {
            if (SetProperty(ref _isBusy, value))
            {
                OnPropertyChanged(nameof(CanChange));
            }
        }
    }

    public bool CanChange => !IsBusy && !IsLocked;

    public void SetEnabledSilently(bool enabled)
    {
        _suppress = true;
        try
        {
            IsEnabled = enabled;
            _info = _info with { Enabled = enabled };
        }
        finally
        {
            _suppress = false;
        }
    }

    public bool Matches(string search) =>
        search.Length == 0 ||
        TaskPath.Contains(search, StringComparison.CurrentCultureIgnoreCase) ||
        ActionSummary.Contains(search, StringComparison.CurrentCultureIgnoreCase) ||
        Author.Contains(search, StringComparison.CurrentCultureIgnoreCase);
}

/// <summary>
/// Вкладка «Планировщик»: все задания Windows, включение и отключение с записью в «Машину времени».
/// </summary>
public sealed class TaskManagerViewModel : ObservableObject
{
    private readonly SmartOptimizerService _service;
    private readonly Func<string, Task> _onActionCompletedAsync;
    private readonly Action<string> _showBanner;

    private string _searchText = "";
    private int _filterMode;
    private bool _isLoading;
    private bool _hasLoaded;
    private string _summaryText = "Список заданий загружается при первом открытии вкладки.";

    public TaskManagerViewModel(
        SmartOptimizerService service,
        Func<string, Task> onActionCompletedAsync,
        Action<string> showBanner)
    {
        _service = service;
        _onActionCompletedAsync = onActionCompletedAsync;
        _showBanner = showBanner;

        Items = new ObservableCollection<ScheduledTaskItemViewModel>();
        View = CollectionViewSource.GetDefaultView(Items);
        View.Filter = candidate => candidate is ScheduledTaskItemViewModel item && IsVisible(item);
        RefreshCommand = new AsyncRelayCommand(_ => RefreshAsync());
    }

    public ObservableCollection<ScheduledTaskItemViewModel> Items { get; }
    public ICollectionView View { get; }
    public ICommand RefreshCommand { get; }

    public bool IsElevated => _service.IsRunningAsAdministrator;
    public bool IsLimited => !IsElevated;

    public string SearchText
    {
        get => _searchText;
        set
        {
            if (SetProperty(ref _searchText, value ?? ""))
            {
                RefreshView();
            }
        }
    }

    /// <summary>0 — все, 1 — сторонние, 2 — включённые, 3 — отключённые, 4 — упомянутые в каталоге настроек.</summary>
    public int FilterMode
    {
        get => _filterMode;
        set
        {
            if (SetProperty(ref _filterMode, value))
            {
                RefreshView();
            }
        }
    }

    public bool IsLoading
    {
        get => _isLoading;
        private set => SetProperty(ref _isLoading, value);
    }

    public string SummaryText
    {
        get => _summaryText;
        private set => SetProperty(ref _summaryText, value);
    }

    public Task EnsureLoadedAsync() => _hasLoaded ? Task.CompletedTask : RefreshAsync();

    public async Task RefreshAsync()
    {
        if (IsLoading)
        {
            return;
        }

        IsLoading = true;
        try
        {
            var tasks = await _service.GetScheduledTasksAsync();
            Items.Clear();
            foreach (var info in tasks)
            {
                Items.Add(new ScheduledTaskItemViewModel(
                    info,
                    _service.GetScheduledTaskProtection(info.TaskPath),
                    _service.GetScheduledTaskHint(info.TaskPath),
                    ToggleAsync));
            }

            _hasLoaded = true;
            RefreshView();
        }
        catch (Exception ex)
        {
            SummaryText = $"Не удалось получить список заданий: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    private bool IsVisible(ScheduledTaskItemViewModel item)
    {
        var passesFilter = FilterMode switch
        {
            1 => !item.IsMicrosoft,
            2 => item.IsEnabled,
            3 => !item.IsEnabled,
            4 => item.CatalogHint.Length > 0,
            _ => true
        };

        return passesFilter && item.Matches(SearchText.Trim());
    }

    private void RefreshView()
    {
        View.Refresh();
        var shown = Items.Count(IsVisible);
        SummaryText = Items.Count == 0
            ? "Задания не найдены."
            : $"Показано {shown} из {Items.Count} · включено: {Items.Count(i => i.IsEnabled)} · сторонних: {Items.Count(i => !i.IsMicrosoft)}";
    }

    private async Task ToggleAsync(ScheduledTaskItemViewModel item, bool enable)
    {
        item.IsBusy = true;
        try
        {
            var path = item.TaskPath;
            var result = await Task.Run(() => _service.SetScheduledTaskEnabledAsync(path, enable));
            if (!result.Succeeded && result.ConfirmationRequired != TweakConfirmationKind.None)
            {
                var agreed = UserPrompts.Confirm(new ConfirmationRequest(
                    "Задание защиты Windows",
                    $"{result.UserFriendlyMessage}\n\nВсё равно отключить задание? Изменение можно отменить в разделе «Машина времени».",
                    IsWarning: true));

                result = agreed
                    ? await Task.Run(() => _service.SetScheduledTaskEnabledAsync(path, enable, acceptDangerous: true))
                    : result with { UserFriendlyMessage = $"Задание «{item.Name}» оставлено без изменений." };
            }

            _showBanner(result.UserFriendlyMessage);
            if (result.Succeeded)
            {
                item.SetEnabledSilently(enable);
                if (result.RollbackSessionId is not null)
                {
                    await _onActionCompletedAsync(result.UserFriendlyMessage);
                }
            }
            else
            {
                item.SetEnabledSilently(!enable);
            }
        }
        catch (Exception ex)
        {
            item.SetEnabledSilently(!enable);
            _showBanner($"Задание «{item.Name}»: {ex.Message}");
        }
        finally
        {
            item.IsBusy = false;
        }
    }
}
