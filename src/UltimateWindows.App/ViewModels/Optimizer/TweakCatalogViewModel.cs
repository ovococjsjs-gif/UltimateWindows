using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Windows.Data;
using System.Windows.Input;
using Microsoft.Win32;
using UltimateWindows.App.Infrastructure;
using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Optimizer.Models;
using UltimateWindows.Modules.Optimizer.Services;

namespace UltimateWindows.App.ViewModels;

/// <summary>
/// Цветная метка рядом с настройкой. <see cref="Tone"/> — одно из: Neutral, Safe, Caution, Danger, Accent.
/// </summary>
public sealed record ChipViewModel(string Text, string Tone, string? ToolTip = null);

/// <summary>
/// Одна цель настройки в подробностях: что это, что сейчас и что станет.
/// </summary>
public sealed class TweakActionDetailViewModel
{
    public TweakActionDetailViewModel(TweakActionState state)
    {
        KindLabel = state.KindLabel;
        TargetDisplay = state.TargetDisplay;
        StateLine = !state.TargetExists
            ? "Нет в этой системе — будет пропущено."
            : state.IsInDesiredState
                ? $"Сейчас: {state.CurrentDisplay} — уже как в настройке. Стандарт Windows: {state.DefaultDisplay}."
                : $"Сейчас: {state.CurrentDisplay} → станет: {state.DesiredDisplay}. Стандарт Windows: {state.DefaultDisplay}.";
    }

    public string KindLabel { get; }
    public string TargetDisplay { get; }
    public string StateLine { get; }
}

public sealed class TweakItemViewModel : ObservableObject
{
    private readonly Func<TweakItemViewModel, bool, Task> _onUserToggleAsync;
    private readonly Func<string, IReadOnlyList<TweakActionState>> _describeActions;
    private readonly bool _isElevated;

    private EvaluatedTweakState _state;
    private bool _isApplied;
    private bool _suppressCallback;
    private bool _isBusy;
    private bool _isExpanded;
    private IReadOnlyList<ChipViewModel> _chips = [];

    public TweakItemViewModel(
        EvaluatedTweakState state,
        int order,
        bool isElevated,
        Func<TweakItemViewModel, bool, Task> onUserToggleAsync,
        Func<string, IReadOnlyList<TweakActionState>> describeActions)
    {
        _state = state;
        _isApplied = state.IsCurrentlyApplied;
        _isElevated = isElevated;
        _onUserToggleAsync = onUserToggleAsync;
        _describeActions = describeActions;

        Order = order;
        Details = new ObservableCollection<TweakActionDetailViewModel>();
        ToggleDetailsCommand = new RelayCommand(_ => IsExpanded = !IsExpanded);
        RebuildChips();
    }

    public DeclarativeTweakRule Rule => _state.Rule;
    public TweakStateKind State => _state.State;
    public TweakApplicability Applicability => _state.Applicability;

    public int Order { get; }
    public string TweakId => Rule.TweakId;
    public string Title => Rule.FriendlyTitle;
    public string Explanation => Rule.FriendlyExplanation;
    public TweakCategory Category => Rule.Category;
    public string CategoryTitle => Rule.CategoryDisplayName;
    public int CategoryOrder => TweakCategoryInfo.GetOrder(Rule.Category);
    public bool IsDangerous => Rule.IsDangerous;
    public bool IsNotApplicable => Applicability.Status == TweakApplicabilityStatus.NotApplicable;

    /// <summary>Включена полностью или частично — такую настройку нельзя прятать фильтрами.</summary>
    public bool IsActive => State is TweakStateKind.Applied or TweakStateKind.Partial;

    /// <summary>Включена полностью: именно это показывает переключатель и считают все счётчики «включено».</summary>
    public bool IsFullyApplied => State == TweakStateKind.Applied;

    public bool IsApplied
    {
        get => _isApplied;
        set
        {
            if (_isApplied == value)
            {
                return;
            }

            _isApplied = value;
            OnPropertyChanged();
            if (!_suppressCallback)
            {
                _ = _onUserToggleAsync(this, value);
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
                OnPropertyChanged(nameof(CanToggle));
            }
        }
    }

    /// <summary>Настройку, которая этому компьютеру не подходит, включить нельзя; выключить — можно всегда.</summary>
    public bool CanToggle => !IsBusy && (!IsNotApplicable || IsActive);

    /// <summary>
    /// Пояснение под описанием: почему настройка не подходит этому компьютеру или не рекомендуется.
    /// </summary>
    public string AdvisoryNote => Applicability.Status switch
    {
        TweakApplicabilityStatus.NotApplicable => Applicability.Reason ?? "",
        TweakApplicabilityStatus.NotRecommended => $"Не рекомендуется для этого компьютера. {Applicability.Reason}",
        _ => IsDangerous ? "Включается только после отдельного подтверждения." : ""
    };

    public bool HasAdvisoryNote => AdvisoryNote.Length > 0;

    public IReadOnlyList<ChipViewModel> Chips
    {
        get => _chips;
        private set => SetProperty(ref _chips, value);
    }

    public ObservableCollection<TweakActionDetailViewModel> Details { get; }

    public bool IsExpanded
    {
        get => _isExpanded;
        set
        {
            if (!SetProperty(ref _isExpanded, value))
            {
                return;
            }

            OnPropertyChanged(nameof(DetailsButtonText));
            if (value)
            {
                ReloadDetails();
            }
        }
    }

    public string DetailsButtonText => IsExpanded ? "Скрыть" : "Что изменится";

    public string DetailsHeadline => Rule.Actions.Count == 1
        ? $"Настройка меняет одну цель ({Rule.TweakId})"
        : $"Настройка меняет целей: {Rule.Actions.Count} ({Rule.TweakId})";

    public ICommand ToggleDetailsCommand { get; }

    /// <summary>
    /// Принимает свежее состояние из системы, не вызывая применения.
    /// </summary>
    public void Update(EvaluatedTweakState state)
    {
        _state = state;
        SetAppliedSilently(state.IsCurrentlyApplied);
        OnPropertyChanged(nameof(State));
        OnPropertyChanged(nameof(Applicability));
        OnPropertyChanged(nameof(IsNotApplicable));
        OnPropertyChanged(nameof(IsActive));
        OnPropertyChanged(nameof(IsFullyApplied));
        OnPropertyChanged(nameof(CanToggle));
        OnPropertyChanged(nameof(AdvisoryNote));
        OnPropertyChanged(nameof(HasAdvisoryNote));
        RebuildChips();
        if (IsExpanded)
        {
            ReloadDetails();
        }
    }

    public void SetAppliedSilently(bool applied)
    {
        _suppressCallback = true;
        try
        {
            IsApplied = applied;
        }
        finally
        {
            _suppressCallback = false;
        }
    }

    public bool Matches(string search) =>
        search.Length == 0 ||
        Title.Contains(search, StringComparison.CurrentCultureIgnoreCase) ||
        Explanation.Contains(search, StringComparison.CurrentCultureIgnoreCase) ||
        TweakId.Contains(search, StringComparison.OrdinalIgnoreCase);

    private void ReloadDetails()
    {
        Details.Clear();
        try
        {
            foreach (var action in _describeActions(TweakId))
            {
                Details.Add(new TweakActionDetailViewModel(action));
            }
        }
        catch (Exception)
        {
            // Подробности — справочные сведения; их отсутствие не мешает пользоваться настройкой
        }
    }

    private void RebuildChips()
    {
        var chips = new List<ChipViewModel>(4)
        {
            Rule.Risk switch
            {
                RiskLevel.Safe => new ChipViewModel("Безопасно", "Safe", "Ничего не ломает и не отключает полезных функций."),
                RiskLevel.Low => new ChipViewModel("Есть побочный эффект", "Neutral", "Отключает функцию, описанную в пояснении. Прочитайте его перед включением."),
                RiskLevel.High or RiskLevel.Critical => new ChipViewModel("Опасно", "Danger", "Ослабляет защиту или устойчивость Windows. В наборы не входит."),
                _ => new ChipViewModel("С оговорками", "Caution", "У части пользователей что-то перестанет работать. В наборы не входит.")
            }
        };

        if (State == TweakStateKind.Partial)
        {
            chips.Add(new ChipViewModel(
                $"Включено частично: {_state.AppliedActionCount} из {_state.PresentActionCount}",
                "Caution",
                "Часть целей уже в нужном состоянии. Включите настройку, чтобы применить остальные."));
        }

        if (IsNotApplicable)
        {
            chips.Add(new ChipViewModel("Не подходит этому компьютеру", "Neutral"));
        }

        if (Rule.Restart != TweakRestartKind.None)
        {
            chips.Add(new ChipViewModel($"Действует {Rule.RestartDisplayName}", "Neutral"));
        }

        if (Rule.RequiresAdministrator && !_isElevated)
        {
            chips.Add(new ChipViewModel("Нужны права администратора", "Caution"));
        }

        Chips = chips;
    }
}

/// <summary>
/// Раздел каталога в левой колонке. Раздел без категории — «Все настройки».
/// </summary>
public sealed class TweakCategoryViewModel : ObservableObject
{
    private string _countText = "";

    public TweakCategoryViewModel(TweakCategory? category, string title)
    {
        Category = category;
        Title = title;
    }

    public TweakCategory? Category { get; }
    public string Title { get; }

    public string CountText
    {
        get => _countText;
        private set => SetProperty(ref _countText, value);
    }

    public void SetCounts(int active, int total) => CountText = $"{active} / {total}";
}

public sealed class TweakPresetViewModel : ObservableObject
{
    private string _progressText = "";

    public TweakPresetViewModel(TweakPresetDescriptor descriptor, ICommand openCommand)
    {
        Descriptor = descriptor;
        OpenCommand = openCommand;
    }

    public TweakPresetDescriptor Descriptor { get; }
    public string Title => Descriptor.Title;
    public string Description => Descriptor.Description;
    public ICommand OpenCommand { get; }

    public string ProgressText
    {
        get => _progressText;
        private set => SetProperty(ref _progressText, value);
    }

    public void SetProgress(int active, int total) => ProgressText = $"включено {active} из {total}";
}

public sealed class BatchPreviewItemViewModel : ObservableObject
{
    private readonly Action _onSelectionChanged;
    private bool _isSelected;

    public BatchPreviewItemViewModel(
        string tweakId,
        string title,
        string statusText,
        string tone,
        bool isSelectable,
        bool isSelected,
        bool needsNotRecommendedConsent,
        bool needsDangerousConsent,
        Action onSelectionChanged)
    {
        TweakId = tweakId;
        Title = title;
        StatusText = statusText;
        Tone = tone;
        IsSelectable = isSelectable;
        _isSelected = isSelectable && isSelected;
        NeedsNotRecommendedConsent = needsNotRecommendedConsent;
        NeedsDangerousConsent = needsDangerousConsent;
        _onSelectionChanged = onSelectionChanged;
    }

    public string TweakId { get; }
    public string Title { get; }
    public string StatusText { get; }
    public string Tone { get; }
    public bool IsSelectable { get; }
    public bool NeedsNotRecommendedConsent { get; }
    public bool NeedsDangerousConsent { get; }

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (IsSelectable && SetProperty(ref _isSelected, value))
            {
                _onSelectionChanged();
            }
        }
    }
}

/// <summary>
/// Окно предпросмотра набора или профиля: что будет включено. Каждую строку можно снять.
/// Настройка, которой нужно согласие (не рекомендуется этому компьютеру, опасная), изначально не отмечена:
/// отметка и есть согласие.
/// </summary>
public sealed class TweakBatchPreviewViewModel : ObservableObject
{
    public TweakBatchPreviewViewModel(string title, string description, string note, ICommand applyCommand, ICommand cancelCommand)
    {
        Title = title;
        Description = description;
        Note = note;
        ApplyCommand = applyCommand;
        CancelCommand = cancelCommand;
        Items = new ObservableCollection<BatchPreviewItemViewModel>();
    }

    public string Title { get; }
    public string Description { get; }
    public string Note { get; }
    public bool HasNote => Note.Length > 0;
    public ObservableCollection<BatchPreviewItemViewModel> Items { get; }
    public ICommand ApplyCommand { get; }
    public ICommand CancelCommand { get; }

    public int SelectedCount => Items.Count(i => i.IsSelected);
    public bool HasSelection => SelectedCount > 0;
    public string ApplyButtonText => SelectedCount == 0 ? "Нечего включать" : $"Включить ({SelectedCount})";

    public string FooterText
    {
        get
        {
            var already = Items.Count(i => !i.IsSelectable && i.Tone == "Safe");
            return already > 0
                ? $"Уже включено: {already}. Всё, что будет включено сейчас, отменяется одной записью в «Машине времени»."
                : "Всё, что будет включено сейчас, отменяется одной записью в «Машине времени».";
        }
    }

    public void NotifySelectionChanged()
    {
        OnPropertyChanged(nameof(SelectedCount));
        OnPropertyChanged(nameof(HasSelection));
        OnPropertyChanged(nameof(ApplyButtonText));
    }
}

/// <summary>
/// Вкладка «Настройки Windows»: каталог твиков с разделами, поиском, фильтрами, готовыми наборами и профилями.
/// </summary>
public sealed class TweakCatalogViewModel : ObservableObject
{
    private readonly SmartOptimizerService _service;
    private readonly Func<string, Task> _onActionCompletedAsync;
    private readonly Action<string> _showBanner;
    private readonly Dictionary<string, TweakItemViewModel> _byId = new(StringComparer.OrdinalIgnoreCase);
    private readonly bool _isElevated;

    private TweakCategoryViewModel _selectedCategory;
    private string _searchText = "";
    private bool _showOnlyEnabled;
    private bool _hideNotApplicable = true;
    private bool _showDangerous;
    private bool _isLoading;
    private bool _isApplyingBatch;
    private string _summaryText = "";
    private bool _hasVisibleTweaks = true;
    private TweakBatchPreviewViewModel? _preview;

    public TweakCatalogViewModel(
        SmartOptimizerService service,
        Func<string, Task> onActionCompletedAsync,
        Action<string> showBanner)
    {
        _service = service;
        _onActionCompletedAsync = onActionCompletedAsync;
        _showBanner = showBanner;
        _isElevated = service.IsRunningAsAdministrator;

        AllTweaks = new ObservableCollection<TweakItemViewModel>();
        Categories = new ObservableCollection<TweakCategoryViewModel>();
        Presets = new ObservableCollection<TweakPresetViewModel>();

        // Список строится из каталога сразу, без обращения к системе; состояние подтягивается в RefreshAsync
        var order = 0;
        foreach (var rule in _service.GetCatalogRules())
        {
            var item = new TweakItemViewModel(
                new EvaluatedTweakState(rule, TweakStateKind.NotApplied, TweakApplicability.Applicable),
                order++,
                _isElevated,
                HandleToggleAsync,
                _service.DescribeTweakActions);
            AllTweaks.Add(item);
            _byId[rule.TweakId] = item;
        }

        _selectedCategory = new TweakCategoryViewModel(null, "Все настройки");
        Categories.Add(_selectedCategory);
        foreach (var category in TweakCategoryInfo.DisplayOrder)
        {
            if (AllTweaks.Any(t => t.Category == category))
            {
                Categories.Add(new TweakCategoryViewModel(category, TweakCategoryInfo.GetTitle(category)));
            }
        }

        foreach (var preset in _service.GetPresets())
        {
            var captured = preset;
            Presets.Add(new TweakPresetViewModel(captured, new RelayCommand(_ => OpenPresetPreview(captured))));
        }

        VisibleTweaks = CollectionViewSource.GetDefaultView(AllTweaks);
        VisibleTweaks.Filter = candidate => candidate is TweakItemViewModel item && IsVisible(item);
        VisibleTweaks.SortDescriptions.Add(new SortDescription(nameof(TweakItemViewModel.CategoryOrder), ListSortDirection.Ascending));
        VisibleTweaks.SortDescriptions.Add(new SortDescription(nameof(TweakItemViewModel.Order), ListSortDirection.Ascending));
        VisibleTweaks.GroupDescriptions.Add(new PropertyGroupDescription(nameof(TweakItemViewModel.CategoryTitle)));

        RefreshCommand = new AsyncRelayCommand(_ => RefreshAsync());
        ClearSearchCommand = new RelayCommand(_ => SearchText = "");
        ExportProfileCommand = new RelayCommand(_ => ExportProfile());
        ImportProfileCommand = new RelayCommand(_ => ImportProfile());

        Recount();
        RefreshView();
    }

    public ObservableCollection<TweakItemViewModel> AllTweaks { get; }
    public ICollectionView VisibleTweaks { get; }
    public ObservableCollection<TweakCategoryViewModel> Categories { get; }
    public ObservableCollection<TweakPresetViewModel> Presets { get; }

    public TweakCategoryViewModel SelectedCategory
    {
        get => _selectedCategory;
        set
        {
            // При перестроении списка ListBox на мгновение сбрасывает выбор — остаёмся на прежнем разделе
            if (value is not null && SetProperty(ref _selectedCategory, value))
            {
                RefreshView();
            }
        }
    }

    public string SearchText
    {
        get => _searchText;
        set
        {
            if (SetProperty(ref _searchText, value ?? ""))
            {
                OnPropertyChanged(nameof(HasSearchText));
                RefreshView();
            }
        }
    }

    public bool HasSearchText => SearchText.Trim().Length > 0;

    public bool ShowOnlyEnabled
    {
        get => _showOnlyEnabled;
        set
        {
            if (SetProperty(ref _showOnlyEnabled, value))
            {
                RefreshView();
            }
        }
    }

    public bool HideNotApplicable
    {
        get => _hideNotApplicable;
        set
        {
            if (SetProperty(ref _hideNotApplicable, value))
            {
                Recount();
                RefreshView();
            }
        }
    }

    public bool ShowDangerous
    {
        get => _showDangerous;
        set
        {
            if (SetProperty(ref _showDangerous, value))
            {
                Recount();
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

    public bool HasVisibleTweaks
    {
        get => _hasVisibleTweaks;
        private set
        {
            if (SetProperty(ref _hasVisibleTweaks, value))
            {
                OnPropertyChanged(nameof(HasNoVisibleTweaks));
            }
        }
    }

    public bool HasNoVisibleTweaks => !HasVisibleTweaks;

    public TweakBatchPreviewViewModel? Preview
    {
        get => _preview;
        private set
        {
            if (SetProperty(ref _preview, value))
            {
                OnPropertyChanged(nameof(IsPreviewOpen));
            }
        }
    }

    public bool IsPreviewOpen => Preview is not null;

    public int ActiveTweaksCount => AllTweaks.Count(t => t.IsFullyApplied);

    public ICommand RefreshCommand { get; }
    public ICommand ClearSearchCommand { get; }
    public ICommand ExportProfileCommand { get; }
    public ICommand ImportProfileCommand { get; }

    /// <summary>
    /// Перечитывает состояние всех настроек из системы. Чтение идёт в фоне: в нём участвуют службы и планировщик.
    /// </summary>
    public async Task RefreshAsync()
    {
        if (IsLoading)
        {
            return;
        }

        IsLoading = true;
        try
        {
            var states = await Task.Run(_service.EvaluateAllTweaks);
            foreach (var state in states)
            {
                if (_byId.TryGetValue(state.Rule.TweakId, out var item))
                {
                    item.Update(state);
                }
            }

            Recount();
            RefreshView();
        }
        catch (Exception ex)
        {
            _showBanner($"Не удалось прочитать состояние настроек: {ex.Message}");
        }
        finally
        {
            IsLoading = false;
        }
    }

    private bool IsVisible(TweakItemViewModel item)
    {
        if (!IsListed(item))
        {
            return false;
        }

        if (SelectedCategory.Category is { } category && item.Category != category)
        {
            return false;
        }

        if (ShowOnlyEnabled && !item.IsActive)
        {
            return false;
        }

        return item.Matches(SearchText.Trim());
    }

    /// <summary>
    /// Входит ли настройка в каталог при текущих флажках (без учёта раздела и поиска).
    /// Включённая настройка видна всегда, чтобы её можно было выключить.
    /// </summary>
    private bool IsListed(TweakItemViewModel item)
    {
        if (item.IsActive)
        {
            return true;
        }

        if (HideNotApplicable && item.IsNotApplicable)
        {
            return false;
        }

        return !item.IsDangerous || ShowDangerous;
    }

    private void RefreshView()
    {
        VisibleTweaks.Refresh();
        HasVisibleTweaks = !VisibleTweaks.IsEmpty;
    }

    private void Recount()
    {
        var listed = AllTweaks.Where(IsListed).ToList();
        foreach (var category in Categories)
        {
            var inCategory = category.Category is { } c ? listed.Where(t => t.Category == c).ToList() : listed;
            category.SetCounts(inCategory.Count(t => t.IsFullyApplied), inCategory.Count);
        }

        foreach (var preset in Presets)
        {
            var items = preset.Descriptor.TweakIds
                .Select(id => _byId.TryGetValue(id, out var item) ? item : null)
                .Where(item => item is not null && !item.IsNotApplicable)
                .ToList();
            preset.SetProgress(items.Count(item => item!.IsFullyApplied), items.Count);
        }

        SummaryText = $"Включено {listed.Count(t => t.IsFullyApplied)} из {listed.Count}";
        OnPropertyChanged(nameof(ActiveTweaksCount));
    }

    private async Task HandleToggleAsync(TweakItemViewModel item, bool targetState)
    {
        if (item.IsBusy)
        {
            return;
        }

        item.IsBusy = true;
        try
        {
            var id = item.TweakId;
            var result = await Task.Run(() => _service.SetTweakStateAsync(id, targetState));

            // Опасная или не рекомендуемая этому компьютеру настройка включается только после явного согласия
            if (!result.Succeeded && result.ConfirmationRequired != TweakConfirmationKind.None)
            {
                var dangerous = result.ConfirmationRequired == TweakConfirmationKind.DangerousTweak;
                var agreed = UserPrompts.Confirm(new ConfirmationRequest(
                    dangerous ? "Опасная настройка" : "Настройка не рекомендуется",
                    $"{result.UserFriendlyMessage}\n\nВсё равно включить? Изменение можно отменить в разделе «Машина времени».",
                    IsWarning: dangerous));

                result = agreed
                    ? await Task.Run(() => _service.SetTweakStateAsync(id, targetState, default, TweakApplyOptions.AcceptAll))
                    : result with { UserFriendlyMessage = $"«{item.Title}» оставлено без изменений." };
            }

            _showBanner(result.UserFriendlyMessage);

            var fresh = await Task.Run(() => _service.EvaluateTweak(id));
            if (fresh is not null)
            {
                item.Update(fresh);
            }
            else
            {
                item.SetAppliedSilently(!targetState);
            }

            Recount();

            // Список перестраивается, только если от состояния этой настройки зависит, видна ли она
            if (ShowOnlyEnabled || item.IsDangerous || item.IsNotApplicable)
            {
                RefreshView();
            }

            if (result.Succeeded && result.RollbackSessionId is not null)
            {
                await _onActionCompletedAsync(result.UserFriendlyMessage);
            }
        }
        catch (Exception ex)
        {
            item.SetAppliedSilently(!targetState);
            _showBanner($"«{item.Title}»: {ex.Message}");
        }
        finally
        {
            item.IsBusy = false;
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Наборы и профили
    // ---------------------------------------------------------------------------------------------

    private void OpenPresetPreview(TweakPresetDescriptor preset) =>
        OpenPreview($"Набор «{preset.Title}»", preset.Description, note: "", preset.TweakIds);

    private void OpenPreview(string title, string description, string note, IReadOnlyList<string> tweakIds)
    {
        TweakBatchPreviewViewModel? preview = null;
        preview = new TweakBatchPreviewViewModel(
            title,
            description,
            note,
            new AsyncRelayCommand(_ => ApplyPreviewAsync(preview!), _ => !_isApplyingBatch),
            new RelayCommand(_ => Preview = null));

        foreach (var id in tweakIds)
        {
            if (!_byId.TryGetValue(id, out var item))
            {
                continue;
            }

            var applicability = item.Applicability;
            var needsAdmin = item.Rule.RequiresAdministrator && !_isElevated;

            string status;
            string tone;
            var selectable = true;
            var selected = true;
            var notRecommended = false;

            if (item.State == TweakStateKind.Applied)
            {
                (status, tone, selectable) = ("Уже включено", "Safe", false);
            }
            else if (applicability.Status == TweakApplicabilityStatus.NotApplicable)
            {
                (status, tone, selectable) = ($"Не подходит этому компьютеру. {applicability.Reason}", "Neutral", false);
            }
            else if (needsAdmin)
            {
                (status, tone, selectable) = ("Нужны права администратора — перезапустите программу с правами.", "Caution", false);
            }
            else if (item.IsDangerous)
            {
                (status, tone, selected) = ("Опасная настройка. Отметьте, только если понимаете последствия.", "Danger", false);
            }
            else if (applicability.Status == TweakApplicabilityStatus.NotRecommended)
            {
                (status, tone, selected, notRecommended) = ($"Не рекомендуется: {applicability.Reason}", "Caution", false, true);
            }
            else if (item.State == TweakStateKind.Partial)
            {
                (status, tone) = ("Сейчас включено частично — набор включит настройку полностью.", "Accent");
            }
            else
            {
                // «Plain» — обычное пояснение без цветной подложки
                (status, tone) = (item.Explanation, "Plain");
            }

            preview.Items.Add(new BatchPreviewItemViewModel(
                item.TweakId,
                item.Title,
                status,
                tone,
                selectable,
                selected,
                notRecommended,
                item.IsDangerous,
                preview.NotifySelectionChanged));
        }

        Preview = preview;
    }

    private async Task ApplyPreviewAsync(TweakBatchPreviewViewModel preview)
    {
        var chosen = preview.Items.Where(i => i.IsSelected).ToList();
        if (chosen.Count == 0 || _isApplyingBatch)
        {
            return;
        }

        _isApplyingBatch = true;
        try
        {
            // Отметка строки, которой нужно согласие, и есть согласие пользователя
            var options = new TweakApplyOptions(
                AcceptNotRecommended: chosen.Any(i => i.NeedsNotRecommendedConsent),
                AcceptDangerous: chosen.Any(i => i.NeedsDangerousConsent));

            var ids = chosen.Select(i => i.TweakId).ToArray();
            var title = preview.Title;
            var result = await Task.Run(() => _service.ApplyTweakBatchAsync(ids, title, options));

            Preview = null;

            var firstFailure = result.Items.FirstOrDefault(i => i.Outcome == TweakBatchItemOutcome.Failed);
            _showBanner(firstFailure is null
                ? result.UserFriendlyMessage
                : $"{result.UserFriendlyMessage} Не удалось: «{firstFailure.Title}» — {firstFailure.Note}");

            await RefreshAsync();
            if (result.RollbackSessionId is not null)
            {
                await _onActionCompletedAsync(result.UserFriendlyMessage);
            }
        }
        catch (Exception ex)
        {
            _showBanner($"{preview.Title}: {ex.Message}");
        }
        finally
        {
            _isApplyingBatch = false;
        }
    }

    private void ExportProfile()
    {
        var dialog = new SaveFileDialog
        {
            Title = "Сохранить включённые настройки в файл профиля",
            Filter = "Профиль настроек (*.yaml)|*.yaml",
            FileName = "ultimatewindows-profile.yaml"
        };

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        try
        {
            var yaml = _service.ExportActiveTweaksToYaml(Path.GetFileNameWithoutExtension(dialog.FileName));
            File.WriteAllText(dialog.FileName, yaml);
            _showBanner($"Профиль сохранён: {dialog.FileName}. Его можно применить на другом компьютере.");
        }
        catch (Exception ex)
        {
            _showBanner($"Не удалось сохранить профиль: {ex.Message}");
        }
    }

    private void ImportProfile()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Открыть файл профиля настроек",
            Filter = "Профиль настроек (*.yaml;*.yml)|*.yaml;*.yml"
        };

        if (dialog.ShowDialog() != true || !File.Exists(dialog.FileName))
        {
            return;
        }

        try
        {
            OpenProfilePreview(File.ReadAllText(dialog.FileName));
        }
        catch (Exception ex)
        {
            _showBanner($"Не удалось прочитать профиль: {ex.Message}");
        }
    }

    /// <summary>
    /// Показывает, что включит профиль, ничего не применяя.
    /// </summary>
    public void OpenProfilePreview(string yamlContent)
    {
        var profile = _service.ReadProfile(yamlContent);
        if (profile.KnownTweakIds.Count == 0)
        {
            _showBanner(profile.UnknownTweakIds.Count > 0
                ? $"Профиль «{profile.Name}»: ни одна из его настроек не известна этой версии программы."
                : "В выбранном профиле не указано ни одной настройки.");
            return;
        }

        var note = profile.UnknownTweakIds.Count > 0
            ? $"В профиле есть настройки, которых нет в этой версии программы ({profile.UnknownTweakIds.Count}): {string.Join(", ", profile.UnknownTweakIds.Take(4))}{(profile.UnknownTweakIds.Count > 4 ? "…" : "")}. Они будут пропущены."
            : "";

        OpenPreview(
            $"Профиль «{profile.Name}»",
            "Настройки из файла профиля. Проверьте список и снимите отметки с того, что включать не нужно.",
            note,
            profile.KnownTweakIds);
    }

    /// <summary>
    /// Открывает предпросмотр набора по его названию — для переходов из других разделов программы.
    /// </summary>
    public void OpenPresetPreview(string presetKey)
    {
        var preset = Presets.FirstOrDefault(p => string.Equals(p.Descriptor.Key, presetKey, StringComparison.OrdinalIgnoreCase));
        if (preset is not null)
        {
            OpenPresetPreview(preset.Descriptor);
        }
    }
}
