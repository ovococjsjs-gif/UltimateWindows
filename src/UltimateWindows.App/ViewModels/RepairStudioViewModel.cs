using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;
using UltimateWindows.App.Infrastructure;
using UltimateWindows.Modules.Repair.Diagnostics;
using UltimateWindows.Modules.Repair.ErrorCodes;
using UltimateWindows.Modules.Repair.Models;
using UltimateWindows.Modules.Repair.Services;

namespace UltimateWindows.App.ViewModels;

public sealed record RepairSectionFilterOption(RepairSectionId? Section, string Title)
{
    public override string ToString() => Title;
}

public sealed record ErrorFamilyFilterOption(ErrorCodeFamily? Family, string Title)
{
    public override string ToString() => Title;
}

public sealed class DiagnosticRuleItemViewModel : ObservableObject
{
    private bool _isSelectedForFix;
    private RepairHealthState? _state;
    private string _evidence = "Нажмите «Проверить систему», чтобы считать текущее состояние этого узла.";

    public DiagnosticRuleItemViewModel(RepairRuleDefinition rule, ICommand fixSingleCommand)
    {
        Rule = rule;
        FixSingleCommand = fixSingleCommand;
    }

    public RepairRuleDefinition Rule { get; }
    public string Id => Rule.Id;
    public string Title => Rule.Title;
    public string SectionTitle => Rule.SectionTitle;
    public string Symptom => Rule.Symptom;
    public string Explanation => Rule.Explanation;
    public string FixSummary => Rule.FixSummary;
    public string SeverityBadge => Rule.SeverityBadge;
    public string RiskBadge => Rule.RiskBadge;
    public string RollbackBadge => Rule.RollbackBadge;
    public string ErrorCodesDisplay => Rule.RelatedErrorCodes.Count == 0
        ? "—"
        : string.Join(", ", Rule.RelatedErrorCodes);

    public bool IsSelectedForFix
    {
        get => _isSelectedForFix;
        set => SetProperty(ref _isSelectedForFix, value);
    }

    public RepairHealthState? State => _state;
    public bool HasIssue => _state == RepairHealthState.IssueDetected;

    public string StateBadge => _state switch
    {
        null => "Готово",
        RepairHealthState.Healthy => "Норма",
        RepairHealthState.IssueDetected => "Найдено",
        RepairHealthState.NeedsElevation => "Нужен Админ",
        RepairHealthState.NotApplicable => "Не требуется",
        _ => "Ошибка чтения"
    };

    public string Evidence
    {
        get => _evidence;
        private set => SetProperty(ref _evidence, value);
    }

    public ICommand FixSingleCommand { get; }

    public void ApplyFinding(RepairCheckFinding finding)
    {
        _state = finding.State;
        Evidence = finding.Evidence;
        IsSelectedForFix = finding.State == RepairHealthState.IssueDetected && !Rule.RequiresExplicitConfirmation;
        OnPropertyChanged(nameof(State));
        OnPropertyChanged(nameof(HasIssue));
        OnPropertyChanged(nameof(StateBadge));
    }
}

public sealed class PeIssueItemViewModel : ObservableObject
{
    public PeIssueItemViewModel(
        string contextExecutable,
        PeDependencyIssue issue,
        ICommand quarantineCommand,
        ICommand installPackageCommand)
    {
        ContextExecutable = contextExecutable;
        Issue = issue;
        QuarantineCommand = quarantineCommand;
        InstallPackageCommand = installPackageCommand;
    }

    public string ContextExecutable { get; }
    public PeDependencyIssue Issue { get; }
    public string ImportedDllName => Issue.ImportedDllName;
    public string SimpleExplanation => Issue.SimpleExplanation;
    public string ExpertTechnicalDetails => Issue.ExpertTechnicalDetails;
    public bool CanQuarantineConflictingLocalDll => Issue.CanQuarantineConflictingLocalDll;
    public bool CanInstallOfficialRuntime => Issue.CanInstallOfficialRuntime;
    public string InstallButtonLabel => Issue.RecommendedPackage is not null
        ? $"Установить «{Issue.RecommendedPackage.FriendlyName}»"
        : "Установить пакет";

    public ICommand QuarantineCommand { get; }
    public ICommand InstallPackageCommand { get; }
}

public sealed class RuntimePackageItemViewModel : ObservableObject
{
    private string _installStatusBadge = "Проверка...";
    private bool _isInstalled;

    public RuntimePackageItemViewModel(OfficialRuntimePackage package, ICommand installCommand)
    {
        Package = package;
        InstallCommand = installCommand;
    }

    public OfficialRuntimePackage Package { get; }
    public string FriendlyName => Package.FriendlyName;
    public string Category => Package.Category;
    public string PublisherName => Package.PublisherName;
    public string ArchitectureBadge => Package.ArchitectureBadge;
    public string DeliveryMethodBadge => Package.DeliveryMethodBadge;
    public string WingetPackageId => Package.WingetPackageId;

    public string InstallStatusBadge
    {
        get => _installStatusBadge;
        private set => SetProperty(ref _installStatusBadge, value);
    }

    public bool IsInstalled
    {
        get => _isInstalled;
        private set => SetProperty(ref _isInstalled, value);
    }

    public ICommand InstallCommand { get; }

    public void UpdateStatus(OfficialRuntimeStatusReport report)
    {
        IsInstalled = report.IsInstalled;
        InstallStatusBadge = report.StatusBadge;
    }
}

public sealed class CrashEventItemViewModel : ObservableObject
{
    public CrashEventItemViewModel(
        SystemCrashEventEntry entry,
        ICommand inspectInPeDoctorCommand,
        ICommand jumpToRepairOrCodeCommand)
    {
        Entry = entry;
        InspectInPeDoctorCommand = inspectInPeDoctorCommand;
        JumpToRepairOrCodeCommand = jumpToRepairOrCodeCommand;
    }

    public SystemCrashEventEntry Entry { get; }
    public string TimeLocalDisplay => Entry.TimeLocalDisplay;
    public string EventBadge => Entry.EventBadge;
    public string ExceptionHex => Entry.ExceptionHex;
    public string SimpleSummary => Entry.SimpleSummary;
    public bool CanInspectInPeDoctor => Entry.CanInspectExecutableInPeDoctor;
    public bool HasJumpTarget =>
        !string.IsNullOrWhiteSpace(Entry.RecommendedRepairRuleId) ||
        Entry.ExceptionCode.HasValue;

    public ICommand InspectInPeDoctorCommand { get; }
    public ICommand JumpToRepairOrCodeCommand { get; }
}

public sealed class RepairPlaybookItemViewModel : ObservableObject
{
    public RepairPlaybookItemViewModel(RepairPlaybookDescriptor descriptor, ICommand runPlaybookCommand)
    {
        Descriptor = descriptor;
        RunPlaybookCommand = runPlaybookCommand;
    }

    public RepairPlaybookDescriptor Descriptor { get; }
    public string FriendlyTitle => Descriptor.FriendlyTitle;
    public string FriendlyDescription => Descriptor.FriendlyDescription;
    public string ExpertCommandsPreview => Descriptor.ExpertCommandsPreview;
    public string AccessBadge => Descriptor.AccessBadge;
    public ICommand RunPlaybookCommand { get; }
}

public sealed class RepairStudioViewModel : ObservableObject
{
    private readonly SystemRepairService _repairService;
    private readonly Func<string, Task> _onActionCompletedAsync;
    private readonly List<DiagnosticRuleItemViewModel> _allDiagnosticRules;

    private int _selectedSubTabIndex;
    private bool _isBusy;

    // Вкладка 0: Диагностика ОС (107 правил)
    private RepairSectionFilterOption _selectedSectionOption;
    private string _diagnosticSearchText = "";
    private bool _onlyIssuesFilter;
    private DiagnosticRuleItemViewModel? _selectedDiagnosticRule;
    private string _diagnosticsSummaryText;

    // Вкладка 1: Среды выполнения и PE-Доктор
    private string _targetExecutablePath = @"C:\Windows\System32\notepad.exe";
    private string _peDiagnosisHeadline = "Выберите .exe программы или нажмите «Проверить все программы» — сканер найдёт конфликты разрядности 0xC000007B и недостающие пакеты VC++ / DirectX / .NET.";
    private string _targetArchitectureBadge = "Готов к проверке";
    private string _runtimeCatalogHeadline = "23 официальных пакета Microsoft / OpenAL / Khronos с проверкой цифровой подписи WinVerifyTrust.";

    // Вкладка 2: Сбои программ и BSOD
    private string _bsodScanHeadline = "Нажмите «Проверить дампы и журнал», чтобы разобрать синие экраны из C:\\Windows\\Minidump и вылеты программ из Журнала событий.";

    // Вкладка 3: Справочник кодов ошибок
    private string _errorSearchQuery = "";
    private ErrorFamilyFilterOption _selectedErrorFamilyOption;
    private ErrorCodeEntry? _selectedErrorCode;
    private string _errorCatalogSummaryText = "";

    // Вкладка 4: Системные рецепты, CBS.log и переустановка поверх
    private string _cbsLogHeadline = "Нажмите «Проверить CBS.log», чтобы узнать итог последней проверки SFC / DISM.";
    private string _reinstallTitle = "";
    private string _reinstallDetails = "";
    private string _reinstallSpaceBadge = "";

    // Общая строка уведомления
    private string _lastRepairActionBanner = "";
    private string _lastRepairTechnicalLog = "";

    public RepairStudioViewModel(
        SystemRepairService repairService,
        Func<string, Task> onActionCompletedAsync)
    {
        _repairService = repairService;
        _onActionCompletedAsync = onActionCompletedAsync;

        FilteredDiagnosticRules = new ObservableCollection<DiagnosticRuleItemViewModel>();
        DependencyIssues = new ObservableCollection<PeIssueItemViewModel>();
        OfficialRuntimes = new ObservableCollection<RuntimePackageItemViewModel>();
        Minidumps = new ObservableCollection<BsodMinidumpReport>();
        CrashEvents = new ObservableCollection<CrashEventItemViewModel>();
        FilteredErrorCodes = new ObservableCollection<ErrorCodeEntry>();
        Playbooks = new ObservableCollection<RepairPlaybookItemViewModel>();

        SectionOptions = BuildSectionOptions();
        _selectedSectionOption = SectionOptions[0];

        ErrorFamilyOptions =
        [
            new(null, $"Все семейства ({ErrorCodeCatalog.Count} кодов)"),
            new(ErrorCodeFamily.WindowsUpdateAndCbs, "Центр обновления / CBS / Store"),
            new(ErrorCodeFamily.AppAndLoaderNtStatus, "Сбой программы / DLL (NTSTATUS)"),
            new(ErrorCodeFamily.SystemComDirectXHResult, "Система / Win32 / MSI / DirectX"),
            new(ErrorCodeFamily.BlueScreenBugCheck, "Синий экран (BugCheck)")
        ];
        _selectedErrorFamilyOption = ErrorFamilyOptions[0];

        // Команды навигации и действий
        SelectSubTabCommand = new RelayCommand(p =>
        {
            if (p is string s && int.TryParse(s, out var idx)) SelectedSubTabIndex = idx;
        });

        ScanSystemHealthCommand = new AsyncRelayCommand(_ => ScanDiagnosticsAsync(), _ => !IsBusy);
        FixSelectedIssuesCommand = new AsyncRelayCommand(_ => FixSelectedRulesAsync(), _ => !IsBusy);

        BrowseExecutableCommand = new RelayCommand(_ => BrowseForExecutable());
        DiagnoseExecutableCommand = new RelayCommand(_ => RunExecutableDiagnosis());
        ScanInstalledProgramsCommand = new AsyncRelayCommand(_ => ScanInstalledProgramsAsync(), _ => !IsBusy);
        RefreshRuntimeStatusesCommand = new AsyncRelayCommand(_ => RefreshRuntimeStatusesAsync(), _ => !IsBusy);
        InstallMissingBaselineRuntimesCommand = new AsyncRelayCommand(_ => InstallMissingBaselineRuntimesAsync(), _ => !IsBusy);

        ScanBsodAndCrashesCommand = new AsyncRelayCommand(_ => ScanBsodAndCrashLogsAsync(), _ => !IsBusy);
        OpenDumpFileCommand = new AsyncRelayCommand(_ => OpenAndAnalyzeDumpFileAsync(), _ => !IsBusy);

        JumpToLinkedRepairRuleCommand = new RelayCommand(_ => JumpFromErrorCodeToRepairRule());
        InstallLinkedRuntimeFromErrorCommand = new AsyncRelayCommand(_ => InstallLinkedRuntimeFromErrorAsync(), _ => !IsBusy);

        CheckCbsLogCommand = new RelayCommand(_ => RefreshCbsAndReinstallStatus());
        OpenWindowsRecoveryCommand = new RelayCommand(_ => OpenWindowsRecovery());

        // Загрузка правил диагностики (107 правил)
        var rules = _repairService.GetDiagnosticRules();
        _allDiagnosticRules = new List<DiagnosticRuleItemViewModel>(rules.Count);
        foreach (var rule in rules)
        {
            var capturedRule = rule;
            _allDiagnosticRules.Add(new DiagnosticRuleItemViewModel(
                capturedRule,
                new AsyncRelayCommand(_ => FixSingleRuleAsync(capturedRule))));
        }

        _diagnosticsSummaryText = $"В каталоге {_allDiagnosticRules.Count} правил в 16 разделах. Нажмите «Проверить систему» для полной диагностики.";
        ApplyDiagnosticFilter();

        // Загрузка каталога сред выполнения (22 пакета)
        foreach (var pkg in _repairService.GetOfficialRuntimeCatalog())
        {
            var captured = pkg;
            OfficialRuntimes.Add(new RuntimePackageItemViewModel(
                captured,
                new AsyncRelayCommand(_ => InstallRuntimePackageAsync(captured))));
        }

        // Загрузка справочника кодов ошибок
        ApplyErrorCatalogFilter();

        // Загрузка тяжёлых рецептов + готовности CBS / Recovery
        foreach (var pb in _repairService.GetAvailablePlaybooks())
        {
            var capturedPb = pb;
            Playbooks.Add(new RepairPlaybookItemViewModel(
                capturedPb,
                new AsyncRelayCommand(_ => RunPlaybookAsync(capturedPb))));
        }

        RefreshCbsAndReinstallStatus();
    }

    public IReadOnlyList<RepairSectionFilterOption> SectionOptions { get; }
    public IReadOnlyList<ErrorFamilyFilterOption> ErrorFamilyOptions { get; }

    public ObservableCollection<DiagnosticRuleItemViewModel> FilteredDiagnosticRules { get; }
    public ObservableCollection<PeIssueItemViewModel> DependencyIssues { get; }
    public ObservableCollection<RuntimePackageItemViewModel> OfficialRuntimes { get; }
    public ObservableCollection<BsodMinidumpReport> Minidumps { get; }
    public ObservableCollection<CrashEventItemViewModel> CrashEvents { get; }
    public ObservableCollection<ErrorCodeEntry> FilteredErrorCodes { get; }
    public ObservableCollection<RepairPlaybookItemViewModel> Playbooks { get; }

    public bool IsBusy
    {
        get => _isBusy;
        private set => SetProperty(ref _isBusy, value);
    }

    public int SelectedSubTabIndex
    {
        get => _selectedSubTabIndex;
        set
        {
            if (SetProperty(ref _selectedSubTabIndex, value))
            {
                OnPropertyChanged(nameof(IsDiagnosticsTab));
                OnPropertyChanged(nameof(IsPeDoctorTab));
                OnPropertyChanged(nameof(IsBsodTab));
                OnPropertyChanged(nameof(IsErrorCatalogTab));
                OnPropertyChanged(nameof(IsPlaybooksTab));
            }
        }
    }

    public bool IsDiagnosticsTab => SelectedSubTabIndex == 0;
    public bool IsPeDoctorTab => SelectedSubTabIndex == 1;
    public bool IsBsodTab => SelectedSubTabIndex == 2;
    public bool IsErrorCatalogTab => SelectedSubTabIndex == 3;
    public bool IsPlaybooksTab => SelectedSubTabIndex == 4;

    // ---- Свойства вкладки 0: Диагностика ОС ----
    public RepairSectionFilterOption SelectedSectionOption
    {
        get => _selectedSectionOption;
        set
        {
            if (SetProperty(ref _selectedSectionOption, value))
            {
                ApplyDiagnosticFilter();
            }
        }
    }

    public string DiagnosticSearchText
    {
        get => _diagnosticSearchText;
        set
        {
            if (SetProperty(ref _diagnosticSearchText, value))
            {
                ApplyDiagnosticFilter();
            }
        }
    }

    public bool OnlyIssuesFilter
    {
        get => _onlyIssuesFilter;
        set
        {
            if (SetProperty(ref _onlyIssuesFilter, value))
            {
                ApplyDiagnosticFilter();
            }
        }
    }

    public DiagnosticRuleItemViewModel? SelectedDiagnosticRule
    {
        get => _selectedDiagnosticRule;
        set
        {
            if (SetProperty(ref _selectedDiagnosticRule, value))
            {
                OnPropertyChanged(nameof(HasSelectedDiagnosticRule));
            }
        }
    }

    public bool HasSelectedDiagnosticRule => SelectedDiagnosticRule is not null;
    public string DiagnosticsSummaryText { get => _diagnosticsSummaryText; private set => SetProperty(ref _diagnosticsSummaryText, value); }

    // ---- Свойства вкладки 1: PE-Доктор и Среды выполнения ----
    public string TargetExecutablePath { get => _targetExecutablePath; set => SetProperty(ref _targetExecutablePath, value); }
    public string PeDiagnosisHeadline { get => _peDiagnosisHeadline; private set => SetProperty(ref _peDiagnosisHeadline, value); }
    public string TargetArchitectureBadge { get => _targetArchitectureBadge; private set => SetProperty(ref _targetArchitectureBadge, value); }
    public string RuntimeCatalogHeadline { get => _runtimeCatalogHeadline; private set => SetProperty(ref _runtimeCatalogHeadline, value); }

    // ---- Свойства вкладки 2: Сбои и BSOD ----
    public string BsodScanHeadline { get => _bsodScanHeadline; private set => SetProperty(ref _bsodScanHeadline, value); }

    // ---- Свойства вкладки 3: Справочник ошибок ----
    public string ErrorSearchQuery
    {
        get => _errorSearchQuery;
        set
        {
            if (SetProperty(ref _errorSearchQuery, value))
            {
                ApplyErrorCatalogFilter();
            }
        }
    }

    public ErrorFamilyFilterOption SelectedErrorFamilyOption
    {
        get => _selectedErrorFamilyOption;
        set
        {
            if (SetProperty(ref _selectedErrorFamilyOption, value))
            {
                ApplyErrorCatalogFilter();
            }
        }
    }

    public ErrorCodeEntry? SelectedErrorCode
    {
        get => _selectedErrorCode;
        set
        {
            if (SetProperty(ref _selectedErrorCode, value))
            {
                OnPropertyChanged(nameof(HasSelectedErrorCode));
                OnPropertyChanged(nameof(SelectedErrorHasRepairLink));
                OnPropertyChanged(nameof(SelectedErrorHasRuntimeLink));
            }
        }
    }

    public bool HasSelectedErrorCode => SelectedErrorCode is not null;
    public bool SelectedErrorHasRepairLink => SelectedErrorCode?.HasLinkedRepairRule == true;
    public bool SelectedErrorHasRuntimeLink => SelectedErrorCode?.HasLinkedRuntimePackage == true;
    public string ErrorCatalogSummaryText { get => _errorCatalogSummaryText; private set => SetProperty(ref _errorCatalogSummaryText, value); }

    // ---- Свойства вкладки 4: CBS.log и Восстановление ОС ----
    public string CbsLogHeadline { get => _cbsLogHeadline; private set => SetProperty(ref _cbsLogHeadline, value); }
    public string ReinstallTitle { get => _reinstallTitle; private set => SetProperty(ref _reinstallTitle, value); }
    public string ReinstallDetails { get => _reinstallDetails; private set => SetProperty(ref _reinstallDetails, value); }
    public string ReinstallSpaceBadge { get => _reinstallSpaceBadge; private set => SetProperty(ref _reinstallSpaceBadge, value); }

    // ---- Общие баннеры ----
    public string LastRepairActionBanner
    {
        get => _lastRepairActionBanner;
        private set
        {
            if (SetProperty(ref _lastRepairActionBanner, value)) OnPropertyChanged(nameof(HasRepairActionBanner));
        }
    }

    public string LastRepairTechnicalLog { get => _lastRepairTechnicalLog; private set => SetProperty(ref _lastRepairTechnicalLog, value); }

    public bool HasRepairActionBanner => !string.IsNullOrWhiteSpace(LastRepairActionBanner);
    public bool HasDependencyIssues => DependencyIssues.Count > 0;
    public bool HasMinidumps => Minidumps.Count > 0;
    public bool HasCrashEvents => CrashEvents.Count > 0;

    // ---- Команды ----
    public ICommand SelectSubTabCommand { get; }
    public ICommand ScanSystemHealthCommand { get; }
    public ICommand FixSelectedIssuesCommand { get; }
    public ICommand BrowseExecutableCommand { get; }
    public ICommand DiagnoseExecutableCommand { get; }
    public ICommand ScanInstalledProgramsCommand { get; }
    public ICommand RefreshRuntimeStatusesCommand { get; }
    public ICommand InstallMissingBaselineRuntimesCommand { get; }
    public ICommand ScanBsodAndCrashesCommand { get; }
    public ICommand OpenDumpFileCommand { get; }
    public ICommand JumpToLinkedRepairRuleCommand { get; }
    public ICommand InstallLinkedRuntimeFromErrorCommand { get; }
    public ICommand CheckCbsLogCommand { get; }
    public ICommand OpenWindowsRecoveryCommand { get; }

    public async Task ScanDiagnosticsAsync()
    {
        IsBusy = true;
        DiagnosticsSummaryText = "Идёт глубокая проверка 16 подсистем Windows (реестр, службы, сеть, оболочка, WMI, CBS.log, диск)...";
        try
        {
            var findings = await _repairService.ScanSystemHealthAsync();
            var byId = findings.ToDictionary(f => f.Rule.Id, StringComparer.OrdinalIgnoreCase);

            foreach (var item in _allDiagnosticRules)
            {
                if (byId.TryGetValue(item.Id, out var f))
                {
                    item.ApplyFinding(f);
                }
            }

            var issuesCount = findings.Count(f => f.State == RepairHealthState.IssueDetected);
            var healthyCount = findings.Count(f => f.State == RepairHealthState.Healthy);
            var naCount = findings.Count(f => f.State == RepairHealthState.NotApplicable);

            DiagnosticsSummaryText = issuesCount == 0
                ? $"Проверено правил: {findings.Count} • Отклонений: 0 • В норме: {healthyCount} (неприменимо: {naCount}). Все проверенные узлы здоровы!"
                : $"Проверено правил: {findings.Count} • Найдено отклонений: {issuesCount} • В норме: {healthyCount}. Отметьте нужные пункты и нажмите «Исправить отмеченные».";

            ApplyDiagnosticFilter();
            await _onActionCompletedAsync(DiagnosticsSummaryText);
        }
        catch (Exception ex)
        {
            DiagnosticsSummaryText = $"Ошибка диагностики: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task FixSelectedRulesAsync()
    {
        var selected = _allDiagnosticRules.Where(r => r.IsSelectedForFix).Select(r => r.Rule).ToList();
        if (selected.Count == 0)
        {
            LastRepairActionBanner = "Отметьте хотя бы одно правило галочкой в списке слева.";
            return;
        }

        var allowRisky = ConfirmRiskyRulesIfNeeded(selected);
        if (selected.Any(r => r.RequiresExplicitConfirmation) && !allowRisky)
        {
            LastRepairActionBanner = "Исправление правил с повышенным риском отменено пользователем.";
            return;
        }

        await ExecuteDiagnosticFixBatchAsync(selected.Select(r => r.Id).ToList(), allowRisky);
    }

    private async Task FixSingleRuleAsync(RepairRuleDefinition rule)
    {
        var allowRisky = ConfirmRiskyRulesIfNeeded([rule]);
        if (rule.RequiresExplicitConfirmation && !allowRisky)
        {
            return;
        }

        await ExecuteDiagnosticFixBatchAsync([rule.Id], allowRisky);
    }

    private async Task ExecuteDiagnosticFixBatchAsync(IReadOnlyList<string> ruleIds, bool allowRisky)
    {
        IsBusy = true;
        LastRepairActionBanner = $"Выполняется ремонт и повторная проверка ({ruleIds.Count} правил)...";
        try
        {
            var batch = await _repairService.FixIssuesAsync(ruleIds, allowRisky);
            LastRepairActionBanner = batch.SummaryHeadline;
            LastRepairTechnicalLog = string.Join(Environment.NewLine, batch.Outcomes.Select(o => $"{o.RuleTitle}: {o.Message}"));

            // Обновляем строки правил по результатам фазы Verify
            foreach (var outcome in batch.Outcomes)
            {
                var vm = _allDiagnosticRules.FirstOrDefault(r => string.Equals(r.Id, outcome.RuleId, StringComparison.OrdinalIgnoreCase));
                if (vm is not null)
                {
                    vm.ApplyFinding(new RepairCheckFinding(vm.Rule, outcome.PostFixState, outcome.PostFixEvidence, DateTimeOffset.UtcNow));
                }
            }

            ApplyDiagnosticFilter();
            await _onActionCompletedAsync(batch.SummaryHeadline);
        }
        catch (Exception ex)
        {
            LastRepairActionBanner = $"Ошибка пакетного ремонта: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    public void RunExecutableDiagnosis()
    {
        if (string.IsNullOrWhiteSpace(TargetExecutablePath) || !File.Exists(TargetExecutablePath))
        {
            PeDiagnosisHeadline = "Указанный .exe файл не найден. Выберите существующий файл программы или игры.";
            return;
        }

        var report = _repairService.DiagnoseExecutable(TargetExecutablePath);
        TargetArchitectureBadge = report.BinaryHeader.IsValidPeFile
            ? $"{report.BinaryHeader.ArchitectureDisplay} • Импортов: {report.TotalDirectImportsCount}"
            : "Некорректный PE-заголовок";

        PeDiagnosisHeadline = report.HeadlineVerdict;
        var exeLabel = Path.GetFileName(TargetExecutablePath);

        DependencyIssues.Clear();
        foreach (var issue in report.Issues)
        {
            var captured = issue;
            DependencyIssues.Add(new PeIssueItemViewModel(
                exeLabel,
                captured,
                new AsyncRelayCommand(_ => QuarantineConflictingDllAsync(captured)),
                new AsyncRelayCommand(_ =>
                    captured.RecommendedPackage is not null
                        ? InstallRuntimePackageAsync(captured.RecommendedPackage)
                        : Task.CompletedTask)));
        }

        OnPropertyChanged(nameof(HasDependencyIssues));
    }

    public async Task ScanInstalledProgramsAsync()
    {
        IsBusy = true;
        PeDiagnosisHeadline = "Массовая проверка основных .exe файлов всех установленных программ...";
        try
        {
            var summary = await _repairService.ScanInstalledProgramsDependenciesAsync();
            TargetArchitectureBadge = $"Проверено: {summary.ExecutablesInspected} из {summary.TotalProgramsFound}";

            DependencyIssues.Clear();
            foreach (var finding in summary.BrokenPrograms)
            {
                foreach (var issue in finding.Diagnosis.Issues)
                {
                    var captured = issue;
                    DependencyIssues.Add(new PeIssueItemViewModel(
                        finding.Program.DisplayName,
                        captured,
                        new AsyncRelayCommand(_ => QuarantineConflictingDllAsync(captured)),
                        new AsyncRelayCommand(_ =>
                            captured.RecommendedPackage is not null
                                ? InstallRuntimePackageAsync(captured.RecommendedPackage)
                                : Task.CompletedTask)));
                }
            }

            OnPropertyChanged(nameof(HasDependencyIssues));
            PeDiagnosisHeadline = summary.BrokenPrograms.Count == 0
                ? $"Проверено программ: {summary.ExecutablesInspected} ({summary.Elapsed.TotalSeconds:F1} с). Проблем 0xC000007B и недостающих сред выполнения не обнаружено!"
                : $"Проверено программ: {summary.ExecutablesInspected} • Найдено проблемных программ: {summary.BrokenPrograms.Count} (рекомендуемых пакетов: {summary.DistinctRecommendedPackages.Count}).";

            await _onActionCompletedAsync(PeDiagnosisHeadline);
        }
        catch (Exception ex)
        {
            PeDiagnosisHeadline = $"Ошибка массовой проверки программ: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task RefreshRuntimeStatusesAsync()
    {
        try
        {
            var statuses = await _repairService.GetOfficialRuntimeStatusesAsync();
            var byKey = statuses.ToDictionary(s => s.Package.PackageKey, StringComparer.OrdinalIgnoreCase);

            foreach (var vm in OfficialRuntimes)
            {
                if (byKey.TryGetValue(vm.Package.PackageKey, out var st))
                {
                    vm.UpdateStatus(st);
                }
            }

            var installedCount = statuses.Count(s => s.IsInstalled);
            RuntimeCatalogHeadline = $"Установлено в системе: {installedCount} из {statuses.Count} пакетов (прямая загрузка Microsoft + проверка подписи WinVerifyTrust).";
        }
        catch (Exception ex)
        {
            RuntimeCatalogHeadline = $"Ошибка проверки установленных пакетов: {ex.Message}";
        }
    }

    private async Task InstallMissingBaselineRuntimesAsync()
    {
        await RefreshRuntimeStatusesAsync();
        var missing = OfficialRuntimes
            .Where(r => r.Package.IsRecommendedBaseline && !r.IsInstalled)
            .Select(r => r.Package)
            .ToList();

        if (missing.Count == 0)
        {
            LastRepairActionBanner = "Все базовые рекомендуемые пакеты (VC++ x86/x64, .NET, WebView2) уже установлены.";
            return;
        }

        IsBusy = true;
        var okCount = 0;
        try
        {
            foreach (var pkg in missing)
            {
                LastRepairActionBanner = $"Скачивание, проверка WinVerifyTrust и установка: {pkg.FriendlyName}...";
                var res = await _repairService.InstallOfficialRuntimeAsync(pkg);
                if (res.Succeeded) okCount++;
            }

            await RefreshRuntimeStatusesAsync();
            LastRepairActionBanner = $"Базовый набор установлен: успешно {okCount} из {missing.Count}.";
            await _onActionCompletedAsync(LastRepairActionBanner);
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task ScanBsodAndCrashLogsAsync()
    {
        BsodScanHeadline = "Разбор дампов из C:\\Windows\\Minidump и вылетов программ из Журнала событий Windows...";
        try
        {
            var scan = await _repairService.ScanCrashHistoryDetailedAsync(maxItems: 25);
            var dumps = scan.Minidumps;
            var events = scan.CrashEvents;

            Minidumps.Clear();
            foreach (var d in dumps) Minidumps.Add(d);

            CrashEvents.Clear();
            foreach (var ev in events)
            {
                var captured = ev;
                CrashEvents.Add(new CrashEventItemViewModel(
                    captured,
                    new RelayCommand(_ => InspectCrashExecutable(captured)),
                    new RelayCommand(_ => JumpFromCrashEvent(captured))));
            }

            OnPropertyChanged(nameof(HasMinidumps));
            OnPropertyChanged(nameof(HasCrashEvents));

            var headline = dumps.Count == 0 && events.Count == 0
                ? "Дампов синих экранов и записей о критических сбоях программ не найдено."
                : $"Найдено дампов BSOD: {dumps.Count} • Сбоев программ и драйверов в журнале: {events.Count}.";

            if (scan.FolderNote is not null)
            {
                headline = $"{headline} {scan.FolderNote}";
            }

            BsodScanHeadline = headline;
            await _onActionCompletedAsync(BsodScanHeadline);
        }
        catch (Exception ex)
        {
            BsodScanHeadline = $"Ошибка чтения журналов сбоев: {ex.Message}";
        }
    }

    public void RefreshCbsAndReinstallStatus()
    {
        var cbs = _repairService.AnalyzeCbsLog();
        CbsLogHeadline = cbs.HumanVerdict;

        var readiness = _repairService.GetInPlaceReinstallReadiness();
        ReinstallTitle = readiness.RecommendedMethodTitle;
        ReinstallDetails = readiness.StepByStepInstructions;
        ReinstallSpaceBadge = readiness.HasEnoughDiskSpace
            ? $"Свободно на C:\\: {readiness.FreeSystemDriveGb:F1} ГБ (достаточно)"
            : $"Свободно на C:\\: {readiness.FreeSystemDriveGb:F1} ГБ (нужно ≥ 20 ГБ)";
    }

    private void OpenWindowsRecovery()
    {
        var opened = _repairService.OpenWindowsRecoveryReinstall();
        LastRepairActionBanner = opened
            ? "Открыт раздел «Параметры → Система → Восстановление»."
            : "Не удалось автоматически открыть ms-settings:recovery.";
    }

    private void InspectCrashExecutable(SystemCrashEventEntry entry)
    {
        if (string.IsNullOrWhiteSpace(entry.FaultingExecutablePath)) return;
        TargetExecutablePath = entry.FaultingExecutablePath;
        SelectedSubTabIndex = 1;
        RunExecutableDiagnosis();
    }

    private void JumpFromCrashEvent(SystemCrashEventEntry entry)
    {
        if (!string.IsNullOrWhiteSpace(entry.RecommendedRepairRuleId))
        {
            FocusDiagnosticRule(entry.RecommendedRepairRuleId);
            return;
        }

        if (entry.ExceptionCode.HasValue)
        {
            ErrorSearchQuery = $"0x{entry.ExceptionCode.Value:X8}";
            SelectedSubTabIndex = 3;
        }
    }

    private void JumpFromErrorCodeToRepairRule()
    {
        var ruleId = SelectedErrorCode?.PrimaryRepairRuleId;
        if (!string.IsNullOrWhiteSpace(ruleId))
        {
            FocusDiagnosticRule(ruleId);
        }
    }

    private async Task InstallLinkedRuntimeFromErrorAsync()
    {
        var key = SelectedErrorCode?.PrimaryRuntimePackageKey;
        if (string.IsNullOrWhiteSpace(key)) return;

        var pkg = OfficialRuntimes.FirstOrDefault(p => string.Equals(p.Package.PackageKey, key, StringComparison.OrdinalIgnoreCase))?.Package;
        if (pkg is not null)
        {
            await InstallRuntimePackageAsync(pkg);
        }
    }

    private void FocusDiagnosticRule(string ruleId)
    {
        _selectedSectionOption = SectionOptions[0];
        _onlyIssuesFilter = false;
        _diagnosticSearchText = "";
        OnPropertyChanged(nameof(SelectedSectionOption));
        OnPropertyChanged(nameof(OnlyIssuesFilter));
        OnPropertyChanged(nameof(DiagnosticSearchText));
        ApplyDiagnosticFilter();

        var match = FilteredDiagnosticRules.FirstOrDefault(r => string.Equals(r.Id, ruleId, StringComparison.OrdinalIgnoreCase));
        if (match is not null)
        {
            SelectedDiagnosticRule = match;
        }

        SelectedSubTabIndex = 0;
    }

    private void ApplyDiagnosticFilter()
    {
        var sec = _selectedSectionOption?.Section;
        var q = _diagnosticSearchText?.Trim() ?? "";

        var matches = _allDiagnosticRules.Where(item =>
        {
            if (sec.HasValue && item.Rule.Section != sec.Value) return false;
            if (_onlyIssuesFilter && !item.HasIssue) return false;
            if (q.Length > 0)
            {
                return item.Title.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                       item.Symptom.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                       item.Id.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                       item.ErrorCodesDisplay.Contains(q, StringComparison.OrdinalIgnoreCase);
            }

            return true;
        }).ToList();

        FilteredDiagnosticRules.Clear();
        foreach (var m in matches)
        {
            FilteredDiagnosticRules.Add(m);
        }

        if (SelectedDiagnosticRule is null || !FilteredDiagnosticRules.Contains(SelectedDiagnosticRule))
        {
            SelectedDiagnosticRule = FilteredDiagnosticRules.FirstOrDefault();
        }
    }

    private void ApplyErrorCatalogFilter()
    {
        var results = _repairService.SearchErrorCodes(_errorSearchQuery, _selectedErrorFamilyOption?.Family, maxResults: 200);
        FilteredErrorCodes.Clear();
        foreach (var e in results)
        {
            FilteredErrorCodes.Add(e);
        }

        SelectedErrorCode = FilteredErrorCodes.FirstOrDefault();
        ErrorCatalogSummaryText = $"Показано кодов: {FilteredErrorCodes.Count} (поддерживается поиск по 0x8007..., знаковым числам -2147..., кодам MSI и словам симптома).";
    }

    private static List<RepairSectionFilterOption> BuildSectionOptions()
    {
        var list = new List<RepairSectionFilterOption>
        {
            new(null, "Все разделы")
        };
        foreach (var sec in Enum.GetValues<RepairSectionId>())
        {
            list.Add(new(sec, RepairSectionDisplay.GetTitle(sec)));
        }

        return list;
    }

    private static bool ConfirmRiskyRulesIfNeeded(IReadOnlyList<RepairRuleDefinition> rules)
    {
        var risky = rules.Where(r => r.RequiresExplicitConfirmation).ToList();
        if (risky.Count == 0) return false;

        var names = string.Join("\n• ", risky.Select(r => $"{r.Title} ({r.RiskBadge})"));
        var answer = MessageBox.Show(
            $"Следующие правила помечены повышенным уровнем внимания:\n\n• {names}\n\nПродолжить исправление с сохранением точки отката в «Машине времени»?",
            "Подтверждение ремонта",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        return answer == MessageBoxResult.Yes;
    }

    private async Task OpenAndAnalyzeDumpFileAsync()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Выберите файл дампа синего экрана (.dmp)",
            Filter = "Файлы дампов (*.dmp)|*.dmp|Все файлы (*.*)|*.*",
            CheckFileExists = true
        };

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        try
        {
            var report = await _repairService.AnalyzeDumpFileAsync(dialog.FileName);
            if (report is null)
            {
                BsodScanHeadline = $"Файл «{Path.GetFileName(dialog.FileName)}» не является дампом ядра Windows или дампом программы.";
                return;
            }

            Minidumps.Insert(0, report);
            OnPropertyChanged(nameof(HasMinidumps));
            BsodScanHeadline = $"{report.BugCheckName} ({report.BugCheckHex}) • {report.CulpritBadge}. {report.SimpleHumanExplanation}";
        }
        catch (Exception ex)
        {
            BsodScanHeadline = $"Не удалось прочитать файл дампа: {ex.Message}";
        }
    }

    private void BrowseForExecutable()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Выберите проблемный .exe файл игры или программы",
            Filter = "Приложения Windows (*.exe)|*.exe|Библиотеки DLL (*.dll)|*.dll|Все файлы (*.*)|*.*",
            CheckFileExists = true
        };

        if (dialog.ShowDialog() == true)
        {
            TargetExecutablePath = dialog.FileName;
            RunExecutableDiagnosis();
        }
    }

    private async Task QuarantineConflictingDllAsync(PeDependencyIssue issue)
    {
        if (string.IsNullOrWhiteSpace(issue.ResolvedFilePath))
        {
            return;
        }

        var result = await _repairService.QuarantineConflictingLocalDllAsync(issue.ResolvedFilePath);
        LastRepairActionBanner = result.UserFriendlySummary;
        LastRepairTechnicalLog = result.TechnicalLogOutput;
        RunExecutableDiagnosis();
        await _onActionCompletedAsync(result.UserFriendlySummary);
    }

    private async Task InstallRuntimePackageAsync(OfficialRuntimePackage package)
    {
        LastRepairActionBanner = $"Скачивание, проверка цифровой подписи WinVerifyTrust и установка «{package.FriendlyName}»...";
        var result = await _repairService.InstallOfficialRuntimeAsync(package);
        LastRepairActionBanner = result.UserFriendlySummary;
        LastRepairTechnicalLog = result.TechnicalLogOutput;
        await RefreshRuntimeStatusesAsync();
        await _onActionCompletedAsync(result.UserFriendlySummary);
    }

    private async Task RunPlaybookAsync(RepairPlaybookDescriptor descriptor)
    {
        LastRepairActionBanner = $"Выполняется рецепт «{descriptor.FriendlyTitle}»...";
        var result = await _repairService.ExecutePlaybookAsync(descriptor.Id);
        LastRepairActionBanner = result.UserFriendlySummary;
        LastRepairTechnicalLog = result.TechnicalLogOutput;
        RefreshCbsAndReinstallStatus();
        await _onActionCompletedAsync(result.UserFriendlySummary);
    }
}
