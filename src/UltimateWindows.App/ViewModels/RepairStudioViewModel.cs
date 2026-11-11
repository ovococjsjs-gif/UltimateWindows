using System.Collections.ObjectModel;
using System.IO;
using System.Windows.Input;
using Microsoft.Win32;
using UltimateWindows.App.Infrastructure;
using UltimateWindows.Modules.Repair.Models;
using UltimateWindows.Modules.Repair.Services;

namespace UltimateWindows.App.ViewModels;

public sealed class PeIssueItemViewModel : ObservableObject
{
    public PeIssueItemViewModel(
        PeDependencyIssue issue,
        ICommand quarantineCommand,
        ICommand installPackageCommand)
    {
        Issue = issue;
        QuarantineCommand = quarantineCommand;
        InstallPackageCommand = installPackageCommand;
    }

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
    public RuntimePackageItemViewModel(OfficialRuntimePackage package, ICommand installCommand)
    {
        Package = package;
        InstallCommand = installCommand;
    }

    public OfficialRuntimePackage Package { get; }
    public string FriendlyName => Package.FriendlyName;
    public string PublisherName => Package.PublisherName;
    public string ArchitectureBadge => Package.ArchitectureBadge;
    public string WingetPackageId => Package.WingetPackageId;
    public ICommand InstallCommand { get; }
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

    private int _selectedSubTabIndex;
    private string _targetExecutablePath = @"C:\Windows\System32\notepad.exe";
    private string _peDiagnosisHeadline = "Выберите проблемный .exe файл игры или программы — Доктор проверит разрядность всех импортируемых DLL (0xC000007B) и подберет официальный пакет Microsoft.";
    private string _targetArchitectureBadge = "Готов к анализу";
    private string _bsodScanHeadline = "Нажмите «Проверить синие экраны и сбои», чтобы расшифровать минидампы C:\\Windows\\Minidump и журнал событий.";
    private string _lastRepairActionBanner = "";
    private string _lastRepairTechnicalLog = "";

    public RepairStudioViewModel(
        SystemRepairService repairService,
        Func<string, Task> onActionCompletedAsync)
    {
        _repairService = repairService;
        _onActionCompletedAsync = onActionCompletedAsync;

        DependencyIssues = new ObservableCollection<PeIssueItemViewModel>();
        OfficialRuntimes = new ObservableCollection<RuntimePackageItemViewModel>();
        Minidumps = new ObservableCollection<BsodMinidumpReport>();
        CrashEvents = new ObservableCollection<SystemCrashEventEntry>();
        Playbooks = new ObservableCollection<RepairPlaybookItemViewModel>();

        SelectSubTabCommand = new RelayCommand(p =>
        {
            if (p is string s && int.TryParse(s, out var idx)) SelectedSubTabIndex = idx;
        });
        BrowseExecutableCommand = new RelayCommand(_ => BrowseForExecutable());
        DiagnoseExecutableCommand = new RelayCommand(_ => RunExecutableDiagnosis());
        ScanBsodAndCrashesCommand = new AsyncRelayCommand(_ => ScanBsodAndCrashLogsAsync());

        foreach (var pkg in _repairService.GetOfficialRuntimeCatalog())
        {
            var captured = pkg;
            OfficialRuntimes.Add(new RuntimePackageItemViewModel(
                captured,
                new AsyncRelayCommand(_ => InstallRuntimePackageAsync(captured))));
        }

        foreach (var pb in _repairService.GetAvailablePlaybooks())
        {
            var capturedPb = pb;
            Playbooks.Add(new RepairPlaybookItemViewModel(
                capturedPb,
                new AsyncRelayCommand(_ => RunPlaybookAsync(capturedPb))));
        }
    }

    public ObservableCollection<PeIssueItemViewModel> DependencyIssues { get; }
    public ObservableCollection<RuntimePackageItemViewModel> OfficialRuntimes { get; }
    public ObservableCollection<BsodMinidumpReport> Minidumps { get; }
    public ObservableCollection<SystemCrashEventEntry> CrashEvents { get; }
    public ObservableCollection<RepairPlaybookItemViewModel> Playbooks { get; }

    public int SelectedSubTabIndex
    {
        get => _selectedSubTabIndex;
        set
        {
            if (SetProperty(ref _selectedSubTabIndex, value))
            {
                OnPropertyChanged(nameof(IsPlaybooksTab));
                OnPropertyChanged(nameof(IsPeDoctorTab));
                OnPropertyChanged(nameof(IsBsodTab));
            }
        }
    }

    public bool IsPlaybooksTab => SelectedSubTabIndex == 0;
    public bool IsPeDoctorTab => SelectedSubTabIndex == 1;
    public bool IsBsodTab => SelectedSubTabIndex == 2;

    public string TargetExecutablePath { get => _targetExecutablePath; set => SetProperty(ref _targetExecutablePath, value); }
    public string PeDiagnosisHeadline { get => _peDiagnosisHeadline; private set => SetProperty(ref _peDiagnosisHeadline, value); }
    public string TargetArchitectureBadge { get => _targetArchitectureBadge; private set => SetProperty(ref _targetArchitectureBadge, value); }
    public string BsodScanHeadline { get => _bsodScanHeadline; private set => SetProperty(ref _bsodScanHeadline, value); }

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

    public ICommand SelectSubTabCommand { get; }
    public ICommand BrowseExecutableCommand { get; }
    public ICommand DiagnoseExecutableCommand { get; }
    public ICommand ScanBsodAndCrashesCommand { get; }

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

        DependencyIssues.Clear();
        foreach (var issue in report.Issues)
        {
            var captured = issue;
            DependencyIssues.Add(new PeIssueItemViewModel(
                captured,
                new AsyncRelayCommand(_ => QuarantineConflictingDllAsync(captured)),
                new AsyncRelayCommand(_ =>
                    captured.RecommendedPackage is not null
                        ? InstallRuntimePackageAsync(captured.RecommendedPackage)
                        : Task.CompletedTask)));
        }

        OnPropertyChanged(nameof(HasDependencyIssues));
    }

    public async Task ScanBsodAndCrashLogsAsync()
    {
        BsodScanHeadline = "Анализ системных минидампов C:\\Windows\\Minidump и критических событий Windows...";
        try
        {
            var (dumps, events) = await _repairService.ScanBsodAndCrashHistoryAsync(maxItems: 20);

            Minidumps.Clear();
            foreach (var d in dumps) Minidumps.Add(d);

            CrashEvents.Clear();
            foreach (var ev in events) CrashEvents.Add(ev);

            OnPropertyChanged(nameof(HasMinidumps));
            OnPropertyChanged(nameof(HasCrashEvents));

            BsodScanHeadline = dumps.Count == 0 && events.Count == 0
                ? "Синих экранов (BSOD) и критических падений программ за последнее время не обнаружено."
                : $"Найдено минидампов BSOD: {dumps.Count} • Записей сбоев в журнале: {events.Count}.";

            await _onActionCompletedAsync(BsodScanHeadline);
        }
        catch (Exception ex)
        {
            BsodScanHeadline = $"Ошибка чтения журналов сбоев: {ex.Message}";
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
        if (string.IsNullOrWhiteSpace(issue.ResolvedFilePath)) return;

        var res = await _repairService.QuarantineConflictingLocalDllAsync(issue.ResolvedFilePath);
        LastRepairActionBanner = res.UserFriendlySummary;
        LastRepairTechnicalLog = res.TechnicalLogOutput;

        if (res.Succeeded) RunExecutableDiagnosis();
        await _onActionCompletedAsync(res.UserFriendlySummary);
    }

    private async Task InstallRuntimePackageAsync(OfficialRuntimePackage package)
    {
        LastRepairActionBanner = $"Установка официального пакета «{package.FriendlyName}» через winget...";
        LastRepairTechnicalLog = $"winget install --exact --id {package.WingetPackageId}";

        var res = await _repairService.InstallOfficialRuntimeAsync(package);
        LastRepairActionBanner = res.UserFriendlySummary;
        LastRepairTechnicalLog = res.TechnicalLogOutput;

        await _onActionCompletedAsync(res.UserFriendlySummary);
    }

    private async Task RunPlaybookAsync(RepairPlaybookDescriptor playbook)
    {
        LastRepairActionBanner = $"Выполняется рецепт ремонта «{playbook.FriendlyTitle}»...";
        LastRepairTechnicalLog = playbook.ExpertCommandsPreview;

        var res = await _repairService.ExecutePlaybookAsync(playbook.Id);
        LastRepairActionBanner = res.UserFriendlySummary;
        LastRepairTechnicalLog = res.TechnicalLogOutput;

        await _onActionCompletedAsync(res.UserFriendlySummary);
    }
}
