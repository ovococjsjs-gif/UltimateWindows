using System.Collections.ObjectModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Input;
using Microsoft.Win32;
using UltimateWindows.App.Infrastructure;
using UltimateWindows.Core.Contracts;
using UltimateWindows.Core.Elevation;
using UltimateWindows.Core.Enums;
using UltimateWindows.Core.Guards;
using UltimateWindows.Core.Models;
using UltimateWindows.Modules.Cleaner.Services;
using UltimateWindows.Modules.Apps.Services;
using UltimateWindows.Modules.Drivers.Orchestration;
using UltimateWindows.Modules.Drivers.Services;
using UltimateWindows.Modules.Hardware.Services;
using UltimateWindows.Modules.Optimizer.Services;
using UltimateWindows.Modules.Repair.Services;
using UltimateWindows.Modules.Safety.Services;
using UltimateWindows.Modules.Security.Services;
using UltimateWindows.NativeInterop.Cleaner;
using UltimateWindows.NativeInterop.Apps;
using UltimateWindows.NativeInterop.Drivers;
using UltimateWindows.NativeInterop.Hardware;
using UltimateWindows.NativeInterop.Optimizer;
using UltimateWindows.NativeInterop.Repair;
using UltimateWindows.NativeInterop.Restore;
using UltimateWindows.NativeInterop.Security;
using UltimateWindows.NativeInterop.SecurityHunter;

namespace UltimateWindows.App.ViewModels;

public sealed class TransactionItemViewModel : ObservableObject
{
    public TransactionItemViewModel(
        TransactionRecord record,
        ICommand rollbackCommand,
        ICommand togglePinCommand)
    {
        Record = record;
        RollbackCommand = rollbackCommand;
        TogglePinCommand = togglePinCommand;
    }

    public TransactionRecord Record { get; }
    public Guid SessionId => Record.SessionId;
    public string FriendlyTitle => Record.FriendlyTitle;
    public string FriendlySummary => Record.FriendlySummary;
    public string TechnicalDetails => Record.TechnicalDetails;
    public string CreatedDisplay => Record.CreatedDisplayLocal;
    public string StoredSizeText => Record.FormattedStoredSize;
    public bool IsPinned => Record.IsPinned;
    public bool CanRollback => Record.RollbackUnavailableReason is null;
    public string StatusBadge => Record.RollbackUnavailableReason ?? (Record.IsPinned ? "Закреплено" : "В журнале");
    public string PinButtonText => Record.IsPinned ? "Открепить" : "Закрепить";

    public ICommand RollbackCommand { get; }
    public ICommand TogglePinCommand { get; }
}

public sealed class SmartAuditActionItemViewModel : ObservableObject
{
    public SmartAuditActionItemViewModel(SmartAuditActionItem item, ICommand jumpCommand)
    {
        Item = item;
        JumpCommand = jumpCommand;
    }

    public SmartAuditActionItem Item { get; }
    public string SimpleTitle => Item.SimpleTitle;
    public string SimpleRecommendation => Item.SimpleRecommendation;
    public string DomainBadge => Item.DomainBadge;
    public ICommand JumpCommand { get; }
}

public sealed class MainViewModel : ObservableObject
{
    private readonly IVaultService _vaultService;
    private readonly SmartSystemAuditOrchestrator _smartAuditOrchestrator;

    private SystemDomain _selectedDomain = SystemDomain.HealthOverview;
    private bool _isExpertMode;
    private CancellationTokenSource? _auditCts;
    private readonly HashSet<SystemDomain> _initialized = [];
    private string _auditStamp = "Нет результата";
    private string _auditDetails = "";
    private string _smartAuditTitle = "Проверка ещё не запускалась";
    private string _smartAuditSubheadline = "Соберите локальную сводку о диске, устройствах, сбоях и защите. Проверка не применяет исправления.";
    private string _statusNotification = "Готово к работе";
    private string _vaultUsageText = "0 КБ";
    private double _vaultUsagePercent;
    private int _activeCheckpointsCount;
    private int _maxBudgetMb = 250;
    private int _retentionDays = 14;
    private string _testPathInput = @"C:\Users\User\AppData\Local\Google\Chrome\User Data\Default\Login Data";
    private string _testPathVerdict = "СТРОГО ЗАЩИЩЕНО: база сохраненных паролей браузера никогда не удаляется.";

    private string _systemDriveUsageHeadline = "Данные о системном томе недоступны";
    private double _systemDriveUsedPercent;
    private bool _isSystemDriveCriticallyFull;

    public MainViewModel()
        : this(new ZeroBloatVaultService(stateApplier: new WindowsSystemStateApplier()))
    {
    }

    public MainViewModel(IVaultService vaultService)
    {
        _vaultService = vaultService;
        IsAdmin = ElevationChecker.IsRunningAsAdministrator();
        OsDisplayHeader = BuildOsDisplayHeader();

        MaxBudgetMb = (int)(_vaultService.CurrentPolicy.MaxVaultBytes / VaultQuotaPolicy.Megabyte);
        RetentionDays = _vaultService.CurrentPolicy.FileBlobRetentionDays;

        Transactions = new ObservableCollection<TransactionItemViewModel>();
        SmartAuditActions = new ObservableCollection<SmartAuditActionItemViewModel>();

        NavigateCommand = new RelayCommand(param =>
        {
            if (param is string domainName && Enum.TryParse<SystemDomain>(domainName, out var parsed))
            {
                SelectedDomain = parsed;
            }
        });

        RunOneClickSmartAuditCommand = new AsyncRelayCommand(_ => RunOneClickSmartAuditAsync());
        CancelAuditCommand = new RelayCommand(_ => _auditCts?.Cancel());
        OpenToolCommand = new RelayCommand(p => { if (p is ToolDestination tool) OpenTool(tool); });
        RestartAsAdminCommand = new RelayCommand(_ => RestartWithAdministratorRights(), _ => !IsAdmin);
        SaveQuotaPolicyCommand = new AsyncRelayCommand(_ => SaveQuotaPolicyAsync());
        PurgeBlobsCommand = new AsyncRelayCommand(_ => PurgeUnpinnedBlobsAsync());
        EvaluatePathCommand = new RelayCommand(_ => EvaluateSamplePath());
        FillSamplePathCommand = new RelayCommand(param =>
        {
            if (param is string sample)
            {
                TestPathInput = sample;
                EvaluateSamplePath();
            }
        });

        var hardwareService = new HardwareStudioService(_vaultService, new WindowsHardwarePlatformProvider());
        _hardwareStudio = new(() => new HardwareStudioViewModel(hardwareService, OnSubModuleActionAsync));

        var cleanerService = new VaultSafeCleanerService(_vaultService, new WindowsCleanerPlatformBridge());
        _cleanerStudio = new(() => new CleanerStudioViewModel(cleanerService, async msg =>
        {
            RefreshSystemDriveTelemetry();
            await OnSubModuleActionAsync(msg);
        }));

        var repairService = new SystemRepairService(_vaultService, new WindowsRepairPlatformBridge());
        _repairStudio = new(() => new RepairStudioViewModel(repairService, OnSubModuleActionAsync));

        var optimizerService = new SmartOptimizerService(_vaultService, new WindowsOptimizerPlatformBridge());
        _optimizerStudio = new(() => new OptimizerStudioViewModel(optimizerService, OnSubModuleActionAsync));

        var securityService = new AntiMinerSecurityService(_vaultService, new WindowsSecurityPlatformBridge());
        _antiMinerStudio = new(() => new AntiMinerStudioViewModel(securityService, OnSubModuleActionAsync));

        var driverService = new OfficialDriverService(_vaultService, new WindowsDriverPlatformBridge());
        _driverStudio = new(() => new DriverStudioViewModel(
            driverService,
            OnSubModuleActionAsync,
            switchToCatalogTab: () => HardwareStudio.SelectedSubTabIndex = 4));

        _smartAuditOrchestrator = new SmartSystemAuditOrchestrator(
            hardwareService, driverService, cleanerService, repairService, optimizerService, securityService);

        var appsService = new AppsAndAutomationService(
            _vaultService,
            new WindowsAppsPlatformBridge(),
            hardwareService,
            driverService,
            cleanerService,
            repairService,
            securityService,
            _smartAuditOrchestrator);
        _appsStudio = new(() => new AppsStudioViewModel(appsService, OnSubModuleActionAsync));

        // Ошибка, которую команда не обработала сама, показывается в строке состояния, а не закрывает программу
        AsyncRelayCommand.UnhandledError = ex => StatusNotification = $"Не удалось выполнить действие: {ex.Message}";

        RefreshSystemDriveTelemetry();
    }

    private async Task OnSubModuleActionAsync(string msg)
    {
        StatusNotification = msg;
        await RefreshVaultStateAsync();
    }

    private async Task InitializeSectionAsync(SystemDomain domain)
    {
        if (!_initialized.Add(domain)) return;
        try
        {
            switch (domain)
            {
                case SystemDomain.Optimizer: await OptimizerStudio.RefreshAllAsync(); break;
                case SystemDomain.SmartCleaner: CleanerStudio.ReloadVolumes(); await CleanerStudio.RefreshSystemReservesAsync(); break;
                case SystemDomain.HardwareAndDrivers: await Task.WhenAll(HardwareStudio.RefreshAuditAsync(), DriverStudio.InitializeFastAsync()); break;
                case SystemDomain.AppsAndAutomation: await AppsStudio.InitializeFastAsync(); break;
                case SystemDomain.TimeMachineVault: await RefreshVaultStateAsync(); break;
            }
        }
        catch (Exception ex)
        {
            _initialized.Remove(domain);
            StatusNotification = $"Не удалось загрузить раздел «{WorkbenchDirectory.Sections.First(s => s.Domain == domain).Title}»: {ex.Message}";
        }
    }

    public void OpenTool(ToolDestination tool)
    {
        SelectedDomain = tool.Domain;
        switch (tool.Domain)
        {
            case SystemDomain.SmartCleaner: CleanerStudio.SelectedSubTabIndex = tool.Tab; break;
            case SystemDomain.Optimizer: OptimizerStudio.SelectedSubTabIndex = tool.Tab; break;
            case SystemDomain.DllAndRepair: RepairStudio.SelectedSubTabIndex = tool.Tab; break;
            case SystemDomain.AntiMiner: AntiMinerStudio.SelectedSubTabIndex = tool.Tab; break;
            case SystemDomain.HardwareAndDrivers: HardwareStudio.SelectedSubTabIndex = tool.Tab; break;
            case SystemDomain.AppsAndAutomation: AppsStudio.SelectedSubTabIndex = tool.Tab; break;
        }
    }

    public IReadOnlyList<WorkbenchSection> Sections => WorkbenchDirectory.Sections;
    public IReadOnlyList<ToolDestination> QuickTasks { get; } = WorkbenchDirectory.Tools.Take(3).ToArray();
    public WorkbenchSection SelectedSection
    {
        get => Sections.First(s => s.Domain == SelectedDomain);
        set { if (value is not null) SelectedDomain = value.Domain; }
    }

    public bool IsAdmin { get; }

    /// <summary>
    /// Программа работает без прав администратора: диагностика доступна, большинство исправлений — нет.
    /// </summary>
    public bool IsLimitedMode => !IsAdmin;

    public string OsDisplayHeader { get; }
    public string PrivilegeBadgeText => IsAdmin ? "Администратор (полный доступ)" : "Ограниченный режим (без прав администратора)";

    private readonly Lazy<HardwareStudioViewModel> _hardwareStudio;
    public HardwareStudioViewModel HardwareStudio => _hardwareStudio.Value;
    private readonly Lazy<CleanerStudioViewModel> _cleanerStudio;
    public CleanerStudioViewModel CleanerStudio => _cleanerStudio.Value;
    private readonly Lazy<RepairStudioViewModel> _repairStudio;
    public RepairStudioViewModel RepairStudio => _repairStudio.Value;
    private readonly Lazy<OptimizerStudioViewModel> _optimizerStudio;
    public OptimizerStudioViewModel OptimizerStudio => _optimizerStudio.Value;
    private readonly Lazy<AntiMinerStudioViewModel> _antiMinerStudio;
    public AntiMinerStudioViewModel AntiMinerStudio => _antiMinerStudio.Value;
    private readonly Lazy<DriverStudioViewModel> _driverStudio;
    public DriverStudioViewModel DriverStudio => _driverStudio.Value;
    private readonly Lazy<AppsStudioViewModel> _appsStudio;
    public AppsStudioViewModel AppsStudio => _appsStudio.Value;

    public ObservableCollection<SmartAuditActionItemViewModel> SmartAuditActions { get; }
    public ObservableCollection<TransactionItemViewModel> Transactions { get; }

    public string SystemDriveUsageHeadline { get => _systemDriveUsageHeadline; private set => SetProperty(ref _systemDriveUsageHeadline, value); }
    public double SystemDriveUsedPercent { get => _systemDriveUsedPercent; private set => SetProperty(ref _systemDriveUsedPercent, value); }
    public bool IsSystemDriveCriticallyFull { get => _isSystemDriveCriticallyFull; private set => SetProperty(ref _isSystemDriveCriticallyFull, value); }

    public bool IsRunningSmartAudit => _auditCts is not null;
    public string AuditStamp { get => _auditStamp; private set => SetProperty(ref _auditStamp, value); }
    public string AuditDetails { get => _auditDetails; private set => SetProperty(ref _auditDetails, value); }
    public string SmartAuditTitle { get => _smartAuditTitle; private set => SetProperty(ref _smartAuditTitle, value); }
    public string SmartAuditSubheadline { get => _smartAuditSubheadline; private set => SetProperty(ref _smartAuditSubheadline, value); }
    public bool HasSmartAuditActions => SmartAuditActions.Count > 0;

    public SystemDomain SelectedDomain
    {
        get => _selectedDomain;
        set
        {
            if (SetProperty(ref _selectedDomain, value))
            {
                OnPropertyChanged(nameof(SelectedSection));
                _ = InitializeSectionAsync(value);
            }
        }
    }

    public bool IsExpertMode { get => _isExpertMode; set => SetProperty(ref _isExpertMode, value); }

    public string StatusNotification { get => _statusNotification; set => SetProperty(ref _statusNotification, value); }
    public string VaultUsageText { get => _vaultUsageText; private set => SetProperty(ref _vaultUsageText, value); }
    public double VaultUsagePercent { get => _vaultUsagePercent; private set => SetProperty(ref _vaultUsagePercent, value); }
    public int ActiveCheckpointsCount { get => _activeCheckpointsCount; private set => SetProperty(ref _activeCheckpointsCount, value); }

    public int MaxBudgetMb { get => _maxBudgetMb; set => SetProperty(ref _maxBudgetMb, Math.Clamp(value, 32, 2048)); }
    public int RetentionDays { get => _retentionDays; set => SetProperty(ref _retentionDays, Math.Clamp(value, 1, 90)); }
    public string TestPathInput { get => _testPathInput; set => SetProperty(ref _testPathInput, value); }
    public string TestPathVerdict { get => _testPathVerdict; private set => SetProperty(ref _testPathVerdict, value); }

    public ICommand NavigateCommand { get; }
    public ICommand OpenToolCommand { get; }
    public ICommand CancelAuditCommand { get; }
    public ICommand RunOneClickSmartAuditCommand { get; }
    public ICommand RestartAsAdminCommand { get; }
    public ICommand SaveQuotaPolicyCommand { get; }
    public ICommand PurgeBlobsCommand { get; }
    public ICommand EvaluatePathCommand { get; }
    public ICommand FillSamplePathCommand { get; }

    public void RefreshSystemDriveTelemetry()
    {
        try
        {
            var sysRoot = Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\";
            var di = new DriveInfo(sysRoot);
            if (di.IsReady && di.TotalSize > 0)
            {
                var used = di.TotalSize - di.AvailableFreeSpace;
                var pct = Math.Round((double)used / di.TotalSize * 100.0, 1);
                SystemDriveUsedPercent = pct;
                IsSystemDriveCriticallyFull = pct >= 90.0;
                SystemDriveUsageHeadline =
                    $"Диск {sysRoot.TrimEnd('\\')} — свободно {ByteFormatter.Format(di.AvailableFreeSpace)} из {ByteFormatter.Format(di.TotalSize)} ({pct:F1}% занято)";
            }
        }
        catch
        {
            SystemDriveUsageHeadline = "Данные о системном томе недоступны";
            IsSystemDriveCriticallyFull = false;
            SystemDriveUsedPercent = 0;
        }
    }

    public async Task RefreshVaultStateAsync()
    {
        var stats = await _vaultService.GetStorageStatsAsync();
        VaultUsageText = stats.FormattedUsage;
        VaultUsagePercent = stats.UsagePercentage;
        ActiveCheckpointsCount = stats.ActiveTransactionCount;

        var history = await _vaultService.GetHistoryAsync(60);
        Transactions.Clear();
        foreach (var rec in history)
        {
            Transactions.Add(new TransactionItemViewModel(
                rec,
                new AsyncRelayCommand(_ => RollbackAsync(rec.SessionId)),
                new AsyncRelayCommand(_ => TogglePinAsync(rec.SessionId, !rec.IsPinned))));
        }
    }

    private async Task RunOneClickSmartAuditAsync()
    {
        if (_auditCts is not null) return;
        using var cts = new CancellationTokenSource();
        _auditCts = cts;
        OnPropertyChanged(nameof(IsRunningSmartAudit));
        SmartAuditActions.Clear();
        OnPropertyChanged(nameof(HasSmartAuditActions));
        SmartAuditTitle = "Идёт проверка компьютера";
        SmartAuditSubheadline = "Собираем показатели шести разделов. Можно продолжать работу или остановить проверку.";
        AuditStamp = "В процессе";
        AuditDetails = "";
        try
        {
            var summary = await Task.Run(() => _smartAuditOrchestrator.RunOneClickAuditAsync(false, false, cts.Token));
            cts.Token.ThrowIfCancellationRequested();
            AuditStamp = $"Проверено {summary.CompletedAtUtc.ToLocalTime():dd.MM · HH:mm}";
            SmartAuditTitle = "Результаты проверки готовы";
            SmartAuditSubheadline = $"Рекомендаций в сводке: {summary.TopActionItems.Count}. Оценка объёма очистки: {summary.FormattedReclaimableSpace}. Изменения не вносились.";
            AuditDetails = $"Расчётный индекс: {summary.CompositeHealthScore}/100 · защита {summary.SecurityScore} · оборудование {summary.HardwareScore} · драйверы {summary.DriversScore} · стабильность {summary.StabilityRepairScore}.";
            foreach (var act in summary.TopActionItems)
            {
                var capturedDomain = act.TargetDomain;
                SmartAuditActions.Add(new SmartAuditActionItemViewModel(
                    act,
                    new RelayCommand(_ => SelectedDomain = capturedDomain)));
            }

            OnPropertyChanged(nameof(HasSmartAuditActions));
            StatusNotification = summary.ExecutiveHeadline;
        }
        catch (OperationCanceledException) when (cts.IsCancellationRequested)
        {
            AuditStamp = "Остановлено";
            SmartAuditTitle = "Проверка остановлена";
            SmartAuditSubheadline = "Полный результат не получен. Можно запустить проверку снова.";
        }
        catch (Exception ex)
        {
            AuditStamp = "Нет результата";
            SmartAuditTitle = "Не удалось завершить проверку";
            SmartAuditSubheadline = ex.Message;
        }
        finally
        {
            _auditCts = null;
            OnPropertyChanged(nameof(IsRunningSmartAudit));
        }
    }

    private void RestartWithAdministratorRights()
    {
        var currentArguments = Environment.GetCommandLineArgs().Skip(1);
        var relaunchArguments = ElevationStartupPolicy.BuildRelaunchArguments(currentArguments);

        var result = ProcessElevation.TryRelaunchElevated(relaunchArguments, out var error);
        switch (result)
        {
            case ElevationRequestResult.RelaunchStarted:
                System.Windows.Application.Current?.Shutdown();
                break;

            case ElevationRequestResult.DeclinedByUser:
                StatusNotification = "Запрос прав администратора отклонён. Программа продолжает работать в ограниченном режиме.";
                break;

            case ElevationRequestResult.AlreadyElevated:
                StatusNotification = "Программа уже работает с правами администратора.";
                break;

            default:
                StatusNotification = $"Не удалось перезапустить программу с правами администратора: {error}";
                break;
        }
    }

    private async Task RollbackAsync(Guid sessionId)
    {
        try
        {
            await Task.Run(() => _vaultService.RollbackTransactionAsync(sessionId));
            StatusNotification = "Изменения отменены — параметры возвращены в прежнее состояние.";
        }
        catch (Exception ex)
        {
            // Запись остаётся неотменённой: откат можно повторить, например с правами администратора
            StatusNotification = $"Отменить изменения удалось не полностью: {ex.Message}";
        }

        if (_optimizerStudio.IsValueCreated) await OptimizerStudio.RefreshAfterRollbackAsync();
        await RefreshVaultStateAsync();
    }

    private async Task TogglePinAsync(Guid sessionId, bool pin)
    {
        await _vaultService.SetPinnedAsync(sessionId, pin);
        StatusNotification = pin
            ? "Точка отката закреплена."
            : "Закрепление снято.";
        await RefreshVaultStateAsync();
    }

    private async Task SaveQuotaPolicyAsync()
    {
        var updated = _vaultService.CurrentPolicy with
        {
            MaxVaultBytes = MaxBudgetMb * VaultQuotaPolicy.Megabyte,
            FileBlobRetentionDays = RetentionDays
        };

        await _vaultService.UpdatePolicyAsync(updated);
        StatusNotification = $"Квота хранилища: не более {MaxBudgetMb} МБ, автоочистка карантина через {RetentionDays} дн.";
        await RefreshVaultStateAsync();
    }

    private async Task PurgeUnpinnedBlobsAsync()
    {
        if (!UserPrompts.Confirm(new("Удалить незакреплённые архивы?", "Файлы в этих копиях нельзя будет восстановить. Журнал и закреплённые копии останутся.", true))) return;
        var removed = await _vaultService.PurgeAllUnpinnedBlobsAsync();
        StatusNotification = $"Очищено архивов карантина: {removed}.";
        await RefreshVaultStateAsync();
    }

    private void EvaluateSamplePath()
    {
        var decision = BrowserVaultGuard.EvaluatePath(TestPathInput);
        TestPathVerdict = decision switch
        {
            VaultPathDecision.ProtectedCredentialsOrAutofill =>
                "СТРОГО ЗАЩИЩЕНО: база паролей, ключей шифрования или автозаполнения форм. Удаление заблокировано.",
            VaultPathDecision.ProtectedSessionOrExtension =>
                "ЗАЩИЩЕНО: активные сессии входа, вкладки или хранилище расширений.",
            VaultPathDecision.SafeDisposableCache =>
                "БЕЗОПАСНЫЙ КЭШ: временные файлы кэша — очищаются без потери паролей.",
            _ =>
                "НЕЙТРАЛЬНЫЙ ПУТЬ: не затрагивается автоматической очисткой."
        };
    }

    private static string BuildOsDisplayHeader()
    {
        var arch = RuntimeInformation.OSArchitecture.ToString().ToUpperInvariant();

        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", writable: false);
                var prod = key?.GetValue("ProductName")?.ToString() ?? "Windows";
                var dispVer = key?.GetValue("DisplayVersion")?.ToString() ?? "";
                var buildStr = key?.GetValue("CurrentBuildNumber")?.ToString() ?? "";
                if (int.TryParse(buildStr, out var buildNum) && buildNum >= 22000 && prod.Contains("Windows 10"))
                {
                    prod = prod.Replace("Windows 10", "Windows 11");
                }

                var verPart = !string.IsNullOrWhiteSpace(dispVer) ? $" ({dispVer})" : "";
                return $"{prod}{verPart} · сборка {buildStr} · {arch}";
            }
            catch
            {
                // Fallback
            }
        }

        return $"{RuntimeInformation.OSDescription} · {arch}";
    }
}
