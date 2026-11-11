using System.Collections.ObjectModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Input;
using Microsoft.Win32;
using UltimateWindows.App.Infrastructure;
using UltimateWindows.Core.Contracts;
using UltimateWindows.Core.Enums;
using UltimateWindows.Core.Guards;
using UltimateWindows.Core.Models;
using UltimateWindows.Modules.Cleaner.Services;
using UltimateWindows.Modules.Drivers.Orchestration;
using UltimateWindows.Modules.Drivers.Services;
using UltimateWindows.Modules.Hardware.Services;
using UltimateWindows.Modules.Optimizer.Services;
using UltimateWindows.Modules.Repair.Services;
using UltimateWindows.Modules.Safety.Services;
using UltimateWindows.Modules.Security.Services;
using UltimateWindows.NativeInterop.Cleaner;
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
    public bool CanRollback => !Record.IsReverted;
    public string StatusBadge => Record.IsReverted ? "Отменено" : (Record.IsPinned ? "Закреплено" : "Активно");
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
    private bool _isRunningSmartAudit;
    private int _compositeHealthScore = 96;
    private string _smartAuditTitle = "Комплексный аудит всех подсистем ПК в 1 клик";
    private string _smartAuditSubheadline = "Проверяет диск C:\\, кэш без удаления паролей, твики, скрытые майнеры, синие экраны BSOD и драйверы WHQL.";
    private string _statusNotification = "Готово к работе";
    private string _vaultUsageText = "0 КБ";
    private double _vaultUsagePercent;
    private int _activeCheckpointsCount;
    private int _maxBudgetMb = 250;
    private int _retentionDays = 14;
    private string _testPathInput = @"C:\Users\User\AppData\Local\Google\Chrome\User Data\Default\Login Data";
    private string _testPathVerdict = "СТРОГО ЗАЩИЩЕНО: база сохраненных паролей браузера никогда не удаляется.";

    private string _systemDriveUsageHeadline = "Проверка диска C:\\...";
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
        OsDisplayHeader = BuildOsDisplayHeader(IsAdmin);

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

        JumpToDiskAnalyzerCommand = new AsyncRelayCommand(_ =>
        {
            SelectedDomain = SystemDomain.SmartCleaner;
            CleanerStudio.SelectedSubTabIndex = 0;
            return CleanerStudio.AnalyzeDiskSpaceAsync();
        });

        JumpToSpaceSaverCommand = new RelayCommand(_ =>
        {
            SelectedDomain = SystemDomain.SmartCleaner;
            CleanerStudio.SelectedSubTabIndex = 3;
        });

        RunOneClickSmartAuditCommand = new AsyncRelayCommand(_ => RunOneClickSmartAuditAsync());
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
        HardwareStudio = new HardwareStudioViewModel(hardwareService, OnSubModuleActionAsync);

        var cleanerService = new VaultSafeCleanerService(_vaultService, new WindowsCleanerPlatformBridge());
        CleanerStudio = new CleanerStudioViewModel(cleanerService, async msg =>
        {
            RefreshSystemDriveTelemetry();
            await OnSubModuleActionAsync(msg);
        });

        var repairService = new SystemRepairService(_vaultService, new WindowsRepairPlatformBridge());
        RepairStudio = new RepairStudioViewModel(repairService, OnSubModuleActionAsync);

        var optimizerService = new SmartOptimizerService(_vaultService, new WindowsOptimizerPlatformBridge());
        OptimizerStudio = new OptimizerStudioViewModel(optimizerService, OnSubModuleActionAsync);

        var securityService = new AntiMinerSecurityService(_vaultService, new WindowsSecurityPlatformBridge());
        AntiMinerStudio = new AntiMinerStudioViewModel(securityService, OnSubModuleActionAsync);

        var driverService = new OfficialDriverService(_vaultService, new WindowsDriverPlatformBridge());
        DriverStudio = new DriverStudioViewModel(driverService, OnSubModuleActionAsync);

        _smartAuditOrchestrator = new SmartSystemAuditOrchestrator(
            hardwareService, driverService, cleanerService, repairService, optimizerService, securityService);

        RefreshSystemDriveTelemetry();
        _ = InitializeAsync();
    }

    private async Task OnSubModuleActionAsync(string msg)
    {
        StatusNotification = msg;
        await RefreshVaultStateAsync();
    }

    private async Task InitializeAsync()
    {
        try
        {
            var vaultTask = RefreshVaultStateAsync();
            var hwTask = HardwareStudio.RefreshAuditAsync();
            var reservesTask = CleanerStudio.RefreshSystemReservesAsync();
            var optTask = OptimizerStudio.RefreshAllAsync();
            await Task.WhenAll(vaultTask, hwTask, reservesTask, optTask);
        }
        catch
        {
            // Ignore background warmup failures
        }
    }

    public bool IsAdmin { get; }
    public string OsDisplayHeader { get; }
    public string PrivilegeBadgeText => IsAdmin ? "Администратор (полный доступ)" : "Пользовательский режим (без UAC)";

    public HardwareStudioViewModel HardwareStudio { get; }
    public CleanerStudioViewModel CleanerStudio { get; }
    public RepairStudioViewModel RepairStudio { get; }
    public OptimizerStudioViewModel OptimizerStudio { get; }
    public AntiMinerStudioViewModel AntiMinerStudio { get; }
    public DriverStudioViewModel DriverStudio { get; }

    public ObservableCollection<SmartAuditActionItemViewModel> SmartAuditActions { get; }
    public ObservableCollection<TransactionItemViewModel> Transactions { get; }

    public string SystemDriveUsageHeadline { get => _systemDriveUsageHeadline; private set => SetProperty(ref _systemDriveUsageHeadline, value); }
    public double SystemDriveUsedPercent { get => _systemDriveUsedPercent; private set => SetProperty(ref _systemDriveUsedPercent, value); }
    public bool IsSystemDriveCriticallyFull { get => _isSystemDriveCriticallyFull; private set => SetProperty(ref _isSystemDriveCriticallyFull, value); }

    public int CompositeHealthScore { get => _compositeHealthScore; private set => SetProperty(ref _compositeHealthScore, value); }
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
                OnPropertyChanged(nameof(IsOverviewVisible));
                OnPropertyChanged(nameof(IsCleanerVisible));
                OnPropertyChanged(nameof(IsOptimizerVisible));
                OnPropertyChanged(nameof(IsAntiMinerVisible));
                OnPropertyChanged(nameof(IsRepairVisible));
                OnPropertyChanged(nameof(IsHardwareVisible));
                OnPropertyChanged(nameof(IsTimeMachineVisible));

                OnPropertyChanged(nameof(IsOverviewNav));
                OnPropertyChanged(nameof(IsCleanerNav));
                OnPropertyChanged(nameof(IsOptimizerNav));
                OnPropertyChanged(nameof(IsAntiMinerNav));
                OnPropertyChanged(nameof(IsRepairNav));
                OnPropertyChanged(nameof(IsHardwareNav));
                OnPropertyChanged(nameof(IsVaultNav));
            }
        }
    }

    public bool IsOverviewVisible => SelectedDomain == SystemDomain.HealthOverview;
    public bool IsCleanerVisible => SelectedDomain == SystemDomain.SmartCleaner;
    public bool IsOptimizerVisible => SelectedDomain == SystemDomain.Optimizer;
    public bool IsAntiMinerVisible => SelectedDomain == SystemDomain.AntiMiner;
    public bool IsRepairVisible => SelectedDomain == SystemDomain.DllAndRepair;
    public bool IsHardwareVisible => SelectedDomain == SystemDomain.HardwareAndDrivers;
    public bool IsTimeMachineVisible => SelectedDomain == SystemDomain.TimeMachineVault;

    public bool IsOverviewNav { get => IsOverviewVisible; set { if (value) SelectedDomain = SystemDomain.HealthOverview; } }
    public bool IsCleanerNav { get => IsCleanerVisible; set { if (value) SelectedDomain = SystemDomain.SmartCleaner; } }
    public bool IsOptimizerNav { get => IsOptimizerVisible; set { if (value) SelectedDomain = SystemDomain.Optimizer; } }
    public bool IsAntiMinerNav { get => IsAntiMinerVisible; set { if (value) SelectedDomain = SystemDomain.AntiMiner; } }
    public bool IsRepairNav { get => IsRepairVisible; set { if (value) SelectedDomain = SystemDomain.DllAndRepair; } }
    public bool IsHardwareNav { get => IsHardwareVisible; set { if (value) SelectedDomain = SystemDomain.HardwareAndDrivers; } }
    public bool IsVaultNav { get => IsTimeMachineVisible; set { if (value) SelectedDomain = SystemDomain.TimeMachineVault; } }

    public bool IsExpertMode
    {
        get => _isExpertMode;
        set
        {
            if (SetProperty(ref _isExpertMode, value)) OnPropertyChanged(nameof(ExperienceModeLabel));
        }
    }

    public string ExperienceModeLabel => IsExpertMode ? "Эксперт (ключи и логи)" : "Эксперт";

    public string StatusNotification { get => _statusNotification; set => SetProperty(ref _statusNotification, value); }
    public string VaultUsageText { get => _vaultUsageText; private set => SetProperty(ref _vaultUsageText, value); }
    public double VaultUsagePercent { get => _vaultUsagePercent; private set => SetProperty(ref _vaultUsagePercent, value); }
    public int ActiveCheckpointsCount { get => _activeCheckpointsCount; private set => SetProperty(ref _activeCheckpointsCount, value); }

    public int MaxBudgetMb { get => _maxBudgetMb; set => SetProperty(ref _maxBudgetMb, Math.Clamp(value, 32, 2048)); }
    public int RetentionDays { get => _retentionDays; set => SetProperty(ref _retentionDays, Math.Clamp(value, 1, 90)); }
    public string TestPathInput { get => _testPathInput; set => SetProperty(ref _testPathInput, value); }
    public string TestPathVerdict { get => _testPathVerdict; private set => SetProperty(ref _testPathVerdict, value); }

    public ICommand NavigateCommand { get; }
    public ICommand JumpToDiskAnalyzerCommand { get; }
    public ICommand JumpToSpaceSaverCommand { get; }
    public ICommand RunOneClickSmartAuditCommand { get; }
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
            SystemDriveUsageHeadline = "Системный диск C:";
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
        if (_isRunningSmartAudit) return;

        _isRunningSmartAudit = true;
        SmartAuditTitle = "Выполняется глубокий аудит 6 подсистем ПК...";
        SmartAuditSubheadline = "Анти-майнер, паспорт железа, драйверы WHQL, дампы BSOD, безопасный кэш и автозагрузка.";

        try
        {
            var summary = await _smartAuditOrchestrator.RunOneClickAuditAsync(
                includeStealthMinerDecoyProbe: false,
                queryOnlineDriverCatalog: false);

            CompositeHealthScore = summary.CompositeHealthScore;
            SmartAuditTitle = summary.ExecutiveHeadline;
            SmartAuditSubheadline =
                $"Защита: {summary.SecurityScore}/100  •  Железо: {summary.HardwareScore}/100  •  Драйверы: {summary.DriversScore}/100  •  Стабильность: {summary.StabilityRepairScore}/100  •  Мусор кэша: {summary.FormattedReclaimableSpace}";

            SmartAuditActions.Clear();
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
        catch (Exception ex)
        {
            SmartAuditTitle = "Ошибка при выполнении аудита";
            SmartAuditSubheadline = ex.Message;
        }
        finally
        {
            _isRunningSmartAudit = false;
        }
    }

    private async Task RollbackAsync(Guid sessionId)
    {
        await _vaultService.RollbackTransactionAsync(sessionId);
        OptimizerStudio.ReloadTweaksAndHosts();
        StatusNotification = "Изменения успешно отменены — параметры возвращены назад.";
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

    private static string BuildOsDisplayHeader(bool isAdmin)
    {
        var arch = RuntimeInformation.OSArchitecture.ToString().ToUpperInvariant();
        var role = isAdmin ? "Admin" : "User";

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
                return $"{prod}{verPart} • 64-bit ({arch}) • {role}";
            }
            catch
            {
                // Fallback
            }
        }

        return $"{RuntimeInformation.OSDescription} ({arch}) • {role}";
    }
}
