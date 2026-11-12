using System.Collections.ObjectModel;
using System.IO;
using System.Windows.Input;
using UltimateWindows.App.Infrastructure;
using UltimateWindows.Core.Models;
using UltimateWindows.Modules.Hardware.Analysis;
using UltimateWindows.Modules.Hardware.Models;
using UltimateWindows.Modules.Hardware.Services;

namespace UltimateWindows.App.ViewModels;

public sealed class AdvisoryItemViewModel : ObservableObject
{
    public AdvisoryItemViewModel(HardwareAdvisoryFinding finding, ICommand autoFixCommand)
    {
        Finding = finding;
        AutoFixCommand = autoFixCommand;
    }

    public HardwareAdvisoryFinding Finding { get; }
    public string SimpleTitle => Finding.SimpleTitle;
    public string SimpleExplanation => Finding.SimpleExplanation;
    public string ExpertTelemetryDetails => Finding.ExpertTelemetryDetails;
    public string ImpactBadge => Finding.EstimatedImpactBadge;
    public bool CanAutoFix => Finding.CanAutoFixInOneClick;
    public string AutoFixLabel => Finding.AutoFixActionLabel ?? "Исправить в 1 клик";
    public ICommand AutoFixCommand { get; }
}

public sealed class PowerPlanItemViewModel : ObservableObject
{
    public PowerPlanItemViewModel(PowerPlanInfo plan, ICommand activateCommand)
    {
        Plan = plan;
        ActivateCommand = activateCommand;
    }

    public PowerPlanInfo Plan { get; }
    public Guid SchemeGuid => Plan.SchemeGuid;
    public string FriendlyName => Plan.FriendlyName;
    public bool IsActive => Plan.IsActive;
    public bool CanActivate => !Plan.IsActive;
    public string StateBadge => Plan.IsActive ? "Активна" : (Plan.IsHighOrUltimatePerformance ? "Турбо" : "Стандарт");
    public ICommand ActivateCommand { get; }
}

public sealed class SensorRowViewModel
{
    public SensorRowViewModel(HardwareSensorReading reading)
    {
        Reading = reading;
    }

    public HardwareSensorReading Reading { get; }
    public string HardwareGroup => Reading.HardwareGroup;
    public string SensorName => Reading.SensorName;
    public string CategoryLabel => Reading.CategoryBadge;
    public string FormattedCurrent => Reading.FormattedCurrent;
    public string FormattedMin => Reading.FormattedMin;
    public string FormattedMax => Reading.FormattedMax;
}

public sealed class HardwareStudioViewModel : ObservableObject
{
    private readonly HardwareStudioService _hardwareService;
    private readonly Func<string, Task> _onActionCompletedAsync;
    private readonly List<SensorRowViewModel> _allSensors = new();
    private CancellationTokenSource? _stressCts;
    private CancellationTokenSource? _benchCts;

    private HardwareSnapshot? _lastSnapshot;
    private HardwareAuditSummary? _lastAudit;
    private HardwareSensorInventory? _lastSensors;
    private HardwareBenchmarkSuiteReport? _lastBenchSuite;
    private CpuBenchmarkResult? _lastCpuBench;
    private GpuBenchmarkResult? _lastGpuBench;
    private MemoryBenchmarkResult? _lastRamBench;
    private StorageBenchmarkResult? _lastDiskBench;

    private int _selectedSubTabIndex;
    private int _hardwareScore = 100;
    private string _shortMachineSpecLine = "Определение конфигурации ПК...";
    private string _cpuSummary = "Сканирование процессора...";
    private string _cpuExpert = "";
    private string _boardSummary = "Сканирование платы и BIOS...";
    private string _boardExpert = "";
    private string _memorySummary = "Сканирование оперативной памяти...";
    private string _memoryExpert = "";
    private string _gpuSummary = "Сканирование видеокарты...";
    private string _gpuExpert = "";
    private string _storageSummary = "Чтение S.M.A.R.T. накопителей...";
    private string _storageExpert = "";
    private string _displaySummary = "Проверка мониторов и Гц...";
    private string _displayExpert = "";
    private string _reportStatusText = "";

    // Вкладка 1: Датчики, Схемы питания и Вентиляторы
    private string _sensorBackendHeadline = "Опрос сквозных датчиков оборудования...";
    private string _sensorSearchText = "";
    private string _powerAndFanStatusText = "Переключение схемы питания сохраняет точку отката в Хранилище.";

    // Вкладка 2: Лёгкие бенчмарки + Стресс-тест
    private bool _isBenchmarkRunning;
    private string _benchmarkBannerText = "Лёгкие быстрые тесты (1–2 сек на узел, приоритет Ниже среднего — интерфейс не зависает).";
    private string _cpuBenchHeadline = "Ожидание запуска";
    private string _cpuBenchDetails = "1 поток (отзывчивость) + все потоки SIMD (многозадачность)";
    private string _gpuBenchHeadline = "Ожидание запуска";
    private string _gpuBenchDetails = "Direct3D 11 Compute Shader (FP32 FMA + скорость памяти)";
    private string _ramBenchHeadline = "Ожидание запуска";
    private string _ramBenchDetails = "Пропускная способность ОЗУ (ГБ/с) и задержка (нс)";
    private string _diskBenchHeadline = "Ожидание запуска";
    private string _diskBenchDetails = "Щадящий экспресс-буфер 32 МБ: линейная скорость и 4K IOPS";

    private int _stressDurationSeconds = 10;
    private int _thermalCutoffCelsius = 90;
    private bool _isStressRunning;
    private string _stressStatusText = "Готов к проверке стабильности CPU/ОЗУ с контролем эталонных сумм и защитой от перегрева.";
    private string _stressThroughputText = "—";
    private string _stressIntegrityBadge = "Ошибок: 0";

    public HardwareStudioViewModel(
        HardwareStudioService hardwareService,
        Func<string, Task> onActionCompletedAsync)
    {
        _hardwareService = hardwareService;
        _onActionCompletedAsync = onActionCompletedAsync;

        Advisories = new ObservableCollection<AdvisoryItemViewModel>();
        Drives = new ObservableCollection<StorageDriveSmartInfo>();
        RamSticks = new ObservableCollection<MemoryModuleSlotInfo>();
        Monitors = new ObservableCollection<DisplayMonitorInfo>();
        FilteredSensors = new ObservableCollection<SensorRowViewModel>();
        PowerPlans = new ObservableCollection<PowerPlanItemViewModel>();

        SelectSubTabCommand = new RelayCommand(p =>
        {
            if (p is string s && int.TryParse(s, out var idx)) SelectedSubTabIndex = idx;
        });
        RefreshHardwareCommand = new AsyncRelayCommand(_ => RefreshAuditAsync());
        RefreshSensorsCommand = new AsyncRelayCommand(_ => RefreshSensorsAndPowerAsync());
        UnlockUltimatePlanCommand = new AsyncRelayCommand(_ => UnlockUltimatePowerPlanAsync());
        ApplyFanPresetCommand = new AsyncRelayCommand(p =>
        {
            if (p is string raw && Enum.TryParse<FanCoolingPreset>(raw, ignoreCase: true, out var preset))
                return ApplyFanPresetInternalAsync(preset);
            return Task.CompletedTask;
        });

        ExportHtmlReportCommand = new AsyncRelayCommand(_ => ExportReportInternalAsync(HardwareReportFormat.Html));
        ExportJsonReportCommand = new AsyncRelayCommand(_ => ExportReportInternalAsync(HardwareReportFormat.Json));
        ExportTxtReportCommand = new AsyncRelayCommand(_ => ExportReportInternalAsync(HardwareReportFormat.Txt));

        RunFullQuickBenchCommand = new AsyncRelayCommand(_ => RunFullQuickBenchmarkAsync());
        RunCpuBenchCommand = new AsyncRelayCommand(_ => RunCpuBenchmarkOnlyAsync());
        RunGpuBenchCommand = new AsyncRelayCommand(_ => RunGpuBenchmarkOnlyAsync());
        RunRamBenchCommand = new AsyncRelayCommand(_ => RunRamBenchmarkOnlyAsync());
        RunDiskBenchCommand = new AsyncRelayCommand(_ => RunDiskBenchmarkOnlyAsync());
        CancelBenchmarkCommand = new RelayCommand(_ => _benchCts?.Cancel());

        StartStressTestCommand = new AsyncRelayCommand(_ => StartStressTestAsync());
        StopStressTestCommand = new RelayCommand(_ => StopStressTest());
    }

    public ObservableCollection<AdvisoryItemViewModel> Advisories { get; }
    public ObservableCollection<StorageDriveSmartInfo> Drives { get; }
    public ObservableCollection<MemoryModuleSlotInfo> RamSticks { get; }
    public ObservableCollection<DisplayMonitorInfo> Monitors { get; }
    public ObservableCollection<SensorRowViewModel> FilteredSensors { get; }
    public ObservableCollection<PowerPlanItemViewModel> PowerPlans { get; }

    public int SelectedSubTabIndex
    {
        get => _selectedSubTabIndex;
        set
        {
            if (SetProperty(ref _selectedSubTabIndex, value))
            {
                OnPropertyChanged(nameof(IsSpecsTab));
                OnPropertyChanged(nameof(IsSensorsPowerTab));
                OnPropertyChanged(nameof(IsBenchAndStressTab));
                OnPropertyChanged(nameof(IsDriversTab));
                OnPropertyChanged(nameof(IsCatalogTab));
                OnPropertyChanged(nameof(IsStoreRescueTab));
                OnPropertyChanged(nameof(IsVulnerableTab));
            }
        }
    }

    public bool IsSpecsTab => SelectedSubTabIndex == 0;
    public bool IsSensorsPowerTab => SelectedSubTabIndex == 1;
    public bool IsBenchAndStressTab => SelectedSubTabIndex == 2;
    public bool IsDriversTab => SelectedSubTabIndex == 3;
    public bool IsCatalogTab => SelectedSubTabIndex == 4;
    public bool IsStoreRescueTab => SelectedSubTabIndex == 5;
    public bool IsVulnerableTab => SelectedSubTabIndex == 6;

    public bool HasNoAdvisories => Advisories.Count == 0;
    public int HardwareScore { get => _hardwareScore; private set => SetProperty(ref _hardwareScore, value); }
    public string ShortMachineSpecLine { get => _shortMachineSpecLine; private set => SetProperty(ref _shortMachineSpecLine, value); }

    public string CpuSummary { get => _cpuSummary; private set => SetProperty(ref _cpuSummary, value); }
    public string CpuExpert { get => _cpuExpert; private set => SetProperty(ref _cpuExpert, value); }
    public string BoardSummary { get => _boardSummary; private set => SetProperty(ref _boardSummary, value); }
    public string BoardExpert { get => _boardExpert; private set => SetProperty(ref _boardExpert, value); }
    public string MemorySummary { get => _memorySummary; private set => SetProperty(ref _memorySummary, value); }
    public string MemoryExpert { get => _memoryExpert; private set => SetProperty(ref _memoryExpert, value); }
    public string GpuSummary { get => _gpuSummary; private set => SetProperty(ref _gpuSummary, value); }
    public string GpuExpert { get => _gpuExpert; private set => SetProperty(ref _gpuExpert, value); }
    public string StorageSummary { get => _storageSummary; private set => SetProperty(ref _storageSummary, value); }
    public string StorageExpert { get => _storageExpert; private set => SetProperty(ref _storageExpert, value); }
    public string DisplaySummary { get => _displaySummary; private set => SetProperty(ref _displaySummary, value); }
    public string DisplayExpert { get => _displayExpert; private set => SetProperty(ref _displayExpert, value); }
    public string ReportStatusText { get => _reportStatusText; private set => SetProperty(ref _reportStatusText, value); }

    public string SensorBackendHeadline { get => _sensorBackendHeadline; private set => SetProperty(ref _sensorBackendHeadline, value); }
    public string PowerAndFanStatusText { get => _powerAndFanStatusText; private set => SetProperty(ref _powerAndFanStatusText, value); }

    public string SensorSearchText
    {
        get => _sensorSearchText;
        set
        {
            if (SetProperty(ref _sensorSearchText, value))
            {
                RebuildFilteredSensors();
            }
        }
    }

    public bool IsBenchmarkRunning
    {
        get => _isBenchmarkRunning;
        private set
        {
            if (SetProperty(ref _isBenchmarkRunning, value))
            {
                OnPropertyChanged(nameof(CanStartBenchmark));
            }
        }
    }

    public bool CanStartBenchmark => !IsBenchmarkRunning;
    public string BenchmarkBannerText { get => _benchmarkBannerText; private set => SetProperty(ref _benchmarkBannerText, value); }
    public string CpuBenchHeadline { get => _cpuBenchHeadline; private set => SetProperty(ref _cpuBenchHeadline, value); }
    public string CpuBenchDetails { get => _cpuBenchDetails; private set => SetProperty(ref _cpuBenchDetails, value); }
    public string GpuBenchHeadline { get => _gpuBenchHeadline; private set => SetProperty(ref _gpuBenchHeadline, value); }
    public string GpuBenchDetails { get => _gpuBenchDetails; private set => SetProperty(ref _gpuBenchDetails, value); }
    public string RamBenchHeadline { get => _ramBenchHeadline; private set => SetProperty(ref _ramBenchHeadline, value); }
    public string RamBenchDetails { get => _ramBenchDetails; private set => SetProperty(ref _ramBenchDetails, value); }
    public string DiskBenchHeadline { get => _diskBenchHeadline; private set => SetProperty(ref _diskBenchHeadline, value); }
    public string DiskBenchDetails { get => _diskBenchDetails; private set => SetProperty(ref _diskBenchDetails, value); }

    public int StressDurationSeconds { get => _stressDurationSeconds; set => SetProperty(ref _stressDurationSeconds, Math.Clamp(value, 5, 120)); }
    public int ThermalCutoffCelsius { get => _thermalCutoffCelsius; set => SetProperty(ref _thermalCutoffCelsius, Math.Clamp(value, 75, 95)); }

    public bool IsStressRunning
    {
        get => _isStressRunning;
        private set
        {
            if (SetProperty(ref _isStressRunning, value)) OnPropertyChanged(nameof(CanStartStress));
        }
    }

    public bool CanStartStress => !IsStressRunning;
    public string StressStatusText { get => _stressStatusText; private set => SetProperty(ref _stressStatusText, value); }
    public string StressThroughputText { get => _stressThroughputText; private set => SetProperty(ref _stressThroughputText, value); }
    public string StressIntegrityBadge { get => _stressIntegrityBadge; private set => SetProperty(ref _stressIntegrityBadge, value); }

    public ICommand SelectSubTabCommand { get; }
    public ICommand RefreshHardwareCommand { get; }
    public ICommand RefreshSensorsCommand { get; }
    public ICommand UnlockUltimatePlanCommand { get; }
    public ICommand ApplyFanPresetCommand { get; }
    public ICommand ExportHtmlReportCommand { get; }
    public ICommand ExportJsonReportCommand { get; }
    public ICommand ExportTxtReportCommand { get; }
    public ICommand RunFullQuickBenchCommand { get; }
    public ICommand RunCpuBenchCommand { get; }
    public ICommand RunGpuBenchCommand { get; }
    public ICommand RunRamBenchCommand { get; }
    public ICommand RunDiskBenchCommand { get; }
    public ICommand CancelBenchmarkCommand { get; }
    public ICommand StartStressTestCommand { get; }
    public ICommand StopStressTestCommand { get; }

    public async Task RefreshAuditAsync()
    {
        var (snap, audit) = await _hardwareService.CaptureAndAnalyzeAsync();
        _lastSnapshot = snap;
        _lastAudit = audit;
        HardwareScore = audit.HardwareHealthScore;

        var coreTopology = snap.Cpu.EfficientCores > 0
            ? $"{snap.Cpu.PhysicalCores} ядер ({snap.Cpu.PerformanceCores}P+{snap.Cpu.EfficientCores}E) / {snap.Cpu.LogicalProcessors} потоков"
            : $"{snap.Cpu.PhysicalCores} ядер / {snap.Cpu.LogicalProcessors} потоков";
        var mhzVal = snap.Cpu.CurrentClockMhz > 0 ? snap.Cpu.CurrentClockMhz : snap.Cpu.BaseClockMhz;
        var mhzPart = mhzVal > 0 ? $" • {mhzVal} МГц" : "";
        var cpuTempPart = snap.Cpu.PackageTemperatureC.HasValue ? $" • {snap.Cpu.PackageTemperatureC.Value:F0}°C" : "";
        CpuSummary = $"{snap.Cpu.BrandName}\n{coreTopology}{mhzPart}{cpuTempPart}";

        var pwrVolt = $"{(snap.Cpu.PackagePowerWatts.HasValue ? $"Pkg={snap.Cpu.PackagePowerWatts.Value:F1}W, " : "")}" +
                      $"{(snap.Cpu.CoreVoltageVolts.HasValue ? $"Vcore={snap.Cpu.CoreVoltageVolts.Value:F3}V, " : "")}";
        CpuExpert = $"{pwrVolt}Vendor={snap.Cpu.Vendor}, F/M={snap.Cpu.Family}/{snap.Cpu.Model}, L3={ByteFormatter.Format(snap.Cpu.L3CacheBytes)}, ISA=[{string.Join(", ", snap.Cpu.InstructionSets)}]";

        BoardSummary = $"{snap.Motherboard.BoardManufacturer} {snap.Motherboard.BoardProduct}\nBIOS: {snap.Motherboard.BiosVersion} ({snap.Motherboard.BiosReleaseDate}) • Схема: {snap.ActivePowerPlan.FriendlyName}";
        BoardExpert = $"SMBIOS v{snap.Motherboard.SmbiosMajorVersion}.{snap.Motherboard.SmbiosMinorVersion}, BiosVendor={snap.Motherboard.BiosVendor}";

        var chanLabel = snap.Memory.IsDualOrMultiChannelActive
            ? "Двухканальный режим"
            : (snap.Memory.PopulatedSlotsCount >= 2 ? "Одноканальный режим (!)" : "Одноканальный режим");
        var speedPart = snap.Memory.ConfiguredSpeedMtPerSec > 0 ? $" @ {snap.Memory.ConfiguredSpeedMtPerSec} МТ/с" : "";
        MemorySummary = $"{snap.Memory.FormattedTotal} {snap.Memory.MemoryGeneration}{speedPart} (свободно {ByteFormatter.Format(snap.Memory.AvailablePhysicalBytes)})\nСлотов: {snap.Memory.PopulatedSlotsCount} из {Math.Max(snap.Memory.TotalSlotsCount, snap.Memory.PopulatedSlotsCount)} • {chanLabel}";
        MemoryExpert = snap.Memory.Modules.Count > 0
            ? string.Join(" | ", snap.Memory.Modules.Where(m => m.IsPopulated).Select(m =>
                $"{m.DeviceLocator}: {m.FormattedCapacity} @ {m.ConfiguredSpeedMtPerSec} MT/s [{m.ProfileAndSpecBadge}] ({m.Manufacturer} {m.PartNumber})"))
            : $"Available={ByteFormatter.Format(snap.Memory.AvailablePhysicalBytes)}";

        RamSticks.Clear();
        foreach (var m in snap.Memory.Modules.Where(x => x.IsPopulated)) RamSticks.Add(m);

        if (snap.Gpus.Count > 0)
        {
            var g = snap.Gpus[0];
            var tempPart = g.CoreTemperatureC.HasValue ? $" • {g.CoreTemperatureC.Value:F0}°C" : "";
            var pwrPart = g.PowerDrawWatts.HasValue ? $" • {g.PowerDrawWatts.Value:F0} Вт" : "";
            GpuSummary = $"{g.Name} ({g.FormattedVram}){tempPart}{pwrPart}\nДрайвер: {g.DriverVersion}";
            GpuExpert = string.Join(" || ", snap.Gpus.Select(x =>
                $"{x.Name}: PCIe Gen{x.CurrentPcieGen?.ToString() ?? "?"} x{x.CurrentPcieLanes?.ToString() ?? "?"}, ReBAR={(x.IsResizableBarEnabled.HasValue ? (x.IsResizableBarEnabled.Value ? "ON" : "OFF") : "N/A")}{(x.HotspotTemperatureC.HasValue ? $", HotSpot={x.HotspotTemperatureC.Value:F0}°C" : "")}{(x.FanSpeedRpm.HasValue ? $", Fan={x.FanSpeedRpm.Value}RPM" : "")}"));
        }
        else
        {
            GpuSummary = "Базовый графический адаптер";
            GpuExpert = "Расширенная телеметрия GPU недоступна.";
        }

        Drives.Clear();
        foreach (var d in snap.Drives) Drives.Add(d);

        if (snap.Drives.Count > 0)
        {
            StorageSummary = string.Join("\n", snap.Drives.Select(d =>
            {
                var life = d.RemainingLifePercent.HasValue ? $", ресурс {d.RemainingLifePercent}%" : "";
                var temp = d.TemperatureC.HasValue ? $", {d.TemperatureC}°C" : "";
                var state = d.IsHealthy ? "Исправен" : "ТРЕВОГА S.M.A.R.T.!";
                return $"{d.Model} ({d.FormattedCapacity}, {d.BusKind}) — {state}{life}{temp}";
            }));
            StorageExpert = string.Join(" || ", snap.Drives.Select(d =>
                $"Disk#{d.DriveIndex} FW={d.FirmwareRevision} TBW={d.TotalBytesWrittenTb?.ToString("F2") ?? "-"}TB POH={d.PowerOnHours?.ToString() ?? "-"}h"));
        }
        else
        {
            StorageSummary = "Системный накопитель работает штатно";
            StorageExpert = "Запустите от имени Администратора для прямого опроса NVMe S.M.A.R.T.";
        }

        Monitors.Clear();
        foreach (var m in snap.Monitors) Monitors.Add(m);

        if (snap.Monitors.Count > 0)
        {
            DisplaySummary = string.Join("\n", snap.Monitors.Select(m =>
            {
                var diag = m.DiagonalInches.HasValue ? $" ({m.DiagonalInches:F1}\")" : "";
                return $"{m.FriendlyModelName}{diag}: {m.NativeWidthPx}×{m.NativeHeightPx} @ {m.CurrentRefreshHz} Гц (макс. {m.MaxSupportedRefreshHz} Гц)";
            }));
            DisplayExpert = string.Join(" || ", snap.Monitors.Select(m => $"{m.GdiDeviceName} Mfg={m.ManufacturerCode}"));
        }
        else
        {
            DisplaySummary = "Стандартный дисплей";
            DisplayExpert = "EDID не обнаружен.";
        }

        var gpuShort = snap.Gpus.Count > 0 ? $" • {snap.Gpus[0].Name}" : "";
        ShortMachineSpecLine = $"{snap.Cpu.BrandName.Trim()} ({snap.Cpu.PhysicalCores}C/{snap.Cpu.LogicalProcessors}T) • {snap.Memory.FormattedTotal} ОЗУ{gpuShort}";

        Advisories.Clear();
        foreach (var finding in audit.Findings)
        {
            Advisories.Add(new AdvisoryItemViewModel(
                finding,
                new AsyncRelayCommand(_ => ApplyFindingFixAsync(finding))));
        }

        OnPropertyChanged(nameof(HasNoAdvisories));

        await RefreshSensorsAndPowerAsync();
    }

    public async Task RefreshSensorsAndPowerAsync()
    {
        var inv = await _hardwareService.QuerySensorsAsync();
        _lastSensors = inv;
        SensorBackendHeadline = inv.BackendHeadline;

        _allSensors.Clear();
        foreach (var s in inv.Readings)
        {
            _allSensors.Add(new SensorRowViewModel(s));
        }

        RebuildFilteredSensors();

        var plans = await _hardwareService.GetPowerPlansAsync();
        PowerPlans.Clear();
        foreach (var plan in plans)
        {
            var captured = plan;
            PowerPlans.Add(new PowerPlanItemViewModel(
                captured,
                new AsyncRelayCommand(_ => SwitchPowerPlanInternalAsync(captured))));
        }
    }

    private void RebuildFilteredSensors()
    {
        FilteredSensors.Clear();
        var q = _sensorSearchText?.Trim() ?? "";
        foreach (var row in _allSensors)
        {
            if (q.Length == 0 ||
                row.HardwareGroup.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                row.SensorName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                row.CategoryLabel.Contains(q, StringComparison.OrdinalIgnoreCase))
            {
                FilteredSensors.Add(row);
            }
        }
    }

    private async Task SwitchPowerPlanInternalAsync(PowerPlanInfo targetPlan)
    {
        var (_, msg) = await _hardwareService.SwitchPowerPlanAsync(targetPlan.SchemeGuid, targetPlan.FriendlyName);
        PowerAndFanStatusText = msg;
        await RefreshAuditAsync();
        await _onActionCompletedAsync(msg);
    }

    private async Task UnlockUltimatePowerPlanAsync()
    {
        var (ok, schemeGuid, msg) = await _hardwareService.UnlockUltimatePerformancePlanAsync();
        if (ok && schemeGuid.HasValue)
        {
            var (swOk, swMsg) = await _hardwareService.SwitchPowerPlanAsync(schemeGuid.Value, "Максимальная производительность");
            if (swOk) msg = swMsg;
        }

        PowerAndFanStatusText = msg;
        await RefreshAuditAsync();
        await _onActionCompletedAsync(msg);
    }

    private async Task ApplyFanPresetInternalAsync(FanCoolingPreset preset)
    {
        var (_, _, msg) = await _hardwareService.ApplyFanCoolingPresetAsync(preset);
        PowerAndFanStatusText = msg;
        await RefreshSensorsAndPowerAsync();
        await _onActionCompletedAsync(msg);
    }

    public async Task<string> ExportReportInternalAsync(HardwareReportFormat format)
    {
        if (_lastSnapshot is null || _lastAudit is null)
        {
            await RefreshAuditAsync();
        }

        var ext = format switch
        {
            HardwareReportFormat.Html => "html",
            HardwareReportFormat.Json => "json",
            _ => "txt"
        };

        var docsDir = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        if (string.IsNullOrWhiteSpace(docsDir))
        {
            docsDir = Path.GetTempPath();
        }

        var reportsDir = Path.Combine(docsDir, "UltimateWindows", "Reports");
        Directory.CreateDirectory(reportsDir);

        var fileName = $"HardwareReport-{DateTime.Now:yyyyMMdd-HHmmss}.{ext}";
        var fullPath = Path.Combine(reportsDir, fileName);

        var savedPath = await _hardwareService.ExportHardwareReportAsync(
            fullPath,
            format,
            _lastSnapshot,
            _lastAudit,
            _lastSensors,
            _lastBenchSuite);

        var msg = $"Отчёт о железе ({ext.ToUpperInvariant()}) сохранён: {savedPath}";
        ReportStatusText = msg;
        await _onActionCompletedAsync(msg);
        return savedPath;
    }

    public async Task RunFullQuickBenchmarkAsync()
    {
        if (IsBenchmarkRunning) return;

        _benchCts = new CancellationTokenSource();
        IsBenchmarkRunning = true;

        var progress = new Progress<string>(step => BenchmarkBannerText = step);
        try
        {
            var suite = await _hardwareService.RunFullQuickBenchmarkSuiteAsync(progress, _benchCts.Token);
            _lastBenchSuite = suite;
            if (suite.Cpu is not null) ApplyCpuBench(suite.Cpu);
            if (suite.Gpu is not null) ApplyGpuBench(suite.Gpu);
            if (suite.Memory is not null) ApplyRamBench(suite.Memory);
            if (suite.Storage is not null) ApplyDiskBench(suite.Storage);

            BenchmarkBannerText = $"Экспресс-бенчмарк завершён за {suite.TotalDuration.TotalSeconds:F1} сек: Индекс {suite.CompositeScore:N0} балл. ({suite.OverallTierBadge}).";
            await _onActionCompletedAsync(BenchmarkBannerText);
        }
        catch (OperationCanceledException)
        {
            BenchmarkBannerText = "Бенчмарк остановлен пользователем.";
        }
        finally
        {
            _benchCts?.Dispose();
            _benchCts = null;
            IsBenchmarkRunning = false;
        }
    }

    public async Task RunCpuBenchmarkOnlyAsync()
    {
        if (IsBenchmarkRunning) return;
        _benchCts = new CancellationTokenSource();
        IsBenchmarkRunning = true;
        BenchmarkBannerText = "Выполняется лёгкий тест CPU (1 поток + все потоки SIMD)...";
        try
        {
            var res = await _hardwareService.RunCpuBenchmarkAsync(_benchCts.Token);
            ApplyCpuBench(res);
            RebuildPartialSuite();
            BenchmarkBannerText = $"Тест CPU: 1T = {res.SingleCoreScore:N0} балл. | MT = {res.MultiCoreScore:N0} балл. ({res.MultiCoreSimdGflops:F1} ГФЛОПС).";
        }
        catch (OperationCanceledException) { BenchmarkBannerText = "Тест CPU отменён."; }
        finally { _benchCts?.Dispose(); _benchCts = null; IsBenchmarkRunning = false; }
    }

    public async Task RunGpuBenchmarkOnlyAsync()
    {
        if (IsBenchmarkRunning) return;
        _benchCts = new CancellationTokenSource();
        IsBenchmarkRunning = true;
        BenchmarkBannerText = "Выполняется лёгкий вычислительный тест GPU DirectCompute (cs_5_0)...";
        try
        {
            var res = await _hardwareService.RunGpuBenchmarkAsync(_benchCts.Token);
            ApplyGpuBench(res);
            RebuildPartialSuite();
            BenchmarkBannerText = $"Тест GPU ({res.AdapterName}): {res.ShaderAluGflops:F1} ГФЛОПС • {res.VramBandwidthGbPerSec:F1} ГБ/с ({res.ComputeScore:N0} балл.).";
        }
        catch (OperationCanceledException) { BenchmarkBannerText = "Тест GPU отменён."; }
        finally { _benchCts?.Dispose(); _benchCts = null; IsBenchmarkRunning = false; }
    }

    public async Task RunRamBenchmarkOnlyAsync()
    {
        if (IsBenchmarkRunning) return;
        _benchCts = new CancellationTokenSource();
        IsBenchmarkRunning = true;
        BenchmarkBannerText = "Замер пропускной способности и латентности ОЗУ...";
        try
        {
            var res = await _hardwareService.RunMemoryBenchmarkAsync(_benchCts.Token);
            ApplyRamBench(res);
            RebuildPartialSuite();
            BenchmarkBannerText = $"Тест ОЗУ: {res.BandwidthGbPerSec:F1} ГБ/с, задержка {res.LatencyNanoseconds:F1} нс ({res.MemoryScore:N0} балл.).";
        }
        catch (OperationCanceledException) { BenchmarkBannerText = "Тест ОЗУ отменён."; }
        finally { _benchCts?.Dispose(); _benchCts = null; IsBenchmarkRunning = false; }
    }

    public async Task RunDiskBenchmarkOnlyAsync()
    {
        if (IsBenchmarkRunning) return;
        _benchCts = new CancellationTokenSource();
        IsBenchmarkRunning = true;
        BenchmarkBannerText = "Щадящий экспресс-замер скорости накопителя (буфер 32 МБ)...";
        try
        {
            var res = await _hardwareService.RunStorageBenchmarkAsync(ct: _benchCts.Token);
            ApplyDiskBench(res);
            RebuildPartialSuite();
            BenchmarkBannerText = $"Тест диска ({res.TargetVolume}): чтение {res.SeqReadMbPerSec:F0} МБ/с, запись {res.SeqWriteMbPerSec:F0} МБ/с, 4K {res.Random4kIops:N0} IOPS.";
        }
        catch (OperationCanceledException) { BenchmarkBannerText = "Тест диска отменён."; }
        finally { _benchCts?.Dispose(); _benchCts = null; IsBenchmarkRunning = false; }
    }

    private void ApplyCpuBench(CpuBenchmarkResult r)
    {
        _lastCpuBench = r;
        CpuBenchHeadline = $"1T: {r.SingleCoreScore:N0} pts • MT: {r.MultiCoreScore:N0} pts";
        CpuBenchDetails = $"Ускорение ×{r.MultiThreadScaling:F2} ({r.LogicalThreadsUsed} пот.) • {r.MultiCoreSimdGflops:F1} ГФЛОПС";
    }

    private void ApplyGpuBench(GpuBenchmarkResult r)
    {
        _lastGpuBench = r;
        GpuBenchHeadline = $"{r.ShaderAluGflops:F1} ГФЛОПС • {r.ComputeScore:N0} pts";
        GpuBenchDetails = $"{r.AdapterName} • VRAM {r.VramBandwidthGbPerSec:F1} ГБ/с ({r.BackendName})";
    }

    private void ApplyRamBench(MemoryBenchmarkResult r)
    {
        _lastRamBench = r;
        RamBenchHeadline = $"{r.BandwidthGbPerSec:F1} ГБ/с • {r.LatencyNanoseconds:F1} нс";
        RamBenchDetails = $"{r.TierBadge} • Индекс памяти: {r.MemoryScore:N0} pts";
    }

    private void ApplyDiskBench(StorageBenchmarkResult r)
    {
        _lastDiskBench = r;
        DiskBenchHeadline = $"Чт: {r.SeqReadMbPerSec:F0} МБ/с • Зап: {r.SeqWriteMbPerSec:F0} МБ/с";
        DiskBenchDetails = $"Том {r.TargetVolume} • Случайное 4K: {r.Random4kIops:N0} IOPS ({r.StorageScore:N0} pts)";
    }

    private void RebuildPartialSuite()
    {
        if (_lastCpuBench is not null && _lastGpuBench is not null && _lastRamBench is not null && _lastDiskBench is not null)
        {
            int composite = (int)Math.Round(
                _lastCpuBench.MultiCoreScore * 0.35 +
                _lastCpuBench.SingleCoreScore * 0.15 +
                _lastGpuBench.ComputeScore * 0.25 +
                _lastRamBench.MemoryScore * 0.15 +
                _lastDiskBench.StorageScore * 0.10);

            _lastBenchSuite = new HardwareBenchmarkSuiteReport(
                CompletedAtUtc: DateTimeOffset.UtcNow,
                CompositeScore: composite,
                OverallTierBadge: _lastCpuBench.TierBadge,
                Cpu: _lastCpuBench,
                Gpu: _lastGpuBench,
                Memory: _lastRamBench,
                Storage: _lastDiskBench,
                TotalDuration: _lastCpuBench.Duration + _lastGpuBench.Duration + _lastRamBench.Duration + _lastDiskBench.Duration);
        }
    }

    private async Task ApplyFindingFixAsync(HardwareAdvisoryFinding finding)
    {
        var (_, message) = await _hardwareService.ApplyAdvisoryAutoFixAsync(finding);
        await RefreshAuditAsync();
        await _onActionCompletedAsync(message);
    }

    private async Task StartStressTestAsync()
    {
        if (IsStressRunning) return;

        _stressCts = new CancellationTokenSource();
        IsStressRunning = true;

        var progress = new Progress<StressTestProgress>(p =>
        {
            StressStatusText = p.StatusMessage;
            StressThroughputText = $"{p.MillionsOpsPerSecond:F1} млн опер./сек";
            StressIntegrityBadge = $"Ошибок: {p.IntegrityErrorCount}";
        });

        try
        {
            var final = await _hardwareService.RunThermalSafeStressTestAsync(
                TimeSpan.FromSeconds(StressDurationSeconds),
                maxSafeCpuTempC: ThermalCutoffCelsius,
                maxSafeGpuTempC: Math.Min(ThermalCutoffCelsius, 88),
                progress: progress,
                ct: _stressCts.Token);

            StressStatusText = final.StatusMessage;
            StressThroughputText = $"{final.MillionsOpsPerSecond:F1} млн опер./сек";
            StressIntegrityBadge = $"Ошибок: {final.IntegrityErrorCount}";
            await _onActionCompletedAsync(final.StatusMessage);
        }
        catch (OperationCanceledException)
        {
            StressStatusText = "Стресс-тест остановлен пользователем.";
        }
        finally
        {
            _stressCts?.Dispose();
            _stressCts = null;
            IsStressRunning = false;
        }
    }

    private void StopStressTest() => _stressCts?.Cancel();
}
