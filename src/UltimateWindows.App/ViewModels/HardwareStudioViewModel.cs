using System.Collections.ObjectModel;
using System.Windows.Input;
using UltimateWindows.App.Infrastructure;
using UltimateWindows.Core.Models;
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

public sealed class HardwareStudioViewModel : ObservableObject
{
    private readonly HardwareStudioService _hardwareService;
    private readonly Func<string, Task> _onActionCompletedAsync;
    private CancellationTokenSource? _stressCts;

    private int _hardwareScore = 100;
    private string _cpuSummary = "Сканирование процессора...";
    private string _cpuExpert = "";
    private string _boardSummary = "Сканирование материнской платы и BIOS...";
    private string _boardExpert = "";
    private string _memorySummary = "Сканирование оперативной памяти...";
    private string _memoryExpert = "";
    private string _gpuSummary = "Сканирование видеоподсистемы...";
    private string _gpuExpert = "";
    private string _storageSummary = "Чтение паспорта дисков и S.M.A.R.T....";
    private string _storageExpert = "";
    private string _displaySummary = "Проверка мониторов и частоты обновления...";
    private string _displayExpert = "";

    private int _stressDurationSeconds = 10;
    private int _thermalCutoffCelsius = 90;
    private bool _isStressRunning;
    private string _stressStatusText = "Готов к проверке стабильности процессора и памяти (с защитой от перегрева).";
    private string _stressThroughputText = "—";

    public HardwareStudioViewModel(
        HardwareStudioService hardwareService,
        Func<string, Task> onActionCompletedAsync)
    {
        _hardwareService = hardwareService;
        _onActionCompletedAsync = onActionCompletedAsync;

        Advisories = new ObservableCollection<AdvisoryItemViewModel>();

        RefreshHardwareCommand = new AsyncRelayCommand(_ => RefreshAuditAsync());
        StartStressTestCommand = new AsyncRelayCommand(_ => StartStressTestAsync());
        StopStressTestCommand = new RelayCommand(_ => StopStressTest());
    }

    public ObservableCollection<AdvisoryItemViewModel> Advisories { get; }

    public bool HasNoAdvisories => Advisories.Count == 0;

    public int HardwareScore
    {
        get => _hardwareScore;
        private set => SetProperty(ref _hardwareScore, value);
    }

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

    public int StressDurationSeconds
    {
        get => _stressDurationSeconds;
        set => SetProperty(ref _stressDurationSeconds, Math.Clamp(value, 5, 120));
    }

    public int ThermalCutoffCelsius
    {
        get => _thermalCutoffCelsius;
        set => SetProperty(ref _thermalCutoffCelsius, Math.Clamp(value, 75, 95));
    }

    public bool IsStressRunning
    {
        get => _isStressRunning;
        private set
        {
            if (SetProperty(ref _isStressRunning, value))
            {
                OnPropertyChanged(nameof(CanStartStress));
            }
        }
    }

    public bool CanStartStress => !IsStressRunning;

    public string StressStatusText
    {
        get => _stressStatusText;
        private set => SetProperty(ref _stressStatusText, value);
    }

    public string StressThroughputText
    {
        get => _stressThroughputText;
        private set => SetProperty(ref _stressThroughputText, value);
    }

    public ICommand RefreshHardwareCommand { get; }
    public ICommand StartStressTestCommand { get; }
    public ICommand StopStressTestCommand { get; }

    public async Task RefreshAuditAsync()
    {
        var (snap, audit) = await _hardwareService.CaptureAndAnalyzeAsync();
        HardwareScore = audit.HardwareHealthScore;

        // 1. CPU
        var coreTopology = snap.Cpu.EfficientCores > 0
            ? $"{snap.Cpu.PhysicalCores} ядер ({snap.Cpu.PerformanceCores}P + {snap.Cpu.EfficientCores}E) / {snap.Cpu.LogicalProcessors} потоков"
            : $"{snap.Cpu.PhysicalCores} ядер / {snap.Cpu.LogicalProcessors} потоков";
        var mhzPart = snap.Cpu.BaseClockMhz > 0 ? $" • {snap.Cpu.BaseClockMhz} МГц" : "";
        CpuSummary = $"{snap.Cpu.BrandName}\n{coreTopology}{mhzPart}";
        CpuExpert = $"Vendor={snap.Cpu.Vendor}, Family={snap.Cpu.Family}, Model={snap.Cpu.Model}, Stepping={snap.Cpu.Stepping}, L3={ByteFormatter.Format(snap.Cpu.L3CacheBytes)}, ISA=[{string.Join(", ", snap.Cpu.InstructionSets)}]";

        // 2. Motherboard & BIOS
        BoardSummary = $"{snap.Motherboard.BoardManufacturer} {snap.Motherboard.BoardProduct}\nBIOS: {snap.Motherboard.BiosVersion} ({snap.Motherboard.BiosReleaseDate}) • Профиль питания: {snap.ActivePowerPlan.FriendlyName}";
        BoardExpert = $"SMBIOS v{snap.Motherboard.SmbiosMajorVersion}.{snap.Motherboard.SmbiosMinorVersion}, BiosVendor={snap.Motherboard.BiosVendor}, Scheme={snap.ActivePowerPlan.SchemeGuid}";

        // 3. Memory
        var chanLabel = snap.Memory.IsDualOrMultiChannelActive
            ? "Двухканальный режим активен"
            : (snap.Memory.PopulatedSlotsCount >= 2 ? "Внимание: одноканальный режим" : "Одноканальный режим");
        var speedPart = snap.Memory.ConfiguredSpeedMtPerSec > 0 ? $" • {snap.Memory.ConfiguredSpeedMtPerSec} МТ/с" : "";
        MemorySummary = $"{snap.Memory.FormattedTotal} {snap.Memory.MemoryGeneration}{speedPart}\nЗанято слотов: {snap.Memory.PopulatedSlotsCount} из {Math.Max(snap.Memory.TotalSlotsCount, snap.Memory.PopulatedSlotsCount)} • {chanLabel}";
        MemoryExpert = snap.Memory.Modules.Count > 0
            ? string.Join(" | ", snap.Memory.Modules.Where(m => m.IsPopulated).Select(m => $"{m.DeviceLocator}:{m.FormattedCapacity}@{m.ConfiguredSpeedMtPerSec}/{m.RatedSpeedMtPerSec}MT/s ({m.Manufacturer} {m.PartNumber})"))
            : $"Available={ByteFormatter.Format(snap.Memory.AvailablePhysicalBytes)}";

        // 4. GPU
        if (snap.Gpus.Count > 0)
        {
            var g = snap.Gpus[0];
            var tempPart = g.CoreTemperatureC.HasValue ? $" • Температура: {g.CoreTemperatureC.Value:F0}°C" : "";
            GpuSummary = $"{g.Name} ({g.FormattedVram}){tempPart}\nДрайвер: {g.DriverVersion}";
            GpuExpert = string.Join(" || ", snap.Gpus.Select(x =>
                $"{x.Name}: PCIe Gen{x.CurrentPcieGen?.ToString() ?? "?"} x{x.CurrentPcieLanes?.ToString() ?? "?"} (Max x{x.MaxPcieLanes?.ToString() ?? "?"}), ReBAR={(x.IsResizableBarEnabled.HasValue ? (x.IsResizableBarEnabled.Value ? "ON" : "OFF") : "N/A")}, Power={x.PowerDrawWatts?.ToString("F1") ?? "-"}W"));
        }
        else
        {
            GpuSummary = "Базовый графический адаптер";
            GpuExpert = "Видеокарта не вернула расширенный профиль реестра / NVML.";
        }

        // 5. Storage S.M.A.R.T.
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
                $"Disk#{d.DriveIndex} FW={d.FirmwareRevision} TBW={d.TotalBytesWrittenTb?.ToString("F2") ?? "-"}TB POH={d.PowerOnHours?.ToString() ?? "-"}h UnsafeOff={d.UnsafeShutdowns?.ToString() ?? "-"} MediaErr={d.MediaIntegrityErrors ?? 0}"));
        }
        else
        {
            StorageSummary = "Системный накопитель работает штатно";
            StorageExpert = "Для глубокого чтения NVMe Health Log может потребоваться запуск от имени Администратора.";
        }

        // 6. Monitors & Refresh Rate
        if (snap.Monitors.Count > 0)
        {
            DisplaySummary = string.Join("\n", snap.Monitors.Select(m =>
            {
                var diag = m.DiagonalInches.HasValue ? $" ({m.DiagonalInches:F1}\")" : "";
                return $"{m.FriendlyModelName}{diag}: {m.NativeWidthPx}×{m.NativeHeightPx} @ {m.CurrentRefreshHz} Гц (макс. {m.MaxSupportedRefreshHz} Гц)";
            }));
            DisplayExpert = string.Join(" || ", snap.Monitors.Select(m =>
                $"{m.GdiDeviceName} Mfg={m.ManufacturerCode} Year={m.ManufactureYear?.ToString() ?? "?"} BitDepth={m.ColorBitDepth?.ToString() ?? "?"}-bit"));
        }
        else
        {
            DisplaySummary = "Стандартный дисплей рабочего стола";
            DisplayExpert = "EDID не обнаружен.";
        }

        // 7. Advisories
        Advisories.Clear();
        foreach (var finding in audit.Findings)
        {
            Advisories.Add(new AdvisoryItemViewModel(
                finding,
                new AsyncRelayCommand(_ => ApplyFindingFixAsync(finding))));
        }

        OnPropertyChanged(nameof(HasNoAdvisories));
    }

    private async Task ApplyFindingFixAsync(HardwareAdvisoryFinding finding)
    {
        var (_, message) = await _hardwareService.ApplyAdvisoryAutoFixAsync(finding);
        await RefreshAuditAsync();
        await _onActionCompletedAsync(message);
    }

    private async Task StartStressTestAsync()
    {
        if (IsStressRunning)
        {
            return;
        }

        _stressCts = new CancellationTokenSource();
        IsStressRunning = true;

        var progress = new Progress<StressTestProgress>(p =>
        {
            StressStatusText = p.StatusMessage;
            StressThroughputText = $"{p.MillionsOpsPerSecond:F1} млн опер./сек";
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

    private void StopStressTest()
    {
        _stressCts?.Cancel();
    }
}
