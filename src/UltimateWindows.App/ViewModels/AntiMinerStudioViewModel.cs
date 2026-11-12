using System.Collections.ObjectModel;
using System.Windows.Input;
using Microsoft.Win32;
using UltimateWindows.App.Infrastructure;
using UltimateWindows.Modules.Security.Analyzers;
using UltimateWindows.Modules.Security.Models;
using UltimateWindows.Modules.Security.Services;

namespace UltimateWindows.App.ViewModels;

public sealed class ThreatItemViewModel : ObservableObject
{
    public ThreatItemViewModel(SecurityThreatFinding finding, ICommand quarantineCommand)
    {
        Finding = finding;
        QuarantineCommand = quarantineCommand;
    }

    public SecurityThreatFinding Finding { get; }
    public string CategoryLabel => Finding.EffectiveCategoryLabel;
    public string SimpleTitle => Finding.SimpleTitle;
    public string SimpleExplanation => Finding.SimpleExplanation;
    public string ConfidenceBadge => Finding.ConfidenceBadge;
    public string ExpertTechnicalEvidence => Finding.ExpertTechnicalEvidence;
    public string RecommendedActionLabel => Finding.RecommendedActionLabel;
    public bool CanQuarantineFileSafely => Finding.CanQuarantineFileSafely;
    public bool CanRemediateAny => Finding.CanRemediateAny;
    public ICommand QuarantineCommand { get; }
}

public sealed class PersistenceItemViewModel : ObservableObject
{
    public PersistenceItemViewModel(PersistenceAnomalyRecord record, ICommand remediateCommand)
    {
        Record = record;
        RemediateCommand = remediateCommand;
    }

    public PersistenceAnomalyRecord Record { get; }
    public string ZoneTitle => Record.ZoneTitle;
    public string StatusBadge => Record.StatusBadge;
    public string EntryName => Record.EntryName;
    public string PayloadCommandOrPath => Record.PayloadCommandOrPath;
    public string RegistryOrTaskPath => Record.RegistryOrTaskPath;
    public bool CanRemediate => Record.CanRemediate;
    public ICommand RemediateCommand { get; }
}

public sealed class QuarantineEntryViewModel : ObservableObject
{
    public QuarantineEntryViewModel(QuarantinedThreatEntry entry, ICommand restoreCommand)
    {
        Entry = entry;
        RestoreCommand = restoreCommand;
    }

    public QuarantinedThreatEntry Entry { get; }
    public string TimestampLocalText => Entry.TimestampLocalText;
    public string FriendlyTitle => Entry.FriendlyTitle;
    public string PrimaryPath => Entry.PrimaryPath;
    public string StatusBadge => Entry.IsReverted ? "Восстановлено" : "В карантине (.uwq)";
    public bool CanRestore => !Entry.IsReverted;
    public ICommand RestoreCommand { get; }
}

/// <summary>
/// ViewModel раздела «Анти-майнер и Защита 2.0» (5 профильных вкладок: Обзор угроз, Автозакрепление 18 зон,
/// Защитник и саботаж, Память и сигнатуры PE-sieve/YARA, Карантин .uwq).
/// </summary>
public sealed class AntiMinerStudioViewModel : ObservableObject
{
    private const string AllZonesLabel = "Все 18 зон закрепления";

    private readonly AntiMinerSecurityService _securityService;
    private readonly Func<string, Task> _onActionCompletedAsync;
    private IReadOnlyList<OsSabotageFinding> _lastSabotageList = [];
    private IReadOnlyList<PersistenceAnomalyRecord> _allPersistence = [];
    private IReadOnlyList<DefenderExclusionFinding> _allDefenderExclusions = [];
    private IReadOnlyList<ProcessTelemetrySample> _allProcesses = [];

    private int _selectedSubTabIndex;
    private bool _enableDropOnInspectProbe = true;
    private bool _isScanning;
    private int _securityScore = 100;
    private string _scanHeadline = "Нажмите «Полная проверка ПК», чтобы проверить скрытые CPU/GPU-майнеры, 18 зон автозакрепления, исключения Защитника Windows, брандмауэр, hosts и память процессов.";
    private string _lastRemediationBanner = "";
    private ThreatItemViewModel? _selectedThreat;

    private string _selectedZoneFilter = AllZonesLabel;
    private string _persistenceSearchText = "";
    private bool _onlyAnomalousPersistenceFilter;

    private string _defenderCustomScanPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private string _processSearchText = "";
    private string _customPeSievePath = "";
    private string _customYaraPath = "";
    private string _customYaraRulesPath = "";
    private string _yaraScanTargetPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

    public AntiMinerStudioViewModel(
        AntiMinerSecurityService securityService,
        Func<string, Task> onActionCompletedAsync)
    {
        _securityService = securityService;
        _onActionCompletedAsync = onActionCompletedAsync;

        Threats = new ObservableCollection<ThreatItemViewModel>();
        SabotageLocks = new ObservableCollection<OsSabotageFinding>();
        FilteredPersistenceEntries = new ObservableCollection<PersistenceItemViewModel>();
        DefenderExclusions = new ObservableCollection<DefenderExclusionFinding>();
        FirewallAnomalies = new ObservableCollection<FirewallRuleAnomaly>();
        SuspiciousUsers = new ObservableCollection<SuspiciousUserAccountFinding>();
        FilteredProcessSnapshots = new ObservableCollection<ProcessTelemetrySample>();
        ExternalScanners = new ObservableCollection<ExternalScannerStatus>();
        QuarantineHistory = new ObservableCollection<QuarantineEntryViewModel>();

        var zones = new List<string> { AllZonesLabel };
        foreach (var z in PersistenceZoneCatalog.AllZones)
        {
            zones.Add(CreateDummyZoneTitle(z));
        }
        ZoneFilterOptions = zones;

        RunSecurityScanCommand = new AsyncRelayCommand(_ => RunScanAsync());
        RunQuickSecurityScanCommand = new AsyncRelayCommand(_ => RunQuickScanAsync());
        NeutralizeAllThreatsCommand = new AsyncRelayCommand(_ => NeutralizeAllRemediableThreatsAsync());
        HealSabotageCommand = new AsyncRelayCommand(_ => HealAllSabotageAsync());
        CleanDefenderExclusionsCommand = new AsyncRelayCommand(_ => CleanDangerousDefenderExclusionsAsync());
        RunDefenderQuickScanCommand = new AsyncRelayCommand(_ => TriggerDefenderScanAsync(DefenderScanMode.QuickScan));
        RunDefenderCustomScanCommand = new AsyncRelayCommand(_ => TriggerDefenderScanAsync(DefenderScanMode.CustomPathScan));
        BrowsePeSieveCommand = new RelayCommand(_ => BrowseExecutable(p => CustomPeSievePath = p, "PE-sieve|pe-sieve*.exe;*.exe"));
        BrowseYaraCommand = new RelayCommand(_ => BrowseExecutable(p => CustomYaraPath = p, "YARA|yara*.exe;yr*.exe;*.exe"));
        BrowseYaraRulesCommand = new RelayCommand(_ => BrowseExecutable(p => CustomYaraRulesPath = p, "Правила YARA|*.yar;*.yara;*.*"));
        RunPeSieveCheckCommand = new AsyncRelayCommand(_ => RunPeSieveCheckAsync());
        RunYaraCheckCommand = new AsyncRelayCommand(_ => RunYaraCheckAsync());
        RefreshQuarantineCommand = new AsyncRelayCommand(_ => RefreshQuarantineHistoryAsync());

        RefreshScannerStatuses();
    }

    public ObservableCollection<ThreatItemViewModel> Threats { get; }
    public ObservableCollection<OsSabotageFinding> SabotageLocks { get; }
    public ObservableCollection<PersistenceItemViewModel> FilteredPersistenceEntries { get; }
    public ObservableCollection<DefenderExclusionFinding> DefenderExclusions { get; }
    public ObservableCollection<FirewallRuleAnomaly> FirewallAnomalies { get; }
    public ObservableCollection<SuspiciousUserAccountFinding> SuspiciousUsers { get; }
    public ObservableCollection<ProcessTelemetrySample> FilteredProcessSnapshots { get; }
    public ObservableCollection<ExternalScannerStatus> ExternalScanners { get; }
    public ObservableCollection<QuarantineEntryViewModel> QuarantineHistory { get; }
    public IReadOnlyList<string> ZoneFilterOptions { get; }

    public int SelectedSubTabIndex
    {
        get => _selectedSubTabIndex;
        set
        {
            if (SetProperty(ref _selectedSubTabIndex, value))
            {
                OnPropertyChanged(nameof(IsOverviewTab));
                OnPropertyChanged(nameof(IsPersistenceTab));
                OnPropertyChanged(nameof(IsDefenderSabotageTab));
                OnPropertyChanged(nameof(IsMemorySignaturesTab));
                OnPropertyChanged(nameof(IsQuarantineTab));
            }
        }
    }

    public bool IsOverviewTab => SelectedSubTabIndex == 0;
    public bool IsPersistenceTab => SelectedSubTabIndex == 1;
    public bool IsDefenderSabotageTab => SelectedSubTabIndex == 2;
    public bool IsMemorySignaturesTab => SelectedSubTabIndex == 3;
    public bool IsQuarantineTab => SelectedSubTabIndex == 4;

    public bool EnableDropOnInspectProbe
    {
        get => _enableDropOnInspectProbe;
        set => SetProperty(ref _enableDropOnInspectProbe, value);
    }

    public bool IsScanning
    {
        get => _isScanning;
        private set => SetProperty(ref _isScanning, value);
    }

    public int SecurityScore
    {
        get => _securityScore;
        private set
        {
            if (SetProperty(ref _securityScore, value))
            {
                OnPropertyChanged(nameof(SecurityScoreBadge));
            }
        }
    }

    public string SecurityScoreBadge => $"Индекс защиты: {SecurityScore} / 100";

    public string ScanHeadline
    {
        get => _scanHeadline;
        private set => SetProperty(ref _scanHeadline, value);
    }

    public string LastRemediationBanner
    {
        get => _lastRemediationBanner;
        private set
        {
            if (SetProperty(ref _lastRemediationBanner, value))
            {
                OnPropertyChanged(nameof(HasRemediationBanner));
            }
        }
    }

    public ThreatItemViewModel? SelectedThreat
    {
        get => _selectedThreat;
        set
        {
            if (SetProperty(ref _selectedThreat, value))
            {
                OnPropertyChanged(nameof(SelectedThreatEvidence));
            }
        }
    }

    public string SelectedThreatEvidence => SelectedThreat is null
        ? "Выберите карточку угрозы в таблице выше, чтобы увидеть техническую доказательную базу (PID, пути, ключи реестра, флаги памяти и сеть)."
        : $"{SelectedThreat.SimpleTitle}\n{SelectedThreat.ExpertTechnicalEvidence}";

    public string SelectedZoneFilter
    {
        get => _selectedZoneFilter;
        set
        {
            if (SetProperty(ref _selectedZoneFilter, value))
            {
                RebuildPersistenceFilter();
            }
        }
    }

    public string PersistenceSearchText
    {
        get => _persistenceSearchText;
        set
        {
            if (SetProperty(ref _persistenceSearchText, value))
            {
                RebuildPersistenceFilter();
            }
        }
    }

    public bool OnlyAnomalousPersistenceFilter
    {
        get => _onlyAnomalousPersistenceFilter;
        set
        {
            if (SetProperty(ref _onlyAnomalousPersistenceFilter, value))
            {
                RebuildPersistenceFilter();
            }
        }
    }

    public string DefenderCustomScanPath
    {
        get => _defenderCustomScanPath;
        set => SetProperty(ref _defenderCustomScanPath, value);
    }

    public string ProcessSearchText
    {
        get => _processSearchText;
        set
        {
            if (SetProperty(ref _processSearchText, value))
            {
                RebuildProcessFilter();
            }
        }
    }

    public string CustomPeSievePath
    {
        get => _customPeSievePath;
        set
        {
            if (SetProperty(ref _customPeSievePath, value))
            {
                _securityService.ExternalScanners.CustomPeSievePath = value;
                RefreshScannerStatuses();
            }
        }
    }

    public string CustomYaraPath
    {
        get => _customYaraPath;
        set
        {
            if (SetProperty(ref _customYaraPath, value))
            {
                _securityService.ExternalScanners.CustomYaraPath = value;
                RefreshScannerStatuses();
            }
        }
    }

    public string CustomYaraRulesPath
    {
        get => _customYaraRulesPath;
        set
        {
            if (SetProperty(ref _customYaraRulesPath, value))
            {
                _securityService.ExternalScanners.CustomYaraRulesPath = value;
            }
        }
    }

    public string YaraScanTargetPath
    {
        get => _yaraScanTargetPath;
        set => SetProperty(ref _yaraScanTargetPath, value);
    }

    public string KpiSummaryStrip =>
        $"Зон закрепления: 18 (записей: {_allPersistence.Count}, аномалий: {_allPersistence.Count(p => p.IsAnomaly)}) • " +
        $"Исключений Defender: {_allDefenderExclusions.Count} (опасных: {_allDefenderExclusions.Count(e => e.IsDangerousMinerExclusion)}) • " +
        $"Проверено процессов: {_allProcesses.Count}";

    public bool HasRemediationBanner => !string.IsNullOrWhiteSpace(LastRemediationBanner);
    public bool HasThreats => Threats.Count > 0;
    public bool HasSabotageLocks => SabotageLocks.Count > 0;
    public bool HasDangerousDefenderExclusions => _allDefenderExclusions.Any(e => e.IsDangerousMinerExclusion);

    public ICommand RunSecurityScanCommand { get; }
    public ICommand RunQuickSecurityScanCommand { get; }
    public ICommand NeutralizeAllThreatsCommand { get; }
    public ICommand HealSabotageCommand { get; }
    public ICommand CleanDefenderExclusionsCommand { get; }
    public ICommand RunDefenderQuickScanCommand { get; }
    public ICommand RunDefenderCustomScanCommand { get; }
    public ICommand BrowsePeSieveCommand { get; }
    public ICommand BrowseYaraCommand { get; }
    public ICommand BrowseYaraRulesCommand { get; }
    public ICommand RunPeSieveCheckCommand { get; }
    public ICommand RunYaraCheckCommand { get; }
    public ICommand RefreshQuarantineCommand { get; }

    public Task RunScanAsync() => ExecuteScanInternalAsync(EnableDropOnInspectProbe);

    public Task RunQuickScanAsync() => ExecuteScanInternalAsync(useDecoyProbe: false);

    private async Task ExecuteScanInternalAsync(bool useDecoyProbe)
    {
        if (IsScanning) return;

        IsScanning = true;
        ScanHeadline = useDecoyProbe
            ? "Фаза 1/2: Тихий замер CPU и GPU -> Фаза 2/2: Приманка Drop-on-Inspect, аудит 18 зон закрепления, Defender, брандмауэра и памяти..."
            : "Быстрая ревизия 18 зон автозакрепления, портов Stratum IPv4/IPv6, исключений Defender и блокировок ОС...";

        try
        {
            var report = await _securityService.RunFullSecurityScanAsync(useDecoyProbe);
            SecurityScore = report.SecurityHealthScore;
            ScanHeadline = report.HeadlineSummary;

            Threats.Clear();
            foreach (var t in report.Threats)
            {
                var captured = t;
                Threats.Add(new ThreatItemViewModel(
                    captured,
                    new AsyncRelayCommand(_ => QuarantineThreatItemAsync(captured))));
            }
            SelectedThreat = Threats.FirstOrDefault();

            _lastSabotageList = report.SabotageLocks;
            SabotageLocks.Clear();
            foreach (var s in report.SabotageLocks)
            {
                SabotageLocks.Add(s);
            }

            _allPersistence = report.SafePersistenceEntries;
            _allDefenderExclusions = report.SafeDefenderExclusions;
            _allProcesses = report.SafeProcessSnapshots;

            DefenderExclusions.Clear();
            foreach (var ex in _allDefenderExclusions)
            {
                DefenderExclusions.Add(ex);
            }

            FirewallAnomalies.Clear();
            foreach (var fw in report.SafeFirewallAnomalies)
            {
                FirewallAnomalies.Add(fw);
            }

            SuspiciousUsers.Clear();
            foreach (var u in report.SafeSuspiciousUsers)
            {
                SuspiciousUsers.Add(u);
            }

            ExternalScanners.Clear();
            foreach (var sc in report.SafeExternalScanners)
            {
                ExternalScanners.Add(sc);
            }

            RebuildPersistenceFilter();
            RebuildProcessFilter();
            await RefreshQuarantineHistoryAsync();

            OnPropertyChanged(nameof(HasThreats));
            OnPropertyChanged(nameof(HasSabotageLocks));
            OnPropertyChanged(nameof(HasDangerousDefenderExclusions));
            OnPropertyChanged(nameof(KpiSummaryStrip));

            await _onActionCompletedAsync(report.HeadlineSummary);
        }
        catch (Exception ex)
        {
            ScanHeadline = $"Ошибка при выполнении сканирования: {ex.Message}";
        }
        finally
        {
            IsScanning = false;
        }
    }

    public async Task RefreshQuarantineHistoryAsync()
    {
        var items = await _securityService.GetQuarantineHistoryAsync();
        QuarantineHistory.Clear();
        foreach (var entry in items)
        {
            var captured = entry;
            QuarantineHistory.Add(new QuarantineEntryViewModel(
                captured,
                new AsyncRelayCommand(_ => RestoreQuarantineEntryAsync(captured.SessionId))));
        }
    }

    private void RebuildPersistenceFilter()
    {
        FilteredPersistenceEntries.Clear();
        var query = (_persistenceSearchText ?? "").Trim();

        foreach (var rec in _allPersistence
            .OrderByDescending(r => r.IsAnomaly)
            .ThenBy(r => r.Category)
            .ThenBy(r => r.EntryName, StringComparer.OrdinalIgnoreCase))
        {
            if (_onlyAnomalousPersistenceFilter && !rec.IsAnomaly)
            {
                continue;
            }

            if (!string.IsNullOrWhiteSpace(_selectedZoneFilter) &&
                !string.Equals(_selectedZoneFilter, AllZonesLabel, StringComparison.Ordinal) &&
                !string.Equals(rec.ZoneTitle, _selectedZoneFilter, StringComparison.Ordinal))
            {
                continue;
            }

            if (!string.IsNullOrWhiteSpace(query) &&
                !rec.EntryName.Contains(query, StringComparison.OrdinalIgnoreCase) &&
                !rec.PayloadCommandOrPath.Contains(query, StringComparison.OrdinalIgnoreCase) &&
                !rec.RegistryOrTaskPath.Contains(query, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var captured = rec;
            FilteredPersistenceEntries.Add(new PersistenceItemViewModel(
                captured,
                new AsyncRelayCommand(_ => RemediatePersistenceItemAsync(captured))));
        }
    }

    private void RebuildProcessFilter()
    {
        FilteredProcessSnapshots.Clear();
        var query = (_processSearchText ?? "").Trim();

        foreach (var proc in _allProcesses
            .OrderByDescending(p => p.BaselineCpuPercent + p.BaselineGpuPercent)
            .ThenByDescending(p => p.PrivateExecutableRegionCount)
            .ThenBy(p => p.ProcessName, StringComparer.OrdinalIgnoreCase))
        {
            if (!string.IsNullOrWhiteSpace(query) &&
                !proc.ProcessName.Contains(query, StringComparison.OrdinalIgnoreCase) &&
                !proc.ExecutablePath.Contains(query, StringComparison.OrdinalIgnoreCase) &&
                !proc.CommandLine.Contains(query, StringComparison.OrdinalIgnoreCase) &&
                !proc.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture).Contains(query, StringComparison.Ordinal))
            {
                continue;
            }

            FilteredProcessSnapshots.Add(proc);
        }
    }

    private void RefreshScannerStatuses()
    {
        ExternalScanners.Clear();
        foreach (var s in _securityService.ExternalScanners.ProbeAvailableScanners())
        {
            ExternalScanners.Add(s);
        }
    }

    private async Task QuarantineThreatItemAsync(SecurityThreatFinding finding)
    {
        var res = await _securityService.QuarantineThreatAsync(finding);
        LastRemediationBanner = res.UserFriendlyMessage;
        if (res.Succeeded)
        {
            await ExecuteScanInternalAsync(useDecoyProbe: false);
        }

        await _onActionCompletedAsync(res.UserFriendlyMessage);
    }

    private async Task NeutralizeAllRemediableThreatsAsync()
    {
        var remediable = Threats.Where(t => t.CanRemediateAny).Select(t => t.Finding).ToList();
        if (remediable.Count == 0)
        {
            LastRemediationBanner = "Нет активных угроз, требующих автоматического обезвреживания.";
            return;
        }

        int okCount = 0;
        foreach (var f in remediable)
        {
            var r = await _securityService.QuarantineThreatAsync(f);
            if (r.Succeeded) okCount++;
        }

        LastRemediationBanner = $"Обезврежено угроз: {okCount} из {remediable.Count}. Подробности сохранены в «Машине времени».";
        await ExecuteScanInternalAsync(useDecoyProbe: false);
        await _onActionCompletedAsync(LastRemediationBanner);
    }

    private async Task RemediatePersistenceItemAsync(PersistenceAnomalyRecord record)
    {
        var res = await _securityService.RemovePersistenceAnomalyAsync(record);
        LastRemediationBanner = res.UserFriendlyMessage;
        if (res.Succeeded)
        {
            await ExecuteScanInternalAsync(useDecoyProbe: false);
        }

        await _onActionCompletedAsync(res.UserFriendlyMessage);
    }

    private async Task CleanDangerousDefenderExclusionsAsync()
    {
        var res = await _securityService.RemoveDangerousDefenderExclusionsAsync(_allDefenderExclusions);
        LastRemediationBanner = res.UserFriendlyMessage;
        if (res.Succeeded && res.FixedItemsCount > 0)
        {
            await ExecuteScanInternalAsync(useDecoyProbe: false);
        }

        await _onActionCompletedAsync(res.UserFriendlyMessage);
    }

    private async Task TriggerDefenderScanAsync(DefenderScanMode mode)
    {
        var (ok, msg) = await _securityService.StartDefenderScanAsync(
            mode,
            mode == DefenderScanMode.CustomPathScan ? DefenderCustomScanPath : null);

        LastRemediationBanner = msg;
        if (ok)
        {
            await _onActionCompletedAsync(msg);
        }
    }

    private async Task RunPeSieveCheckAsync()
    {
        var candidatePids = _allProcesses
            .OrderByDescending(p => p.BaselineCpuPercent + p.BaselineGpuPercent + p.PrivateExecutableRegionCount * 10)
            .Select(p => p.ProcessId)
            .Take(12)
            .ToList();

        var hits = await _securityService.RunPeSieveDeepCheckAsync(candidatePids);
        if (hits.Count == 0)
        {
            var peAvailable = ExternalScanners.FirstOrDefault(s => s.ScannerId == "pe-sieve")?.IsAvailable ?? false;
            LastRemediationBanner = peAvailable
                ? "Проверка PE-sieve завершена: внедрённых PE-имплантов и Process Hollowing не обнаружено."
                : "Сканер PE-sieve не подключён: укажите путь к pe-sieve64.exe или поместите его в папку tools\\.";
            return;
        }

        foreach (var h in hits)
        {
            var captured = h;
            Threats.Insert(0, new ThreatItemViewModel(captured, new AsyncRelayCommand(_ => QuarantineThreatItemAsync(captured))));
        }

        OnPropertyChanged(nameof(HasThreats));
        SelectedSubTabIndex = 0;
        LastRemediationBanner = $"PE-sieve обнаружил имплантов в памяти процессов: {hits.Count} шт.";
    }

    private async Task RunYaraCheckAsync()
    {
        var hits = await _securityService.RunYaraScanAsync(YaraScanTargetPath);
        if (hits.Count == 0)
        {
            var yaraAvailable = ExternalScanners.FirstOrDefault(s => s.ScannerId == "yara")?.IsAvailable ?? false;
            LastRemediationBanner = yaraAvailable
                ? $"Проверка YARA («{YaraScanTargetPath}») завершена: совпадений с сигнатурами не найдено."
                : "Сканер YARA или файл правил .yar не подключён: укажите путь на вкладке «Память и сигнатуры».";
            return;
        }

        foreach (var h in hits)
        {
            var captured = h;
            Threats.Insert(0, new ThreatItemViewModel(captured, new AsyncRelayCommand(_ => QuarantineThreatItemAsync(captured))));
        }

        OnPropertyChanged(nameof(HasThreats));
        SelectedSubTabIndex = 0;
        LastRemediationBanner = $"Сканер YARA обнаружил совпадений: {hits.Count} шт.";
    }

    private async Task HealAllSabotageAsync()
    {
        if (_lastSabotageList.Count == 0) return;

        var res = await _securityService.HealAllSabotageLocksAsync(_lastSabotageList);
        LastRemediationBanner = res.UserFriendlyMessage;
        if (res.Succeeded)
        {
            await ExecuteScanInternalAsync(useDecoyProbe: false);
        }

        await _onActionCompletedAsync(res.UserFriendlyMessage);
    }

    private async Task RestoreQuarantineEntryAsync(Guid sessionId)
    {
        var res = await _securityService.RestoreFromQuarantineAsync(sessionId);
        LastRemediationBanner = res.UserFriendlyMessage;
        await RefreshQuarantineHistoryAsync();
        await _onActionCompletedAsync(res.UserFriendlyMessage);
    }

    private static void BrowseExecutable(Action<string> setter, string filter)
    {
        var dlg = new OpenFileDialog
        {
            Filter = filter,
            CheckFileExists = true
        };
        if (dlg.ShowDialog() == true)
        {
            setter(dlg.FileName);
        }
    }

    private static string CreateDummyZoneTitle(PersistenceZone zone) =>
        new PersistenceAnomalyRecord(
            ThreatDetectionVector.SuspiciousRegistryAutorun,
            "", "", "", null, false, null, Category: zone).ZoneTitle;
}
