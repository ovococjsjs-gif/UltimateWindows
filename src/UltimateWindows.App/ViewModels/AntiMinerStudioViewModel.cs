using System.Collections.ObjectModel;
using System.Windows.Input;
using UltimateWindows.App.Infrastructure;
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
    public string SimpleTitle => Finding.SimpleTitle;
    public string SimpleExplanation => Finding.SimpleExplanation;
    public string ConfidenceBadge => Finding.ConfidenceBadge;
    public string ExpertTechnicalEvidence => Finding.ExpertTechnicalEvidence;
    public bool CanQuarantineFileSafely => Finding.CanQuarantineFileSafely;
    public ICommand QuarantineCommand { get; }
}

/// <summary>
/// ViewModel экрана Фазы 5 «Защита от скрытых майнеров (Drop-on-Inspect, Stratum, ревизор закрепления и реабилитация ОС)».
/// </summary>
public sealed class AntiMinerStudioViewModel : ObservableObject
{
    private readonly AntiMinerSecurityService _securityService;
    private readonly Func<string, Task> _onActionCompletedAsync;
    private IReadOnlyList<OsSabotageFinding> _lastSabotageList = [];

    private bool _enableDropOnInspectProbe = true;
    private bool _isScanning;
    private int _securityScore = 100;
    private string _scanHeadline = "Нажмите «Запустить глубокий поиск майнеров», чтобы проверить маскирующиеся процессы, сетевые пулы Stratum, скрытые задачи и блокировки системы.";
    private string _lastRemediationBanner = "";

    public AntiMinerStudioViewModel(
        AntiMinerSecurityService securityService,
        Func<string, Task> onActionCompletedAsync)
    {
        _securityService = securityService;
        _onActionCompletedAsync = onActionCompletedAsync;

        Threats = new ObservableCollection<ThreatItemViewModel>();
        SabotageLocks = new ObservableCollection<OsSabotageFinding>();

        RunSecurityScanCommand = new AsyncRelayCommand(_ => RunScanAsync());
        HealSabotageCommand = new AsyncRelayCommand(_ => HealAllSabotageAsync());
    }

    public ObservableCollection<ThreatItemViewModel> Threats { get; }
    public ObservableCollection<OsSabotageFinding> SabotageLocks { get; }

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

    public bool HasRemediationBanner => !string.IsNullOrWhiteSpace(LastRemediationBanner);
    public bool HasThreats => Threats.Count > 0;
    public bool HasSabotageLocks => SabotageLocks.Count > 0;

    public ICommand RunSecurityScanCommand { get; }
    public ICommand HealSabotageCommand { get; }

    public async Task RunScanAsync()
    {
        if (IsScanning) return;

        IsScanning = true;
        ScanHeadline = EnableDropOnInspectProbe
            ? "Фаза 1/2: Тихий замер нагрузки процессов -> Фаза 2/2: Стелс-приманка Drop-on-Inspect и аудит Stratum/IFEO/задач..."
            : "Быстрая проверка маскировки системных процессов, портов Stratum и блокировок реестра...";

        try
        {
            var report = await _securityService.RunFullSecurityScanAsync(EnableDropOnInspectProbe);
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

            _lastSabotageList = report.SabotageLocks;
            SabotageLocks.Clear();
            foreach (var s in report.SabotageLocks)
            {
                SabotageLocks.Add(s);
            }

            OnPropertyChanged(nameof(HasThreats));
            OnPropertyChanged(nameof(HasSabotageLocks));

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

    private async Task QuarantineThreatItemAsync(SecurityThreatFinding finding)
    {
        var res = await _securityService.QuarantineThreatAsync(finding);
        LastRemediationBanner = res.UserFriendlyMessage;
        if (res.Succeeded)
        {
            await RunScanAsync();
        }

        await _onActionCompletedAsync(res.UserFriendlyMessage);
    }

    private async Task HealAllSabotageAsync()
    {
        if (_lastSabotageList.Count == 0) return;

        var res = await _securityService.HealAllSabotageLocksAsync(_lastSabotageList);
        LastRemediationBanner = res.UserFriendlyMessage;
        if (res.Succeeded)
        {
            await RunScanAsync();
        }

        await _onActionCompletedAsync(res.UserFriendlyMessage);
    }
}
