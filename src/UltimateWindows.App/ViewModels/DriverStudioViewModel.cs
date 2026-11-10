using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Windows.Input;
using UltimateWindows.App.Infrastructure;
using UltimateWindows.Modules.Drivers.Models;
using UltimateWindows.Modules.Drivers.Services;

namespace UltimateWindows.App.ViewModels;

public sealed class DriverFindingItemViewModel : ObservableObject
{
    public DriverFindingItemViewModel(
        DriverAuditFinding finding,
        ICommand installWhqlCommand,
        ICommand backupInfCommand,
        ICommand openVendorPortalCommand)
    {
        Finding = finding;
        InstallWhqlCommand = installWhqlCommand;
        BackupInfCommand = backupInfCommand;
        OpenVendorPortalCommand = openVendorPortalCommand;
    }

    public DriverAuditFinding Finding { get; }
    public string SimpleTitle => Finding.SimpleTitle;
    public string SimpleExplanation => Finding.SimpleExplanation;
    public string ExpertTechnicalDetails => Finding.ExpertTechnicalDetails;
    public bool CanInstallViaWindowsUpdate => Finding.CanInstallViaWindowsUpdate;
    public bool CanBackupOemInf => Finding.CanBackupOemInf;
    public bool HasOfficialVendorUrl => !string.IsNullOrWhiteSpace(Finding.OfficialVendorUrl);

    public ICommand InstallWhqlCommand { get; }
    public ICommand BackupInfCommand { get; }
    public ICommand OpenVendorPortalCommand { get; }
}

/// <summary>
/// ViewModel секции Фазы 6 «Официальный менеджер WHQL-драйверов (CfgMgr32 + 4-компонентный Hardware ID + компактный бэкап oemXX.inf)».
/// </summary>
public sealed class DriverStudioViewModel : ObservableObject
{
    private readonly OfficialDriverService _driverService;
    private readonly Func<string, Task> _onActionCompletedAsync;

    private bool _queryWindowsUpdateOnline;
    private bool _isBusy;
    private int _driverScore = 100;
    private string _driverSummaryHeadline = "Нажмите «Проверить драйверы», чтобы найти устройства без драйвера (Код 28/43), базовые видеоадаптеры и подписанные WHQL-обновления.";
    private string _lastDriverOperationBanner = "";

    public DriverStudioViewModel(
        OfficialDriverService driverService,
        Func<string, Task> onActionCompletedAsync)
    {
        _driverService = driverService;
        _onActionCompletedAsync = onActionCompletedAsync;

        DriverFindings = new ObservableCollection<DriverFindingItemViewModel>();
        AuditDriversCommand = new AsyncRelayCommand(_ => RunDriverAuditAsync());
    }

    public ObservableCollection<DriverFindingItemViewModel> DriverFindings { get; }

    public bool QueryWindowsUpdateOnline
    {
        get => _queryWindowsUpdateOnline;
        set => SetProperty(ref _queryWindowsUpdateOnline, value);
    }

    public bool IsBusy
    {
        get => _isBusy;
        private set => SetProperty(ref _isBusy, value);
    }

    public int DriverScore
    {
        get => _driverScore;
        private set
        {
            if (SetProperty(ref _driverScore, value))
            {
                OnPropertyChanged(nameof(DriverScoreBadge));
            }
        }
    }

    public string DriverScoreBadge => $"Драйверы: {DriverScore} / 100";

    public string DriverSummaryHeadline
    {
        get => _driverSummaryHeadline;
        private set => SetProperty(ref _driverSummaryHeadline, value);
    }

    public string LastDriverOperationBanner
    {
        get => _lastDriverOperationBanner;
        private set
        {
            if (SetProperty(ref _lastDriverOperationBanner, value))
            {
                OnPropertyChanged(nameof(HasDriverOperationBanner));
            }
        }
    }

    public bool HasDriverOperationBanner => !string.IsNullOrWhiteSpace(LastDriverOperationBanner);
    public bool HasDriverFindings => DriverFindings.Count > 0;

    public ICommand AuditDriversCommand { get; }

    public async Task RunDriverAuditAsync()
    {
        if (IsBusy) return;

        IsBusy = true;
        DriverSummaryHeadline = QueryWindowsUpdateOnline
            ? "Опрос дерева устройств CfgMgr32 и поиск подписанных WHQL-драйверов в каталоге Microsoft Windows Update..."
            : "Быстрый опрос дерева устройств CfgMgr32 (коды ошибок 1/10/18/28/31/43 и базовые адаптеры)...";

        try
        {
            var report = await _driverService.AuditDevicesAndDriversAsync(QueryWindowsUpdateOnline);
            DriverScore = report.DriverHealthScore;
            DriverSummaryHeadline = report.SummaryHeadline;

            DriverFindings.Clear();
            foreach (var f in report.Findings)
            {
                var captured = f;
                DriverFindings.Add(new DriverFindingItemViewModel(
                    captured,
                    new AsyncRelayCommand(_ => InstallWhqlAsync(captured)),
                    new AsyncRelayCommand(_ => BackupOemInfAsync(captured.Device)),
                    new RelayCommand(_ => OpenOfficialVendorUrl(captured.OfficialVendorUrl))));
            }

            OnPropertyChanged(nameof(HasDriverFindings));
            await _onActionCompletedAsync(report.SummaryHeadline);
        }
        catch (Exception ex)
        {
            DriverSummaryHeadline = $"Ошибка при проверке драйверов: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task BackupOemInfAsync(SystemDeviceNode device)
    {
        var res = await _driverService.BackupDeviceDriverToVaultAsync(device);
        LastDriverOperationBanner = res.UserFriendlyMessage;
        await _onActionCompletedAsync(res.UserFriendlyMessage);
    }

    private async Task InstallWhqlAsync(DriverAuditFinding finding)
    {
        if (finding.RecommendedWhqlUpdate is null) return;

        var res = await _driverService.InstallOfficialWhqlDriverAsync(finding.Device, finding.RecommendedWhqlUpdate);
        LastDriverOperationBanner = res.UserFriendlyMessage;
        if (res.Succeeded)
        {
            await RunDriverAuditAsync();
        }

        await _onActionCompletedAsync(res.UserFriendlyMessage);
    }

    private static void OpenOfficialVendorUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url) || !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = url,
                UseShellExecute = true
            });
        }
        catch
        {
            // Ignore browser launch error
        }
    }
}
