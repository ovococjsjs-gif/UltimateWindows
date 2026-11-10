using System.Collections.ObjectModel;
using System.IO;
using System.Windows.Input;
using UltimateWindows.App.Infrastructure;
using UltimateWindows.Modules.Cleaner.Models;
using UltimateWindows.Modules.Cleaner.Services;

namespace UltimateWindows.App.ViewModels;

/// <summary>
/// ViewModel экрана «Бережная очистка, гигиена реестра и карта диска» (Vault-Safe Cleaner).
/// Строит двухэтапный безопасный процесс: Предварительный анализ (Dry-Run) -> Бережная очистка с защитой паролей.
/// </summary>
public sealed class CleanerStudioViewModel : ObservableObject
{
    private readonly VaultSafeCleanerService _cleanerService;
    private readonly Func<string, Task> _onActionCompletedAsync;

    private CleanupScanReport? _lastScanReport;

    private bool _preservePasswordsAndAutofill = true;
    private bool _preserveBrowserSessions = true;
    private bool _cleanBrowserCaches = true;
    private bool _cleanSystemTempAndShaders = true;
    private bool _cleanRegistryOrphans = true;
    private bool _emptyRecycleBin;
    private bool _includeDeveloperCaches;

    private bool _isScanning;
    private bool _isCleaning;
    private bool _isAnalyzingDisk;

    private string _scanSummaryHeadline = "Нажмите «Проверить безопасный объем», чтобы увидеть точный список временного мусора без удаления.";
    private string _browserWarningBanner = "";
    private string _lastCleanupOutcome = "";

    private string _diskMapTargetPath;
    private string _diskMapStatusText = "Выберите папку или диск для мгновенного поиска самых тяжелых каталогов и файлов.";

    public CleanerStudioViewModel(
        VaultSafeCleanerService cleanerService,
        Func<string, Task> onActionCompletedAsync)
    {
        _cleanerService = cleanerService;
        _onActionCompletedAsync = onActionCompletedAsync;

        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        _diskMapTargetPath = !string.IsNullOrWhiteSpace(userProfile) && Directory.Exists(userProfile)
            ? userProfile
            : (Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\");

        Categories = new ObservableCollection<CleanupCategorySummary>();
        RegistryOrphans = new ObservableCollection<RegistryOrphanCandidate>();
        TopDirectories = new ObservableCollection<DiskSpaceItem>();
        LargestFiles = new ObservableCollection<DiskSpaceItem>();

        ScanPreviewCommand = new AsyncRelayCommand(_ => RunScanPreviewAsync());
        ExecuteSafeCleanCommand = new AsyncRelayCommand(_ => ExecuteSafeCleanAsync(), _ => CanExecuteClean);
        AnalyzeDiskSpaceCommand = new AsyncRelayCommand(_ => AnalyzeDiskSpaceAsync());
        SelectDiskPresetCommand = new RelayCommand(param =>
        {
            if (param is string presetKey)
            {
                ApplyDiskPreset(presetKey);
            }
        });
    }

    public ObservableCollection<CleanupCategorySummary> Categories { get; }
    public ObservableCollection<RegistryOrphanCandidate> RegistryOrphans { get; }
    public ObservableCollection<DiskSpaceItem> TopDirectories { get; }
    public ObservableCollection<DiskSpaceItem> LargestFiles { get; }

    public bool PreservePasswordsAndAutofill
    {
        get => _preservePasswordsAndAutofill;
        set
        {
            if (SetProperty(ref _preservePasswordsAndAutofill, value))
            {
                OnPropertyChanged(nameof(VaultShieldBadgeText));
            }
        }
    }

    public bool PreserveBrowserSessions
    {
        get => _preserveBrowserSessions;
        set => SetProperty(ref _preserveBrowserSessions, value);
    }

    public bool CleanBrowserCaches
    {
        get => _cleanBrowserCaches;
        set => SetProperty(ref _cleanBrowserCaches, value);
    }

    public bool CleanSystemTempAndShaders
    {
        get => _cleanSystemTempAndShaders;
        set => SetProperty(ref _cleanSystemTempAndShaders, value);
    }

    public bool CleanRegistryOrphans
    {
        get => _cleanRegistryOrphans;
        set => SetProperty(ref _cleanRegistryOrphans, value);
    }

    public bool EmptyRecycleBin
    {
        get => _emptyRecycleBin;
        set => SetProperty(ref _emptyRecycleBin, value);
    }

    public bool IncludeDeveloperCaches
    {
        get => _includeDeveloperCaches;
        set => SetProperty(ref _includeDeveloperCaches, value);
    }

    public string VaultShieldBadgeText => PreservePasswordsAndAutofill
        ? "🔒 АКТИВНА БРОНЯ ЛИЧНЫХ ДАННЫХ: пароли, логины, автозаполнение форм и открытые аккаунты НЕ ТРОГАЮТСЯ"
        : "⚠️ Внимание: броня паролей отключена вручную (рекомендуется всегда держать включенной)";

    public bool IsScanning
    {
        get => _isScanning;
        private set
        {
            if (SetProperty(ref _isScanning, value))
            {
                OnPropertyChanged(nameof(CanExecuteClean));
            }
        }
    }

    public bool IsCleaning
    {
        get => _isCleaning;
        private set
        {
            if (SetProperty(ref _isCleaning, value))
            {
                OnPropertyChanged(nameof(CanExecuteClean));
            }
        }
    }

    public bool IsAnalyzingDisk
    {
        get => _isAnalyzingDisk;
        private set => SetProperty(ref _isAnalyzingDisk, value);
    }

    public bool CanExecuteClean =>
        !IsScanning &&
        !IsCleaning &&
        _lastScanReport is not null &&
        (_lastScanReport.TotalReclaimableBytes > 0 || _lastScanReport.TotalRegistryOrphansCount > 0);

    public bool HasBrowserWarnings => !string.IsNullOrWhiteSpace(BrowserWarningBanner);
    public bool HasRegistryOrphans => RegistryOrphans.Count > 0;
    public bool HasCleanupOutcome => !string.IsNullOrWhiteSpace(LastCleanupOutcome);
    public bool HasDiskMapResults => TopDirectories.Count > 0 || LargestFiles.Count > 0;

    public string ScanSummaryHeadline
    {
        get => _scanSummaryHeadline;
        private set => SetProperty(ref _scanSummaryHeadline, value);
    }

    public string BrowserWarningBanner
    {
        get => _browserWarningBanner;
        private set
        {
            if (SetProperty(ref _browserWarningBanner, value))
            {
                OnPropertyChanged(nameof(HasBrowserWarnings));
            }
        }
    }

    public string LastCleanupOutcome
    {
        get => _lastCleanupOutcome;
        private set
        {
            if (SetProperty(ref _lastCleanupOutcome, value))
            {
                OnPropertyChanged(nameof(HasCleanupOutcome));
            }
        }
    }

    public string DiskMapTargetPath
    {
        get => _diskMapTargetPath;
        set => SetProperty(ref _diskMapTargetPath, value);
    }

    public string DiskMapStatusText
    {
        get => _diskMapStatusText;
        private set => SetProperty(ref _diskMapStatusText, value);
    }

    public ICommand ScanPreviewCommand { get; }
    public AsyncRelayCommand ExecuteSafeCleanCommand { get; }
    public ICommand AnalyzeDiskSpaceCommand { get; }
    public ICommand SelectDiskPresetCommand { get; }

    public CleanupOptions BuildOptions() => new()
    {
        PreservePasswordsAndAutofill = PreservePasswordsAndAutofill,
        PreserveBrowserSessions = PreserveBrowserSessions,
        CleanBrowserCaches = CleanBrowserCaches,
        CleanSystemTempAndShaders = CleanSystemTempAndShaders,
        CleanRegistryOrphans = CleanRegistryOrphans,
        EmptyRecycleBin = EmptyRecycleBin,
        IncludeDeveloperCaches = IncludeDeveloperCaches,
        MinimumTempFileAgeHours = 24
    };

    public async Task RunScanPreviewAsync()
    {
        if (IsScanning || IsCleaning) return;

        IsScanning = true;
        LastCleanupOutcome = "";
        ScanSummaryHeadline = "Идет бережное сканирование кэша браузеров, временных папок и ссылок реестра...";

        try
        {
            var options = BuildOptions();
            var report = await _cleanerService.ScanAsync(options);
            _lastScanReport = report;

            Categories.Clear();
            foreach (var cat in report.Categories)
            {
                Categories.Add(cat);
            }

            RegistryOrphans.Clear();
            foreach (var orphan in report.RegistryOrphans.Take(50))
            {
                RegistryOrphans.Add(orphan);
            }

            OnPropertyChanged(nameof(HasRegistryOrphans));
            OnPropertyChanged(nameof(CanExecuteClean));
            ExecuteSafeCleanCommand.RaiseCanExecuteChanged();

            BrowserWarningBanner = report.RunningBrowserWarnings.Count > 0
                ? "ℹ️ " + string.Join(" ", report.RunningBrowserWarnings)
                : "";

            if (report.TotalReclaimableBytes == 0 && report.TotalRegistryOrphansCount == 0)
            {
                ScanSummaryHeadline = "✅ Система уже чиста! Лишнего кэша и битых ссылок реестра не обнаружено.";
            }
            else
            {
                ScanSummaryHeadline =
                    $"Готово к освобождению: {report.FormattedTotalReclaimable} ({report.TotalFilesCount:N0} файлов)" +
                    (report.TotalRegistryOrphansCount > 0
                        ? $" и {report.TotalRegistryOrphansCount} устаревших записей реестра"
                        : "");
            }

            await _onActionCompletedAsync($"Проверка очистки завершена: доступно {report.FormattedTotalReclaimable}");
        }
        catch (Exception ex)
        {
            ScanSummaryHeadline = $"Не удалось завершить сканирование: {ex.Message}";
        }
        finally
        {
            IsScanning = false;
            ExecuteSafeCleanCommand.RaiseCanExecuteChanged();
        }
    }

    public async Task ExecuteSafeCleanAsync()
    {
        if (_lastScanReport is null || IsCleaning || IsScanning) return;

        IsCleaning = true;
        try
        {
            var options = BuildOptions();
            var result = await _cleanerService.ExecuteCleanupAsync(_lastScanReport, options);

            LastCleanupOutcome = $"✨ {result.UserSummaryMessage}";
            _lastScanReport = null;
            Categories.Clear();
            RegistryOrphans.Clear();
            OnPropertyChanged(nameof(HasRegistryOrphans));
            OnPropertyChanged(nameof(CanExecuteClean));
            ExecuteSafeCleanCommand.RaiseCanExecuteChanged();

            ScanSummaryHeadline = $"Очистка успешно выполнена — освобождено {result.FormattedFreed}.";
            await _onActionCompletedAsync(result.UserSummaryMessage);
        }
        catch (Exception ex)
        {
            LastCleanupOutcome = $"⚠️ Очистка прервана защитным фильтром: {ex.Message}";
        }
        finally
        {
            IsCleaning = false;
            ExecuteSafeCleanCommand.RaiseCanExecuteChanged();
        }
    }

    public async Task AnalyzeDiskSpaceAsync()
    {
        if (IsAnalyzingDisk || string.IsNullOrWhiteSpace(DiskMapTargetPath)) return;

        IsAnalyzingDisk = true;
        DiskMapStatusText = $"Параллельное сканирование «{DiskMapTargetPath}» без перехода по символическим ссылкам...";

        try
        {
            var report = await _cleanerService.AnalyzeDiskSpaceAsync(DiskMapTargetPath, topDirectoryLimit: 10, largestFilesLimit: 10);

            TopDirectories.Clear();
            foreach (var dir in report.TopDirectories)
            {
                TopDirectories.Add(dir);
            }

            LargestFiles.Clear();
            foreach (var file in report.LargestFiles)
            {
                LargestFiles.Add(file);
            }

            OnPropertyChanged(nameof(HasDiskMapResults));

            DiskMapStatusText =
                $"Проверено {report.FormattedTotalScanned} ({report.TotalFilesCount:N0} файлов) за {report.Elapsed.TotalSeconds:F2} сек • {report.ScanMethodDescription}";

            await _onActionCompletedAsync($"Карта диска построена за {report.Elapsed.TotalSeconds:F2} сек ({report.FormattedTotalScanned})");
        }
        catch (Exception ex)
        {
            DiskMapStatusText = $"Не удалось проанализировать путь: {ex.Message}";
        }
        finally
        {
            IsAnalyzingDisk = false;
        }
    }

    private void ApplyDiskPreset(string presetKey)
    {
        var candidate = presetKey switch
        {
            "UserProfile" => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "Downloads" => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            "SystemDrive" => Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\",
            _ => DiskMapTargetPath
        };

        if (!string.IsNullOrWhiteSpace(candidate) && Directory.Exists(candidate))
        {
            DiskMapTargetPath = candidate;
            _ = AnalyzeDiskSpaceAsync();
        }
    }
}
