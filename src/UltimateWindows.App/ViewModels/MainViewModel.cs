using System.Collections.ObjectModel;
using System.Windows.Input;
using UltimateWindows.App.Infrastructure;
using UltimateWindows.Core.Contracts;
using UltimateWindows.Core.Enums;
using UltimateWindows.Core.Guards;
using UltimateWindows.Core.Models;
using UltimateWindows.Modules.Safety.Services;
using UltimateWindows.NativeInterop.Restore;
using UltimateWindows.NativeInterop.Security;

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
    public string StoredSizeText => $"Занято: {Record.FormattedStoredSize}";
    public bool IsPinned => Record.IsPinned;
    public bool CanRollback => !Record.IsReverted;
    public string StatusBadge => Record.IsReverted ? "Возвращено назад" : (Record.IsPinned ? "Закреплено 📌" : "Доступен откат");
    public string PinButtonText => Record.IsPinned ? "Открепить" : "📌 Закрепить";

    public ICommand RollbackCommand { get; }
    public ICommand TogglePinCommand { get; }
}

public sealed class MainViewModel : ObservableObject
{
    private readonly IVaultService _vaultService;

    private SystemDomain _selectedDomain = SystemDomain.HealthOverview;
    private bool _isExpertMode;
    private string _statusNotification = "Готово к работе • Пароли браузеров и личные данные под защитой";
    private string _vaultUsageText = "0 КБ из 250 МБ";
    private double _vaultUsagePercent;
    private int _activeCheckpointsCount;
    private int _maxBudgetMb = 250;
    private int _retentionDays = 14;
    private string _testPathInput = @"C:\Users\User\AppData\Local\Google\Chrome\User Data\Default\Login Data";
    private string _testPathVerdict = "🔒 СТРОГО ЗАЩИЩЕНО: база сохраненных паролей браузера никогда не удаляется.";

    public MainViewModel()
        : this(new ZeroBloatVaultService(stateApplier: new WindowsSystemStateApplier()))
    {
    }

    public MainViewModel(IVaultService vaultService)
    {
        _vaultService = vaultService;
        IsAdmin = ElevationChecker.IsRunningAsAdministrator();

        MaxBudgetMb = (int)(_vaultService.CurrentPolicy.MaxVaultBytes / VaultQuotaPolicy.Megabyte);
        RetentionDays = _vaultService.CurrentPolicy.FileBlobRetentionDays;

        OverviewCards = new ObservableCollection<HealthSummaryCard>(BuildDefaultCards());
        Transactions = new ObservableCollection<TransactionItemViewModel>();

        NavigateCommand = new RelayCommand(param =>
        {
            if (param is string domainName && Enum.TryParse<SystemDomain>(domainName, out var parsed))
            {
                SelectedDomain = parsed;
            }
        });

        CreateSampleCheckpointCommand = new AsyncRelayCommand(_ => CreateSampleSafeCheckpointAsync());
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

        _ = RefreshVaultStateAsync();
    }

    public bool IsAdmin { get; }

    public string PrivilegeBadgeText =>
        IsAdmin ? "Права Администратора активны" : "Обычный режим (безопасный просмотр)";

    public ObservableCollection<HealthSummaryCard> OverviewCards { get; }

    public ObservableCollection<TransactionItemViewModel> Transactions { get; }

    public SystemDomain SelectedDomain
    {
        get => _selectedDomain;
        set
        {
            if (SetProperty(ref _selectedDomain, value))
            {
                OnPropertyChanged(nameof(IsOverviewVisible));
                OnPropertyChanged(nameof(IsCleanerVisible));
                OnPropertyChanged(nameof(IsTimeMachineVisible));
                OnPropertyChanged(nameof(IsModulePreviewVisible));
                OnPropertyChanged(nameof(CurrentSectionTitle));
                OnPropertyChanged(nameof(CurrentSectionSubtitle));
            }
        }
    }

    public bool IsOverviewVisible => SelectedDomain == SystemDomain.HealthOverview;
    public bool IsCleanerVisible => SelectedDomain == SystemDomain.SmartCleaner;
    public bool IsTimeMachineVisible => SelectedDomain == SystemDomain.TimeMachineVault;
    public bool IsModulePreviewVisible =>
        SelectedDomain is not SystemDomain.HealthOverview
            and not SystemDomain.SmartCleaner
            and not SystemDomain.TimeMachineVault;

    public bool IsExpertMode
    {
        get => _isExpertMode;
        set
        {
            if (SetProperty(ref _isExpertMode, value))
            {
                OnPropertyChanged(nameof(ExperienceModeLabel));
            }
        }
    }

    public string ExperienceModeLabel =>
        IsExpertMode ? "Режим эксперта (тех. детали открыты)" : "Простой режим (понятный язык)";

    public string CurrentSectionTitle => SelectedDomain switch
    {
        SystemDomain.HealthOverview => "Здоровье и порядок системы",
        SystemDomain.SmartCleaner => "Бережная очистка без потери паролей",
        SystemDomain.Optimizer => "Умное ускорение и приватность",
        SystemDomain.AntiMiner => "Защита от скрытых майнеров",
        SystemDomain.DllAndRepair => "Доктор библиотек DLL и ошибок ОС",
        SystemDomain.HardwareAndDrivers => "Железо (AIDA-класс) и WHQL-драйверы",
        SystemDomain.TimeMachineVault => "Машина времени и не засоряющие ОС бэкапы",
        _ => "UltimateWindows"
    };

    public string CurrentSectionSubtitle => SelectedDomain switch
    {
        SystemDomain.HealthOverview => "Все ключевые инструменты в одном окне: понятно для новичка, прозрачно для профессионала и 100% обратимо.",
        SystemDomain.SmartCleaner => "Удаляем только безопасный кэш системы, видеокарт и браузеров. Пароли, вкладки и автозаполнение форм под замком.",
        SystemDomain.Optimizer => "Адаптивные настройки под ваше железо без вредных мифов и без поломки служб Windows.",
        SystemDomain.AntiMiner => "Поведенческий поиск тихих майнеров (включая прячущихся от Диспетчера задач) и восстановление заблокированных политик.",
        SystemDomain.DllAndRepair => "Диагностика ошибки 0xc000007b, официальные пакеты Visual C++ / DirectX / .NET и расшифровка синих экранов BSOD.",
        SystemDomain.HardwareAndDrivers => "Поиск скрытых потерь FPS (выключенный XMP, монитор 144 Гц на 60 Гц, перегрев Hotspot) и подписанные драйверы.",
        SystemDomain.TimeMachineVault => "Любое изменение занимает килобайты, сжимается и ограничено строгой квотой диска без мусора в системе.",
        _ => ""
    };

    public string StatusNotification
    {
        get => _statusNotification;
        set => SetProperty(ref _statusNotification, value);
    }

    public string VaultUsageText
    {
        get => _vaultUsageText;
        private set => SetProperty(ref _vaultUsageText, value);
    }

    public double VaultUsagePercent
    {
        get => _vaultUsagePercent;
        private set => SetProperty(ref _vaultUsagePercent, value);
    }

    public int ActiveCheckpointsCount
    {
        get => _activeCheckpointsCount;
        private set => SetProperty(ref _activeCheckpointsCount, value);
    }

    public int MaxBudgetMb
    {
        get => _maxBudgetMb;
        set => SetProperty(ref _maxBudgetMb, Math.Clamp(value, 32, 2048));
    }

    public int RetentionDays
    {
        get => _retentionDays;
        set => SetProperty(ref _retentionDays, Math.Clamp(value, 1, 90));
    }

    public string TestPathInput
    {
        get => _testPathInput;
        set => SetProperty(ref _testPathInput, value);
    }

    public string TestPathVerdict
    {
        get => _testPathVerdict;
        private set => SetProperty(ref _testPathVerdict, value);
    }

    public ICommand NavigateCommand { get; }
    public ICommand CreateSampleCheckpointCommand { get; }
    public ICommand SaveQuotaPolicyCommand { get; }
    public ICommand PurgeBlobsCommand { get; }
    public ICommand EvaluatePathCommand { get; }
    public ICommand FillSamplePathCommand { get; }

    public async Task RefreshVaultStateAsync()
    {
        var stats = await _vaultService.GetStorageStatsAsync();
        VaultUsageText = stats.FormattedUsage;
        VaultUsagePercent = stats.UsagePercentage;
        ActiveCheckpointsCount = stats.ActiveTransactionCount;

        var history = await _vaultService.GetHistoryAsync(50);
        Transactions.Clear();
        foreach (var rec in history)
        {
            Transactions.Add(new TransactionItemViewModel(
                rec,
                new AsyncRelayCommand(_ => RollbackAsync(rec.SessionId)),
                new AsyncRelayCommand(_ => TogglePinAsync(rec.SessionId, !rec.IsPinned))));
        }
    }

    private async Task CreateSampleSafeCheckpointAsync()
    {
        await using var session = _vaultService.BeginTransaction(
            SystemDomain.Optimizer,
            friendlyTitle: "Ускорение отклика меню и отключение рекламных советов Windows",
            friendlySummary: "Отключены навязчивые баннеры в меню «Пуск» и уменьшена задержка показа меню. Можно вернуть в 1 клик.",
            technicalDetails: @"HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SubscribedContent-338388Enabled: 1 -> 0; MenuShowDelay: 400 -> 100");

        session.RecordStateDelta(
            StateTargetKind.SystemSetting,
            @"HKCU\Control Panel\Desktop\MenuShowDelay",
            previousStateJson: "{\"Value\":\"400\"}",
            newStateJson: "{\"Value\":\"100\"}");

        var committed = await session.CommitAsync();
        StatusNotification = $"Создана точка отката «{committed.FriendlyTitle}» (размер всего {committed.FormattedStoredSize})";
        await RefreshVaultStateAsync();
    }

    private async Task RollbackAsync(Guid sessionId)
    {
        await _vaultService.RollbackTransactionAsync(sessionId);
        StatusNotification = "Изменения успешно отменены — система возвращена в исходное состояние.";
        await RefreshVaultStateAsync();
    }

    private async Task TogglePinAsync(Guid sessionId, bool pin)
    {
        await _vaultService.SetPinnedAsync(sessionId, pin);
        StatusNotification = pin
            ? "Точка отката закреплена и защищена от автоочистки."
            : "Закрепление снято — точка подчиняется общему сроку хранения.";
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
        StatusNotification = $"Лимит бэкапов обновлен: максимум {MaxBudgetMb} МБ, автоочистка карантина через {RetentionDays} дн.";
        await RefreshVaultStateAsync();
    }

    private async Task PurgeUnpinnedBlobsAsync()
    {
        var removed = await _vaultService.PurgeAllUnpinnedBlobsAsync();
        StatusNotification = $"Очищено файловых архивов карантина: {removed}. Микро-записи отката настроек сохранены.";
        await RefreshVaultStateAsync();
    }

    private void EvaluateSamplePath()
    {
        var decision = BrowserVaultGuard.EvaluatePath(TestPathInput);
        TestPathVerdict = decision switch
        {
            VaultPathDecision.ProtectedCredentialsOrAutofill =>
                "🔒 СТРОГО ЗАЩИЩЕНО: пароли, ключи шифрования, закладки или автозаполнение форм. Удаление заблокировано на уровне ядра.",
            VaultPathDecision.ProtectedSessionOrExtension =>
                "🛡️ ЗАЩИЩЕНО: активные сессии входа, вкладки или хранилище расширений (2FA / кошельки). Не удаляется при стандартной очистке.",
            VaultPathDecision.SafeDisposableCache =>
                "✅ БЕЗОПАСНЫЙ КЭШ: временные файлы кэша/шейдеров. Можно смело очищать без потери паролей и настроек!",
            _ =>
                "ℹ️ НЕЙТРАЛЬНЫЙ ПУТЬ: не удаляется автоматически без явного проверенного правила."
        };
    }

    private static IReadOnlyList<HealthSummaryCard> BuildDefaultCards() =>
    [
        new(
            SystemDomain.SmartCleaner,
            "🧹",
            "Бережная очистка места",
            "Удаляет гигабайты кэша браузеров, временных файлов и старых шейдеров видеокарты. Пароли, открытые вкладки и автозаполнение форм остаются нетронутыми.",
            "Фильтр BrowserVaultGuard блокирует Login Data, Web Data, Local State, logins.json, key4.db, formhistory.sqlite. Карта диска через чтение NTFS $MFT + верифицированная чистка сирот реестра.",
            "Пароли под замком 🔒",
            RiskLevel.Safe,
            95,
            "Открыть очистку"),

        new(
            SystemDomain.Optimizer,
            "⚡",
            "Ускорение и тишина в фоне",
            "Убирает лишние программы из автозагрузки, отключает навязчивую рекламу и фоновую телеметрию с учетом типа вашего диска (SSD/HDD).",
            "Декларативные YAML-правила в стиле OptimizerNXT с предварительным чтением исходных значений реестра/служб в SQLite-журнал и анализом контекстного меню ShellEx.",
            "100% обратимо",
            RiskLevel.Safe,
            90,
            "Настроить систему"),

        new(
            SystemDomain.AntiMiner,
            "🛡️",
            "Поиск скрытых майнеров",
            "Находит вредоносные майнеры, даже если они хитро выключаются при открытии Диспетчера задач, и лечит заблокированные ими настройки системы.",
            "ETW/PDH детект просадки GPU/CPU (Drop-on-Inspect), анализ Stratum TCP-соединений, проверка подписи системных процессов CryptCATAdmin, ревизия WMI, скрытых задач без SD и IFEO.",
            "Стелс-защита",
            RiskLevel.Safe,
            100,
            "Проверить на майнеры"),

        new(
            SystemDomain.DllAndRepair,
            "🧩",
            "Лечение ошибок, BSOD и DLL",
            "Чинит не запускающиеся игры и программы (ошибка 0xc000007b, нехватка vcruntime/d3dx9) установкой официальных пакетов Microsoft без риска занести вирус.",
            "Разбор PE-заголовков и таблицы импорта (x86 SysWOW64 vs x64 System32), пакеты VC++ 2005-2022 / DirectX June 2010 / .NET с проверкой WinVerifyTrust + парсер минидампов BSOD и DISM/SFC.",
            "Официальные пакеты",
            RiskLevel.Safe,
            92,
            "Диагностика ошибок"),

        new(
            SystemDomain.HardwareAndDrivers,
            "🖥️",
            "Железо (AIDA-класс) и Драйверы",
            "Показывает температуры, ресурс SSD и подсказывает, где теряется мощность ПК (например, если экран 144 Гц работает на 60 Гц или не включен профиль памяти XMP).",
            "Гибридный опрос NVAPI/ADLX/IGCL, SMBIOS, EDID, NVMe S.M.A.R.T. IOCTL и PawnIO (без уязвимого WinRing0). Драйверы по 4-компонентному Hardware ID через WUApiLib без дублирования DriverStore.",
            "Совместимо с HVCI",
            RiskLevel.Safe,
            94,
            "Анализ железа"),

        new(
            SystemDomain.TimeMachineVault,
            "⏱️",
            "Машина времени (Не засоряет ПК)",
            "Хранит историю всех улучшений, занимая считанные килобайты благодаря сжатию и автоочистке старых архивов. Вернуть всё как было можно одной кнопкой.",
            "SQLite (auto_vacuum = INCREMENTAL) + CAS-хранилище SHA-256 со сжатием Brotli (Optimal) и шифрованием AES-256-GCM. Жесткий потолок min(250 МБ, 0.5% свободного места) + TTL 14 дней.",
            "Zero-Bloat квота",
            RiskLevel.Safe,
            100,
            "Открыть историю")
    ];
}
