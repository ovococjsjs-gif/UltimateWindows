using System.Text;
using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Optimizer.Models;

namespace UltimateWindows.Modules.Optimizer.Catalog;

/// <summary>
/// Барьер безопасности твиков. Делит вмешательства в защиту Windows на два вида:
/// 1) запрещённые всегда — обход активации и лицензирования Windows;
/// 2) ослабляющие защиту (Защитник, SmartScreen, защита ядра HVCI, контроль учётных записей) — допустимы
///    только в правилах, честно помеченных как опасные (<see cref="RiskLevel.High"/> и выше).
/// Опасное правило не входит в наборы и применяется лишь после отдельного подтверждения пользователя,
/// поэтому оно не может включиться «заодно» или под видом безобидной настройки.
/// </summary>
public static class TweakSafetyGuard
{
    private static readonly string[] AlwaysForbiddenKeyFragments =
    [
        @"SOFTWAREPROTECTIONPLATFORM"
    ];

    private static readonly string[] ProtectionWeakeningKeyFragments =
    [
        @"WINDOWS DEFENDER",
        @"DISABLEANTISPYWARE",
        @"DISABLEREALTIMEMONITORING",
        @"WINDEFEND",
        @"SMARTSCREEN",
        @"DEVICEGUARD\SCENARIOS\HYPERVISORENFORCEDCODEINTEGRITY",
        @"WINDOWS\CURRENTVERSION\POLICIES\SYSTEM\ENABLELUA"
    ];

    /// <summary>
    /// Изменение недопустимо ни при каких условиях.
    /// </summary>
    public static bool IsAlwaysForbidden(TweakRegistryMutation mutation) =>
        ContainsAnyFragment(mutation, AlwaysForbiddenKeyFragments);

    /// <summary>
    /// Изменение ослабляет защиту Windows и допустимо только в опасном правиле.
    /// </summary>
    public static bool WeakensSystemProtection(TweakRegistryMutation mutation) =>
        ContainsAnyFragment(mutation, ProtectionWeakeningKeyFragments);

    /// <summary>
    /// Изменение безопасно: оно не трогает ни защиту Windows, ни лицензирование.
    /// </summary>
    public static bool IsSafeAllowedMutation(TweakRegistryMutation mutation)
    {
        if (mutation is null || string.IsNullOrWhiteSpace(mutation.SubKeyPath))
        {
            return false;
        }

        return !IsAlwaysForbidden(mutation) && !WeakensSystemProtection(mutation);
    }

    public static void ThrowIfUnsafeRule(DeclarativeTweakRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        foreach (var m in rule.Mutations)
        {
            if (m is null || string.IsNullOrWhiteSpace(m.SubKeyPath))
            {
                throw new InvalidOperationException(
                    $"В правиле '{rule.TweakId}' есть изменение без пути раздела реестра.");
            }

            if (IsAlwaysForbidden(m))
            {
                throw new InvalidOperationException(
                    $"Защитный фильтр TweakSafetyGuard заблокировал правило '{rule.TweakId}': вмешательство в лицензирование Windows запрещено ({m.SubKeyPath}).");
            }

            if (WeakensSystemProtection(m) && !rule.IsDangerous)
            {
                throw new InvalidOperationException(
                    $"Защитный фильтр TweakSafetyGuard заблокировал правило '{rule.TweakId}': оно ослабляет защиту Windows ({m.SubKeyPath}) и должно быть помечено как опасное.");
            }
        }
    }

    private static bool ContainsAnyFragment(TweakRegistryMutation? mutation, string[] fragments)
    {
        if (mutation is null)
        {
            return false;
        }

        var combined = $@"{mutation.Hive}\{mutation.SubKeyPath}\{mutation.ValueName}"
            .Replace('/', '\\')
            .ToUpperInvariant();

        foreach (var fragment in fragments)
        {
            if (combined.Contains(fragment, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}

/// <summary>
/// Каталог встроенных обратимых твиков Windows 10/11. Каждое включение записывается в журнал отката.
/// У твиков, которые подходят не всякому компьютеру, заданы условия применимости (<see cref="TweakRequirements"/>).
/// </summary>
public static class DeclarativeTweakCatalog
{
    private static readonly IReadOnlyList<DeclarativeTweakRule> BuiltInRules =
    [
        // ==================== 1. СИСТЕМА И ОТЗЫВЧИВОСТЬ (8 ТВИКОВ) ====================
        new(
            TweakId: "sys.disable-error-reporting-wer",
            Category: TweakCategory.SystemAndPerformance,
            IconGlyph: "SYS",
            FriendlyTitle: "Отключить отчеты об ошибках Windows (WER)",
            FriendlyExplanation: "Прекращает фоновый сбор и отправку тяжелых дампов при закрытии программ.",
            ImpactBadge: "Меньше фоновой нагрузки",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: true,
            Mutations:
            [
                new("HKLM", @"SOFTWARE\Microsoft\Windows\Windows Error Reporting", "Disabled", RegistryTweakValueKind.DWord, "1", "0", ExistedByDefault: false)
            ]),

        new(
            TweakId: "sys.disable-compatibility-assistant",
            Category: TweakCategory.SystemAndPerformance,
            IconGlyph: "SYS",
            FriendlyTitle: "Отключить Помощника по совместимости программ (PCA)",
            FriendlyExplanation: "Отключает фоновое отслеживание старых установщиков службой Program Compatibility Assistant.",
            ImpactBadge: "Экономия ресурсов",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: true,
            Mutations:
            [
                new("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\AppCompat", "DisablePCA", RegistryTweakValueKind.DWord, "1", "0", ExistedByDefault: false)
            ]),

        new(
            TweakId: "sys.disable-sticky-keys",
            Category: TweakCategory.SystemAndPerformance,
            IconGlyph: "SYS",
            FriendlyTitle: "Отключить залипание и фильтрацию клавиш (5× Shift)",
            FriendlyExplanation: "Убирает раздражающее системное окно с писком при частом нажатии Shift в играх и работе.",
            ImpactBadge: "Без вылетов из игр",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: false,
            Mutations:
            [
                new("HKCU", @"Control Panel\Accessibility\StickyKeys", "Flags", RegistryTweakValueKind.String, "506", "510", ExistedByDefault: true),
                new("HKCU", @"Control Panel\Accessibility\Keyboard Response", "Flags", RegistryTweakValueKind.String, "122", "126", ExistedByDefault: true),
                new("HKCU", @"Control Panel\Accessibility\ToggleKeys", "Flags", RegistryTweakValueKind.String, "58", "62", ExistedByDefault: true)
            ]),

        new(
            TweakId: "sys.fast-shutdown-auto-end-tasks",
            Category: TweakCategory.SystemAndPerformance,
            IconGlyph: "SYS",
            FriendlyTitle: "Быстрое выключение и перезагрузка без ожидания зависших окон",
            FriendlyExplanation: "Сокращает таймаут завершения фоновых процессов и служб с 5–20 секунд до 2 секунд.",
            ImpactBadge: "Быстрое выключение",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: false,
            Mutations:
            [
                new("HKCU", @"Control Panel\Desktop", "AutoEndTasks", RegistryTweakValueKind.String, "1", "0", ExistedByDefault: false),
                new("HKCU", @"Control Panel\Desktop", "WaitToKillAppTimeout", RegistryTweakValueKind.String, "2000", "20000", ExistedByDefault: false),
                new("HKCU", @"Control Panel\Desktop", "HungAppTimeout", RegistryTweakValueKind.String, "1000", "5000", ExistedByDefault: false)
            ]),

        new(
            TweakId: "sys.disable-print-spooler",
            Category: TweakCategory.SystemAndPerformance,
            IconGlyph: "SYS",
            FriendlyTitle: "Отключить службу печати (если у вас нет принтера)",
            FriendlyExplanation: "Останавливает фоновый диспетчер очереди печати Spooler (включите обратно при подключении принтера).",
            ImpactBadge: "Минус фоновая служба",
            Risk: RiskLevel.Low,
            RequiresAdministrator: true,
            Mutations:
            [
                new("HKLM", @"SYSTEM\CurrentControlSet\Services\Spooler", "Start", RegistryTweakValueKind.DWord, "4", "2", ExistedByDefault: true)
            ]),

        new(
            TweakId: "sys.disable-fax-service",
            Category: TweakCategory.SystemAndPerformance,
            IconGlyph: "SYS",
            FriendlyTitle: "Отключить устаревшую службу Факса (Fax)",
            FriendlyExplanation: "Отключает неиспользуемую службу факсимильной связи Windows.",
            ImpactBadge: "Чистые службы",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: true,
            Mutations:
            [
                new("HKLM", @"SYSTEM\CurrentControlSet\Services\Fax", "Start", RegistryTweakValueKind.DWord, "4", "3", ExistedByDefault: true)
            ]),

        new(
            TweakId: "sys.svchost-split-threshold-ram",
            Category: TweakCategory.SystemAndPerformance,
            IconGlyph: "SYS",
            FriendlyTitle: "Объединить процессы svchost.exe для ПК с 16–64 ГБ ОЗУ",
            FriendlyExplanation: "Уменьшает количество разрозненных процессов svchost.exe в Диспетчере задач и накладные расходы дескрипторов.",
            ImpactBadge: "Меньше процессов",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: true,
            Mutations:
            [
                // Стандартное значение Windows — 0x380000 КБ (3,5 ГБ), то есть 3670016 в десятичной записи
                new("HKLM", @"SYSTEM\CurrentControlSet\Control", "SvcHostSplitThresholdInKB", RegistryTweakValueKind.DWord, "67108864", "3670016", ExistedByDefault: true)
            ]),

        new(
            TweakId: "sys.enable-win32-long-paths",
            Category: TweakCategory.SystemAndPerformance,
            IconGlyph: "SYS",
            FriendlyTitle: "Снять устаревшее ограничение длины пути 260 символов (MAX_PATH)",
            FriendlyExplanation: "Разрешает архиваторам, Git, компиляторам и современным программам работать с глубокими вложенными папками.",
            ImpactBadge: "Без ошибок длинных путей",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: true,
            Mutations:
            [
                new("HKLM", @"SYSTEM\CurrentControlSet\Control\FileSystem", "LongPathsEnabled", RegistryTweakValueKind.DWord, "1", "0", ExistedByDefault: true)
            ]),

        // ==================== 2. ДИСКОВЫЙ ПРИВОД И SSD (6 ТВИКОВ) ====================
        new(
            TweakId: "disk.disable-ntfs-last-access-timestamp",
            Category: TweakCategory.DiskAndFileSystem,
            IconGlyph: "DSK",
            FriendlyTitle: "Отключить запись временной метки последнего чтения NTFS",
            FriendlyExplanation: "Прекращает лишнюю перезапись метаданных на SSD при каждом чтении тысяч мелких файлов.",
            ImpactBadge: "Ресурс и скорость SSD",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: true,
            Mutations:
            [
                new("HKLM", @"SYSTEM\CurrentControlSet\Control\FileSystem", "NtfsDisableLastAccessUpdate", RegistryTweakValueKind.DWord, "1", "0", ExistedByDefault: true)
            ]),

        new(
            TweakId: "disk.disable-8dot3-legacy-names",
            Category: TweakCategory.DiskAndFileSystem,
            IconGlyph: "DSK",
            FriendlyTitle: "Отключить генерацию устаревших коротких имен MS-DOS (8.3)",
            FriendlyExplanation: "Ускоряет создание и перечисление больших папок с десятками тысяч файлов на томах NTFS.",
            ImpactBadge: "Быстрые папки NTFS",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: true,
            Mutations:
            [
                new("HKLM", @"SYSTEM\CurrentControlSet\Control\FileSystem", "NtfsDisable8dot3NameCreation", RegistryTweakValueKind.DWord, "1", "2", ExistedByDefault: true)
            ]),

        new(
            TweakId: "disk.disable-superfetch-sysmain",
            Category: TweakCategory.DiskAndFileSystem,
            IconGlyph: "DSK",
            FriendlyTitle: "Отключить Superfetch (SysMain) на быстрых NVMe / SSD",
            FriendlyExplanation: "Убирает постоянную фоновую подгрузку на диск от службы SysMain (рекомендуется для SSD).",
            ImpactBadge: "Без фоновых чтений диска",
            Risk: RiskLevel.Low,
            RequiresAdministrator: true,
            Mutations:
            [
                new("HKLM", @"SYSTEM\CurrentControlSet\Services\SysMain", "Start", RegistryTweakValueKind.DWord, "4", "2", ExistedByDefault: true)
            ],
            Requirements: new TweakRequirements(BestOnSolidStateSystemDrive: true)),

        new(
            TweakId: "disk.disable-hibernation-boot-files",
            Category: TweakCategory.DiskAndFileSystem,
            IconGlyph: "DSK",
            FriendlyTitle: "Отключить спящий режим гибернации в реестре питания",
            FriendlyExplanation: "Освобождает место от файла гибернации на системном SSD и выключает неполное завершение Fast Startup.",
            ImpactBadge: "Освобождает ГБ на C:\\",
            Risk: RiskLevel.Low,
            RequiresAdministrator: true,
            Mutations:
            [
                new("HKLM", @"SYSTEM\CurrentControlSet\Control\Power", "HibernateEnabled", RegistryTweakValueKind.DWord, "0", "1", ExistedByDefault: true)
            ],
            Requirements: new TweakRequirements(
                BatteryWarning: "Это устройство с батареей. Без гибернации при полной разрядке во сне несохранённые данные будут потеряны.")),

        new(
            TweakId: "disk.disable-windows-search-indexer",
            Category: TweakCategory.DiskAndFileSystem,
            IconGlyph: "DSK",
            FriendlyTitle: "Отключить фоновое индексирование диска (Windows Search)",
            FriendlyExplanation: "Останавливает постоянное сканирование дисков службой WSearch (обычный поиск по именам продолжает работать).",
            ImpactBadge: "Тишина диска и CPU",
            Risk: RiskLevel.Low,
            RequiresAdministrator: true,
            Mutations:
            [
                new("HKLM", @"SYSTEM\CurrentControlSet\Services\WSearch", "Start", RegistryTweakValueKind.DWord, "4", "2", ExistedByDefault: true)
            ]),

        new(
            TweakId: "disk.disable-ntfs-efs-overhead",
            Category: TweakCategory.DiskAndFileSystem,
            IconGlyph: "DSK",
            FriendlyTitle: "Отключить устаревшую подсистему файлового шифрования EFS",
            FriendlyExplanation: "Убирает накладные проверки драйвера NTFS EFS на домашних ПК (не влияет на BitLocker).",
            ImpactBadge: "Меньше накладных вызовов",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: true,
            Mutations:
            [
                new("HKLM", @"SYSTEM\CurrentControlSet\Control\FileSystem", "NtfsDisableEncryption", RegistryTweakValueKind.DWord, "1", "0", ExistedByDefault: true)
            ]),

        // ==================== 3. ТЕЛЕМЕТРИЯ СТОРОННИХ ПРИЛОЖЕНИЙ (6 ТВИКОВ — КАК В OPTIMIZER) ====================
        new(
            TweakId: "app.disable-office-telemetry",
            Category: TweakCategory.AppTelemetry,
            IconGlyph: "APP",
            FriendlyTitle: "Отключить телеметрию Microsoft Office (2016 / 2019 / 2021 / 365)",
            FriendlyExplanation: "Отключает фоновых агентов логирования и отправки документов диагностической телеметрии Office.",
            ImpactBadge: "Office без слежки",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: false,
            Mutations:
            [
                new("HKCU", @"Software\Policies\Microsoft\Office\16.0\osm", "Enablelogging", RegistryTweakValueKind.DWord, "0", "1", ExistedByDefault: false),
                new("HKCU", @"Software\Policies\Microsoft\Office\16.0\osm", "EnableUpload", RegistryTweakValueKind.DWord, "0", "1", ExistedByDefault: false),
                new("HKCU", @"Software\Policies\Microsoft\Office\Common\ClientTelemetry", "DisableTelemetry", RegistryTweakValueKind.DWord, "1", "0", ExistedByDefault: false)
            ]),

        new(
            TweakId: "app.disable-firefox-telemetry",
            Category: TweakCategory.AppTelemetry,
            IconGlyph: "APP",
            FriendlyTitle: "Отключить телеметрию Mozilla Firefox",
            FriendlyExplanation: "Применяет официальную корпоративную политику Mozilla для запрета фоновой отправки телеметрии.",
            ImpactBadge: "Firefox приватность",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: true,
            Mutations:
            [
                new("HKLM", @"SOFTWARE\Policies\Mozilla\Firefox", "DisableTelemetry", RegistryTweakValueKind.DWord, "1", "0", ExistedByDefault: false),
                new("HKLM", @"SOFTWARE\Policies\Mozilla\Firefox", "DisableDefaultBrowserAgent", RegistryTweakValueKind.DWord, "1", "0", ExistedByDefault: false)
            ]),

        new(
            TweakId: "app.disable-chrome-telemetry",
            Category: TweakCategory.AppTelemetry,
            IconGlyph: "APP",
            FriendlyTitle: "Отключить телеметрию и фоновый сканер Google Chrome",
            FriendlyExplanation: "Отключает сбор метрик использования и тяжелый фоновый Software Reporter Tool в Chrome.",
            ImpactBadge: "Chrome без нагрузки CPU",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: true,
            Mutations:
            [
                new("HKLM", @"SOFTWARE\Policies\Google\Chrome", "MetricsReportingEnabled", RegistryTweakValueKind.DWord, "0", "1", ExistedByDefault: false),
                new("HKLM", @"SOFTWARE\Policies\Google\Chrome", "ChromeCleanupEnabled", RegistryTweakValueKind.DWord, "0", "1", ExistedByDefault: false),
                new("HKLM", @"SOFTWARE\Policies\Google\Chrome", "ChromeCleanupReportingEnabled", RegistryTweakValueKind.DWord, "0", "1", ExistedByDefault: false)
            ]),

        new(
            TweakId: "app.disable-edge-telemetry-bloat",
            Category: TweakCategory.AppTelemetry,
            IconGlyph: "APP",
            FriendlyTitle: "Отключить фоновый автозапуск и рекламную телеметрию Microsoft Edge",
            FriendlyExplanation: "Запрещает Edge держаться в памяти после закрытия окна и отключает персонализацию рекламы.",
            ImpactBadge: "Освобождает ОЗУ",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: true,
            Mutations:
            [
                new("HKLM", @"SOFTWARE\Policies\Microsoft\Edge", "StartupBoostEnabled", RegistryTweakValueKind.DWord, "0", "1", ExistedByDefault: false),
                new("HKLM", @"SOFTWARE\Policies\Microsoft\Edge", "BackgroundModeEnabled", RegistryTweakValueKind.DWord, "0", "1", ExistedByDefault: false),
                new("HKLM", @"SOFTWARE\Policies\Microsoft\Edge", "PersonalizationReportingEnabled", RegistryTweakValueKind.DWord, "0", "1", ExistedByDefault: false)
            ]),

        new(
            TweakId: "app.disable-visualstudio-telemetry",
            Category: TweakCategory.AppTelemetry,
            IconGlyph: "APP",
            FriendlyTitle: "Отключить телеметрию Visual Studio и SDK",
            FriendlyExplanation: "Отключает фоновый сбор диагностических сессий Visual Studio Customer Experience Improvement.",
            ImpactBadge: "Чистая среда разработки",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: false,
            Mutations:
            [
                new("HKCU", @"Software\Microsoft\VisualStudio\Telemetry", "TurnOffSwitch", RegistryTweakValueKind.DWord, "1", "0", ExistedByDefault: false),
                new("HKCU", @"Software\Policies\Microsoft\VisualStudio\SQM", "OptIn", RegistryTweakValueKind.DWord, "0", "1", ExistedByDefault: false)
            ]),

        new(
            TweakId: "app.disable-nvidia-telemetry-overlay-spam",
            Category: TweakCategory.AppTelemetry,
            IconGlyph: "APP",
            FriendlyTitle: "Отключить фоновую телеметрию драйвера NVIDIA",
            FriendlyExplanation: "Отключает сбор статистики использования в панели NVIDIA без затрагивания игровых профилей и драйвера.",
            ImpactBadge: "Чистый видеодрайвер",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: false,
            Mutations:
            [
                new("HKCU", @"Software\NVIDIA Corporation\NVControlPanel2\Client", "OptInOrOutPreference", RegistryTweakValueKind.DWord, "0", "1", ExistedByDefault: false)
            ]),

        // ==================== 4. КОНФИДЕНЦИАЛЬНОСТЬ И ФОНОВЫЙ ШУМ (6 ТВИКОВ) ====================
        new(
            TweakId: "quiet.reduce-windows-diagnostic-telemetry",
            Category: TweakCategory.QuietBackgroundAndAds,
            IconGlyph: "PRV",
            FriendlyTitle: "Снизить сбор диагностической телеметрии Windows до минимума",
            FriendlyExplanation: "Ограничивает отправку диагностических логов ОС и отключает службу обратной связи сисадмина.",
            ImpactBadge: "Приватность ОС",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: true,
            Mutations:
            [
                new("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", RegistryTweakValueKind.DWord, "0", "3", ExistedByDefault: false),
                new("HKCU", @"Software\Microsoft\Siuf\Rules", "NumberOfSIUFInPeriod", RegistryTweakValueKind.DWord, "0", "1", ExistedByDefault: false)
            ]),

        new(
            TweakId: "quiet.disable-start-menu-bing-web-search",
            Category: TweakCategory.QuietBackgroundAndAds,
            IconGlyph: "PRV",
            FriendlyTitle: "Локальный поиск в меню «Пуск» без медленных запросов в Bing",
            FriendlyExplanation: "Поиск в меню «Пуск» мгновенно ищет только ваши локальные файлы и программы на ПК.",
            ImpactBadge: "Мгновенный Пуск",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: false,
            Mutations:
            [
                new("HKCU", @"Software\Policies\Microsoft\Windows\Explorer", "DisableSearchBoxSuggestions", RegistryTweakValueKind.DWord, "1", "0", ExistedByDefault: false)
            ]),

        new(
            TweakId: "quiet.disable-ads-and-lockscreen-tips",
            Category: TweakCategory.QuietBackgroundAndAds,
            IconGlyph: "PRV",
            FriendlyTitle: "Отключить рекламный ID, промо-советы в «Пуске» и на экране блокировки",
            FriendlyExplanation: "Убирает всплывающие предложения сторонних игр, промо-баннеры и рекламный идентификатор.",
            ImpactBadge: "Без рекламы в ОС",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: false,
            Mutations:
            [
                new("HKCU", @"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", RegistryTweakValueKind.DWord, "0", "1", ExistedByDefault: true),
                new("HKCU", @"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SubscribedContent-338388Enabled", RegistryTweakValueKind.DWord, "0", "1", ExistedByDefault: true),
                new("HKCU", @"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "RotatingLockScreenOverlayEnabled", RegistryTweakValueKind.DWord, "0", "1", ExistedByDefault: true),
                new("HKCU", @"Software\Microsoft\Windows\CurrentVersion\Privacy", "TailoredExperiencesWithDiagnosticDataEnabled", RegistryTweakValueKind.DWord, "0", "1", ExistedByDefault: true)
            ]),

        new(
            TweakId: "quiet.disable-activity-history-timeline",
            Category: TweakCategory.QuietBackgroundAndAds,
            IconGlyph: "PRV",
            FriendlyTitle: "Отключить сбор истории активности и облачную отправку таймлайна",
            FriendlyExplanation: "Прекращает ведение журнала открываемых файлов и программ для облачной синхронизации.",
            ImpactBadge: "Приватность истории",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: true,
            Mutations:
            [
                new("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\System", "EnableActivityFeed", RegistryTweakValueKind.DWord, "0", "1", ExistedByDefault: false),
                new("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\System", "PublishUserActivities", RegistryTweakValueKind.DWord, "0", "1", ExistedByDefault: false),
                new("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\System", "UploadUserActivities", RegistryTweakValueKind.DWord, "0", "1", ExistedByDefault: false)
            ]),

        new(
            TweakId: "quiet.disable-media-player-network-sharing",
            Category: TweakCategory.QuietBackgroundAndAds,
            IconGlyph: "PRV",
            FriendlyTitle: "Отключить сетевой общий доступ к медиабиблиотекам Windows Media",
            FriendlyExplanation: "Закрывает фоновое вещание домашней медиабиблиотеки по локальной сети.",
            ImpactBadge: "Меньше открытых служб",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: true,
            Mutations:
            [
                new("HKLM", @"SOFTWARE\Policies\Microsoft\WindowsMediaPlayer", "PreventLibrarySharing", RegistryTweakValueKind.DWord, "1", "0", ExistedByDefault: false)
            ]),

        new(
            TweakId: "quiet.disable-cortana-and-copilot",
            Category: TweakCategory.QuietBackgroundAndAds,
            IconGlyph: "PRV",
            FriendlyTitle: "Отключить фоновые помощники Cortana и Windows Copilot",
            FriendlyExplanation: "Отключает фоновых голосовых и ИИ-ассистентов на панели задач для экономии ОЗУ.",
            ImpactBadge: "Чистая панель задач",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: false,
            Mutations:
            [
                new("HKCU", @"Software\Policies\Microsoft\Windows\WindowsCopilot", "TurnOffWindowsCopilot", RegistryTweakValueKind.DWord, "1", "0", ExistedByDefault: false)
            ]),

        // ==================== 5. ИНТЕРФЕЙС WINDOWS 10 / 11 (5 ТВИКОВ) ====================
        new(
            TweakId: "ui.fast-menu-response",
            Category: TweakCategory.UiAndResponsiveness,
            IconGlyph: "UI",
            FriendlyTitle: "Мгновенный отклик контекстных меню Проводника (20 мс вместо 400 мс)",
            FriendlyExplanation: "Уменьшает задержку раскрытия меню Windows с 400 мс до 20 мс.",
            ImpactBadge: "Отклик UI в 20× быстрее",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: false,
            Mutations:
            [
                new("HKCU", @"Control Panel\Desktop", "MenuShowDelay", RegistryTweakValueKind.String, "20", "400", ExistedByDefault: true)
            ]),

        new(
            TweakId: "ui.win11-classic-full-context-menu",
            Category: TweakCategory.UiAndResponsiveness,
            IconGlyph: "UI",
            FriendlyTitle: "Полное классическое контекстное меню в Windows 11",
            FriendlyExplanation: "Сразу открывает полное меню правого клика без лишнего нажатия «Показать дополнительные параметры».",
            ImpactBadge: "Удобный правый клик",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: false,
            Mutations:
            [
                new("HKCU", @"Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32", "", RegistryTweakValueKind.String, "", "", ExistedByDefault: false)
            ],
            Requirements: new TweakRequirements(MinWindowsBuild: 22000)),

        new(
            TweakId: "ui.taskbar-end-task-button",
            Category: TweakCategory.UiAndResponsiveness,
            IconGlyph: "UI",
            FriendlyTitle: "Кнопка «Завершить задачу» правым кликом по панели задач Windows 11",
            FriendlyExplanation: "Штатная опция для мгновенного закрытия зависшего окна прямо с панели задач.",
            ImpactBadge: "Закрытие в 1 клик",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: false,
            Mutations:
            [
                new("HKCU", @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings", "TaskbarEndTask", RegistryTweakValueKind.DWord, "1", "0", ExistedByDefault: false)
            ],
            Requirements: new TweakRequirements(MinWindowsBuild: 22631)),

        new(
            TweakId: "ui.explorer-open-this-pc",
            Category: TweakCategory.UiAndResponsiveness,
            IconGlyph: "UI",
            FriendlyTitle: "Открывать Проводник сразу на «Этот компьютер» (диски C:\\, D:\\)",
            FriendlyExplanation: "При нажатии Win+E сразу открывает список дисков вместо рекламного экрана «Главная / Быстрый доступ».",
            ImpactBadge: "Удобный Проводник",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: false,
            Mutations:
            [
                new("HKCU", @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "LaunchTo", RegistryTweakValueKind.DWord, "1", "2", ExistedByDefault: false)
            ]),

        new(
            TweakId: "ui.hide-widgets-and-news-interests",
            Category: TweakCategory.UiAndResponsiveness,
            IconGlyph: "UI",
            FriendlyTitle: "Отключить панель «Виджеты / Новости и интересы» (экономия 150–300 МБ ОЗУ)",
            FriendlyExplanation: "Убирает фоновый браузерный процесс виджетов погоды и новостей с панели задач Windows 10 и 11.",
            ImpactBadge: "Минус WebView2 в фоне",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: false,
            Mutations:
            [
                new("HKCU", @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "TaskbarDa", RegistryTweakValueKind.DWord, "0", "1", ExistedByDefault: false),
                new("HKCU", @"Software\Microsoft\Windows\CurrentVersion\Feeds", "ShellFeedsTaskbarViewMode", RegistryTweakValueKind.DWord, "2", "0", ExistedByDefault: false)
            ]),

        // ==================== 6. ИГРЫ, МЫШЬ И СЕТЬ (5 ТВИКОВ) ====================
        new(
            TweakId: "gaming.mmcss-low-latency-profile",
            Category: TweakCategory.GamingAndLatency,
            IconGlyph: "GAM",
            FriendlyTitle: "Отключить троттлинг сети и повысить приоритет игр (MMCSS)",
            FriendlyExplanation: "Убирает лимит пакетов NetworkThrottlingIndex и снижает фоновый резерв планировщика до 10%.",
            ImpactBadge: "Ровный пинг и FPS",
            Risk: RiskLevel.Low,
            RequiresAdministrator: true,
            Mutations:
            [
                new("HKLM", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile", "SystemResponsiveness", RegistryTweakValueKind.DWord, "10", "20", ExistedByDefault: true),
                new("HKLM", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile", "NetworkThrottlingIndex", RegistryTweakValueKind.DWord, "-1", "10", ExistedByDefault: true)
            ]),

        new(
            TweakId: "gaming.disable-mouse-acceleration-enhance-pointer",
            Category: TweakCategory.GamingAndLatency,
            IconGlyph: "GAM",
            FriendlyTitle: "Честный ввод мыши 1:1 (отключение программной акселерации)",
            FriendlyExplanation: "Выключает «Повышенную точность установки указателя» для точного прицеливания и работы с графикой.",
            ImpactBadge: "Точность мыши 1:1",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: false,
            Mutations:
            [
                new("HKCU", @"Control Panel\Mouse", "MouseSpeed", RegistryTweakValueKind.String, "0", "1", ExistedByDefault: true),
                new("HKCU", @"Control Panel\Mouse", "MouseThreshold1", RegistryTweakValueKind.String, "0", "6", ExistedByDefault: true),
                new("HKCU", @"Control Panel\Mouse", "MouseThreshold2", RegistryTweakValueKind.String, "0", "10", ExistedByDefault: true)
            ]),

        new(
            TweakId: "gaming.disable-xbox-gamedvr-background-capture",
            Category: TweakCategory.GamingAndLatency,
            IconGlyph: "GAM",
            FriendlyTitle: "Отключить фоновую запись клипов Xbox Game DVR",
            FriendlyExplanation: "Убирает постоянный кольцевой видеозахват экрана в играх, повышая стабильность 1% Low FPS.",
            ImpactBadge: "Без просадок 1% Low",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: false,
            Mutations:
            [
                new("HKCU", @"System\GameConfigStore", "GameDVR_Enabled", RegistryTweakValueKind.DWord, "0", "1", ExistedByDefault: true),
                new("HKCU", @"Software\Microsoft\Windows\CurrentVersion\GameDVR", "AppCaptureEnabled", RegistryTweakValueKind.DWord, "0", "1", ExistedByDefault: false)
            ]),

        new(
            TweakId: "gaming.enable-gpu-hardware-scheduling-hags",
            Category: TweakCategory.GamingAndLatency,
            IconGlyph: "GAM",
            FriendlyTitle: "Включить планирование графического процессора с аппаратным ускорением (HAGS)",
            FriendlyExplanation: "Необходимо для генерации кадров DLSS 3 / FSR 3 и снижения задержки рендера современных GPU.",
            ImpactBadge: "Поддержка DLSS 3 + Latency",
            Risk: RiskLevel.Low,
            RequiresAdministrator: true,
            Mutations:
            [
                new("HKLM", @"SYSTEM\CurrentControlSet\Control\GraphicsDrivers", "HwSchMode", RegistryTweakValueKind.DWord, "2", "1", ExistedByDefault: true)
            ],
            Requirements: new TweakRequirements(MinWindowsBuild: 19041)),

        new(
            TweakId: "gaming.enable-windows-game-mode",
            Category: TweakCategory.GamingAndLatency,
            IconGlyph: "GAM",
            FriendlyTitle: "Активировать игровой режим Windows (блокировка фоновых обновлений в игре)",
            FriendlyExplanation: "Не позволяет фоновым задачам отбирать потоки процессора во время полноэкранной игры.",
            ImpactBadge: "Стабильный фреймтайм",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: false,
            Mutations:
            [
                new("HKCU", @"Software\Microsoft\GameBar", "AllowAutoGameMode", RegistryTweakValueKind.DWord, "1", "1", ExistedByDefault: false),
                new("HKCU", @"Software\Microsoft\GameBar", "AutoGameModeEnabled", RegistryTweakValueKind.DWord, "1", "1", ExistedByDefault: false)
            ]),

        // ==================== 7. БЕЗОПАСНОСТЬ ПРОВОДНИКА И СЕТИ (3 ТВИКА — ИТОГО 39!) ====================
        new(
            TweakId: "ui.show-real-file-extensions",
            Category: TweakCategory.SecurityAndClarity,
            IconGlyph: "SEC",
            FriendlyTitle: "Показывать настоящие расширения всех файлов (.exe, .scr, .bat)",
            FriendlyExplanation: "Защищает от запуска троянов и майнеров, замаскированных под PDF-документы или архивы.",
            ImpactBadge: "Защита от подмены .exe",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: false,
            Mutations:
            [
                new("HKCU", @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt", RegistryTweakValueKind.DWord, "0", "1", ExistedByDefault: true)
            ]),

        new(
            TweakId: "sec.disable-smbv1-protocol",
            Category: TweakCategory.SecurityAndClarity,
            IconGlyph: "SEC",
            FriendlyTitle: "Отключить уязвимый сетевой протокол SMBv1 (как в Optimizer)",
            FriendlyExplanation: "Блокирует устаревший протокол SMBv1, используемый сетевыми шифровальщиками класса EternalBlue.",
            ImpactBadge: "Защита локальной сети",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: true,
            Mutations:
            [
                new("HKLM", @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1", RegistryTweakValueKind.DWord, "0", "1", ExistedByDefault: false)
            ]),

        new(
            TweakId: "sec.disable-autorun-external-drives",
            Category: TweakCategory.SecurityAndClarity,
            IconGlyph: "SEC",
            FriendlyTitle: "Заблокировать скрытый автозапуск autorun.inf со всех флешек",
            FriendlyExplanation: "Предотвращает автоматическое исполнение вредоносных файлов при подключении чужих USB-накопителей.",
            ImpactBadge: "Защита USB-портов",
            Risk: RiskLevel.Safe,
            RequiresAdministrator: false,
            Mutations:
            [
                new("HKCU", @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun", RegistryTweakValueKind.DWord, "255", "145", ExistedByDefault: false)
            ])
    ];

    private static readonly IReadOnlyList<string> RecommendedPresetIds =
    [
        "ui.show-real-file-extensions",
        "ui.fast-menu-response",
        "ui.explorer-open-this-pc",
        "sys.disable-error-reporting-wer",
        "sys.disable-sticky-keys",
        "sys.fast-shutdown-auto-end-tasks",
        "sys.enable-win32-long-paths",
        "disk.disable-ntfs-last-access-timestamp",
        "quiet.disable-start-menu-bing-web-search",
        "quiet.disable-ads-and-lockscreen-tips",
        "sec.disable-smbv1-protocol",
        "sec.disable-autorun-external-drives"
    ];

    private static readonly IReadOnlyList<string> GamingPresetIds =
    [
        "gaming.mmcss-low-latency-profile",
        "gaming.disable-mouse-acceleration-enhance-pointer",
        "gaming.disable-xbox-gamedvr-background-capture",
        "gaming.enable-windows-game-mode",
        "sys.disable-sticky-keys",
        "ui.hide-widgets-and-news-interests",
        "app.disable-edge-telemetry-bloat",
        "disk.disable-ntfs-last-access-timestamp"
    ];

    private static readonly IReadOnlyList<string> PrivacyPresetIds =
    [
        "quiet.reduce-windows-diagnostic-telemetry",
        "quiet.disable-start-menu-bing-web-search",
        "quiet.disable-ads-and-lockscreen-tips",
        "quiet.disable-activity-history-timeline",
        "quiet.disable-media-player-network-sharing",
        "quiet.disable-cortana-and-copilot",
        "app.disable-office-telemetry",
        "app.disable-firefox-telemetry",
        "app.disable-chrome-telemetry",
        "app.disable-edge-telemetry-bloat",
        "app.disable-visualstudio-telemetry",
        "app.disable-nvidia-telemetry-overlay-spam"
    ];

    public static IReadOnlyList<DeclarativeTweakRule> GetAllRules() => BuiltInRules;

    public static IReadOnlyList<string> GetPresetIds(string presetKey) => presetKey.ToLowerInvariant() switch
    {
        "gaming" => GamingPresetIds,
        "privacy" => PrivacyPresetIds,
        _ => RecommendedPresetIds
    };

    public static DeclarativeTweakRule? FindById(string tweakId) =>
        BuiltInRules.FirstOrDefault(r => string.Equals(r.TweakId, tweakId, StringComparison.OrdinalIgnoreCase));
}

public static class YamlTweakProfileSerializer
{
    public static string ExportProfileToYaml(string profileName, IEnumerable<string> enabledTweakIds)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Декларативный профиль безопасной настройки UltimateWindows");
        sb.AppendLine("schema_version: 1");
        sb.AppendLine($"profile_name: \"{EscapeYaml(profileName)}\"");
        sb.AppendLine($"exported_at_utc: \"{DateTimeOffset.UtcNow:O}\"");
        sb.AppendLine("enabled_tweaks:");

        foreach (var id in enabledTweakIds.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
        {
            sb.AppendLine($"  - {id}");
        }

        return sb.ToString();
    }

    public static (string ProfileName, IReadOnlyList<string> EnabledTweakIds) ImportProfileFromYaml(string yamlContent)
    {
        if (string.IsNullOrWhiteSpace(yamlContent))
        {
            return ("Безымянный профиль", []);
        }

        var profileName = "Импортированный профиль";
        var ids = new List<string>();
        var inTweaksList = false;

        foreach (var rawLine in yamlContent.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var line = rawLine.Trim();
            if (line.StartsWith('#')) continue;

            if (line.StartsWith("profile_name:", StringComparison.OrdinalIgnoreCase))
            {
                profileName = line["profile_name:".Length..].Trim().Trim('"', '\'');
                inTweaksList = false;
                continue;
            }

            if (line.StartsWith("enabled_tweaks:", StringComparison.OrdinalIgnoreCase))
            {
                inTweaksList = true;
                continue;
            }

            if (inTweaksList && line.StartsWith('-'))
            {
                var id = line[1..].Trim().Trim('"', '\'');
                if (!string.IsNullOrWhiteSpace(id))
                {
                    ids.Add(id);
                }
            }
            else if (!rawLine.StartsWith(' ') && !rawLine.StartsWith('\t'))
            {
                inTweaksList = false;
            }
        }

        return (profileName, ids);
    }

    private static string EscapeYaml(string input) =>
        input.Replace("\\", "\\\\").Replace("\"", "\\\"");
}
