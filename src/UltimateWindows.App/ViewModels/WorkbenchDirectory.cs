using UltimateWindows.App.Infrastructure;
using UltimateWindows.Core.Enums;
using static UltimateWindows.Core.Enums.SystemDomain;

namespace UltimateWindows.App.ViewModels;

public sealed record WorkbenchSection(SystemDomain Domain, string Title, string Glyph, string Guide);
public sealed record ToolDestination(SystemDomain Domain, int Tab, string Title, string Detail, string Keywords = "")
{
    public WorkbenchSection Section => WorkbenchDirectory.Sections.First(s => s.Domain == Domain);
}

/// <summary>Поиск и быстрые задачи используют одни и те же адреса. Переход никогда не применяет изменения.</summary>
public static class WorkbenchDirectory
{
    public static IReadOnlyList<WorkbenchSection> Sections { get; } =
    [
        new(HealthOverview, "Обзор", "\uE80F", "Сводная проверка собирает локальные показатели. Оценка относится к моменту проверки, а не к текущей нагрузке."),
        new(SmartCleaner, "Диск и очистка", "\uEDA2", "Карта показывает, что занимает место. Для очистки выберите категории и рассчитайте план. Удаление кэша необратимо."),
        new(Optimizer, "Настройки Windows", "\uE713", "Сначала проверьте текущее значение и область применения. Вернуть стандарт Windows и вернуть прежнее значение — разные действия."),
        new(AntiMiner, "Защита", "\uEA18", "Откройте признаки обнаружения перед выбором действия. Эвристическая находка сама по себе не подтверждает заражение."),
        new(DllAndRepair, "Ремонт системы", "\uE90F", "Выберите симптом, прочитайте результат диагностики и только затем запускайте исправление. Часть изменений требует перезагрузки."),
        new(HardwareAndDrivers, "Оборудование", "\uE950", "Здесь находятся паспорт ПК, датчики, тесты и драйверы. Доступность показаний зависит от устройства и прав."),
        new(AppsAndAutomation, "Программы", "\uE71D", "Обновления, удаление и расписание — отдельные действия. Просмотрите список пакетов перед применением."),
        new(TimeMachineVault, "Машина времени", "\uE81C", "Проверьте состав записи и наличие копии перед откатом. Закреплённые копии сохраняются, пока вы не снимете закрепление.")
    ];

    public static IReadOnlyList<ToolDestination> Tools { get; } =
    [
        new(SmartCleaner, 1, "Освободить место", "План очистки кэша и данных браузеров", "temp cookie корзина"),
        new(DllAndRepair, 2, "Разобрать сбой", "Дампы памяти и события Windows", "BSOD синий экран WHEA"),
        new(HardwareAndDrivers, 3, "Проверить драйверы", "Состояние устройств и совместимые обновления", "WHQL hardware id"),
        new(SmartCleaner, 0, "Карта диска", "Размер папок, расширения и самые большие файлы", "NTFS MFT treemap"),
        new(SmartCleaner, 2, "Гигиена реестра", "Найти устаревшие ссылки и посмотреть причины", "registry"),
        new(SmartCleaner, 3, "Дубликаты и резервы", "Одинаковые файлы и системное хранилище", "SHA Windows.old hiberfil"),
        new(SmartCleaner, 4, "Правила очистки программ", "Предпросмотр встроенных и импортированных правил", "Winapp2"),
        new(Optimizer, 0, "Настройки и наборы", "Текущее значение, риск и предпросмотр изменений", "твики пресеты privacy"),
        new(Optimizer, 1, "Службы Windows", "Тип запуска и состояние службы", "services"),
        new(Optimizer, 2, "Задания планировщика", "Найти зарегистрированные задания", "tasks"),
        new(Optimizer, 3, "Автозагрузка", "Программы, запускаемые при входе", "startup"),
        new(Optimizer, 4, "Системные приложения", "Установленные приложения Windows", "UWP Appx"),
        new(Optimizer, 5, "Сеть и DNS", "Настройки разрешения имён и проверка связи", "пинг hosts"),
        new(Optimizer, 6, "Инструменты настройки", "Расширения оболочки и занятые файлы", "проводник блокировки"),
        new(AntiMiner, 0, "Проверка безопасности", "Сигналы и рекомендации по защите", "анти майнер"),
        new(AntiMiner, 1, "Точки закрепления", "Обзор механизмов автозапуска", "persistence"),
        new(AntiMiner, 2, "Состояние защиты Windows", "Параметры Microsoft Defender и ограничения", "защитник брандмауэр"),
        new(AntiMiner, 3, "Дополнительные сканеры", "Проверка доступности средств анализа памяти", "YARA"),
        new(AntiMiner, 4, "Карантин", "Просмотр изолированных файлов", "восстановить"),
        new(DllAndRepair, 0, "Диагностика Windows", "Проверки по симптомам", "починить пуск поиск службы"),
        new(DllAndRepair, 1, "Зависимости программы", "Библиотеки и разрядность исполняемого файла", "DLL PE runtime 0xc000007b"),
        new(DllAndRepair, 3, "Справочник ошибок", "Найти объяснение системного кода", "HRESULT"),
        new(DllAndRepair, 4, "Сценарии ремонта", "Штатные средства восстановления Windows", "DISM SFC"),
        new(HardwareAndDrivers, 0, "Паспорт компьютера", "Процессор, память, диски и мониторы", "CPU RAM SMART DIMM EDID"),
        new(HardwareAndDrivers, 1, "Датчики и питание", "Показания устройств и схемы питания", "температура"),
        new(HardwareAndDrivers, 2, "Тесты производительности", "Бенчмарки и стресс-тест", "benchmark GPU нагрузка"),
        new(HardwareAndDrivers, 4, "Каталог драйверов", "Официальные пакеты производителей"),
        new(HardwareAndDrivers, 5, "Хранилище драйверов", "Пакеты, резервные копии и офлайн-наборы", "DriverStore INF"),
        new(HardwareAndDrivers, 6, "Аудит драйверов ядра", "Проверка установленных драйверов", "BYOVD"),
        new(AppsAndAutomation, 0, "Обновления программ", "Доступные версии пакетов", "winget"),
        new(AppsAndAutomation, 1, "Каталог программ", "Наборы для установки", "winget"),
        new(AppsAndAutomation, 2, "Удаление программ", "Деинсталлятор и выбор остатков", "AppData uninstall хвосты"),
        new(AppsAndAutomation, 3, "Совместимость с Windows 11", "Требования к ПК, батарея, сон и память", "TPM ESU Secure Boot"),
        new(AppsAndAutomation, 4, "Расписание и отчёт", "Автообслуживание и архив диагностики", "автопилот поддержка ZIP"),
        new(TimeMachineVault, 0, "Журнал изменений", "Снимки, карантин и политика хранения", "Vault откат"),
        new(HealthOverview, 0, "Обзор компьютера", "Локальная сводка и комплексная проверка", "аудит")
    ];

    public static IReadOnlyList<ToolDestination> Search(string query)
    {
        var terms = query.Split(' ', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        return Tools.Where(t => terms.All(w => $"{t.Title} {t.Section.Title} {t.Detail} {t.Keywords}"
            .Contains(w, StringComparison.OrdinalIgnoreCase))).ToArray();
    }
}

public sealed class ToolFinderViewModel : ObservableObject
{
    private string _query = "";
    public string Query
    {
        get => _query;
        set
        {
            if (!SetProperty(ref _query, value)) return;
            Results = WorkbenchDirectory.Search(value);
            OnPropertyChanged(nameof(Results));
            OnPropertyChanged(nameof(IsEmpty));
        }
    }
    public IReadOnlyList<ToolDestination> Results { get; private set; } = WorkbenchDirectory.Tools;
    public bool IsEmpty => Results.Count == 0;
}
