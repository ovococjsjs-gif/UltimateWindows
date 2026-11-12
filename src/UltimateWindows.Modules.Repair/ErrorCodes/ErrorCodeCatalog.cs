using System.Globalization;
using UltimateWindows.Modules.Repair.Bsod;

namespace UltimateWindows.Modules.Repair.ErrorCodes;

public enum ErrorCodeFamily
{
    WindowsUpdateAndCbs = 1,
    AppAndLoaderNtStatus = 2,
    SystemComDirectXHResult = 3,
    BlueScreenBugCheck = 4
}

public static class ErrorCodeFamilyDisplay
{
    public static string GetTitle(ErrorCodeFamily family) => family switch
    {
        ErrorCodeFamily.WindowsUpdateAndCbs => "Центр обновления / CBS / Store",
        ErrorCodeFamily.AppAndLoaderNtStatus => "Сбой программы / DLL (NTSTATUS)",
        ErrorCodeFamily.SystemComDirectXHResult => "Система / Win32 / MSI / DirectX",
        ErrorCodeFamily.BlueScreenBugCheck => "Синий экран (BugCheck)",
        _ => family.ToString()
    };
}

/// <summary>
/// Запись справочника кодов ошибок Windows с привязкой к правилам ремонта и пакетам сред выполнения.
/// </summary>
public sealed record ErrorCodeEntry(
    uint NumericCode,
    string DisplayCode,
    string SymbolicName,
    ErrorCodeFamily Family,
    string ShortTitle,
    string DetailedExplanation,
    string RecommendedFixSteps,
    IReadOnlyList<string> RelatedRepairRuleIds,
    IReadOnlyList<string> RelatedRuntimePackageKeys,
    bool IsPlainWin32OrMsiDecimal = false)
{
    public string FamilyTitle => ErrorCodeFamilyDisplay.GetTitle(Family);
    public bool HasLinkedRepairRule => RelatedRepairRuleIds.Count > 0;
    public bool HasLinkedRuntimePackage => RelatedRuntimePackageKeys.Count > 0;
    public string? PrimaryRepairRuleId => RelatedRepairRuleIds.Count > 0 ? RelatedRepairRuleIds[0] : null;
    public string? PrimaryRuntimePackageKey => RelatedRuntimePackageKeys.Count > 0 ? RelatedRuntimePackageKeys[0] : null;
}

/// <summary>
/// Единый справочник кодов ошибок Windows (HRESULT, NTSTATUS, Win32, MSI, Центр обновления, Store, DirectX и 76 кодов остановки BSOD).
/// Понимает шестнадцатеричную («0x80070005», «80070005»), знаковую десятичную («-2147024891»), обычную десятичную («1603», «2503») запись и текстовый поиск.
/// </summary>
public static class ErrorCodeCatalog
{
    private static readonly IReadOnlyList<ErrorCodeEntry> AllEntries = BuildAllEntries();

    public static IReadOnlyList<ErrorCodeEntry> GetAll() => AllEntries;

    public static int Count => AllEntries.Count;

    /// <summary>
    /// Ищет подходящие коды по строке запроса (код в шестнадцатеричном/десятичном виде, символьное имя или русское описание).
    /// Если введён незнакомый HRESULT вида 0x8007XXXX, автоматически расшифровывает младшие 16 бит как код Win32.
    /// </summary>
    public static IReadOnlyList<ErrorCodeEntry> Search(string? query, ErrorCodeFamily? familyFilter = null, int maxResults = 150)
    {
        IEnumerable<ErrorCodeEntry> source = AllEntries;
        if (familyFilter.HasValue)
        {
            source = source.Where(e => e.Family == familyFilter.Value);
        }

        if (string.IsNullOrWhiteSpace(query))
        {
            return source.Take(maxResults).ToList();
        }

        var trimmed = query.Trim();
        var results = new List<ErrorCodeEntry>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (TryParseUserCode(trimmed, out var parsedCode, out var wasDecimalOnly))
        {
            foreach (var entry in source)
            {
                var exactMatch = entry.NumericCode == parsedCode &&
                                 (!wasDecimalOnly || entry.IsPlainWin32OrMsiDecimal || parsedCode > 0xFFFFu);
                if (exactMatch && seen.Add($"{entry.Family}:{entry.DisplayCode}:{entry.SymbolicName}"))
                {
                    results.Add(entry);
                }
            }

            // Если ввели 0x8007XXXX, которого нет как отдельного HRESULT, пробуем расшифровать хвост Win32
            if (results.Count == 0 && (parsedCode & 0xFFFF_0000u) == 0x8007_0000u)
            {
                var win32Tail = parsedCode & 0xFFFFu;
                var tailEntry = AllEntries.FirstOrDefault(e => e.IsPlainWin32OrMsiDecimal && e.NumericCode == win32Tail);
                if (tailEntry is not null && (!familyFilter.HasValue || familyFilter.Value == ErrorCodeFamily.SystemComDirectXHResult))
                {
                    results.Add(new ErrorCodeEntry(
                        NumericCode: parsedCode,
                        DisplayCode: $"0x{parsedCode:X8}",
                        SymbolicName: $"HRESULT_FROM_WIN32({tailEntry.SymbolicName})",
                        Family: ErrorCodeFamily.SystemComDirectXHResult,
                        ShortTitle: $"Код Win32 {win32Tail} в обёртке HRESULT: {tailEntry.ShortTitle}",
                        DetailedExplanation: $"Префикс 0x8007 означает обычную ошибку Win32 (код {win32Tail}). {tailEntry.DetailedExplanation}",
                        RecommendedFixSteps: tailEntry.RecommendedFixSteps,
                        RelatedRepairRuleIds: tailEntry.RelatedRepairRuleIds,
                        RelatedRuntimePackageKeys: tailEntry.RelatedRuntimePackageKeys));
                }
                else if (!familyFilter.HasValue || familyFilter.Value == ErrorCodeFamily.SystemComDirectXHResult)
                {
                    results.Add(new ErrorCodeEntry(
                        NumericCode: parsedCode,
                        DisplayCode: $"0x{parsedCode:X8}",
                        SymbolicName: $"HRESULT_FROM_WIN32({win32Tail})",
                        Family: ErrorCodeFamily.SystemComDirectXHResult,
                        ShortTitle: $"Общая системная ошибка Win32 (десятичный код {win32Tail})",
                        DetailedExplanation: $"Код 0x{parsedCode:X8} представляет собой ошибку Win32 №{win32Tail} (0x{win32Tail:X4}), упакованную в HRESULT.",
                        RecommendedFixSteps: "Проверьте свободное место на диске, права доступа от имени администратора и целостность системных файлов (DISM + SFC).",
                        RelatedRepairRuleIds: ["sfc.cbs-component-store"],
                        RelatedRuntimePackageKeys: []));
                }
            }

            // Для BugCheck с флагом 0x10000000 (_M)
            if (results.Count == 0 && (parsedCode & 0xF000_0000u) == 0x1000_0000u)
            {
                var bc = BugCheckCatalog.Describe(parsedCode);
                if (bc.IsKnown && (!familyFilter.HasValue || familyFilter.Value == ErrorCodeFamily.BlueScreenBugCheck))
                {
                    results.Add(FromBugCheck(bc));
                }
            }
        }

        // Текстовый поиск по коду, символьному имени, заголовку и описанию
        foreach (var entry in source)
        {
            if (results.Count >= maxResults) break;

            if (entry.DisplayCode.Contains(trimmed, StringComparison.OrdinalIgnoreCase) ||
                entry.SymbolicName.Contains(trimmed, StringComparison.OrdinalIgnoreCase) ||
                entry.ShortTitle.Contains(trimmed, StringComparison.OrdinalIgnoreCase) ||
                entry.DetailedExplanation.Contains(trimmed, StringComparison.OrdinalIgnoreCase))
            {
                if (seen.Add($"{entry.Family}:{entry.DisplayCode}:{entry.SymbolicName}"))
                {
                    results.Add(entry);
                }
            }
        }

        return results;
    }

    public static ErrorCodeEntry? LookupExact(uint code)
    {
        var exact = AllEntries.FirstOrDefault(e => !e.IsPlainWin32OrMsiDecimal && e.NumericCode == code);
        if (exact is not null) return exact;

        var search = Search($"0x{code:X8}", maxResults: 1);
        return search.Count > 0 ? search[0] : null;
    }

    public static bool TryParseUserCode(string input, out uint code, out bool wasPlainDecimal)
    {
        code = 0;
        wasPlainDecimal = false;
        if (string.IsNullOrWhiteSpace(input)) return false;

        var s = input.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return uint.TryParse(s[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out code);
        }

        // Отрицательное десятичное представление HRESULT (например -2147024891 -> 0x80070005)
        if (s.StartsWith('-') && int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var signedInt))
        {
            code = unchecked((uint)signedInt);
            return true;
        }

        // Шестнадцатеричная строка длины 8 с буквами A–F или типичным префиксом 80/C0/C1/E0/88
        if (s.Length == 8 && uint.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex8))
        {
            var hasHexLetters = s.Any(ch => ch is (>= 'a' and <= 'f') or (>= 'A' and <= 'F'));
            var topByte = (hex8 >> 24) & 0xFFu;
            if (hasHexLetters || topByte is 0x80 or 0x88 or 0xC0 or 0xC1 or 0xE0 or 0x40)
            {
                code = hex8;
                return true;
            }
        }

        if (uint.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var plainDec))
        {
            code = plainDec;
            wasPlainDecimal = true;
            return true;
        }

        return false;
    }

    private static ErrorCodeEntry H(
        uint code,
        string name,
        ErrorCodeFamily family,
        string title,
        string explanation,
        string steps,
        string[]? rules = null,
        string[]? runtimes = null) =>
        new(
            NumericCode: code,
            DisplayCode: $"0x{code:X8}",
            SymbolicName: name,
            Family: family,
            ShortTitle: title,
            DetailedExplanation: explanation,
            RecommendedFixSteps: steps,
            RelatedRepairRuleIds: rules ?? [],
            RelatedRuntimePackageKeys: runtimes ?? []);

    private static ErrorCodeEntry Dec(
        uint code,
        string name,
        string title,
        string explanation,
        string steps,
        string[]? rules = null,
        string[]? runtimes = null) =>
        new(
            NumericCode: code,
            DisplayCode: code.ToString(CultureInfo.InvariantCulture),
            SymbolicName: name,
            Family: ErrorCodeFamily.SystemComDirectXHResult,
            ShortTitle: title,
            DetailedExplanation: explanation,
            RecommendedFixSteps: steps,
            RelatedRepairRuleIds: rules ?? [],
            RelatedRuntimePackageKeys: runtimes ?? [],
            IsPlainWin32OrMsiDecimal: true);

    private static ErrorCodeEntry FromBugCheck(BugCheckDescriptor bc) =>
        new(
            NumericCode: bc.Code,
            DisplayCode: $"0x{bc.Code:X8}",
            SymbolicName: bc.Name,
            Family: ErrorCodeFamily.BlueScreenBugCheck,
            ShortTitle: $"Синий экран {bc.Name}",
            DetailedExplanation: bc.SimpleReason,
            RecommendedFixSteps: bc.RecommendedAction,
            RelatedRepairRuleIds: bc.Category == BugCheckCategory.SystemProcessOrFiles ? ["sfc.cbs-component-store"] : [],
            RelatedRuntimePackageKeys: []);

    private static IReadOnlyList<ErrorCodeEntry> BuildAllEntries()
    {
        var list = new List<ErrorCodeEntry>(180)
        {
            // ==================== ПРИЛОЖЕНИЯ, ЗАГРУЗЧИК PE И DLL (NTSTATUS) ====================
            H(0xC000007Bu, "STATUS_INVALID_IMAGE_FORMAT", ErrorCodeFamily.AppAndLoaderNtStatus,
                "Конфликт разрядности DLL (32-бит против 64-бит)",
                "64-битная программа или игра пытается загрузить 32-битную библиотеку .dll (чаще всего вручную скопированную в папку игры xinput1_3.dll, d3dx9_43.dll или vcruntime140.dll) либо наоборот.",
                "Откройте .exe программы в «PE-Докторе», изолируйте чужеродную локальную DLL в карантин и установите официальный пакет Visual C++ / DirectX.",
                runtimes: ["vcredist-2015-2022-x64", "directx-june-2010"]),

            H(0xC0000135u, "STATUS_DLL_NOT_FOUND", ErrorCodeFamily.AppAndLoaderNtStatus,
                "Не найдена необходимая библиотека DLL",
                "Загрузчик Windows не нашёл одну из библиотек, указанных в таблице импорта исполняемого файла (.exe).",
                "Проверьте .exe в «PE-Докторе» и установите недостающий пакет Visual C++, DirectX, .NET или WebView2.",
                runtimes: ["vcredist-2015-2022-x64", "directx-june-2010"]),

            H(0xC0000139u, "STATUS_ENTRYPOINT_NOT_FOUND", ErrorCodeFamily.AppAndLoaderNtStatus,
                "Точка входа в процедуру не найдена в DLL",
                "Библиотека DLL найдена, но её версия устарела или подменена несовместимым файлом в папке программы, поэтому нужной функции в ней нет.",
                "Проверьте папку программы в «PE-Докторе» на старые копии системных DLL и обновите Visual C++ 2015–2026.",
                runtimes: ["vcredist-2015-2022-x64"]),

            H(0xC0000142u, "STATUS_DLL_INIT_FAILED", ErrorCodeFamily.AppAndLoaderNtStatus,
                "Ошибка инициализации библиотеки DLL при запуске",
                "Одна из DLL вернула ошибку в DllMain при старте процесса. Часто вызывается повреждёнными системными файлами, сторонними оверлеями или блокировкой со стороны антивируса.",
                "Выполните проверку системных файлов (DISM + SFC), обновите Visual C++ и временно отключите сторонние оверлеи.",
                rules: ["sfc.cbs-component-store"], runtimes: ["vcredist-2015-2022-x64"]),

            H(0xC0000005u, "STATUS_ACCESS_VIOLATION", ErrorCodeFamily.AppAndLoaderNtStatus,
                "Нарушение прав доступа к памяти (Access Violation)",
                "Программа обратилась к неразрешённому или нулевому адресу памяти. Причины: ошибка в коде самой программы/мода, сбой видеодрайвера, агрессивный разгон ОЗУ или перехватчик оверлея.",
                "Посмотрите модуль сбоя на вкладке «Синие экраны и сбои», обновите драйвер видеокарты и проверьте целостность файлов программы."),

            H(0xC000001Du, "STATUS_ILLEGAL_INSTRUCTION", ErrorCodeFamily.AppAndLoaderNtStatus,
                "Недопустимая инструкция процессора (AVX /AVX2 / SSE4.2)",
                "Программа скомпилирована с использованием процессорных инструкций (например AVX2), которые не поддерживаются процессором или отключены в среде виртуализации.",
                "Проверьте системные требования программы к CPU и убедитесь, что набор инструкций не ограничен настройками bcdedit (xsavedisable)."),

            H(0xC0000022u, "STATUS_ACCESS_DENIED", ErrorCodeFamily.AppAndLoaderNtStatus,
                "Отказано в доступе при загрузке процесса или DLL",
                "Учётной записи не хватает прав на чтение .exe/.dll файла либо запуск заблокирован антивирусом/SmartScreen.",
                "Проверьте права доступа к папке программы, целостность системных файлов и запустите от имени администратора.",
                rules: ["disk.dirty-and-temp-health"]),

            H(0xC00000FDu, "STATUS_STACK_OVERFLOW", ErrorCodeFamily.AppAndLoaderNtStatus,
                "Переполнение стека вызовов (Stack Overflow)",
                "Бесконечная рекурсия или чрезмерное выделение данных в стеке потока внутри программы или плагина.",
                "Отключите недавно добавленные плагины/модификации программы и обновите её до актуальной версии."),

            H(0xC000012Fu, "STATUS_INVALID_IMAGE_NOT_MZ", ErrorCodeFamily.AppAndLoaderNtStatus,
                "Повреждён исполняемый файл или DLL («Плохой образ»)",
                "Файл .dll или .exe обрезан, заполнен нулями после внезапного выключения ПК или не имеет заголовка MZ.",
                "Если в окне ошибки указан системный файл из C:\\Windows\\System32 — выполните DISM + SFC; если файл программы — переустановите программу.",
                rules: ["sfc.cbs-component-store"]),

            H(0xC000027Bu, "STATUS_STOWED_EXCEPTION", ErrorCodeFamily.AppAndLoaderNtStatus,
                "Внутреннее исключение приложения WinRT / UWP / XAML",
                "Современное приложение Windows (Параметры, Магазин, Фотографии, Терминал) завершилось из-за сбоя пакета XAML или кэша AppX.",
                "Выполните починку кэша Microsoft Store и перерегистрацию системных пакетов XAML.",
                rules: ["store.reset-cache-and-register", "shell.win11-xaml-packages"]),

            H(0xC0000374u, "STATUS_HEAP_CORRUPTION", ErrorCodeFamily.AppAndLoaderNtStatus,
                "Повреждение кучи памяти (Heap Corruption)",
                "Менеджер памяти Windows обнаружил запись за границы выделенного блока кучи (часто из-за кривых расширений контекстного меню Проводника или старых кодеков).",
                "Если падает explorer.exe — отключите сторонние расширения контекстного меню в разделе «Оптимизатор → Автозагрузка» и проверьте системные файлы.",
                rules: ["sfc.cbs-component-store"]),

            H(0xC0000409u, "STATUS_STACK_BUFFER_OVERRUN", ErrorCodeFamily.AppAndLoaderNtStatus,
                "Аварийная остановка защиты стека (__fastfail)",
                "Механизм безопасности Control Flow Guard / Stack Cookie принудительно завершил процесс для предотвращения порчи памяти.",
                "Обновите программу и пакеты Visual C++, а если падает системный процесс — запустите проверку DISM + SFC.",
                rules: ["sfc.cbs-component-store"], runtimes: ["vcredist-2015-2022-x64"]),

            H(0xC0000428u, "STATUS_INVALID_IMAGE_HASH", ErrorCodeFamily.AppAndLoaderNtStatus,
                "Неверная цифровая подпись драйвера или системной DLL",
                "Ядро Windows отклонило загрузку файла с нарушенной или отозванной цифровой подписью.",
                "Обновите проблемный драйвер/античит до подписанной WHQL-версии и проверьте системное время ПК.",
                rules: ["time.ntp-sync-health", "sfc.cbs-component-store"]),

            H(0xE0434352u, "CLR_EXCEPTION_COMPLUS", ErrorCodeFamily.AppAndLoaderNtStatus,
                "Необработанное исключение приложения .NET",
                "Управляемое приложение .NET завершилось с необработанным исключением (точный тип исключения записывается в соседнее событие Event ID 1026).",
                "Откройте вкладку «Синие экраны и сбои» для просмотра Event ID 1026 и проверьте наличие нужного пакета .NET Desktop Runtime.",
                runtimes: ["dotnet-desktop-8-x64", "dotnet-desktop-10-x64"]),

            H(0xE06D7363u, "CPP_EH_EXCEPTION", ErrorCodeFamily.AppAndLoaderNtStatus,
                "Неперехваченное исключение Microsoft C++ ('msc')",
                "Нативная программа на C++ выбросила исключение std::exception (например при отсутствии файла ресурсов, недоступности %TEMP% или повреждении настроек).",
                "Проверьте доступность папки %TEMP%, права администратора и обновите Microsoft Visual C++ 2015–2026.",
                rules: ["disk.dirty-and-temp-health"], runtimes: ["vcredist-2015-2022-x64"]),

            // ==================== ЦЕНТР ОБНОВЛЕНИЯ, CBS, DISM И STORE ====================
            H(0x80073712u, "ERROR_SXS_COMPONENT_STORE_CORRUPT", ErrorCodeFamily.WindowsUpdateAndCbs,
                "Повреждено хранилище компонентов Windows (WinSxS)",
                "Часть файлов или манифестов в папке C:\\Windows\\WinSxS отсутствует либо не проходит проверку хэша, из-за чего установка обновлений прерывается.",
                "Запустите восстановление образа DISM /RestoreHealth и затем sfc /scannow.",
                rules: ["sfc.cbs-component-store", "wu.reset-corrupt-cache"]),

            H(0x80073701u, "ERROR_SXS_ASSEMBLY_MISSING", ErrorCodeFamily.WindowsUpdateAndCbs,
                "Отсутствует зависимая системная сборка в WinSxS",
                "Обновление ссылается на системный пакет или языковой компонент, которого нет в локальном хранилище.",
                "Выполните DISM /RestoreHealth и сбросьте кэш Центра обновления; если не помогает — используйте «Переустановить сейчас» с сохранением файлов.",
                rules: ["sfc.cbs-component-store", "wu.reset-corrupt-cache"]),

            H(0x800F081Fu, "CBS_E_SOURCE_MISSING", ErrorCodeFamily.WindowsUpdateAndCbs,
                "Не найдены исходные файлы для восстановления компонентов или .NET 3.5",
                "Служба обслуживания CBS не смогла скачать эталонные файлы с серверов Центра обновления (например из-за блокировки политики WSUS или повреждения кэша).",
                "Проверьте отсутствие блокирующей политики WSUS, восстановите сеть/прокси и выполните DISM /RestoreHealth.",
                rules: ["wu.wsus-hijack-policy", "net.dead-local-proxy", "sfc.cbs-component-store"], runtimes: ["dotnet-fx-35"]),

            H(0x800F0831u, "CBS_E_STORE_CORRUPTION", ErrorCodeFamily.WindowsUpdateAndCbs,
                "Повреждение манифеста пакета в хранилище CBS",
                "При установке накопительного обновления обнаружен повреждённый манифест предыдущего обновления.",
                "Запустите DISM /RestoreHealth + sfc /scannow; в тяжёлых случаях — обновление на месте (Reinstall now).",
                rules: ["sfc.cbs-component-store"]),

            H(0x800F0906u, "CBS_E_DOWNLOAD_FAILURE", ErrorCodeFamily.WindowsUpdateAndCbs,
                "Не удалось скачать файлы компонента с серверов Microsoft",
                "Установка .NET Framework 3.5 или дополнительных возможностей Windows не смогла достучаться до серверов обновления.",
                "Проверьте прокси, файл hosts и политику WSUS, затем повторите установку компонента.",
                rules: ["net.dead-local-proxy", "net.hosts-file-health", "wu.wsus-hijack-policy"]),

            H(0x800F0922u, "CBS_E_INSTALLERS_FAILED", ErrorCodeFamily.WindowsUpdateAndCbs,
                "Сбой установщика обновления (раздел EFI < 100 МБ, VPN или .NET)",
                "Установщик компонента завершился ошибкой. Две главные причины: переполнен системный раздел EFI (System Reserved) либо активное VPN-соединение во время обновления.",
                "Отключите VPN, проверьте свободное место на диске C:\\ и системном разделе, выполните DISM + SFC.",
                rules: ["disk.low-free-space", "sfc.cbs-component-store"]),

            H(0x800F0984u, "PSFX_E_MATCHING_BINARY_MISSING", ErrorCodeFamily.WindowsUpdateAndCbs,
                "Несовпадение бинарного файла дельта-обновления Windows 11",
                "Файл в хранилище WinSxS не совпадает с базовой версией, ожидаемой патчем PSFX.",
                "Выполните DISM /RestoreHealth и сброс кэша Центра обновления.",
                rules: ["sfc.cbs-component-store", "wu.reset-corrupt-cache"]),

            H(0x800F0988u, "PSFX_E_INVALID_DELTA_COMBINATION", ErrorCodeFamily.WindowsUpdateAndCbs,
                "Нарушена цепочка дельта-обновлений WinSxS",
                "После очистки или прерванного обновления отсутствует базовый слой компонента в WinSxS.",
                "Выполните DISM /RestoreHealth; если ошибка сохраняется — используйте «Переустановить сейчас» через Центр обновления.",
                rules: ["sfc.cbs-component-store"]),

            H(0x800F0991u, "PSFX_E_COMPONENT_HYDRATION_FAILED", ErrorCodeFamily.WindowsUpdateAndCbs,
                "Сбой распаковки системного компонента при обновлении",
                "Повреждён скачанный пакет обновления в SoftwareDistribution или хранилище WinSxS.",
                "Сбросьте кэш Центра обновления Windows и запустите DISM /RestoreHealth.",
                rules: ["wu.reset-corrupt-cache", "sfc.cbs-component-store"]),

            H(0x8024001Eu, "WU_E_SERVICE_STOP", ErrorCodeFamily.WindowsUpdateAndCbs,
                "Операция прервана из-за остановки службы Центра обновления",
                "Служба wuauserv или фоновая передача BITS остановилась во время загрузки/установки.",
                "Восстановите тип запуска служб Центра обновления и выполните сброс кэша.",
                rules: ["wu.core-services", "wu.reset-corrupt-cache"]),

            H(0x80240022u, "WU_E_ALL_UPDATES_FAILED", ErrorCodeFamily.WindowsUpdateAndCbs,
                "Сбой установки всех пакетов в очереди Центра обновления",
                "Обобщённый сбой агента Windows Update при повреждённом кэше SoftwareDistribution или очереди BITS.",
                "Выполните полный сброс компонентов Центра обновления и проверку DISM + SFC.",
                rules: ["wu.reset-corrupt-cache", "sfc.cbs-component-store"]),

            H(0x80240034u, "WU_E_DOWNLOAD_FAILED", ErrorCodeFamily.WindowsUpdateAndCbs,
                "Не удалось скачать пакет обновления Windows",
                "Загрузка обновления оборвалась или застряла в повреждённом состоянии.",
                "Проверьте прокси/DNS и выполните сброс кэша Центра обновления.",
                rules: ["wu.reset-corrupt-cache", "net.dead-local-proxy", "net.dns-winsock-stack"]),

            H(0x8024401Cu, "WU_E_PT_HTTP_STATUS_REQUEST_TIMEOUT", ErrorCodeFamily.WindowsUpdateAndCbs,
                "Таймаут ответа серверов Центра обновления Microsoft",
                "Сервер обновления не ответил вовремя из-за нестабильного DNS, прокси или блокировки в файле hosts.",
                "Проверьте локальный прокси, файл hosts и сбросьте кэш DNS.",
                rules: ["net.dead-local-proxy", "net.hosts-file-health", "net.dns-winsock-stack"]),

            H(0x8024402Cu, "WU_E_PT_WINHTTP_NAME_NOT_RESOLVED", ErrorCodeFamily.WindowsUpdateAndCbs,
                "Не удалось разрешить DNS-имя серверов обновления",
                "Системный стек WinHTTP не может получить IP-адреса серверов Microsoft из-за сбоя DNS или мёртвого прокси.",
                "Проверьте службу DNS-клиента, отключите мёртвый локальный прокси и очистите кэш DNS.",
                rules: ["net.dead-local-proxy", "net.core-services", "net.dns-winsock-stack"]),

            H(0x8024500Cu, "WU_E_REDIRECTOR_CONNECT_POLICY", ErrorCodeFamily.WindowsUpdateAndCbs,
                "Политика блокирует подключение к Центру обновления Windows",
                "В реестре включены политики запрета обновлений или поддельный локальный сервер WSUS.",
                "Снимите блокирующие политики Центра обновления и проверьте настройку WSUS.",
                rules: ["wu.access-policies", "wu.wsus-hijack-policy"]),

            H(0x80246007u, "WU_E_DM_NOTDOWNLOADED", ErrorCodeFamily.WindowsUpdateAndCbs,
                "Обновление не было скачано менеджером загрузок BITS",
                "Очередь фоновой интеллектуальной передачи (BITS) зависла на битом файле qmgr*.dat или служба BITS отключена.",
                "Включите службу BITS и выполните сброс Центра обновления Windows.",
                rules: ["wu.core-services", "wu.reset-corrupt-cache"]),

            H(0x80246008u, "WU_E_DM_FAILTOCONNECTTOBITS", ErrorCodeFamily.WindowsUpdateAndCbs,
                "Агент обновления не смог подключиться к службе BITS",
                "Служба фоновой передачи данных (BITS) отключена или повреждена.",
                "Восстановите тип запуска службы BITS и перезапустите службы обновления.",
                rules: ["wu.core-services", "wu.reset-corrupt-cache"]),

            H(0x80248007u, "WU_E_DS_NODATA", ErrorCodeFamily.WindowsUpdateAndCbs,
                "Отсутствуют данные в локальной базе обновлений DataStore.edb",
                "Локальная база SoftwareDistribution\\DataStore повреждена.",
                "Выполните полный сброс компонентов Центра обновления Windows (пересоздаст чистую базу).",
                rules: ["wu.reset-corrupt-cache"]),

            H(0x80070643u, "ERROR_INSTALL_FAILURE", ErrorCodeFamily.WindowsUpdateAndCbs,
                "Фатальная ошибка во время установки пакета MSI или обновления",
                "Установщик вернул общую ошибку выполнения: отключена служба Windows Installer, повреждён .NET или ожидается перезагрузка.",
                "Проверьте флаг ожидающей перезагрузки, службу Windows Installer и выполните DISM + SFC.",
                rules: ["wu.pending-reboot", "wmi.msi-installer-service", "sfc.cbs-component-store"]),

            H(0x80070BC9u, "ERROR_FAIL_REBOOT_REQUIRED", ErrorCodeFamily.WindowsUpdateAndCbs,
                "Установка заблокирована до перезагрузки компьютера",
                "Предыдущее обновление или установщик оставил незавершённые операции замены файлов до перезагрузки.",
                "Перезагрузите компьютер, чтобы завершить отложенные операции обслуживания.",
                rules: ["wu.pending-reboot"]),

            H(0xC1900101u, "MOSETUP_E_DRIVER_ROLLBACK", ErrorCodeFamily.WindowsUpdateAndCbs,
                "Откат крупного обновления сборки Windows из-за драйвера",
                "При переходе на новую сборку Windows 10/11 один из сторонних драйверов (антивирус, шифрование диска, старый драйвер чипсета/Wi-Fi) вызвал сбой на этапе перезагрузки.",
                "Отключите внешние USB-устройства, временно удалите сторонний антивирус, обновите драйверы чипсета/NVMe и освободите не менее 25 ГБ на C:\\.",
                rules: ["disk.low-free-space", "sfc.cbs-component-store"]),

            H(0xC1900200u, "MOSETUP_E_COMPAT_SYSREQ", ErrorCodeFamily.WindowsUpdateAndCbs,
                "Система не прошла проверку минимальных требований обновления",
                "Недостаточно места на системном разделе EFI или диске C:\\ либо не выполнены аппаратные требования сборки.",
                "Освободите место на диске C:\\ и проверьте раздел EFI.",
                rules: ["disk.low-free-space"]),

            H(0xC1900208u, "MOSETUP_E_COMPAT_APP_BLOCK", ErrorCodeFamily.WindowsUpdateAndCbs,
                "Несовместимая программа блокирует обновление версии Windows",
                "Мастер обновления обнаружил старую программу или драйвер, несовместимый с новой сборкой ОС.",
                "Удалите устаревшее ПО, указанное в отчёте совместимости, и повторите обновление."),

            H(0x80073CF3u, "ERROR_INSTALL_RESOLVE_DEPENDENCY_FAILED", ErrorCodeFamily.WindowsUpdateAndCbs,
                "Microsoft Store не смог разрешить зависимости пакета AppX",
                "Не удалось установить фреймворк-зависимость (UI.Xaml / VCLibs / WindowsAppRuntime) или повреждён кэш Store.",
                "Выполните сброс кэша Microsoft Store и проверьте службы AppXSvc / InstallService.",
                rules: ["store.core-services", "store.reset-cache-and-register"]),

            H(0x80073CF6u, "ERROR_INSTALL_REGISTRATION_FAILURE", ErrorCodeFamily.WindowsUpdateAndCbs,
                "Не удалось зарегистрировать пакет приложения UWP / Microsoft Store",
                "Сбой регистрации манифеста AppX из-за повреждённого кэша Store или отключённых служб развёртывания.",
                "Восстановите службы Microsoft Store, сбросьте кэш Store и проверьте системные файлы.",
                rules: ["store.core-services", "store.reset-cache-and-register", "sfc.cbs-component-store"]),

            H(0x80073CF9u, "ERROR_INSTALL_FAILED", ErrorCodeFamily.WindowsUpdateAndCbs,
                "Сбой установки приложения из Microsoft Store",
                "Магазин не смог распаковать или зарегистрировать приложение (часто отсутствует папка AUInstallAgent или сбит кэш Store).",
                "Запустите починку Microsoft Store и проверьте права на папку %TEMP%.",
                rules: ["store.reset-cache-and-register", "disk.dirty-and-temp-health"]),

            H(0x80073D02u, "ERROR_PACKAGES_IN_USE", ErrorCodeFamily.WindowsUpdateAndCbs,
                "Обновляемый пакет UWP сейчас запущен и занят",
                "Приложение или фоновый компонент оболочки открыт, поэтому AppX не может заменить его файлы.",
                "Закройте обновляемое приложение (или перезапустите Проводник) и повторите попытку."),

            H(0x80072EE2u, "ERROR_INTERNET_TIMEOUT", ErrorCodeFamily.WindowsUpdateAndCbs,
                "Превышено время ожидания сетевого запроса (WinInet / Store / Update)",
                "Соединение с серверами Microsoft оборвалось по таймауту из-за прокси, MTU/DNS или блокировки.",
                "Проверьте локальный прокси 127.0.0.1, файл hosts и выполните сброс DNS и Winsock.",
                rules: ["net.dead-local-proxy", "net.hosts-file-health", "net.dns-winsock-stack"]),

            H(0x80072EE7u, "ERROR_INTERNET_NAME_NOT_RESOLVED", ErrorCodeFamily.WindowsUpdateAndCbs,
                "Не удалось определить IP-адрес сервера (ошибка DNS)",
                "Клиент DNS не смог разрешить доменное имя Microsoft Store или Центра обновления.",
                "Проверьте службу DNS-клиента и сбросьте кэш DNS и сокеты Winsock.",
                rules: ["net.core-services", "net.dns-winsock-stack"]),

            H(0x80072EFDu, "ERROR_INTERNET_CANNOT_CONNECT", ErrorCodeFamily.WindowsUpdateAndCbs,
                "Не удалось установить TCP-соединение с сервером",
                "Чаще всего оставлен включённым мёртвый системный прокси-сервер (127.0.0.1) после закрытия VPN/прокси-клиента.",
                "Проверьте и отключите зависший локальный прокси в настройках сети.",
                rules: ["net.dead-local-proxy", "net.dns-winsock-stack"]),

            H(0x80072F8Fu, "ERROR_INTERNET_DECODING_LP / SEC_CERT_DATE_INVALID", ErrorCodeFamily.WindowsUpdateAndCbs,
                "Ошибка проверки SSL/TLS сертификата из-за неверной даты и времени ПК",
                "Системные часы компьютера отстают или спешат, поэтому сертификаты серверов Microsoft считаются недействительными.",
                "Включите службу времени Windows и выполните принудительную синхронизацию NTP.",
                rules: ["time.w32time-service", "time.ntp-sync-health"]),

            // ==================== СИСТЕМА, WIN32, MSI, COM, WMI, DIRECTX ====================
            H(0x80070002u, "ERROR_FILE_NOT_FOUND", ErrorCodeFamily.SystemComDirectXHResult,
                "Не удаётся найти указанный файл",
                "В Центре обновления означает рассинхронизацию кэша SoftwareDistribution; в обычных программах — отсутствие нужного файла.",
                "Если ошибка в Центре обновления — сбросьте кэш Центра обновления; если при запуске программы — проверьте .exe в PE-Докторе.",
                rules: ["wu.reset-corrupt-cache"]),

            H(0x80070003u, "ERROR_PATH_NOT_FOUND", ErrorCodeFamily.SystemComDirectXHResult,
                "Системе не удаётся найти указанный путь",
                "Отсутствует ожидаемая системная папка (например %TEMP% или подпапка SoftwareDistribution).",
                "Проверьте целостность папки %TEMP% и сбросьте кэш Центра обновления.",
                rules: ["disk.dirty-and-temp-health", "wu.reset-corrupt-cache"]),

            H(0x80070005u, "E_ACCESSDENIED", ErrorCodeFamily.SystemComDirectXHResult,
                "Отказано в доступе (Access Denied)",
                "Недостаточно прав учётной записи, папка %TEMP% закрыта от записи либо операцию заблокировал сторонний антивирус или политика.",
                "Запустите программу с правами администратора, проверьте доступность %TEMP% и блокирующие политики.",
                rules: ["disk.dirty-and-temp-health", "tools.unlock-regedit", "tools.unlock-cmd"]),

            H(0x8007000Du, "ERROR_INVALID_DATA", ErrorCodeFamily.SystemComDirectXHResult,
                "Недопустимые данные (повреждён пакет или конфигурация)",
                "Скачанный файл обновления или манифест обрезан либо содержит повреждённые данные.",
                "Сбросьте кэш Центра обновления и выполните проверку DISM + SFC.",
                rules: ["wu.reset-corrupt-cache", "sfc.cbs-component-store"]),

            H(0x80070020u, "ERROR_SHARING_VIOLATION", ErrorCodeFamily.SystemComDirectXHResult,
                "Файл занят другим процессом",
                "Обновляемый или удаляемый файл удерживается запущенной программой или фоновым сканером.",
                "Закройте фоновые программы или перезагрузите ПК и повторите действие."),

            H(0x80070057u, "E_INVALIDARG", ErrorCodeFamily.SystemComDirectXHResult,
                "Параметр задан неверно",
                "Передан некорректный аргумент системному вызову либо повреждены метаданные кэша обновлений или диска.",
                "Проверьте флаг ошибок диска (fsutil dirty), сбросьте кэш Центра обновления и запустите DISM + SFC.",
                rules: ["disk.dirty-and-temp-health", "wu.reset-corrupt-cache", "sfc.cbs-component-store"]),

            H(0x80070070u, "ERROR_DISK_FULL", ErrorCodeFamily.SystemComDirectXHResult,
                "Недостаточно места на диске",
                "На системном разделе C:\\ закончилось свободное пространство для распаковки пакетов или файла подкачки.",
                "Освободите место в разделе «Диск, Кэш и Реестр» (системные резервы C:\\, кэш браузеров и карта диска).",
                rules: ["disk.low-free-space"]),

            H(0x8007007Eu, "ERROR_MOD_NOT_FOUND", ErrorCodeFamily.SystemComDirectXHResult,
                "Не найден указанный модуль (DLL)",
                "Библиотека DLL или одна из её зависимых библиотек отсутствует в системе.",
                "Проверьте .exe программы в «PE-Докторе» и установите пакеты Visual C++ / DirectX.",
                runtimes: ["vcredist-2015-2022-x64", "directx-june-2010"]),

            H(0x800700C1u, "ERROR_BAD_EXE_FORMAT", ErrorCodeFamily.SystemComDirectXHResult,
                "Приложение не является приложением Win32 (конфликт x86/x64 или битый файл)",
                "Попытка загрузить 32-битную DLL в 64-битный процесс (или наоборот) либо исполняемый файл повреждён.",
                "Проверьте файл в «PE-Докторе» на конфликт разрядности и целостность заголовка MZ/PE.",
                runtimes: ["vcredist-2015-2022-x64"]),

            H(0x80070422u, "ERROR_SERVICE_DISABLED", ErrorCodeFamily.SystemComDirectXHResult,
                "Необходимая системная служба отключена",
                "Операция обратилась к системной службе (Центр обновления, Брандмауэр, Аудио, Поиск, Магазин), у которой выставлен тип запуска «Отключена».",
                "Запустите полную диагностику на вкладке «Диагностика и ремонт» — программа найдёт отключённые базовые службы и восстановит их запуск.",
                rules: ["wu.core-services", "fw.core-services", "store.core-services", "audio.core-services"]),

            H(0x80070424u, "ERROR_SERVICE_DOES_NOT_EXIST", ErrorCodeFamily.SystemComDirectXHResult,
                "Указанная системная служба не установлена",
                "Регистрация системной службы повреждена или отсутствует в текущей редакции Windows.",
                "Выполните проверку целостности системных файлов DISM + SFC.",
                rules: ["sfc.cbs-component-store"]),

            H(0x8007045Du, "ERROR_IO_DEVICE", ErrorCodeFamily.SystemComDirectXHResult,
                "Ошибка ввода-вывода на устройстве хранения (I/O Device Error)",
                "Накопитель или USB-порт не смог прочитать/записать сектор данных (плохой кабель SATA/USB, нехватка питания порта или сбойные блоки диска).",
                "Проверьте S.M.A.R.T. накопителя в разделе «Железо и Драйверы» и статус тома.",
                rules: ["disk.dirty-and-temp-health"]),

            H(0x80070490u, "ERROR_NOT_FOUND", ErrorCodeFamily.SystemComDirectXHResult,
                "Элемент не найден (повреждён манифест CBS или индекс)",
                "В Центре обновления и DISM указывает на отсутствие элемента в базе компонентов CBS.",
                "Выполните DISM /RestoreHealth + sfc /scannow.",
                rules: ["sfc.cbs-component-store", "wu.reset-corrupt-cache"]),

            H(0x80070570u, "ERROR_FILE_CORRUPT", ErrorCodeFamily.SystemComDirectXHResult,
                "Файл или папка повреждены и чтение невозможно",
                "Повреждение файловой системы NTFS или битый скачанный архив.",
                "Проверьте флаг ошибок диска (fsutil dirty / chkdsk) и целостность системных файлов.",
                rules: ["disk.dirty-and-temp-health", "sfc.cbs-component-store"]),

            H(0x800706BAu, "RPC_S_SERVER_UNAVAILABLE", ErrorCodeFamily.SystemComDirectXHResult,
                "Сервер RPC недоступен",
                "Не отвечает удалённый или локальный вызов процедур (остановлены службы DCOM/WMI/Spooler или соединение блокирует брандмауэр).",
                "Проверьте базовые системные службы, службу печати и репозиторий WMI.",
                rules: ["wmi.service-and-dcom", "print.spooler-service", "fw.core-services"]),

            H(0x800736B1u, "ERROR_SXS_CANT_GEN_ACTCTX", ErrorCodeFamily.SystemComDirectXHResult,
                "Не удалось запустить приложение из-за параллельной конфигурации (Side-by-Side)",
                "Программе не хватает точной версии библиотек Microsoft Visual C++ 2005 или 2008 в папке WinSxS.",
                "Установите официальные пакеты Visual C++ 2005 SP1 и Visual C++ 2008 SP1 (x86 и x64) на вкладке «Среды выполнения».",
                runtimes: ["vcredist-2005-x86", "vcredist-2005-x64", "vcredist-2008-x86", "vcredist-2008-x64"]),

            H(0x80040154u, "REGDB_E_CLASSNOTREG", ErrorCodeFamily.SystemComDirectXHResult,
                "Класс не зарегистрирован (Class not registered)",
                "COM/WinRT-компонент не зарегистрирован в реестре, отключён DCOM либо сбита регистрация системных приложений оболочки/браузера.",
                "Проверьте параметр EnableDCOM, перерегистрируйте пакеты оболочки/Store и выполните SFC.",
                rules: ["wmi.enable-dcom", "shell.win11-xaml-packages", "store.reset-cache-and-register"]),

            H(0x80041002u, "WBEM_E_NOT_FOUND", ErrorCodeFamily.SystemComDirectXHResult,
                "Объект или класс WMI не найден",
                "Запрашиваемый класс отсутствует в репозитории WMI либо база WMI рассогласована.",
                "Выполните мягкую сверку и восстановление репозитория WMI (winmgmt /salvagerepository).",
                rules: ["wmi.repository-consistency", "wmi.service-and-dcom"]),

            H(0x8004100Eu, "WBEM_E_INVALID_NAMESPACE", ErrorCodeFamily.SystemComDirectXHResult,
                "Повреждено пространство имён WMI (root\\cimv2)",
                "Репозиторий WMI повреждён сторонним клинером или сбоем питания.",
                "Запустите восстановление репозитория WMI и проверку системных файлов.",
                rules: ["wmi.repository-consistency", "sfc.cbs-component-store"]),

            H(0x80041013u, "WBEM_E_PROVIDER_LOAD_FAILURE", ErrorCodeFamily.SystemComDirectXHResult,
                "Не удалось загрузить COM-поставщика WMI",
                "Отсутствует или повреждена системная библиотека поставщика WMI.",
                "Восстановите репозиторий WMI и запустите DISM + SFC.",
                rules: ["wmi.repository-consistency", "sfc.cbs-component-store"]),

            H(0x887A0005u, "DXGI_ERROR_DEVICE_REMOVED", ErrorCodeFamily.SystemComDirectXHResult,
                "Видеокарта физически отключилась или сбросила драйвер в игре",
                "Графический процессор перестал отвечать на команды DirectX 11/12 (нестабильный разгон GPU/VRAM, перегрев, просадка 12V блока питания или баг драйвера).",
                "Снимите разгон видеокарты, обновите видеодрайвер и установите DirectX Runtime.",
                runtimes: ["directx-june-2010"]),

            H(0x887A0006u, "DXGI_ERROR_DEVICE_HUNG", ErrorCodeFamily.SystemComDirectXHResult,
                "Зависание конвейера видеокарты (GPU Hung)",
                "Конкретный шейдер или команда игры вызвала зависание графического драйвера.",
                "Очистите кэш шейдеров видеокарты в разделе «Диск, Кэш и Реестр», отключите оверлеи и обновите драйвер GPU.",
                runtimes: ["directx-june-2010"]),

            H(0x80092013u, "CRYPT_E_REVOCATION_OFFLINE", ErrorCodeFamily.SystemComDirectXHResult,
                "Не удалось проверить отзыв цифрового сертификата по сети",
                "Служба криптографии не может связаться с сервером CRL/OCSP из-за мёртвого прокси, блокировки в hosts или сбитых часов.",
                "Проверьте локальный прокси, файл hosts, службу CryptSvc и синхронизацию времени.",
                rules: ["net.dead-local-proxy", "net.hosts-file-health", "time.ntp-sync-health"]),

            H(0x800B0100u, "TRUST_E_NOSIGNATURE", ErrorCodeFamily.SystemComDirectXHResult,
                "В файле пакета отсутствует цифровая подпись",
                "Скачанный пакет обновления или установщик обрезан, либо повреждена папка каталогов подписей catroot2.",
                "Выполните сброс Центра обновления Windows (пересоздаст catroot2) и проверку DISM + SFC.",
                rules: ["wu.reset-corrupt-cache", "svc.cryptsvc-health"]),

            H(0x800B0109u, "CERT_E_UNTRUSTEDROOT", ErrorCodeFamily.SystemComDirectXHResult,
                "Цепочка сертификатов ведёт к недоверенному корневому центру",
                "Сбиты системные часы, соединение перехватывается прокси/антивирусом либо отключено автообновление корневых сертификатов.",
                "Синхронизируйте время Windows и проверьте настройки локального прокси.",
                rules: ["time.ntp-sync-health", "net.dead-local-proxy"]),

            // ==================== ДЕСЯТИЧНЫЕ КОДЫ MSI И WIN32 ====================
            Dec(2, "ERROR_FILE_NOT_FOUND", "Системе не удаётся найти указанный файл",
                "Отсутствует целевой файл или исполняемый путь службы.",
                "Проверьте путь к файлу или выполните проверку системных файлов.",
                rules: ["sfc.cbs-component-store"]),

            Dec(5, "ERROR_ACCESS_DENIED", "Отказано в доступе",
                "Операция требует прав администратора либо блокируется политикой или антивирусом.",
                "Перезапустите с правами администратора и проверьте блокирующие политики.",
                rules: ["disk.dirty-and-temp-health"]),

            Dec(126, "ERROR_MOD_NOT_FOUND", "Не найден указанный модуль (DLL)",
                "Отсутствует загружаемая библиотека DLL или её зависимость.",
                "Проверьте .exe файл программы в «PE-Докторе».",
                runtimes: ["vcredist-2015-2022-x64"]),

            Dec(193, "ERROR_BAD_EXE_FORMAT", "Не является приложением Win32",
                "Несовпадение разрядности 32/64 бит между .exe и .dll либо битый исполняемый файл.",
                "Проверьте .exe файл в «PE-Докторе».",
                runtimes: ["vcredist-2015-2022-x64"]),

            Dec(1058, "ERROR_SERVICE_DISABLED", "Служба отключена и не может быть запущена",
                "Целевая служба имеет тип запуска «Отключена» (Disabled).",
                "Выполните диагностику служб на вкладке «Диагностика и ремонт».",
                rules: ["wu.core-services", "fw.core-services"]),

            Dec(1601, "ERROR_INSTALL_SERVICE_FAILURE", "Не удаётся получить доступ к службе Windows Installer",
                "Служба установщика MSI (msiserver) отключена или заблокирована политикой DisableMSI.",
                "Восстановите службу Windows Installer и снимите политику DisableMSI.",
                rules: ["wmi.msi-installer-service", "wmi.disable-msi-policy"]),

            Dec(1603, "ERROR_INSTALL_FAILURE", "В процессе установки MSI произошла неисправимая ошибка",
                "Пакет .msi не смог записать файлы в %TEMP% / Program Files, уже установлена более новая версия пакета или ожидается перезагрузка ОС.",
                "Проверьте доступность папки %TEMP%, флаг ожидающей перезагрузки и службу Windows Installer.",
                rules: ["disk.dirty-and-temp-health", "wu.pending-reboot", "wmi.msi-installer-service"]),

            Dec(1618, "ERROR_INSTALL_ALREADY_RUNNING", "Уже выполняется другая установка MSI",
                "В фоне завис процесс msiexec.exe от предыдущего установщика.",
                "Дождитесь завершения другого установщика или перезапустите службу Windows Installer.",
                rules: ["wmi.msi-installer-service"]),

            Dec(1619, "ERROR_INSTALL_PACKAGE_OPEN_FAILED", "Не удалось открыть пакет установки MSI",
                "Файл .msi повреждён при скачивании или лежит в сетевой/временной папке без прав чтения.",
                "Скопируйте .msi в локальную папку и проверьте ассоциацию файлов .msi.",
                rules: ["assoc.msi-package"]),

            Dec(1625, "ERROR_INSTALL_PACKAGE_REJECTED", "Установка запрещена системной политикой",
                "В реестре включена политика запрета установки MSI-пакетов (DisableMSI).",
                "Снимите политику блокировки MSI на вкладке «Диагностика и ремонт».",
                rules: ["wmi.disable-msi-policy"]),

            Dec(1719, "ERROR_INSTALL_SERVICE_SAFEBOOT", "Служба Windows Installer недоступна (или ПК в безопасном режиме)",
                "Повреждена регистрация msiexec / службы msiserver либо Windows загружена в Safe Mode.",
                "Восстановите службу msiserver в обычном режиме загрузки Windows.",
                rules: ["wmi.msi-installer-service"]),

            Dec(2502, "MSI_INTERNAL_ERROR_2502", "Внутренняя ошибка установщика 2502 (нет прав на C:\\Windows\\Temp или %TEMP%)",
                "Установщик MSI запущен без повышения прав или не может создать временный файл в папке Temp.",
                "Проверьте здоровье папки %TEMP% и запускайте установщик от имени администратора.",
                rules: ["disk.dirty-and-temp-health"]),

            Dec(2503, "MSI_INTERNAL_ERROR_2503", "Внутренняя ошибка установщика 2503 (заблокирована запись во временную папку)",
                "Классическая ошибка Windows 10/11 при сбитых правах на C:\\Windows\\Temp или пользовательский %TEMP%.",
                "Выполните проверку папки %TEMP% и запустите командную строку от имени администратора для установки .msi.",
                rules: ["disk.dirty-and-temp-health"])
        };

        // Подключаем все коды синего экрана из BugCheckCatalog
        foreach (var bc in BugCheckCatalog.GetAll().OrderBy(b => b.Code))
        {
            list.Add(FromBugCheck(bc));
        }

        return list;
    }
}
