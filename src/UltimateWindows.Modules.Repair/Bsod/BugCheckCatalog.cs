namespace UltimateWindows.Modules.Repair.Bsod;

/// <summary>
/// Группа причин синего экрана. От группы зависит общий совет и то,
/// можно ли искать виновный драйвер по стеку вызовов.
/// </summary>
public enum BugCheckCategory
{
    Unknown = 0,
    DriverFault = 1,
    MemoryCorruption = 2,
    HardwareError = 3,
    StorageOrFileSystem = 4,
    Graphics = 5,
    PowerOrSleep = 6,
    SystemProcessOrFiles = 7,
    BootOrConfiguration = 8,
    WatchdogTimeout = 9,
    SecurityOrVirtualization = 10,
    ManuallyInitiated = 11
}

/// <summary>
/// Описание кода остановки (bug check code).
/// </summary>
/// <param name="FaultAddressParameterIndex">
/// Номер параметра (с нуля), в котором Windows передаёт адрес сбойной инструкции или указатель внутрь виновного драйвера.
/// Значение -1 означает, что такого параметра у этого кода нет.
/// </param>
public sealed record BugCheckDescriptor(
    uint Code,
    string Name,
    BugCheckCategory Category,
    string SimpleReason,
    string RecommendedAction,
    int FaultAddressParameterIndex = -1)
{
    public bool IsKnown => Category != BugCheckCategory.Unknown;
}

/// <summary>
/// Справочник кодов остановки Windows. Имена кодов и смысл параметров взяты из открытого справочника
/// Microsoft «Bug Check Code Reference»; пояснения и советы написаны для этого проекта.
/// </summary>
public static class BugCheckCatalog
{
    private static readonly Dictionary<uint, BugCheckDescriptor> ByCode = BuildCatalog();

    public static int Count => ByCode.Count;

    public static IReadOnlyCollection<BugCheckDescriptor> GetAll() => ByCode.Values;

    public static BugCheckDescriptor Describe(uint code)
    {
        if (ByCode.TryGetValue(code, out var exact))
        {
            return exact;
        }

        // Варианты с битом 0x10000000 — те же ошибки, записанные без подробностей (суффикс _M в имени).
        if ((code & 0xF000_0000u) == 0x1000_0000u && ByCode.TryGetValue(code & 0x0FFF_FFFFu, out var baseCode))
        {
            return baseCode with { Code = code, Name = baseCode.Name + "_M" };
        }

        return new BugCheckDescriptor(
            code,
            $"BUGCHECK_0x{code:X8}",
            BugCheckCategory.Unknown,
            DefaultReason(BugCheckCategory.Unknown),
            DefaultAction(BugCheckCategory.Unknown));
    }

    public static string DefaultReason(BugCheckCategory category) => category switch
    {
        BugCheckCategory.DriverFault =>
            "Драйвер обратился к памяти или ресурсу ядра недопустимым образом.",
        BugCheckCategory.MemoryCorruption =>
            "Повреждены служебные структуры памяти ядра. Обычно это ошибка драйвера, реже — неисправная оперативная память.",
        BugCheckCategory.HardwareError =>
            "Оборудование сообщило о неисправимой ошибке.",
        BugCheckCategory.StorageOrFileSystem =>
            "Windows не смогла прочитать или записать данные на диск либо обнаружила повреждение файловой системы.",
        BugCheckCategory.Graphics =>
            "Видеокарта или её драйвер перестали отвечать.",
        BugCheckCategory.PowerOrSleep =>
            "Драйвер устройства не завершил переход в сон или выход из сна за отведённое время.",
        BugCheckCategory.SystemProcessOrFiles =>
            "Аварийно завершился процесс или компонент, без которого Windows не может работать.",
        BugCheckCategory.BootOrConfiguration =>
            "Windows не смогла загрузиться с системного диска или прочитать свою конфигурацию.",
        BugCheckCategory.WatchdogTimeout =>
            "Процессор или драйвер слишком долго не отвечал, и сторожевой таймер Windows остановил систему.",
        BugCheckCategory.SecurityOrVirtualization =>
            "Сбой в подсистеме защиты ядра или виртуализации Windows.",
        BugCheckCategory.ManuallyInitiated =>
            "Сбой вызван намеренно: с клавиатуры, из отладчика или удержанием кнопки питания.",
        _ =>
            "Зафиксировано аварийное завершение ядра Windows (синий экран)."
    };

    public static string DefaultAction(BugCheckCategory category) => category switch
    {
        BugCheckCategory.DriverFault =>
            "Обновите или переустановите драйверы устройств. Если сбой начался после обновления драйвера, верните его предыдущую версию.",
        BugCheckCategory.MemoryCorruption =>
            "Обновите драйверы устройств. Если сбои повторяются, проверьте оперативную память средством проверки памяти Windows и отключите разгон памяти (XMP/EXPO).",
        BugCheckCategory.HardwareError =>
            "Сбросьте разгон и пониженное напряжение в BIOS, проверьте температуры и блок питания, обновите BIOS. Драйверы здесь обычно ни при чём.",
        BugCheckCategory.StorageOrFileSystem =>
            "Проверьте состояние диска (S.M.A.R.T.) на вкладке «Железо», запустите chkdsk для системного раздела и проверьте кабель или слот накопителя.",
        BugCheckCategory.Graphics =>
            "Переустановите драйвер видеокарты с сайта производителя, уберите разгон видеокарты и проверьте её температуру.",
        BugCheckCategory.PowerOrSleep =>
            "Обновите драйверы чипсета, сети и видеокарты. Если сбой повторяется, отключите быстрый запуск Windows.",
        BugCheckCategory.SystemProcessOrFiles =>
            "Запустите проверку системных файлов (DISM + SFC) и проверьте состояние системного диска.",
        BugCheckCategory.BootOrConfiguration =>
            "Проверьте режим контроллера дисков в BIOS (AHCI/RAID) и состояние системного диска, затем выполните восстановление загрузки из среды восстановления Windows.",
        BugCheckCategory.WatchdogTimeout =>
            "Обновите драйверы накопителя, сети и видеокарты, а также прошивку SSD. Если сбой повторяется под нагрузкой, сбросьте разгон процессора.",
        BugCheckCategory.SecurityOrVirtualization =>
            "Установите обновления Windows и BIOS и обновите драйверы. Если сбой начался после установки программы с драйвером ядра, удалите её.",
        BugCheckCategory.ManuallyInitiated =>
            "Если сбой вызвали вы сами, ничего делать не нужно.",
        _ =>
            "Проверьте системные файлы (DISM + SFC) и обновите драйверы устройств."
    };

    private static Dictionary<uint, BugCheckDescriptor> BuildCatalog()
    {
        var map = new Dictionary<uint, BugCheckDescriptor>();

        void Add(
            uint code,
            string name,
            BugCheckCategory category,
            string? reason = null,
            string? action = null,
            int faultParameter = -1)
        {
            map[code] = new BugCheckDescriptor(
                code,
                name,
                category,
                reason ?? DefaultReason(category),
                action ?? DefaultAction(category),
                faultParameter);
        }

        // ---------- Ошибки драйверов ----------
        Add(0x00000001, "APC_INDEX_MISMATCH", BugCheckCategory.DriverFault);
        Add(0x0000000A, "IRQL_NOT_LESS_OR_EQUAL", BugCheckCategory.DriverFault,
            "Код ядра или драйвера обратился к недоступной памяти на повышенном уровне прерываний.",
            faultParameter: 3);
        Add(0x00000018, "REFERENCE_BY_POINTER", BugCheckCategory.DriverFault);
        Add(0x0000001E, "KMODE_EXCEPTION_NOT_HANDLED", BugCheckCategory.DriverFault,
            "В режиме ядра возникло исключение, которое никто не обработал.",
            faultParameter: 1);
        Add(0x0000003B, "SYSTEM_SERVICE_EXCEPTION", BugCheckCategory.DriverFault,
            "Исключение возникло при выполнении системного вызова в режиме ядра.",
            faultParameter: 1);
        Add(0x0000003D, "INTERRUPT_EXCEPTION_NOT_HANDLED", BugCheckCategory.DriverFault);
        Add(0x00000044, "MULTIPLE_IRP_COMPLETE_REQUESTS", BugCheckCategory.DriverFault);
        Add(0x0000004A, "IRQL_GT_ZERO_AT_SYSTEM_SERVICE", BugCheckCategory.DriverFault);
        Add(0x0000007E, "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", BugCheckCategory.DriverFault,
            "Системный поток вызвал исключение, которое не было обработано.",
            faultParameter: 1);
        Add(0x0000007F, "UNEXPECTED_KERNEL_MODE_TRAP", BugCheckCategory.DriverFault,
            "Процессор сообщил об ошибке, которую ядро не смогло обработать. Причина — драйвер, переполнивший стек ядра, либо неисправное оборудование.",
            "Обновите драйверы устройств. Если сбои повторяются, сбросьте разгон и проверьте оперативную память.");
        Add(0x0000008E, "KERNEL_MODE_EXCEPTION_NOT_HANDLED", BugCheckCategory.DriverFault,
            "В режиме ядра возникло исключение, которое никто не обработал.",
            faultParameter: 1);
        Add(0x000000BE, "ATTEMPTED_WRITE_TO_READONLY_MEMORY", BugCheckCategory.DriverFault,
            "Драйвер попытался записать данные в память, доступную только для чтения.");
        Add(0x000000C1, "SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION", BugCheckCategory.DriverFault,
            "Драйвер записал данные за пределы выделенного ему участка памяти.");
        Add(0x000000C4, "DRIVER_VERIFIER_DETECTED_VIOLATION", BugCheckCategory.DriverFault,
            "Средство проверки драйверов (Driver Verifier) поймало драйвер на нарушении правил.",
            "Обновите или удалите указанный драйвер. После диагностики отключите Driver Verifier командой «verifier /reset».");
        Add(0x000000C9, "DRIVER_VERIFIER_IOMANAGER_VIOLATION", BugCheckCategory.DriverFault,
            "Средство проверки драйверов (Driver Verifier) поймало драйвер на нарушении правил ввода-вывода.",
            "Обновите или удалите указанный драйвер. После диагностики отключите Driver Verifier командой «verifier /reset».");
        Add(0x000000CE, "DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS", BugCheckCategory.DriverFault,
            "Драйвер выгрузился, не отменив свои незавершённые операции.");
        Add(0x000000D1, "DRIVER_IRQL_NOT_LESS_OR_EQUAL", BugCheckCategory.DriverFault,
            "Драйвер обратился к недоступной памяти на повышенном уровне прерываний. Почти всегда это ошибка самого драйвера.",
            faultParameter: 3);
        Add(0x000000D5, "DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL", BugCheckCategory.DriverFault,
            "Драйвер обратился к памяти, которую уже освободил.",
            faultParameter: 2);
        Add(0x000000D6, "DRIVER_PAGE_FAULT_BEYOND_END_OF_ALLOCATION", BugCheckCategory.DriverFault,
            "Драйвер обратился к памяти за пределами выделенного ему участка.",
            faultParameter: 2);
        Add(0x000000F7, "DRIVER_OVERRAN_STACK_BUFFER", BugCheckCategory.DriverFault,
            "Драйвер переполнил буфер в стеке ядра.");
        Add(0x000000FC, "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY", BugCheckCategory.DriverFault,
            "Произошла попытка выполнить код из области памяти, где исполнение запрещено.",
            faultParameter: 0);
        Add(0x000000FE, "BUGCODE_USB_DRIVER", BugCheckCategory.DriverFault,
            "Ошибка драйвера USB-контроллера или USB-устройства.",
            "Обновите драйверы чипсета и USB-контроллера и отключите недавно подключённые USB-устройства.");
        Add(0x0000010D, "WDF_VIOLATION", BugCheckCategory.DriverFault,
            "Драйвер нарушил правила платформы драйверов Windows (WDF).");
        Add(0x00000144, "BUGCODE_USB3_DRIVER", BugCheckCategory.DriverFault,
            "Ошибка драйвера контроллера USB 3.x или подключённого к нему устройства.",
            "Обновите драйверы чипсета и USB-контроллера и отключите недавно подключённые USB-устройства.");
        Add(0x00000153, "KERNEL_LOCK_ENTRY_LEAKED_ON_THREAD_TERMINATION", BugCheckCategory.DriverFault);
        Add(0x00000162, "KERNEL_AUTO_BOOST_INVALID_LOCK_RELEASE", BugCheckCategory.DriverFault);

        // ---------- Повреждение памяти ядра ----------
        Add(0x00000019, "BAD_POOL_HEADER", BugCheckCategory.MemoryCorruption);
        Add(0x0000001A, "MEMORY_MANAGEMENT", BugCheckCategory.MemoryCorruption,
            "Серьёзная ошибка диспетчера памяти Windows. Причина — ошибка драйвера или неисправная оперативная память.");
        Add(0x0000004E, "PFN_LIST_CORRUPT", BugCheckCategory.MemoryCorruption);
        Add(0x00000050, "PAGE_FAULT_IN_NONPAGED_AREA", BugCheckCategory.MemoryCorruption,
            "Произошло обращение к адресу памяти, которого не существует. Причина — ошибка драйвера или антивируса либо неисправная оперативная память.",
            faultParameter: 2);
        Add(0x000000C2, "BAD_POOL_CALLER", BugCheckCategory.MemoryCorruption,
            "Драйвер неверно запросил или освободил память ядра.");
        Add(0x000000C5, "DRIVER_CORRUPTED_EXPOOL", BugCheckCategory.MemoryCorruption,
            "Драйвер повредил системный пул памяти ядра.",
            faultParameter: 3);
        Add(0x00000109, "CRITICAL_STRUCTURE_CORRUPTION", BugCheckCategory.MemoryCorruption,
            "Изменён защищённый код или данные ядра. Причина — драйвер, вмешивающийся в ядро, или неисправная оперативная память.");
        Add(0x00000139, "KERNEL_SECURITY_CHECK_FAILURE", BugCheckCategory.MemoryCorruption,
            "Ядро обнаружило повреждение критической структуры данных. Обычно это ошибка драйвера.");
        Add(0x0000013A, "KERNEL_MODE_HEAP_CORRUPTION", BugCheckCategory.MemoryCorruption,
            "Повреждена куча памяти ядра. Обычно это ошибка драйвера.");
        Add(0x00000189, "BAD_OBJECT_HEADER", BugCheckCategory.MemoryCorruption);

        // ---------- Неисправность оборудования ----------
        Add(0x0000002E, "DATA_BUS_ERROR", BugCheckCategory.HardwareError,
            "Ошибка шины данных. Чаще всего неисправна оперативная память.");
        Add(0x00000080, "NMI_HARDWARE_FAILURE", BugCheckCategory.HardwareError);
        Add(0x0000009C, "MACHINE_CHECK_EXCEPTION", BugCheckCategory.HardwareError,
            "Процессор сообщил о неисправимой аппаратной ошибке.");
        Add(0x00000101, "CLOCK_WATCHDOG_TIMEOUT", BugCheckCategory.HardwareError,
            "Одно из ядер процессора перестало отвечать на прерывания таймера. Частые причины — разгон, пониженное напряжение, устаревший BIOS.");
        Add(0x00000124, "WHEA_UNCORRECTABLE_ERROR", BugCheckCategory.HardwareError,
            "Процессор, память или шина сообщили о неисправимой аппаратной ошибке. Частые причины — разгон, пониженное напряжение, перегрев.");
        Add(0x0000012B, "FAULTY_HARDWARE_CORRUPTED_PAGE", BugCheckCategory.HardwareError,
            "Найдена страница памяти с искажённым битом. Это признак неисправной оперативной памяти.",
            "Проверьте оперативную память средством проверки памяти Windows, отключите разгон памяти (XMP/EXPO) и при повторении замените неисправную планку.");
        Add(0x0000017E, "MICROCODE_REVISION_MISMATCH", BugCheckCategory.HardwareError,
            "Ядра процессора работают с разными версиями микрокода.",
            "Обновите BIOS до последней версии с сайта производителя.");

        // ---------- Диск и файловая система ----------
        Add(0x00000023, "FAT_FILE_SYSTEM", BugCheckCategory.StorageOrFileSystem);
        Add(0x00000024, "NTFS_FILE_SYSTEM", BugCheckCategory.StorageOrFileSystem);
        Add(0x00000077, "KERNEL_STACK_INPAGE_ERROR", BugCheckCategory.StorageOrFileSystem,
            "Windows не смогла прочитать с диска страницу памяти ядра из файла подкачки.");
        Add(0x0000007A, "KERNEL_DATA_INPAGE_ERROR", BugCheckCategory.StorageOrFileSystem,
            "Windows не смогла прочитать с диска страницу памяти ядра из файла подкачки.");
        Add(0x00000154, "UNEXPECTED_STORE_EXCEPTION", BugCheckCategory.StorageOrFileSystem,
            "Сбой диспетчера сжатой памяти. Часто связан с неисправным или медленно отвечающим системным диском.");

        // ---------- Видеокарта ----------
        Add(0x000000EA, "THREAD_STUCK_IN_DEVICE_DRIVER", BugCheckCategory.Graphics,
            "Поток драйвера устройства, обычно видеокарты, завис в бесконечном ожидании.");
        Add(0x0000010E, "VIDEO_MEMORY_MANAGEMENT_INTERNAL", BugCheckCategory.Graphics,
            "Внутренняя ошибка диспетчера видеопамяти. Обычно это ошибка драйвера видеокарты.");
        Add(0x00000113, "VIDEO_DXGKRNL_FATAL_ERROR", BugCheckCategory.Graphics,
            "Графическое ядро DirectX обнаружило нарушение. Обычно это ошибка драйвера видеокарты.");
        Add(0x00000116, "VIDEO_TDR_FAILURE", BugCheckCategory.Graphics,
            "Видеокарта перестала отвечать, и Windows не смогла перезапустить её драйвер.",
            faultParameter: 1);
        Add(0x00000117, "VIDEO_TDR_TIMEOUT_DETECTED", BugCheckCategory.Graphics,
            "Драйвер видеокарты не ответил за отведённое время.",
            faultParameter: 1);
        Add(0x00000119, "VIDEO_SCHEDULER_INTERNAL_ERROR", BugCheckCategory.Graphics,
            "Планировщик видеокарты обнаружил неисправимое нарушение. Обычно это ошибка драйвера видеокарты или её перегрев.");
        Add(0x00000141, "VIDEO_ENGINE_TIMEOUT_DETECTED", BugCheckCategory.Graphics,
            "Один из блоков видеокарты не ответил за отведённое время.",
            faultParameter: 1);

        // ---------- Электропитание и сон ----------
        Add(0x0000009F, "DRIVER_POWER_STATE_FAILURE", BugCheckCategory.PowerOrSleep);
        Add(0x000000A0, "INTERNAL_POWER_ERROR", BugCheckCategory.PowerOrSleep,
            "Ошибка диспетчера электропитания. Часто возникает при работе с файлом гибернации.",
            "Обновите драйверы чипсета и накопителя. Если сбой возникает при гибернации, пересоздайте её файл командами «powercfg /h off» и «powercfg /h on».");
        Add(0x0000014F, "PDC_WATCHDOG_TIMEOUT", BugCheckCategory.PowerOrSleep,
            "Компонент системы не отреагировал вовремя при выходе из режима ожидания.");

        // ---------- Сторожевые таймеры ----------
        Add(0x00000133, "DPC_WATCHDOG_VIOLATION", BugCheckCategory.WatchdogTimeout,
            "Драйвер слишком долго удерживал процессор в обработчике прерывания. Чаще всего виноват драйвер накопителя, сети или видеокарты.");
        Add(0x000001D5, "DRIVER_PNP_WATCHDOG", BugCheckCategory.WatchdogTimeout,
            "Драйвер не завершил операцию Plug and Play за отведённое время.");

        // ---------- Системные процессы и файлы ----------
        Add(0x000000EF, "CRITICAL_PROCESS_DIED", BugCheckCategory.SystemProcessOrFiles,
            "Внезапно завершился критически важный процесс Windows. Причина — повреждённые системные файлы или сбой системного диска.");
        Add(0x000000F4, "CRITICAL_OBJECT_TERMINATION", BugCheckCategory.SystemProcessOrFiles,
            "Внезапно завершился критически важный процесс или поток Windows. Причина — повреждённые системные файлы или сбой системного диска.");
        Add(0xC000021A, "WINLOGON_FATAL_ERROR", BugCheckCategory.SystemProcessOrFiles,
            "Аварийно завершился системный процесс входа в систему (winlogon или csrss).");
        Add(0xC0000221, "STATUS_IMAGE_CHECKSUM_MISMATCH", BugCheckCategory.SystemProcessOrFiles,
            "Повреждён системный файл или драйвер: его контрольная сумма не совпала.");

        // ---------- Загрузка и конфигурация ----------
        Add(0x00000051, "REGISTRY_ERROR", BugCheckCategory.BootOrConfiguration,
            "Серьёзная ошибка реестра: файл куста повреждён либо диск читается с ошибками.");
        Add(0x0000005C, "HAL_INITIALIZATION_FAILED", BugCheckCategory.BootOrConfiguration);
        Add(0x0000006B, "PROCESS1_INITIALIZATION_FAILED", BugCheckCategory.BootOrConfiguration);
        Add(0x00000074, "BAD_SYSTEM_CONFIG_INFO", BugCheckCategory.BootOrConfiguration,
            "Повреждён системный раздел реестра или параметры загрузки.");
        Add(0x0000007B, "INACCESSIBLE_BOOT_DEVICE", BugCheckCategory.BootOrConfiguration,
            "Windows потеряла доступ к системному диску во время загрузки.");
        Add(0x000000A5, "ACPI_BIOS_ERROR", BugCheckCategory.BootOrConfiguration,
            "BIOS компьютера не полностью соответствует стандарту ACPI.",
            "Обновите BIOS до последней версии с сайта производителя платы или ноутбука.");
        Add(0x000000ED, "UNMOUNTABLE_BOOT_VOLUME", BugCheckCategory.BootOrConfiguration,
            "Windows не смогла подключить системный раздел: повреждена файловая система или сам диск.");

        // ---------- Защита ядра и виртуализация ----------
        Add(0x0000018B, "SECURE_KERNEL_ERROR", BugCheckCategory.SecurityOrVirtualization);
        Add(0x00020001, "HYPERVISOR_ERROR", BugCheckCategory.SecurityOrVirtualization);

        // ---------- Сбой, вызванный вручную ----------
        Add(0x000000E2, "MANUALLY_INITIATED_CRASH", BugCheckCategory.ManuallyInitiated);
        Add(0x000001C8, "MANUALLY_INITIATED_POWER_BUTTON_HOLD", BugCheckCategory.ManuallyInitiated,
            "Дамп записан из-за долгого удержания кнопки питания: система перед этим зависла.",
            "Если компьютер завис сам, проверьте драйверы и температуры; если кнопку удерживали намеренно, ничего делать не нужно.");
        Add(0xDEADDEAD, "MANUALLY_INITIATED_CRASH1", BugCheckCategory.ManuallyInitiated);

        return map;
    }
}
