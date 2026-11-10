using System.Buffers.Binary;
using System.Text;
using UltimateWindows.Modules.Repair.Models;

namespace UltimateWindows.Modules.Repair.Bsod;

/// <summary>
/// Бинарный парсер файлов минидампов аварийного завершения Windows (C:\Windows\Minidump\*.dmp)
/// по спецификации Microsoft DbgHelp MINIDUMP_HEADER ('MDMP').
/// Расшифровывает стоп-коды BSOD, определяет сторонний сбойный драйвер (.sys) и переводит причину на понятный язык.
/// </summary>
public sealed class MinidumpBinaryAnalyzer
{
    private const uint MdmpMagic = 0x504D444D; // 'MDMP' в Little-Endian
    private const uint StreamTypeModuleList = 4;
    private const uint StreamTypeException = 6;
    private const uint StreamTypeSystemInfo = 7;
    private const int MinidumpModuleStructSize = 108; // 0x6C байт в формате Microsoft MINIDUMP_MODULE (Pack=4)

    private static readonly HashSet<string> StandardMicrosoftKernelModules = new(StringComparer.OrdinalIgnoreCase)
    {
        "ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe", "hal.dll", "halmacpi.dll",
        "kdcom.dll", "mcupdate_genuineintel.dll", "mcupdate_authenticamd.dll",
        "clfs.sys", "tm.sys", "pshed.sys", "bootvid.dll", "clipsp.sys", "fltmgr.sys",
        "ksecdd.sys", "cmimcext.sys", "werkernel.sys", "ntosext.sys", "ci.dll",
        "cng.sys", "wdf01000.sys", "wdfldr.sys", "acpiex.sys", "acpi.sys", "wmilib.sys",
        "pci.sys", "tpm.sys", "intelpep.sys", "amdpep.sys", "win32k.sys", "win32kbase.sys",
        "win32kfull.sys", "cdd.dll", "volmgr.sys", "volmgrx.sys", "mountmgr.sys", "partmgr.sys",
        "fvevol.sys", "volsnap.sys", "ntfs.sys", "ndis.sys", "netio.sys", "tcpip.sys"
    };

    private static readonly (string DriverPrefix, string VendorDescription)[] KnownThirdPartyDriverHints =
    [
        ("nvlddmkm", "Видеодрайвер NVIDIA GeForce (nvlddmkm.sys)"),
        ("nvhda", "Аудиодрайвер NVIDIA HDMI (nvhda64v.sys)"),
        ("amdkmdag", "Видеодрайвер AMD Radeon (amdkmdag.sys)"),
        ("amdfendr", "Модуль защиты сбоев AMD Radeon"),
        ("igdkmd", "Видеодрайвер Intel Graphics"),
        ("rt640x64", "Сетевой драйвер Realtek Ethernet"),
        ("rtwlane", "Драйвер Wi-Fi адаптера Realtek"),
        ("netwtw", "Драйвер Wi-Fi адаптера Intel Wireless"),
        ("mtkwl", "Драйвер Wi-Fi адаптера MediaTek"),
        ("iastor", "Драйвер контроллера накопителей Intel RST"),
        ("secnvme", "Драйвер накопителя Samsung NVMe"),
        ("vgk.sys", "Ядерный античит Riot Vanguard (vgk.sys)"),
        ("bedaisy", "Ядерный античит BattlEye (BEDaisy.sys)"),
        ("easyanticheat", "Ядерный античит EasyAntiCheat"),
        ("inpoutx64", "Устаревший уязвимый драйвер прямого доступа к портам"),
        ("winring0", "Устаревший уязвимый драйвер мониторинга WinRing0")
    ];

    public static BsodMinidumpReport? ParseMinidumpBytes(ReadOnlySpan<byte> data, string sourceFilePath = "<memory.dmp>")
    {
        if (data.Length < 32)
        {
            return null;
        }

        var sig = BinaryPrimitives.ReadUInt32LittleEndian(data[..4]);
        if (sig != MdmpMagic)
        {
            return null;
        }

        var streamCount = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(8, 4));
        var streamDirRva = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(12, 4));
        var unixTimestamp = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(20, 4));

        var crashTime = unixTimestamp > 0
            ? DateTimeOffset.FromUnixTimeSeconds(unixTimestamp)
            : DateTimeOffset.UtcNow;

        if (streamDirRva == 0 || streamCount > 256 || streamDirRva + (streamCount * 12) > data.Length)
        {
            return BuildReport(sourceFilePath, crashTime, null, PeArchitecture.Unknown, "Windows Minidump", []);
        }

        var cpuArch = PeArchitecture.Unknown;
        var osBuildSummary = "Windows 10 / 11";
        uint? bugCheckCode = null;
        var loadedModules = new List<string>();

        for (int i = 0; i < streamCount; i++)
        {
            var entry = data.Slice((int)streamDirRva + (i * 12), 12);
            var streamType = BinaryPrimitives.ReadUInt32LittleEndian(entry[..4]);
            var dataSize = BinaryPrimitives.ReadUInt32LittleEndian(entry.Slice(4, 4));
            var rva = BinaryPrimitives.ReadUInt32LittleEndian(entry.Slice(8, 4));

            if (rva == 0 || dataSize == 0 || (long)rva + dataSize > data.Length)
            {
                continue;
            }

            var streamSlice = data.Slice((int)rva, (int)dataSize);

            if (streamType == StreamTypeSystemInfo && streamSlice.Length >= 16)
            {
                var archCode = BinaryPrimitives.ReadUInt16LittleEndian(streamSlice[..2]);
                cpuArch = archCode switch
                {
                    0 => PeArchitecture.X86,
                    9 => PeArchitecture.X64,
                    12 => PeArchitecture.Arm64,
                    _ => PeArchitecture.Unknown
                };

                var major = BinaryPrimitives.ReadUInt32LittleEndian(streamSlice.Slice(8, 4));
                var minor = BinaryPrimitives.ReadUInt32LittleEndian(streamSlice.Slice(12, 4));
                var build = streamSlice.Length >= 20 ? BinaryPrimitives.ReadUInt32LittleEndian(streamSlice.Slice(16, 4)) : 0;
                osBuildSummary = build > 0 ? $"Windows NT {major}.{minor} (Build {build})" : $"Windows NT {major}.{minor}";
            }
            else if (streamType == StreamTypeException && streamSlice.Length >= 16)
            {
                // MINIDUMP_EXCEPTION_STREAM: ThreadId (4) + __alignment (4) + ExceptionRecord.ExceptionCode (4)
                var code = BinaryPrimitives.ReadUInt32LittleEndian(streamSlice.Slice(8, 4));
                if (code != 0)
                {
                    bugCheckCode = code;
                }
            }
            else if (streamType == StreamTypeModuleList && streamSlice.Length >= 4)
            {
                var moduleCount = BinaryPrimitives.ReadUInt32LittleEndian(streamSlice[..4]);
                var cappedCount = Math.Min(moduleCount, 512u);

                for (int m = 0; m < cappedCount; m++)
                {
                    var modOffset = 4 + (m * MinidumpModuleStructSize);
                    if (modOffset + MinidumpModuleStructSize > streamSlice.Length)
                    {
                        break;
                    }

                    var moduleNameRva = BinaryPrimitives.ReadUInt32LittleEndian(streamSlice.Slice(modOffset + 20, 4));
                    if (TryReadMinidumpString(data, moduleNameRva, out var fullModulePath))
                    {
                        var shortName = ExtractFileNameCrossPlatform(fullModulePath);
                        if (!string.IsNullOrWhiteSpace(shortName))
                        {
                            loadedModules.Add(shortName);
                        }
                    }
                }
            }
        }

        return BuildReport(sourceFilePath, crashTime, bugCheckCode, cpuArch, osBuildSummary, loadedModules);
    }

    public IReadOnlyList<BsodMinidumpReport> ScanMinidumpDirectory(string minidumpDirectory, int maxReports = 15)
    {
        if (string.IsNullOrWhiteSpace(minidumpDirectory) || !Directory.Exists(minidumpDirectory))
        {
            return Array.Empty<BsodMinidumpReport>();
        }

        var reports = new List<BsodMinidumpReport>();
        IEnumerable<string> dumpFiles;
        try
        {
            dumpFiles = Directory.EnumerateFiles(minidumpDirectory, "*.dmp", SearchOption.TopDirectoryOnly)
                .OrderByDescending(File.GetLastWriteTimeUtc)
                .Take(maxReports);
        }
        catch
        {
            return Array.Empty<BsodMinidumpReport>();
        }

        foreach (var file in dumpFiles)
        {
            try
            {
                var fi = new FileInfo(file);
                if (!fi.Exists || fi.Length < 32 || fi.Length > 32 * 1024 * 1024)
                {
                    continue;
                }

                var bytes = File.ReadAllBytes(file);
                var parsed = ParseMinidumpBytes(bytes, file);
                if (parsed is not null)
                {
                    reports.Add(parsed);
                }
            }
            catch
            {
                // Пропускаем недоступные системные дампы без сбоя
            }
        }

        return reports;
    }

    private static BsodMinidumpReport BuildReport(
        string dumpPath,
        DateTimeOffset crashTime,
        uint? bugCheckCode,
        PeArchitecture arch,
        string osBuild,
        List<string> loadedModules)
    {
        string? suspectedThirdParty = null;
        string? vendorLabel = null;

        // 1. Сначала ищем известные проблемные драйверы видеокарт/сети/античитов среди загруженных модулей
        foreach (var mod in loadedModules)
        {
            foreach (var (prefix, desc) in KnownThirdPartyDriverHints)
            {
                if (mod.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    suspectedThirdParty = mod;
                    vendorLabel = desc;
                    break;
                }
            }

            if (suspectedThirdParty is not null)
            {
                break;
            }
        }

        // 2. Если известных сигнатур нет, берем первый сторонний .sys модуль вне ядра Microsoft
        if (suspectedThirdParty is null)
        {
            suspectedThirdParty = loadedModules.FirstOrDefault(m =>
                m.EndsWith(".sys", StringComparison.OrdinalIgnoreCase) &&
                !StandardMicrosoftKernelModules.Contains(m));
        }

        var (bugName, baseReason, baseAction) = DescribeStopCode(bugCheckCode);

        if (vendorLabel is not null)
        {
            baseReason = $"{baseReason} В дампе обнаружен активный сторонний модуль: {vendorLabel}.";
            baseAction = $"Обновите или чисто переустановите WHQL-драйвер для «{vendorLabel}», а также проверьте целостность ОС через рецепт DISM + SFC.";
        }
        else if (suspectedThirdParty is not null)
        {
            baseReason = $"{baseReason} Вероятный сторонний драйвер в стеке модулей: {suspectedThirdParty}.";
        }

        return new BsodMinidumpReport(
            DumpFilePath: dumpPath,
            CrashTimestampUtc: crashTime,
            BugCheckCode: bugCheckCode,
            BugCheckName: bugName,
            ProcessorArchitecture: arch,
            OsBuildSummary: osBuild,
            SuspectedThirdPartyDriver: suspectedThirdParty,
            SimpleHumanExplanation: baseReason,
            RecommendedUserAction: baseAction,
            LoadedDriverModulesSample: loadedModules.Take(14).ToList());
    }

    private static (string Name, string SimpleReason, string Action) DescribeStopCode(uint? code) => code switch
    {
        0x00000116 or 0x00000117 => (
            "VIDEO_TDR_FAILURE",
            "Видеокарта перестала отвечать на команды Windows (сбой видеодрайвера или перегрев чипа/памяти GPU).",
            "Проверьте температуры GPU Hotspot на вкладке «Железо», уберите разгон и установите стабильный WHQL-видеодрайвер."),

        0x00000124 => (
            "WHEA_UNCORRECTABLE_ERROR",
            "Процессор, контроллер памяти или NVMe-диск сообщил об аппаратной ошибке (часто из-за нестабильного андервольтинга/разгона или перегрева).",
            "Сбросьте нестабильный разгон CPU/Curve Optimizer в BIOS и запустите стресс-тест стабильности во вкладке «Железо»."),

        0x0000001A => (
            "MEMORY_MANAGEMENT",
            "Критическая ошибка управления оперативной памятью или файлом подкачки.",
            "Проверьте стабильность XMP/EXPO профиля ОЗУ и запустите рецепт проверки системных файлов DISM + SFC."),

        0x0000003B => (
            "SYSTEM_SERVICE_EXCEPTION",
            "Сбой при переходе системной службы или графического драйвера в режим ядра.",
            "Запустите восстановление системных компонентов (DISM + SFC) и обновите драйверы видеокарты и чипсета."),

        0x00000050 => (
            "PAGE_FAULT_IN_NONPAGED_AREA",
            "Драйвер или античит обратился к неверному адресу в защищенной области памяти (либо сбоит планка ОЗУ).",
            "Проверьте сторонние драйверы/античиты и целостность системных файлов Windows."),

        0x0000009F => (
            "DRIVER_POWER_STATE_FAILURE",
            "Один из драйверов устройств завис при выходе ПК из сна или переключении режима энергосбережения.",
            "Обновите драйверы Wi-Fi/чипсета и проверьте схему электропитания."),

        0x00000133 => (
            "DPC_WATCHDOG_VIOLATION",
            "Драйвер устройства (чаще всего SSD, Wi-Fi или видеокарты) слишком долго удерживал процессор в прерывании.",
            "Проверьте прошивку NVMe SSD и обновите сетевой и графический драйверы."),

        0x00000139 => (
            "KERNEL_SECURITY_CHECK_FAILURE",
            "Ядро Windows остановило систему из-за повреждения структуры памяти или несовместимого старого драйвера.",
            "Запустите рецепт проверки целостности ОС (DISM + SFC) и удалите устаревшие утилиты с ядерными драйверами."),

        0x000000EF => (
            "CRITICAL_PROCESS_DIED",
            "Внезапно завершился критически важный системный процесс Windows (возможны поврежденные системные файлы или сбой SSD).",
            "Проверьте здоровье S.M.A.R.T. системного диска и выполните восстановление хранилища DISM + SFC."),

        _ => (
            code.HasValue ? $"BUGCHECK_0x{code.Value:X8}" : "KERNEL_MINIDUMP_REPORT",
            "Зафиксировано аварийное завершение ядра Windows (синий экран).",
            "Рекомендуется выполнить проверку системного хранилища DISM + SFC и обновить сторонние драйверы.")
    };

    private static bool TryReadMinidumpString(ReadOnlySpan<byte> data, uint rva, out string value)
    {
        value = "";
        if (rva == 0 || (long)rva + 4 > data.Length)
        {
            return false;
        }

        var byteLength = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((int)rva, 4));
        if (byteLength == 0 || byteLength > 1024 || (long)rva + 4 + byteLength > data.Length)
        {
            return false;
        }

        value = Encoding.Unicode.GetString(data.Slice((int)rva + 4, (int)byteLength));
        return true;
    }

    private static string ExtractFileNameCrossPlatform(string rawPath)
    {
        var idx = rawPath.LastIndexOfAny(['\\', '/']);
        return idx >= 0 ? rawPath[(idx + 1)..] : rawPath;
    }
}
