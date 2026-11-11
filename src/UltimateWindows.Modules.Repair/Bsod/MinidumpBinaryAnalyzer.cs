using System.Buffers.Binary;
using System.Text;
using UltimateWindows.Modules.Repair.Models;

namespace UltimateWindows.Modules.Repair.Bsod;

/// <summary>
/// Анализатор файлов аварийных дампов Windows.
///
/// Синие экраны записывают дампы ядра (C:\Windows\Minidump\*.dmp, форматы PAGEDU64 и PAGEDUMP) —
/// их разбирает <see cref="KernelCrashDumpReader"/>, а здесь из сырых данных делается вывод:
/// какой код остановки, что он значит и какой драйвер вероятнее всего виноват.
/// Дампы упавших программ (формат MDMP) тоже распознаются, но помечаются как сбой программы, а не как синий экран.
/// </summary>
public sealed class MinidumpBinaryAnalyzer
{
    private const uint MdmpMagic = 0x504D444D; // 'MDMP'
    private const uint StreamTypeModuleList = 4;
    private const uint StreamTypeException = 6;
    private const uint StreamTypeSystemInfo = 7;
    private const int MinidumpModuleStructSize = 108; // MINIDUMP_MODULE

    // Малые дампы занимают от сотен килобайт до нескольких мегабайт — их читаем целиком.
    // У больших дампов (полный дамп памяти) нужен только заголовок.
    private const int MaxFullReadBytes = 16 * 1024 * 1024;
    private const int HeaderOnlyReadBytes = 64 * 1024;

    // В глубине стека лежат устаревшие адреса от прошлых вызовов, поэтому смотрим только на его вершину.
    private const int MaxStackHintsForAttribution = 64;

    private sealed record CulpritAttribution(
        string? SuspectDriver,
        CrashCulpritConfidence Confidence,
        string? FaultingModule,
        string? Evidence);

    /// <summary>
    /// Разбирает содержимое файла дампа. Возвращает null, если это не дамп ядра и не дамп программы.
    /// </summary>
    /// <param name="data">Содержимое файла (для больших дампов достаточно начала файла).</param>
    /// <param name="sourceFilePath">Путь к файлу, только для отчёта.</param>
    /// <param name="fileTimestampUtc">Время записи файла; используется, если в самом дампе времени сбоя нет.</param>
    public static BsodMinidumpReport? ParseMinidumpBytes(
        ReadOnlySpan<byte> data,
        string sourceFilePath = "<memory.dmp>",
        DateTimeOffset? fileTimestampUtc = null)
    {
        var kernelDump = KernelCrashDumpReader.TryParse(data);
        if (kernelDump is not null)
        {
            return BuildKernelReport(kernelDump, sourceFilePath, fileTimestampUtc);
        }

        return ParseUserModeMinidump(data, sourceFilePath, fileTimestampUtc);
    }

    /// <summary>
    /// Разбирает один файл дампа с диска. Возвращает null, если файла нет или это не дамп.
    /// Большие дампы целиком не читаются: для кода остановки достаточно заголовка.
    /// </summary>
    public static BsodMinidumpReport? AnalyzeDumpFile(string dumpFilePath)
    {
        if (string.IsNullOrWhiteSpace(dumpFilePath))
        {
            return null;
        }

        var info = new FileInfo(dumpFilePath);
        if (!info.Exists || info.Length < 32)
        {
            return null;
        }

        var bytes = ReadDumpPrefix(info.FullName, info.Length);
        return ParseMinidumpBytes(bytes, info.FullName, new DateTimeOffset(info.LastWriteTimeUtc));
    }

    public IReadOnlyList<BsodMinidumpReport> ScanMinidumpDirectory(string minidumpDirectory, int maxReports = 15) =>
        ScanMinidumpDirectoryDetailed(minidumpDirectory, maxReports).Reports;

    /// <summary>
    /// Разбирает самые свежие дампы из папки и сообщает, удалось ли вообще прочитать папку.
    /// Папка C:\Windows\Minidump доступна только администраторам, и это не должно выглядеть как «сбоев не было».
    /// </summary>
    public MinidumpScanResult ScanMinidumpDirectoryDetailed(string minidumpDirectory, int maxReports = 15)
    {
        if (string.IsNullOrWhiteSpace(minidumpDirectory) || !Directory.Exists(minidumpDirectory))
        {
            return new MinidumpScanResult([], MinidumpFolderStatus.FolderMissing, 0);
        }

        List<string> dumpFiles;
        try
        {
            dumpFiles = Directory.EnumerateFiles(minidumpDirectory, "*.dmp", SearchOption.TopDirectoryOnly)
                .OrderByDescending(File.GetLastWriteTimeUtc)
                .Take(Math.Max(1, maxReports))
                .ToList();
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            return new MinidumpScanResult([], MinidumpFolderStatus.AccessDenied, 0);
        }
        catch (IOException)
        {
            return new MinidumpScanResult([], MinidumpFolderStatus.ReadError, 0);
        }

        var reports = new List<BsodMinidumpReport>();
        var unreadable = 0;

        foreach (var file in dumpFiles)
        {
            try
            {
                var parsed = AnalyzeDumpFile(file);
                if (parsed is not null)
                {
                    reports.Add(parsed);
                }
                else
                {
                    unreadable++;
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                unreadable++;
            }
        }

        return new MinidumpScanResult(reports, MinidumpFolderStatus.Scanned, unreadable);
    }

    private static byte[] ReadDumpPrefix(string file, long length)
    {
        var toRead = length <= MaxFullReadBytes ? (int)length : HeaderOnlyReadBytes;
        using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

        var buffer = new byte[toRead];
        var read = stream.ReadAtLeast(buffer, toRead, throwOnEndOfStream: false);
        return read == toRead ? buffer : buffer[..read];
    }

    // ================================ ДАМП ЯДРА (СИНИЙ ЭКРАН) ================================

    private static BsodMinidumpReport BuildKernelReport(
        KernelCrashDump dump,
        string dumpPath,
        DateTimeOffset? fileTimestampUtc)
    {
        var descriptor = BugCheckCatalog.Describe(dump.BugCheckCode);
        var attribution = AttributeCulprit(dump, descriptor);

        var reason = descriptor.SimpleReason;
        var action = descriptor.RecommendedAction;

        if (attribution.SuspectDriver is not null)
        {
            var label = DescribeDriver(attribution.SuspectDriver);
            switch (attribution.Confidence)
            {
                case CrashCulpritConfidence.High:
                    reason += $" Сбой произошёл в драйвере {label}.";
                    action = $"Обновите или переустановите {label} с сайта производителя. Если сбой начался после обновления, верните предыдущую версию драйвера.";
                    break;

                case CrashCulpritConfidence.Medium:
                    reason += $" Вероятный источник — {label}: его код найден в стеке вызовов перед сбоем.";
                    action = $"Обновите или переустановите {label} с сайта производителя. Если сбой начался после обновления, верните предыдущую версию драйвера.";
                    break;

                default:
                    reason += $" Возможный источник — {label}: его код найден в стеке вызовов. При повреждении памяти виновником нередко оказывается другой драйвер или сама память.";
                    action = $"{descriptor.RecommendedAction} Начните с обновления драйвера {attribution.SuspectDriver}.";
                    break;
            }
        }
        else if (attribution.FaultingModule is not null)
        {
            reason += $" Сбой произошёл в системном модуле {attribution.FaultingModule}. Сам модуль Windows редко бывает причиной: обычно память повредил сторонний драйвер или неисправно оборудование.";
        }

        var thirdPartyModules = dump.LoadedModules
            .Select(m => m.Name)
            .Where(name => !KernelModuleClassifier.IsWindowsComponent(name))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(24)
            .ToList();

        return new BsodMinidumpReport(
            DumpFilePath: dumpPath,
            CrashTimestampUtc: dump.CrashTimeUtc ?? fileTimestampUtc ?? default,
            BugCheckCode: dump.BugCheckCode,
            BugCheckName: descriptor.Name,
            ProcessorArchitecture: MapMachine(dump.MachineImageType),
            OsBuildSummary: DescribeOsBuild(dump),
            SuspectedThirdPartyDriver: attribution.SuspectDriver,
            SimpleHumanExplanation: reason,
            RecommendedUserAction: action,
            LoadedDriverModulesSample: thirdPartyModules,
            DumpKind: CrashDumpKind.KernelBugCheck,
            CulpritConfidence: attribution.Confidence,
            FaultingModule: attribution.FaultingModule,
            TechnicalEvidence: attribution.Evidence,
            BugCheckParameters: dump.BugCheckParameters,
            ExceptionCode: null);
    }

    private static CulpritAttribution AttributeCulprit(KernelCrashDump dump, BugCheckDescriptor descriptor)
    {
        var none = new CulpritAttribution(null, CrashCulpritConfidence.None, null, null);

        if (dump.LoadedModules.Count == 0 || descriptor.Category == BugCheckCategory.ManuallyInitiated)
        {
            return none;
        }

        // 1. Самое надёжное: параметр кода остановки, в котором Windows сама передаёт адрес сбойной инструкции.
        KernelDumpModule? faultModule = null;
        ulong faultAddress = 0;
        var parameterIndex = descriptor.FaultAddressParameterIndex;
        if (parameterIndex >= 0 && parameterIndex < dump.BugCheckParameters.Count)
        {
            faultAddress = dump.BugCheckParameters[parameterIndex];
            faultModule = dump.FindModule(faultAddress);
        }

        if (faultModule is not null && !KernelModuleClassifier.IsWindowsComponent(faultModule.Name))
        {
            return new CulpritAttribution(
                faultModule.Name,
                CrashCulpritConfidence.High,
                faultModule.Name,
                $"Параметр {parameterIndex + 1} кода остановки (0x{faultAddress:X}) указывает внутрь {faultModule.Name}+0x{faultAddress - faultModule.BaseAddress:X}.");
        }

        // 2. Запасной путь: первый сторонний драйвер на вершине стека вызовов ядра.
        //    Для аппаратных сбоев и ошибок диска он не годится: там стек случаен.
        var stackConfidence = StackConfidenceFor(descriptor.Category);
        if (stackConfidence != CrashCulpritConfidence.None)
        {
            var examined = 0;
            foreach (var hint in dump.StackFrameHints)
            {
                examined++;
                if (examined > MaxStackHintsForAttribution)
                {
                    break;
                }

                if (KernelModuleClassifier.IsWindowsComponent(hint.Module.Name))
                {
                    continue;
                }

                return new CulpritAttribution(
                    hint.Module.Name,
                    stackConfidence,
                    faultModule?.Name,
                    $"В стеке вызовов ядра найден адрес 0x{hint.Address:X} внутри {hint.Module.Name}+0x{hint.OffsetInModule:X}.");
            }
        }

        if (faultModule is not null)
        {
            return new CulpritAttribution(
                null,
                CrashCulpritConfidence.None,
                faultModule.Name,
                $"Параметр {parameterIndex + 1} кода остановки (0x{faultAddress:X}) указывает внутрь системного модуля {faultModule.Name}+0x{faultAddress - faultModule.BaseAddress:X}.");
        }

        return none;
    }

    private static CrashCulpritConfidence StackConfidenceFor(BugCheckCategory category) => category switch
    {
        BugCheckCategory.DriverFault => CrashCulpritConfidence.Medium,
        BugCheckCategory.Graphics => CrashCulpritConfidence.Medium,
        BugCheckCategory.WatchdogTimeout => CrashCulpritConfidence.Medium,
        BugCheckCategory.PowerOrSleep => CrashCulpritConfidence.Medium,
        BugCheckCategory.MemoryCorruption => CrashCulpritConfidence.Low,
        BugCheckCategory.Unknown => CrashCulpritConfidence.Low,
        _ => CrashCulpritConfidence.None
    };

    private static string DescribeDriver(string moduleName)
    {
        var description = KernelModuleClassifier.DescribeKnownDriver(moduleName);
        return description is null ? moduleName : $"{moduleName} ({description})";
    }

    private static string DescribeOsBuild(KernelCrashDump dump)
    {
        var build = dump.BuildNumber;
        var family = build switch
        {
            >= 22000 => "Windows 11",
            >= 10240 => "Windows 10",
            >= 9200 => "Windows 8 / 8.1",
            >= 7600 => "Windows 7",
            _ => "Windows"
        };

        var bits = dump.Is64Bit ? "64-разрядная" : "32-разрядная";
        return build > 0 ? $"{family}, сборка {build}, {bits}" : $"{family}, {bits}";
    }

    private static PeArchitecture MapMachine(uint machine) => machine switch
    {
        KernelCrashDumpReader.MachineAmd64 => PeArchitecture.X64,
        KernelCrashDumpReader.MachineArm64 => PeArchitecture.Arm64,
        KernelCrashDumpReader.MachineI386 => PeArchitecture.X86,
        _ => PeArchitecture.Unknown
    };

    // ================================ ДАМП ПРОГРАММЫ (MDMP) ================================

    private static BsodMinidumpReport? ParseUserModeMinidump(
        ReadOnlySpan<byte> data,
        string sourceFilePath,
        DateTimeOffset? fileTimestampUtc)
    {
        if (data.Length < 32 || BinaryPrimitives.ReadUInt32LittleEndian(data[..4]) != MdmpMagic)
        {
            return null;
        }

        var streamCount = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(8, 4));
        var streamDirRva = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(12, 4));
        var unixTimestamp = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(20, 4));

        var crashTime = unixTimestamp > 0
            ? DateTimeOffset.FromUnixTimeSeconds(unixTimestamp)
            : fileTimestampUtc ?? default;

        var cpuArch = PeArchitecture.Unknown;
        var osBuildSummary = "Windows";
        uint? exceptionCode = null;
        ulong exceptionAddress = 0;
        var modules = new List<KernelDumpModule>();

        var directoryFits = streamDirRva != 0
            && streamCount <= 256
            && (long)streamDirRva + ((long)streamCount * 12) <= data.Length;

        for (var i = 0; directoryFits && i < (int)streamCount; i++)
        {
            var entry = data.Slice((int)streamDirRva + (i * 12), 12);
            var streamType = BinaryPrimitives.ReadUInt32LittleEndian(entry[..4]);
            var dataSize = BinaryPrimitives.ReadUInt32LittleEndian(entry.Slice(4, 4));
            var rva = BinaryPrimitives.ReadUInt32LittleEndian(entry.Slice(8, 4));

            if (rva == 0 || dataSize == 0 || (long)rva + dataSize > data.Length)
            {
                continue;
            }

            var stream = data.Slice((int)rva, (int)dataSize);

            if (streamType == StreamTypeSystemInfo && stream.Length >= 20)
            {
                cpuArch = BinaryPrimitives.ReadUInt16LittleEndian(stream[..2]) switch
                {
                    0 => PeArchitecture.X86,
                    9 => PeArchitecture.X64,
                    12 => PeArchitecture.Arm64,
                    _ => PeArchitecture.Unknown
                };

                var major = BinaryPrimitives.ReadUInt32LittleEndian(stream.Slice(8, 4));
                var minor = BinaryPrimitives.ReadUInt32LittleEndian(stream.Slice(12, 4));
                var build = BinaryPrimitives.ReadUInt32LittleEndian(stream.Slice(16, 4));
                osBuildSummary = build > 0 ? $"Windows NT {major}.{minor}, сборка {build}" : $"Windows NT {major}.{minor}";
            }
            else if (streamType == StreamTypeException && stream.Length >= 32)
            {
                // MINIDUMP_EXCEPTION_STREAM: ThreadId (4), выравнивание (4), затем MINIDUMP_EXCEPTION:
                // ExceptionCode (4), ExceptionFlags (4), ExceptionRecord (8), ExceptionAddress (8)
                var code = BinaryPrimitives.ReadUInt32LittleEndian(stream.Slice(8, 4));
                if (code != 0)
                {
                    exceptionCode = code;
                    exceptionAddress = BinaryPrimitives.ReadUInt64LittleEndian(stream.Slice(24, 8));
                }
            }
            else if (streamType == StreamTypeModuleList && stream.Length >= 4)
            {
                var moduleCount = Math.Min(BinaryPrimitives.ReadUInt32LittleEndian(stream[..4]), 1024u);

                for (var m = 0; m < (int)moduleCount; m++)
                {
                    var moduleOffset = 4 + (m * MinidumpModuleStructSize);
                    if (moduleOffset + MinidumpModuleStructSize > stream.Length)
                    {
                        break;
                    }

                    // MINIDUMP_MODULE: BaseOfImage (8), SizeOfImage (4), CheckSum (4), TimeDateStamp (4), ModuleNameRva (4)
                    var baseOfImage = BinaryPrimitives.ReadUInt64LittleEndian(stream.Slice(moduleOffset, 8));
                    var sizeOfImage = BinaryPrimitives.ReadUInt32LittleEndian(stream.Slice(moduleOffset + 8, 4));
                    var timeDateStamp = BinaryPrimitives.ReadUInt32LittleEndian(stream.Slice(moduleOffset + 16, 4));
                    var nameRva = BinaryPrimitives.ReadUInt32LittleEndian(stream.Slice(moduleOffset + 20, 4));

                    if (TryReadMinidumpString(data, nameRva, out var fullModulePath))
                    {
                        var shortName = ExtractFileName(fullModulePath);
                        if (!string.IsNullOrWhiteSpace(shortName))
                        {
                            modules.Add(new KernelDumpModule(shortName, baseOfImage, sizeOfImage, timeDateStamp));
                        }
                    }
                }
            }
        }

        // Первым в списке модулей идёт сам исполняемый файл программы
        var processName = modules.Count > 0 ? modules[0].Name : null;
        var faultingModule = exceptionCode.HasValue
            ? modules.FirstOrDefault(m => m.Contains(exceptionAddress))?.Name
            : null;

        var exceptionName = DescribeUserModeException(exceptionCode);
        var explanation = new StringBuilder("Это дамп упавшей программы");
        if (processName is not null)
        {
            explanation.Append(' ').Append(processName);
        }

        explanation.Append(", а не синего экрана.");
        if (exceptionCode.HasValue)
        {
            explanation.Append($" Исключение: {exceptionName}.");
        }

        if (faultingModule is not null)
        {
            explanation.Append($" Сбой произошёл в модуле {faultingModule}.");
        }

        return new BsodMinidumpReport(
            DumpFilePath: sourceFilePath,
            CrashTimestampUtc: crashTime,
            BugCheckCode: null,
            BugCheckName: exceptionName,
            ProcessorArchitecture: cpuArch,
            OsBuildSummary: osBuildSummary,
            SuspectedThirdPartyDriver: null,
            SimpleHumanExplanation: explanation.ToString(),
            RecommendedUserAction: "Обновите или переустановите эту программу. Если сбой происходит в системной библиотеке, запустите проверку системных файлов (DISM + SFC).",
            LoadedDriverModulesSample: modules.Select(m => m.Name).Take(14).ToList(),
            DumpKind: CrashDumpKind.UserModeProcess,
            CulpritConfidence: CrashCulpritConfidence.None,
            FaultingModule: faultingModule,
            TechnicalEvidence: exceptionCode.HasValue ? $"Адрес исключения: 0x{exceptionAddress:X}." : null,
            BugCheckParameters: null,
            ExceptionCode: exceptionCode);
    }

    private static string DescribeUserModeException(uint? code) => code switch
    {
        null => "USER_MODE_DUMP",
        0xC0000005 => "ACCESS_VIOLATION",
        0xC0000006 => "IN_PAGE_ERROR",
        0xC0000017 => "NO_MEMORY",
        0xC000001D => "ILLEGAL_INSTRUCTION",
        0xC0000094 => "INTEGER_DIVIDE_BY_ZERO",
        0xC00000FD => "STACK_OVERFLOW",
        0xC0000135 => "DLL_NOT_FOUND",
        0xC0000142 => "DLL_INIT_FAILED",
        0xC0000374 => "HEAP_CORRUPTION",
        0xC0000409 => "STACK_BUFFER_OVERRUN",
        0xE0434352 => "CLR_EXCEPTION",
        0xE06D7363 => "CPP_EXCEPTION",
        0x80000003 => "BREAKPOINT",
        _ => $"EXCEPTION_0x{code.GetValueOrDefault():X8}"
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

    private static string ExtractFileName(string rawPath)
    {
        var index = rawPath.LastIndexOfAny(['\\', '/']);
        return index >= 0 ? rawPath[(index + 1)..] : rawPath;
    }
}
