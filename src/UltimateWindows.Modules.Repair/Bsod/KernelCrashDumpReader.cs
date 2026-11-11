using System.Buffers.Binary;
using System.Text;

namespace UltimateWindows.Modules.Repair.Bsod;

/// <summary>
/// Модуль ядра (драйвер), загруженный в момент сбоя: имя и диапазон адресов.
/// </summary>
public sealed record KernelDumpModule(
    string Name,
    ulong BaseAddress,
    uint SizeOfImage,
    uint TimeDateStamp)
{
    public bool Contains(ulong address) =>
        SizeOfImage > 0 && address >= BaseAddress && address - BaseAddress < SizeOfImage;
}

/// <summary>
/// Адрес возврата, найденный в сохранённом стеке ядра, вместе с модулем, которому он принадлежит.
/// </summary>
public sealed record KernelStackFrameHint(
    ulong Address,
    KernelDumpModule Module)
{
    public ulong OffsetInModule => Address - Module.BaseAddress;
}

/// <summary>
/// Сырые данные дампа ядра Windows (форматы PAGEDU64 и PAGEDUMP), без каких-либо выводов.
/// </summary>
public sealed record KernelCrashDump(
    bool Is64Bit,
    uint MachineImageType,
    uint MajorVersion,
    uint BuildNumber,
    uint ProcessorCount,
    uint BugCheckCode,
    IReadOnlyList<ulong> BugCheckParameters,
    uint DumpType,
    DateTimeOffset? CrashTimeUtc,
    TimeSpan? SystemUpTime,
    uint ExceptionCode,
    ulong ExceptionAddress,
    ulong InstructionPointer,
    IReadOnlyList<KernelDumpModule> LoadedModules,
    IReadOnlyList<KernelStackFrameHint> StackFrameHints)
{
    /// <summary>Малый дамп памяти (triage dump): только в нём есть список драйверов и стек.</summary>
    public bool IsTriageDump => DumpType == KernelCrashDumpReader.DumpTypeTriage;

    public KernelDumpModule? FindModule(ulong address)
    {
        if (address == 0)
        {
            return null;
        }

        foreach (var module in LoadedModules)
        {
            if (module.Contains(address))
            {
                return module;
            }
        }

        return null;
    }
}

/// <summary>
/// Читает заголовок дампа ядра Windows и блок малого дампа (triage dump).
///
/// Синие экраны записывают дампы в формате DUMP_HEADER64 (подпись «PAGEDU64») или DUMP_HEADER32
/// (подпись «PAGEDUMP»). Это не формат MDMP: MDMP пишут только пользовательские программы.
/// Раскладка полей взята из открытого описания структур DUMP_HEADER32, DUMP_HEADER64 и TRIAGE_DUMP
/// в документации Microsoft; код этого класса написан для проекта с нуля.
/// </summary>
public static class KernelCrashDumpReader
{
    public const uint DumpTypeFull = 1;
    public const uint DumpTypeKernel = 2;
    public const uint DumpTypeTriage = 4;

    public const uint MachineI386 = 0x014C;
    public const uint MachineAmd64 = 0x8664;
    public const uint MachineArm64 = 0xAA64;

    /// <summary>Сколько первых байт файла нужно, чтобы прочитать код ошибки и её параметры.</summary>
    public const int MinimumHeaderBytes = 0x80;

    /// <summary>Полный размер заголовка 64-разрядного дампа; малый дамп продолжается сразу за ним.</summary>
    public const int Header64Size = 0x2000;

    /// <summary>Полный размер заголовка 32-разрядного дампа.</summary>
    public const int Header32Size = 0x1000;

    private const uint SignaturePage = 0x45474150;   // 'PAGE'
    private const uint ValidDump64 = 0x34365544;     // 'DU64'
    private const uint ValidDump32 = 0x504D5544;     // 'DUMP'

    // ---- DUMP_HEADER64 ----
    private const int H64MajorVersion = 0x08;
    private const int H64MinorVersion = 0x0C;
    private const int H64MachineImageType = 0x30;
    private const int H64NumberProcessors = 0x34;
    private const int H64BugCheckCode = 0x38;
    private const int H64BugCheckParameters = 0x40;
    private const int H64ContextRecord = 0x348;
    private const int H64ExceptionRecord = 0xF00;
    private const int H64DumpType = 0xF98;
    private const int H64SystemTime = 0xFA8;
    private const int H64SystemUpTime = 0x1030;

    // Смещения счётчика команд внутри структуры CONTEXT
    private const int Amd64ContextRip = 0xF8;
    private const int Arm64ContextPc = 0x108;

    // ---- DUMP_HEADER32 ----
    private const int H32MajorVersion = 0x08;
    private const int H32MinorVersion = 0x0C;
    private const int H32MachineImageType = 0x20;
    private const int H32NumberProcessors = 0x24;
    private const int H32BugCheckCode = 0x28;
    private const int H32BugCheckParameters = 0x2C;
    private const int H32ContextRecord = 0x320;
    private const int H32ExceptionRecord = 0x7D0;
    private const int H32DumpType = 0xF88;
    private const int H32SystemUpTime = 0xFB8;
    private const int H32SystemTime = 0xFC0;
    private const int X86ContextEip = 0xB8;

    // ---- TRIAGE_DUMP (одинаковые смещения полей ULONG в 32- и 64-разрядном варианте) ----
    private const int TriageCallStackOffset = 0x28;
    private const int TriageSizeOfCallStack = 0x2C;
    private const int TriageDriverListOffset = 0x30;
    private const int TriageDriverCount = 0x34;
    private const int TriageTopOfStack = 0x48;

    // ---- DUMP_DRIVER_ENTRY64: ULONG DriverNameOffset, выравнивание, KLDR_DATA_TABLE_ENTRY64 ----
    private const int Driver64EntrySize = 0x90;
    private const int Driver64DllBase = 0x38;
    private const int Driver64SizeOfImage = 0x48;
    private const int Driver64TimeDateStamp = 0x88;

    // ---- DUMP_DRIVER_ENTRY32: ULONG DriverNameOffset, KLDR_DATA_TABLE_ENTRY32 ----
    private const int Driver32EntrySize = 0x4C;
    private const int Driver32DllBase = 0x1C;
    private const int Driver32SizeOfImage = 0x24;
    private const int Driver32TimeDateStamp = 0x48;

    private const int MaxDriverCount = 4096;
    private const int MaxDriverNameChars = 520;
    private const int MaxCallStackBytes = 1024 * 1024;
    private const int MaxStackFrameHints = 256;
    private const uint MaxPlausibleImageSize = 1u << 30;

    /// <summary>
    /// Проверяет, начинается ли буфер с подписи дампа ядра.
    /// </summary>
    public static bool LooksLikeKernelDump(ReadOnlySpan<byte> data)
    {
        if (data.Length < 8)
        {
            return false;
        }

        if (BinaryPrimitives.ReadUInt32LittleEndian(data[..4]) != SignaturePage)
        {
            return false;
        }

        var valid = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(4, 4));
        return valid is ValidDump64 or ValidDump32;
    }

    /// <summary>
    /// Разбирает дамп ядра. Достаточно первых <see cref="MinimumHeaderBytes"/> байт, чтобы получить код ошибки;
    /// время сбоя, список драйверов и стек читаются, только если соответствующая часть файла есть в буфере.
    /// Возвращает null, если это не дамп ядра.
    /// </summary>
    public static KernelCrashDump? TryParse(ReadOnlySpan<byte> data)
    {
        if (data.Length < MinimumHeaderBytes || !LooksLikeKernelDump(data))
        {
            return null;
        }

        var is64Bit = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(4, 4)) == ValidDump64;
        return is64Bit ? Parse64(data) : Parse32(data);
    }

    private static KernelCrashDump Parse64(ReadOnlySpan<byte> data)
    {
        var machine = ReadUInt32(data, H64MachineImageType);
        var parameters = new ulong[4];
        for (var i = 0; i < parameters.Length; i++)
        {
            parameters[i] = ReadUInt64(data, H64BugCheckParameters + (i * 8));
        }

        var dumpType = ReadUInt32(data, H64DumpType);

        var instructionPointerOffset = machine == MachineArm64 ? Arm64ContextPc : Amd64ContextRip;
        var instructionPointer = ReadUInt64(data, H64ContextRecord + instructionPointerOffset);

        IReadOnlyList<KernelDumpModule> modules = [];
        IReadOnlyList<KernelStackFrameHint> stackHints = [];

        if (dumpType == DumpTypeTriage && data.Length >= Header64Size + 0x50)
        {
            modules = ReadDriverList(data, Header64Size, is64Bit: true);
            stackHints = ReadStackHints(data, Header64Size, is64Bit: true, modules);
        }

        return new KernelCrashDump(
            Is64Bit: true,
            MachineImageType: machine,
            MajorVersion: ReadUInt32(data, H64MajorVersion),
            BuildNumber: ReadUInt32(data, H64MinorVersion),
            ProcessorCount: ReadUInt32(data, H64NumberProcessors),
            BugCheckCode: ReadUInt32(data, H64BugCheckCode),
            BugCheckParameters: parameters,
            DumpType: dumpType,
            CrashTimeUtc: ReadFileTime(data, H64SystemTime),
            SystemUpTime: ReadUpTime(data, H64SystemUpTime),
            ExceptionCode: ReadUInt32(data, H64ExceptionRecord),
            ExceptionAddress: ReadUInt64(data, H64ExceptionRecord + 0x10),
            InstructionPointer: instructionPointer,
            LoadedModules: modules,
            StackFrameHints: stackHints);
    }

    private static KernelCrashDump Parse32(ReadOnlySpan<byte> data)
    {
        var parameters = new ulong[4];
        for (var i = 0; i < parameters.Length; i++)
        {
            parameters[i] = ReadUInt32(data, H32BugCheckParameters + (i * 4));
        }

        var dumpType = ReadUInt32(data, H32DumpType);

        IReadOnlyList<KernelDumpModule> modules = [];
        IReadOnlyList<KernelStackFrameHint> stackHints = [];

        if (dumpType == DumpTypeTriage && data.Length >= Header32Size + 0x50)
        {
            modules = ReadDriverList(data, Header32Size, is64Bit: false);
            stackHints = ReadStackHints(data, Header32Size, is64Bit: false, modules);
        }

        return new KernelCrashDump(
            Is64Bit: false,
            MachineImageType: ReadUInt32(data, H32MachineImageType),
            MajorVersion: ReadUInt32(data, H32MajorVersion),
            BuildNumber: ReadUInt32(data, H32MinorVersion),
            ProcessorCount: ReadUInt32(data, H32NumberProcessors),
            BugCheckCode: ReadUInt32(data, H32BugCheckCode),
            BugCheckParameters: parameters,
            DumpType: dumpType,
            CrashTimeUtc: ReadFileTime(data, H32SystemTime),
            SystemUpTime: ReadUpTime(data, H32SystemUpTime),
            ExceptionCode: ReadUInt32(data, H32ExceptionRecord),
            ExceptionAddress: ReadUInt32(data, H32ExceptionRecord + 0x0C),
            InstructionPointer: ReadUInt32(data, H32ContextRecord + X86ContextEip),
            LoadedModules: modules,
            StackFrameHints: stackHints);
    }

    private static IReadOnlyList<KernelDumpModule> ReadDriverList(ReadOnlySpan<byte> data, int triageBase, bool is64Bit)
    {
        var listOffset = ReadUInt32(data, triageBase + TriageDriverListOffset);
        var count = ReadUInt32(data, triageBase + TriageDriverCount);
        if (listOffset == 0 || count == 0 || count > MaxDriverCount || listOffset >= (uint)data.Length)
        {
            return [];
        }

        var entrySize = is64Bit ? Driver64EntrySize : Driver32EntrySize;
        var modules = new List<KernelDumpModule>((int)count);

        for (var i = 0; i < (int)count; i++)
        {
            var entryOffset = (long)listOffset + ((long)i * entrySize);
            if (entryOffset + entrySize > data.Length)
            {
                break;
            }

            var entry = data.Slice((int)entryOffset, entrySize);
            var nameOffset = BinaryPrimitives.ReadUInt32LittleEndian(entry[..4]);

            ulong baseAddress;
            uint sizeOfImage;
            uint timeDateStamp;
            if (is64Bit)
            {
                baseAddress = BinaryPrimitives.ReadUInt64LittleEndian(entry.Slice(Driver64DllBase, 8));
                sizeOfImage = BinaryPrimitives.ReadUInt32LittleEndian(entry.Slice(Driver64SizeOfImage, 4));
                timeDateStamp = BinaryPrimitives.ReadUInt32LittleEndian(entry.Slice(Driver64TimeDateStamp, 4));
            }
            else
            {
                baseAddress = BinaryPrimitives.ReadUInt32LittleEndian(entry.Slice(Driver32DllBase, 4));
                sizeOfImage = BinaryPrimitives.ReadUInt32LittleEndian(entry.Slice(Driver32SizeOfImage, 4));
                timeDateStamp = BinaryPrimitives.ReadUInt32LittleEndian(entry.Slice(Driver32TimeDateStamp, 4));
            }

            // Отбрасываем записи, которые не похожи на загруженный образ ядра:
            // так повреждённый или нестандартный дамп не приведёт к ложному обвинению драйвера.
            if (!IsPlausibleKernelImage(baseAddress, sizeOfImage, is64Bit))
            {
                continue;
            }

            var name = ReadDumpString(data, nameOffset);
            if (name is null)
            {
                continue;
            }

            modules.Add(new KernelDumpModule(ExtractFileName(name), baseAddress, sizeOfImage, timeDateStamp));
        }

        return modules;
    }

    private static IReadOnlyList<KernelStackFrameHint> ReadStackHints(
        ReadOnlySpan<byte> data,
        int triageBase,
        bool is64Bit,
        IReadOnlyList<KernelDumpModule> modules)
    {
        if (modules.Count == 0)
        {
            return [];
        }

        var stackOffset = ReadUInt32(data, triageBase + TriageCallStackOffset);
        var stackSize = ReadUInt32(data, triageBase + TriageSizeOfCallStack);
        if (stackOffset == 0 || stackSize == 0 || stackSize > MaxCallStackBytes || stackOffset >= (uint)data.Length)
        {
            return [];
        }

        var available = (int)Math.Min(stackSize, (uint)data.Length - stackOffset);
        var stack = data.Slice((int)stackOffset, available);
        var slotSize = is64Bit ? 8 : 4;
        var hints = new List<KernelStackFrameHint>();

        // Стек сохранён от вершины (самые свежие вызовы) к основанию, поэтому идём по порядку.
        for (var position = 0; position + slotSize <= stack.Length && hints.Count < MaxStackFrameHints; position += slotSize)
        {
            var value = is64Bit
                ? BinaryPrimitives.ReadUInt64LittleEndian(stack.Slice(position, 8))
                : BinaryPrimitives.ReadUInt32LittleEndian(stack.Slice(position, 4));

            if (!IsKernelSpaceAddress(value, is64Bit))
            {
                continue;
            }

            foreach (var module in modules)
            {
                if (module.Contains(value))
                {
                    hints.Add(new KernelStackFrameHint(value, module));
                    break;
                }
            }
        }

        return hints;
    }

    private static bool IsKernelSpaceAddress(ulong address, bool is64Bit) =>
        is64Bit ? address >= 0xFFFF_8000_0000_0000UL : address >= 0x8000_0000UL;

    private static bool IsPlausibleKernelImage(ulong baseAddress, uint sizeOfImage, bool is64Bit) =>
        sizeOfImage is > 0 and < MaxPlausibleImageSize && IsKernelSpaceAddress(baseAddress, is64Bit);

    /// <summary>
    /// Строка малого дампа: ULONG с длиной в символах, за ним текст UTF-16LE.
    /// </summary>
    private static string? ReadDumpString(ReadOnlySpan<byte> data, uint offset)
    {
        if (offset == 0 || (long)offset + 4 > data.Length)
        {
            return null;
        }

        var charCount = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((int)offset, 4));
        if (charCount == 0 || charCount > MaxDriverNameChars)
        {
            return null;
        }

        var byteCount = (long)charCount * 2;
        if ((long)offset + 4 + byteCount > data.Length)
        {
            return null;
        }

        var text = Encoding.Unicode.GetString(data.Slice((int)offset + 4, (int)byteCount)).TrimEnd('\0').Trim();
        if (text.Length == 0)
        {
            return null;
        }

        foreach (var ch in text)
        {
            if (char.IsControl(ch))
            {
                return null;
            }
        }

        return text;
    }

    private static string ExtractFileName(string rawPath)
    {
        var index = rawPath.LastIndexOfAny(['\\', '/']);
        return index >= 0 && index < rawPath.Length - 1 ? rawPath[(index + 1)..] : rawPath;
    }

    private static DateTimeOffset? ReadFileTime(ReadOnlySpan<byte> data, int offset)
    {
        if (offset + 8 > data.Length)
        {
            return null;
        }

        var fileTime = BinaryPrimitives.ReadInt64LittleEndian(data.Slice(offset, 8));

        // Допустимый диапазон: с 2000 года по 2200 год. Всё остальное — заполнитель или мусор.
        const long minFileTime = 125_911_584_000_000_000L;
        const long maxFileTime = 189_028_512_000_000_000L;
        if (fileTime < minFileTime || fileTime > maxFileTime)
        {
            return null;
        }

        return DateTimeOffset.FromFileTime(fileTime).ToUniversalTime();
    }

    private static TimeSpan? ReadUpTime(ReadOnlySpan<byte> data, int offset)
    {
        if (offset + 8 > data.Length)
        {
            return null;
        }

        var ticks = BinaryPrimitives.ReadInt64LittleEndian(data.Slice(offset, 8));

        // Время работы хранится в интервалах по 100 нс. Больше 10 лет без перезагрузки не бывает.
        if (ticks <= 0 || ticks > TimeSpan.FromDays(3650).Ticks)
        {
            return null;
        }

        return TimeSpan.FromTicks(ticks);
    }

    private static uint ReadUInt32(ReadOnlySpan<byte> data, int offset) =>
        offset >= 0 && offset + 4 <= data.Length
            ? BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, 4))
            : 0u;

    private static ulong ReadUInt64(ReadOnlySpan<byte> data, int offset) =>
        offset >= 0 && offset + 8 <= data.Length
            ? BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(offset, 8))
            : 0UL;
}
