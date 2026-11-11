using System.Buffers.Binary;
using System.Text;
using UltimateWindows.Modules.Repair.Bsod;
using UltimateWindows.Modules.Repair.Models;
using Xunit;

namespace UltimateWindows.UnitTests;

/// <summary>
/// Проверка разбора дампов ядра Windows (PAGEDU64 / PAGEDUMP) — именно такие файлы пишет синий экран.
/// Образцы собираются по открытой раскладке DUMP_HEADER64, DUMP_HEADER32 и TRIAGE_DUMP64.
/// </summary>
public sealed class KernelCrashDumpTests : IDisposable
{
    private const ulong NtBase = 0xFFFFF80012000000UL;
    private const ulong HalBase = 0xFFFFF80011F00000UL;
    private const ulong NvidiaBase = 0xFFFFF80055000000UL;
    private const ulong RealtekBase = 0xFFFFF80060000000UL;
    private const ulong KasperskyBase = 0xFFFFF80061000000UL;

    private static readonly KernelDumpFixture.Driver[] TypicalDrivers =
    [
        new("ntoskrnl.exe", NtBase, 0x01047000),
        new("hal.dll", HalBase, 0x00006000),
        new(@"\SystemRoot\System32\drivers\nvlddmkm.sys", NvidiaBase, 0x03A00000),
        new("rt640x64.sys", RealtekBase, 0x00100000),
        new("klif.sys", KasperskyBase, 0x00120000),
        new("dump_stornvme.sys", 0xFFFFF80062000000UL, 0x00030000)
    ];

    private readonly string _sandboxDir;

    public KernelCrashDumpTests()
    {
        _sandboxDir = Path.Combine(Path.GetTempPath(), $"uw_kdump_tests_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_sandboxDir);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_sandboxDir))
            {
                Directory.Delete(_sandboxDir, recursive: true);
            }
        }
        catch
        {
            // Ignore transient AV/OS file lock during teardown
        }
    }

    [Fact]
    public void Reader_ParsesHeaderDriverListAndStack_OfX64TriageDump()
    {
        var crashTime = new DateTimeOffset(2026, 10, 17, 9, 30, 0, TimeSpan.Zero);
        var bytes = KernelDumpFixture.BuildTriageDump64(
            bugCheckCode: 0x000000D1,
            parameters: [0x48, 2, 0, NvidiaBase + 0x123456],
            buildNumber: 26100,
            drivers: TypicalDrivers,
            stackValues: [NtBase + 0x345678, 0x2, NvidiaBase + 0x123456, 0x00007FF712345678UL],
            crashTimeUtc: crashTime);

        var dump = KernelCrashDumpReader.TryParse(bytes);

        Assert.NotNull(dump);
        Assert.True(dump!.Is64Bit);
        Assert.True(dump.IsTriageDump);
        Assert.Equal(KernelCrashDumpReader.MachineAmd64, dump.MachineImageType);
        Assert.Equal(26100u, dump.BuildNumber);
        Assert.Equal(12u, dump.ProcessorCount);
        Assert.Equal(0x000000D1u, dump.BugCheckCode);
        Assert.Equal(new ulong[] { 0x48, 2, 0, NvidiaBase + 0x123456 }, dump.BugCheckParameters);
        Assert.Equal(crashTime, dump.CrashTimeUtc);
        Assert.Equal(TimeSpan.FromHours(5), dump.SystemUpTime);

        Assert.Equal(TypicalDrivers.Length, dump.LoadedModules.Count);
        Assert.Equal("ntoskrnl.exe", dump.LoadedModules[0].Name);
        // Полный путь из дампа сокращается до имени файла
        Assert.Equal("nvlddmkm.sys", dump.LoadedModules[2].Name);
        Assert.Equal(NvidiaBase, dump.LoadedModules[2].BaseAddress);
        Assert.Equal(0x03A00000u, dump.LoadedModules[2].SizeOfImage);

        // В стеке два адреса внутри модулей ядра; пользовательские адреса и мелкие числа пропускаются
        Assert.Equal(2, dump.StackFrameHints.Count);
        Assert.Equal("ntoskrnl.exe", dump.StackFrameHints[0].Module.Name);
        Assert.Equal("nvlddmkm.sys", dump.StackFrameHints[1].Module.Name);
        Assert.Equal(0x123456UL, dump.StackFrameHints[1].OffsetInModule);

        Assert.Equal("hal.dll", dump.FindModule(HalBase + 0x10)?.Name);
        Assert.Null(dump.FindModule(0xFFFFF80099999999UL));
    }

    [Fact]
    public void Analyzer_BlamesDriver_WhenBugCheckParameterPointsInsideIt()
    {
        var crashTime = new DateTimeOffset(2026, 10, 17, 9, 30, 0, TimeSpan.Zero);
        var bytes = KernelDumpFixture.BuildTriageDump64(
            bugCheckCode: 0x000000D1,
            parameters: [0x48, 2, 0, NvidiaBase + 0x123456],
            buildNumber: 26100,
            drivers: TypicalDrivers,
            stackValues: [NtBase + 0x345678, RealtekBase + 0x100],
            crashTimeUtc: crashTime);

        var report = MinidumpBinaryAnalyzer.ParseMinidumpBytes(bytes, @"C:\Windows\Minidump\101726-12078-01.dmp");

        Assert.NotNull(report);
        Assert.Equal(CrashDumpKind.KernelBugCheck, report!.DumpKind);
        Assert.Equal(0x000000D1u, report.BugCheckCode);
        Assert.Equal("DRIVER_IRQL_NOT_LESS_OR_EQUAL", report.BugCheckName);
        Assert.Equal("0x000000D1", report.BugCheckHex);
        Assert.Equal(PeArchitecture.X64, report.ProcessorArchitecture);
        Assert.Contains("Windows 11", report.OsBuildSummary);
        Assert.Contains("26100", report.OsBuildSummary);
        Assert.Equal(crashTime, report.CrashTimestampUtc);

        // Адрес из параметра 4 важнее стека: виноват nvlddmkm.sys, а не rt640x64.sys из стека
        Assert.Equal("nvlddmkm.sys", report.SuspectedThirdPartyDriver);
        Assert.Equal(CrashCulpritConfidence.High, report.CulpritConfidence);
        Assert.Equal("nvlddmkm.sys", report.FaultingModule);
        Assert.Equal("Виновник: nvlddmkm.sys", report.CulpritBadge);
        Assert.Contains("NVIDIA", report.SimpleHumanExplanation);
        Assert.Contains("nvlddmkm.sys", report.RecommendedUserAction);
        Assert.Contains("0xFFFFF80055123456", report.ParametersDisplay);
        Assert.Contains("nvlddmkm.sys+0x123456", report.TechnicalEvidence);

        // В списке сторонних модулей нет компонентов Windows и драйверов записи дампа
        Assert.Contains("rt640x64.sys", report.LoadedDriverModulesSample);
        Assert.DoesNotContain("ntoskrnl.exe", report.LoadedDriverModulesSample);
        Assert.DoesNotContain("dump_stornvme.sys", report.LoadedDriverModulesSample);
    }

    [Fact]
    public void Analyzer_FallsBackToStack_WhenFaultAddressIsInsideWindowsKernel()
    {
        var bytes = KernelDumpFixture.BuildTriageDump64(
            bugCheckCode: 0x0000003B,
            parameters: [0xC0000005, NtBase + 0x205EF5, 0xFFFFF10AE8226FC8UL, 0],
            buildNumber: 19045,
            drivers: TypicalDrivers,
            stackValues: [NtBase + 0x3F0A12, NtBase + 0x205EF5, RealtekBase + 0x4321, NvidiaBase + 0x10]);

        var report = MinidumpBinaryAnalyzer.ParseMinidumpBytes(bytes);

        Assert.NotNull(report);
        Assert.Equal("SYSTEM_SERVICE_EXCEPTION", report!.BugCheckName);
        Assert.Contains("Windows 10", report.OsBuildSummary);
        Assert.Equal("ntoskrnl.exe", report.FaultingModule);
        Assert.Equal("rt640x64.sys", report.SuspectedThirdPartyDriver);
        Assert.Equal(CrashCulpritConfidence.Medium, report.CulpritConfidence);
        Assert.Equal("Вероятно: rt640x64.sys", report.CulpritBadge);
        Assert.Contains("Realtek", report.SimpleHumanExplanation);
    }

    [Fact]
    public void Analyzer_GivesLowConfidence_ForMemoryCorruptionFoundOnlyOnStack()
    {
        var bytes = KernelDumpFixture.BuildTriageDump64(
            bugCheckCode: 0x00000050,
            parameters: [0xFFFFD00012345000UL, 0, NtBase + 0x1000, 2],
            buildNumber: 22631,
            drivers: TypicalDrivers,
            stackValues: [NtBase + 0x1000, KasperskyBase + 0x777]);

        var report = MinidumpBinaryAnalyzer.ParseMinidumpBytes(bytes);

        Assert.NotNull(report);
        Assert.Equal("PAGE_FAULT_IN_NONPAGED_AREA", report!.BugCheckName);
        Assert.Equal("klif.sys", report.SuspectedThirdPartyDriver);
        Assert.Equal(CrashCulpritConfidence.Low, report.CulpritConfidence);
        Assert.Contains("Kaspersky", report.SimpleHumanExplanation);
    }

    [Fact]
    public void Analyzer_DoesNotBlameDrivers_ForHardwareErrors()
    {
        // При аппаратной ошибке стек случаен: драйвер видеокарты в нём не делает его виновным
        var bytes = KernelDumpFixture.BuildTriageDump64(
            bugCheckCode: 0x00000124,
            parameters: [0, 0xFFFFE000ABCDE028UL, 0xBE000000, 0x800400],
            buildNumber: 26100,
            drivers: TypicalDrivers,
            stackValues: [NtBase + 0x10, NvidiaBase + 0x999]);

        var report = MinidumpBinaryAnalyzer.ParseMinidumpBytes(bytes);

        Assert.NotNull(report);
        Assert.Equal("WHEA_UNCORRECTABLE_ERROR", report!.BugCheckName);
        Assert.Null(report.SuspectedThirdPartyDriver);
        Assert.Equal(CrashCulpritConfidence.None, report.CulpritConfidence);
        Assert.Equal("Драйвер не выявлен", report.CulpritBadge);
        Assert.Contains("BIOS", report.RecommendedUserAction);
    }

    [Fact]
    public void Analyzer_ReportsWindowsModule_WhenNoThirdPartyDriverIsInvolved()
    {
        var bytes = KernelDumpFixture.BuildTriageDump64(
            bugCheckCode: 0x1000007E,
            parameters: [0xFFFFFFFFC0000005UL, NtBase + 0x97C320, 0, 0],
            buildNumber: 26100,
            drivers: TypicalDrivers,
            stackValues: [NtBase + 0x97C320, NtBase + 0x400000]);

        var report = MinidumpBinaryAnalyzer.ParseMinidumpBytes(bytes);

        Assert.NotNull(report);
        Assert.Equal("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M", report!.BugCheckName);
        Assert.Null(report.SuspectedThirdPartyDriver);
        Assert.Equal("ntoskrnl.exe", report.FaultingModule);
        Assert.Equal("Сбой в ntoskrnl.exe", report.CulpritBadge);
        Assert.Contains("системном модуле ntoskrnl.exe", report.SimpleHumanExplanation);
    }

    [Fact]
    public void Analyzer_ReadsBugCheckFromHeaderOnly_WhenDumpIsNotTriage()
    {
        // Полный дамп памяти: читается только начало файла, списка драйверов в нём нет
        var bytes = KernelDumpFixture.BuildTriageDump64(
            bugCheckCode: 0x000000EF,
            parameters: [0xFFFF9A0B11223344UL, 0, 0, 0],
            buildNumber: 26100,
            drivers: TypicalDrivers,
            stackValues: [NvidiaBase + 0x10],
            dumpType: KernelCrashDumpReader.DumpTypeFull);

        var report = MinidumpBinaryAnalyzer.ParseMinidumpBytes(bytes.AsSpan(0, KernelCrashDumpReader.Header64Size));

        Assert.NotNull(report);
        Assert.Equal("CRITICAL_PROCESS_DIED", report!.BugCheckName);
        Assert.Null(report.SuspectedThirdPartyDriver);
        Assert.Empty(report.LoadedDriverModulesSample);
        Assert.Contains("DISM", report.RecommendedUserAction);
    }

    [Fact]
    public void Reader_ParsesX86Header()
    {
        var bytes = KernelDumpFixture.BuildHeader32(
            bugCheckCode: 0x0000000A,
            parameters: [0x00000004, 0x00000002, 0x00000001, 0x8052A3F1],
            buildNumber: 19045);

        var dump = KernelCrashDumpReader.TryParse(bytes);
        Assert.NotNull(dump);
        Assert.False(dump!.Is64Bit);
        Assert.Equal(KernelCrashDumpReader.MachineI386, dump.MachineImageType);
        Assert.Equal(0x0000000Au, dump.BugCheckCode);
        Assert.Equal(new ulong[] { 4, 2, 1, 0x8052A3F1 }, dump.BugCheckParameters);
        Assert.Empty(dump.LoadedModules);

        var report = MinidumpBinaryAnalyzer.ParseMinidumpBytes(bytes);
        Assert.NotNull(report);
        Assert.Equal("IRQL_NOT_LESS_OR_EQUAL", report!.BugCheckName);
        Assert.Equal(PeArchitecture.X86, report.ProcessorArchitecture);
        Assert.Contains("32-разрядная", report.OsBuildSummary);
        Assert.Contains("Windows 10", report.OsBuildSummary);
    }

    [Fact]
    public void Analyzer_UsesFileTime_WhenDumpHasNoValidCrashTime()
    {
        var bytes = KernelDumpFixture.BuildTriageDump64(
            bugCheckCode: 0x00000133,
            parameters: [1, 0x1E00, 0, 0],
            buildNumber: 26100,
            drivers: TypicalDrivers,
            stackValues: [],
            crashTimeUtc: null);

        var fileTime = new DateTimeOffset(2026, 11, 2, 18, 45, 0, TimeSpan.Zero);

        var withFileTime = MinidumpBinaryAnalyzer.ParseMinidumpBytes(bytes, "dump.dmp", fileTime);
        Assert.NotNull(withFileTime);
        Assert.Equal(fileTime, withFileTime!.CrashTimestampUtc);
        Assert.True(withFileTime.HasKnownCrashTime);

        var withoutAnyTime = MinidumpBinaryAnalyzer.ParseMinidumpBytes(bytes);
        Assert.NotNull(withoutAnyTime);
        Assert.False(withoutAnyTime!.HasKnownCrashTime);
        Assert.Equal("время неизвестно", withoutAnyTime.CrashLocalDisplay);
    }

    [Fact]
    public void Reader_IgnoresImplausibleDriverEntries_InsteadOfBlamingThem()
    {
        // Повреждённый список: адрес в пользовательской области и нулевой размер образа
        KernelDumpFixture.Driver[] corrupted =
        [
            new("ntoskrnl.exe", NtBase, 0x01047000),
            new("ghost.sys", 0x0000000000401000UL, 0x00010000),
            new("empty.sys", 0xFFFFF80070000000UL, 0)
        ];

        var bytes = KernelDumpFixture.BuildTriageDump64(
            bugCheckCode: 0x000000D1,
            parameters: [0, 2, 0, 0x0000000000401234UL],
            buildNumber: 26100,
            drivers: corrupted,
            stackValues: [0x0000000000401234UL]);

        var dump = KernelCrashDumpReader.TryParse(bytes);
        Assert.NotNull(dump);
        Assert.Single(dump!.LoadedModules);

        var report = MinidumpBinaryAnalyzer.ParseMinidumpBytes(bytes);
        Assert.NotNull(report);
        Assert.Null(report!.SuspectedThirdPartyDriver);
    }

    [Fact]
    public void Analyzer_RejectsGarbageAndTruncatedFiles()
    {
        Assert.Null(MinidumpBinaryAnalyzer.ParseMinidumpBytes(new byte[4096]));
        Assert.Null(MinidumpBinaryAnalyzer.ParseMinidumpBytes(Encoding.ASCII.GetBytes("PAGEDU64 truncated")));
        Assert.Null(MinidumpBinaryAnalyzer.ParseMinidumpBytes(ReadOnlySpan<byte>.Empty));

        // Заявленное число драйверов больше, чем помещается в файле: разбор не должен падать
        var bytes = KernelDumpFixture.BuildTriageDump64(
            bugCheckCode: 0x000000D1,
            parameters: [0, 2, 0, NvidiaBase + 1],
            buildNumber: 26100,
            drivers: TypicalDrivers,
            stackValues: [NtBase + 1]);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x2034, 4), 4000);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x202C, 4), 0x000F0000);

        var report = MinidumpBinaryAnalyzer.ParseMinidumpBytes(bytes);
        Assert.NotNull(report);
        Assert.Equal(0x000000D1u, report!.BugCheckCode);
    }

    [Fact]
    public void BugCheckCatalog_KnowsCommonCodes_AndDescribesUnknownOnes()
    {
        Assert.True(BugCheckCatalog.Count >= 70);

        foreach (var descriptor in BugCheckCatalog.GetAll())
        {
            Assert.False(string.IsNullOrWhiteSpace(descriptor.Name));
            Assert.False(string.IsNullOrWhiteSpace(descriptor.SimpleReason));
            Assert.False(string.IsNullOrWhiteSpace(descriptor.RecommendedAction));
            Assert.InRange(descriptor.FaultAddressParameterIndex, -1, 3);
        }

        Assert.Equal("VIDEO_TDR_FAILURE", BugCheckCatalog.Describe(0x116).Name);
        Assert.Equal(BugCheckCategory.Graphics, BugCheckCatalog.Describe(0x116).Category);
        Assert.Equal("KERNEL_MODE_EXCEPTION_NOT_HANDLED_M", BugCheckCatalog.Describe(0x1000008E).Name);
        Assert.Equal(1, BugCheckCatalog.Describe(0x1000008E).FaultAddressParameterIndex);

        var unknown = BugCheckCatalog.Describe(0x00ABCDEF);
        Assert.False(unknown.IsKnown);
        Assert.Equal("BUGCHECK_0x00ABCDEF", unknown.Name);
    }

    [Fact]
    public void KernelModuleClassifier_SeparatesWindowsComponentsFromThirdPartyDrivers()
    {
        Assert.True(KernelModuleClassifier.IsWindowsComponent("ntoskrnl.exe"));
        Assert.True(KernelModuleClassifier.IsWindowsComponent("NTFS.SYS"));
        Assert.True(KernelModuleClassifier.IsWindowsComponent("dump_storahci.sys"));
        Assert.True(KernelModuleClassifier.IsWindowsComponent("npfs.sys"));
        Assert.False(KernelModuleClassifier.IsWindowsComponent("nvlddmkm.sys"));
        Assert.False(KernelModuleClassifier.IsWindowsComponent(""));

        Assert.Contains("NVIDIA", KernelModuleClassifier.DescribeKnownDriver("nvlddmkm.sys"));
        Assert.Contains("Vanguard", KernelModuleClassifier.DescribeKnownDriver("vgk.sys"));
        Assert.Null(KernelModuleClassifier.DescribeKnownDriver("some-unknown-driver.sys"));
    }

    [Fact]
    public void DirectoryScan_ReadsDumps_CountsUnreadableFiles_AndReportsMissingFolder()
    {
        var dumpDir = Path.Combine(_sandboxDir, "Minidump");
        Directory.CreateDirectory(dumpDir);

        var crashTime = new DateTimeOffset(2026, 10, 22, 14, 40, 0, TimeSpan.Zero);
        File.WriteAllBytes(
            Path.Combine(dumpDir, "102226-10531-01.dmp"),
            KernelDumpFixture.BuildTriageDump64(
                bugCheckCode: 0x00000116,
                parameters: [0xFFFF800011112222UL, NvidiaBase + 0x17C0E0, 0xFFFFFFFFC000009AUL, 4],
                buildNumber: 26100,
                drivers: TypicalDrivers,
                stackValues: [NtBase + 5],
                crashTimeUtc: crashTime));
        File.WriteAllBytes(Path.Combine(dumpDir, "broken.dmp"), new byte[64]);
        File.WriteAllText(Path.Combine(dumpDir, "notes.txt"), "not a dump");

        var analyzer = new MinidumpBinaryAnalyzer();
        var scan = analyzer.ScanMinidumpDirectoryDetailed(dumpDir);

        Assert.Equal(MinidumpFolderStatus.Scanned, scan.FolderStatus);
        Assert.Equal(1, scan.UnreadableFileCount);
        var report = Assert.Single(scan.Reports);
        Assert.Equal("VIDEO_TDR_FAILURE", report.BugCheckName);
        Assert.Equal("nvlddmkm.sys", report.SuspectedThirdPartyDriver);
        Assert.Equal(CrashCulpritConfidence.High, report.CulpritConfidence);
        Assert.Equal(crashTime, report.CrashTimestampUtc);

        Assert.Single(analyzer.ScanMinidumpDirectory(dumpDir));

        var missing = analyzer.ScanMinidumpDirectoryDetailed(Path.Combine(_sandboxDir, "NoSuchFolder"));
        Assert.Equal(MinidumpFolderStatus.FolderMissing, missing.FolderStatus);
        Assert.Empty(missing.Reports);

        var history = new CrashHistoryScanResult([], [], MinidumpFolderStatus.AccessDenied, 0);
        Assert.Contains("администратор", history.FolderNote);
        Assert.Null(new CrashHistoryScanResult([], [], MinidumpFolderStatus.Scanned, 0).FolderNote);
    }
}

/// <summary>
/// Собирает образцы дампов ядра по открытой раскладке структур Windows.
/// </summary>
internal static class KernelDumpFixture
{
    internal sealed record Driver(string Name, ulong BaseAddress, uint SizeOfImage);

    private const int Header64Size = 0x2000;
    private const int TriageBlockSize = 0x100;
    private const int DriverEntrySize = 0x90;

    public static byte[] BuildTriageDump64(
        uint bugCheckCode,
        ulong[] parameters,
        uint buildNumber,
        IReadOnlyList<Driver> drivers,
        ulong[] stackValues,
        DateTimeOffset? crashTimeUtc = null,
        uint machine = 0x8664,
        uint dumpType = 4)
    {
        var driverListOffset = Header64Size + TriageBlockSize;
        var stringPoolOffset = driverListOffset + (drivers.Count * DriverEntrySize);

        // Строки малого дампа: ULONG с длиной в символах, затем UTF-16LE; выравнивание на 8 байт
        var nameOffsets = new int[drivers.Count];
        var cursor = stringPoolOffset;
        for (var i = 0; i < drivers.Count; i++)
        {
            nameOffsets[i] = cursor;
            cursor += 4 + (drivers[i].Name.Length * 2) + 2;
            cursor = (cursor + 7) & ~7;
        }

        var stackOffset = cursor;
        var stackSize = stackValues.Length * 8;
        var buffer = new byte[stackOffset + stackSize + 64];

        // ---- DUMP_HEADER64 ----
        Encoding.ASCII.GetBytes("PAGEDU64").CopyTo(buffer, 0);
        WriteUInt32(buffer, 0x08, 15);
        WriteUInt32(buffer, 0x0C, buildNumber);
        WriteUInt32(buffer, 0x30, machine);
        WriteUInt32(buffer, 0x34, 12);
        WriteUInt32(buffer, 0x38, bugCheckCode);
        for (var i = 0; i < 4; i++)
        {
            WriteUInt64(buffer, 0x40 + (i * 8), parameters[i]);
        }

        WriteUInt32(buffer, 0xF00, 0x80000003);            // Exception.ExceptionCode: точка останова KeBugCheckEx
        WriteUInt32(buffer, 0xF98, dumpType);
        if (crashTimeUtc.HasValue)
        {
            WriteInt64(buffer, 0xFA8, crashTimeUtc.Value.ToFileTime());
        }

        WriteInt64(buffer, 0x1030, TimeSpan.FromHours(5).Ticks);

        // ---- TRIAGE_DUMP64 ----
        WriteUInt32(buffer, Header64Size + 0x04, (uint)buffer.Length);        // SizeOfDump
        WriteUInt32(buffer, Header64Size + 0x28, (uint)stackOffset);          // CallStackOffset
        WriteUInt32(buffer, Header64Size + 0x2C, (uint)stackSize);            // SizeOfCallStack
        WriteUInt32(buffer, Header64Size + 0x30, (uint)driverListOffset);     // DriverListOffset
        WriteUInt32(buffer, Header64Size + 0x34, (uint)drivers.Count);        // DriverCount
        WriteUInt32(buffer, Header64Size + 0x38, (uint)stringPoolOffset);     // StringPoolOffset
        WriteUInt64(buffer, Header64Size + 0x48, 0xFFFFF10AE8226000UL);       // TopOfStack

        // ---- DUMP_DRIVER_ENTRY64 ----
        for (var i = 0; i < drivers.Count; i++)
        {
            var entry = driverListOffset + (i * DriverEntrySize);
            WriteUInt32(buffer, entry, (uint)nameOffsets[i]);                 // DriverNameOffset
            WriteUInt64(buffer, entry + 0x38, drivers[i].BaseAddress);        // LdrEntry.DllBase
            WriteUInt32(buffer, entry + 0x48, drivers[i].SizeOfImage);        // LdrEntry.SizeOfImage
            WriteUInt32(buffer, entry + 0x88, 0x65000000u + (uint)i);          // LdrEntry.TimeDateStamp

            WriteUInt32(buffer, nameOffsets[i], (uint)drivers[i].Name.Length);
            Encoding.Unicode.GetBytes(drivers[i].Name).CopyTo(buffer, nameOffsets[i] + 4);
        }

        // ---- Стек ядра: от вершины к основанию ----
        for (var i = 0; i < stackValues.Length; i++)
        {
            WriteUInt64(buffer, stackOffset + (i * 8), stackValues[i]);
        }

        return buffer;
    }

    public static byte[] BuildHeader32(uint bugCheckCode, uint[] parameters, uint buildNumber)
    {
        var buffer = new byte[0x1000];

        // ---- DUMP_HEADER32 ----
        Encoding.ASCII.GetBytes("PAGEDUMP").CopyTo(buffer, 0);
        WriteUInt32(buffer, 0x08, 15);
        WriteUInt32(buffer, 0x0C, buildNumber);
        WriteUInt32(buffer, 0x20, 0x014C);
        WriteUInt32(buffer, 0x24, 4);
        WriteUInt32(buffer, 0x28, bugCheckCode);
        for (var i = 0; i < 4; i++)
        {
            WriteUInt32(buffer, 0x2C + (i * 4), parameters[i]);
        }

        WriteUInt32(buffer, 0xF88, 4);
        return buffer;
    }

    private static void WriteUInt32(byte[] buffer, int offset, uint value) =>
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(offset, 4), value);

    private static void WriteUInt64(byte[] buffer, int offset, ulong value) =>
        BinaryPrimitives.WriteUInt64LittleEndian(buffer.AsSpan(offset, 8), value);

    private static void WriteInt64(byte[] buffer, int offset, long value) =>
        BinaryPrimitives.WriteInt64LittleEndian(buffer.AsSpan(offset, 8), value);
}
