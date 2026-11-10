using System.Buffers.Binary;
using System.Text;
using UltimateWindows.Modules.Repair.Bsod;
using UltimateWindows.Modules.Repair.Contracts;
using UltimateWindows.Modules.Repair.Models;
using UltimateWindows.Modules.Repair.PeDoctor;
using UltimateWindows.Modules.Repair.Services;
using UltimateWindows.Modules.Safety.Services;
using Xunit;

namespace UltimateWindows.UnitTests;

public sealed class PeDoctorBsodAndRepairTests : IDisposable
{
    private readonly string _sandboxDir;

    public PeDoctorBsodAndRepairTests()
    {
        _sandboxDir = Path.Combine(Path.GetTempPath(), $"uw_repair_tests_{Guid.NewGuid():N}");
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
    public void BinaryPeDependencyDoctor_Detects0xC000007BMismatch_AndMapsMissingVCRuntime()
    {
        var gameDir = Path.Combine(_sandboxDir, "CyberGame");
        var sys64 = Path.Combine(_sandboxDir, "FakeSystem32");
        var sys32 = Path.Combine(_sandboxDir, "FakeSysWOW64");
        Directory.CreateDirectory(gameDir);
        Directory.CreateDirectory(sys64);
        Directory.CreateDirectory(sys32);

        // 1. Создаем 64-битный game.exe, импортирующий xinput1_3.dll, vcruntime140.dll, kernel32.dll и виртуальный ApiSet
        var exePath = Path.Combine(gameDir, "CyberGame.exe");
        File.WriteAllBytes(exePath, BuildSyntheticPeBinary(
            is64Bit: true,
            importedDlls: ["xinput1_3.dll", "VCRUNTIME140.dll", "KERNEL32.dll", "api-ms-win-core-synch-l1-2-0.dll"]));

        // 2. Кладем рядом с 64-битной игрой ОШИБОЧНУЮ 32-битную xinput1_3.dll (классическая причина 0xC000007B!)
        var wrongLocalDll = Path.Combine(gameDir, "xinput1_3.dll");
        File.WriteAllBytes(wrongLocalDll, BuildSyntheticPeBinary(is64Bit: false, importedDlls: []));

        var doctor = new BinaryPeDependencyDoctor();
        var report = doctor.DiagnoseExecutable(exePath, sys64, sys32);

        Assert.True(report.BinaryHeader.IsValidPeFile);
        Assert.Equal(PeArchitecture.X64, report.BinaryHeader.Architecture);
        Assert.True(report.Has0xC000007BConflict);
        Assert.Equal(2, report.Issues.Count);

        var mismatch = Assert.Single(report.Issues, i => i.Kind == DependencyIssueKind.ArchitectureMismatch0xC000007B);
        Assert.Equal("xinput1_3.dll", mismatch.ImportedDllName, ignoreCase: true);
        Assert.Equal(PeArchitecture.X86, mismatch.ActualDllArchitecture);
        Assert.NotNull(mismatch.RecommendedPackage);
        Assert.Equal("Microsoft.DirectX", mismatch.RecommendedPackage!.WingetPackageId);

        var missingVc = Assert.Single(report.Issues, i => i.Kind == DependencyIssueKind.MissingOfficialRuntimeDll);
        Assert.Equal("VCRUNTIME140.dll", missingVc.ImportedDllName);
        Assert.NotNull(missingVc.RecommendedPackage);
        Assert.Equal("Microsoft.VCRedist.2015+.x64", missingVc.RecommendedPackage!.WingetPackageId);
    }

    [Fact]
    public async Task QuarantineConflictingLocalDll_Fixes0xC000007BWithOneClickRollback_AndBlocksSystem32Quarantine()
    {
        var gameDir = Path.Combine(_sandboxDir, "WitcherApp");
        var sys64 = Path.Combine(_sandboxDir, "WinSys32");
        var sys32 = Path.Combine(_sandboxDir, "WinWow64");
        Directory.CreateDirectory(gameDir);
        Directory.CreateDirectory(sys64);
        Directory.CreateDirectory(sys32);

        // В System32 лежит правильная 64-битная xinput1_3.dll, а в папке игры — битая 32-битная!
        var sysGoodDll = Path.Combine(sys64, "xinput1_3.dll");
        File.WriteAllBytes(sysGoodDll, BuildSyntheticPeBinary(is64Bit: true, importedDlls: []));

        var gameExe = Path.Combine(gameDir, "app.exe");
        File.WriteAllBytes(gameExe, BuildSyntheticPeBinary(is64Bit: true, importedDlls: ["xinput1_3.dll"]));

        var rogueBytes = BuildSyntheticPeBinary(is64Bit: false, importedDlls: []);
        var rogueLocalDll = Path.Combine(gameDir, "xinput1_3.dll");
        File.WriteAllBytes(rogueLocalDll, rogueBytes);

        var vault = new ZeroBloatVaultService(Path.Combine(_sandboxDir, "Vault"));
        var bridge = new FakeRepairBridge(sys64, sys32, Path.Combine(_sandboxDir, "Dumps"), isAdmin: false);
        var service = new SystemRepairService(vault, bridge);

        // До карантина — ошибка 0xC000007B
        Assert.True(service.DiagnoseExecutable(gameExe).Has0xC000007BConflict);

        // Попытка поместить в карантин системный файл из System32 жестко блокируется!
        var blockedSys = await service.QuarantineConflictingLocalDllAsync(sysGoodDll);
        Assert.False(blockedSys.Succeeded);
        Assert.True(File.Exists(sysGoodDll));

        // Изолируем конфликтную локальную 32-битную DLL из папки игры
        var quarantineRes = await service.QuarantineConflictingLocalDllAsync(rogueLocalDll);
        Assert.True(quarantineRes.Succeeded);
        Assert.NotNull(quarantineRes.RollbackSessionId);
        Assert.False(File.Exists(rogueLocalDll));

        // Теперь игра видит правильную 64-битную библиотеку из System32 — конфликт 0xC000007B полностью устранен!
        var healthyDiag = service.DiagnoseExecutable(gameExe);
        Assert.True(healthyDiag.IsHealthy);
        Assert.False(healthyDiag.Has0xC000007BConflict);

        // Проверяем откат в 1 клик: локальный файл возвращается байт-в-байт!
        await vault.RollbackTransactionAsync(quarantineRes.RollbackSessionId!.Value);
        Assert.True(File.Exists(rogueLocalDll));
        Assert.Equal(rogueBytes, File.ReadAllBytes(rogueLocalDll));
    }

    [Fact]
    public void MinidumpBinaryAnalyzer_ParsesMdmpStreams_AndPinpointsNvidiaTdrDriver()
    {
        var mdmpBytes = BuildSyntheticMinidump(
            bugCheckCode: 0x00000116u,
            osMajor: 10,
            osMinor: 0,
            osBuild: 22631,
            modulePaths:
            [
                @"\SystemRoot\system32\ntoskrnl.exe",
                @"\SystemRoot\system32\hal.dll",
                @"\SystemRoot\System32\drivers\nvlddmkm.sys"
            ]);

        var report = MinidumpBinaryAnalyzer.ParseMinidumpBytes(mdmpBytes, @"C:\Windows\Minidump\111026-01.dmp");

        Assert.NotNull(report);
        Assert.Equal(0x00000116u, report!.BugCheckCode);
        Assert.Equal("VIDEO_TDR_FAILURE", report.BugCheckName);
        Assert.Equal(PeArchitecture.X64, report.ProcessorArchitecture);
        Assert.Contains("22631", report.OsBuildSummary);
        Assert.Equal("nvlddmkm.sys", report.SuspectedThirdPartyDriver);
        Assert.Contains("NVIDIA", report.SimpleHumanExplanation);
    }

    [Fact]
    public async Task SystemRepairService_ChecksElevationForAdminPlaybooks_AndExecutesUserPlaybooks()
    {
        var vault = new ZeroBloatVaultService(Path.Combine(_sandboxDir, "VaultPb"));
        var nonAdminBridge = new FakeRepairBridge(
            Path.Combine(_sandboxDir, "S64"),
            Path.Combine(_sandboxDir, "S32"),
            Path.Combine(_sandboxDir, "Dumps"),
            isAdmin: false);

        var service = new SystemRepairService(vault, nonAdminBridge);

        // DISM + SFC требует прав администратора
        var adminBlocked = await service.ExecutePlaybookAsync(RepairPlaybookId.DismAndSfcIntegrity);
        Assert.False(adminBlocked.Succeeded);
        Assert.Contains("Администратора", adminBlocked.UserFriendlySummary);

        // Сброс кэша иконок не требует прав администратора и фиксируется в журнале Машины времени
        var iconOk = await service.ExecutePlaybookAsync(RepairPlaybookId.IconAndThumbnailCacheRebuild);
        Assert.True(iconOk.Succeeded);
        Assert.NotNull(iconOk.RollbackSessionId);
    }

    // ==================== ГЕНЕРАТОРЫ СПЕЦИФИКАЦИОННЫХ БИНАРНЫХ СТРУКТУР PE И MDMP ====================

    private static byte[] BuildSyntheticPeBinary(bool is64Bit, IReadOnlyList<string> importedDlls)
    {
        var buf = new byte[2048];
        // DOS Header: 'MZ' + e_lfanew = 0x80
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(0, 2), 0x5A4D);
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(0x3C, 4), 0x80);

        // NT Signature: 'PE\0\0'
        int pe = 0x80;
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(pe, 4), 0x00004550);

        // COFF File Header (20 bytes)
        int coff = pe + 4;
        ushort machine = is64Bit ? (ushort)0x8664 : (ushort)0x014C;
        ushort optSize = is64Bit ? (ushort)240 : (ushort)224;
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(coff, 2), machine);
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(coff + 2, 2), 1); // 1 секция (.idata)
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(coff + 16, 2), optSize);

        // Optional Header
        int opt = coff + 20;
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(opt, 2), is64Bit ? (ushort)0x020B : (ushort)0x010B);
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(opt + 68, 2), 3); // WINDOWS_CUI

        int dataDirOffset = opt + (is64Bit ? 112 : 96);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(dataDirOffset - 4, 4), 16); // NumberOfRvaAndSizes

        // Секция .idata: VirtualAddress = 0x2000, PointerToRawData = 0x300, SizeOfRawData = 0x500
        const uint secRva = 0x2000;
        const uint secRawPtr = 0x300;
        const uint secRawSize = 0x500;

        if (importedDlls.Count > 0)
        {
            // DataDirectory[1] = Import Table RVA = 0x2000
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(dataDirOffset + 8, 4), secRva);
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(dataDirOffset + 12, 4), (uint)((importedDlls.Count + 1) * 20));
        }

        int secHdr = opt + optSize;
        Encoding.ASCII.GetBytes(".idata").CopyTo(buf.AsSpan(secHdr, 6));
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(secHdr + 8, 4), secRawSize);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(secHdr + 12, 4), secRva);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(secHdr + 16, 4), secRawSize);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(secHdr + 20, 4), secRawPtr);

        // Заполняем IMAGE_IMPORT_DESCRIPTOR массив + строки имен DLL
        int descCursor = (int)secRawPtr;
        int strCursor = (int)secRawPtr + ((importedDlls.Count + 1) * 20) + 16;

        foreach (var dll in importedDlls)
        {
            uint nameRva = secRva + (uint)(strCursor - (int)secRawPtr);
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(descCursor + 12, 4), nameRva);
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(descCursor + 16, 4), nameRva); // FirstThunk non-zero

            var ascii = Encoding.ASCII.GetBytes(dll);
            ascii.CopyTo(buf.AsSpan(strCursor, ascii.Length));
            buf[strCursor + ascii.Length] = 0;

            descCursor += 20;
            strCursor += ascii.Length + 1;
        }

        return buf;
    }

    private static byte[] BuildSyntheticMinidump(
        uint bugCheckCode,
        uint osMajor,
        uint osMinor,
        uint osBuild,
        IReadOnlyList<string> modulePaths)
    {
        var buf = new byte[4096];

        // MINIDUMP_HEADER (32 bytes)
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(0, 4), 0x504D444D); // 'MDMP'
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(4, 4), 0x0000A793);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(8, 4), 3);          // 3 потока: SystemInfo, Exception, ModuleList
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(12, 4), 32);        // StreamDirectoryRva = 32
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(20, 4), 1762800000u);

        // Directory Entry 0: SystemInfoStream (Type 7) at RVA 128, Size 56
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(32, 4), 7);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(36, 4), 56);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(40, 4), 128);

        // Directory Entry 1: ExceptionStream (Type 6) at RVA 200, Size 168
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(44, 4), 6);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(48, 4), 168);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(52, 4), 200);

        // Directory Entry 2: ModuleListStream (Type 4) at RVA 400
        uint modListSize = (uint)(4 + (modulePaths.Count * 108));
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(56, 4), 4);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(60, 4), modListSize);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(64, 4), 400);

        // SystemInfoStream @ 128
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(128, 2), 9); // PROCESSOR_ARCHITECTURE_AMD64
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(136, 4), osMajor);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(140, 4), osMinor);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(144, 4), osBuild);

        // ExceptionStream @ 200 (ExceptionCode at +8)
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(208, 4), bugCheckCode);

        // ModuleListStream @ 400 + UTF-16LE MINIDUMP_STRINGs starting @ 1600
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(400, 4), (uint)modulePaths.Count);
        int strOffset = 1600;
        for (int i = 0; i < modulePaths.Count; i++)
        {
            int modPos = 404 + (i * 108);
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(modPos + 20, 4), (uint)strOffset);

            var utf16 = Encoding.Unicode.GetBytes(modulePaths[i]);
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(strOffset, 4), (uint)utf16.Length);
            utf16.CopyTo(buf.AsSpan(strOffset + 4, utf16.Length));
            strOffset += 4 + utf16.Length + 2;
        }

        return buf;
    }

    private sealed class FakeRepairBridge(
        string sys64,
        string sys32,
        string dumpDir,
        bool isAdmin) : DefaultRepairPlatformBridge
    {
        public override string GetSystem64Directory() => sys64;
        public override string GetSysWow64Directory() => sys32;
        public override string GetMinidumpDirectory() => dumpDir;
        public override bool IsRunningAsAdministrator() => isAdmin;

        public override Task<(bool Succeeded, string OutputLog)> ExecutePlaybookNativeStepsAsync(
            RepairPlaybookId playbookId,
            CancellationToken ct = default)
            => Task.FromResult((true, $"Simulated execution of {playbookId}"));
    }
}
