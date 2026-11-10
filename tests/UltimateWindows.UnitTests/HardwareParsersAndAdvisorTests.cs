using System.Buffers.Binary;
using System.Text;
using UltimateWindows.Modules.Hardware.Analysis;
using UltimateWindows.Modules.Hardware.Contracts;
using UltimateWindows.Modules.Hardware.Models;
using UltimateWindows.Modules.Hardware.Parsers;
using UltimateWindows.Modules.Hardware.Services;
using UltimateWindows.Modules.Hardware.Stress;
using UltimateWindows.Modules.Safety.Services;
using Xunit;

namespace UltimateWindows.UnitTests;

public sealed class HardwareParsersAndAdvisorTests : IDisposable
{
    private readonly string _tempDir;

    public HardwareParsersAndAdvisorTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "UltimateWindowsHwTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    [Fact]
    public void SmbiosParser_DecodesBoardBiosAndExtended32GbDdr5DualChannel()
    {
        var rawBuffer = BuildSampleRawSmbios(
            slot1Locator: "DIMM_A2",
            slot1Bank: "CHANNEL A",
            slot2Locator: "DIMM_B2",
            slot2Bank: "CHANNEL B");

        var parsed = SmbiosBinaryParser.ParseWindowsRawSmbios(rawBuffer);

        Assert.Equal("ASUSTeK COMPUTER INC.", parsed.Motherboard.BoardManufacturer);
        Assert.Equal("ROG STRIX B650E-F", parsed.Motherboard.BoardProduct);
        Assert.Equal("2412", parsed.Motherboard.BiosVersion);
        Assert.Equal(2, parsed.MemorySlots.Count);

        var firstStick = parsed.MemorySlots[0];
        Assert.Equal("DDR5", firstStick.MemoryType);
        Assert.Equal(32L * 1024 * 1024 * 1024, firstStick.CapacityBytes);
        Assert.Equal(6000, firstStick.RatedSpeedMtPerSec);
        Assert.Equal(4800, firstStick.ConfiguredSpeedMtPerSec);
        Assert.True(SmbiosBinaryParser.InferMultiChannelTopology(parsed.MemorySlots));
    }

    [Fact]
    public void SmbiosParser_DetectsSingleChannelMisplacementWhenBothSticksInChannelA()
    {
        var rawBuffer = BuildSampleRawSmbios(
            slot1Locator: "DIMM_A1",
            slot1Bank: "CHANNEL A",
            slot2Locator: "DIMM_A2",
            slot2Bank: "CHANNEL A");

        var parsed = SmbiosBinaryParser.ParseWindowsRawSmbios(rawBuffer);
        Assert.False(SmbiosBinaryParser.InferMultiChannelTopology(parsed.MemorySlots));
    }

    [Fact]
    public void EdidParser_ExtractsManufacturerModelBitDepthDiagonalAnd165HzMaxRefresh()
    {
        var edid = new byte[128];
        // Header 00 FF FF FF FF FF FF 00
        edid[1] = 0xFF; edid[2] = 0xFF; edid[3] = 0xFF;
        edid[4] = 0xFF; edid[5] = 0xFF; edid[6] = 0xFF;

        // Manufacturer 'AUS' -> A(1), U(21), S(19) -> (1 << 10) | (21 << 5) | 19 = 0x06B3
        BinaryPrimitives.WriteUInt16BigEndian(edid.AsSpan(8, 2), 0x06B3);
        edid[17] = 34; // 1990 + 34 = 2024
        edid[20] = 0x80 | (3 << 4); // Digital + 10-bit color depth
        edid[21] = 60; // 60 cm width
        edid[22] = 34; // 34 cm height (~27.2")

        // Descriptor 0 (offset 54): DTD 2560x1440 @ 60 Hz
        var dtd = edid.AsSpan(54, 18);
        BinaryPrimitives.WriteUInt16LittleEndian(dtd[..2], 24150); // 241.5 MHz
        dtd[2] = 0x00; // 2560 low byte (0x0A00)
        dtd[3] = 160;  // HBlank
        dtd[4] = 0xA0; // HActive high nibble = 0xA (2560)
        dtd[5] = 0xA0; // 1440 low byte (0x05A0)
        dtd[6] = 41;   // VBlank
        dtd[7] = 0x50; // VActive high nibble = 0x5 (1440)

        // Descriptor 1 (offset 72): Monitor Name 0xFC = "VG27AQ\n"
        var nameDesc = edid.AsSpan(72, 18);
        nameDesc[3] = 0xFC;
        Encoding.ASCII.GetBytes("VG27AQ\n      ").CopyTo(nameDesc.Slice(5, 13));

        // Descriptor 2 (offset 90): Range Limits 0xFD -> Max VRate = 165 Hz
        var rangeDesc = edid.AsSpan(90, 18);
        rangeDesc[3] = 0xFD;
        rangeDesc[6] = 165;

        var profile = EdidBinaryParser.TryParse(edid);

        Assert.NotNull(profile);
        Assert.Equal("AUS", profile.ManufacturerCode);
        Assert.Equal("VG27AQ", profile.MonitorName);
        Assert.Equal(2024, profile.ManufactureYear);
        Assert.Equal(10, profile.ColorBitDepth);
        Assert.Equal(2560, profile.PreferredWidthPx);
        Assert.Equal(1440, profile.PreferredHeightPx);
        Assert.Equal(165, profile.EdidMaxRefreshHz);
        Assert.InRange(profile.DiagonalInches ?? 0, 27.0, 27.3);
    }

    [Fact]
    public void SmartParser_DecodesNvmeHealthLogAndAtaSataCrcCableErrors()
    {
        // 1. NVMe 512-byte Health Information Log
        var nvmeLog = new byte[512];
        nvmeLog[0] = 0; // CriticalWarning = 0 (Healthy)
        BinaryPrimitives.WriteUInt16LittleEndian(nvmeLog.AsSpan(1, 2), 315); // 315 K = 42 °C
        nvmeLog[3] = 100; // AvailableSpare 100%
        nvmeLog[4] = 10;  // Threshold 10%
        nvmeLog[5] = 7;   // 7% used -> 93% remaining life
        BinaryPrimitives.WriteUInt64LittleEndian(nvmeLog.AsSpan(48, 8), 250_000_000UL); // 250M * 512KB = 128.0 TB TBW
        BinaryPrimitives.WriteUInt64LittleEndian(nvmeLog.AsSpan(128, 8), 4200UL); // POH

        var nvme = SmartBinaryParser.TryParseNvmeHealthLog(nvmeLog);
        Assert.NotNull(nvme);
        Assert.True(nvme.IsHealthy);
        Assert.Equal(42, nvme.TemperatureC);
        Assert.Equal(93, nvme.RemainingLifePercent);
        Assert.Equal(128.0, nvme.TotalBytesWrittenTb);
        Assert.Equal(4200, nvme.PowerOnHours);

        // 2. ATA/SATA 512-byte SMART Sector
        var ataSector = new byte[512];
        // Attr 0 (offset 2): 0xC2 Temperature -> младший байт 37°C, старшие байты содержат исторический макс 58°C
        ataSector[2] = 0xC2;
        ataSector[2 + 3] = 63;
        ataSector[2 + 5] = 37;
        ataSector[2 + 7] = 58;

        // Attr 1 (offset 14): 0xC7 UltraDMA CRC Error Count = 48
        ataSector[14] = 0xC7;
        ataSector[14 + 3] = 100;
        BinaryPrimitives.WriteUInt32LittleEndian(ataSector.AsSpan(14 + 5, 4), 48);

        // Attr 2 (offset 26): 0xE7 SSD Life Left = 88%
        ataSector[26] = 0xE7;
        ataSector[26 + 3] = 88;

        var ata = SmartBinaryParser.TryParseAtaSmartSector(ataSector);
        Assert.NotNull(ata);
        Assert.True(ata.IsHealthy);
        Assert.Equal(37, ata.TemperatureC);
        Assert.Equal(48, ata.UltraDmaCrcErrors);
        Assert.Equal(88, ata.RemainingLifePercent);
    }

    [Fact]
    public async Task AdvisorAndAutoFix_DetectsBottlenecksAndRecordsUndoInZeroBloatVault()
    {
        var fakePlatform = new FakeWindowsHardwareProvider();
        var vault = new ZeroBloatVaultService(explicitVaultDirectory: _tempDir);
        var studio = new HardwareStudioService(vault, fakePlatform);

        var (_, audit) = await studio.CaptureAndAnalyzeAsync();

        Assert.Contains(audit.Findings, f => f.Code == AdvisoryCode.MonitorRefreshSuboptimal);
        Assert.Contains(audit.Findings, f => f.Code == AdvisoryCode.MemoryXmpOrExpoDisabled);
        Assert.Contains(audit.Findings, f => f.Code == AdvisoryCode.GpuPcieLinkDegraded);
        Assert.Contains(audit.Findings, f => f.Code == AdvisoryCode.ThermalHotspotOrThrottling);
        Assert.Contains(audit.Findings, f => f.Code == AdvisoryCode.PowerPlanThrottling);

        var hzFinding = audit.Findings.First(f => f.Code == AdvisoryCode.MonitorRefreshSuboptimal);
        var (ok, _) = await studio.ApplyAdvisoryAutoFixAsync(hzFinding);

        Assert.True(ok);
        Assert.Equal(165, fakePlatform.CurrentMonitorHz);

        var history = await vault.GetHistoryAsync();
        Assert.Single(history);
        Assert.Contains("165 Гц", history[0].FriendlyTitle);
    }

    [Fact]
    public async Task ThermalSafeStressRunner_AbortsImmediatelyWhenThermalCutoffExceeded()
    {
        var overheatingPlatform = new FakeWindowsHardwareProvider { SimulatedGpuTempC = 91.5 };
        var runner = new ThermalSafeStressRunner(overheatingPlatform);

        var result = await runner.RunStabilityTestAsync(
            duration: TimeSpan.FromSeconds(10),
            maxSafeCpuTempC: 92.0,
            maxSafeGpuTempC: 88.0);

        Assert.True(result.WasAbortedByThermalCutoff);
        Assert.True(result.Elapsed < TimeSpan.FromSeconds(4));
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDir))
            {
                Directory.Delete(_tempDir, recursive: true);
            }
        }
        catch
        {
            // Игнорируем отложенное закрытие дескрипторов
        }
    }

    private static byte[] BuildSampleRawSmbios(
        string slot1Locator,
        string slot1Bank,
        string slot2Locator,
        string slot2Bank)
    {
        using var tables = new MemoryStream();

        // Type 0: BIOS Information (formatted length 0x18)
        var t0 = new byte[0x18];
        t0[0] = 0; t0[1] = (byte)t0.Length; t0[2] = 1;
        t0[0x04] = 1; // Vendor
        t0[0x05] = 2; // Version
        t0[0x08] = 3; // Date
        tables.Write(t0);
        WriteSmbiosStrings(tables, "American Megatrends Inc.", "2412", "09/15/2026");

        // Type 2: Baseboard Information (formatted length 0x08)
        var t2 = new byte[0x08];
        t2[0] = 2; t2[1] = (byte)t2.Length; t2[2] = 2;
        t2[0x04] = 1; // Manufacturer
        t2[0x05] = 2; // Product
        t2[0x06] = 3; // Version
        tables.Write(t2);
        WriteSmbiosStrings(tables, "ASUSTeK COMPUTER INC.", "ROG STRIX B650E-F", "Rev 1.xx");

        // Two Type 17 Memory Devices (formatted length 0x22 -> supports ExtendedSize + ConfiguredMemorySpeed)
        WriteType17Dimm(tables, handle: 10, slot1Locator, slot1Bank);
        WriteType17Dimm(tables, handle: 11, slot2Locator, slot2Bank);

        // Type 127: End-of-Table
        tables.Write([127, 4, 0xFF, 0x00, 0x00, 0x00]);

        var tableBytes = tables.ToArray();
        var raw = new byte[8 + tableBytes.Length];
        raw[1] = 3; // Major 3
        raw[2] = 6; // Minor 6
        BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(4, 4), (uint)tableBytes.Length);
        tableBytes.CopyTo(raw.AsSpan(8));
        return raw;
    }

    private static void WriteType17Dimm(MemoryStream ms, ushort handle, string devLoc, string bankLoc)
    {
        var t17 = new byte[0x22];
        t17[0] = 17;
        t17[1] = (byte)t17.Length;
        BinaryPrimitives.WriteUInt16LittleEndian(t17.AsSpan(2, 2), handle);
        BinaryPrimitives.WriteUInt16LittleEndian(t17.AsSpan(0x0C, 2), 0x7FFF); // Extended Size >= 32 GB
        t17[0x10] = 1; // DeviceLocator
        t17[0x11] = 2; // BankLocator
        t17[0x12] = 0x22; // DDR5
        BinaryPrimitives.WriteUInt16LittleEndian(t17.AsSpan(0x15, 2), 6000); // Rated 6000 MT/s
        t17[0x17] = 3; // Manufacturer
        t17[0x1A] = 4; // PartNumber
        BinaryPrimitives.WriteUInt32LittleEndian(t17.AsSpan(0x1C, 4), 32768u); // 32768 MiB = 32 GB
        BinaryPrimitives.WriteUInt16LittleEndian(t17.AsSpan(0x20, 2), 4800); // Configured 4800 MT/s (XMP/EXPO off)

        ms.Write(t17);
        WriteSmbiosStrings(ms, devLoc, bankLoc, "SK Hynix", "HMCG88AGBAA");
    }

    private static void WriteSmbiosStrings(MemoryStream ms, params string[] strings)
    {
        foreach (var s in strings)
        {
            ms.Write(Encoding.UTF8.GetBytes(s));
            ms.WriteByte(0);
        }

        ms.WriteByte(0);
    }

    private sealed class FakeWindowsHardwareProvider : IHardwarePlatformProvider
    {
        public int CurrentMonitorHz { get; set; } = 60;
        public double SimulatedGpuTempC { get; set; } = 74.0;

        public Task<HardwareSnapshot> CaptureSnapshotAsync(CancellationToken ct = default)
        {
            var snap = new HardwareSnapshot(
                CapturedAtUtc: DateTimeOffset.UtcNow,
                Cpu: new CpuHardwareInfo("AuthenticAMD", "AMD Ryzen 7 7800X3D", 25, 97, 2, 8, 16, 8, 0, 512 * 1024, 8 * 1024 * 1024, 96 * 1024 * 1024, 4200, 5050, 65.0, 22.0, ["SSE4.2", "AVX2", "AVX-512F"]),
                Motherboard: new MotherboardBiosInfo("ASUSTeK", "B650E-F", "1.0", "AMI", "2412", "09/2026", "ASUS", "PC", 3, 6),
                Memory: new MemorySubsystemInfo(32L * 1024 * 1024 * 1024, 20L * 1024 * 1024 * 1024, ConfiguredSpeedMtPerSec: 4800, MaxRatedSpeedMtPerSec: 6000, "DDR5", 2, 4, true, []),
                Gpus:
                [
                    new GpuHardwareInfo(0, "NVIDIA GeForce RTX 4070 Super", "NVIDIA", 12L * 1024 * 1024 * 1024, "566.14",
                        CurrentPcieGen: 4, MaxPcieGen: 4, CurrentPcieLanes: 4, MaxPcieLanes: 16,
                        IsResizableBarEnabled: false, CoreTemperatureC: 72.0, HotspotTemperatureC: 101.0,
                        MemoryTemperatureC: 80.0, FanSpeedPercent: 68, PowerDrawWatts: 215.0, CoreLoadPercent: 95)
                ],
                Drives:
                [
                    new StorageDriveSmartInfo(0, "Samsung SSD 990 PRO 2TB", "S7123", "4B2QJXD7", StorageBusKind.Nvme,
                        2000L * 1000 * 1000 * 1000, IsHealthy: true, RemainingLifePercent: 98, TemperatureC: 44,
                        TotalHostReadsTb: 12.4, TotalBytesWrittenTb: 9.8, PowerOnHours: 1400, PowerCycles: 210,
                        UnsafeShutdowns: 2, MediaIntegrityErrors: 0, ReallocatedSectors: null, UltraDmaCrcErrors: null)
                ],
                Monitors:
                [
                    new DisplayMonitorInfo(@"\\.\DISPLAY1", "VG27AQ", "AUS", 2024, 2560, 1440, CurrentMonitorHz, 165, 10, 27.2)
                ],
                Battery: new BatteryHealthInfo(false, true, 100, null, null),
                ActivePowerPlan: new PowerPlanInfo(new Guid("a1841308-3541-4fab-bc81-f71556f20b4a"), "Экономия энергии", IsPowerSaver: true, IsHighOrUltimatePerformance: false));

            return Task.FromResult(snap);
        }

        public Task<(double? CpuTempC, double? GpuTempC)> PollThermalSensorsAsync(CancellationToken ct = default)
            => Task.FromResult<(double?, double?)>((68.0, SimulatedGpuTempC));

        public Task<(bool Success, int PreviousHz, string Message)> TrySetDisplayRefreshRateAsync(
            string gdiDeviceName,
            int targetRefreshHz,
            CancellationToken ct = default)
        {
            var prev = CurrentMonitorHz;
            CurrentMonitorHz = targetRefreshHz;
            return Task.FromResult((true, prev, "OK"));
        }

        public Task<(bool Success, Guid PreviousSchemeGuid, string Message)> TrySetActivePowerSchemeAsync(
            Guid targetSchemeGuid,
            CancellationToken ct = default)
            => Task.FromResult((true, new Guid("a1841308-3541-4fab-bc81-f71556f20b4a"), "OK"));
    }
}
