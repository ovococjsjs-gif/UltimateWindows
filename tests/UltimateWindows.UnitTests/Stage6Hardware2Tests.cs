using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using UltimateWindows.Modules.Hardware.Benchmarks;
using UltimateWindows.Modules.Hardware.Contracts;
using UltimateWindows.Modules.Hardware.Models;
using UltimateWindows.Modules.Hardware.Parsers;
using UltimateWindows.Modules.Hardware.Services;
using UltimateWindows.Modules.Hardware.Stress;
using UltimateWindows.Modules.Safety.Services;
using Xunit;

namespace UltimateWindows.UnitTests;

public sealed class Stage6Hardware2Tests : IDisposable
{
    private readonly string _tempDir;
    private readonly ZeroBloatVaultService _vault;

    public Stage6Hardware2Tests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "UW_Stage6Tests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _vault = new ZeroBloatVaultService(_tempDir);
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
        catch { }
    }

    [Fact]
    public void SmbiosBinaryParser_ExtractsExtendedType17Fields_FormFactorRanksVoltageEccAndSerial()
    {
        var raw = new List<byte>
        {
            0x00, 0x03, 0x03, 0x00 // SMBIOS 3.3
        };

        var structBytes = new byte[40];
        structBytes[0] = 17; // Type 17 (Memory Device)
        structBytes[1] = 40; // Length = 40 bytes (включая ConfiguredVoltage на смещении 0x26)
        BinaryPrimitives.WriteUInt16LittleEndian(structBytes.AsSpan(2, 2), 0x002A);
        BinaryPrimitives.WriteUInt16LittleEndian(structBytes.AsSpan(8, 2), 72);    // TotalWidth = 72 bit (ECC)
        BinaryPrimitives.WriteUInt16LittleEndian(structBytes.AsSpan(10, 2), 64);   // DataWidth = 64 bit
        BinaryPrimitives.WriteUInt16LittleEndian(structBytes.AsSpan(12, 2), 16384);// 16384 MB (16 GB)
        structBytes[14] = 0x09; // FormFactor = DIMM
        structBytes[16] = 1;    // String #1: DeviceLocator
        structBytes[17] = 2;    // String #2: BankLocator
        structBytes[18] = 0x22; // MemoryType = DDR5
        BinaryPrimitives.WriteUInt16LittleEndian(structBytes.AsSpan(21, 2), 6000); // MaxSpeed = 6000 MT/s
        structBytes[23] = 3;    // String #3: Manufacturer
        structBytes[24] = 4;    // String #4: SerialNumber
        structBytes[26] = 5;    // String #5: PartNumber
        structBytes[27] = 0x02; // Attributes: 2 ranks
        BinaryPrimitives.WriteUInt16LittleEndian(structBytes.AsSpan(32, 2), 6000); // ConfiguredSpeed = 6000 MT/s
        BinaryPrimitives.WriteUInt16LittleEndian(structBytes.AsSpan(38, 2), 1350); // ConfiguredVoltage = 1350 mV (1.35V)

        var stringsBlob = Encoding.ASCII.GetBytes("DIMM_A2\0BANK 0\0G.Skill\0SN-998877\0F5-6000J3038F16G\0\0");
        uint tableLen = (uint)(structBytes.Length + stringsBlob.Length + 6);
        var lenBytes = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(lenBytes, tableLen);
        raw.AddRange(lenBytes);
        raw.AddRange(structBytes);
        raw.AddRange(stringsBlob);
        raw.AddRange(new byte[] { 127, 4, 0, 0, 0, 0 });

        var parsed = SmbiosBinaryParser.ParseWindowsRawSmbios(raw.ToArray());
        var stick = Assert.Single(parsed.MemorySlots);

        Assert.Equal("DIMM_A2", stick.DeviceLocator);
        Assert.Equal("DDR5", stick.MemoryType);
        Assert.Equal("DIMM", stick.FormFactor);
        Assert.Equal(72, stick.TotalWidthBits);
        Assert.Equal(64, stick.DataWidthBits);
        Assert.True(stick.HasEcc);
        Assert.Equal("SN-998877", stick.SerialNumber);
        Assert.Equal(2, stick.Ranks);
        Assert.Equal(1350, stick.ConfiguredVoltageMillivolts);
        Assert.Contains("XMP/EXPO", stick.ProfileAndSpecBadge);
    }

    [Fact]
    public async Task LightweightBenchmarks_CpuMemoryStorageAndSuite_RunFastAndCleanUpTempFiles()
    {
        var fakeProvider = new FakeStage6HardwareProvider();
        var runner = new LightweightBenchmarkRunner(fakeProvider);

        var cpu = await runner.RunCpuBenchmarkAsync(TimeSpan.FromMilliseconds(180), TimeSpan.FromMilliseconds(220));
        Assert.True(cpu.SingleCoreScore > 0);
        Assert.True(cpu.MultiCoreScore > 0);
        Assert.True(cpu.MultiCoreSimdGflops > 0);

        var ram = await runner.RunMemoryBenchmarkAsync(TimeSpan.FromMilliseconds(250));
        Assert.True(ram.BandwidthGbPerSec > 0);
        Assert.True(ram.LatencyNanoseconds > 0);
        Assert.True(ram.MemoryScore > 0);

        var benchDir = Path.Combine(_tempDir, "disk_bench");
        Directory.CreateDirectory(benchDir);
        var disk = await runner.RunStorageBenchmarkAsync(benchDir, testSizeMegabytes: 8);
        Assert.True(disk.SeqWriteMbPerSec > 0);
        Assert.True(disk.SeqReadMbPerSec > 0);
        Assert.True(disk.Random4kIops > 0);
        Assert.Empty(Directory.GetFiles(benchDir, "uw-quick-bench-*.tmp"));

        var studio = new HardwareStudioService(_vault, fakeProvider);
        var suite = await studio.RunFullQuickBenchmarkSuiteAsync();
        Assert.True(suite.CompositeScore > 0);
        Assert.NotNull(suite.Gpu);
        Assert.Equal(2450.5, suite.Gpu!.ShaderAluGflops);
    }

    [Fact]
    public async Task ThermalSafeStressRunner_VerifiesGoldenChecksumIntegrityAndRecordsTelemetryHistory()
    {
        var fakeProvider = new FakeStage6HardwareProvider();
        var runner = new ThermalSafeStressRunner(fakeProvider);
        var result = await runner.RunStabilityTestAsync(
            duration: TimeSpan.FromMilliseconds(750),
            maxSafeCpuTempC: 90,
            maxSafeGpuTempC: 88);

        Assert.False(result.WasAbortedByThermalCutoff);
        Assert.Equal(0, result.IntegrityErrorCount);
        Assert.True(result.MillionsOpsPerSecond > 0);
        Assert.NotNull(result.History);
        Assert.NotEmpty(result.History!);
    }

    [Fact]
    public async Task HardwareReportExporter_WritesValidHtmlJsonAndTxtReports()
    {
        var studio = new HardwareStudioService(_vault, new FakeStage6HardwareProvider());
        var (snap, audit) = await studio.CaptureAndAnalyzeAsync();
        var sensors = await studio.QuerySensorsAsync();
        var suite = await studio.RunFullQuickBenchmarkSuiteAsync();

        var htmlPath = Path.Combine(_tempDir, "report.html");
        var jsonPath = Path.Combine(_tempDir, "report.json");
        var txtPath = Path.Combine(_tempDir, "report.txt");

        await studio.ExportHardwareReportAsync(htmlPath, HardwareReportFormat.Html, snap, audit, sensors, suite);
        await studio.ExportHardwareReportAsync(jsonPath, HardwareReportFormat.Json, snap, audit, sensors, suite);
        await studio.ExportHardwareReportAsync(txtPath, HardwareReportFormat.Txt, snap, audit, sensors, suite);

        var html = await File.ReadAllTextAsync(htmlPath);
        Assert.Contains("<!DOCTYPE html>", html);
        Assert.Contains("AMD Ryzen 7 7800X3D", html);
        Assert.Contains("2450.5", html);

        var json = await File.ReadAllTextAsync(jsonPath);
        using var doc = JsonDocument.Parse(json);
        Assert.True(doc.RootElement.TryGetProperty("Snapshot", out _));
        Assert.True(doc.RootElement.TryGetProperty("Benchmarks", out _));

        var txt = await File.ReadAllTextAsync(txtPath);
        Assert.Contains("ULTIMATE WINDOWS v2.0", txt);
        Assert.Contains("AMD Ryzen 7 7800X3D", txt);
    }

    [Fact]
    public async Task HardwareStudioService_PowerPlansUnlockAndRollbackCheckpoint_WorkEndToEnd()
    {
        var fake = new FakeStage6HardwareProvider();
        var studio = new HardwareStudioService(_vault, fake);

        var plans = await studio.GetPowerPlansAsync();
        Assert.Equal(2, plans.Count);

        var (unlocked, schemeGuid, unlockMsg) = await studio.UnlockUltimatePerformancePlanAsync();
        Assert.True(unlocked, unlockMsg);
        Assert.NotNull(schemeGuid);

        var (switched, switchMsg) = await studio.SwitchPowerPlanAsync(schemeGuid!.Value, "Максимальная производительность");
        Assert.True(switched, switchMsg);

        var history = await _vault.GetHistoryAsync(10);
        Assert.Contains(history, h => h.FriendlyTitle.Contains("Переключение схемы электропитания"));

        var (fanOk, fanCount, _) = await studio.ApplyFanCoolingPresetAsync(FanCoolingPreset.Balanced);
        Assert.True(fanOk);
        Assert.Equal(2, fanCount);
    }

    private sealed class FakeStage6HardwareProvider : IHardwarePlatformProvider
    {
        private static readonly Guid Balanced = new("381b4222-f694-41f0-9685-ff5bb260df2e");
        private static readonly Guid HighPerf = new("8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c");
        private static readonly Guid Ultimate = new("e9a42b02-d5df-448d-aa00-03f14749eb61");
        private Guid _active = Balanced;

        public Task<HardwareSnapshot> CaptureSnapshotAsync(CancellationToken ct = default)
        {
            var snap = new HardwareSnapshot(
                CapturedAtUtc: DateTimeOffset.UtcNow,
                Cpu: new CpuHardwareInfo(
                    Vendor: "AuthenticAMD",
                    BrandName: "AMD Ryzen 7 7800X3D",
                    Family: 25,
                    Model: 97,
                    Stepping: 2,
                    PhysicalCores: 8,
                    LogicalProcessors: 16,
                    PerformanceCores: 8,
                    EfficientCores: 0,
                    L1CacheBytes: 524_288,
                    L2CacheBytes: 8_388_608,
                    L3CacheBytes: 100_663_296,
                    BaseClockMhz: 4200,
                    CurrentClockMhz: 5050,
                    PackageTemperatureC: 58.0,
                    TotalLoadPercent: 14.5,
                    InstructionSets: new[] { "AVX2", "AVX-512" },
                    PackagePowerWatts: 48.2,
                    CoreVoltageVolts: 1.185),
                Motherboard: new MotherboardBiosInfo(
                    BoardManufacturer: "MSI",
                    BoardProduct: "MAG B650 TOMAHAWK",
                    BoardVersion: "1.0",
                    BiosVendor: "AMI",
                    BiosVersion: "1.J0",
                    BiosReleaseDate: "08/15/2025",
                    SystemManufacturer: "MSI",
                    SystemProductName: "MS-7D75",
                    SmbiosMajorVersion: 3,
                    SmbiosMinorVersion: 5),
                Memory: new MemorySubsystemInfo(
                    TotalPhysicalBytes: 34_359_738_368,
                    AvailablePhysicalBytes: 24_000_000_000,
                    ConfiguredSpeedMtPerSec: 6000,
                    MaxRatedSpeedMtPerSec: 6000,
                    MemoryGeneration: "DDR5",
                    PopulatedSlotsCount: 2,
                    TotalSlotsCount: 4,
                    IsDualOrMultiChannelActive: true,
                    Modules: Array.Empty<MemoryModuleSlotInfo>()),
                Gpus: new[]
                {
                    new GpuHardwareInfo(
                        Index: 0,
                        Name: "NVIDIA GeForce RTX 4070 SUPER",
                        Vendor: "NVIDIA",
                        DedicatedVramBytes: 12_884_901_888,
                        DriverVersion: "32.0.15.6636",
                        CurrentPcieGen: 4,
                        MaxPcieGen: 4,
                        CurrentPcieLanes: 16,
                        MaxPcieLanes: 16,
                        IsResizableBarEnabled: true,
                        CoreTemperatureC: 52.0,
                        HotspotTemperatureC: 63.0,
                        MemoryTemperatureC: 60.0,
                        FanSpeedPercent: 35,
                        PowerDrawWatts: 42.5,
                        CoreLoadPercent: 12,
                        CoreClockMhz: 2475,
                        MemoryClockMhz: 10501,
                        FanSpeedRpm: 1150)
                },
                Drives: new[]
                {
                    new StorageDriveSmartInfo(
                        DriveIndex: 0,
                        Model: "Samsung SSD 990 PRO 2TB",
                        SerialNumber: "S73WNJ0X",
                        FirmwareRevision: "4B2QJXD7",
                        BusKind: StorageBusKind.Nvme,
                        CapacityBytes: 2_000_398_934_016,
                        IsHealthy: true,
                        RemainingLifePercent: 99,
                        TemperatureC: 41,
                        TotalHostReadsTb: 6.1,
                        TotalBytesWrittenTb: 8.4,
                        PowerOnHours: 1200,
                        PowerCycles: 180,
                        UnsafeShutdowns: 2,
                        MediaIntegrityErrors: 0,
                        ReallocatedSectors: 0,
                        UltraDmaCrcErrors: 0)
                },
                Monitors: new[]
                {
                    new DisplayMonitorInfo(
                        GdiDeviceName: @"\\.\DISPLAY1",
                        FriendlyModelName: "LG UltraGear",
                        ManufacturerCode: "GSM",
                        ManufactureYear: 2024,
                        NativeWidthPx: 2560,
                        NativeHeightPx: 1440,
                        CurrentRefreshHz: 165,
                        MaxSupportedRefreshHz: 165,
                        ColorBitDepth: 10,
                        DiagonalInches: 27.0)
                },
                Battery: new BatteryHealthInfo(false, true, 100, null, null),
                ActivePowerPlan: new PowerPlanInfo(_active, "Сбалансированная", false, false, true));
            return Task.FromResult(snap);
        }

        public Task<(double? CpuTempC, double? GpuTempC)> PollThermalSensorsAsync(CancellationToken ct = default)
            => Task.FromResult(((double?)58.0, (double?)52.0));

        public Task<(bool Success, int PreviousHz, string Message)> TrySetDisplayRefreshRateAsync(string gdiDeviceName, int targetRefreshHz, CancellationToken ct = default)
            => Task.FromResult((true, 60, "OK"));

        public Task<(bool Success, Guid PreviousSchemeGuid, string Message)> TrySetActivePowerSchemeAsync(Guid targetSchemeGuid, CancellationToken ct = default)
        {
            var prev = _active;
            _active = targetSchemeGuid;
            return Task.FromResult((true, prev, "Схема переключена."));
        }

        public Task<HardwareSensorInventory> QuerySensorInventoryAsync(CancellationToken ct = default)
            => Task.FromResult(BuildSensors());

        public Task<IReadOnlyList<PowerPlanInfo>> EnumeratePowerPlansAsync(CancellationToken ct = default)
            => Task.FromResult<IReadOnlyList<PowerPlanInfo>>(new[]
            {
                new PowerPlanInfo(Balanced, "Сбалансированная", false, false, _active == Balanced),
                new PowerPlanInfo(HighPerf, "Высокая производительность", false, true, _active == HighPerf)
            });

        public Task<(bool Success, Guid? SchemeGuid, string Message)> UnlockUltimatePerformancePlanAsync(CancellationToken ct = default)
            => Task.FromResult<(bool, Guid?, string)>((true, Ultimate, "Разблокировано."));

        public Task<(bool Success, int AffectedFanCount, string Message)> ApplyFanCoolingPresetAsync(FanCoolingPreset preset, CancellationToken ct = default)
            => Task.FromResult((true, 2, "Применено к 2 вентиляторам."));

        public Task<GpuBenchmarkResult> RunGpuComputeBenchmarkAsync(TimeSpan targetDuration, CancellationToken ct = default)
            => Task.FromResult(new GpuBenchmarkResult(
                AdapterName: "NVIDIA GeForce RTX 4070 SUPER",
                BackendName: "Direct3D 11 DirectCompute (cs_5_0)",
                IsHardwareAccelerated: true,
                ComputeScore: 8100,
                ShaderAluGflops: 2450.5,
                VramBandwidthGbPerSec: 504.0,
                Duration: TimeSpan.FromMilliseconds(400),
                TierBadge: "Уверенная игровая видеокарта"));

        private static HardwareSensorInventory BuildSensors() => new(
            SampledAtUtc: DateTimeOffset.UtcNow,
            BackendState: PawnIoBackendState.PawnIoActive,
            BackendHeadline: "Активен подписанный драйвер PawnIO",
            Readings: new[]
            {
                new HardwareSensorReading("AMD Ryzen 7 7800X3D", "CPU Package", SensorCategory.Temperature, 58.0, 41.0, 67.0, "°C"),
                new HardwareSensorReading("MSI MAG B650 TOMAHAWK", "System Fan #1", SensorCategory.Fan, 980, 750, 1320, "об/мин")
            },
            ControllableFans: new[]
            {
                new ControllableFanChannel("/lpc/nct6687d/control/0", "MSI MAG B650", "CPU Fan", 55, 980)
            });
    }
}
