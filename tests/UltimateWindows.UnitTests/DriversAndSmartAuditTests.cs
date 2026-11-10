using System.Text;
using UltimateWindows.Core.Enums;
using UltimateWindows.Core.Models;
using UltimateWindows.Modules.Cleaner.Services;
using UltimateWindows.Modules.Drivers.Analyzers;
using UltimateWindows.Modules.Drivers.Models;
using UltimateWindows.Modules.Drivers.Orchestration;
using UltimateWindows.Modules.Drivers.Services;
using UltimateWindows.Modules.Hardware.Services;
using UltimateWindows.Modules.Optimizer.Services;
using UltimateWindows.Modules.Repair.Services;
using UltimateWindows.Modules.Safety.Services;
using UltimateWindows.Modules.Security.Services;
using Xunit;

namespace UltimateWindows.UnitTests;

public sealed class DriversAndSmartAuditTests : IDisposable
{
    private readonly string _tempDir;
    private readonly ZeroBloatVaultService _vault;

    public DriversAndSmartAuditTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "uw-phase6-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _vault = new ZeroBloatVaultService(
            Path.Combine(_tempDir, "vault"),
            new VaultQuotaPolicy { MaxVaultBytes = 64 * VaultQuotaPolicy.Megabyte });
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
            // Ignore cleanup lock in test teardown
        }
    }

    [Fact]
    public void HardwareIdAnalyzer_ParsesFourComponentPciId_AndRejectsMismatchedLaptopSubsys()
    {
        var raw = @"PCI\VEN_10DE&DEV_2684&SUBSYS_16A11043&REV_A1";
        var parsed = HardwareIdAndProblemAnalyzer.ParseHardwareId(raw);

        Assert.NotNull(parsed);
        Assert.True(parsed!.HasFullFourPartPciId);
        Assert.Equal("PCI", parsed.BusEnumerator);
        Assert.Equal("10DE", parsed.VendorId);
        Assert.Equal("2684", parsed.DeviceId);
        Assert.Equal("16A11043", parsed.SubsystemId);
        Assert.Equal("A1", parsed.RevisionId);

        var deviceHwIds = new[]
        {
            @"PCI\VEN_10DE&DEV_2684&SUBSYS_16A11043&REV_A1",
            @"PCI\VEN_10DE&DEV_2684&SUBSYS_16A11043"
        };

        Assert.Equal(100, HardwareIdAndProblemAnalyzer.ComputeHardwareIdMatchRank(
            deviceHwIds, @"PCI\VEN_10DE&DEV_2684&SUBSYS_16A11043&REV_A1"));
        Assert.Equal(90, HardwareIdAndProblemAnalyzer.ComputeHardwareIdMatchRank(
            deviceHwIds, @"PCI\VEN_10DE&DEV_2684&SUBSYS_16A11043"));
        Assert.Equal(65, HardwareIdAndProblemAnalyzer.ComputeHardwareIdMatchRank(
            deviceHwIds, @"PCI\VEN_10DE&DEV_2684"));

        // Different OEM laptop SUBSYS must be strictly rejected (Rank = 0)!
        Assert.Equal(0, HardwareIdAndProblemAnalyzer.ComputeHardwareIdMatchRank(
            deviceHwIds, @"PCI\VEN_10DE&DEV_2684&SUBSYS_99991028"));

        var portal = HardwareIdAndProblemAnalyzer.ResolveOfficialVendorPortal(deviceHwIds);
        Assert.NotNull(portal);
        Assert.Equal("NVIDIA", portal!.Value.VendorName);
        Assert.StartsWith("https://www.nvidia.com", portal.Value.OfficialPortalUrl);
    }

    [Fact]
    public async Task OfficialDriverService_DetectsCode28AndBasicDisplay_BlocksNonWhql_AndBacksUpSingleInfToVault()
    {
        var bridge = new FakeDriverPlatformBridge
        {
            Devices =
            [
                new SystemDeviceNode(
                    @"PCI\VEN_10DE&DEV_2684&SUBSYS_16A11043\4&11AA22",
                    "Microsoft Basic Display Adapter",
                    "Display",
                    "(Standard display types)",
                    [@"PCI\VEN_10DE&DEV_2684&SUBSYS_16A11043&REV_A1"],
                    ConfigManagerProblemCode: 0,
                    DriverVersion: "10.0.22621.1",
                    DriverDate: "2006-06-21",
                    InfName: "display.inf"),
                new SystemDeviceNode(
                    @"PCI\VEN_10EC&DEV_8125&SUBSYS_87D71043\4&33BB44",
                    "PCI Ethernet Controller",
                    "Net",
                    "Realtek",
                    [@"PCI\VEN_10EC&DEV_8125&SUBSYS_87D71043"],
                    ConfigManagerProblemCode: 28,
                    DriverVersion: "",
                    DriverDate: "",
                    InfName: ""),
                new SystemDeviceNode(
                    @"HDAUDIO\FUNC_01&VEN_10EC&DEV_1220\5&77CC88",
                    "Realtek High Definition Audio",
                    "MEDIA",
                    "Realtek",
                    [@"HDAUDIO\FUNC_01&VEN_10EC&DEV_1220&SUBSYS_10438735"],
                    ConfigManagerProblemCode: 0,
                    DriverVersion: "6.0.9556.1",
                    DriverDate: "2024-05-14",
                    InfName: "oem42.inf")
            ],
            WuCandidates =
            [
                new OfficialDriverCandidate(
                    "wu-realtek-25g",
                    "Realtek - Net - 10.68.815.2025",
                    "Realtek Gaming 2.5GbE Family Controller",
                    "Realtek",
                    "10.68.815.2025",
                    "2025-08-15",
                    @"PCI\VEN_10EC&DEV_8125&SUBSYS_87D71043",
                    90,
                    DriverSourceKind.WindowsUpdateWhqlCatalog,
                    "https://www.realtek.com/Download/Index",
                    IsWhqlVerified: true)
            ]
        };

        var service = new OfficialDriverService(_vault, bridge);
        var audit = await service.AuditDevicesAndDriversAsync(queryWindowsUpdateCatalog: true);

        Assert.Equal(1, audit.ProblemDeviceCount);
        Assert.Equal(1, audit.BasicFallbackDisplayCount);
        Assert.Contains(audit.Findings, f => f.Device.ConfigManagerProblemCode == 28 && f.CanInstallViaWindowsUpdate);
        Assert.Contains(audit.Findings, f => f.Device.IsBasicDisplayFallback);

        // Non-WHQL candidate must be rejected
        var unsignedCandidate = bridge.WuCandidates[0] with { IsWhqlVerified = false };
        var rejected = await service.InstallOfficialWhqlDriverAsync(bridge.Devices[1], unsignedCandidate);
        Assert.False(rejected.Succeeded);

        // Selective single-INF backup compresses oem42.inf into Zero-Bloat Vault without leaving temp files behind
        var backup = await service.BackupDeviceDriverToVaultAsync(bridge.Devices[2]);
        Assert.True(backup.Succeeded);
        Assert.NotNull(backup.RollbackSessionId);

        var stats = await _vault.GetStorageStatsAsync();
        Assert.Equal(1, stats.BlobCount);
    }

    [Fact]
    public async Task SmartSystemAuditOrchestrator_ComputesWeightedCompositeScoreAcrossAllSixEngines()
    {
        var hw = new HardwareStudioService(_vault);
        var drv = new OfficialDriverService(_vault, new FakeDriverPlatformBridge
        {
            Devices =
            [
                new SystemDeviceNode(
                    @"PCI\VEN_8086&DEV_7A70\3&112233",
                    "Intel Wi-Fi 6E AX211",
                    "Net",
                    "Intel",
                    [@"PCI\VEN_8086&DEV_7A70"],
                    ConfigManagerProblemCode: 28,
                    DriverVersion: "",
                    DriverDate: "",
                    InfName: "")
            ]
        });
        var clean = new VaultSafeCleanerService(_vault);
        var rep = new SystemRepairService(_vault);
        var opt = new SmartOptimizerService(_vault);
        var sec = new AntiMinerSecurityService(_vault);

        var orchestrator = new SmartSystemAuditOrchestrator(hw, drv, clean, rep, opt, sec);
        var summary = await orchestrator.RunOneClickAuditAsync();

        Assert.InRange(summary.CompositeHealthScore, 50, 100);
        Assert.Equal(82, summary.DriversScore);
        Assert.Contains(summary.TopActionItems, a => a.TargetDomain == SystemDomain.HardwareAndDrivers);
    }

    private sealed class FakeDriverPlatformBridge : DefaultDriverPlatformBridge
    {
        public List<SystemDeviceNode> Devices { get; set; } = [];
        public List<OfficialDriverCandidate> WuCandidates { get; set; } = [];

        public override bool IsRunningAsAdministrator() => true;

        public override Task<IReadOnlyList<SystemDeviceNode>> EnumerateDevicesAsync(CancellationToken ct = default) =>
            Task.FromResult<IReadOnlyList<SystemDeviceNode>>(Devices);

        public override Task<IReadOnlyList<OfficialDriverCandidate>> SearchWindowsUpdateDriversAsync(
            IReadOnlyList<SystemDeviceNode> devices,
            CancellationToken ct = default) =>
            Task.FromResult<IReadOnlyList<OfficialDriverCandidate>>(WuCandidates);

        public override async Task<(bool Succeeded, IReadOnlyList<string> ExportedFiles, string ErrorMessage)> ExportSingleOemInfAsync(
            string oemInfName,
            string destinationDirectory,
            CancellationToken ct = default)
        {
            var infFile = Path.Combine(destinationDirectory, oemInfName);
            var catFile = Path.Combine(destinationDirectory, "rtkhda64.cat");
            await File.WriteAllTextAsync(infFile, "[Version]\r\nSignature=\"$WINDOWS NT$\"\r\n", Encoding.UTF8, ct);
            await File.WriteAllBytesAsync(catFile, [0x30, 0x82, 0x01, 0x0A], ct);
            return (true, [infFile, catFile], "");
        }

        public override Task<(bool Succeeded, bool RebootRequired, string ErrorMessage)> InstallWindowsUpdateDriverAsync(
            string updateIdentityId,
            CancellationToken ct = default) =>
            Task.FromResult((true, false, ""));
    }
}
