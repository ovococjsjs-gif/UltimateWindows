using System.Text;
using UltimateWindows.Core.Enums;
using UltimateWindows.Core.Models;
using UltimateWindows.Modules.Safety.Services;
using UltimateWindows.Modules.Security.Analyzers;
using UltimateWindows.Modules.Security.Models;
using UltimateWindows.Modules.Security.Services;
using Xunit;

namespace UltimateWindows.UnitTests;

public sealed class AntiMinerAndSecurityTests : IDisposable
{
    private readonly string _tempDir;
    private readonly ZeroBloatVaultService _vault;

    public AntiMinerAndSecurityTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "uw-phase5-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _vault = new ZeroBloatVaultService(explicitVaultDirectory: Path.Combine(_tempDir, "vault"));
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
    public void HeuristicEngine_DetectsMasqueradingSvchost_AndIgnoresGenuineSystem32Svchost()
    {
        var engine = new MinerThreatHeuristicEngine();
        var processes = new[]
        {
            new ProcessTelemetrySample(
                ProcessId: 840,
                ProcessName: "svchost.exe",
                ExecutablePath: @"C:\Windows\System32\svchost.exe",
                CommandLine: @"C:\Windows\System32\svchost.exe -k netsvcs -p",
                BaselineCpuPercent: 2.1,
                DuringInspectCpuPercent: 2.0,
                ExitedDuringInspect: false,
                IsAuthenticodeSigned: true),
            new ProcessTelemetrySample(
                ProcessId: 9124,
                ProcessName: "svchost.exe",
                ExecutablePath: @"C:\ProgramData\WindowsTelemetry\svchost.exe",
                CommandLine: @"C:\ProgramData\WindowsTelemetry\svchost.exe --donate-level 1",
                BaselineCpuPercent: 64.0,
                DuringInspectCpuPercent: 63.5,
                ExitedDuringInspect: false,
                IsAuthenticodeSigned: false)
        };

        var findings = engine.AnalyzeTelemetry(processes, [], [], @"C:\Windows");

        Assert.DoesNotContain(findings, f => f.SuspectProcessId == 840);
        var rogue = Assert.Single(findings, f => f.SuspectProcessId == 9124 && f.Vector == ThreatDetectionVector.ProcessMasquerading);
        Assert.True(rogue.ConfidenceScorePercent >= 95);
        Assert.True(rogue.CanQuarantineFileSafely);
    }

    [Fact]
    public void HeuristicEngine_DetectsStealthDropOnInspectMiner_StratumPool_AndGhostTask_WithoutBrowserFalsePositive()
    {
        var engine = new MinerThreatHeuristicEngine();
        var processes = new[]
        {
            new ProcessTelemetrySample(
                ProcessId: 4412,
                ProcessName: "audio_helper.exe",
                ExecutablePath: @"C:\Users\Alex\AppData\Roaming\CodecPack\audio_helper.exe",
                CommandLine: @"C:\Users\Alex\AppData\Roaming\CodecPack\audio_helper.exe --silent",
                BaselineCpuPercent: 79.4,
                DuringInspectCpuPercent: 1.1,
                ExitedDuringInspect: false,
                IsAuthenticodeSigned: false),
            new ProcessTelemetrySample(
                ProcessId: 5200,
                ProcessName: "chrome.exe",
                ExecutablePath: @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                CommandLine: "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --type=utility",
                BaselineCpuPercent: 8.0,
                DuringInspectCpuPercent: 7.5,
                ExitedDuringInspect: false,
                IsAuthenticodeSigned: true)
        };

        var connections = new[]
        {
            new ProcessTcpConnectionInfo(4412, "192.168.1.15", 53120, "198.51.100.77", 3333),
            new ProcessTcpConnectionInfo(5200, "192.168.1.15", 53199, "203.0.113.10", 3333)
        };

        var persistence = new[]
        {
            new PersistenceAnomalyRecord(
                ThreatDetectionVector.HiddenScheduledTask,
                @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Maintenance\SilentCodecSync",
                @"\Microsoft\Windows\Maintenance\SilentCodecSync",
                @"C:\Users\Alex\AppData\Roaming\CodecPack\audio_helper.exe",
                @"C:\Users\Alex\AppData\Roaming\CodecPack\audio_helper.exe",
                IsMissingSecurityDescriptorSd: true,
                PreviousValueSerialized: "{}")
        };

        var findings = engine.AnalyzeTelemetry(processes, connections, persistence, @"C:\Windows");

        Assert.DoesNotContain(findings, f => f.SuspectProcessId == 5200);
        Assert.Contains(findings, f => f.SuspectProcessId == 4412 && f.Vector == ThreatDetectionVector.DropOnInspectEvasion);
        Assert.Contains(findings, f => f.SuspectProcessId == 4412 && f.Vector == ThreatDetectionVector.StratumMiningPoolConnection);
        Assert.Contains(findings, f => f.Vector == ThreatDetectionVector.HiddenScheduledTask && f.ConfidenceScorePercent >= 90);
    }

    [Fact]
    public async Task SecurityService_QuarantinesRogueBinaryToUwq_BlocksWindowsDir_AndSupportsByteExactRollback()
    {
        var rogueFile = Path.Combine(_tempDir, "fake_miner_worker.exe");
        var payload = Encoding.UTF8.GetBytes("TEST-FAKE-MINER-PAYLOAD-FOR-VAULT-QUARANTINE");
        await File.WriteAllBytesAsync(rogueFile, payload);

        var bridge = new FakeSecurityPlatformBridge();
        var service = new AntiMinerSecurityService(_vault, bridge);

        // 1. Genuine Windows path must be strictly refused even if passed manually
        var winDirFakeFile = Path.Combine(_tempDir, "Windows", "System32", "cmd.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(winDirFakeFile)!);
        await File.WriteAllBytesAsync(winDirFakeFile, [0x4D, 0x5A]);
        bridge.WindowsDir = Path.Combine(_tempDir, "Windows");

        var windowsFinding = new SecurityThreatFinding(
            "test-win",
            ThreatDetectionVector.SuspiciousMinerCommandLine,
            RiskLevel.Attention,
            85,
            400,
            winDirFakeFile,
            null,
            "System binary",
            "Test",
            "Test",
            CanQuarantineFileSafely: true);

        var blockedRes = await service.QuarantineThreatAsync(windowsFinding);
        Assert.False(blockedRes.Succeeded);
        Assert.True(File.Exists(winDirFakeFile));

        // 2. Rogue binary outside Windows is terminated, encrypted into .uwq, and removed from active path
        var rogueFinding = new SecurityThreatFinding(
            "test-rogue",
            ThreatDetectionVector.DropOnInspectEvasion,
            RiskLevel.Critical,
            95,
            7777,
            rogueFile,
            null,
            "Скрытый майнер fake_miner_worker.exe",
            "Тестовая изоляция",
            "CPU drop 80% -> 0%",
            CanQuarantineFileSafely: true);

        var okRes = await service.QuarantineThreatAsync(rogueFinding);
        Assert.True(okRes.Succeeded);
        Assert.Contains(7777, bridge.TerminatedPids);
        Assert.False(File.Exists(rogueFile));
        Assert.NotNull(okRes.RollbackSessionId);

        // 3. Zero-Bloat Vault rollback restores the exact binary byte-for-byte
        await _vault.RollbackTransactionAsync(okRes.RollbackSessionId!.Value);
        Assert.True(File.Exists(rogueFile));
        Assert.Equal(payload, await File.ReadAllBytesAsync(rogueFile));
    }

    [Fact]
    public async Task SecurityService_HealsPostMinerSabotageLocks_AndRecordsVaultTransaction()
    {
        var bridge = new FakeSecurityPlatformBridge
        {
            SabotageLocks =
            [
                new OsSabotageFinding(
                    OsSabotageKind.TaskManagerDisabledByPolicy,
                    @"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr",
                    "HKCU",
                    @"Software\Microsoft\Windows\CurrentVersion\Policies\System",
                    "DisableTaskMgr",
                    "1",
                    "Заблокирован Диспетчер задач",
                    "DisableTaskMgr = 1"),
                new OsSabotageFinding(
                    OsSabotageKind.SecurityDomainsBlockedInHosts,
                    @"C:\Windows\System32\drivers\etc\hosts",
                    "",
                    "",
                    "Hosts",
                    "0.0.0.0 virustotal.com",
                    "Блокировка сайтов антивирусов в hosts",
                    "2 строки блокируют обновления защитника")
            ]
        };

        var service = new AntiMinerSecurityService(_vault, bridge);
        var scan = await service.RunFullSecurityScanAsync(enableDropOnInspectProbe: false);
        Assert.Equal(2, scan.SabotageLocks.Count);

        var heal = await service.HealAllSabotageLocksAsync(scan.SabotageLocks);
        Assert.True(heal.Succeeded);
        Assert.Equal(2, bridge.RepairedTargets.Count);
        Assert.NotNull(heal.RollbackSessionId);
    }

    private sealed class FakeSecurityPlatformBridge : DefaultSecurityPlatformBridge
    {
        public string WindowsDir { get; set; } = @"C:\Windows";
        public List<int> TerminatedPids { get; } = [];
        public List<string> RepairedTargets { get; } = [];
        public List<OsSabotageFinding> SabotageLocks { get; set; } = [];

        public override bool IsRunningAsAdministrator() => true;

        public override string GetWindowsDirectory() => WindowsDir;

        public override Task<IReadOnlyList<OsSabotageFinding>> ScanOsSabotageLocksAsync(CancellationToken ct = default) =>
            Task.FromResult<IReadOnlyList<OsSabotageFinding>>(SabotageLocks);

        public override Task<bool> TerminateSuspectProcessAsync(int processId, CancellationToken ct = default)
        {
            TerminatedPids.Add(processId);
            return Task.FromResult(true);
        }

        public override Task<(bool Succeeded, string? OriginalHostsBackupContent)> RepairSabotageLockAsync(
            OsSabotageFinding lockFinding,
            CancellationToken ct = default)
        {
            RepairedTargets.Add(lockFinding.TargetDisplayPath);
            var origHosts = lockFinding.Kind == OsSabotageKind.SecurityDomainsBlockedInHosts
                ? "127.0.0.1 localhost\r\n0.0.0.0 virustotal.com\r\n"
                : null;
            return Task.FromResult((true, origHosts));
        }
    }
}
