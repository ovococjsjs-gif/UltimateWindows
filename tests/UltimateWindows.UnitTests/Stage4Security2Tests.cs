using System.Text;
using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Safety.Services;
using UltimateWindows.Modules.Security.Analyzers;
using UltimateWindows.Modules.Security.Catalog;
using UltimateWindows.Modules.Security.Models;
using UltimateWindows.Modules.Security.Scanners;
using UltimateWindows.Modules.Security.Services;
using Xunit;

namespace UltimateWindows.UnitTests;

public sealed class Stage4Security2Tests : IDisposable
{
    private readonly string _tempDir;
    private readonly ZeroBloatVaultService _vault;

    public Stage4Security2Tests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "uw-stage4-sec-tests-" + Guid.NewGuid().ToString("N"));
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
            // Ignore teardown file lock
        }
    }

    [Fact]
    public void ThreatIndicatorCatalog_LoadsAllEmbeddedSignatures_AndMatchesMiningPools()
    {
        var catalog = ThreatIndicatorCatalog.Shared;
        Assert.Equal(2, catalog.SchemaVersion);
        Assert.True(catalog.MiningPoolDomains.Count >= 55);
        Assert.True(catalog.StratumPorts.Count >= 14);
        Assert.True(catalog.MinerCliMarkers.Count >= 25);
        Assert.Contains("WinRing0x64.sys", catalog.AbusedDriverFileNames);
        Assert.Contains("GoogleUpdateTaskMachineQC", catalog.KnownRogueServiceAndTaskNames);

        Assert.True(catalog.MatchesMiningPoolDomain("eu1.pool.supportxmr.com", out var matched));
        Assert.Equal("supportxmr.com", matched, ignoreCase: true);
        Assert.False(catalog.MatchesMiningPoolDomain("windowsupdate.microsoft.com", out _));
    }

    [Fact]
    public void PersistenceZoneCatalog_Covers18Zones_AndValidatesWinlogonBootExecuteAndDefenderExclusions()
    {
        Assert.Equal(18, PersistenceZoneCatalog.AllZones.Count);
        Assert.Equal(18, PersistenceZoneCatalog.AllZones.Distinct().Count());

        // Winlogon Userinit checks
        Assert.False(PersistenceZoneCatalog.IsWinlogonUserinitAnomalous(@"C:\Windows\system32\userinit.exe,", @"C:\Windows"));
        Assert.True(PersistenceZoneCatalog.IsWinlogonUserinitAnomalous(@"C:\Windows\system32\userinit.exe, C:\Users\Public\loader.exe", @"C:\Windows"));

        // BootExecute checks
        Assert.False(PersistenceZoneCatalog.IsBootExecuteAnomalous(["autocheck autochk *"], out _));
        Assert.True(PersistenceZoneCatalog.IsBootExecuteAnomalous(["autocheck autochk *", "autocheck miner_boot"], out var rogueBoot));
        Assert.Equal("autocheck miner_boot", rogueBoot);

        // Defender exclusion risk classification
        var safeDevFolder = PersistenceZoneCatalog.ClassifyDefenderExclusion(
            DefenderExclusionKind.Path,
            @"D:\Projects\MyDotNetSolution",
            isPolicyEnforced: false,
            @"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
            @"C:\Windows");
        Assert.False(safeDevFolder.IsDangerousMinerExclusion);

        var rootBlindSpot = PersistenceZoneCatalog.ClassifyDefenderExclusion(
            DefenderExclusionKind.Path,
            @"C:\",
            isPolicyEnforced: false,
            @"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
            @"C:\Windows");
        Assert.True(rootBlindSpot.IsDangerousMinerExclusion);
        Assert.Equal(RiskLevel.Critical, rootBlindSpot.Severity);

        var exeExtBlindSpot = PersistenceZoneCatalog.ClassifyDefenderExclusion(
            DefenderExclusionKind.Extension,
            ".exe",
            isPolicyEnforced: false,
            @"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions",
            @"C:\Windows");
        Assert.True(exeExtBlindSpot.IsDangerousMinerExclusion);
        Assert.Equal(RiskLevel.Critical, exeExtBlindSpot.Severity);

        var hollowProcessExcl = PersistenceZoneCatalog.ClassifyDefenderExclusion(
            DefenderExclusionKind.Process,
            "dwm.exe",
            isPolicyEnforced: false,
            @"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes",
            @"C:\Windows");
        Assert.True(hollowProcessExcl.IsDangerousMinerExclusion);
    }

    [Fact]
    public void HeuristicEngine_DetectsGpuDropOnInspect_ProcessHollowing_Ipv6Stratum_AndEcosystemAnomalies()
    {
        var engine = new MinerThreatHeuristicEngine();

        var processes = new[]
        {
            // Неподписанный загрузчик в AppData, породивший скомпрометированный донор RegAsm.exe
            new ProcessTelemetrySample(
                ProcessId: 3100,
                ProcessName: "vpn_updater",
                ExecutablePath: @"C:\Users\User\AppData\Roaming\VpnHelper\vpn_updater.exe",
                CommandLine: @"C:\Users\User\AppData\Roaming\VpnHelper\vpn_updater.exe",
                BaselineCpuPercent: 1.0,
                DuringInspectCpuPercent: 0.8,
                ExitedDuringInspect: false,
                IsAuthenticodeSigned: false),
            // Внедрённый майнер внутри системного донора RegAsm.exe + GPU Drop-on-Inspect (91% -> 0%)
            new ProcessTelemetrySample(
                ProcessId: 3188,
                ProcessName: "RegAsm",
                ExecutablePath: @"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe",
                CommandLine: @"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe",
                BaselineCpuPercent: 4.5,
                DuringInspectCpuPercent: 1.0,
                ExitedDuringInspect: false,
                IsAuthenticodeSigned: true,
                BaselineGpuPercent: 91.2,
                DuringInspectGpuPercent: 0.0,
                ParentProcessId: 3100,
                ParentProcessName: "vpn_updater",
                PrivateExecutableRegionCount: 4)
        };

        var ipv6Connections = new[]
        {
            new ProcessTcpConnectionInfo(3188, "2001:db8::2", 55100, "2606:4700::6810:1234", 14444, IsIpv6: true)
        };

        var persistence = new[]
        {
            new PersistenceAnomalyRecord(
                Vector: ThreatDetectionVector.DotNetProfilerHijack,
                RegistryOrTaskPath: @"HKCU\Environment",
                EntryName: "COR_PROFILER_PATH",
                PayloadCommandOrPath: @"C:\Users\Public\Libraries\clr_hook.dll",
                ReferencedExecutablePath: @"C:\Users\Public\Libraries\clr_hook.dll",
                IsMissingSecurityDescriptorSd: false,
                PreviousValueSerialized: @"C:\Users\Public\Libraries\clr_hook.dll",
                Category: PersistenceZone.DotNetCorProfilerEnvironment,
                IsAnomaly: true,
                RemediationKind: PersistenceRemediationKind.DeleteRegistryValue,
                RemediationTarget: @"HKCU|Environment|COR_PROFILER_PATH"),
            // Здоровая подписанная запись не должна попадать в список угроз
            new PersistenceAnomalyRecord(
                Vector: ThreatDetectionVector.SuspiciousRegistryAutorun,
                RegistryOrTaskPath: @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                EntryName: "SecurityHealth",
                PayloadCommandOrPath: @"C:\Windows\system32\SecurityHealthSystray.exe",
                ReferencedExecutablePath: null,
                IsMissingSecurityDescriptorSd: false,
                PreviousValueSerialized: null,
                Category: PersistenceZone.RunAndRunOnceKeys,
                IsAnomaly: false,
                IsSigned: true)
        };

        var exclusions = new[]
        {
            PersistenceZoneCatalog.ClassifyDefenderExclusion(
                DefenderExclusionKind.Path,
                @"C:\Users\User\AppData\Roaming",
                isPolicyEnforced: false,
                @"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
                @"C:\Windows")
        };

        var fwRules = new[]
        {
            new FirewallRuleAnomaly(
                RuleId: "{BAD-RULE-1}",
                DisplayName: "Block Defender Cloud",
                Direction: "Исходящее (Out)",
                Action: "Блокировать (Block)",
                ApplicationPath: @"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe",
                RemoteAddresses: "*",
                RemotePorts: "*",
                RawRegistryValue: "v2.30|Action=Block|Active=TRUE|Dir=Out|",
                SimpleExplanation: "Блокирует облачную защиту антивируса.")
        };

        var users = new[]
        {
            new SuspiciousUserAccountFinding(
                UserName: "SvcSupport$",
                IsAdministrator: true,
                IsEnabled: true,
                EndsWithDollarSign: true,
                IsHiddenInWinlogonSpecialAccounts: true,
                Comment: "",
                Reason: "Скрытый администратор с суффиксом $")
        };

        var artifacts = new[]
        {
            new DirectoryThreatArtifact(
                FilePath: @"C:\Users\User\AppData\Roaming\VpnHelper\WinRing0x64.sys",
                ArtifactKind: "Драйвер MSR",
                FileSizeBytes: 14540,
                IsBloatedPaddingSuspect: false,
                MatchedIndicator: "WinRing0x64.sys",
                SimpleExplanation: "Драйвер прямого доступа к MSR в папке пользователя")
        };

        var findings = engine.AnalyzeFullEcosystem(
            processes,
            ipv6Connections,
            persistence,
            exclusions,
            fwRules,
            users,
            artifacts,
            dnsCachedPoolDomains: ["pool.hashvault.pro"],
            windowsDirectory: @"C:\Windows");

        Assert.Contains(findings, f => f.Vector == ThreatDetectionVector.GpuDropOnInspectEvasion && f.SuspectProcessId == 3188);
        Assert.Contains(findings, f => f.Vector == ThreatDetectionVector.ProcessHollowingOrImplant && f.SuspectProcessId == 3188);
        Assert.Contains(findings, f => f.Vector == ThreatDetectionVector.StratumMiningPoolConnection && f.SuspectProcessId == 3188);
        Assert.Contains(findings, f => f.Vector == ThreatDetectionVector.DotNetProfilerHijack);
        Assert.Contains(findings, f => f.Vector == ThreatDetectionVector.DangerousDefenderExclusion);
        Assert.Contains(findings, f => f.Vector == ThreatDetectionVector.MaliciousFirewallRule);
        Assert.Contains(findings, f => f.Vector == ThreatDetectionVector.HiddenOrRogueUserAccount);
        Assert.Contains(findings, f => f.Vector == ThreatDetectionVector.MinerStagingArtifactOrBloatedBinary);
        Assert.Contains(findings, f => f.Vector == ThreatDetectionVector.DnsCacheMiningPool);
        Assert.DoesNotContain(findings, f => f.SimpleTitle.Contains("SecurityHealth", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ExternalScannerCoordinator_ParsesPeSieveJsonAndYaraStdout_WithoutFalsePositives()
    {
        const string hollowJson = """
        {
          "pid": 6044,
          "is_64_bit": 1,
          "is_managed": 0,
          "main_image_path": "C:\\Windows\\System32\\conhost.exe",
          "scanned": {
            "total": 18,
            "skipped": 0,
            "modified": {
              "total": 2,
              "patched": 0,
              "iat_hooked": 0,
              "replaced": 1,
              "hdr_modified": 0,
              "implanted_pe": 1,
              "implanted_shc": 0
            }
          }
        }
        """;

        var hit = ExternalScannerCoordinator.ParsePeSieveJsonReport(hollowJson, @"C:\Windows");
        Assert.NotNull(hit);
        Assert.Equal(ThreatDetectionVector.ExternalPeSieveImplant, hit!.Vector);
        Assert.Equal(6044, hit.SuspectProcessId);
        // conhost.exe лежит в C:\Windows\System32 — карантин системного файла должен быть запрещён, но процесс можно завершить!
        Assert.False(hit.CanQuarantineFileSafely);
        Assert.True(hit.CanRemediateAny);

        // Одиночный inline-патч оверлея без имплантов игнорируется
        const string overlayJson = """
        {
          "pid": 7100,
          "main_image_path": "D:\\Games\\Game.exe",
          "scanned": {
            "total": 40,
            "modified": { "total": 1, "patched": 1, "implanted_pe": 0, "replaced": 0, "hdr_modified": 0 }
          }
        }
        """;
        Assert.Null(ExternalScannerCoordinator.ParsePeSieveJsonReport(overlayJson, @"C:\Windows"));

        const string yaraOut = """
        SilentCryptoMiner_Loader C:\Users\Alex\AppData\Local\Temp\svc_host_upd.exe
        XMRig_Stratum_Config C:\Users\Alex\AppData\Roaming\Codec\config.json
        """;
        var yaraHits = ExternalScannerCoordinator.ParseYaraStdout(yaraOut, @"C:\Windows");
        Assert.Equal(2, yaraHits.Count);
        Assert.All(yaraHits, y => Assert.True(y.CanQuarantineFileSafely));
    }

    [Fact]
    public async Task SecurityService_CompositeNeutralization_StopsProcess_RemovesPersistence_QuarantinesFile_AndRestores()
    {
        var minerPath = Path.Combine(_tempDir, "silent_worker.exe");
        var originalBytes = Encoding.UTF8.GetBytes("STAGE4-COMPOSITE-QUARANTINE-TEST-BINARY");
        await File.WriteAllBytesAsync(minerPath, originalBytes);

        var bridge = new Stage4FakeBridge();
        var service = new AntiMinerSecurityService(_vault, bridge);

        var persistence = new PersistenceAnomalyRecord(
            Vector: ThreatDetectionVector.ComClassHijack,
            RegistryOrTaskPath: @"HKCU\Software\Classes\CLSID\{11111111-2222-3333-4444-555555555555}\InprocServer32",
            EntryName: "{11111111-2222-3333-4444-555555555555}",
            PayloadCommandOrPath: minerPath,
            ReferencedExecutablePath: minerPath,
            IsMissingSecurityDescriptorSd: false,
            PreviousValueSerialized: minerPath,
            Category: PersistenceZone.ComInprocAndLocalServerHijack,
            IsAnomaly: true,
            RemediationKind: PersistenceRemediationKind.DeleteRegistrySubKey,
            RemediationTarget: @"HKCU|Software\Classes\CLSID\{11111111-2222-3333-4444-555555555555}");

        var finding = new SecurityThreatFinding(
            FindingId: "comp-1",
            Vector: ThreatDetectionVector.ComClassHijack,
            Severity: RiskLevel.Critical,
            ConfidenceScorePercent: 95,
            SuspectProcessId: 8844,
            SuspectFilePath: minerPath,
            PersistenceRecord: persistence,
            SimpleTitle: "Перехват COM + майнер",
            SimpleExplanation: "Комплексная угроза",
            ExpertTechnicalEvidence: "Test",
            CanQuarantineFileSafely: true);

        var res = await service.QuarantineThreatAsync(finding);
        Assert.True(res.Succeeded);
        Assert.Equal(3, res.FixedItemsCount);
        Assert.Contains(8844, bridge.KilledPids);
        Assert.Contains(persistence.EntryName, bridge.RemovedPersistenceEntries);
        Assert.False(File.Exists(minerPath));

        var history = await service.GetQuarantineHistoryAsync();
        var qItem = Assert.Single(history);
        Assert.False(qItem.IsReverted);
        Assert.Contains(minerPath, qItem.QuarantinedPaths);

        var restoreRes = await service.RestoreFromQuarantineAsync(qItem.SessionId);
        Assert.True(restoreRes.Succeeded);
        Assert.True(File.Exists(minerPath));
        Assert.Equal(originalBytes, await File.ReadAllBytesAsync(minerPath));
    }

    private sealed class Stage4FakeBridge : DefaultSecurityPlatformBridge
    {
        public List<int> KilledPids { get; } = [];
        public List<string> RemovedPersistenceEntries { get; } = [];

        public override bool IsRunningAsAdministrator() => true;
        public override string GetWindowsDirectory() => @"C:\Windows";

        public override Task<bool> TerminateSuspectProcessAsync(int processId, CancellationToken ct = default)
        {
            KilledPids.Add(processId);
            return Task.FromResult(true);
        }

        public override Task<(bool Succeeded, StateTargetKind? RollbackKind, string? RollbackTarget, string? PreviousStateJson)> RemovePersistenceEntryAsync(
            PersistenceAnomalyRecord record,
            CancellationToken ct = default)
        {
            RemovedPersistenceEntries.Add(record.EntryName);
            return Task.FromResult<(bool, StateTargetKind?, string?, string?)>((
                true,
                StateTargetKind.SystemSetting,
                $"DeletedRegistryKey:{record.RegistryOrTaskPath}",
                record.PreviousValueSerialized ?? "{}"));
        }
    }
}
