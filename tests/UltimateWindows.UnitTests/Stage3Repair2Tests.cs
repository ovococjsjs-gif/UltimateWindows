using System.Globalization;
using UltimateWindows.Core.Contracts;
using UltimateWindows.Core.Enums;
using UltimateWindows.Core.Models;
using UltimateWindows.Modules.Repair.Catalog;
using UltimateWindows.Modules.Repair.Diagnostics;
using UltimateWindows.Modules.Repair.ErrorCodes;
using UltimateWindows.Modules.Repair.Models;
using UltimateWindows.Modules.Repair.PeDoctor;
using UltimateWindows.Modules.Repair.Services;
using UltimateWindows.Modules.Safety.Services;
using Xunit;

namespace UltimateWindows.UnitTests;

public sealed class Stage3Repair2Tests : IDisposable
{
    private readonly string _sandboxDir;

    public Stage3Repair2Tests()
    {
        _sandboxDir = Path.Combine(Path.GetTempPath(), $"uw_stage3_tests_{Guid.NewGuid():N}");
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
            // Ignore teardown lock
        }
    }

    [Fact]
    public void BuiltInRepairCatalog_LoadsOver100RulesAcrossAll16Sections_AndBlocksLicensingTampering()
    {
        var rules = RepairCatalogLoader.LoadBuiltInCatalog();
        Assert.True(rules.Count >= 100, $"Expected >= 100 rules, actual: {rules.Count}");

        var representedSections = rules.Select(r => r.Section).Distinct().ToHashSet();
        foreach (var sec in Enum.GetValues<RepairSectionId>())
        {
            Assert.Contains(sec, representedSections);
        }

        // Проверяем запрет вмешательства в sppsvc / SoftwareProtectionPlatform
        const string forbiddenJson = """
        {
          "schemaVersion": 1,
          "section": "CriticalServices",
          "rules": [
            {
              "id": "bad.licensing",
              "title": "Запрещённое правило",
              "symptom": "Тест",
              "explanation": "Тест",
              "fixSummary": "Тест",
              "services": [
                { "serviceName": "sppsvc", "healthyStartup": "Automatic" }
              ]
            }
          ]
        }
        """;
        Assert.Throws<InvalidDataException>(() => RepairCatalogLoader.ParseCatalogJson(forbiddenJson, "forbidden.json"));
    }

    [Fact]
    public void ErrorCodeCatalog_AllCrossReferencesResolve_AndDecodesHexSignedDecimalAndWin32HResult()
    {
        var allRulesById = RepairCatalogLoader.LoadBuiltInCatalog().Select(r => r.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var allRuntimesByKey = OfficialRuntimeCatalog.GetAllPackages().Select(p => p.PackageKey).ToHashSet(StringComparer.OrdinalIgnoreCase);

        Assert.True(ErrorCodeCatalog.Count >= 140, $"Expected >= 140 error codes, actual: {ErrorCodeCatalog.Count}");

        foreach (var entry in ErrorCodeCatalog.GetAll())
        {
            foreach (var ruleId in entry.RelatedRepairRuleIds)
            {
                Assert.True(allRulesById.Contains(ruleId), $"ErrorCode {entry.DisplayCode} references missing rule '{ruleId}'");
            }

            foreach (var pkgKey in entry.RelatedRuntimePackageKeys)
            {
                Assert.True(allRuntimesByKey.Contains(pkgKey), $"ErrorCode {entry.DisplayCode} references missing runtime '{pkgKey}'");
            }
        }

        // 1. Поиск по знаковому десятичному значению (-2147024891 == 0x80070005 E_ACCESSDENIED)
        var accessDenied = ErrorCodeCatalog.Search("-2147024891");
        Assert.NotEmpty(accessDenied);
        Assert.Equal(0x80070005u, accessDenied[0].NumericCode);

        // 2. Поиск по коду MSI 1603
        var msi1603 = ErrorCodeCatalog.Search("1603");
        Assert.Contains(msi1603, e => e.DisplayCode == "1603");

        // 3. Автоматическая расшифровка незнакомого HRESULT вида 0x8007XXXX (0x80070032 -> Win32 50 ERROR_NOT_SUPPORTED)
        var wrappedWin32 = ErrorCodeCatalog.Search("0x80070032");
        Assert.NotEmpty(wrappedWin32);
        Assert.Equal(0x80070032u, wrappedWin32[0].NumericCode);
        Assert.Contains("50", wrappedWin32[0].DetailedExplanation);

        // 4. Поиск кода остановки BSOD 0x00000116 VIDEO_TDR_FAILURE
        var tdr = ErrorCodeCatalog.Search("0x00000116");
        Assert.NotEmpty(tdr);
        Assert.Contains("VIDEO_TDR_FAILURE", tdr[0].SymbolicName);
    }

    [Fact]
    public async Task RepairDiagnosticEngine_DetectsFixesVerifies_AndRollsBackViaTimeMachineInOneTransaction()
    {
        var bridge = new InMemoryRepairBridge();
        var vaultDir = Path.Combine(_sandboxDir, "Vault");
        var applier = new InMemoryRepairRollbackApplier(bridge);
        var vault = new ZeroBloatVaultService(vaultDir, stateApplier: applier);

        // Симулируем поломки:
        // 1) DisableTaskMgr = 1 в HKCU
        // 2) DisableRegistryTools = 0 в HKCU (явный 0 НЕ является блокировкой!)
        // 3) Служба Audiosrv отключена (Disabled)
        bridge.SetDword("HKCU", @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr", 1);
        bridge.SetDword("HKCU", @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableRegistryTools", 0);
        bridge.SetService("Audiosrv", RepairServiceStartupKind.Disabled, isRunning: false);
        bridge.SetService("AudioEndpointBuilder", RepairServiceStartupKind.Automatic, isRunning: true);

        var service = new SystemRepairService(vault, bridge);

        // Фаза 1: ОБНАРУЖИТЬ
        var findings = await service.ScanSystemHealthAsync();
        var taskMgrFinding = Assert.Single(findings, f => f.Rule.Id == "tools.unlock-taskmgr");
        var regeditFinding = Assert.Single(findings, f => f.Rule.Id == "tools.unlock-regedit");
        var audioFinding = Assert.Single(findings, f => f.Rule.Id == "audio.core-services");

        Assert.Equal(RepairHealthState.IssueDetected, taskMgrFinding.State);
        Assert.Equal(RepairHealthState.Healthy, regeditFinding.State); // DWord 0 не должен давать ложную тревогу!
        Assert.Equal(RepairHealthState.IssueDetected, audioFinding.State);

        // Фаза 2 + 3: ИСПРАВИТЬ И ПРОВЕРИТЬ
        var fixBatch = await service.FixIssuesAsync(["tools.unlock-taskmgr", "audio.core-services"]);
        Assert.Equal(2, fixBatch.SucceededCount);
        Assert.Equal(2, fixBatch.VerifiedHealthyCount);
        Assert.NotNull(fixBatch.RollbackSessionId);

        Assert.False(bridge.ReadRegistryValue("HKCU", @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr").ValueExists);
        Assert.Equal(RepairServiceStartupKind.Automatic, bridge.QueryServiceState("Audiosrv").Startup);
        Assert.True(bridge.QueryServiceState("Audiosrv").IsRunning);

        // Фаза 4: ОТКАТ В 1 КЛИК через Машину времени возвращает оба узла в исходное состояние
        await vault.RollbackTransactionAsync(fixBatch.RollbackSessionId!.Value);
        Assert.Equal(1, bridge.ReadRegistryValue("HKCU", @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr").DwordValue);
        Assert.Equal(RepairServiceStartupKind.Disabled, bridge.QueryServiceState("Audiosrv").Startup);
    }

    [Fact]
    public void CbsLogAnalyzer_ScopesToLatestSfcTransaction_AndDetectsUnrepairableFiles()
    {
        // Сценарий 1: старая сессия SFC нашла поломку, но последняя сессия всё восстановила
        const string healedLog = """
        2026-11-10 12:00:00, Info                  CSI    00000001 [SR] Beginning Verify and Repair transaction
        2026-11-10 12:01:00, Info                  CSI    00000002 [SR] Cannot repair member file [l:10]"d3d11.dll" of Microsoft-Windows-DirectX
        2026-11-11 09:30:00, Info                  CSI    00000010 [SR] Beginning Verify and Repair transaction
        2026-11-11 09:31:15, Info                  CSI    00000011 [SR] Repairing corrupted file \??\C:\Windows\System32\"d3d11.dll" from store
        2026-11-11 09:32:00, Info                  CSI    00000012 [SR] Verify complete
        """;

        var healed = CbsLogAnalyzer.AnalyzeText(healedLog);
        Assert.False(healed.HasUnrepairableCorruption);
        Assert.Empty(healed.UnrepairableFiles);
        Assert.Contains("d3d11.dll", healed.RepairedFiles);

        // Сценарий 2: в последней сессии остались невосстановленные файлы
        const string brokenLog = """
        2026-11-11 10:15:00, Info                  CSI    00000020 [SR] Beginning Verify and Repair transaction
        2026-11-11 10:16:00, Info                  CSI    00000021 [SR] Cannot repair member file [l:12]"shell32.dll" of Microsoft-Windows-Shell32
        """;

        var broken = CbsLogAnalyzer.AnalyzeText(brokenLog);
        Assert.True(broken.HasUnrepairableCorruption);
        Assert.Contains("shell32.dll", broken.UnrepairableFiles);
    }

    [Fact]
    public void AppCrashAnalyzer_ClassifiesEvent1000SideBySideAndDotNet_WithRuntimeAndRuleLinks()
    {
        var now = DateTimeOffset.UtcNow;

        // Event 1000: падение в vcruntime140.dll с 0xc0000005
        var ev1000 = AppCrashAnalyzer.BuildAnalyzedEntry(
            eventId: 1000,
            provider: "Application Error",
            timestampUtc: now,
            dataItems:
            [
                "StudioApp.exe", "2.1.0.0", "65f0a1", "vcruntime140.dll", "14.38.0.0", "65e0b2",
                "c0000005", "00000000000012a0", "1a40", "01da9000", @"C:\Program Files\Studio\StudioApp.exe", @"C:\Windows\System32\vcruntime140.dll"
            ]);

        Assert.Equal(SystemCrashEventKind.ApplicationCrash1000, ev1000.Kind);
        Assert.Equal(0xC0000005u, ev1000.ExceptionCode);
        Assert.Equal("vcredist-2015-2022-x64", ev1000.RecommendedRuntimeKey);
        Assert.Equal(@"C:\Program Files\Studio\StudioApp.exe", ev1000.FaultingExecutablePath);

        // SideBySide Event 33 с упоминанием VC90.CRT x86
        var sxs = AppCrashAnalyzer.BuildAnalyzedEntry(
            eventId: 33,
            provider: "SideBySide",
            timestampUtc: now,
            dataItems: ["Microsoft.VC90.CRT,processorArchitecture=\"x86\",version=\"9.0.30729.6161\"", "", @"C:\Games\OldGame\game.exe"]);

        Assert.Equal(SystemCrashEventKind.SideBySideManifestError, sxs.Kind);
        Assert.Equal("vcredist-2008-x86", sxs.RecommendedRuntimeKey);
    }

    [Fact]
    public void OfficialRuntimeCatalog_Has23SignedPackages_AndInstalledScannerRespectsSubfolderDlls()
    {
        var packages = OfficialRuntimeCatalog.GetAllPackages();
        Assert.Equal(23, packages.Count);

        foreach (var pkg in packages)
        {
            if (pkg.DirectDownloadUrl is not null)
            {
                Assert.True(
                    OfficialRuntimeCatalog.IsTrustedOfficialDownloadUrl(pkg.DirectDownloadUrl),
                    $"Package {pkg.PackageKey} has untrusted URL: {pkg.DirectDownloadUrl}");
            }
            else
            {
                Assert.False(string.IsNullOrWhiteSpace(pkg.OptionalWindowsFeatureName) && string.IsNullOrWhiteSpace(pkg.WingetPackageId));
            }
        }

        Assert.False(OfficialRuntimeCatalog.IsTrustedOfficialDownloadUrl("http://aka.ms/vc14/vc_redist.x64.exe"));
        Assert.False(OfficialRuntimeCatalog.IsTrustedOfficialDownloadUrl("https://evil-dll-downloads.example.com/vcruntime140.dll"));

        // Проверяем InstalledProgramsDependencyScanner + WinSxS VC90 + вложенную папку bin\
        var fakeWindows = Path.Combine(_sandboxDir, "Windows");
        var sys64 = Path.Combine(fakeWindows, "System32");
        var sys32 = Path.Combine(fakeWindows, "SysWOW64");
        var winSxSVc90 = Path.Combine(fakeWindows, "WinSxS", "amd64_microsoft.vc90.crt_1fc8b3b9a1e18e3b_9.0.30729");
        Directory.CreateDirectory(sys64);
        Directory.CreateDirectory(sys32);
        Directory.CreateDirectory(winSxSVc90);

        // Кладем msvcr90.dll в WinSxS (как в настоящей Windows!)
        File.WriteAllBytes(Path.Combine(winSxSVc90, "msvcr90.dll"), PeDoctorBsodAndRepairTests.BuildSyntheticPeBinary(true, []));

        // Программа №1: здоровая (собственная engine.dll лежит в подпапке bin\, а msvcr90.dll — в WinSxS)
        var healthyDir = Path.Combine(_sandboxDir, "HealthyApp");
        var healthyBin = Path.Combine(healthyDir, "bin");
        Directory.CreateDirectory(healthyBin);
        var healthyExe = Path.Combine(healthyDir, "HealthyApp.exe");
        File.WriteAllBytes(healthyExe, PeDoctorBsodAndRepairTests.BuildSyntheticPeBinary(true, ["engine.dll", "msvcr90.dll"]));
        File.WriteAllBytes(Path.Combine(healthyBin, "engine.dll"), PeDoctorBsodAndRepairTests.BuildSyntheticPeBinary(true, []));

        // Программа №2: сломана (не хватает vcruntime140.dll)
        var brokenDir = Path.Combine(_sandboxDir, "BrokenApp");
        Directory.CreateDirectory(brokenDir);
        var brokenExe = Path.Combine(brokenDir, "BrokenApp.exe");
        File.WriteAllBytes(brokenExe, PeDoctorBsodAndRepairTests.BuildSyntheticPeBinary(true, ["vcruntime140.dll"]));

        var scanner = new InstalledProgramsDependencyScanner();
        var summary = scanner.ScanPrograms(
            [
                new InstalledProgramInfo("Healthy Studio", "1.0", "Vendor", healthyExe, healthyDir),
                new InstalledProgramInfo("Broken Game", "2.0", "Studio", brokenExe, brokenDir)
            ],
            sys64,
            sys32);

        Assert.Equal(2, summary.ExecutablesInspected);
        var singleBroken = Assert.Single(summary.BrokenPrograms);
        Assert.Equal("Broken Game", singleBroken.Program.DisplayName);
        Assert.Contains(summary.DistinctRecommendedPackages, p => p.PackageKey == "vcredist-2015-2022-x64");

        // Проверяем разрешение контрактов api-ms-win-crt-*.dll через системную ucrtbase.dll на Windows 10/11
        var ucrtExe = Path.Combine(healthyDir, "NotepadLike.exe");
        File.WriteAllBytes(ucrtExe, PeDoctorBsodAndRepairTests.BuildSyntheticPeBinary(
            true,
            ["api-ms-win-crt-runtime-l1-1-0.dll", "api-ms-win-crt-private-l1-1-0.dll"]));

        var doctor = new BinaryPeDependencyDoctor();
        // Пока ucrtbase.dll нет в FakeSystem32 — PE-Доктор рекомендует поставить VC++ v14
        var withoutUcrt = doctor.DiagnoseExecutable(ucrtExe, sys64, sys32);
        Assert.False(withoutUcrt.IsHealthy);

        // Когда в System32 присутствует штатная 64-битная ucrtbase.dll — контракты UCRT считаются здоровыми!
        File.WriteAllBytes(Path.Combine(sys64, "ucrtbase.dll"), PeDoctorBsodAndRepairTests.BuildSyntheticPeBinary(true, []));
        var withUcrt = doctor.DiagnoseExecutable(ucrtExe, sys64, sys32);
        Assert.True(withUcrt.IsHealthy);
        Assert.Empty(withUcrt.Issues);
    }

    private sealed class InMemoryRepairBridge : DefaultRepairPlatformBridge
    {
        private readonly Dictionary<string, (RepairRegistryValueKind Kind, string? Str, int? Dw)> _reg = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, (RepairServiceStartupKind Startup, bool Running)> _svc = new(StringComparer.OrdinalIgnoreCase);

        public override bool IsRunningAsAdministrator() => true;
        public override int GetWindowsBuildNumber() => 26100;

        public void SetDword(string hive, string subKey, string name, int val) =>
            _reg[$@"{hive}\{subKey}\{name}"] = (RepairRegistryValueKind.DWord, val.ToString(CultureInfo.InvariantCulture), val);

        public void SetService(string name, RepairServiceStartupKind startup, bool isRunning) =>
            _svc[name] = (startup, isRunning);

        public override RepairRegistryValueState ReadRegistryValue(string hive, string subKey, string valueName)
        {
            var keyPrefix = $@"{hive}\{subKey}\";
            var keyExists = _reg.Keys.Any(k => k.StartsWith(keyPrefix, StringComparison.OrdinalIgnoreCase));
            if (!_reg.TryGetValue($@"{hive}\{subKey}\{valueName}", out var val))
            {
                return new RepairRegistryValueState(keyExists, false, RepairRegistryValueKind.String, null, null, null);
            }

            return new RepairRegistryValueState(true, true, val.Kind, val.Str, val.Dw, val.Str ?? val.Dw?.ToString(CultureInfo.InvariantCulture));
        }

        public override (bool Succeeded, string? CreatedKeyPath, string? Error) WriteRegistryValue(
            string hive, string subKey, string valueName, RepairRegistryValueKind kind, string? stringValue, int? dwordValue)
        {
            _reg[$@"{hive}\{subKey}\{valueName}"] = (kind, stringValue ?? dwordValue?.ToString(CultureInfo.InvariantCulture), dwordValue);
            return (true, null, null);
        }

        public override (bool Succeeded, string? Error) DeleteRegistryValue(string hive, string subKey, string valueName)
        {
            _reg.Remove($@"{hive}\{subKey}\{valueName}");
            return (true, null);
        }

        public override RepairServiceState QueryServiceState(string serviceName) =>
            _svc.TryGetValue(serviceName, out var s)
                ? new RepairServiceState(true, s.Startup, s.Running)
                : new RepairServiceState(false, RepairServiceStartupKind.Unknown, false);

        public override Task<(bool Succeeded, string? Error)> RepairServiceAsync(
            string serviceName, RepairServiceStartupKind targetStartup, bool startIfStopped, CancellationToken ct = default)
        {
            var prev = _svc.TryGetValue(serviceName, out var s) ? s.Running : false;
            _svc[serviceName] = (targetStartup, startIfStopped || prev);
            return Task.FromResult<(bool, string?)>((true, null));
        }

        public override Task<RepairCustomProbeResult> RunCustomProbeAsync(string customProbeId, CancellationToken ct = default) =>
            Task.FromResult(new RepairCustomProbeResult(RepairHealthState.Healthy, "OK"));
    }

    private sealed class InMemoryRepairRollbackApplier(InMemoryRepairBridge bridge) : ISystemStateApplier
    {
        public Task ApplyRollbackDeltaAsync(
            StateDeltaRecord delta,
            Func<string, CancellationToken, Task<byte[]>> restoreBlobBytesAsync,
            CancellationToken ct = default)
        {
            if (delta.TargetKind == StateTargetKind.RegistryValue && !string.IsNullOrWhiteSpace(delta.PreviousStateJson))
            {
                using var doc = System.Text.Json.JsonDocument.Parse(delta.PreviousStateJson);
                var r = doc.RootElement;
                var hive = r.GetProperty("Hive").GetString()!;
                var subKey = r.GetProperty("SubKey").GetString()!;
                var valueName = r.GetProperty("ValueName").GetString()!;
                var existed = r.GetProperty("ExistedBefore").GetBoolean();
                if (!existed)
                {
                    bridge.DeleteRegistryValue(hive, subKey, valueName);
                }
                else
                {
                    var kind = (RepairRegistryValueKind)r.GetProperty("ValueKind").GetInt32();
                    var data = r.GetProperty("SerializedData").GetString();
                    int? dw = kind == RepairRegistryValueKind.DWord && int.TryParse(data, out var parsed) ? parsed : null;
                    bridge.WriteRegistryValue(hive, subKey, valueName, kind, data, dw);
                }
            }
            else if (delta.TargetKind == StateTargetKind.WindowsService && !string.IsNullOrWhiteSpace(delta.PreviousStateJson))
            {
                using var doc = System.Text.Json.JsonDocument.Parse(delta.PreviousStateJson);
                var svcName = doc.RootElement.GetProperty("ServiceName").GetString()!;
                var startup = Enum.Parse<RepairServiceStartupKind>(doc.RootElement.GetProperty("Startup").GetString()!, ignoreCase: true);
                bridge.SetService(svcName, startup, isRunning: false);
            }

            return Task.CompletedTask;
        }
    }
}
