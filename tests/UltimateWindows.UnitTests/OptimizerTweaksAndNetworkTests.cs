using UltimateWindows.Core.Contracts;
using UltimateWindows.Core.Enums;
using UltimateWindows.Core.Models;
using UltimateWindows.Modules.Optimizer.Catalog;
using UltimateWindows.Modules.Optimizer.Models;
using UltimateWindows.Modules.Optimizer.Network;
using UltimateWindows.Modules.Optimizer.Services;
using UltimateWindows.Modules.Safety.Services;
using Xunit;

namespace UltimateWindows.UnitTests;

public sealed class OptimizerTweaksAndNetworkTests : IDisposable
{
    private readonly string _sandboxDir;

    public OptimizerTweaksAndNetworkTests()
    {
        _sandboxDir = Path.Combine(Path.GetTempPath(), $"uw_optimizer_tests_{Guid.NewGuid():N}");
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
    public void TweakSafetyGuard_ApprovesAllBuiltInRules_AndBlocksDefenderHvciAndUacTampering()
    {
        foreach (var rule in DeclarativeTweakCatalog.GetAllRules())
        {
            TweakSafetyGuard.ThrowIfUnsafeRule(rule);
        }

        Assert.False(TweakSafetyGuard.IsSafeAllowedMutation(new TweakRegistryMutation(
            "HKLM", @"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", RegistryTweakValueKind.DWord, "1", "0")));

        Assert.False(TweakSafetyGuard.IsSafeAllowedMutation(new TweakRegistryMutation(
            "HKLM", @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled", RegistryTweakValueKind.DWord, "0", "1")));

        Assert.False(TweakSafetyGuard.IsSafeAllowedMutation(new TweakRegistryMutation(
            "HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", RegistryTweakValueKind.DWord, "0", "1")));
    }

    [Fact]
    public void TweakSafetyGuard_AllowsProtectionWeakeningOnlyInRulesMarkedDangerous_AndAlwaysBlocksLicensing()
    {
        var defenderMutation = new TweakRegistryMutation(
            "HKLM", @"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring", RegistryTweakValueKind.DWord, "1", "0");

        Assert.True(TweakSafetyGuard.WeakensSystemProtection(defenderMutation));
        Assert.False(TweakSafetyGuard.IsAlwaysForbidden(defenderMutation));

        // Под видом безопасной настройки ослабить защиту Windows нельзя
        var disguised = BuildTestRule("test.disguised-defender", RiskLevel.Safe, defenderMutation);
        Assert.False(disguised.IsDangerous);
        Assert.Throws<InvalidOperationException>(() => TweakSafetyGuard.ThrowIfUnsafeRule(disguised));

        // Правило, честно помеченное как опасное, допустимо
        var honest = BuildTestRule("test.honest-defender", RiskLevel.High, defenderMutation);
        Assert.True(honest.IsDangerous);
        TweakSafetyGuard.ThrowIfUnsafeRule(honest);

        // Вмешательство в лицензирование запрещено даже в опасном правиле
        var licensingMutation = new TweakRegistryMutation(
            "HKLM", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform", "SkipRearm", RegistryTweakValueKind.DWord, "1", "0");

        Assert.True(TweakSafetyGuard.IsAlwaysForbidden(licensingMutation));
        Assert.False(TweakSafetyGuard.IsSafeAllowedMutation(licensingMutation));
        Assert.Throws<InvalidOperationException>(
            () => TweakSafetyGuard.ThrowIfUnsafeRule(BuildTestRule("test.licensing", RiskLevel.Critical, licensingMutation)));
    }

    [Fact]
    public void TweakRequirements_EvaluateAgainstSystemFacts_AndNeverBlockOnUnknownFacts()
    {
        var windows11Only = new TweakRequirements(MinWindowsBuild: 22000);
        var onWindows10 = windows11Only.Evaluate(new SystemFacts(WindowsBuildNumber: 19045));
        Assert.Equal(TweakApplicabilityStatus.NotApplicable, onWindows10.Status);
        Assert.Contains("Windows 11", onWindows10.Reason);
        Assert.True(windows11Only.Evaluate(new SystemFacts(WindowsBuildNumber: 26100)).IsApplicable);
        Assert.True(windows11Only.Evaluate(SystemFacts.Unknown).IsApplicable);

        var windows10Only = new TweakRequirements(MaxWindowsBuild: 19045);
        Assert.Equal(TweakApplicabilityStatus.NotApplicable, windows10Only.Evaluate(new SystemFacts(WindowsBuildNumber: 22631)).Status);
        Assert.True(windows10Only.Evaluate(new SystemFacts(WindowsBuildNumber: 19045)).IsApplicable);

        var solidStateOnly = new TweakRequirements(BestOnSolidStateSystemDrive: true);
        Assert.Equal(TweakApplicabilityStatus.NotRecommended, solidStateOnly.Evaluate(new SystemFacts(SystemDriveIsSolidState: false)).Status);
        Assert.True(solidStateOnly.Evaluate(new SystemFacts(SystemDriveIsSolidState: true)).IsApplicable);
        Assert.True(solidStateOnly.Evaluate(SystemFacts.Unknown).IsApplicable);

        var desktopOnly = new TweakRequirements(BatteryWarning: "Это устройство с батареей.");
        var onLaptop = desktopOnly.Evaluate(new SystemFacts(HasBattery: true));
        Assert.Equal(TweakApplicabilityStatus.NotRecommended, onLaptop.Status);
        Assert.Equal("Это устройство с батареей.", onLaptop.Reason);
        Assert.True(desktopOnly.Evaluate(new SystemFacts(HasBattery: false)).IsApplicable);

        Assert.True(TweakRequirements.None.Evaluate(new SystemFacts(19045, false, true, 4L * 1024 * 1024 * 1024)).IsApplicable);
    }

    [Fact]
    public async Task SmartOptimizerService_RespectsApplicability_AndAsksBeforeNotRecommendedTweaks()
    {
        // Ноутбук с Windows 10 и системным жёстким диском
        var bridge = new FakeOptimizerBridge
        {
            Facts = new SystemFacts(WindowsBuildNumber: 19045, SystemDriveIsSolidState: false, HasBattery: true)
        };
        var vault = new ZeroBloatVaultService(Path.Combine(_sandboxDir, "VaultFacts"));
        var service = new SmartOptimizerService(vault, bridge);

        var states = service.EvaluateAllTweaks();
        Assert.Equal(
            TweakApplicabilityStatus.NotApplicable,
            states.Single(s => s.Rule.TweakId == "ui.win11-classic-full-context-menu").Applicability.Status);
        Assert.Equal(
            TweakApplicabilityStatus.NotRecommended,
            states.Single(s => s.Rule.TweakId == "disk.disable-superfetch-sysmain").Applicability.Status);
        Assert.Equal(
            TweakApplicabilityStatus.NotRecommended,
            states.Single(s => s.Rule.TweakId == "disk.disable-hibernation-boot-files").Applicability.Status);
        Assert.True(states.Single(s => s.Rule.TweakId == "ui.fast-menu-response").Applicability.IsApplicable);

        // Твик только для Windows 11 нельзя включить на Windows 10 даже с явным согласием
        var notApplicable = await service.SetTweakStateAsync(
            "ui.win11-classic-full-context-menu", enableTweak: true, options: TweakApplyOptions.AcceptAll);
        Assert.False(notApplicable.Succeeded);
        Assert.Equal(TweakConfirmationKind.None, notApplicable.ConfirmationRequired);
        Assert.Empty(bridge.Store);

        // Не рекомендуемый твик без согласия не применяется и просит подтверждение
        var needsConsent = await service.SetTweakStateAsync("disk.disable-superfetch-sysmain", enableTweak: true);
        Assert.False(needsConsent.Succeeded);
        Assert.Equal(TweakConfirmationKind.NotRecommendedForThisPc, needsConsent.ConfirmationRequired);
        Assert.Contains("HDD", needsConsent.UserFriendlyMessage);
        Assert.Empty(bridge.Store);

        // С явным согласием пользователя твик применяется
        var consented = await service.SetTweakStateAsync(
            "disk.disable-superfetch-sysmain", enableTweak: true, options: new TweakApplyOptions(AcceptNotRecommended: true));
        Assert.True(consented.Succeeded);
        Assert.Equal("4", bridge.Store[@"HKLM\SYSTEM\CurrentControlSet\Services\SysMain::Start"].Val);

        // Возврат к стандарту Windows разрешён всегда и подтверждений не требует
        var restored = await service.SetTweakStateAsync("disk.disable-superfetch-sysmain", enableTweak: false);
        Assert.True(restored.Succeeded);
        Assert.Equal("2", bridge.Store[@"HKLM\SYSTEM\CurrentControlSet\Services\SysMain::Start"].Val);
    }

    [Fact]
    public void BuiltInCatalog_HasNoDangerousRulesInPresets_AndRestoresCorrectWindowsDefaults()
    {
        var rules = DeclarativeTweakCatalog.GetAllRules();

        // Идентификаторы уникальны
        Assert.Equal(rules.Count, rules.Select(r => r.TweakId).Distinct(StringComparer.OrdinalIgnoreCase).Count());

        // В готовые наборы не попадает ничего опасного и ничего с условиями применимости
        foreach (var presetKey in new[] { "recommended", "gaming", "privacy" })
        {
            foreach (var id in DeclarativeTweakCatalog.GetPresetIds(presetKey))
            {
                var rule = DeclarativeTweakCatalog.FindById(id);
                Assert.NotNull(rule);
                Assert.False(rule!.IsDangerous);
                Assert.Same(TweakRequirements.None, rule.EffectiveRequirements);
            }
        }

        // Стандартный порог разделения svchost в Windows — 0x380000 КБ
        var svchost = DeclarativeTweakCatalog.FindById("sys.svchost-split-threshold-ram");
        Assert.NotNull(svchost);
        Assert.Equal("3670016", svchost!.Mutations[0].DefaultRestoreSerializedValue);
    }

    private static DeclarativeTweakRule BuildTestRule(string id, RiskLevel risk, TweakRegistryMutation mutation) =>
        new(
            id,
            TweakCategory.SecurityAndClarity,
            "TST",
            "Тестовое правило",
            "Правило только для проверки защитного фильтра.",
            "—",
            risk,
            RequiresAdministrator: true,
            Mutations: [mutation]);

    [Fact]
    public async Task SmartOptimizerService_TogglesTweaks_ExportsImportsYaml_AndRecordsVaultRollback()
    {
        var bridge1 = new FakeOptimizerBridge();
        bridge1.Store[@"HKCU\Control Panel\Desktop::MenuShowDelay"] = ((int)RegistryTweakValueKind.String, "400");

        var applier = new RecordingStateApplier();
        var vault1 = new ZeroBloatVaultService(Path.Combine(_sandboxDir, "Vault1"), stateApplier: applier);
        var service1 = new SmartOptimizerService(vault1, bridge1);

        var enableRes = await service1.SetTweakStateAsync("ui.fast-menu-response", enableTweak: true);
        Assert.True(enableRes.Succeeded);
        Assert.NotNull(enableRes.RollbackSessionId);
        Assert.Equal("20", bridge1.Store[@"HKCU\Control Panel\Desktop::MenuShowDelay"].Val);

        // Проверяем экспорт активных настроек в декларативный YAML и импорт на второй чистой машине
        var yaml = service1.ExportActiveTweaksToYaml("Киберспорт и скорость");
        Assert.Contains("ui.fast-menu-response", yaml);

        var bridge2 = new FakeOptimizerBridge();
        var vault2 = new ZeroBloatVaultService(Path.Combine(_sandboxDir, "Vault2"));
        var service2 = new SmartOptimizerService(vault2, bridge2);

        var importRes = await service2.ImportAndApplyYamlProfileAsync(yaml);
        Assert.True(importRes.Succeeded);
        Assert.Equal("20", bridge2.Store[@"HKCU\Control Panel\Desktop::MenuShowDelay"].Val);

        // Проверяем откат в 1 клик на первой системе (возврат "400" из Машины времени)
        await vault1.RollbackTransactionAsync(enableRes.RollbackSessionId!.Value);
        Assert.Single(applier.RestoredDeltas);
        Assert.Contains("400", applier.RestoredDeltas[0].PreviousStateJson);
    }

    [Fact]
    public async Task FileLockHunter_BlocksCriticalSystemProcesses_AndAllowsPoliteCloseOfUserApps()
    {
        var bridge = new FakeOptimizerBridge();
        var vault = new ZeroBloatVaultService(Path.Combine(_sandboxDir, "VaultLock"));
        var service = new SmartOptimizerService(vault, bridge);

        var criticalProc = new LockingProcessInfo(
            ProcessId: 820,
            ApplicationName: "svchost.exe",
            ExecutablePath: @"C:\Windows\System32\svchost.exe",
            ProcessKindLabel: "Служба",
            IsCriticalSystemProcess: false);

        var blocked = await service.RequestSafeCloseLockingProcessAsync(criticalProc);
        Assert.False(blocked.Succeeded);

        var editorProc = new LockingProcessInfo(
            ProcessId: 4512,
            ApplicationName: "WINWORD.EXE",
            ExecutablePath: @"C:\Program Files\Microsoft Office\WINWORD.EXE",
            ProcessKindLabel: "Обычное приложение",
            IsCriticalSystemProcess: false);

        var closed = await service.RequestSafeCloseLockingProcessAsync(editorProc);
        Assert.True(closed.Succeeded);
    }

    [Fact]
    public void HostsInspector_IgnoresLocalhost_AndFlagsMaliciousSecurityDomainBlocks()
    {
        const string sampleHosts = """
            # Стандартный файл hosts
            127.0.0.1       localhost
            ::1             localhost
            192.168.10.25   gitlab.company.local
            0.0.0.0         www.virustotal.com
            127.0.0.1       fe2.update.microsoft.com
            """;

        var parsed = NetworkAndHostsInspector.ParseHostsContent(sampleHosts);
        Assert.Equal(3, parsed.Count);

        var corp = Assert.Single(parsed, x => x.DomainHost == "gitlab.company.local");
        Assert.False(corp.IsSuspiciousSecurityBlock);

        Assert.Equal(2, parsed.Count(x => x.IsSuspiciousSecurityBlock));
    }

    [Fact]
    public async Task OptimizerV2CatalogAndHostsEditor_CoversAllCategories_BlocksSecurityHijacks_AndRecordsHostsRollback()
    {
        var rules = DeclarativeTweakCatalog.GetAllRules();
        Assert.True(rules.Count >= 36);
        Assert.Contains(rules, r => r.Category == TweakCategory.DiskAndFileSystem);
        Assert.Contains(rules, r => r.Category == TweakCategory.AppTelemetry);
        Assert.Contains(rules, r => r.Category == TweakCategory.GamingAndLatency);

        var hostsFile = Path.Combine(_sandboxDir, "hosts_test");
        await File.WriteAllTextAsync(hostsFile, "127.0.0.1 localhost\r\n");

        var bridge = new FakeOptimizerBridge { CustomHostsPath = hostsFile };
        var applier = new RecordingStateApplier();
        var vault = new ZeroBloatVaultService(Path.Combine(_sandboxDir, "VaultHosts"), stateApplier: applier);
        var service = new SmartOptimizerService(vault, bridge);

        // Попытка заблокировать домен безопасности или Windows Update отклоняется защитным фильтром
        var blocked = await service.AddHostsEntryAsync("0.0.0.0", "www.virustotal.com");
        Assert.False(blocked.Succeeded);

        // Обычный рекламный/телеметрийный домен добавляется и сохраняет бекап в Машину времени
        var added = await service.AddHostsEntryAsync("0.0.0.0", "ads.example-tracker.org");
        Assert.True(added.Succeeded);
        Assert.NotNull(added.RollbackSessionId);
        Assert.Single(service.InspectHostsFile(), e => e.DomainHost == "ads.example-tracker.org");

        await vault.RollbackTransactionAsync(added.RollbackSessionId!.Value);
        Assert.Single(applier.RestoredDeltas);
        Assert.Equal("HostsSabotageCleanup", applier.RestoredDeltas[0].TargetPath);
    }

    private sealed class FakeOptimizerBridge : DefaultOptimizerPlatformBridge
    {
        public string? CustomHostsPath { get; set; }
        public SystemFacts Facts { get; set; } = SystemFacts.Unknown;

        public override SystemFacts GetSystemFacts() => Facts;
        public Dictionary<string, (int Kind, string Val)> Store { get; } = new(StringComparer.OrdinalIgnoreCase);

        public override string GetHostsFilePath() => CustomHostsPath ?? base.GetHostsFilePath();

        public override bool IsRunningAsAdministrator() => true;

        public override (bool Exists, int ValueKindCode, string? SerializedValue) ReadRegistryValue(
            string hive,
            string subKeyPath,
            string valueName)
        {
            var key = $@"{hive}\{subKeyPath}::{valueName}";
            return Store.TryGetValue(key, out var item)
                ? (true, item.Kind, item.Val)
                : (false, 1, null);
        }

        public override bool WriteRegistryValue(
            string hive,
            string subKeyPath,
            string valueName,
            RegistryTweakValueKind kind,
            string serializedValue)
        {
            var key = $@"{hive}\{subKeyPath}::{valueName}";
            if (kind == RegistryTweakValueKind.DeleteValue)
            {
                Store.Remove(key);
                return true;
            }

            Store[key] = ((int)kind, serializedValue);
            return true;
        }

        public override Task<bool> TryPoliteCloseProcessAsync(int processId, CancellationToken ct = default) =>
            Task.FromResult(processId == 4512);
    }

    private sealed class RecordingStateApplier : ISystemStateApplier
    {
        public List<StateDeltaRecord> RestoredDeltas { get; } = [];

        public Task ApplyRollbackDeltaAsync(
            StateDeltaRecord delta,
            Func<string, CancellationToken, Task<byte[]>> restoreBlobBytesAsync,
            CancellationToken ct = default)
        {
            RestoredDeltas.Add(delta);
            return Task.CompletedTask;
        }
    }
}
