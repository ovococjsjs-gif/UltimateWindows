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
        bridge.Services["SysMain"] = ServiceStartupMode.Automatic;
        var vault = new ZeroBloatVaultService(Path.Combine(_sandboxDir, "VaultFacts"));
        var service = new SmartOptimizerService(vault, bridge);

        var states = service.EvaluateAllTweaks();
        Assert.Equal(
            TweakApplicabilityStatus.NotApplicable,
            states.Single(s => s.Rule.TweakId == "explorer.classic-context-menu").Applicability.Status);
        Assert.Equal(
            TweakApplicabilityStatus.NotRecommended,
            states.Single(s => s.Rule.TweakId == "disk.disable-sysmain").Applicability.Status);
        Assert.Equal(
            TweakApplicabilityStatus.NotRecommended,
            states.Single(s => s.Rule.TweakId == "disk.disable-hibernation").Applicability.Status);
        Assert.True(states.Single(s => s.Rule.TweakId == "explorer.menu-delay").Applicability.IsApplicable);

        // Твик только для Windows 11 нельзя включить на Windows 10 даже с явным согласием
        var notApplicable = await service.SetTweakStateAsync(
            "explorer.classic-context-menu", enableTweak: true, options: TweakApplyOptions.AcceptAll);
        Assert.False(notApplicable.Succeeded);
        Assert.Equal(TweakConfirmationKind.None, notApplicable.ConfirmationRequired);
        Assert.Empty(bridge.Store);

        // Не рекомендуемый твик без согласия не применяется и просит подтверждение
        var needsConsent = await service.SetTweakStateAsync("disk.disable-sysmain", enableTweak: true);
        Assert.False(needsConsent.Succeeded);
        Assert.Equal(TweakConfirmationKind.NotRecommendedForThisPc, needsConsent.ConfirmationRequired);
        Assert.Contains("HDD", needsConsent.UserFriendlyMessage);
        Assert.Equal(ServiceStartupMode.Automatic, bridge.Services["SysMain"]);

        // С явным согласием пользователя твик применяется
        var consented = await service.SetTweakStateAsync(
            "disk.disable-sysmain", enableTweak: true, options: new TweakApplyOptions(AcceptNotRecommended: true));
        Assert.True(consented.Succeeded);
        Assert.Equal(ServiceStartupMode.Disabled, bridge.Services["SysMain"]);
        Assert.Equal(TweakRestartKind.Reboot, consented.RestartRequired);

        // Возврат к стандарту Windows разрешён всегда и подтверждений не требует
        var restored = await service.SetTweakStateAsync("disk.disable-sysmain", enableTweak: false);
        Assert.True(restored.Succeeded);
        Assert.Equal(ServiceStartupMode.Automatic, bridge.Services["SysMain"]);
    }

    [Fact]
    public void BuiltInCatalog_HasNoDangerousRulesInPresets_AndRestoresCorrectWindowsDefaults()
    {
        var rules = DeclarativeTweakCatalog.GetAllRules();

        // Идентификаторы уникальны
        Assert.Equal(rules.Count, rules.Select(r => r.TweakId).Distinct(StringComparer.OrdinalIgnoreCase).Count());

        // В готовые наборы попадают только настройки без оговорок: риск Safe или Low
        var presets = DeclarativeTweakCatalog.GetPresets();
        Assert.Equal(new[] { "recommended", "privacy", "gaming", "clean-ui" }, presets.Select(p => p.Key).ToArray());
        foreach (var preset in presets)
        {
            Assert.False(string.IsNullOrWhiteSpace(preset.Title));
            Assert.False(string.IsNullOrWhiteSpace(preset.Description));
            foreach (var id in preset.TweakIds)
            {
                var rule = DeclarativeTweakCatalog.FindById(id);
                Assert.NotNull(rule);
                Assert.False(rule.IsDangerous);
                Assert.True(rule.Risk <= RiskLevel.Low, $"{id} в наборе «{preset.Key}» имеет риск {rule.Risk}");
            }
        }

        // Набор «Рекомендуемый» не трогает ничего с побочным эффектом
        Assert.All(
            DeclarativeTweakCatalog.GetPresetIds("recommended"),
            id => Assert.Equal(RiskLevel.Safe, DeclarativeTweakCatalog.FindById(id)!.Risk));

        // Стандартный порог разделения svchost в Windows — 0x380000 КБ
        var svchost = DeclarativeTweakCatalog.FindById("perf.svchost-split");
        Assert.NotNull(svchost);
        Assert.Equal("3670016", svchost.Mutations[0].DefaultRestoreSerializedValue);

        // Права администратора выводятся из действий: куст пользователя их не требует, политики и службы — требуют
        Assert.False(DeclarativeTweakCatalog.FindById("explorer.show-file-extensions")!.RequiresAdministrator);
        Assert.True(DeclarativeTweakCatalog.FindById("ads.disable-bing-in-start")!.RequiresAdministrator);
        Assert.True(DeclarativeTweakCatalog.FindById("privacy.disable-telemetry-services")!.RequiresAdministrator);
    }

    private static DeclarativeTweakRule BuildTestRule(string id, RiskLevel risk, TweakAction action) =>
        new(
            id,
            TweakCategory.Security,
            "Тестовое правило",
            "Правило только для проверки защитного фильтра.",
            risk,
            [action]);

    [Fact]
    public async Task SmartOptimizerService_TogglesTweaks_ExportsImportsYaml_AndRecordsVaultRollback()
    {
        var bridge1 = new FakeOptimizerBridge();
        bridge1.Store[@"HKCU\Control Panel\Desktop::MenuShowDelay"] = ((int)RegistryTweakValueKind.String, "400");

        var applier = new RecordingStateApplier();
        var vault1 = new ZeroBloatVaultService(Path.Combine(_sandboxDir, "Vault1"), stateApplier: applier);
        var service1 = new SmartOptimizerService(vault1, bridge1);

        var enableRes = await service1.SetTweakStateAsync("explorer.menu-delay", enableTweak: true);
        Assert.True(enableRes.Succeeded);
        Assert.NotNull(enableRes.RollbackSessionId);
        Assert.Equal("100", bridge1.Store[@"HKCU\Control Panel\Desktop::MenuShowDelay"].Val);

        // Проверяем экспорт активных настроек в декларативный YAML и импорт на второй чистой машине
        var yaml = service1.ExportActiveTweaksToYaml("Киберспорт и скорость");
        Assert.Contains("explorer.menu-delay", yaml);

        var bridge2 = new FakeOptimizerBridge();
        var vault2 = new ZeroBloatVaultService(Path.Combine(_sandboxDir, "Vault2"));
        var service2 = new SmartOptimizerService(vault2, bridge2);

        var importRes = await service2.ImportAndApplyYamlProfileAsync(yaml);
        Assert.True(importRes.Succeeded);
        Assert.Equal("100", bridge2.Store[@"HKCU\Control Panel\Desktop::MenuShowDelay"].Val);

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
        Assert.True(rules.Count >= 150);
        foreach (var category in TweakCategoryInfo.DisplayOrder)
        {
            Assert.Contains(rules, r => r.Category == category);
        }

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
