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
        if (Directory.Exists(_sandboxDir))
        {
            Directory.Delete(_sandboxDir, recursive: true);
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

    private sealed class FakeOptimizerBridge : DefaultOptimizerPlatformBridge
    {
        public Dictionary<string, (int Kind, string Val)> Store { get; } = new(StringComparer.OrdinalIgnoreCase);

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
