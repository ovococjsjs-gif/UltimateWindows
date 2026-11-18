using System.IO;
using System.Windows.Controls;
using Microsoft.Win32;
using UltimateWindows.App.ViewModels;
using UltimateWindows.App.Views;
using UltimateWindows.Core.Models;
using UltimateWindows.Modules.Safety.Services;
using UltimateWindows.Modules.Security.Models;
using UltimateWindows.Modules.Security.Services;
using UltimateWindows.NativeInterop.Restore;
using UltimateWindows.NativeInterop.SecurityHunter;
using Xunit;

namespace UltimateWindows.WindowsTests;

// Не использовать системные политики или настоящий автозапуск: для теста достаточно временных значений HKCU.
[Collection("Windows")]
public sealed class SecurityJournalIntegrationTests : IDisposable
{
    private readonly string _key = @"Software\UW-Review-" + Guid.NewGuid().ToString("N");
    private readonly DirectoryInfo _dir = Directory.CreateTempSubdirectory("uw-security-");
    private ZeroBloatVaultService OpenVault() => new(_dir.FullName, new WindowsSystemStateApplier());
    private AntiMinerSecurityService OpenService() => new(OpenVault(), new WindowsSecurityPlatformBridge());

    [Fact]
    public Task NativePartialBatchSurvivesReopenAndRefusesConflictingUndo() => WpfHost.RunAsync(async () =>
    {
        byte[] original = [0, 255, 41, 13];
        using var key = Registry.CurrentUser.CreateSubKey(_key);
        key.SetValue("A", original); key.SetValue("B", "before");
        OsSabotageFinding Review(string name, string value, string label) => new(OsSabotageKind.RegistryEditorDisabledByPolicy,
            $@"HKCU\{_key}::{name}", "HKCU", _key, name, value, label, "Тестовый объект");
        var a = Review("A", Convert.ToBase64String(original), "Настройка A");
        var b = Review("B", "before", "Настройка B");
        // Оба снимка A создаются до первого удаления; на втором шаге проверенное значение уже отсутствует.
        var r = await OpenService().HealAllSabotageLocksAsync([a, a with { SimpleTitle = "Повторная проверка A" }, b]);
        Assert.False(r.Succeeded); Assert.Equal(1, r.FixedItemsCount);
        var id = Assert.IsType<Guid>(r.RollbackSessionId); Assert.Equal(id, r.JournalSessionId);
        Assert.Null(key.GetValue("A")); Assert.Equal("before", key.GetValue("B"));

        var saved = Assert.Single(await OpenVault().GetHistoryAsync());
        Assert.Equal(new[] { StepState.Applied, StepState.Unconfirmed, StepState.Planned }, saved.Deltas.Select(d => d.Step!.State));
        Assert.Single(saved.RestorableDeltas); Assert.Contains("доступен откат", saved.StepSummary);
        using var trace = BindingErrorTrace.Start();
        var service = OpenService();
        var vm = new AntiMinerStudioViewModel(service, _ => Task.CompletedTask) { SelectedSubTabIndex = 4 };
        await vm.RefreshQuarantineHistoryAsync();
        var row = Assert.Single(vm.QuarantineHistory);
        Assert.Equal("Частично · 1/3", row.StatusBadge); Assert.True(row.CanRestore); Assert.Empty(row.Entry.QuarantinedPaths);
        var view = new SecurityWorkspaceView { DataContext = vm };
        using (var surface = UiSurface.Show(view, 990, 370))
        {
            var grid = Assert.IsType<DataGrid>(view.FindName("QuarantineGrid"));
            grid.SelectedItem = row;
            await surface.SettleAsync();
            surface.Save("security-partial");
        }
        Assert.Empty(trace.Errors);

        key.SetValue("A", "new owner"); key.SetValue("B", "new setting");
        var refused = await service.RestoreFromQuarantineAsync(id);
        Assert.False(refused.Succeeded); Assert.False(Assert.Single(await OpenVault().GetHistoryAsync()).IsReverted);
        Assert.Equal("new owner", key.GetValue("A"));
        key.DeleteValue("A");
        var undo = await OpenService().RestoreFromQuarantineAsync(id);
        Assert.True(undo.Succeeded, undo.UserFriendlyMessage); Assert.Equal(1, undo.FixedItemsCount);
        Assert.Equal(RegistryValueKind.Binary, key.GetValueKind("A")); Assert.Equal(original, Assert.IsType<byte[]>(key.GetValue("A")));
        Assert.Equal("new setting", key.GetValue("B")); Assert.True(Assert.Single(await OpenVault().GetHistoryAsync()).IsReverted);
    });

    [Fact]
    public async Task ReplacedValueMustStillMatchExpectedKindAndDataBeforeNativeRollback()
    {
        const string original = @"%TEMP%\fixture";
        using var key = Registry.CurrentUser.CreateSubKey(_key);
        key.SetValue("Setting", original, RegistryValueKind.ExpandString);
        var record = new PersistenceAnomalyRecord(ThreatDetectionVector.SuspiciousRegistryAutorun, $@"HKCU\{_key}",
            "Setting", original, null, false, original, RemediationKind: PersistenceRemediationKind.RestoreRegistryDefault,
            RemediationTarget: $"HKCU|{_key}|Setting|DWORD:3");
        var r = await OpenService().RemovePersistenceAnomalyAsync(record);
        Assert.True(r.Succeeded, r.UserFriendlyMessage); var id = Assert.IsType<Guid>(r.RollbackSessionId);
        Assert.Equal(3, key.GetValue("Setting"));
        key.SetValue("Setting", "3", RegistryValueKind.String);
        var vault = OpenVault();
        await Assert.ThrowsAsync<IOException>(() => vault.RollbackTransactionAsync(id));
        Assert.Equal("3", key.GetValue("Setting"));
        key.DeleteValue("Setting");
        await Assert.ThrowsAsync<IOException>(() => vault.RollbackTransactionAsync(id));
        Assert.Null(key.GetValue("Setting"));
        key.SetValue("Setting", 3);
        await vault.RollbackTransactionAsync(id);
        Assert.Equal(RegistryValueKind.ExpandString, key.GetValueKind("Setting"));
        Assert.Equal(original, key.GetValue("Setting", null, RegistryValueOptions.DoNotExpandEnvironmentNames));
    }

    public void Dispose() { Registry.CurrentUser.DeleteSubKeyTree(_key, false); _dir.Delete(true); }
}
