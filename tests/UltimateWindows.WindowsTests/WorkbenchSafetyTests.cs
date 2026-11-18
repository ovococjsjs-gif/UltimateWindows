using System.IO;
using Microsoft.Win32;
using UltimateWindows.NativeInterop.Restore;
using UltimateWindows.App.ViewModels;
using UltimateWindows.App.Views;
using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Apps.Models;
using UltimateWindows.Modules.Cleaner.Scanners;
using UltimateWindows.Modules.Cleaner.Models;
using UltimateWindows.NativeInterop.Cleaner;
using UltimateWindows.Modules.Cleaner.Services;
using UltimateWindows.Modules.Safety.Services;
using UltimateWindows.NativeInterop.Apps;
using Xunit;

namespace UltimateWindows.WindowsTests;

[Collection("Windows")]
public sealed class WorkbenchSafetyTests
{
    [Theory]
    [InlineData("bsod", SystemDomain.DllAndRepair, 2)]
    [InlineData("Cookie", SystemDomain.SmartCleaner, 1)]
    [InlineData("DriverStore INF", SystemDomain.HardwareAndDrivers, 5)]
    public void SearchResolvesTheToolNotJustItsModule(string query, SystemDomain domain, int tab)
    {
        var finder = new ToolFinderViewModel { Query = query };
        var target = Assert.Single(finder.Results);
        Assert.Equal(domain, target.Domain);
        Assert.Equal(tab, target.Tab);
        finder.Query = "no-such-workspace";
        Assert.True(finder.IsEmpty);
    }

    [Fact]
    public async Task NativeLeftoverCleanup_KeepsOversizeFileAndItsFolder_AndRestoresSmallFile()
    {
        var dir = Directory.CreateTempSubdirectory("uw-leftovers-");
        try
        {
            var source = dir.CreateSubdirectory("SampleApp");
            var small = Path.Combine(source.FullName, "settings.ini");
            var big = Path.Combine(source.FullName, "large.bin");
            var bytes = new byte[] { 0, 255, 128, 1, 13, 0, 10 };
            var busy = Path.Combine(source.FullName, "busy.dat");
            using var locked = new FileStream(busy, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None);
            await File.WriteAllBytesAsync(small, bytes);
            using (var stream = File.Create(big)) stream.SetLength(24L * 1024 * 1024 + 1);
            var vault = new ZeroBloatVaultService(Path.Combine(dir.FullName, "history"));
            var result = await new WindowsAppsPlatformBridge().QuarantineAndRemoveLeftoversAsync("SampleApp", null,
                [new AppLeftoverItem(AppLeftoverKind.InstallDirectoryResidue, source.FullName, "test", 0)], vault);
            Assert.False(result.Succeeded); // partial, not unconditional success
            Assert.Equal(1, result.RemovedFileLeftovers);
            Assert.False(File.Exists(small));
            Assert.True(File.Exists(busy));
            Assert.True(File.Exists(big));
            Assert.True(Directory.Exists(source.FullName));
            Assert.NotNull(result.SessionId);
            await vault.RollbackTransactionAsync(result.SessionId.Value);
            Assert.Equal(bytes, await File.ReadAllBytesAsync(small));
        }
        finally { dir.Delete(true); }
    }

    [Fact]
    public async Task RegistryLeftoverRequiresCompleteExport_AndConflictingRestoreKeepsNewValues()
    {
        var subkey = @"Software\UWFixture-" + Guid.NewGuid().ToString("N");
        var fullKey = @"HKCU\" + subkey;
        var dir = Directory.CreateTempSubdirectory("uw-registry-fixture-");
        try
        {
            var vault = new ZeroBloatVaultService(dir.FullName, new WindowsSystemStateApplier());
            var bridge = new WindowsAppsPlatformBridge();
            Task<CleanUninstallResult> Remove() => bridge.QuarantineAndRemoveLeftoversAsync("Fixture", null,
                [new AppLeftoverItem(AppLeftoverKind.RegistrySubKey, fullKey, "test", 0)], vault);
            using (var key = Registry.CurrentUser.CreateSubKey(subkey)) key.SetValue("Payload", new byte[280_000]);
            var rejected = await Remove();
            Assert.False(rejected.Succeeded);
            Assert.Equal(0, rejected.RemovedRegistryLeftovers);
            using (var key = Registry.CurrentUser.OpenSubKey(subkey, true))
            {
                Assert.NotNull(key);
                Assert.Equal(280_000, Assert.IsType<byte[]>(key.GetValue("Payload")).Length);
                key.SetValue("Payload", "Исходное значение");
            }
            var removed = await Remove();
            Assert.True(removed.Succeeded, removed.SummaryMessage);
            Assert.Equal(1, removed.RemovedRegistryLeftovers);
            var id = Assert.IsType<Guid>(removed.SessionId);
            using (var key = Registry.CurrentUser.CreateSubKey(subkey)) key.SetValue("Payload", "Новое значение");
            await Assert.ThrowsAsync<IOException>(() => vault.RollbackTransactionAsync(id));
            using (var key = Registry.CurrentUser.OpenSubKey(subkey)) Assert.Equal("Новое значение", key?.GetValue("Payload"));
            Registry.CurrentUser.DeleteSubKeyTree(subkey);
            await vault.RollbackTransactionAsync(id);
            using (var key = Registry.CurrentUser.OpenSubKey(subkey)) Assert.Equal("Исходное значение", key?.GetValue("Payload"));
        }
        finally
        {
            Registry.CurrentUser.DeleteSubKeyTree(subkey, false);
            dir.Delete(true);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DeferredVaultDeletionSurvivesReopenAndRechecksReferences(bool reuse)
    {
        var dir = Directory.CreateTempSubdirectory("uw-retry-gc-");
        try
        {
            var vault = new ZeroBloatVaultService(Path.Combine(dir.FullName, "vault"));
            var source = Path.Combine(dir.FullName, "sample");
            await File.WriteAllTextAsync(source, "shared payload");
            await using var old = vault.BeginTransaction(SystemDomain.SmartCleaner, "Old", "Test");
            var hash = await old.BackupFileAsync(source);
            await old.CommitAsync();
            var path = Path.Combine(vault.VaultDirectory, "blobs", hash + ".uwq");
            using (File.OpenRead(path)) // denies DELETE sharing on Windows
            {
                await Assert.ThrowsAsync<IOException>(() => vault.PurgeAllUnpinnedBlobsAsync());
                Assert.True(Assert.Single(await vault.GetHistoryAsync()).HasExpiredFile);
            }
            var reopened = new ZeroBloatVaultService(vault.VaultDirectory);
            if (reuse)
            {
                await using var fresh = reopened.BeginTransaction(SystemDomain.SmartCleaner, "New", "Test");
                await fresh.BackupFileAsync(source);
                var saved = await fresh.CommitVerifiedBackupAsync();
                File.Delete(source);
                await reopened.RollbackTransactionAsync(saved.SessionId);
                Assert.Equal("shared payload", await File.ReadAllTextAsync(source));
            }
            else
            {
                Assert.Equal(1, await reopened.EnforceQuotaAndRetentionAsync());
                Assert.False(File.Exists(path));
            }
        }
        finally { dir.Delete(true); }
    }

    [Fact]
    public async Task RegistryOrphanRollbackOnlyRestoresConfirmedDeletesAndRefusesAConflictingValue()
    {
        var dir = Directory.CreateTempSubdirectory("uw-orphan-test-");
        var subkey = @"Software\UW-Orphan-" + Guid.NewGuid().ToString("N");
        try
        {
            var missing = Path.Combine(dir.FullName, "missing.exe");
            var vault = new ZeroBloatVaultService(dir.FullName, new WindowsSystemStateApplier());
            var service = new VaultSafeCleanerService(vault, new WindowsCleanerPlatformBridge());
            RegistryOrphanCandidate Plan(string name) => new(RegistryOrphanKind.BrokenAppPath, "HKCU", subkey, name,
                missing, missing, (int)RegistryValueKind.String, "fixture");
            using (var k = Registry.CurrentUser.CreateSubKey(subkey))
            {
                k.SetValue("Removed", missing);
                k.SetValue("Changed", missing + " --new");
                k.SetValue("DifferentKind", missing, RegistryValueKind.ExpandString);
            }
            var skipped = await service.FixSelectedRegistryOrphansAsync([Plan("DifferentKind"), Plan("Absent")]);
            Assert.Equal(0, skipped.FixedCount);
            Assert.Null(skipped.RollbackSessionId);
            Assert.True(Assert.Single(await vault.GetHistoryAsync()).IsJournalOnly);
            var result = await service.FixSelectedRegistryOrphansAsync([Plan("Removed"), Plan("Changed"), Plan("DifferentKind"), Plan("Absent")]);
            Assert.Equal(1, result.FixedCount);
            var id = Assert.IsType<Guid>(result.RollbackSessionId);
            var saved = (await vault.GetHistoryAsync()).Single(r => r.SessionId == id);
            Assert.Single(saved.Deltas, d => !d.IsJournalOnly);
            using (var k = Registry.CurrentUser.OpenSubKey(subkey, true)!)
            {
                Assert.Null(k.GetValue("Removed"));
                Assert.Equal(missing + " --new", k.GetValue("Changed"));
                Assert.Equal(RegistryValueKind.ExpandString, k.GetValueKind("DifferentKind"));
                k.DeleteValue("Changed"); // unrelated change AFTER cleanup; rollback must not recreate this value
                k.SetValue("Removed", "new owner");
            }
            await Assert.ThrowsAsync<IOException>(() => vault.RollbackTransactionAsync(id));
            using (var k = Registry.CurrentUser.OpenSubKey(subkey, true)!)
            {
                Assert.Equal("new owner", k.GetValue("Removed"));
                k.DeleteValue("Removed");
            }
            await vault.RollbackTransactionAsync(id);
            using var restored = Registry.CurrentUser.OpenSubKey(subkey)!;
            Assert.Equal(missing, restored.GetValue("Removed"));
            Assert.Null(restored.GetValue("Changed"));
            Assert.Null(restored.GetValue("Absent"));
            Assert.Equal(RegistryValueKind.ExpandString, restored.GetValueKind("DifferentKind"));
        }
        finally { Registry.CurrentUser.DeleteSubKeyTree(subkey, false); dir.Delete(true); }
    }

    [Fact]
    public Task ChangingOptionsInvalidatesTheDisplayedCleanupPlan() => WpfHost.RunAsync(async () =>
    {
        var dir = Directory.CreateTempSubdirectory("uw-preview-");
        try
        {
            var source = dir.CreateSubdirectory("sample").FullName;
            var missing = Path.Combine(dir.FullName, "missing");
            var file = Path.Combine(source, "old.tmp");
            await File.WriteAllTextAsync(file, "fixture");
            File.SetLastWriteTimeUtc(file, DateTime.UtcNow.AddDays(-5));
            var svc = new VaultSafeCleanerService(new ZeroBloatVaultService(Path.Combine(dir.FullName, "vault")),
                systemJunkScanner: new SystemJunkScanner(new(source, missing, missing, missing, missing, missing)));
            var vm = new CleanerStudioViewModel(svc, _ => Task.CompletedTask) { CleanBrowserCaches = false };
            await vm.RunScanPreviewAsync();
            Assert.True(vm.CanExecuteClean);
            vm.SelectedSubTabIndex = 1;
            using (var surface = UiSurface.Show(new DiskAndCleanerWorkspaceView { DataContext = vm }, 960, 510))
            {
                await surface.SettleAsync();
                surface.Save("cleaner-plan");
            }
            vm.CleanSystemTempAndShaders = false;
            Assert.False(vm.ExecuteSafeCleanCommand.CanExecute(null));
            Assert.Empty(vm.CandidateFilesPreview);
            await vm.ExecuteSafeCleanAsync();
            Assert.True(File.Exists(file));
        }
        finally { dir.Delete(true); }
    });
}
