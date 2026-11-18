using System.IO;
using UltimateWindows.App.ViewModels;
using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Apps.Models;
using UltimateWindows.Modules.Cleaner.Scanners;
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
            await File.WriteAllTextAsync(small, "original settings");
            using (var stream = File.Create(big)) stream.SetLength(24L * 1024 * 1024 + 1);
            var vault = new ZeroBloatVaultService(Path.Combine(dir.FullName, "history"));
            var result = await new WindowsAppsPlatformBridge().QuarantineAndRemoveLeftoversAsync("SampleApp", null,
                [new AppLeftoverItem(AppLeftoverKind.InstallDirectoryResidue, source.FullName, "test", 0)], vault);
            Assert.False(result.Succeeded); // partial, not unconditional success
            Assert.Equal(1, result.RemovedFileLeftovers);
            Assert.False(File.Exists(small));
            Assert.True(File.Exists(big));
            Assert.True(Directory.Exists(source.FullName));
            Assert.NotNull(result.SessionId);
            await vault.RollbackTransactionAsync(result.SessionId.Value);
            Assert.Equal("original settings", await File.ReadAllTextAsync(small));
        }
        finally { dir.Delete(true); }
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
            vm.CleanSystemTempAndShaders = false;
            Assert.False(vm.ExecuteSafeCleanCommand.CanExecute(null));
            Assert.Empty(vm.CandidateFilesPreview);
            await vm.ExecuteSafeCleanAsync();
            Assert.True(File.Exists(file));
        }
        finally { dir.Delete(true); }
    });
}
