using System.IO;
using UltimateWindows.App;
using UltimateWindows.App.ViewModels;
using UltimateWindows.Core.Enums;
using Xunit;

namespace UltimateWindows.WindowsTests;

/// <summary>
/// Программа целиком на настоящей системе: главное окно открывается, каждый раздел показывается,
/// Оптимизатор читает настоящие настройки, службы и задания. Ничего не меняет, только читает.
/// Выполняется на сборочной машине: на компьютере разработчика окно программы открывать незачем.
/// </summary>
[Collection("Windows")]
public sealed class MainWindowSmokeTests
{
    [Fact]
    public Task MainWindow_Opens_ShowsEverySection_AndReadsTheRealSystem() => WpfHost.RunAsync(async () =>
    {
        if (!TestEnvironment.IsDisposableBuildMachine)
        {
            return;
        }

        using var trace = BindingErrorTrace.Start();
        var notes = new List<string>();
        var reached = "начало";
        try
        {
            var window = new MainWindow();
            using var surface = UiSurface.Show(window, 1360, 840);
            var main = Assert.IsType<MainViewModel>(window.DataContext);
            await surface.SettleAsync();

            reached = "чтение настроек Windows";
            var studio = main.OptimizerStudio;
            var tweaks = studio.Tweaks;
            Assert.True(
                await WpfHost.WaitUntilAsync(() => tweaks.AllTweaks.Count > 0 && !tweaks.IsLoading, TimeSpan.FromSeconds(120)),
                "Список настроек Windows не загрузился с настоящей системы.");
            notes.Add($"настроек: {tweaks.AllTweaks.Count}, включено: {tweaks.ActiveTweaksCount}; {tweaks.SummaryText}");

            reached = "разделы";
            foreach (var domain in Enum.GetValues<SystemDomain>())
            {
                main.SelectedDomain = domain;
                await surface.SettleAsync();
                surface.Save("main-" + domain);
            }

            reached = "оптимизатор: службы";
            main.SelectedDomain = SystemDomain.Optimizer;
            studio.SelectedSubTabIndex = 1;
            Assert.True(
                await WpfHost.WaitUntilAsync(() => studio.Services.Items.Count > 0 && !studio.Services.IsLoading, TimeSpan.FromSeconds(120)),
                "Список служб не загрузился с настоящей системы. " + studio.ActionStatusBanner);
            await surface.SettleAsync();
            surface.Save("main-services");
            notes.Add($"служб: {studio.Services.Items.Count}, сторонних: {studio.Services.Items.Count(s => !s.IsMicrosoft)}, закрытых от изменений: {studio.Services.Items.Count(s => s.IsLocked)}");

            reached = "оптимизатор: планировщик";
            studio.SelectedSubTabIndex = 2;
            Assert.True(
                await WpfHost.WaitUntilAsync(() => studio.Tasks.Items.Count > 0 && !studio.Tasks.IsLoading, TimeSpan.FromSeconds(120)),
                "Список заданий не загрузился с настоящей системы. " + studio.ActionStatusBanner);
            await surface.SettleAsync();
            surface.Save("main-tasks");
            notes.Add($"заданий: {studio.Tasks.Items.Count}, сторонних: {studio.Tasks.Items.Count(t => !t.IsMicrosoft)}, отключённых: {studio.Tasks.Items.Count(t => !t.IsEnabled)}");

            reached = "оптимизатор: остальные вкладки";
            for (var tab = 3; tab <= 6; tab++)
            {
                studio.SelectedSubTabIndex = tab;
                await surface.SettleAsync();
            }

            notes.Add($"автозагрузка: {studio.StartupEntries.Count}, программ: {studio.FilteredInstalledApps.Count}, расширений меню: {studio.ShellExtensions.Count}");
            studio.SelectedSubTabIndex = 0;
            await surface.SettleAsync();

            reached = "очистка 2.0: все вкладки и каталог программ";
            main.SelectedDomain = SystemDomain.SmartCleaner;
            var cleanerVm = main.CleanerStudio;
            await cleanerVm.RefreshSystemReservesAsync();
            for (var ctab = 0; ctab <= 4; ctab++)
            {
                cleanerVm.SelectedSubTabIndex = ctab;
                await surface.SettleAsync();
                surface.Save($"cleaner-tab-{ctab}");
            }

            cleanerVm.SelectedSubTabIndex = 4;
            await cleanerVm.ScanAppRulesAsync();
            await surface.SettleAsync();
            surface.Save("cleaner-app-rules");

            // Быстрая проверка прямого чтения NTFS $MFT на настоящем системном томе C:\
            cleanerVm.SelectedSubTabIndex = 0;
            cleanerVm.DiskMapTargetPath = Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\";
            await cleanerVm.AnalyzeDiskSpaceAsync();
            await surface.SettleAsync();
            surface.Save("cleaner-mft-disk");
            notes.Add($"очистка-каталог: {cleanerVm.AppRulesStatusText}");
            notes.Add($"карта-диска: {cleanerVm.DiskMapStatusText}");

            reached = "ремонт 2.0: все 5 вкладок и живая диагностика ОС";
            main.SelectedDomain = SystemDomain.DllAndRepair;
            var repairVm = main.RepairStudio;
            await repairVm.ScanDiagnosticsAsync();
            await repairVm.RefreshRuntimeStatusesAsync();
            await repairVm.ScanBsodAndCrashLogsAsync();
            repairVm.RunExecutableDiagnosis();

            // Проверка на минимальном разрешении 1024×768 без обрезки вкладок и кнопок
            window.Width = 1024;
            window.Height = 768;
            repairVm.SelectedSubTabIndex = 0;
            await surface.SettleAsync();
            surface.Save("repair-tab-0-1024");

            window.Width = 1360;
            window.Height = 840;
            for (var rtab = 0; rtab <= 4; rtab++)
            {
                repairVm.SelectedSubTabIndex = rtab;
                if (rtab == 3)
                {
                    repairVm.ErrorSearchQuery = "0x80070005";
                }

                await surface.SettleAsync();
                surface.Save($"repair-tab-{rtab}");
            }

            Assert.Empty(trace.Errors);
            notes.Add($"ремонт-диагностика: {repairVm.DiagnosticsSummaryText}");
            notes.Add($"ремонт-пакеты: {repairVm.RuntimeCatalogHeadline}");

            reached = "конец";
        }
        finally
        {
            TestEnvironment.WriteReport(
                "ui-main-window",
                new[] { $"пройдено до: {reached}; ошибок привязки: {trace.Errors.Count}; предупреждений: {trace.Warnings.Count}" }
                    .Concat(notes)
                    .Concat(trace.Errors.Distinct().Take(8).Select(e => "E " + e)));
        }
    });
}
