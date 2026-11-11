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
