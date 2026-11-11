using System.IO;
using System.Windows;
using System.Windows.Controls;
using UltimateWindows.App.Infrastructure;
using UltimateWindows.App.ViewModels;
using UltimateWindows.App.Views;
using UltimateWindows.Modules.Optimizer.Models;
using UltimateWindows.Modules.Optimizer.Services;
using UltimateWindows.Modules.Safety.Services;
using Xunit;

namespace UltimateWindows.WindowsTests;

/// <summary>
/// Раздел «Оптимизатор» целиком: каждая вкладка создаётся, раскладывается и связывается с данными
/// без ошибок разметки и привязок, а основные действия через интерфейс доходят до «системы».
/// Система — образец в памяти, настоящая Windows не затрагивается.
/// </summary>
[Collection("Windows")]
public sealed class OptimizerUiSmokeTests : IDisposable
{
    private const double ViewWidth = 1132;
    private const double ViewHeight = 770;
    private static readonly TimeSpan ActionTimeout = TimeSpan.FromSeconds(30);

    private readonly string _workDirectory;

    public OptimizerUiSmokeTests()
    {
        _workDirectory = Path.Combine(Path.GetTempPath(), $"uw_ui_tests_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_workDirectory);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_workDirectory, recursive: true);
        }
        catch (Exception)
        {
            // Файл базы отката может быть ещё занят — временный каталог очистит система
        }
    }

    [Fact]
    public Task OptimizerWorkspace_ShowsEveryTab_AndActsOnTheSystem_WithoutMarkupOrBindingErrors() => WpfHost.RunAsync(async () =>
    {
        // В проверке никто не ответит на вопрос в окне — на любой вопрос отвечаем «нет»
        var previousConfirm = UserPrompts.Confirm;
        UserPrompts.Confirm = _ => false;
        using var trace = BindingErrorTrace.Start();
        var realWindow = false;
        var reached = "начало";
        try
        {
            var bridge = new SampleOptimizerBridge(_workDirectory);
            var vault = new ZeroBloatVaultService(Path.Combine(_workDirectory, "vault"));
            var service = new SmartOptimizerService(vault, bridge);

            // Несколько настроек уже включены — так видны все состояния строк
            var preApplied = new[] { "privacy.disable-advertising-id", "explorer.show-file-extensions", "ads.disable-tips", "svc.disable-fax" };
            foreach (var id in preApplied)
            {
                var applied = await service.SetTweakStateAsync(id, enableTweak: true);
                Assert.True(applied.Succeeded, $"{id}: {applied.UserFriendlyMessage} {applied.TechnicalDetails}");
            }

            var completedActions = new List<string>();
            var studio = new OptimizerStudioViewModel(service, message =>
            {
                completedActions.Add(message);
                return Task.CompletedTask;
            });

            await studio.RefreshAllAsync();

            var view = new OptimizerWorkspaceView { DataContext = studio };
            using var surface = UiSurface.Show(view, ViewWidth, ViewHeight);
            await surface.SettleAsync();
            realWindow = surface.IsRealWindow;

            // ---------- Настройки Windows ----------
            reached = "настройки Windows";
            var tweaks = studio.Tweaks;
            Assert.True(tweaks.AllTweaks.Count >= 150);
            Assert.True(tweaks.HasVisibleTweaks);
            Assert.All(preApplied, id => Assert.Equal(TweakStateKind.Applied, tweaks.AllTweaks.Single(t => t.TweakId == id).State));
            Assert.True(tweaks.ActiveTweaksCount >= preApplied.Length);
            Assert.True(surface.CountShown<CheckBox>() > 20, "строки настроек с переключателями не построились");
            surface.Save("optimizer-tweaks");

            // Задание, отключённое до нас, даёт настройке состояние «частично»
            Assert.Equal(TweakStateKind.Partial, tweaks.AllTweaks.Single(t => t.TweakId == "privacy.disable-ceip-tasks").State);

            // Опасные настройки скрыты, пока их не попросили показать
            Assert.DoesNotContain(VisibleTweaks(tweaks), t => t.IsDangerous);
            tweaks.ShowDangerous = true;
            Assert.Contains(VisibleTweaks(tweaks), t => t.IsDangerous);
            tweaks.ShowDangerous = false;

            // Настройки для программ, которых нет на компьютере, скрыты; для установленных — видны
            Assert.DoesNotContain(VisibleTweaks(tweaks), t => t.TweakId == "app.firefox-no-telemetry");
            Assert.Contains(VisibleTweaks(tweaks), t => t.TweakId == "app.chrome-no-telemetry");

            // Поиск и раздел
            reached = "поиск и разделы";
            tweaks.SearchText = "Copilot";
            await surface.SettleAsync();
            Assert.InRange(VisibleTweaks(tweaks).Count, 1, 20);
            tweaks.SearchText = "такой настройки точно нет";
            await surface.SettleAsync();
            Assert.True(tweaks.HasNoVisibleTweaks);
            tweaks.SearchText = "";

            var privacy = tweaks.Categories.Single(c => c.Category == TweakCategory.Privacy);
            tweaks.SelectedCategory = privacy;
            await surface.SettleAsync();
            Assert.All(VisibleTweaks(tweaks), t => Assert.Equal(TweakCategory.Privacy, t.Category));

            // Переключатель в строке включает настройку и пишет точку отката
            reached = "переключатель настройки";
            var telemetry = tweaks.AllTweaks.Single(t => t.TweakId == "privacy.disable-telemetry-services");
            telemetry.IsExpanded = true;
            telemetry.IsApplied = true;
            Assert.True(await WpfHost.WaitUntilAsync(() => !telemetry.IsBusy, ActionTimeout));
            Assert.Equal(TweakStateKind.Applied, telemetry.State);
            Assert.Equal(ServiceStartupMode.Disabled, bridge.StartupOf("DiagTrack"));
            Assert.Equal(ServiceStartupMode.Disabled, bridge.StartupOf("dmwappushservice"));
            Assert.Equal(2, telemetry.Details.Count);
            Assert.Single(completedActions);
            await surface.SettleAsync();
            surface.Save("optimizer-tweaks-details");

            // Опасная настройка без согласия не включается, и переключатель возвращается назад
            reached = "опасная настройка";
            tweaks.ShowDangerous = true;
            var smartScreen = tweaks.AllTweaks.Single(t => t.TweakId == "sec.disable-smartscreen");
            smartScreen.IsApplied = true;
            Assert.True(await WpfHost.WaitUntilAsync(() => !smartScreen.IsBusy, ActionTimeout));
            Assert.False(smartScreen.IsApplied);
            Assert.DoesNotContain(bridge.Values.Keys, k => k.Contains("EnableSmartScreen", StringComparison.OrdinalIgnoreCase));
            Assert.Single(completedActions);
            tweaks.ShowDangerous = false;
            tweaks.SelectedCategory = tweaks.Categories[0];

            // Предпросмотр набора: показывает список, применяет отмеченное одной записью
            reached = "предпросмотр набора";
            tweaks.OpenPresetPreview("recommended");
            await surface.SettleAsync();
            var preview = tweaks.Preview;
            Assert.NotNull(preview);
            Assert.True(preview.Items.Count >= 20);
            Assert.Contains(preview.Items, i => !i.IsSelectable && i.Tone == "Safe");   // уже включённые
            Assert.True(preview.SelectedCount > 10);
            surface.Save("optimizer-preset-preview");

            var selectedIds = preview.Items.Where(i => i.IsSelected).Select(i => i.TweakId).ToList();
            preview.ApplyCommand.Execute(null);
            Assert.True(await WpfHost.WaitUntilAsync(() => !tweaks.IsPreviewOpen && !tweaks.IsLoading, ActionTimeout));
            Assert.All(selectedIds, id => Assert.Equal(TweakStateKind.Applied, tweaks.AllTweaks.Single(t => t.TweakId == id).State));
            Assert.Equal(2, completedActions.Count);
            Assert.True(studio.HasActionStatusBanner);
            await surface.SettleAsync();
            surface.Save("optimizer-tweaks-after-preset");

            // ---------- Службы ----------
            reached = "службы";
            studio.SelectedSubTabIndex = 1;
            Assert.True(await WpfHost.WaitUntilAsync(() => studio.Services.Items.Count > 0 && !studio.Services.IsLoading, ActionTimeout));
            await surface.SettleAsync();
            Assert.Equal(16, studio.Services.Items.Count);
            Assert.True(surface.CountShown<DataGridRow>() >= 5, "строки таблицы служб не построились");
            Assert.True(surface.CountShown<ComboBox>() >= 5, "списки типа запуска не построились");
            surface.Save("optimizer-services");

            var adobe = studio.Services.Items.Single(s => s.ServiceName == "AdobeARMservice");
            Assert.False(adobe.IsMicrosoft);
            adobe.SelectedStartup = ServiceStartupMode.Manual;
            Assert.True(await WpfHost.WaitUntilAsync(() => !adobe.IsBusy, ActionTimeout));
            Assert.Equal(ServiceStartupMode.Manual, bridge.StartupOf("AdobeARMservice"));
            Assert.Equal(ServiceStartupMode.Manual, adobe.SelectedStartup);

            // Жизненно важная служба закрыта для изменений, служба защиты требует согласия (ответ «нет»)
            var rpc = studio.Services.Items.Single(s => s.ServiceName == "RpcSs");
            Assert.True(rpc.IsLocked);
            Assert.False(rpc.CanChange);
            var defender = studio.Services.Items.Single(s => s.ServiceName == "WinDefend");
            defender.SelectedStartup = ServiceStartupMode.Disabled;
            Assert.True(await WpfHost.WaitUntilAsync(() => !defender.IsBusy, ActionTimeout));
            Assert.Equal(ServiceStartupMode.Automatic, bridge.StartupOf("WinDefend"));
            Assert.Equal(ServiceStartupMode.Automatic, defender.SelectedStartup);

            studio.Services.FilterMode = 1;
            await surface.SettleAsync();
            Assert.Equal(4, studio.Services.View.Cast<object>().Count());
            studio.Services.FilterMode = 0;

            // ---------- Планировщик ----------
            reached = "планировщик";
            studio.SelectedSubTabIndex = 2;
            Assert.True(await WpfHost.WaitUntilAsync(() => studio.Tasks.Items.Count > 0 && !studio.Tasks.IsLoading, ActionTimeout));
            await surface.SettleAsync();
            Assert.Equal(12, studio.Tasks.Items.Count);
            Assert.True(surface.CountShown<DataGridRow>() >= 5, "строки таблицы заданий не построились");
            surface.Save("optimizer-tasks");

            const string googleTask = @"\GoogleUpdaterTaskSystem140.0.7273.0{9B5B0A31-2B63-4B8A-9A0C-2C7E5F3B6A11}";
            var updater = studio.Tasks.Items.Single(t => t.TaskPath == googleTask);
            updater.IsEnabled = false;
            Assert.True(await WpfHost.WaitUntilAsync(() => !updater.IsBusy, ActionTimeout));
            Assert.False(bridge.TaskEnabled(googleTask));
            Assert.True(studio.Tasks.Items.Single(t => t.TaskPath.Contains("SoftwareProtectionPlatform")).IsLocked);

            // ---------- Автозагрузка, приложения, сеть, инструменты ----------
            reached = "автозагрузка";
            studio.SelectedSubTabIndex = 3;
            await surface.SettleAsync();
            Assert.Equal(5, studio.StartupEntries.Count);
            Assert.True(surface.CountShown<DataGridRow>() >= 3, "строки автозагрузки не построились");
            surface.Save("optimizer-startup");

            reached = "приложения";
            studio.SelectedSubTabIndex = 4;
            await surface.SettleAsync();
            Assert.Equal(6, studio.FilteredInstalledApps.Count);
            surface.Save("optimizer-apps-programs");
            studio.AppsMode = 1;
            Assert.True(await WpfHost.WaitUntilAsync(() => studio.UwpPackages.Count > 0 && !studio.IsLoadingUwp, ActionTimeout));
            await surface.SettleAsync();
            surface.Save("optimizer-apps-windows");

            reached = "сеть";
            studio.SelectedSubTabIndex = 5;
            await surface.SettleAsync();
            Assert.InRange(studio.HostsEntries.Count, 3, 4);
            surface.Save("optimizer-network");

            reached = "инструменты";
            studio.SelectedSubTabIndex = 6;
            await surface.SettleAsync();
            Assert.Equal(3, studio.ShellExtensions.Count);
            surface.Save("optimizer-tools");

            // ---------- Светлая тема ----------
            reached = "светлая тема";
            studio.SelectedSubTabIndex = 0;
            SwitchTheme("FluentLightTheme");
            try
            {
                await surface.SettleAsync();
                surface.Save("optimizer-tweaks-light");
                tweaks.OpenPresetPreview("privacy");
                await surface.SettleAsync();
                surface.Save("optimizer-preset-preview-light");
                tweaks.Preview!.CancelCommand.Execute(null);
                Assert.False(tweaks.IsPreviewOpen);
                studio.SelectedSubTabIndex = 1;
                await surface.SettleAsync();
                surface.Save("optimizer-services-light");
            }
            finally
            {
                SwitchTheme("FluentDarkTheme");
            }

            await surface.SettleAsync();
            reached = "конец";
        }
        finally
        {
            UserPrompts.Confirm = previousConfirm;
            TestEnvironment.WriteReport(
                "ui-optimizer",
                new[] { $"окно: {(realWindow ? "настоящее" : "раскладка без окна")}; пройдено до: {reached}; ошибок привязки: {trace.Errors.Count}; предупреждений: {trace.Warnings.Count}" }
                    .Concat(trace.Errors.Distinct().Take(12).Select(e => "E " + e))
                    .Concat(trace.Warnings.Distinct().Take(4).Select(w => "W " + w)));
        }

        Assert.True(trace.Errors.Count == 0, "Ошибки привязки данных:\n" + string.Join("\n", trace.Errors.Distinct().Take(15)));
    });

    private static List<TweakItemViewModel> VisibleTweaks(TweakCatalogViewModel tweaks) =>
        tweaks.VisibleTweaks.Cast<TweakItemViewModel>().ToList();

    private static void SwitchTheme(string themeName)
    {
        var dictionaries = Application.Current.Resources.MergedDictionaries;
        dictionaries[0] = new ResourceDictionary
        {
            Source = new Uri($"/UltimateWindows;component/Themes/{themeName}.xaml", UriKind.Relative)
        };
    }
}
