using System.Text.Json;
using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Optimizer.Models;
using UltimateWindows.Modules.Optimizer.Services;
using Xunit;

namespace UltimateWindows.UnitTests;

/// <summary>
/// Движок твиков: снять состояние → изменить → проверить → при сбое вернуть. Реестр, службы и задания — в памяти.
/// </summary>
public sealed class TweakEngineTests
{
    private const string MapsUpdateTask = @"\Microsoft\Windows\Maps\MapsUpdateTask";
    private const string MapsToastTask = @"\Microsoft\Windows\Maps\MapsToastTask";

    [Fact]
    public async Task ServiceAndTaskTweak_IsAppliedVerifiedAndRecordedForRollback_ThenRestoredToWindowsDefaults()
    {
        var bridge = new FakeOptimizerBridge();
        bridge.Services["MapsBroker"] = ServiceStartupMode.AutomaticDelayed;
        bridge.Tasks[MapsUpdateTask] = true;
        bridge.Tasks[MapsToastTask] = true;
        var vault = new InMemoryVault();
        var service = new SmartOptimizerService(vault, bridge);

        Assert.Equal(TweakStateKind.NotApplied, service.EvaluateTweak("svc.disable-maps")!.State);

        var enabled = await service.SetTweakStateAsync("svc.disable-maps", enableTweak: true);

        Assert.True(enabled.Succeeded);
        Assert.Equal(ServiceStartupMode.Disabled, bridge.Services["MapsBroker"]);
        Assert.False(bridge.Tasks[MapsUpdateTask]);
        Assert.False(bridge.Tasks[MapsToastTask]);
        Assert.Equal(TweakStateKind.Applied, service.EvaluateTweak("svc.disable-maps")!.State);

        // Отключённая служба останавливается сразу, не дожидаясь перезагрузки
        Assert.Contains("MapsBroker", bridge.StoppedServices);

        // В «Машине времени» — одна запись с прежним состоянием каждой цели
        var record = Assert.Single(vault.Records);
        Assert.Equal(enabled.RollbackSessionId, record.SessionId);
        Assert.Equal(3, record.Deltas.Count);

        var serviceDelta = Assert.Single(record.Deltas, d => d.TargetKind == StateTargetKind.WindowsService);
        Assert.Equal("MapsBroker", serviceDelta.TargetPath);
        using (var previous = JsonDocument.Parse(serviceDelta.PreviousStateJson!))
        {
            Assert.Equal("MapsBroker", previous.RootElement.GetProperty("ServiceName").GetString());
            Assert.Equal("AutomaticDelayed", previous.RootElement.GetProperty("Startup").GetString());
        }

        var taskDeltas = record.Deltas.Where(d => d.TargetKind == StateTargetKind.ScheduledTask).ToList();
        Assert.Equal(2, taskDeltas.Count);
        using (var previous = JsonDocument.Parse(taskDeltas[0].PreviousStateJson!))
        {
            Assert.Equal(MapsUpdateTask, previous.RootElement.GetProperty("TaskPath").GetString());
            Assert.True(previous.RootElement.GetProperty("Enabled").GetBoolean());
        }

        // Повторное включение ничего не меняет и не засоряет журнал
        var again = await service.SetTweakStateAsync("svc.disable-maps", enableTweak: true);
        Assert.True(again.Succeeded);
        Assert.Null(again.RollbackSessionId);
        Assert.Single(vault.Records);

        // Возврат к стандарту Windows
        var restored = await service.SetTweakStateAsync("svc.disable-maps", enableTweak: false);
        Assert.True(restored.Succeeded);
        Assert.Equal(ServiceStartupMode.AutomaticDelayed, bridge.Services["MapsBroker"]);
        Assert.True(bridge.Tasks[MapsUpdateTask]);
        Assert.True(bridge.Tasks[MapsToastTask]);
        Assert.Equal(2, vault.Records.Count);
    }

    [Fact]
    public async Task Tweak_IsAllOrNothing_WhenOneActionFails_AndTheFailureIsReportedHonestly()
    {
        var bridge = new FakeOptimizerBridge();
        foreach (var name in new[] { "XblAuthManager", "XblGameSave", "XboxNetApiSvc", "XboxGipSvc" })
        {
            bridge.Services[name] = ServiceStartupMode.Manual;
        }

        // Третью службу Windows менять не даёт
        bridge.AccessDenied.Add("XboxNetApiSvc");
        var vault = new InMemoryVault();
        var service = new SmartOptimizerService(vault, bridge);

        var result = await service.SetTweakStateAsync("svc.disable-xbox", enableTweak: true);

        Assert.False(result.Succeeded);
        Assert.Contains("XboxNetApiSvc", result.UserFriendlyMessage);
        Assert.Contains("отказано в доступе", result.UserFriendlyMessage);
        Assert.Contains("отменены", result.UserFriendlyMessage);

        // Две службы, которые успели отключиться, возвращены обратно; в журнале ничего нет
        Assert.All(bridge.Services.Values, startup => Assert.Equal(ServiceStartupMode.Manual, startup));
        Assert.Empty(vault.Records);
        Assert.Empty(bridge.StoppedServices);
        Assert.Equal(TweakStateKind.NotApplied, service.EvaluateTweak("svc.disable-xbox")!.State);
    }

    [Fact]
    public async Task Tweak_Fails_WhenWindowsAcceptsTheChangeButDoesNotKeepIt()
    {
        var bridge = new FakeOptimizerBridge();
        bridge.SilentlyIgnored.Add(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced::HideFileExt");
        var vault = new InMemoryVault();
        var service = new SmartOptimizerService(vault, bridge);

        var result = await service.SetTweakStateAsync("explorer.show-file-extensions", enableTweak: true);

        Assert.False(result.Succeeded);
        Assert.Contains("не сохранила изменение", result.UserFriendlyMessage);
        Assert.Empty(vault.Records);
    }

    [Fact]
    public async Task Tweak_SkipsTargetsMissingOnThisSystem_AndIsUnavailableWhenNothingExists()
    {
        var bridge = new FakeOptimizerBridge();
        bridge.Services["MapsBroker"] = ServiceStartupMode.AutomaticDelayed;
        var vault = new InMemoryVault();
        var service = new SmartOptimizerService(vault, bridge);

        // Служба есть, заданий нет: применяется то, что есть
        var maps = await service.SetTweakStateAsync("svc.disable-maps", enableTweak: true);
        Assert.True(maps.Succeeded);
        Assert.Contains("которых нет в этой системе: 2", maps.UserFriendlyMessage);
        var state = service.EvaluateTweak("svc.disable-maps")!;
        Assert.Equal(TweakStateKind.Applied, state.State);
        Assert.Equal(1, state.PresentActionCount);

        // Ни одной цели нет: твик помечен как неприменимый и включить его нельзя
        var fax = service.EvaluateTweak("svc.disable-fax")!;
        Assert.Equal(TweakStateKind.Unavailable, fax.State);
        Assert.Equal(TweakApplicabilityStatus.NotApplicable, fax.Applicability.Status);

        var refused = await service.SetTweakStateAsync("svc.disable-fax", enableTweak: true);
        Assert.False(refused.Succeeded);
        Assert.Single(vault.Records);
    }

    [Fact]
    public async Task PartialState_IsShownAsPartial_AndTurningTheTweakOnFinishesTheRest()
    {
        var bridge = new FakeOptimizerBridge();
        bridge.Services["SCardSvr"] = ServiceStartupMode.Disabled;
        bridge.Services["ScDeviceEnum"] = ServiceStartupMode.Manual;
        bridge.Services["SCPolicySvc"] = ServiceStartupMode.Manual;
        var vault = new InMemoryVault();
        var service = new SmartOptimizerService(vault, bridge);

        var before = service.EvaluateTweak("svc.disable-smart-cards")!;
        Assert.Equal(TweakStateKind.Partial, before.State);
        Assert.False(before.IsCurrentlyApplied);
        Assert.Equal(1, before.AppliedActionCount);
        Assert.Equal(3, before.PresentActionCount);

        var result = await service.SetTweakStateAsync("svc.disable-smart-cards", enableTweak: true);
        Assert.True(result.Succeeded);

        // В журнал попали только две службы, которые действительно изменились
        Assert.Equal(2, Assert.Single(vault.Records).Deltas.Count);
        Assert.Equal(TweakStateKind.Applied, service.EvaluateTweak("svc.disable-smart-cards")!.State);
    }

    [Fact]
    public async Task RegistryTweak_RemembersCreatedKeys_AndReturningToDefaultRemovesTheEmptyKey()
    {
        var bridge = new FakeOptimizerBridge { Facts = new SystemFacts(WindowsBuildNumber: 26100) };
        bridge.Keys.Add(@"HKCU\Software");
        bridge.Keys.Add(@"HKCU\Software\Classes");
        bridge.Keys.Add(@"HKCU\Software\Classes\CLSID");
        var vault = new InMemoryVault();
        var service = new SmartOptimizerService(vault, bridge);

        const string clsid = @"Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}";

        var enabled = await service.SetTweakStateAsync("explorer.classic-context-menu", enableTweak: true);
        Assert.True(enabled.Succeeded);
        Assert.Equal(TweakRestartKind.ExplorerRestart, enabled.RestartRequired);
        Assert.True(bridge.RegistryKeyExists("HKCU", clsid + @"\InprocServer32"));

        // Снимок помнит, какой раздел создал твик: откат уберёт именно его
        var delta = Assert.Single(Assert.Single(vault.Records).Deltas);
        using (var previous = JsonDocument.Parse(delta.PreviousStateJson!))
        {
            Assert.False(previous.RootElement.GetProperty("ExistedBefore").GetBoolean());
            Assert.Equal(clsid, previous.RootElement.GetProperty("CreatedKeyPath").GetString());
        }

        // Windows реагирует на само существование раздела, поэтому возврат к стандарту удаляет и его
        var restored = await service.SetTweakStateAsync("explorer.classic-context-menu", enableTweak: false);
        Assert.True(restored.Succeeded);
        Assert.False(bridge.RegistryKeyExists("HKCU", clsid + @"\InprocServer32"));
        Assert.False(bridge.RegistryKeyExists("HKCU", clsid));
        Assert.True(bridge.RegistryKeyExists("HKCU", @"Software\Classes\CLSID"));
    }

    [Fact]
    public async Task Preset_IsAppliedAsOneRollbackRecord_AndSkipsWhatNeedsConsentOrDoesNotFit()
    {
        // Ноутбук с Windows 11: настройка, вредная для батареи, без согласия пропускается
        var bridge = new FakeOptimizerBridge
        {
            Facts = new SystemFacts(WindowsBuildNumber: 26100, SystemDriveIsSolidState: true, HasBattery: true)
        };
        bridge.Services["MapsBroker"] = ServiceStartupMode.AutomaticDelayed;
        bridge.Tasks[@"\Microsoft\Windows\Maintenance\WinSAT"] = true;
        var vault = new InMemoryVault();
        var service = new SmartOptimizerService(vault, bridge);

        var preset = service.GetPresets().Single(p => p.Key == "gaming");
        var result = await service.ApplyTweakBatchAsync(preset.TweakIds, $"Набор «{preset.Title}»");

        Assert.True(result.Succeeded);
        Assert.Equal(0, result.FailedCount);

        var skipped = result.Items.Where(i => i.Outcome == TweakBatchItemOutcome.Skipped).Select(i => i.TweakId).ToList();
        Assert.Contains("perf.disable-power-throttling", skipped);   // не рекомендуется на батарее
        Assert.Contains("privacy.disable-compat-tasks", skipped);    // таких заданий в этой «системе» нет
        Assert.Equal(preset.TweakIds.Count - skipped.Count, result.AppliedCount);

        // Весь набор — одна запись, которая отменяется целиком
        var record = Assert.Single(vault.Records);
        Assert.Equal(result.RollbackSessionId, record.SessionId);
        Assert.Contains(record.Deltas, d => d.TargetKind == StateTargetKind.WindowsService && d.TargetPath == "MapsBroker");
        Assert.Contains(record.Deltas, d => d.TargetKind == StateTargetKind.ScheduledTask);
        Assert.Contains(record.Deltas, d => d.TargetKind == StateTargetKind.RegistryValue);
        Assert.Equal(TweakRestartKind.Reboot, result.RestartRequired);

        // Повторное применение: всё уже включено, новых записей нет
        var again = await service.ApplyTweakBatchAsync(preset.TweakIds, $"Набор «{preset.Title}»");
        Assert.True(again.Succeeded);
        Assert.Equal(0, again.AppliedCount);
        Assert.Equal(result.AppliedCount, again.AlreadyInStateCount);
        Assert.Null(again.RollbackSessionId);
        Assert.Single(vault.Records);
    }

    [Fact]
    public async Task Batch_NeverEnablesDangerousTweaksWithoutExplicitConsent_AndUndoesEverythingIfRollbackRecordCannotBeSaved()
    {
        var bridge = new FakeOptimizerBridge();
        var vault = new InMemoryVault();
        var service = new SmartOptimizerService(vault, bridge);
        string[] ids = ["explorer.show-file-extensions", "sec.disable-smartscreen", "нет.такой-настройки"];

        var careful = await service.ApplyTweakBatchAsync(ids, "Профиль");
        Assert.Equal(1, careful.AppliedCount);
        Assert.Equal(2, careful.SkippedCount);
        Assert.DoesNotContain(bridge.Store.Keys, k => k.Contains("EnableSmartScreen"));

        var forced = await service.ApplyTweakBatchAsync(ids, "Профиль", TweakApplyOptions.AcceptAll);
        Assert.Equal(1, forced.AppliedCount);
        Assert.Contains(bridge.Store.Keys, k => k.Contains("EnableSmartScreen"));

        // Если запись отката сохранить не удалось, изменения не остаются в системе
        var bridge2 = new FakeOptimizerBridge();
        var brokenVault = new InMemoryVault { FailCommitWith = new IOException("диск переполнен") };
        var service2 = new SmartOptimizerService(brokenVault, bridge2);

        var failed = await service2.ApplyTweakBatchAsync(["explorer.show-file-extensions", "explorer.show-hidden-files"], "Профиль");
        Assert.False(failed.Succeeded);
        Assert.Contains("диск переполнен", failed.UserFriendlyMessage);
        Assert.Empty(bridge2.Store);

        var single = await service2.SetTweakStateAsync("explorer.show-file-extensions", enableTweak: true);
        Assert.False(single.Succeeded);
        Assert.Empty(bridge2.Store);
    }

    [Fact]
    public void TweakForMissingProgram_IsNotApplicable_AndDetailsShowCurrentDesiredAndDefaultStates()
    {
        var bridge = new FakeOptimizerBridge();
        var service = new SmartOptimizerService(new InMemoryVault(), bridge);

        var chrome = service.EvaluateTweak("app.chrome-no-telemetry")!;
        Assert.Equal(TweakApplicabilityStatus.NotApplicable, chrome.Applicability.Status);
        Assert.Contains("Chrome", chrome.Applicability.Reason);

        bridge.Keys.Add(@"HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe");
        Assert.True(service.EvaluateTweak("app.chrome-no-telemetry")!.Applicability.IsApplicable);

        bridge.Services["DiagTrack"] = ServiceStartupMode.Automatic;
        var details = service.DescribeTweakActions("privacy.disable-telemetry-services");
        Assert.Equal(2, details.Count);
        Assert.Equal("Служба", details[0].KindLabel);
        Assert.Equal("DiagTrack", details[0].TargetDisplay);
        Assert.True(details[0].TargetExists);
        Assert.Equal("Автоматически", details[0].CurrentDisplay);
        Assert.Equal("Отключена", details[0].DesiredDisplay);
        Assert.False(details[1].TargetExists);

        // Все задания каталога опрашиваются за одно подключение к планировщику
        var connectionsBefore = bridge.TaskSchedulerConnections;
        _ = service.EvaluateAllTweaks();
        Assert.Equal(connectionsBefore + 1, bridge.TaskSchedulerConnections);
    }

    [Fact]
    public async Task ServiceAndTaskManagers_ProtectVitalObjects_AskBeforeTouchingProtection_AndRecordRollback()
    {
        var bridge = new FakeOptimizerBridge();
        bridge.Services["RpcSs"] = ServiceStartupMode.Automatic;
        bridge.Services["wuauserv"] = ServiceStartupMode.Manual;
        bridge.Services["VendorUpdater"] = ServiceStartupMode.Automatic;
        bridge.Tasks[@"\Vendor\Nightly Report"] = true;
        bridge.Tasks[@"\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan"] = true;
        var vault = new InMemoryVault();
        var service = new SmartOptimizerService(vault, bridge);

        // Жизненно важную службу нельзя ни отключить, ни остановить — даже с согласием
        var vital = await service.SetServiceStartupAsync("RpcSs", ServiceStartupMode.Disabled, acceptDangerous: true);
        Assert.False(vital.Succeeded);
        Assert.Equal(TweakConfirmationKind.None, vital.ConfirmationRequired);
        Assert.False((await service.ControlServiceAsync("RpcSs", start: false, acceptDangerous: true)).Succeeded);
        Assert.Equal(ServiceStartupMode.Automatic, bridge.Services["RpcSs"]);

        // Служба обновлений — только после отдельного подтверждения
        var update = await service.SetServiceStartupAsync("wuauserv", ServiceStartupMode.Disabled);
        Assert.False(update.Succeeded);
        Assert.Equal(TweakConfirmationKind.DangerousTweak, update.ConfirmationRequired);
        Assert.Equal(ServiceStartupMode.Manual, bridge.Services["wuauserv"]);
        Assert.True((await service.SetServiceStartupAsync("wuauserv", ServiceStartupMode.Disabled, acceptDangerous: true)).Succeeded);

        // Обычная служба меняется сразу, прежний тип запуска уходит в журнал
        var vendor = await service.SetServiceStartupAsync("VendorUpdater", ServiceStartupMode.Manual);
        Assert.True(vendor.Succeeded);
        Assert.Equal(ServiceStartupMode.Manual, bridge.Services["VendorUpdater"]);
        var vendorDelta = Assert.Single(vault.Records.Single(r => r.SessionId == vendor.RollbackSessionId).Deltas);
        Assert.Equal(StateTargetKind.WindowsService, vendorDelta.TargetKind);
        Assert.Contains("\"Startup\":\"Automatic\"", vendorDelta.PreviousStateJson);

        Assert.False((await service.SetServiceStartupAsync("НетТакойСлужбы", ServiceStartupMode.Manual)).Succeeded);
        Assert.False((await service.SetServiceStartupAsync("VendorUpdater", ServiceStartupMode.Boot)).Succeeded);

        // Задания: обычное отключается, задание Защитника — только с подтверждением; включить обратно можно всегда
        var task = await service.SetScheduledTaskEnabledAsync(@"\Vendor\Nightly Report", enabled: false);
        Assert.True(task.Succeeded);
        Assert.False(bridge.Tasks[@"\Vendor\Nightly Report"]);
        Assert.Equal(StateTargetKind.ScheduledTask, vault.Records.Single(r => r.SessionId == task.RollbackSessionId).Deltas[0].TargetKind);

        const string defenderTask = @"\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan";
        var defender = await service.SetScheduledTaskEnabledAsync(defenderTask, enabled: false);
        Assert.False(defender.Succeeded);
        Assert.Equal(TweakConfirmationKind.DangerousTweak, defender.ConfirmationRequired);
        Assert.True(bridge.Tasks[defenderTask]);

        // Без прав администратора ничего не меняется
        bridge.IsAdministrator = false;
        Assert.False((await service.SetServiceStartupAsync("VendorUpdater", ServiceStartupMode.Automatic)).Succeeded);
        Assert.False((await service.SetScheduledTaskEnabledAsync(@"\Vendor\Nightly Report", enabled: true)).Succeeded);

        // Подсказка из каталога для известной службы и задания
        Assert.Contains("службы телеметрии", service.GetServiceHint("DiagTrack"));
        Assert.Equal("", service.GetServiceHint("VendorUpdater"));
        Assert.Contains("автономных карт", service.GetScheduledTaskHint(MapsUpdateTask));
    }

    [Fact]
    public async Task Profile_RoundTripsEnabledTweaks_AndReportsUnknownOnes()
    {
        var bridge = new FakeOptimizerBridge();
        bridge.Services["Fax"] = ServiceStartupMode.Manual;
        var service = new SmartOptimizerService(new InMemoryVault(), bridge);

        Assert.True((await service.SetTweakStateAsync("svc.disable-fax", enableTweak: true)).Succeeded);
        Assert.True((await service.SetTweakStateAsync("explorer.show-hidden-files", enableTweak: true)).Succeeded);

        var yaml = service.ExportActiveTweaksToYaml("Домашний ПК") + "  - old.removed-tweak\n";
        var profile = service.ReadProfile(yaml);
        Assert.Equal("Домашний ПК", profile.Name);
        Assert.Equal(new[] { "explorer.show-hidden-files", "svc.disable-fax" }, profile.KnownTweakIds.ToArray());
        Assert.Equal(new[] { "old.removed-tweak" }, profile.UnknownTweakIds.ToArray());

        // На другом компьютере профиль включает то же самое
        var bridge2 = new FakeOptimizerBridge();
        bridge2.Services["Fax"] = ServiceStartupMode.Manual;
        var service2 = new SmartOptimizerService(new InMemoryVault(), bridge2);

        var imported = await service2.ImportAndApplyYamlProfileAsync(yaml);
        Assert.True(imported.Succeeded);
        Assert.Contains("Неизвестных настроек в профиле: 1", imported.UserFriendlyMessage);
        Assert.Equal(ServiceStartupMode.Disabled, bridge2.Services["Fax"]);
        Assert.Equal("1", bridge2.Store[@"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced::Hidden"].Val);
    }
}
