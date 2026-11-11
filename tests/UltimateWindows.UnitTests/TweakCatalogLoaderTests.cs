using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Optimizer.Catalog;
using UltimateWindows.Modules.Optimizer.Models;
using Xunit;

namespace UltimateWindows.UnitTests;

public sealed class TweakCatalogLoaderTests
{
    [Fact]
    public void BuiltInCatalog_IsReadFromEmbeddedDataFiles_AndBecomesTheModelUsedByTheEngine()
    {
        var catalog = TweakCatalogLoader.LoadBuiltIn();

        Assert.True(catalog.Rules.Count >= 150);
        Assert.Contains("recommended", catalog.PresetKeys);
        Assert.Contains("gaming", catalog.PresetKeys);
        Assert.Contains("privacy", catalog.PresetKeys);

        // Значения нет в чистой Windows — возврат к стандарту удаляет его
        var feedback = catalog.FindById("privacy.limit-diagnostic-data");
        Assert.NotNull(feedback);
        var mutation = Assert.Single(feedback.Mutations);
        Assert.Equal("HKLM", mutation.Hive);
        Assert.Equal(@"SOFTWARE\Policies\Microsoft\Windows\DataCollection", mutation.SubKeyPath);
        Assert.Equal("AllowTelemetry", mutation.ValueName);
        Assert.Equal(RegistryTweakValueKind.DWord, mutation.ValueKind);
        Assert.Equal("0", mutation.DesiredSerializedValue);
        Assert.False(mutation.ExistedByDefault);

        // Значение есть в чистой Windows — возврат к стандарту записывает его прежнее содержимое
        var longPaths = Assert.Single(catalog.FindById("disk.long-paths")!.Mutations);
        Assert.True(longPaths.ExistedByDefault);
        Assert.Equal("0", longPaths.DefaultRestoreSerializedValue);

        // Шестнадцатеричная запись и число больше 2^31 хранятся знаковым 32-разрядным числом
        var lastAccess = Assert.Single(catalog.FindById("disk.no-last-access-time")!.Mutations);
        Assert.Equal("-2147483647", lastAccess.DesiredSerializedValue);
        Assert.Equal("-2147483646", lastAccess.DefaultRestoreSerializedValue);
        Assert.Equal("2147483649", TweakRegistryMutation.FormatData(lastAccess.ValueKind, lastAccess.DesiredSerializedValue));

        // Службы и задания — отдельные виды действий со своим стандартным состоянием
        var telemetry = catalog.FindById("privacy.disable-telemetry-services")!;
        Assert.Equal(TweakRestartKind.Reboot, telemetry.Restart);
        var diagTrack = Assert.IsType<TweakServiceAction>(telemetry.Actions[0]);
        Assert.Equal("DiagTrack", diagTrack.ServiceName);
        Assert.Equal(ServiceStartupMode.Disabled, diagTrack.DesiredStartup);
        Assert.Equal(ServiceStartupMode.Automatic, diagTrack.DefaultStartup);

        var maps = catalog.FindById("svc.disable-maps")!;
        Assert.Equal(TweakActionKind.Service, maps.Actions[0].Kind);
        var mapsTask = Assert.IsType<TweakScheduledTaskAction>(maps.Actions[1]);
        Assert.Equal(@"\Microsoft\Windows\Maps\MapsUpdateTask", mapsTask.TaskPath);
        Assert.False(mapsTask.DesiredEnabled);
        Assert.True(mapsTask.DefaultEnabled);

        // Условие «программа установлена»
        var chrome = catalog.FindById("app.chrome-no-telemetry")!;
        Assert.Equal(2, chrome.EffectiveRequirements.InstalledAnyRegistryKey!.Count);
        Assert.Contains("Chrome", chrome.EffectiveRequirements.InstalledNote);

        // Опасные настройки есть, но ни в один набор не входят
        var dangerous = catalog.Rules.Where(r => r.IsDangerous).Select(r => r.TweakId).ToArray();
        Assert.NotEmpty(dangerous);
        Assert.DoesNotContain(catalog.Presets.SelectMany(p => p.TweakIds), id => dangerous.Contains(id));

        Assert.Same(feedback, catalog.FindById("PRIVACY.Limit-Diagnostic-Data"));
        Assert.Same(catalog.GetPresetIds("recommended"), catalog.GetPresetIds("такого набора нет"));
    }

    [Fact]
    public void Loader_AcceptsUnsignedAndHexNumbers_AndTreatsMissingDefaultAsAbsentValue()
    {
        var catalog = TweakCatalogLoader.Parse(Catalog(Tweak(actions: """
            { "type": "registry", "hive": "HKCU", "key": "Software\\Test", "name": "Max", "kind": "dword", "value": 4294967295, "default": "0x10" },
            { "type": "registry", "hive": "HKCU", "key": "Software\\Test", "name": "Text", "kind": "string", "value": "on" },
            { "type": "service", "name": "TestSvc", "startup": "disabled", "default": "automaticDelayed" },
            { "type": "task", "path": "\\Vendor\\Nightly Report", "enabled": false }
            """)));

        var rule = Assert.Single(catalog.Rules);
        Assert.Equal(4, rule.Actions.Count);

        // Реестр хранит DWORD как знаковое 32-разрядное число: 4294967295 записывается как -1
        Assert.Equal("-1", rule.Mutations[0].DesiredSerializedValue);
        Assert.Equal("16", rule.Mutations[0].DefaultRestoreSerializedValue);
        Assert.True(rule.Mutations[0].ExistedByDefault);
        Assert.Equal("on", rule.Mutations[1].DesiredSerializedValue);
        Assert.False(rule.Mutations[1].ExistedByDefault);

        Assert.Equal(ServiceStartupMode.AutomaticDelayed, ((TweakServiceAction)rule.Actions[2]).DefaultStartup);
        Assert.Equal(@"\Vendor\Nightly Report", ((TweakScheduledTaskAction)rule.Actions[3]).TaskPath);

        // Служба и задание требуют прав администратора, даже если остальные действия — в кусте пользователя
        Assert.True(rule.RequiresAdministrator);
        Assert.False(TweakCatalogLoader.Parse(Catalog(Tweak())).Rules[0].RequiresAdministrator);
    }

    [Fact]
    public void Loader_MergesSeveralDataFiles_AndNamesTheFileInErrors()
    {
        var catalog = TweakCatalogLoader.ParseDocuments(
        [
            new TweakCatalogDocument("a.json", $$"""{ "schemaVersion": 2, "tweaks": [ {{Tweak()}} ] }"""),
            new TweakCatalogDocument("b.json", $$"""{ "schemaVersion": 2, "tweaks": [ {{Tweak().Replace("test.sample", "test.second")}} ] }"""),
            new TweakCatalogDocument("presets.json", """
                { "schemaVersion": 2, "presets": { "recommended": { "title": "Набор", "description": "Описание.", "tweaks": [ "test.second", "test.sample" ] } } }
                """)
        ]);

        Assert.Equal(new[] { "test.sample", "test.second" }, catalog.Rules.Select(r => r.TweakId).ToArray());
        var preset = Assert.Single(catalog.Presets);
        Assert.Equal("Набор", preset.Title);
        Assert.Equal(new[] { "test.second", "test.sample" }, preset.TweakIds.ToArray());

        var error = Assert.Throws<InvalidDataException>(() => TweakCatalogLoader.ParseDocuments(
        [
            new TweakCatalogDocument("a.json", Catalog(Tweak())),
            new TweakCatalogDocument("b.json", $$"""{ "schemaVersion": 2, "tweaks": [ {{Tweak()}} ] }""")
        ]));
        Assert.Contains("файл «b.json»", error.Message);
        Assert.Contains("такой идентификатор уже есть", error.Message);
    }

    [Fact]
    public void Loader_RejectsBrokenCatalogs_AndNamesTheProblem()
    {
        AssertRejected("не является корректным JSON", "{ это не JSON");
        AssertRejected("версия формата 1", Catalog(Tweak(), schemaVersion: 1));
        AssertRejected("неизвестное поле «titel»", Catalog(Tweak().Replace("\"title\"", "\"titel\"")));
        AssertRejected("такой идентификатор уже есть", Catalog(Tweak() + "," + Tweak()));
        AssertRejected("неизвестный тип действия «appx»", Catalog(Tweak(actions: """{ "type": "appx", "name": "Microsoft.BingNews" }""")));
        AssertRejected("неизвестный куст реестра «HKML»", Catalog(Tweak(actions: RegistryAction(hive: "HKML"))));
        AssertRejected("не помещается в 32 разряда", Catalog(Tweak(actions: RegistryAction(value: "4294967296"))));
        AssertRejected("твика «test.missing» нет в каталоге", Catalog(Tweak(), presetIds: "\"test.missing\""));
        AssertRejected("эта цель уже меняется", Catalog(Tweak(actions: RegistryAction() + "," + RegistryAction(value: "2"))));
        AssertRejected("поле «restart»", Catalog(Tweak().Replace("\"risk\"", "\"restart\": \"later\", \"risk\"")));
        AssertRejected("для твиков допустимы значения", Catalog(Tweak(risk: "Critical")));

        // Службы и задания
        AssertRejected("неизвестный тип запуска «off»", Catalog(Tweak(actions: """{ "type": "service", "name": "Fax", "startup": "off", "default": "manual" }""")));
        AssertRejected("не имя службы", Catalog(Tweak(actions: """{ "type": "service", "name": "Print Spooler", "startup": "disabled", "default": "automatic" }""")));
        AssertRejected("«startup» совпадает с «default»", Catalog(Tweak(actions: """{ "type": "service", "name": "Fax", "startup": "manual", "default": "manual" }""")));
        AssertRejected("путь задания «path»", Catalog(Tweak(actions: """{ "type": "task", "path": "Microsoft\\Windows\\Task", "enabled": false }""")));
        AssertRejected(
            "задаётся действием типа «service»",
            Catalog(Tweak(actions: RegistryAction(hive: "HKLM", key: @"SYSTEM\\CurrentControlSet\\Services\\Spooler", name: "Start", value: "4"))));

        // Условие «программа установлена» задаётся вместе с пояснением
        AssertRejected(
            "задаются вместе",
            Catalog(Tweak().Replace("\"risk\"", "\"requirements\": { \"installedAny\": [ \"HKLM\\\\SOFTWARE\\\\Vendor\" ] }, \"risk\"")));

        // Барьер безопасности действует и для файла данных
        AssertRejected(
            "должно быть помечено как опасное",
            Catalog(Tweak(actions: RegistryAction(hive: "HKLM", key: @"SOFTWARE\\Policies\\Microsoft\\Windows Defender"))));
        AssertRejected(
            "должно быть помечено как опасное",
            Catalog(Tweak(actions: """{ "type": "service", "name": "wuauserv", "startup": "disabled", "default": "manual" }""")));
        AssertRejected(
            "должно быть помечено как опасное",
            Catalog(Tweak(actions: """{ "type": "task", "path": "\\Microsoft\\Windows\\Windows Defender\\Windows Defender Scheduled Scan", "enabled": false }""")));
        AssertRejected("опасный твик", Catalog(Tweak(risk: "High")));
        AssertRejected("только твики с риском Safe или Low", Catalog(Tweak(risk: "Moderate")));
        AssertRejected(
            "лицензирование Windows запрещено",
            Catalog(Tweak(risk: "High", actions: RegistryAction(hive: "HKLM", key: @"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform")), presetIds: null));
        AssertRejected(
            "лицензирование Windows запрещено",
            Catalog(Tweak(risk: "High", actions: """{ "type": "service", "name": "sppsvc", "startup": "disabled", "default": "automaticDelayed" }"""), presetIds: null));
        AssertRejected(
            "нужна для работы Windows",
            Catalog(Tweak(risk: "High", actions: """{ "type": "service", "name": "RpcSs", "startup": "disabled", "default": "automatic" }"""), presetIds: null));
    }

    [Fact]
    public void SafetyGuard_ClassifiesServicesAndTasks_TheSameWayForCatalogAndManualControl()
    {
        Assert.Equal(SystemObjectProtection.None, TweakSafetyGuard.ClassifyService("Fax"));
        Assert.Equal(SystemObjectProtection.None, TweakSafetyGuard.ClassifyService("DiagTrack"));
        Assert.Equal(SystemObjectProtection.WeakensProtection, TweakSafetyGuard.ClassifyService("WinDefend"));
        Assert.Equal(SystemObjectProtection.WeakensProtection, TweakSafetyGuard.ClassifyService("wuauserv"));
        Assert.Equal(SystemObjectProtection.Critical, TweakSafetyGuard.ClassifyService("RpcSs"));
        Assert.Equal(SystemObjectProtection.Critical, TweakSafetyGuard.ClassifyService("sppsvc"));

        // Служба отдельного пользователя называется «Имя_суффикс»
        Assert.Equal(SystemObjectProtection.WeakensProtection, TweakSafetyGuard.ClassifyService("webthreatdefusersvc_3f2a1"));
        Assert.Equal(SystemObjectProtection.None, TweakSafetyGuard.ClassifyService("CDPUserSvc_3f2a1"));

        Assert.Equal(SystemObjectProtection.None, TweakSafetyGuard.ClassifyScheduledTask(@"\Microsoft\Windows\Maps\MapsUpdateTask"));
        Assert.Equal(
            SystemObjectProtection.WeakensProtection,
            TweakSafetyGuard.ClassifyScheduledTask(@"\Microsoft\Windows\Windows Defender\Windows Defender Cleanup"));
        Assert.Equal(
            SystemObjectProtection.Critical,
            TweakSafetyGuard.ClassifyScheduledTask(@"\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask"));

        // Тип запуска службы, записанный прямо в реестр, подчиняется тем же правилам
        Assert.Equal(
            SystemObjectProtection.Critical,
            TweakSafetyGuard.Classify(new TweakRegistryMutation(
                "HKLM", @"SYSTEM\CurrentControlSet\Services\RpcSs", "Start", RegistryTweakValueKind.DWord, "4", "2", ExistedByDefault: true)));
        Assert.Equal(
            SystemObjectProtection.None,
            TweakSafetyGuard.Classify(new TweakRegistryMutation(
                "HKLM", @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1", RegistryTweakValueKind.DWord, "0", "")));
    }

    private static string Catalog(string tweaks, int schemaVersion = 2, string? presetIds = "\"test.sample\"")
    {
        var presets = presetIds is null
            ? """
              "recommended": { "title": "Набор", "description": "Описание.", "tweaks": [ "test.other" ] }
              """
            : $$"""
              "recommended": { "title": "Набор", "description": "Описание.", "tweaks": [ {{presetIds}} ] }
              """;
        return $$"""{ "schemaVersion": {{schemaVersion}}, "presets": { {{presets}} }, "tweaks": [ {{tweaks}} ] }""";
    }

    private static string Tweak(string risk = "Safe", string? actions = null) =>
        $$"""
        {
          "id": "test.sample", "category": "Performance", "title": "Проверочный твик",
          "explanation": "Нужен только для теста.", "risk": "{{risk}}",
          "actions": [ {{actions ?? RegistryAction()}} ]
        }
        """;

    private static string RegistryAction(string hive = "HKCU", string key = @"Software\\Test", string name = "Flag", string value = "1") =>
        $$"""{ "type": "registry", "hive": "{{hive}}", "key": "{{key}}", "name": "{{name}}", "kind": "dword", "value": {{value}} }""";

    private static void AssertRejected(string expectedMessagePart, string json)
    {
        var error = Assert.Throws<InvalidDataException>(() => TweakCatalogLoader.Parse(json));
        Assert.Contains(expectedMessagePart, error.Message);
    }
}
