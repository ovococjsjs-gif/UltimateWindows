using UltimateWindows.Modules.Optimizer.Catalog;
using UltimateWindows.Modules.Optimizer.Models;
using Xunit;

namespace UltimateWindows.UnitTests;

public sealed class TweakCatalogLoaderTests
{
    [Fact]
    public void BuiltInCatalog_IsReadFromEmbeddedDataFile_AndBecomesTheModelUsedByTheEngine()
    {
        var catalog = TweakCatalogLoader.LoadBuiltIn();

        Assert.NotEmpty(catalog.Rules);
        Assert.Contains("recommended", catalog.PresetKeys);
        Assert.Contains("gaming", catalog.PresetKeys);
        Assert.Contains("privacy", catalog.PresetKeys);

        var wer = catalog.FindById("sys.disable-error-reporting-wer");
        Assert.NotNull(wer);
        var mutation = Assert.Single(wer!.Mutations);
        Assert.Equal("HKLM", mutation.Hive);
        Assert.Equal(@"SOFTWARE\Microsoft\Windows\Windows Error Reporting", mutation.SubKeyPath);
        Assert.Equal("Disabled", mutation.ValueName);
        Assert.Equal(RegistryTweakValueKind.DWord, mutation.ValueKind);
        Assert.Equal("1", mutation.DesiredSerializedValue);

        // Значения нет в чистой Windows — возврат к стандарту удаляет его
        Assert.False(mutation.ExistedByDefault);

        // Значение есть в чистой Windows — возврат к стандарту записывает его прежнее содержимое
        var longPaths = Assert.Single(catalog.FindById("sys.enable-win32-long-paths")!.Mutations);
        Assert.True(longPaths.ExistedByDefault);
        Assert.Equal("0", longPaths.DefaultRestoreSerializedValue);

        Assert.Same(wer, catalog.FindById("SYS.Disable-Error-Reporting-WER"));
        Assert.Same(catalog.GetPresetIds("recommended"), catalog.GetPresetIds("такого набора нет"));
    }

    [Fact]
    public void Loader_AcceptsUnsignedAndHexNumbers_AndTreatsMissingDefaultAsAbsentValue()
    {
        var catalog = TweakCatalogLoader.Parse(Catalog(Tweak(actions: """
            { "type": "registry", "hive": "HKCU", "key": "Software\\Test", "name": "Max", "kind": "dword", "value": 4294967295, "default": "0x10" },
            { "type": "registry", "hive": "HKCU", "key": "Software\\Test", "name": "Text", "kind": "string", "value": "on" }
            """)));

        var rule = Assert.Single(catalog.Rules);

        // Реестр хранит DWORD как знаковое 32-разрядное число: 4294967295 записывается как -1
        Assert.Equal("-1", rule.Mutations[0].DesiredSerializedValue);
        Assert.Equal("16", rule.Mutations[0].DefaultRestoreSerializedValue);
        Assert.True(rule.Mutations[0].ExistedByDefault);
        Assert.Equal("on", rule.Mutations[1].DesiredSerializedValue);
        Assert.False(rule.Mutations[1].ExistedByDefault);
    }

    [Fact]
    public void Loader_RejectsBrokenCatalogs_AndNamesTheProblem()
    {
        AssertRejected("не является корректным JSON", "{ это не JSON");
        AssertRejected("версия формата 2", Catalog(Tweak(), schemaVersion: 2));
        AssertRejected("неизвестное поле «titel»", Catalog(Tweak().Replace("\"title\"", "\"titel\"")));
        AssertRejected("такой идентификатор уже есть", Catalog(Tweak() + "," + Tweak()));
        AssertRejected("неизвестный тип действия «service»", Catalog(Tweak(actions: """{ "type": "service", "name": "Spooler" }""")));
        AssertRejected("неизвестный куст реестра «HKML»", Catalog(Tweak(actions: RegistryAction(hive: "HKML"))));
        AssertRejected("не помещается в 32 разряда", Catalog(Tweak(actions: RegistryAction(value: "4294967296"))));
        AssertRejected("«requiresAdministrator» должно быть true", Catalog(Tweak(actions: RegistryAction(hive: "HKLM"))));
        AssertRejected("твика «test.missing» нет в каталоге", Catalog(Tweak(), presetIds: "\"test.missing\""));

        // Барьер безопасности действует и для файла данных
        AssertRejected(
            "должно быть помечено как опасное",
            Catalog(Tweak(admin: true, actions: RegistryAction(hive: "HKLM", key: @"SOFTWARE\\Policies\\Microsoft\\Windows Defender"))));
        AssertRejected("опасный твик", Catalog(Tweak(risk: "High")));
        AssertRejected(
            "лицензирование Windows запрещено",
            Catalog(Tweak(admin: true, risk: "Critical", actions: RegistryAction(hive: "HKLM", key: @"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform"))));
    }

    private static string Catalog(string tweaks, int schemaVersion = 1, string presetIds = "\"test.sample\"") =>
        $$"""{ "schemaVersion": {{schemaVersion}}, "presets": { "recommended": [ {{presetIds}} ] }, "tweaks": [ {{tweaks}} ] }""";

    private static string Tweak(string risk = "Safe", bool admin = false, string? actions = null) =>
        $$"""
        {
          "id": "test.sample", "category": "SystemAndPerformance", "icon": "SYS", "title": "Проверочный твик",
          "explanation": "Нужен только для теста.", "impact": "Ничего", "risk": "{{risk}}",
          "requiresAdministrator": {{(admin ? "true" : "false")}},
          "actions": [ {{actions ?? RegistryAction()}} ]
        }
        """;

    private static string RegistryAction(string hive = "HKCU", string key = @"Software\\Test", string value = "1") =>
        $$"""{ "type": "registry", "hive": "{{hive}}", "key": "{{key}}", "name": "Flag", "kind": "dword", "value": {{value}} }""";

    private static void AssertRejected(string expectedMessagePart, string json)
    {
        var error = Assert.Throws<InvalidDataException>(() => TweakCatalogLoader.Parse(json));
        Assert.Contains(expectedMessagePart, error.Message);
    }
}
