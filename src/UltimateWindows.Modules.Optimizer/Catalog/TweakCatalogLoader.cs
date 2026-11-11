using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Optimizer.Models;

namespace UltimateWindows.Modules.Optimizer.Catalog;

/// <summary>
/// Каталог твиков, прочитанный из файла данных: правила в порядке показа и готовые наборы.
/// </summary>
public sealed class TweakCatalogData
{
    private readonly Dictionary<string, DeclarativeTweakRule> _rulesById;
    private readonly Dictionary<string, IReadOnlyList<string>> _presets;

    internal TweakCatalogData(
        IReadOnlyList<DeclarativeTweakRule> rules,
        Dictionary<string, DeclarativeTweakRule> rulesById,
        Dictionary<string, IReadOnlyList<string>> presets)
    {
        Rules = rules;
        _rulesById = rulesById;
        _presets = presets;
    }

    public IReadOnlyList<DeclarativeTweakRule> Rules { get; }

    public IReadOnlyCollection<string> PresetKeys => _presets.Keys;

    public DeclarativeTweakRule? FindById(string? tweakId) =>
        tweakId is not null && _rulesById.TryGetValue(tweakId, out var rule) ? rule : null;

    /// <summary>
    /// Идентификаторы твиков набора. Неизвестное название набора означает набор по умолчанию.
    /// </summary>
    public IReadOnlyList<string> GetPresetIds(string? presetKey) =>
        presetKey is not null && _presets.TryGetValue(presetKey, out var ids)
            ? ids
            : _presets[TweakCatalogLoader.DefaultPresetKey];
}

/// <summary>
/// Читает каталог твиков из JSON и проверяет его целиком. Ошибка в файле данных не должна дойти до реестра
/// пользователя, поэтому любое отступление от формата — неизвестное поле, опечатка в названии куста реестра,
/// повтор идентификатора, число не того вида — останавливает загрузку с понятным сообщением
/// (<see cref="InvalidDataException"/>), в котором назван твик и поле.
/// </summary>
public static class TweakCatalogLoader
{
    public const int SupportedSchemaVersion = 1;
    public const string DefaultPresetKey = "recommended";
    public const string BuiltInResourceName = "UltimateWindows.Optimizer.tweaks.json";

    private const string RootContext = "корень файла";

    private static readonly Regex TweakIdPattern = new(@"^[a-z0-9]+(\.[a-z0-9-]+)+$", RegexOptions.CultureInvariant);

    private static readonly string[] KnownHives = ["HKLM", "HKCU", "HKCR", "HKU"];

    private static readonly string[] RootFields = ["schemaVersion", "presets", "tweaks"];

    private static readonly string[] TweakFields =
    [
        "id", "category", "icon", "title", "explanation", "impact", "risk",
        "requiresAdministrator", "requirements", "actions"
    ];

    private static readonly string[] RequirementFields =
    [
        "minWindowsBuild", "maxWindowsBuild", "bestOnSolidStateSystemDrive", "batteryWarning"
    ];

    private static readonly string[] RegistryActionFields = ["type", "hive", "key", "name", "kind", "value", "default"];

    /// <summary>
    /// Каталог, встроенный в сборку (файл <c>Catalog/tweaks.json</c>).
    /// </summary>
    public static TweakCatalogData LoadBuiltIn()
    {
        var assembly = typeof(TweakCatalogLoader).Assembly;
        using var stream = assembly.GetManifestResourceStream(BuiltInResourceName)
            ?? throw new InvalidDataException(
                $"Каталог твиков: в сборке нет встроенного файла данных «{BuiltInResourceName}».");
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return Parse(reader.ReadToEnd());
    }

    public static TweakCatalogData Parse(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            throw new InvalidDataException("Каталог твиков: файл данных пуст.");
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json, new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true
            });
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"Каталог твиков: файл данных не является корректным JSON. {ex.Message}", ex);
        }

        using (document)
        {
            var root = document.RootElement;
            RequireObject(root, RootContext);
            RejectUnknownFields(root, RootContext, RootFields);

            var version = RequireInt(root, "schemaVersion", RootContext);
            if (version != SupportedSchemaVersion)
            {
                throw Error(
                    RootContext,
                    $"версия формата {version} не поддерживается: эта версия программы понимает версию {SupportedSchemaVersion}.");
            }

            var rules = new List<DeclarativeTweakRule>();
            var rulesById = new Dictionary<string, DeclarativeTweakRule>(StringComparer.OrdinalIgnoreCase);
            var index = 0;
            foreach (var tweakElement in RequireArray(root, "tweaks", RootContext).EnumerateArray())
            {
                index++;
                var rule = ParseTweak(tweakElement, index);
                if (!rulesById.TryAdd(rule.TweakId, rule))
                {
                    throw Error(DescribeTweak(rule.TweakId), "такой идентификатор уже есть у другого твика.");
                }

                rules.Add(rule);
            }

            if (rules.Count == 0)
            {
                throw Error(RootContext, "список «tweaks» пуст.");
            }

            return new TweakCatalogData(rules.ToArray(), rulesById, ParsePresets(root, rulesById));
        }
    }

    private static DeclarativeTweakRule ParseTweak(JsonElement element, int index)
    {
        var context = $"твик №{index}";
        RequireObject(element, context);

        var id = RequireString(element, "id", context);
        context = DescribeTweak(id);
        if (!TweakIdPattern.IsMatch(id))
        {
            throw Error(
                context,
                "идентификатор пишется строчными латинскими буквами, цифрами и дефисами, части разделяются точкой — например «privacy.disable-something».");
        }

        RejectUnknownFields(element, context, TweakFields);

        var category = RequireEnum<TweakCategory>(element, "category", context);
        var icon = RequireString(element, "icon", context);
        var title = RequireString(element, "title", context);
        var explanation = RequireString(element, "explanation", context);
        var impact = RequireString(element, "impact", context);
        var risk = RequireEnum<RiskLevel>(element, "risk", context);
        var requiresAdministrator = RequireBool(element, "requiresAdministrator", context);

        TweakRequirements? requirements = null;
        if (element.TryGetProperty("requirements", out var requirementsElement))
        {
            requirements = ParseRequirements(requirementsElement, $"{context}, условия применимости");
        }

        var mutations = new List<TweakRegistryMutation>();
        var targets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var actionIndex = 0;
        foreach (var actionElement in RequireArray(element, "actions", context).EnumerateArray())
        {
            actionIndex++;
            var actionContext = $"{context}, действие №{actionIndex}";
            var mutation = ParseAction(actionElement, actionContext);
            if (!targets.Add($"{mutation.Hive}\n{mutation.SubKeyPath}\n{mutation.ValueName}"))
            {
                throw Error(actionContext, "это значение реестра уже меняется другим действием того же твика.");
            }

            mutations.Add(mutation);
        }

        if (mutations.Count == 0)
        {
            throw Error(context, "нет ни одного действия.");
        }

        if (!requiresAdministrator &&
            mutations.Exists(m => !string.Equals(m.Hive, "HKCU", StringComparison.Ordinal)))
        {
            throw Error(
                context,
                "твик меняет общий для всех пользователей раздел реестра (не HKCU), поэтому «requiresAdministrator» должно быть true.");
        }

        var rule = new DeclarativeTweakRule(
            id,
            category,
            icon,
            title,
            explanation,
            impact,
            risk,
            requiresAdministrator,
            mutations.ToArray(),
            requirements);

        try
        {
            TweakSafetyGuard.ThrowIfUnsafeRule(rule);
        }
        catch (InvalidOperationException ex)
        {
            throw new InvalidDataException($"Каталог твиков: {ex.Message}", ex);
        }

        return rule;
    }

    private static TweakRequirements ParseRequirements(JsonElement element, string context)
    {
        RequireObject(element, context);
        RejectUnknownFields(element, context, RequirementFields);

        var min = OptionalInt(element, "minWindowsBuild", context);
        var max = OptionalInt(element, "maxWindowsBuild", context);
        var bestOnSsd = element.TryGetProperty("bestOnSolidStateSystemDrive", out _) &&
                        RequireBool(element, "bestOnSolidStateSystemDrive", context);
        var batteryWarning = element.TryGetProperty("batteryWarning", out _)
            ? RequireString(element, "batteryWarning", context)
            : null;

        if (min is <= 0 || max is <= 0)
        {
            throw Error(context, "номер сборки Windows должен быть положительным числом, например 22000.");
        }

        if (min is { } minBuild && max is { } maxBuild && minBuild > maxBuild)
        {
            throw Error(context, "«minWindowsBuild» больше, чем «maxWindowsBuild».");
        }

        if (min is null && max is null && !bestOnSsd && batteryWarning is null)
        {
            throw Error(context, "раздел пуст. Если условий нет, удалите «requirements» целиком.");
        }

        return new TweakRequirements(min, max, bestOnSsd, batteryWarning);
    }

    private static TweakRegistryMutation ParseAction(JsonElement element, string context)
    {
        RequireObject(element, context);
        var type = RequireString(element, "type", context);
        return type switch
        {
            "registry" => ParseRegistryAction(element, context),
            _ => throw Error(context, $"неизвестный тип действия «{type}». Эта версия программы понимает тип «registry».")
        };
    }

    private static TweakRegistryMutation ParseRegistryAction(JsonElement element, string context)
    {
        RejectUnknownFields(element, context, RegistryActionFields);

        var hive = RequireString(element, "hive", context);
        if (Array.IndexOf(KnownHives, hive) < 0)
        {
            throw Error(context, $"неизвестный куст реестра «{hive}». Допустимые: {string.Join(", ", KnownHives)}.");
        }

        var key = RequireString(element, "key", context);
        if (key.Contains('/') || key.StartsWith('\\') || key.EndsWith('\\') || key.Contains(@"\\", StringComparison.Ordinal))
        {
            throw Error(context, "путь раздела «key» пишется через одну обратную косую черту, без неё в начале и в конце.");
        }

        // Пустое имя — это значение «(По умолчанию)» раздела
        var name = RequireString(element, "name", context, allowEmpty: true);

        var kindText = RequireString(element, "kind", context);
        var kind = kindText switch
        {
            "dword" => RegistryTweakValueKind.DWord,
            "string" => RegistryTweakValueKind.String,
            _ => throw Error(context, $"неизвестный вид значения «{kindText}». Допустимые: dword, string.")
        };

        if (!element.TryGetProperty("value", out var valueElement))
        {
            throw Error(context, "нет обязательного поля «value».");
        }

        var desired = ReadRegistryData(valueElement, kind, "value", context);

        // «default» — содержимое значения в чистой Windows. Если поля нет, значения в чистой Windows не существует,
        // и возврат к стандарту удаляет его.
        string? standard = null;
        if (element.TryGetProperty("default", out var defaultElement) && defaultElement.ValueKind != JsonValueKind.Null)
        {
            standard = ReadRegistryData(defaultElement, kind, "default", context);
        }

        return new TweakRegistryMutation(
            hive,
            key,
            name,
            kind,
            desired,
            standard ?? string.Empty,
            ExistedByDefault: standard is not null);
    }

    private static string ReadRegistryData(JsonElement value, RegistryTweakValueKind kind, string field, string context)
    {
        if (kind == RegistryTweakValueKind.String)
        {
            if (value.ValueKind != JsonValueKind.String)
            {
                throw Error(context, $"поле «{field}»: значение вида string пишется в кавычках.");
            }

            return value.GetString() ?? string.Empty;
        }

        long number;
        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out var parsed))
        {
            number = parsed;
        }
        else if (value.ValueKind == JsonValueKind.String && TryParseHex(value.GetString(), out var hex))
        {
            number = hex;
        }
        else
        {
            throw Error(
                context,
                $"поле «{field}»: значение вида dword — целое число (например 1) или шестнадцатеричная строка (например \"0x1F\").");
        }

        if (number < int.MinValue || number > uint.MaxValue)
        {
            throw Error(context, $"поле «{field}»: число {number.ToString(CultureInfo.InvariantCulture)} не помещается в 32 разряда.");
        }

        // Мост реестра читает и пишет DWORD как знаковое 32-разрядное число, поэтому 4294967295 хранится как −1
        return unchecked((int)number).ToString(CultureInfo.InvariantCulture);
    }

    private static bool TryParseHex(string? text, out uint value)
    {
        value = 0;
        return text is not null &&
               text.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
               uint.TryParse(text.AsSpan(2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out value);
    }

    private static Dictionary<string, IReadOnlyList<string>> ParsePresets(
        JsonElement root,
        Dictionary<string, DeclarativeTweakRule> rulesById)
    {
        const string sectionContext = "раздел «presets»";
        if (!root.TryGetProperty("presets", out var presetsElement))
        {
            throw Error(RootContext, "нет раздела «presets».");
        }

        RequireObject(presetsElement, sectionContext);

        var presets = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var preset in presetsElement.EnumerateObject())
        {
            var context = $"набор «{preset.Name}»";
            if (preset.Value.ValueKind != JsonValueKind.Array)
            {
                throw Error(context, "ожидался список идентификаторов твиков в квадратных скобках.");
            }

            var ids = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var item in preset.Value.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.String)
                {
                    throw Error(context, "идентификаторы твиков пишутся в кавычках.");
                }

                var id = item.GetString() ?? string.Empty;
                if (!rulesById.TryGetValue(id, out var rule))
                {
                    throw Error(context, $"твика «{id}» нет в каталоге.");
                }

                if (rule.IsDangerous)
                {
                    throw Error(context, $"«{id}» — опасный твик, в наборы такие не входят.");
                }

                if (!seen.Add(id))
                {
                    throw Error(context, $"твик «{id}» указан дважды.");
                }

                ids.Add(rule.TweakId);
            }

            if (ids.Count == 0)
            {
                throw Error(context, "набор пуст.");
            }

            if (!presets.TryAdd(preset.Name, ids.ToArray()))
            {
                throw Error(context, "набор с таким названием уже есть.");
            }
        }

        if (!presets.ContainsKey(DefaultPresetKey))
        {
            throw Error(sectionContext, $"нет обязательного набора «{DefaultPresetKey}».");
        }

        return presets;
    }

    // ---------------------------------------------------------------------------------------------
    // Разбор полей с проверкой
    // ---------------------------------------------------------------------------------------------

    private static string DescribeTweak(string id) => $"твик «{id}»";

    private static InvalidDataException Error(string context, string message) =>
        new($"Каталог твиков: {context}: {message}");

    private static void RequireObject(JsonElement element, string context)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw Error(context, "ожидался объект в фигурных скобках.");
        }
    }

    private static void RejectUnknownFields(JsonElement element, string context, string[] allowed)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
        {
            if (Array.IndexOf(allowed, property.Name) < 0)
            {
                throw Error(context, $"неизвестное поле «{property.Name}». Допустимые поля: {string.Join(", ", allowed)}.");
            }

            if (!seen.Add(property.Name))
            {
                throw Error(context, $"поле «{property.Name}» указано дважды.");
            }
        }
    }

    private static JsonElement RequireArray(JsonElement element, string name, string context)
    {
        if (!element.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Array)
        {
            throw Error(context, $"нет обязательного списка «{name}».");
        }

        return value;
    }

    private static string RequireString(JsonElement element, string name, string context, bool allowEmpty = false)
    {
        if (!element.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String)
        {
            throw Error(context, $"нет обязательного текстового поля «{name}».");
        }

        var text = value.GetString() ?? string.Empty;
        if (!allowEmpty && string.IsNullOrWhiteSpace(text))
        {
            throw Error(context, $"поле «{name}» пустое.");
        }

        return text;
    }

    private static bool RequireBool(JsonElement element, string name, string context)
    {
        if (!element.TryGetProperty(name, out var value) ||
            (value.ValueKind != JsonValueKind.True && value.ValueKind != JsonValueKind.False))
        {
            throw Error(context, $"нет обязательного поля «{name}» со значением true или false.");
        }

        return value.GetBoolean();
    }

    private static int RequireInt(JsonElement element, string name, string context) =>
        OptionalInt(element, name, context)
        ?? throw Error(context, $"нет обязательного числового поля «{name}».");

    private static int? OptionalInt(JsonElement element, string name, string context)
    {
        if (!element.TryGetProperty(name, out var value))
        {
            return null;
        }

        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out var number))
        {
            throw Error(context, $"поле «{name}» должно быть целым числом.");
        }

        return number;
    }

    private static TEnum RequireEnum<TEnum>(JsonElement element, string name, string context)
        where TEnum : struct, Enum
    {
        var text = RequireString(element, name, context);
        var names = Enum.GetNames<TEnum>();
        if (Array.IndexOf(names, text) < 0)
        {
            throw Error(context, $"поле «{name}»: неизвестное значение «{text}». Допустимые: {string.Join(", ", names)}.");
        }

        return Enum.Parse<TEnum>(text);
    }
}
