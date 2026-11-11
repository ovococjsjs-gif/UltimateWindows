using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Optimizer.Models;

namespace UltimateWindows.Modules.Optimizer.Catalog;

/// <summary>
/// Один файл данных каталога: имя (для сообщений об ошибках) и содержимое JSON.
/// </summary>
public sealed record TweakCatalogDocument(string Name, string Json);

/// <summary>
/// Каталог твиков, прочитанный из файлов данных: правила в порядке показа и готовые наборы.
/// </summary>
public sealed class TweakCatalogData
{
    private readonly Dictionary<string, DeclarativeTweakRule> _rulesById;
    private readonly Dictionary<string, TweakPresetDescriptor> _presets;

    internal TweakCatalogData(
        IReadOnlyList<DeclarativeTweakRule> rules,
        Dictionary<string, DeclarativeTweakRule> rulesById,
        IReadOnlyList<TweakPresetDescriptor> presets)
    {
        Rules = rules;
        _rulesById = rulesById;
        Presets = presets;
        _presets = presets.ToDictionary(p => p.Key, StringComparer.OrdinalIgnoreCase);
    }

    public IReadOnlyList<DeclarativeTweakRule> Rules { get; }

    public IReadOnlyList<TweakPresetDescriptor> Presets { get; }

    public IReadOnlyCollection<string> PresetKeys => _presets.Keys;

    public DeclarativeTweakRule? FindById(string? tweakId) =>
        tweakId is not null && _rulesById.TryGetValue(tweakId, out var rule) ? rule : null;

    public TweakPresetDescriptor? FindPreset(string? presetKey) =>
        presetKey is not null && _presets.TryGetValue(presetKey, out var preset) ? preset : null;

    /// <summary>
    /// Идентификаторы твиков набора. Неизвестное название набора означает набор по умолчанию.
    /// </summary>
    public IReadOnlyList<string> GetPresetIds(string? presetKey) =>
        (FindPreset(presetKey) ?? _presets[TweakCatalogLoader.DefaultPresetKey]).TweakIds;
}

/// <summary>
/// Читает каталог твиков из JSON и проверяет его целиком. Ошибка в файле данных не должна дойти до системы
/// пользователя, поэтому любое отступление от формата — неизвестное поле, опечатка в названии куста реестра,
/// повтор идентификатора, число не того вида — останавливает загрузку с понятным сообщением
/// (<see cref="InvalidDataException"/>), в котором назван файл, твик и поле.
/// Каталог может состоять из нескольких файлов: твики и наборы из них складываются.
/// </summary>
public static class TweakCatalogLoader
{
    public const int SupportedSchemaVersion = 2;
    public const string DefaultPresetKey = "recommended";
    public const string BuiltInResourcePrefix = "UltimateWindows.Optimizer.Catalog.";

    private const string RootContext = "корень файла";

    private static readonly Regex TweakIdPattern = new(@"^[a-z0-9]+(\.[a-z0-9-]+)+$", RegexOptions.CultureInvariant);
    private static readonly Regex PresetKeyPattern = new(@"^[a-z0-9]+(-[a-z0-9]+)*$", RegexOptions.CultureInvariant);
    private static readonly Regex ServiceNamePattern = new(@"^[A-Za-z0-9_.\-]+$", RegexOptions.CultureInvariant);

    private static readonly string[] KnownHives = ["HKLM", "HKCU", "HKCR", "HKU"];

    private static readonly string[] RootFields = ["schemaVersion", "presets", "tweaks"];

    private static readonly string[] TweakFields =
    [
        "id", "category", "title", "explanation", "risk", "restart", "requirements", "actions"
    ];

    private static readonly string[] PresetFields = ["title", "description", "tweaks"];

    private static readonly string[] RequirementFields =
    [
        "minWindowsBuild", "maxWindowsBuild", "bestOnSolidStateSystemDrive", "batteryWarning", "installedAny", "installedNote"
    ];

    private static readonly string[] RegistryActionFields =
    [
        "type", "hive", "key", "name", "kind", "value", "default", "removeEmptyKey"
    ];

    private static readonly string[] ServiceActionFields = ["type", "name", "startup", "default"];

    private static readonly string[] TaskActionFields = ["type", "path", "enabled"];

    private static readonly RiskLevel[] AllowedRisks = [RiskLevel.Safe, RiskLevel.Low, RiskLevel.Moderate, RiskLevel.High];

    private static readonly RiskLevel[] PresetRisks = [RiskLevel.Safe, RiskLevel.Low];

    /// <summary>
    /// Каталог, встроенный в сборку (файлы <c>Catalog/Data/*.json</c>). Файлы читаются в порядке имён.
    /// </summary>
    public static TweakCatalogData LoadBuiltIn()
    {
        var assembly = typeof(TweakCatalogLoader).Assembly;
        var names = assembly.GetManifestResourceNames()
            .Where(n => n.StartsWith(BuiltInResourcePrefix, StringComparison.Ordinal) &&
                        n.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();

        if (names.Length == 0)
        {
            throw new InvalidDataException(
                $"Каталог твиков: в сборке нет встроенных файлов данных «{BuiltInResourcePrefix}*.json».");
        }

        var documents = new List<TweakCatalogDocument>(names.Length);
        foreach (var name in names)
        {
            using var stream = assembly.GetManifestResourceStream(name)
                ?? throw new InvalidDataException($"Каталог твиков: не удалось открыть встроенный файл данных «{name}».");
            using var reader = new StreamReader(stream, Encoding.UTF8);
            documents.Add(new TweakCatalogDocument(name[BuiltInResourcePrefix.Length..], reader.ReadToEnd()));
        }

        return ParseDocuments(documents);
    }

    /// <summary>
    /// Каталог из одного файла данных.
    /// </summary>
    public static TweakCatalogData Parse(string json) => ParseDocuments([new TweakCatalogDocument("", json)]);

    public static TweakCatalogData ParseDocuments(IEnumerable<TweakCatalogDocument> documents)
    {
        ArgumentNullException.ThrowIfNull(documents);

        var rules = new List<DeclarativeTweakRule>();
        var rulesById = new Dictionary<string, DeclarativeTweakRule>(StringComparer.OrdinalIgnoreCase);
        var rawPresets = new List<RawPreset>();
        var documentCount = 0;

        foreach (var document in documents)
        {
            documentCount++;
            var file = string.IsNullOrWhiteSpace(document.Name) ? "" : $"файл «{document.Name}», ";
            ParseDocument(document.Json, file, rules, rulesById, rawPresets);
        }

        if (documentCount == 0 || rules.Count == 0)
        {
            throw new InvalidDataException("Каталог твиков: в файлах данных нет ни одного твика (список «tweaks» пуст).");
        }

        return new TweakCatalogData(rules.ToArray(), rulesById, ResolvePresets(rawPresets, rulesById));
    }

    private static void ParseDocument(
        string json,
        string file,
        List<DeclarativeTweakRule> rules,
        Dictionary<string, DeclarativeTweakRule> rulesById,
        List<RawPreset> rawPresets)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            throw new InvalidDataException($"Каталог твиков: {file}файл данных пуст.");
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
            throw new InvalidDataException($"Каталог твиков: {file}файл данных не является корректным JSON. {ex.Message}", ex);
        }

        using (document)
        {
            var root = document.RootElement;
            var rootContext = file + RootContext;
            RequireObject(root, rootContext);
            RejectUnknownFields(root, rootContext, RootFields);

            var version = RequireInt(root, "schemaVersion", rootContext);
            if (version != SupportedSchemaVersion)
            {
                throw Error(
                    rootContext,
                    $"версия формата {version} не поддерживается: эта версия программы понимает версию {SupportedSchemaVersion}.");
            }

            var hasTweaks = root.TryGetProperty("tweaks", out var tweaksElement);
            var hasPresets = root.TryGetProperty("presets", out var presetsElement);
            if (!hasTweaks && !hasPresets)
            {
                throw Error(rootContext, "нет ни списка «tweaks», ни раздела «presets».");
            }

            if (hasTweaks)
            {
                if (tweaksElement.ValueKind != JsonValueKind.Array)
                {
                    throw Error(rootContext, "«tweaks» должен быть списком в квадратных скобках.");
                }

                var index = 0;
                foreach (var tweakElement in tweaksElement.EnumerateArray())
                {
                    index++;
                    var rule = ParseTweak(tweakElement, file, index);
                    if (!rulesById.TryAdd(rule.TweakId, rule))
                    {
                        throw Error(file + DescribeTweak(rule.TweakId), "такой идентификатор уже есть у другого твика.");
                    }

                    rules.Add(rule);
                }
            }

            if (hasPresets)
            {
                ParsePresets(presetsElement, file, rawPresets);
            }
        }
    }

    private static DeclarativeTweakRule ParseTweak(JsonElement element, string file, int index)
    {
        var context = $"{file}твик №{index}";
        RequireObject(element, context);

        var id = RequireString(element, "id", context);
        context = file + DescribeTweak(id);
        if (!TweakIdPattern.IsMatch(id))
        {
            throw Error(
                context,
                "идентификатор пишется строчными латинскими буквами, цифрами и дефисами, части разделяются точкой — например «privacy.disable-something».");
        }

        RejectUnknownFields(element, context, TweakFields);

        var category = RequireEnum<TweakCategory>(element, "category", context);
        var title = RequireString(element, "title", context);
        var explanation = RequireString(element, "explanation", context);
        var risk = RequireEnum<RiskLevel>(element, "risk", context);
        if (Array.IndexOf(AllowedRisks, risk) < 0)
        {
            throw Error(
                context,
                $"поле «risk»: для твиков допустимы значения {string.Join(", ", AllowedRisks)}.");
        }

        var restart = TweakRestartKind.None;
        if (element.TryGetProperty("restart", out _))
        {
            var restartText = RequireString(element, "restart", context);
            restart = restartText switch
            {
                "none" => TweakRestartKind.None,
                "explorer" => TweakRestartKind.ExplorerRestart,
                "signout" => TweakRestartKind.SignOut,
                "reboot" => TweakRestartKind.Reboot,
                _ => throw Error(context, $"поле «restart»: неизвестное значение «{restartText}». Допустимые: none, explorer, signout, reboot.")
            };
        }

        TweakRequirements? requirements = null;
        if (element.TryGetProperty("requirements", out var requirementsElement))
        {
            requirements = ParseRequirements(requirementsElement, $"{context}, условия применимости");
        }

        var actions = new List<TweakAction>();
        var targets = new HashSet<string>(StringComparer.Ordinal);
        var actionIndex = 0;
        foreach (var actionElement in RequireArray(element, "actions", context).EnumerateArray())
        {
            actionIndex++;
            var actionContext = $"{context}, действие №{actionIndex}";
            var action = ParseAction(actionElement, actionContext);
            if (!targets.Add(action.TargetKey))
            {
                throw Error(actionContext, "эта цель уже меняется другим действием того же твика.");
            }

            actions.Add(action);
        }

        if (actions.Count == 0)
        {
            throw Error(context, "нет ни одного действия.");
        }

        var rule = new DeclarativeTweakRule(
            id,
            category,
            title,
            explanation,
            risk,
            actions.ToArray(),
            requirements,
            restart);

        try
        {
            TweakSafetyGuard.ThrowIfUnsafeRule(rule);
        }
        catch (InvalidOperationException ex)
        {
            throw new InvalidDataException($"Каталог твиков: {file}{ex.Message}", ex);
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

        string[]? installedAny = null;
        if (element.TryGetProperty("installedAny", out var installedElement))
        {
            if (installedElement.ValueKind != JsonValueKind.Array)
            {
                throw Error(context, "«installedAny» — список разделов реестра в квадратных скобках.");
            }

            var keys = new List<string>();
            foreach (var item in installedElement.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.String)
                {
                    throw Error(context, "«installedAny»: разделы реестра пишутся в кавычках.");
                }

                var path = item.GetString() ?? string.Empty;
                if (!TrySplitRegistryPath(path, out var hive, out var key) || Array.IndexOf(KnownHives, hive) < 0 || !IsWellFormedKeyPath(key))
                {
                    throw Error(context, $"«installedAny»: «{path}» — не путь раздела реестра вида «HKLM\\SOFTWARE\\Пример».");
                }

                keys.Add($@"{hive}\{key}");
            }

            if (keys.Count == 0)
            {
                throw Error(context, "«installedAny» пуст.");
            }

            installedAny = keys.ToArray();
        }

        var installedNote = element.TryGetProperty("installedNote", out _)
            ? RequireString(element, "installedNote", context)
            : null;

        if ((installedAny is null) != (installedNote is null))
        {
            throw Error(context, "«installedAny» и «installedNote» задаются вместе: список разделов и пояснение, какой программы нет.");
        }

        if (min is null && max is null && !bestOnSsd && batteryWarning is null && installedAny is null)
        {
            throw Error(context, "раздел пуст. Если условий нет, удалите «requirements» целиком.");
        }

        return new TweakRequirements(min, max, bestOnSsd, batteryWarning, installedAny, installedNote);
    }

    private static TweakAction ParseAction(JsonElement element, string context)
    {
        RequireObject(element, context);
        var type = RequireString(element, "type", context);
        return type switch
        {
            "registry" => ParseRegistryAction(element, context),
            "service" => ParseServiceAction(element, context),
            "task" => ParseTaskAction(element, context),
            _ => throw Error(context, $"неизвестный тип действия «{type}». Эта версия программы понимает типы registry, service, task.")
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
        if (!IsWellFormedKeyPath(key))
        {
            throw Error(context, "путь раздела «key» пишется через одну обратную косую черту, без неё в начале и в конце.");
        }

        // Пустое имя — это значение «(По умолчанию)» раздела
        var name = RequireString(element, "name", context, allowEmpty: true);

        if (string.Equals(name, "Start", StringComparison.OrdinalIgnoreCase) &&
            TweakSafetyGuard.TryGetServiceNameFromRegistryPath(key) is { } serviceName &&
            key.EndsWith(@"\" + serviceName, StringComparison.OrdinalIgnoreCase))
        {
            throw Error(
                context,
                $"тип запуска службы «{serviceName}» задаётся действием типа «service», а не записью значения Start в реестр: так изменение сразу видит диспетчер служб.");
        }

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

        if (standard is not null && string.Equals(standard, desired, StringComparison.OrdinalIgnoreCase))
        {
            throw Error(context, "«value» совпадает с «default»: такое действие ничего не меняет.");
        }

        var removeEmptyKey = element.TryGetProperty("removeEmptyKey", out _) && RequireBool(element, "removeEmptyKey", context);
        if (removeEmptyKey && standard is not null)
        {
            throw Error(context, "«removeEmptyKey» имеет смысл только без «default»: раздел удаляется, когда удалено значение.");
        }

        return new TweakRegistryMutation(
            hive,
            key,
            name,
            kind,
            desired,
            standard ?? string.Empty,
            ExistedByDefault: standard is not null,
            RemoveEmptyKeyOnRestore: removeEmptyKey);
    }

    private static TweakServiceAction ParseServiceAction(JsonElement element, string context)
    {
        RejectUnknownFields(element, context, ServiceActionFields);

        var name = RequireString(element, "name", context);
        if (!ServiceNamePattern.IsMatch(name))
        {
            throw Error(context, $"«{name}» — не имя службы. Нужно короткое имя (например DiagTrack), а не отображаемое название.");
        }

        var startup = ReadStartupMode(element, "startup", context);
        var standard = ReadStartupMode(element, "default", context);
        if (startup == standard)
        {
            throw Error(context, "«startup» совпадает с «default»: такое действие ничего не меняет.");
        }

        return new TweakServiceAction(name, startup, standard);
    }

    private static ServiceStartupMode ReadStartupMode(JsonElement element, string field, string context)
    {
        var text = RequireString(element, field, context);
        return text switch
        {
            "automatic" => ServiceStartupMode.Automatic,
            "automaticDelayed" => ServiceStartupMode.AutomaticDelayed,
            "manual" => ServiceStartupMode.Manual,
            "disabled" => ServiceStartupMode.Disabled,
            _ => throw Error(context, $"поле «{field}»: неизвестный тип запуска «{text}». Допустимые: automatic, automaticDelayed, manual, disabled.")
        };
    }

    private static TweakScheduledTaskAction ParseTaskAction(JsonElement element, string context)
    {
        RejectUnknownFields(element, context, TaskActionFields);

        var path = RequireString(element, "path", context);
        if (!path.StartsWith('\\') || path.EndsWith('\\') || path.Contains('/') || path.Contains(@"\\", StringComparison.Ordinal))
        {
            throw Error(context, "путь задания «path» начинается с обратной косой черты и содержит папку и имя, например «\\Microsoft\\Windows\\Maps\\MapsUpdateTask».");
        }

        var enabled = RequireBool(element, "enabled", context);
        return new TweakScheduledTaskAction(path, enabled);
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

    private static bool IsWellFormedKeyPath(string key) =>
        !string.IsNullOrWhiteSpace(key) &&
        !key.Contains('/') &&
        !key.StartsWith('\\') &&
        !key.EndsWith('\\') &&
        !key.Contains(@"\\", StringComparison.Ordinal);

    /// <summary>
    /// Делит запись «HKLM\SOFTWARE\Пример» на куст и путь раздела.
    /// </summary>
    public static bool TrySplitRegistryPath(string? path, out string hive, out string key)
    {
        hive = string.Empty;
        key = string.Empty;
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var separator = path.IndexOf('\\');
        if (separator <= 0 || separator == path.Length - 1)
        {
            return false;
        }

        hive = path[..separator];
        key = path[(separator + 1)..];
        return true;
    }

    // ---------------------------------------------------------------------------------------------
    // Готовые наборы
    // ---------------------------------------------------------------------------------------------

    private sealed record RawPreset(string Key, string Title, string Description, IReadOnlyList<string> Ids, string Context);

    private static void ParsePresets(JsonElement presetsElement, string file, List<RawPreset> sink)
    {
        var sectionContext = $"{file}раздел «presets»";
        RequireObject(presetsElement, sectionContext);

        foreach (var preset in presetsElement.EnumerateObject())
        {
            var context = $"{file}набор «{preset.Name}»";
            if (!PresetKeyPattern.IsMatch(preset.Name))
            {
                throw Error(context, "название набора пишется строчными латинскими буквами, цифрами и дефисами, например «clean-ui».");
            }

            if (sink.Exists(p => string.Equals(p.Key, preset.Name, StringComparison.OrdinalIgnoreCase)))
            {
                throw Error(context, "набор с таким названием уже есть.");
            }

            RequireObject(preset.Value, context);
            RejectUnknownFields(preset.Value, context, PresetFields);

            var title = RequireString(preset.Value, "title", context);
            var description = RequireString(preset.Value, "description", context);

            var ids = new List<string>();
            foreach (var item in RequireArray(preset.Value, "tweaks", context).EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.String)
                {
                    throw Error(context, "идентификаторы твиков пишутся в кавычках.");
                }

                ids.Add(item.GetString() ?? string.Empty);
            }

            if (ids.Count == 0)
            {
                throw Error(context, "набор пуст.");
            }

            sink.Add(new RawPreset(preset.Name, title, description, ids, context));
        }
    }

    private static IReadOnlyList<TweakPresetDescriptor> ResolvePresets(
        List<RawPreset> rawPresets,
        Dictionary<string, DeclarativeTweakRule> rulesById)
    {
        var presets = new List<TweakPresetDescriptor>(rawPresets.Count);
        foreach (var raw in rawPresets)
        {
            var ids = new List<string>(raw.Ids.Count);
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var id in raw.Ids)
            {
                if (!rulesById.TryGetValue(id, out var rule))
                {
                    throw Error(raw.Context, $"твика «{id}» нет в каталоге.");
                }

                if (rule.IsDangerous)
                {
                    throw Error(raw.Context, $"«{id}» — опасный твик, в наборы такие не входят.");
                }

                if (Array.IndexOf(PresetRisks, rule.Risk) < 0)
                {
                    throw Error(raw.Context, $"«{id}» — твик с оговорками (риск {rule.Risk}); в наборы входят только твики с риском Safe или Low.");
                }

                if (!seen.Add(id))
                {
                    throw Error(raw.Context, $"твик «{id}» указан дважды.");
                }

                ids.Add(rule.TweakId);
            }

            presets.Add(new TweakPresetDescriptor(raw.Key, raw.Title, raw.Description, ids.ToArray()));
        }

        if (!presets.Exists(p => string.Equals(p.Key, DefaultPresetKey, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidDataException($"Каталог твиков: нет обязательного набора «{DefaultPresetKey}» (раздел «presets»).");
        }

        return presets.ToArray();
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
