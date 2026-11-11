using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace UltimateWindows.Modules.Cleaner.Rules;

/// <summary>
/// Один файл данных каталога: имя (для сообщений об ошибках) и содержимое JSON.
/// </summary>
public sealed record CleanupRuleDocument(string Name, string Json);

/// <summary>
/// Каталог правил очистки, прочитанный из файлов данных, в порядке применения.
/// Порядок важен: файл достаётся первому правилу, которое его нашло, поэтому точные правила идут раньше общих.
/// </summary>
public sealed class CleanupRuleCatalog
{
    private readonly Dictionary<string, CleanupRule> _byId;

    internal CleanupRuleCatalog(IReadOnlyList<CleanupRule> rules)
    {
        Rules = rules;
        _byId = rules.ToDictionary(r => r.Id, StringComparer.OrdinalIgnoreCase);
    }

    public IReadOnlyList<CleanupRule> Rules { get; }

    public CleanupRule? FindById(string? id) =>
        id is not null && _byId.TryGetValue(id, out var rule) ? rule : null;
}

/// <summary>
/// Читает каталог правил очистки из JSON и проверяет его целиком. Правило с ошибкой не должно дойти до диска
/// пользователя, поэтому любое отступление от формата останавливает загрузку с сообщением
/// (<see cref="InvalidDataException"/>), в котором названы файл, правило и поле.
/// Формат описан в docs/07-CLEANUP-RULES.md.
/// </summary>
public static class CleanupRuleCatalogLoader
{
    public const int SupportedSchemaVersion = 1;
    public const string BuiltInResourcePrefix = "UltimateWindows.Cleaner.Rules.";

    private static readonly Regex RuleIdPattern = new(@"^[a-z0-9]+(\.[a-z0-9-]+)+$", RegexOptions.CultureInvariant);
    private static readonly Regex ProcessNamePattern = new(@"^[A-Za-z0-9 _.\-+]+$", RegexOptions.CultureInvariant);

    private static readonly string[] RootFields = ["schemaVersion", "rules"];

    private static readonly string[] RuleFields =
    [
        "id", "section", "app", "title", "explanation", "kind", "default", "warning", "detect", "processes",
        "skipWhileRunning", "minAgeHours", "files", "exclude", "groupLabels"
    ];

    private static readonly string[] FileFields = ["path", "match", "recurse", "removeEmptyFolders", "removeSelf", "group"];
    private static readonly string[] ExcludeFields = ["path", "match"];
    private static readonly string[] DetectFields = ["anyPath", "anyRegistryKey", "minWindowsBuild", "maxWindowsBuild"];

    private static readonly Lazy<CleanupRuleCatalog> BuiltIn = new(LoadBuiltInCore);

    /// <summary>
    /// Каталог, встроенный в программу. Читается один раз.
    /// </summary>
    public static CleanupRuleCatalog LoadBuiltIn() => BuiltIn.Value;

    public static IReadOnlyList<CleanupRuleDocument> ReadBuiltInDocuments()
    {
        var assembly = typeof(CleanupRuleCatalogLoader).Assembly;
        var names = assembly.GetManifestResourceNames()
            .Where(n => n.StartsWith(BuiltInResourcePrefix, StringComparison.Ordinal) &&
                        n.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        if (names.Count == 0)
        {
            throw new InvalidDataException("Каталог правил очистки: в сборке нет встроенных файлов данных.");
        }

        var documents = new List<CleanupRuleDocument>(names.Count);
        foreach (var name in names)
        {
            using var stream = assembly.GetManifestResourceStream(name)
                ?? throw new InvalidDataException($"Каталог правил очистки: не удалось открыть встроенный файл «{name}».");
            using var reader = new StreamReader(stream, Encoding.UTF8);
            documents.Add(new CleanupRuleDocument(name[BuiltInResourcePrefix.Length..], reader.ReadToEnd()));
        }

        return documents;
    }

    public static CleanupRuleCatalog Load(IEnumerable<CleanupRuleDocument> documents)
    {
        ArgumentNullException.ThrowIfNull(documents);

        var rules = new List<CleanupRule>();
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var document in documents)
        {
            var file = $"файл «{document.Name}», ";
            if (string.IsNullOrWhiteSpace(document.Json))
            {
                throw Error(file + "корень файла", "файл данных пуст.");
            }

            JsonDocument json;
            try
            {
                json = JsonDocument.Parse(document.Json, new JsonDocumentOptions
                {
                    CommentHandling = JsonCommentHandling.Skip,
                    AllowTrailingCommas = true
                });
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException(
                    $"Каталог правил очистки: {file}файл не является корректным JSON. {ex.Message}", ex);
            }

            using (json)
            {
                var root = json.RootElement;
                var rootContext = file + "корень файла";
                RequireObject(root, rootContext);
                RejectUnknownFields(root, rootContext, RootFields);

                var version = RequireInt(root, "schemaVersion", rootContext);
                if (version != SupportedSchemaVersion)
                {
                    throw Error(rootContext, $"версия формата {version} не поддерживается, нужна {SupportedSchemaVersion}.");
                }

                var index = 0;
                foreach (var element in RequireArray(root, "rules", rootContext).EnumerateArray())
                {
                    index++;
                    var rule = ParseRule(element, file, index, document.Name);
                    if (!ids.Add(rule.Id))
                    {
                        throw Error($"{file}правило «{rule.Id}»", "такой идентификатор уже есть у другого правила.");
                    }

                    rules.Add(rule);
                }
            }
        }

        if (rules.Count == 0)
        {
            throw new InvalidDataException("Каталог правил очистки: в файлах данных нет ни одного правила.");
        }

        return new CleanupRuleCatalog(rules);
    }

    private static CleanupRuleCatalog LoadBuiltInCore() => Load(ReadBuiltInDocuments());

    private static CleanupRule ParseRule(JsonElement element, string file, int index, string sourceName)
    {
        var context = $"{file}правило №{index}";
        RequireObject(element, context);

        var id = RequireString(element, "id", context);
        context = $"{file}правило «{id}»";
        if (!RuleIdPattern.IsMatch(id))
        {
            throw Error(context, "идентификатор пишется строчными латинскими буквами, цифрами и дефисами, части разделяются точкой — например «win.temp-user».");
        }

        RejectUnknownFields(element, context, RuleFields);

        var section = RequireEnum<CleanupSection>(element, "section", context);
        var application = RequireString(element, "app", context);
        var title = RequireString(element, "title", context);
        var explanation = RequireString(element, "explanation", context);
        var kind = RequireEnum<CleanupDataKind>(element, "kind", context);
        var selectedByDefault = RequireBool(element, "default", context);
        var warning = OptionalString(element, "warning", context);
        var skipWhileRunning = OptionalBool(element, "skipWhileRunning", context) ?? false;
        var minAge = OptionalInt(element, "minAgeHours", context) ?? 0;
        if (minAge is < 0 or > 8760)
        {
            throw Error(context, "поле «minAgeHours» — число часов от 0 до 8760.");
        }

        var processes = new List<string>();
        foreach (var name in OptionalStringArray(element, "processes", context))
        {
            if (!ProcessNamePattern.IsMatch(name) || name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                throw Error(context, $"поле «processes»: «{name}» — имя процесса пишется без пути и без «.exe».");
            }

            processes.Add(name);
        }

        var files = new List<CleanupFileTarget>();
        var fileIndex = 0;
        foreach (var fileElement in RequireArray(element, "files", context).EnumerateArray())
        {
            fileIndex++;
            files.Add(ParseFileTarget(fileElement, $"{context}, папка №{fileIndex}"));
        }

        if (files.Count == 0)
        {
            throw Error(context, "нет ни одной папки в списке «files».");
        }

        var exclusions = new List<CleanupExclusion>();
        if (element.TryGetProperty("exclude", out var excludeElement))
        {
            if (excludeElement.ValueKind != JsonValueKind.Array)
            {
                throw Error(context, "«exclude» должен быть списком в квадратных скобках.");
            }

            var excludeIndex = 0;
            foreach (var item in excludeElement.EnumerateArray())
            {
                excludeIndex++;
                var excludeContext = $"{context}, исключение №{excludeIndex}";
                RequireObject(item, excludeContext);
                RejectUnknownFields(item, excludeContext, ExcludeFields);
                var path = RequirePath(item, "path", excludeContext, allowRegistryVariable: true);
                var match = OptionalStringArray(item, "match", excludeContext).Select(CleanupPathPattern.NormalizeFilePattern).ToArray();
                exclusions.Add(new CleanupExclusion(path, match));
            }
        }

        CleanupDetection? detection = null;
        if (element.TryGetProperty("detect", out var detectElement))
        {
            detection = ParseDetection(detectElement, $"{context}, условие «detect»");
        }

        var labels = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (element.TryGetProperty("groupLabels", out var labelsElement))
        {
            if (labelsElement.ValueKind != JsonValueKind.Object)
            {
                throw Error(context, "«groupLabels» — объект «имя папки»: «название программы».");
            }

            foreach (var property in labelsElement.EnumerateObject())
            {
                if (property.Value.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(property.Value.GetString()))
                {
                    throw Error(context, $"«groupLabels»: у папки «{property.Name}» нет названия.");
                }

                labels[property.Name.Replace('/', '\\')] = property.Value.GetString()!.Trim();
            }
        }

        var grouped = files.Any(f => f.GroupCaptures > 0);
        if (grouped && files.Any(f => f.GroupCaptures == 0))
        {
            throw Error(context, "в общем правиле поле «group» нужно у каждой папки.");
        }

        if (!grouped && labels.Count > 0)
        {
            throw Error(context, "«groupLabels» имеет смысл только вместе с полем «group» у папок.");
        }

        return new CleanupRule(id, section, application, title, explanation, kind, selectedByDefault, files)
        {
            Warning = warning,
            Detection = detection,
            Processes = processes,
            SkipWhileRunning = skipWhileRunning,
            MinimumAgeHours = minAge,
            Exclusions = exclusions,
            GroupLabels = labels,
            Origin = CleanupRuleOrigin.BuiltIn,
            SourceName = sourceName
        };
    }

    private static CleanupFileTarget ParseFileTarget(JsonElement element, string context)
    {
        RequireObject(element, context);
        RejectUnknownFields(element, context, FileFields);

        var path = RequirePath(element, "path", context, allowRegistryVariable: true);
        CleanupPathPattern.TryParse(path, allowRegistryVariable: true, out var pattern, out _);

        var match = OptionalStringArray(element, "match", context).Select(CleanupPathPattern.NormalizeFilePattern).ToList();
        if (match.Count == 0)
        {
            match.Add("*");
        }

        foreach (var mask in match)
        {
            if (mask.Contains('\\') || mask.Contains('/'))
            {
                throw Error(context, $"поле «match»: «{mask}» — маска имени файла, без папок.");
            }
        }

        var recurse = OptionalBool(element, "recurse", context) ?? true;
        var removeEmptyFolders = OptionalBool(element, "removeEmptyFolders", context) ?? recurse;
        var removeSelf = OptionalBool(element, "removeSelf", context) ?? false;
        var group = OptionalInt(element, "group", context) ?? 0;
        if (group < 0 || group > pattern.WildcardCount)
        {
            throw Error(context, $"поле «group»: в пути звёздочек {pattern.WildcardCount}, а название программы просят собрать из {group}.");
        }

        if (pattern.Segments.Count == 0 && (recurse || match.Contains("*")))
        {
            throw Error(context, "папку, на которую указывает переменная, нельзя чистить целиком: добавьте вложенную папку или точные маски файлов.");
        }

        return new CleanupFileTarget(path, match, recurse, removeEmptyFolders, removeSelf, group);
    }

    private static CleanupDetection ParseDetection(JsonElement element, string context)
    {
        RequireObject(element, context);
        RejectUnknownFields(element, context, DetectFields);

        var paths = new List<string>();
        if (element.TryGetProperty("anyPath", out var pathsElement))
        {
            if (pathsElement.ValueKind != JsonValueKind.Array)
            {
                throw Error(context, "«anyPath» — список путей в квадратных скобках.");
            }

            foreach (var item in pathsElement.EnumerateArray())
            {
                var text = item.ValueKind == JsonValueKind.String ? item.GetString() : null;
                if (!CleanupPathPattern.TryParse(text, allowRegistryVariable: true, out _, out var error))
                {
                    throw Error(context, $"«anyPath»: «{text}» — {error}.");
                }

                paths.Add(text!.Trim());
            }
        }

        var keys = new List<string>();
        foreach (var key in OptionalStringArray(element, "anyRegistryKey", context))
        {
            if (!CleanupPathPattern.IsSupportedRegistryKey(key))
            {
                throw Error(context, $"«anyRegistryKey»: «{key}» — раздел реестра пишется как HKCU\\Раздел или HKLM\\Раздел.");
            }

            keys.Add(key);
        }

        var min = OptionalInt(element, "minWindowsBuild", context);
        var max = OptionalInt(element, "maxWindowsBuild", context);
        if (paths.Count == 0 && keys.Count == 0 && min is null && max is null)
        {
            throw Error(context, "условие пусто. Если условий нет, удалите «detect» целиком.");
        }

        return new CleanupDetection(paths, keys, min, max);
    }

    // ---------------------------------------------------------------------------------------------
    // Разбор полей
    // ---------------------------------------------------------------------------------------------

    private static InvalidDataException Error(string context, string message) =>
        new($"Каталог правил очистки: {context}: {message}");

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

    private static string RequireString(JsonElement element, string name, string context)
    {
        if (!element.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String)
        {
            throw Error(context, $"нет обязательного текстового поля «{name}».");
        }

        var text = value.GetString()!.Trim();
        if (text.Length == 0)
        {
            throw Error(context, $"поле «{name}» пустое.");
        }

        return text;
    }

    private static string? OptionalString(JsonElement element, string name, string context)
    {
        if (!element.TryGetProperty(name, out var value))
        {
            return null;
        }

        if (value.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(value.GetString()))
        {
            throw Error(context, $"поле «{name}» должно быть непустым текстом.");
        }

        return value.GetString()!.Trim();
    }

    private static string RequirePath(JsonElement element, string name, string context, bool allowRegistryVariable)
    {
        var text = RequireString(element, name, context);
        if (!CleanupPathPattern.TryParse(text, allowRegistryVariable, out _, out var error))
        {
            throw Error(context, $"поле «{name}»: {error}.");
        }

        return text;
    }

    private static IReadOnlyList<string> OptionalStringArray(JsonElement element, string name, string context)
    {
        if (!element.TryGetProperty(name, out var value))
        {
            return [];
        }

        if (value.ValueKind != JsonValueKind.Array)
        {
            throw Error(context, $"«{name}» должен быть списком в квадратных скобках.");
        }

        var list = new List<string>();
        foreach (var item in value.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(item.GetString()))
            {
                throw Error(context, $"«{name}»: значения пишутся в кавычках и не бывают пустыми.");
            }

            list.Add(item.GetString()!.Trim());
        }

        return list;
    }

    private static bool RequireBool(JsonElement element, string name, string context) =>
        OptionalBool(element, name, context)
        ?? throw Error(context, $"нет обязательного поля «{name}» со значением true или false.");

    private static bool? OptionalBool(JsonElement element, string name, string context)
    {
        if (!element.TryGetProperty(name, out var value))
        {
            return null;
        }

        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => throw Error(context, $"поле «{name}» принимает значения true или false.")
        };
    }

    private static int RequireInt(JsonElement element, string name, string context) =>
        OptionalInt(element, name, context) ?? throw Error(context, $"нет обязательного числового поля «{name}».");

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
        if (!Enum.TryParse<TEnum>(text, ignoreCase: false, out var value) || !Enum.IsDefined(value) || char.IsDigit(text[0]))
        {
            throw Error(context, $"поле «{name}»: неизвестное значение «{text}». Допустимые: {string.Join(", ", Enum.GetNames<TEnum>())}.");
        }

        return value;
    }
}
