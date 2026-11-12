using System.Reflection;
using System.Text.Json;
using UltimateWindows.Core.Enums;

namespace UltimateWindows.Modules.Repair.Diagnostics;

/// <summary>
/// Загрузчик и строгий валидатор встроенного каталога правил диагностики и ремонта (Diagnostics/Data/*.json).
/// Проверяет схему v1, уникальность идентификаторов, русскоязычные пояснения и запрет обхода лицензирования Windows.
/// </summary>
public static class RepairCatalogLoader
{
    public const string ResourcePrefix = "UltimateWindows.Repair.Diagnostics.";

    public static readonly IReadOnlySet<string> SupportedCustomProbes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "wu-pending-reboot",
        "wu-corrupt-cache",
        "net-dead-local-proxy",
        "net-hosts-health",
        "net-dns-winsock",
        "shell-ctfmon-typing",
        "shell-win11-xaml-packages",
        "shell-icon-thumb-cache",
        "shell-recycle-bin",
        "store-cache-health",
        "print-stuck-queue",
        "time-ntp-sync",
        "wmi-repository",
        "sfc-cbs-health",
        "disk-dirty-and-temp",
        "disk-low-free-space",
        "sys-path-system32",
        "font-cache-health"
    };

    private static readonly Lazy<IReadOnlyList<RepairRuleDefinition>> CachedBuiltIn =
        new(LoadBuiltInInternal, isThreadSafe: true);

    public static IReadOnlyList<RepairRuleDefinition> LoadBuiltInCatalog() => CachedBuiltIn.Value;

    public static IReadOnlyList<RepairRuleDefinition> ParseCatalogJson(
        string json,
        string sourceLabel,
        HashSet<string>? seenIds = null)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            throw new InvalidDataException($"Файл каталога ремонта «{sourceLabel}» пуст.");
        }

        seenIds ??= new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions
        {
            CommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true
        });

        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException($"Корневой элемент «{sourceLabel}» должен быть JSON-объектом.");
        }

        var schemaVersion = RequireInt(root, "schemaVersion", sourceLabel);
        if (schemaVersion != 1)
        {
            throw new InvalidDataException($"«{sourceLabel}»: поддерживается schemaVersion=1 (получено {schemaVersion}).");
        }

        var defaultSectionStr = OptionalString(root, "section");
        RepairSectionId? fileSection = null;
        if (!string.IsNullOrWhiteSpace(defaultSectionStr))
        {
            fileSection = ParseEnum<RepairSectionId>(defaultSectionStr, $"{sourceLabel}:section");
        }

        if (!root.TryGetProperty("rules", out var rulesEl) || rulesEl.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException($"«{sourceLabel}»: отсутствует массив «rules».");
        }

        var parsed = new List<RepairRuleDefinition>();
        var idx = 0;
        foreach (var item in rulesEl.EnumerateArray())
        {
            var ctx = $"{sourceLabel}#rules[{idx++}]";
            var rule = ParseRule(item, fileSection, ctx);
            if (!seenIds.Add(rule.Id))
            {
                throw new InvalidDataException($"Дублирующийся идентификатор правила ремонта: «{rule.Id}» ({ctx}).");
            }

            parsed.Add(rule);
        }

        if (parsed.Count == 0)
        {
            throw new InvalidDataException($"«{sourceLabel}»: массив «rules» не содержит ни одного правила.");
        }

        return parsed;
    }

    private static IReadOnlyList<RepairRuleDefinition> LoadBuiltInInternal()
    {
        var asm = typeof(RepairCatalogLoader).Assembly;
        var names = asm.GetManifestResourceNames()
            .Where(n => n.StartsWith(ResourcePrefix, StringComparison.Ordinal) &&
                        n.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (names.Count == 0)
        {
            throw new InvalidOperationException("В сборке UltimateWindows.Modules.Repair не найдены встроенные ресурсы правил Diagnostics/Data/*.json.");
        }

        var all = new List<RepairRuleDefinition>(96);
        var seenIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var resourceName in names)
        {
            using var stream = asm.GetManifestResourceStream(resourceName)
                ?? throw new InvalidOperationException($"Не удалось открыть ресурс «{resourceName}».");
            using var reader = new StreamReader(stream);
            var json = reader.ReadToEnd();
            var label = resourceName[ResourcePrefix.Length..];
            all.AddRange(ParseCatalogJson(json, label, seenIds));
        }

        return all;
    }

    private static RepairRuleDefinition ParseRule(
        JsonElement el,
        RepairSectionId? defaultSection,
        string ctx)
    {
        if (el.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException($"{ctx}: правило должно быть объектом.");
        }

        var id = RequireString(el, "id", ctx);
        var sectionStr = OptionalString(el, "section");
        var section = !string.IsNullOrWhiteSpace(sectionStr)
            ? ParseEnum<RepairSectionId>(sectionStr, $"{ctx}({id}):section")
            : defaultSection ?? throw new InvalidDataException($"{ctx}({id}): не указан раздел «section».");

        var title = RequireString(el, "title", ctx);
        var symptom = RequireString(el, "symptom", ctx);
        var explanation = RequireString(el, "explanation", ctx);
        var fixSummary = RequireString(el, "fixSummary", ctx);
        var severity = ParseEnum<RepairSeverity>(OptionalString(el, "severity") ?? "Broken", $"{ctx}({id}):severity");
        var risk = ParseEnum<RiskLevel>(OptionalString(el, "risk") ?? "Safe", $"{ctx}({id}):risk");
        var requiresAdmin = OptionalBool(el, "requiresAdmin") ?? true;
        var reversible = OptionalBool(el, "reversible") ?? true;
        var minBuild = OptionalInt(el, "minBuild");
        var maxBuild = OptionalInt(el, "maxBuild");

        if (minBuild.HasValue && maxBuild.HasValue && minBuild.Value > maxBuild.Value)
        {
            throw new InvalidDataException($"{ctx}({id}): minBuild ({minBuild}) больше maxBuild ({maxBuild}).");
        }

        var errorCodes = new List<string>();
        if (el.TryGetProperty("errorCodes", out var codesEl) && codesEl.ValueKind == JsonValueKind.Array)
        {
            foreach (var c in codesEl.EnumerateArray())
            {
                var s = c.GetString();
                if (!string.IsNullOrWhiteSpace(s)) errorCodes.Add(s.Trim());
            }
        }

        var regChecks = new List<RepairRegistryCheck>();
        if (el.TryGetProperty("registry", out var regEl) && regEl.ValueKind == JsonValueKind.Array)
        {
            foreach (var r in regEl.EnumerateArray())
            {
                var rc = ParseRegistryCheck(r, $"{ctx}({id}):registry");
                ValidateNotLicensingBypass($"{rc.Hive}\\{rc.SubKey}\\{rc.ValueName}", $"{ctx}({id})");
                regChecks.Add(rc);
            }
        }

        var svcChecks = new List<RepairServiceCheck>();
        if (el.TryGetProperty("services", out var svcEl) && svcEl.ValueKind == JsonValueKind.Array)
        {
            foreach (var s in svcEl.EnumerateArray())
            {
                var sc = ParseServiceCheck(s, $"{ctx}({id}):services");
                ValidateNotLicensingBypass(sc.ServiceName, $"{ctx}({id})");
                svcChecks.Add(sc);
            }
        }

        var customProbe = OptionalString(el, "customProbe");
        if (!string.IsNullOrWhiteSpace(customProbe) && !SupportedCustomProbes.Contains(customProbe))
        {
            throw new InvalidDataException($"{ctx}({id}): неизвестный идентификатор customProbe «{customProbe}».");
        }

        if (regChecks.Count == 0 && svcChecks.Count == 0 && string.IsNullOrWhiteSpace(customProbe))
        {
            throw new InvalidDataException($"{ctx}({id}): у правила должна быть хотя бы одна проверка (registry, services или customProbe).");
        }

        return new RepairRuleDefinition(
            Id: id,
            Section: section,
            Title: title,
            Symptom: symptom,
            Explanation: explanation,
            FixSummary: fixSummary,
            Severity: severity,
            Risk: risk,
            RequiresAdmin: requiresAdmin,
            IsReversible: reversible,
            MinBuild: minBuild,
            MaxBuild: maxBuild,
            RelatedErrorCodes: errorCodes,
            RegistryChecks: regChecks,
            ServiceChecks: svcChecks,
            CustomProbe: customProbe);
    }

    private static RepairRegistryCheck ParseRegistryCheck(JsonElement el, string ctx)
    {
        var hive = RequireString(el, "hive", ctx).ToUpperInvariant();
        if (hive is not ("HKLM" or "HKCU" or "HKCR"))
        {
            throw new InvalidDataException($"{ctx}: недопустимый куст реестра «{hive}» (разрешены HKLM, HKCU, HKCR).");
        }

        var subKey = RequireString(el, "subKey", ctx).Trim('\\');
        var valueName = el.TryGetProperty("valueName", out var vnEl) && vnEl.ValueKind == JsonValueKind.String
            ? vnEl.GetString() ?? ""
            : throw new InvalidDataException($"{ctx}: отсутствует поле «valueName» (для значения по умолчанию укажите пустую строку \"\").");

        var expectation = ParseEnum<RepairRegistryExpectation>(RequireString(el, "expectation", ctx), $"{ctx}:expectation");
        var fixKind = ParseEnum<RepairRegistryFixKind>(RequireString(el, "fixKind", ctx), $"{ctx}:fixKind");
        var expectedStr = OptionalString(el, "expectedString");
        var expectedDword = OptionalInt(el, "expectedDword");
        var fixStr = OptionalString(el, "fixString");
        var fixDword = OptionalInt(el, "fixDword");
        var onlyIfKeyExists = OptionalBool(el, "onlyIfKeyExists") ?? false;

        return new RepairRegistryCheck(
            Hive: hive,
            SubKey: subKey,
            ValueName: valueName,
            Expectation: expectation,
            FixKind: fixKind,
            ExpectedString: expectedStr,
            ExpectedDword: expectedDword,
            FixString: fixStr,
            FixDword: fixDword,
            OnlyIfKeyExists: onlyIfKeyExists);
    }

    private static RepairServiceCheck ParseServiceCheck(JsonElement el, string ctx)
    {
        var name = RequireString(el, "serviceName", ctx);
        var startup = ParseEnum<RepairServiceStartupKind>(RequireString(el, "healthyStartup", ctx), $"{ctx}:healthyStartup");
        if (startup is RepairServiceStartupKind.Unknown or RepairServiceStartupKind.Disabled)
        {
            throw new InvalidDataException($"{ctx}: healthyStartup службы «{name}» не может быть {startup}.");
        }

        var startIfStopped = OptionalBool(el, "startIfStopped") ?? false;
        var requireRunning = OptionalBool(el, "requireRunning") ?? false;
        var ignoreIfMissing = OptionalBool(el, "ignoreIfMissing") ?? true;

        return new RepairServiceCheck(name, startup, startIfStopped, requireRunning, ignoreIfMissing);
    }

    private static void ValidateNotLicensingBypass(string target, string ctx)
    {
        // Навсегда запрещено вмешиваться в лицензирование и активацию Windows (SoftwareProtectionPlatform, sppsvc, ClipSVC, KMS)
        var upper = target.Replace('/', '\\').ToUpperInvariant();
        if (upper.Contains("SOFTWAREPROTECTIONPLATFORM", StringComparison.Ordinal) ||
            upper.Contains(@"\SERVICES\SPPSVC", StringComparison.Ordinal) ||
            upper.Contains(@"\SERVICES\CLIPSVC", StringComparison.Ordinal) ||
            upper.Contains(@"\SERVICES\LICENSEMANAGER", StringComparison.Ordinal) ||
            upper is "SPPSVC" or "CLIPSVC" or "OSPPSVC" or "LICENSEMANAGER")
        {
            throw new InvalidDataException($"{ctx}: цель «{target}» относится к подсистеме лицензирования Windows и запрещена.");
        }
    }

    private static string RequireString(JsonElement el, string prop, string ctx)
    {
        if (!el.TryGetProperty(prop, out var v) || v.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(v.GetString()))
        {
            throw new InvalidDataException($"{ctx}: отсутствует обязательное строковое поле «{prop}».");
        }

        return v.GetString()!.Trim();
    }

    private static string? OptionalString(JsonElement el, string prop) =>
        el.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString()?.Trim()
            : null;

    private static int RequireInt(JsonElement el, string prop, string ctx)
    {
        if (!el.TryGetProperty(prop, out var v) || v.ValueKind != JsonValueKind.Number || !v.TryGetInt32(out var num))
        {
            throw new InvalidDataException($"{ctx}: отсутствует обязательное целочисленное поле «{prop}».");
        }

        return num;
    }

    private static int? OptionalInt(JsonElement el, string prop) =>
        el.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var num)
            ? num
            : null;

    private static bool? OptionalBool(JsonElement el, string prop) =>
        el.TryGetProperty(prop, out var v) && (v.ValueKind is JsonValueKind.True or JsonValueKind.False)
            ? v.GetBoolean()
            : null;

    private static TEnum ParseEnum<TEnum>(string value, string ctx) where TEnum : struct, Enum
    {
        if (!Enum.TryParse<TEnum>(value, ignoreCase: true, out var parsed))
        {
            throw new InvalidDataException($"{ctx}: недопустимое значение «{value}» для {typeof(TEnum).Name}.");
        }

        return parsed;
    }
}
