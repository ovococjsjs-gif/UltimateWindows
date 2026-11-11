using System.Text;
using UltimateWindows.Modules.Optimizer.Models;

namespace UltimateWindows.Modules.Optimizer.Catalog;

/// <summary>
/// Каталог встроенных обратимых твиков Windows 10/11. Каждое включение записывается в журнал отката.
/// Сами твики и готовые наборы описаны в файлах данных <c>Catalog/Data/*.json</c>, которые встраиваются в сборку:
/// чтобы добавить или поправить твик, достаточно изменить файл данных (формат — в <c>docs/06-TWEAK-CATALOG.md</c>).
/// Файлы читаются один раз при первом обращении и полностью проверяются (<see cref="TweakCatalogLoader"/>).
/// </summary>
public static class DeclarativeTweakCatalog
{
    private static readonly Lazy<TweakCatalogData> BuiltIn =
        new(TweakCatalogLoader.LoadBuiltIn, LazyThreadSafetyMode.ExecutionAndPublication);

    public static TweakCatalogData Data => BuiltIn.Value;

    public static IReadOnlyList<DeclarativeTweakRule> GetAllRules() => BuiltIn.Value.Rules;

    public static IReadOnlyList<TweakPresetDescriptor> GetPresets() => BuiltIn.Value.Presets;

    /// <summary>
    /// Идентификаторы твиков готового набора. Неизвестное название набора означает набор «recommended».
    /// </summary>
    public static IReadOnlyList<string> GetPresetIds(string presetKey) => BuiltIn.Value.GetPresetIds(presetKey);

    public static DeclarativeTweakRule? FindById(string tweakId) => BuiltIn.Value.FindById(tweakId);
}

public static class YamlTweakProfileSerializer
{
    public static string ExportProfileToYaml(string profileName, IEnumerable<string> enabledTweakIds)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Профиль настроек UltimateWindows: список включённых твиков");
        sb.AppendLine("schema_version: 1");
        sb.AppendLine($"profile_name: \"{EscapeYaml(profileName)}\"");
        sb.AppendLine($"exported_at_utc: \"{DateTimeOffset.UtcNow:O}\"");
        sb.AppendLine("enabled_tweaks:");

        foreach (var id in enabledTweakIds.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
        {
            sb.AppendLine($"  - {id}");
        }

        return sb.ToString();
    }

    public static (string ProfileName, IReadOnlyList<string> EnabledTweakIds) ImportProfileFromYaml(string yamlContent)
    {
        if (string.IsNullOrWhiteSpace(yamlContent))
        {
            return ("Безымянный профиль", []);
        }

        var profileName = "Импортированный профиль";
        var ids = new List<string>();
        var inTweaksList = false;

        foreach (var rawLine in yamlContent.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var line = rawLine.Trim();
            if (line.StartsWith('#')) continue;

            if (line.StartsWith("profile_name:", StringComparison.OrdinalIgnoreCase))
            {
                profileName = line["profile_name:".Length..].Trim().Trim('"', '\'');
                inTweaksList = false;
                continue;
            }

            if (line.StartsWith("enabled_tweaks:", StringComparison.OrdinalIgnoreCase))
            {
                inTweaksList = true;
                continue;
            }

            if (inTweaksList && line.StartsWith('-'))
            {
                var id = line[1..].Trim().Trim('"', '\'');
                if (!string.IsNullOrWhiteSpace(id))
                {
                    ids.Add(id);
                }
            }
            else if (!rawLine.StartsWith(' ') && !rawLine.StartsWith('\t'))
            {
                inTweaksList = false;
            }
        }

        return (profileName, ids);
    }

    private static string EscapeYaml(string input) =>
        input.Replace("\\", "\\\\").Replace("\"", "\\\"");
}
