using System.Text;
using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Optimizer.Models;

namespace UltimateWindows.Modules.Optimizer.Catalog;

/// <summary>
/// Барьер безопасности твиков. Делит вмешательства в защиту Windows на два вида:
/// 1) запрещённые всегда — обход активации и лицензирования Windows;
/// 2) ослабляющие защиту (Защитник, SmartScreen, защита ядра HVCI, контроль учётных записей) — допустимы
///    только в правилах, честно помеченных как опасные (<see cref="RiskLevel.High"/> и выше).
/// Опасное правило не входит в наборы и применяется лишь после отдельного подтверждения пользователя,
/// поэтому оно не может включиться «заодно» или под видом безобидной настройки.
/// </summary>
public static class TweakSafetyGuard
{
    private static readonly string[] AlwaysForbiddenKeyFragments =
    [
        @"SOFTWAREPROTECTIONPLATFORM"
    ];

    private static readonly string[] ProtectionWeakeningKeyFragments =
    [
        @"WINDOWS DEFENDER",
        @"DISABLEANTISPYWARE",
        @"DISABLEREALTIMEMONITORING",
        @"WINDEFEND",
        @"SMARTSCREEN",
        @"DEVICEGUARD\SCENARIOS\HYPERVISORENFORCEDCODEINTEGRITY",
        @"WINDOWS\CURRENTVERSION\POLICIES\SYSTEM\ENABLELUA"
    ];

    /// <summary>
    /// Изменение недопустимо ни при каких условиях.
    /// </summary>
    public static bool IsAlwaysForbidden(TweakRegistryMutation mutation) =>
        ContainsAnyFragment(mutation, AlwaysForbiddenKeyFragments);

    /// <summary>
    /// Изменение ослабляет защиту Windows и допустимо только в опасном правиле.
    /// </summary>
    public static bool WeakensSystemProtection(TweakRegistryMutation mutation) =>
        ContainsAnyFragment(mutation, ProtectionWeakeningKeyFragments);

    /// <summary>
    /// Изменение безопасно: оно не трогает ни защиту Windows, ни лицензирование.
    /// </summary>
    public static bool IsSafeAllowedMutation(TweakRegistryMutation mutation)
    {
        if (mutation is null || string.IsNullOrWhiteSpace(mutation.SubKeyPath))
        {
            return false;
        }

        return !IsAlwaysForbidden(mutation) && !WeakensSystemProtection(mutation);
    }

    public static void ThrowIfUnsafeRule(DeclarativeTweakRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        foreach (var m in rule.Mutations)
        {
            if (m is null || string.IsNullOrWhiteSpace(m.SubKeyPath))
            {
                throw new InvalidOperationException(
                    $"В правиле '{rule.TweakId}' есть изменение без пути раздела реестра.");
            }

            if (IsAlwaysForbidden(m))
            {
                throw new InvalidOperationException(
                    $"Защитный фильтр TweakSafetyGuard заблокировал правило '{rule.TweakId}': вмешательство в лицензирование Windows запрещено ({m.SubKeyPath}).");
            }

            if (WeakensSystemProtection(m) && !rule.IsDangerous)
            {
                throw new InvalidOperationException(
                    $"Защитный фильтр TweakSafetyGuard заблокировал правило '{rule.TweakId}': оно ослабляет защиту Windows ({m.SubKeyPath}) и должно быть помечено как опасное.");
            }
        }
    }

    private static bool ContainsAnyFragment(TweakRegistryMutation? mutation, string[] fragments)
    {
        if (mutation is null)
        {
            return false;
        }

        var combined = $@"{mutation.Hive}\{mutation.SubKeyPath}\{mutation.ValueName}"
            .Replace('/', '\\')
            .ToUpperInvariant();

        foreach (var fragment in fragments)
        {
            if (combined.Contains(fragment, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}

/// <summary>
/// Каталог встроенных обратимых твиков Windows 10/11. Каждое включение записывается в журнал отката.
/// Сами твики и готовые наборы описаны в файле данных <c>Catalog/tweaks.json</c>, который встраивается в сборку:
/// чтобы добавить или поправить твик, достаточно изменить этот файл (формат — в <c>docs/06-TWEAK-CATALOG.md</c>).
/// Файл читается один раз при первом обращении и полностью проверяется (<see cref="TweakCatalogLoader"/>).
/// </summary>
public static class DeclarativeTweakCatalog
{
    private static readonly Lazy<TweakCatalogData> BuiltIn =
        new(TweakCatalogLoader.LoadBuiltIn, LazyThreadSafetyMode.ExecutionAndPublication);

    public static IReadOnlyList<DeclarativeTweakRule> GetAllRules() => BuiltIn.Value.Rules;

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
        sb.AppendLine("# Декларативный профиль безопасной настройки UltimateWindows");
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
