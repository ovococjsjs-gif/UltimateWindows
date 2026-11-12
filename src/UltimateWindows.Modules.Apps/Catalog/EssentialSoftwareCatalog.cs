using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using UltimateWindows.Modules.Apps.Models;
using UltimateWindows.Modules.Optimizer.Models;

namespace UltimateWindows.Modules.Apps.Catalog;

/// <summary>
/// Загрузчик встроенного каталога проверенных программ первой необходимости (36 пакетов в 6 категориях)
/// и сопоставление с установленными в системе приложениями.
/// </summary>
public static class EssentialSoftwareCatalog
{
    private static readonly Lazy<IReadOnlyList<EssentialAppEntry>> CachedEntries = new(LoadEmbeddedEntries);

    public static IReadOnlyList<EssentialAppEntry> GetAll() => CachedEntries.Value;

    public static IReadOnlyList<EssentialAppEntry> GetByPreset(EssentialAppBundlePreset preset) =>
        CachedEntries.Value.Where(e => e.Presets.Contains(preset)).ToList();

    public static IReadOnlyList<EssentialAppStatus> EvaluateInstalledStates(
        IReadOnlyList<InstalledApplicationInfo> installedWin32Apps,
        IReadOnlySet<string>? installedWingetIds = null)
    {
        var entries = GetAll();
        var results = new List<EssentialAppStatus>(entries.Count);

        foreach (var entry in entries)
        {
            var matchedByWinget = installedWingetIds is not null &&
                                  installedWingetIds.Contains(entry.WingetId);

            InstalledApplicationInfo? win32Match = null;
            foreach (var app in installedWin32Apps)
            {
                if (string.IsNullOrWhiteSpace(app.DisplayName))
                {
                    continue;
                }

                if (entry.MatchKeywords.Any(kw => MatchesAppDisplayName(app.DisplayName, kw)))
                {
                    win32Match = app;
                    break;
                }
            }

            var isInstalled = matchedByWinget || win32Match is not null;
            results.Add(new EssentialAppStatus(
                entry,
                isInstalled,
                win32Match?.DisplayVersion));
        }

        return results;
    }

    private static bool MatchesAppDisplayName(string displayName, string keyword)
    {
        if (string.IsNullOrWhiteSpace(keyword))
        {
            return false;
        }

        if (string.Equals(displayName.Trim(), keyword.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // Для коротких ключевых слов вроде "Git" проверяем границу слова, чтобы не спутать с "GitHub Desktop"
        if (keyword.Length <= 4)
        {
            return displayName.StartsWith(keyword + " ", StringComparison.OrdinalIgnoreCase) ||
                   displayName.StartsWith(keyword + "-", StringComparison.OrdinalIgnoreCase);
        }

        return displayName.Contains(keyword, StringComparison.OrdinalIgnoreCase);
    }

    private static IReadOnlyList<EssentialAppEntry> LoadEmbeddedEntries()
    {
        var assembly = typeof(EssentialSoftwareCatalog).Assembly;
        var resourceName = assembly.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith("essential-apps.json", StringComparison.OrdinalIgnoreCase));

        if (resourceName is null)
        {
            return Array.Empty<EssentialAppEntry>();
        }

        using var stream = assembly.GetManifestResourceStream(resourceName);
        if (stream is null)
        {
            return Array.Empty<EssentialAppEntry>();
        }

        var options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            Converters = { new JsonStringEnumConverter() }
        };

        var loaded = JsonSerializer.Deserialize<List<EssentialAppEntry>>(stream, options);
        return loaded ?? (IReadOnlyList<EssentialAppEntry>)Array.Empty<EssentialAppEntry>();
    }
}
