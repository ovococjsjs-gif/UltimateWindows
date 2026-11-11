using System.Text;

namespace UltimateWindows.Modules.Cleaner.Rules;

/// <summary>
/// Запись файла, которую не удалось превратить в правило, и причина.
/// </summary>
public sealed record Winapp2SkippedEntry(string Name, string Reason);

public sealed record Winapp2ReadResult(
    string SourceName,
    IReadOnlyList<CleanupRule> Rules,
    IReadOnlyList<Winapp2SkippedEntry> Skipped);

/// <summary>
/// Читает правила очистки из файла в формате winapp2.ini — общепринятом формате сообщества,
/// в котором описаны тысячи программ. Сам файл в программу не входит: пользователь подключает свой.
/// <para>
/// Правила из такого файла считаются внешними: они никогда не отмечены заранее,
/// и защита (<see cref="CleanupPathGuard"/>) к ним строже, чем к встроенному каталогу.
/// </para>
/// </summary>
public static class Winapp2Reader
{
    private const int MaxFileBytes = 16 * 1024 * 1024;

    public static Winapp2ReadResult ReadFile(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        var info = new FileInfo(filePath);
        if (!info.Exists)
        {
            throw new FileNotFoundException("Файл правил не найден.", filePath);
        }

        if (info.Length > MaxFileBytes)
        {
            throw new InvalidDataException("Файл правил слишком большой: больше 16 МБ.");
        }

        return Parse(File.ReadAllText(filePath, Encoding.UTF8), info.Name);
    }

    public static Winapp2ReadResult Parse(string text, string sourceName)
    {
        ArgumentNullException.ThrowIfNull(text);

        var rules = new List<CleanupRule>();
        var skipped = new List<Winapp2SkippedEntry>();
        var usedIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        string? name = null;
        var keys = new List<KeyValuePair<string, string>>();

        void Flush()
        {
            if (name is null)
            {
                return;
            }

            var rule = BuildRule(name, keys, sourceName, usedIds, out var reason);
            if (rule is not null)
            {
                rules.Add(rule);
            }
            else
            {
                skipped.Add(new Winapp2SkippedEntry(name, reason));
            }

            name = null;
            keys.Clear();
        }

        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.Trim().TrimStart('\uFEFF');
            if (line.Length == 0 || line[0] == ';')
            {
                continue;
            }

            if (line[0] == '[' && line[^1] == ']')
            {
                Flush();
                name = line[1..^1].Trim();
                continue;
            }

            var equals = line.IndexOf('=');
            if (name is null || equals <= 0)
            {
                continue;
            }

            keys.Add(new KeyValuePair<string, string>(line[..equals].Trim(), line[(equals + 1)..].Trim()));
        }

        Flush();
        return new Winapp2ReadResult(sourceName, rules, skipped);
    }

    private static CleanupRule? BuildRule(
        string rawName,
        List<KeyValuePair<string, string>> keys,
        string sourceName,
        HashSet<string> usedIds,
        out string reason)
    {
        reason = "";
        var title = rawName.EndsWith('*') ? rawName[..^1].TrimEnd() : rawName;
        if (title.Length == 0)
        {
            reason = "у записи нет названия";
            return null;
        }

        var files = new List<CleanupFileTarget>();
        var exclusions = new List<CleanupExclusion>();
        var registry = new List<CleanupRegistryTarget>();
        var detectPaths = new List<string>();
        var detectKeys = new List<string>();
        var section = CleanupSection.Utilities;
        string? warning = null;
        Version? minOs = null;
        Version? maxOs = null;

        foreach (var (key, value) in keys)
        {
            var kind = StripNumber(key).ToLowerInvariant();
            switch (kind)
            {
                case "filekey":
                {
                    if (!TryParseFileKey(value, out var target, out reason))
                    {
                        return null;
                    }

                    files.Add(target);
                    break;
                }

                case "regkey":
                {
                    var parts = value.Split('|');
                    var keyPath = NormalizeRegistryKey(parts[0]);
                    if (keyPath is null)
                    {
                        reason = $"раздел реестра «{parts[0]}» не поддерживается";
                        return null;
                    }

                    registry.Add(new CleanupRegistryTarget(keyPath, parts.Length > 1 && parts[1].Length > 0 ? parts[1] : null));
                    break;
                }

                case "excludekey":
                {
                    var parts = value.Split('|');
                    if (parts.Length < 2)
                    {
                        break;
                    }

                    // Исключения для реестра относятся к очистке реестра, для файлов они не нужны
                    if (parts[0].Equals("REG", StringComparison.OrdinalIgnoreCase))
                    {
                        break;
                    }

                    var path = ConvertPath(parts[1]);
                    if (!CleanupPathPattern.TryParse(path, allowRegistryVariable: false, out _, out var error))
                    {
                        reason = $"исключение «{parts[1]}»: {error}";
                        return null;
                    }

                    var masks = parts.Length > 2
                        ? parts[2].Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                            .Select(CleanupPathPattern.NormalizeFilePattern)
                            .ToArray()
                        : Array.Empty<string>();
                    if (masks.Length == 1 && masks[0] == "*")
                    {
                        masks = Array.Empty<string>();
                    }

                    exclusions.Add(new CleanupExclusion(path, masks));
                    break;
                }

                case "detect":
                {
                    var keyPath = NormalizeRegistryKey(value);
                    if (keyPath is not null)
                    {
                        detectKeys.Add(keyPath);
                    }

                    break;
                }

                case "detectfile":
                {
                    var path = ConvertPath(value);
                    if (CleanupPathPattern.TryParse(path, allowRegistryVariable: false, out _, out _))
                    {
                        detectPaths.Add(path);
                    }

                    break;
                }

                case "specialdetect":
                {
                    var path = value.ToUpperInvariant() switch
                    {
                        "DET_CHROME" => @"%LocalAppData%\Google\Chrome\User Data",
                        "DET_MOZILLA" => @"%AppData%\Mozilla\Firefox",
                        "DET_THUNDERBIRD" => @"%AppData%\Thunderbird",
                        "DET_OPERA" => @"%AppData%\Opera Software",
                        _ => null
                    };
                    if (path is not null)
                    {
                        detectPaths.Add(path);
                    }

                    break;
                }

                case "detectos":
                {
                    var parts = value.Split('|');
                    minOs = ParseVersion(parts[0]);
                    maxOs = parts.Length > 1 ? ParseVersion(parts[1]) : null;
                    break;
                }

                case "langsecref":
                    section = MapLangSecRef(value);
                    break;

                case "section":
                    section = MapSectionName(value);
                    break;

                case "warning":
                    warning = value.Length > 0 ? value : null;
                    break;
            }
        }

        if (files.Count == 0 && registry.Count == 0)
        {
            reason = "в записи нет ни файлов, ни разделов реестра";
            return null;
        }

        if (files.Count == 0)
        {
            reason = "запись чистит только реестр — эта версия программы применяет файловые правила";
            return null;
        }

        // Условие по версии Windows: записи для старых систем на Windows 10 и 11 не нужны
        var current = new Version(10, 0);
        if ((minOs is not null && current < minOs) || (maxOs is not null && current > maxOs))
        {
            reason = "запись рассчитана на другую версию Windows";
            return null;
        }

        var id = MakeId(title, usedIds);
        var explanation = registry.Count > 0
            ? "Правило из подключённого файла. Удаляет файлы, перечисленные в записи; записи реестра из неё не затрагиваются."
            : "Правило из подключённого файла. Удаляет файлы, перечисленные в записи.";

        return new CleanupRule(id, section, title, title, explanation, CleanupDataKind.Other, SelectedByDefault: false, files)
        {
            Warning = warning,
            Detection = detectPaths.Count > 0 || detectKeys.Count > 0 ? new CleanupDetection(detectPaths, detectKeys) : null,
            Exclusions = exclusions,
            Registry = registry,
            Origin = CleanupRuleOrigin.External,
            SourceName = sourceName
        };
    }

    private static bool TryParseFileKey(string value, out CleanupFileTarget target, out string reason)
    {
        target = new CleanupFileTarget("", [], false, false, false);
        reason = "";

        var parts = value.Split('|');
        var path = ConvertPath(parts[0]);
        if (!CleanupPathPattern.TryParse(path, allowRegistryVariable: false, out _, out var error))
        {
            reason = $"путь «{parts[0]}»: {error}";
            return false;
        }

        var masks = parts.Length > 1
            ? parts[1].Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(CleanupPathPattern.NormalizeFilePattern)
                .ToArray()
            : Array.Empty<string>();
        if (masks.Length == 0)
        {
            masks = ["*"];
        }

        var mode = parts.Length > 2 ? parts[2].Trim().ToUpperInvariant() : "";
        var removeSelf = mode == "REMOVESELF";
        var recurse = removeSelf || mode == "RECURSE";

        target = new CleanupFileTarget(path, masks, recurse, RemoveEmptyFolders: recurse, removeSelf);
        return true;
    }

    /// <summary>
    /// Приводит путь из файла к виду каталога: имена переменных остаются, лишняя косая черта в конце убирается.
    /// </summary>
    private static string ConvertPath(string path) => path.Trim().TrimEnd('\\', '/');

    private static string? NormalizeRegistryKey(string raw)
    {
        var key = raw.Trim().TrimEnd('\\');
        foreach (var (longName, shortName) in new[]
                 {
                     ("HKEY_CURRENT_USER", "HKCU"), ("HKEY_LOCAL_MACHINE", "HKLM")
                 })
        {
            if (key.StartsWith(longName + "\\", StringComparison.OrdinalIgnoreCase))
            {
                key = shortName + key[longName.Length..];
            }
        }

        return CleanupPathPattern.IsSupportedRegistryKey(key) ? key : null;
    }

    private static string StripNumber(string key)
    {
        var end = key.Length;
        while (end > 0 && char.IsDigit(key[end - 1]))
        {
            end--;
        }

        return key[..end];
    }

    private static Version? ParseVersion(string text) =>
        Version.TryParse(text.Trim(), out var version) ? version : null;

    private static CleanupSection MapLangSecRef(string value) => value.Trim() switch
    {
        "3023" => CleanupSection.Media,
        "3025" or "3031" => CleanupSection.Windows,
        "3026" or "3027" or "3028" or "3029" or "3032" or "3033" or "3034" or "3035" or "3037" or "3038" => CleanupSection.Browsers,
        "3030" => CleanupSection.Messengers,
        "3036" => CleanupSection.Media,
        _ => CleanupSection.Utilities
    };

    private static CleanupSection MapSectionName(string value)
    {
        var name = value.Trim().ToLowerInvariant();
        if (name.Contains("game"))
        {
            return CleanupSection.Games;
        }

        if (name.Contains("browser") || name.Contains("internet"))
        {
            return CleanupSection.Browsers;
        }

        if (name.Contains("windows") || name.Contains("microsoft"))
        {
            return CleanupSection.Windows;
        }

        if (name.Contains("media") || name.Contains("audio") || name.Contains("video"))
        {
            return CleanupSection.Media;
        }

        return CleanupSection.Utilities;
    }

    private static string MakeId(string title, HashSet<string> usedIds)
    {
        var builder = new StringBuilder("ext.");
        var lastDash = true;
        foreach (var ch in title.ToLowerInvariant())
        {
            if (ch is (>= 'a' and <= 'z') or (>= '0' and <= '9'))
            {
                builder.Append(ch);
                lastDash = false;
            }
            else if (!lastDash)
            {
                builder.Append('-');
                lastDash = true;
            }
        }

        var baseId = builder.ToString().TrimEnd('-');
        if (baseId.Length <= 4)
        {
            baseId = "ext.rule";
        }

        var id = baseId;
        var suffix = 2;
        while (!usedIds.Add(id))
        {
            id = $"{baseId}-{suffix++}";
        }

        return id;
    }
}
