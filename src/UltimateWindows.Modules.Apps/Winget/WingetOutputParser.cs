using System.Text.RegularExpressions;
using UltimateWindows.Modules.Apps.Models;

namespace UltimateWindows.Modules.Apps.Winget;

/// <summary>
/// Локаленезависимый разбор табличного вывода winget (upgrade / list) без хрупкой привязки к языку Windows.
/// Корректно отсекает индикаторы прогресса, разделитель заголовка «---» и итоговые строки сводки.
/// </summary>
public static partial class WingetOutputParser
{
    [GeneratedRegex(@"^[-\\|/█▒░\s]+$")]
    private static partial Regex SpinnerOrProgressLineRegex();

    [GeneratedRegex(@"^\d+\s+(upgrades?\s+available|обновлен|пакет)", RegexOptions.IgnoreCase)]
    private static partial Regex TrailingSummaryLineRegex();

    /// <summary>
    /// Разбирает вывод команды «winget upgrade --include-unknown --accept-source-agreements».
    /// </summary>
    public static IReadOnlyList<WingetUpgradablePackage> ParseUpgradeTable(string rawOutput)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
        {
            return Array.Empty<WingetUpgradablePackage>();
        }

        var lines = NormalizeLines(rawOutput);
        var dividerIndex = FindDividerLineIndex(lines);
        if (dividerIndex <= 0 || dividerIndex >= lines.Count - 1)
        {
            return Array.Empty<WingetUpgradablePackage>();
        }

        var headerLine = lines[dividerIndex - 1];
        var columnStarts = DetectColumnOffsets(headerLine);
        var packages = new List<WingetUpgradablePackage>();
        var inPinnedSection = false;

        for (var i = dividerIndex + 1; i < lines.Count; i++)
        {
            var line = lines[i];
            if (string.IsNullOrWhiteSpace(line) || SpinnerOrProgressLineRegex().IsMatch(line))
            {
                continue;
            }

            if (line.TrimStart().StartsWith("---", StringComparison.Ordinal))
            {
                // Вторая таблица после первой сводки у winget — это закреплённые (pinned) пакеты
                inPinnedSection = true;
                continue;
            }

            if (IsSummaryOrSectionBanner(line))
            {
                if (line.Contains("pinned", StringComparison.OrdinalIgnoreCase) ||
                    line.Contains("закреп", StringComparison.OrdinalIgnoreCase))
                {
                    inPinnedSection = true;
                }

                continue;
            }

            var parsed = TryParseUpgradeRow(line, columnStarts, inPinnedSection);
            if (parsed is not null)
            {
                packages.Add(parsed);
            }
        }

        return packages;
    }

    /// <summary>
    /// Извлекает множество идентификаторов установленных пакетов из вывода «winget list --accept-source-agreements».
    /// </summary>
    public static HashSet<string> ParseInstalledPackageIds(string rawOutput)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(rawOutput))
        {
            return set;
        }

        var lines = NormalizeLines(rawOutput);
        var dividerIndex = FindDividerLineIndex(lines);
        if (dividerIndex <= 0 || dividerIndex >= lines.Count - 1)
        {
            return set;
        }

        var headerLine = lines[dividerIndex - 1];
        var columnStarts = DetectColumnOffsets(headerLine);

        for (var i = dividerIndex + 1; i < lines.Count; i++)
        {
            var line = lines[i];
            if (string.IsNullOrWhiteSpace(line) ||
                SpinnerOrProgressLineRegex().IsMatch(line) ||
                line.TrimStart().StartsWith("---", StringComparison.Ordinal) ||
                IsSummaryOrSectionBanner(line))
            {
                continue;
            }

            if (columnStarts.Count >= 3 && line.Length > columnStarts[1])
            {
                var idEnd = Math.Min(line.Length, columnStarts[2]);
                var idCandidate = line[columnStarts[1]..idEnd].Trim();
                if (LooksLikePackageId(idCandidate))
                {
                    set.Add(idCandidate);
                    continue;
                }
            }

            // Резервный разбор по группам из 2+ пробелов
            var parts = SplitByMultiSpace(line);
            if (parts.Count >= 2 && LooksLikePackageId(parts[1]))
            {
                set.Add(parts[1]);
            }
        }

        return set;
    }

    private static WingetUpgradablePackage? TryParseUpgradeRow(
        string line,
        IReadOnlyList<int> columnStarts,
        bool isPinned)
    {
        // Способ 1: точная нарезка по смещениям колонок заголовка (Name | Id | Version | Available | Source)
        if (columnStarts.Count >= 4 && line.Length > columnStarts[3])
        {
            var name = SafeSlice(line, columnStarts[0], columnStarts[1]);
            var id = SafeSlice(line, columnStarts[1], columnStarts[2]);
            var installed = SafeSlice(line, columnStarts[2], columnStarts[3]);
            var available = columnStarts.Count >= 5
                ? SafeSlice(line, columnStarts[3], columnStarts[4])
                : SafeSlice(line, columnStarts[3], line.Length);
            var source = columnStarts.Count >= 5 && line.Length > columnStarts[4]
                ? SafeSlice(line, columnStarts[4], line.Length)
                : "winget";

            if (!string.IsNullOrWhiteSpace(name) &&
                LooksLikePackageId(id) &&
                !string.IsNullOrWhiteSpace(available))
            {
                return new WingetUpgradablePackage(
                    PackageId: id,
                    Name: CleanTruncatedCell(name),
                    InstalledVersion: string.IsNullOrWhiteSpace(installed) ? "неизвестно" : installed,
                    AvailableVersion: available,
                    Source: string.IsNullOrWhiteSpace(source) ? "winget" : source,
                    IsPinned: isPinned);
            }
        }

        // Способ 2: резервная нарезка по 2+ пробелам справа налево (если UTF-8 имя сдвинуло колонки)
        var tokens = SplitByMultiSpace(line);
        if (tokens.Count >= 4)
        {
            var hasSource = tokens.Count >= 5 &&
                            (string.Equals(tokens[^1], "winget", StringComparison.OrdinalIgnoreCase) ||
                             string.Equals(tokens[^1], "msstore", StringComparison.OrdinalIgnoreCase));

            var source = hasSource ? tokens[^1] : "winget";
            var availableIdx = hasSource ? tokens.Count - 2 : tokens.Count - 1;
            var installedIdx = availableIdx - 1;
            var idIdx = installedIdx - 1;

            if (idIdx >= 1 && LooksLikePackageId(tokens[idIdx]))
            {
                var name = string.Join(" ", tokens.Take(idIdx));
                return new WingetUpgradablePackage(
                    PackageId: tokens[idIdx],
                    Name: CleanTruncatedCell(name),
                    InstalledVersion: tokens[installedIdx],
                    AvailableVersion: tokens[availableIdx],
                    Source: source,
                    IsPinned: isPinned);
            }
        }

        return null;
    }

    private static List<string> NormalizeLines(string raw)
    {
        var result = new List<string>();
        foreach (var rawLine in raw.Split('\n'))
        {
            // winget рисует прогресс-бар через '\r' на одной строке перед выводом заголовка
            var segments = rawLine.TrimEnd('\r').Split('\r');
            var clean = segments[^1];
            if (!string.IsNullOrWhiteSpace(clean) && !SpinnerOrProgressLineRegex().IsMatch(clean))
            {
                result.Add(clean);
            }
        }

        return result;
    }

    private static int FindDividerLineIndex(IReadOnlyList<string> lines)
    {
        for (var i = 1; i < lines.Count; i++)
        {
            var trimmed = lines[i].Trim();
            if (trimmed.Length >= 20 && trimmed.All(c => c == '-'))
            {
                return i;
            }
        }

        return -1;
    }

    private static List<int> DetectColumnOffsets(string headerLine)
    {
        var offsets = new List<int>();
        var inWord = false;
        var spaceStreak = 0;

        for (var i = 0; i < headerLine.Length; i++)
        {
            var ch = headerLine[i];
            if (!char.IsWhiteSpace(ch))
            {
                if (!inWord && (offsets.Count == 0 || spaceStreak >= 1))
                {
                    offsets.Add(i);
                }

                inWord = true;
                spaceStreak = 0;
            }
            else
            {
                spaceStreak++;
                if (spaceStreak >= 2)
                {
                    inWord = false;
                }
            }
        }

        return offsets;
    }

    private static List<string> SplitByMultiSpace(string line) =>
        Regex.Split(line.Trim(), @"\s{2,}")
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .ToList();

    private static string SafeSlice(string line, int start, int endExclusive)
    {
        if (start >= line.Length)
        {
            return string.Empty;
        }

        var safeEnd = Math.Clamp(endExclusive, start, line.Length);
        return line[start..safeEnd].Trim();
    }

    private static string CleanTruncatedCell(string text) =>
        text.TrimEnd('…').Trim();

    private static bool LooksLikePackageId(string candidate) =>
        !string.IsNullOrWhiteSpace(candidate) &&
        candidate.Length >= 3 &&
        !candidate.Contains(' ') &&
        (candidate.Contains('.') || candidate.Contains('\\') || candidate.All(c => char.IsLetterOrDigit(c) || c is '-' or '_'));

    private static bool IsSummaryOrSectionBanner(string line)
    {
        var trimmed = line.Trim();
        if (TrailingSummaryLineRegex().IsMatch(trimmed))
        {
            return true;
        }

        return trimmed.StartsWith("The following packages", StringComparison.OrdinalIgnoreCase) ||
               trimmed.StartsWith("No installed package", StringComparison.OrdinalIgnoreCase) ||
               trimmed.StartsWith("No applicable upgrade", StringComparison.OrdinalIgnoreCase) ||
               trimmed.StartsWith("Следующие пакеты", StringComparison.OrdinalIgnoreCase) ||
               trimmed.StartsWith("Доступно обновлений", StringComparison.OrdinalIgnoreCase) ||
               trimmed.StartsWith("Обновления не найдены", StringComparison.OrdinalIgnoreCase);
    }
}
