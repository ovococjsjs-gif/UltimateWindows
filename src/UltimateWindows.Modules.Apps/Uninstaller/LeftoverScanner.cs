using System.Text.RegularExpressions;
using UltimateWindows.Modules.Apps.Models;
using UltimateWindows.Modules.Optimizer.Models;

namespace UltimateWindows.Modules.Apps.Uninstaller;

/// <summary>
/// Поисковик остаточных файлов, папок AppData/ProgramData, ярлыков и ключей реестра удалённых программ.
/// Сверка строится по токенам названия, папки установки и ключа деинсталляции с защитой соседних программ.
/// </summary>
public static partial class LeftoverScanner
{
    [GeneratedRegex(@"\b(v?\d+(\.\d+)+|x64|x86|64-bit|32-bit|amd64|en-us|ru-ru|release|edition|setup|installer)\b", RegexOptions.IgnoreCase)]
    private static partial Regex VersionOrArchNoiseRegex();

    private static readonly HashSet<string> GenericIgnoredTokens = new(StringComparer.OrdinalIgnoreCase)
    {
        "app", "application", "software", "program", "client", "desktop", "launcher",
        "viewer", "player", "editor", "studio", "tools", "tool", "utility", "helper",
        "service", "updater", "update", "agent", "host", "runtime", "redistributable",
        "microsoft", "windows", "google", "mozilla", "corporation", "inc", "ltd", "llc", "gmbh"
    };

    /// <summary>
    /// Сканирует переданные корни файловой системы и ключи реестра на предмет остаточных хвостов целевой программы,
    /// исключая пути, принадлежащие другим всё ещё установленным программам.
    /// </summary>
    public static IReadOnlyList<AppLeftoverItem> ScanLeftovers(
        InstalledApplicationInfo targetApp,
        IReadOnlyList<InstalledApplicationInfo> otherInstalledApps,
        IReadOnlyList<(AppLeftoverKind Kind, string RootDirectory)> candidateRoots,
        IReadOnlyList<string> candidateRegistrySoftwareKeys)
    {
        ArgumentNullException.ThrowIfNull(targetApp);

        var tokens = BuildDistinctiveTokens(targetApp);
        if (tokens.Count == 0)
        {
            return Array.Empty<AppLeftoverItem>();
        }

        var otherTokens = BuildProtectedTokensOfOtherApps(targetApp, otherInstalledApps);
        var found = new List<AppLeftoverItem>();
        var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // 1. Остаток собственной папки установки (если она указана и безопасна)
        if (!string.IsNullOrWhiteSpace(targetApp.InstallLocation) &&
            Directory.Exists(targetApp.InstallLocation) &&
            LeftoverSafetyGuard.IsSafeFilesystemLeftoverCandidate(targetApp.InstallLocation) &&
            !IsOwnedByAnotherInstalledApp(targetApp.InstallLocation, targetApp, otherInstalledApps))
        {
            var normalizedInstall = Path.GetFullPath(targetApp.InstallLocation).TrimEnd('\\');
            if (seenPaths.Add(normalizedInstall))
            {
                found.Add(new AppLeftoverItem(
                    AppLeftoverKind.InstallDirectoryResidue,
                    normalizedInstall,
                    "Папка установки программы на диске",
                    EstimateDirectorySizeBounded(normalizedInstall)));
            }
        }

        // 2. Папки в %LOCALAPPDATA%, %APPDATA%, %PROGRAMDATA% и ярлыки .lnk
        foreach (var (kind, rootDir) in candidateRoots)
        {
            if (string.IsNullOrWhiteSpace(rootDir) || !Directory.Exists(rootDir))
            {
                continue;
            }

            if (kind == AppLeftoverKind.ShortcutFile)
            {
                ScanShortcutDirectory(rootDir, tokens, otherTokens, seenPaths, found);
                continue;
            }

            ScanDataDirectory(kind, rootDir, targetApp, tokens, otherTokens, otherInstalledApps, seenPaths, found);
        }

        // 3. Осиротевшие ветки настроек HKCU\Software\... и HKLM\Software\...
        foreach (var regKey in candidateRegistrySoftwareKeys)
        {
            if (!LeftoverSafetyGuard.IsSafeRegistryLeftoverCandidate(regKey))
            {
                continue;
            }

            var leaf = regKey.Split('\\', StringSplitOptions.RemoveEmptyEntries)[^1];
            if (MatchesLeafToken(leaf, tokens) &&
                !MatchesLeafToken(leaf, otherTokens) &&
                seenPaths.Add(regKey))
            {
                found.Add(new AppLeftoverItem(
                    AppLeftoverKind.RegistrySubKey,
                    regKey,
                    $"Ветка настроек реестра «{leaf}»",
                    EstimatedSizeBytes: 0));
            }
        }

        return found;
    }

    public static HashSet<string> BuildDistinctiveTokens(InstalledApplicationInfo app)
    {
        var tokens = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        AddCandidateToken(tokens, CleanAppTitle(app.DisplayName));

        // Без пробелов/дефисов (например "Notepad++" / "7-Zip" -> "7zip", "ShareX" -> "sharex")
        var compactTitle = CompactAlphaNumeric(CleanAppTitle(app.DisplayName));
        if (compactTitle.Length >= 4)
        {
            AddCandidateToken(tokens, compactTitle);
        }

        if (!string.IsNullOrWhiteSpace(app.InstallLocation))
        {
            var leafDir = Path.GetFileName(app.InstallLocation.TrimEnd('\\', '/'));
            AddCandidateToken(tokens, leafDir);
        }

        if (!string.IsNullOrWhiteSpace(app.RegistryKeyPath))
        {
            var regLeaf = app.RegistryKeyPath.Split('\\', StringSplitOptions.RemoveEmptyEntries).LastOrDefault();
            if (!string.IsNullOrWhiteSpace(regLeaf) &&
                !regLeaf.StartsWith('{') &&
                !regLeaf.EndsWith("_is1", StringComparison.OrdinalIgnoreCase))
            {
                AddCandidateToken(tokens, regLeaf);
            }
            else if (!string.IsNullOrWhiteSpace(regLeaf) &&
                     regLeaf.EndsWith("_is1", StringComparison.OrdinalIgnoreCase))
            {
                AddCandidateToken(tokens, regLeaf[..^4]);
            }
        }

        return tokens;
    }

    private static void ScanDataDirectory(
        AppLeftoverKind kind,
        string rootDir,
        InstalledApplicationInfo targetApp,
        HashSet<string> tokens,
        HashSet<string> otherTokens,
        IReadOnlyList<InstalledApplicationInfo> otherApps,
        HashSet<string> seenPaths,
        List<AppLeftoverItem> found)
    {
        IEnumerable<string> firstLevelDirs;
        try
        {
            firstLevelDirs = Directory.EnumerateDirectories(rootDir);
        }
        catch
        {
            return;
        }

        foreach (var subDir in firstLevelDirs)
        {
            var folderName = Path.GetFileName(subDir);
            if (MatchesLeafToken(folderName, tokens) &&
                !MatchesLeafToken(folderName, otherTokens) &&
                LeftoverSafetyGuard.IsSafeFilesystemLeftoverCandidate(subDir) &&
                !IsOwnedByAnotherInstalledApp(subDir, targetApp, otherApps))
            {
                var normalized = Path.GetFullPath(subDir).TrimEnd('\\');
                if (seenPaths.Add(normalized))
                {
                    found.Add(new AppLeftoverItem(
                        kind,
                        normalized,
                        $"Папка данных приложения «{folderName}»",
                        EstimateDirectorySizeBounded(normalized)));
                }

                continue;
            }

            // Проверяем второй уровень внутри папки издателя (например %LOCALAPPDATA%\Publisher\AppName)
            if (!string.IsNullOrWhiteSpace(targetApp.Publisher) &&
                PublisherFolderMatches(folderName, targetApp.Publisher))
            {
                IEnumerable<string> secondLevelDirs;
                try
                {
                    secondLevelDirs = Directory.EnumerateDirectories(subDir);
                }
                catch
                {
                    continue;
                }

                foreach (var nestedDir in secondLevelDirs)
                {
                    var nestedName = Path.GetFileName(nestedDir);
                    if (MatchesLeafToken(nestedName, tokens) &&
                        !MatchesLeafToken(nestedName, otherTokens) &&
                        LeftoverSafetyGuard.IsSafeFilesystemLeftoverCandidate(nestedDir) &&
                        !IsOwnedByAnotherInstalledApp(nestedDir, targetApp, otherApps))
                    {
                        var normalizedNested = Path.GetFullPath(nestedDir).TrimEnd('\\');
                        if (seenPaths.Add(normalizedNested))
                        {
                            found.Add(new AppLeftoverItem(
                                kind,
                                normalizedNested,
                                $"Папка издателя «{folderName}\\{nestedName}»",
                                EstimateDirectorySizeBounded(normalizedNested)));
                        }
                    }
                }
            }
        }
    }

    private static void ScanShortcutDirectory(
        string shortcutDir,
        HashSet<string> tokens,
        HashSet<string> otherTokens,
        HashSet<string> seenPaths,
        List<AppLeftoverItem> found)
    {
        IEnumerable<string> shortcutFiles;
        try
        {
            shortcutFiles = Directory.EnumerateFiles(shortcutDir, "*.lnk", SearchOption.TopDirectoryOnly);
        }
        catch
        {
            return;
        }

        foreach (var lnk in shortcutFiles)
        {
            var baseName = Path.GetFileNameWithoutExtension(lnk);
            if (MatchesLeafToken(baseName, tokens) &&
                !MatchesLeafToken(baseName, otherTokens) &&
                LeftoverSafetyGuard.IsSafeFilesystemLeftoverCandidate(lnk))
            {
                var normalized = Path.GetFullPath(lnk);
                if (seenPaths.Add(normalized))
                {
                    long len = 0;
                    try { len = new FileInfo(normalized).Length; } catch { }
                    found.Add(new AppLeftoverItem(
                        AppLeftoverKind.ShortcutFile,
                        normalized,
                        $"Ярлык запуска «{baseName}.lnk»",
                        len));
                }
            }
        }
    }

    private static HashSet<string> BuildProtectedTokensOfOtherApps(
        InstalledApplicationInfo targetApp,
        IReadOnlyList<InstalledApplicationInfo> otherApps)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var other in otherApps)
        {
            if (string.Equals(other.RegistryKeyPath, targetApp.RegistryKeyPath, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(other.DisplayName, targetApp.DisplayName, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            foreach (var token in BuildDistinctiveTokens(other))
            {
                set.Add(token);
            }
        }

        return set;
    }

    private static bool IsOwnedByAnotherInstalledApp(
        string candidatePath,
        InstalledApplicationInfo targetApp,
        IReadOnlyList<InstalledApplicationInfo> otherApps)
    {
        var normCandidate = candidatePath.TrimEnd('\\', '/') + "\\";
        foreach (var other in otherApps)
        {
            if (string.Equals(other.RegistryKeyPath, targetApp.RegistryKeyPath, StringComparison.OrdinalIgnoreCase) ||
                string.IsNullOrWhiteSpace(other.InstallLocation))
            {
                continue;
            }

            var normOther = other.InstallLocation.TrimEnd('\\', '/') + "\\";
            if (normOther.StartsWith(normCandidate, StringComparison.OrdinalIgnoreCase) ||
                normCandidate.StartsWith(normOther, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool PublisherFolderMatches(string folderName, string publisher)
    {
        if (string.IsNullOrWhiteSpace(folderName) || string.IsNullOrWhiteSpace(publisher))
        {
            return false;
        }

        var cleanPub = CleanAppTitle(publisher);
        return string.Equals(folderName, cleanPub, StringComparison.OrdinalIgnoreCase) ||
               cleanPub.StartsWith(folderName + " ", StringComparison.OrdinalIgnoreCase);
    }

    private static bool MatchesLeafToken(string leafName, HashSet<string> tokens)
    {
        if (string.IsNullOrWhiteSpace(leafName) || tokens.Count == 0)
        {
            return false;
        }

        var cleanLeaf = CleanAppTitle(leafName);
        if (tokens.Contains(leafName) || tokens.Contains(cleanLeaf))
        {
            return true;
        }

        var compactLeaf = CompactAlphaNumeric(cleanLeaf);
        return compactLeaf.Length >= 4 && tokens.Contains(compactLeaf);
    }

    private static void AddCandidateToken(HashSet<string> target, string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return;
        }

        var trimmed = raw.Trim();
        if (trimmed.Length < 4 || GenericIgnoredTokens.Contains(trimmed))
        {
            return;
        }

        target.Add(trimmed);
    }

    private static string CleanAppTitle(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return string.Empty;
        }

        var withoutParens = Regex.Replace(raw, @"\([^)]*\)", " ");
        var withoutVersion = VersionOrArchNoiseRegex().Replace(withoutParens, " ");
        return Regex.Replace(withoutVersion, @"\s+", " ").Trim(' ', '-', '_', '.');
    }

    private static string CompactAlphaNumeric(string text) =>
        new(text.Where(char.IsLetterOrDigit).ToArray());

    private static long EstimateDirectorySizeBounded(string directoryPath, int maxFiles = 2500)
    {
        long total = 0;
        var count = 0;
        try
        {
            foreach (var file in Directory.EnumerateFiles(directoryPath, "*", new EnumerationOptions
                     {
                         RecurseSubdirectories = true,
                         IgnoreInaccessible = true,
                         AttributesToSkip = FileAttributes.ReparsePoint
                     }))
            {
                try
                {
                    total += new FileInfo(file).Length;
                }
                catch
                {
                    // Ignore locked file
                }

                if (++count >= maxFiles)
                {
                    break;
                }
            }
        }
        catch
        {
            // Ignore inaccessible directory
        }

        return total;
    }
}
