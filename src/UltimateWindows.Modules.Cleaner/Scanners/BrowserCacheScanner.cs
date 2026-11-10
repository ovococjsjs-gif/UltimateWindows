using UltimateWindows.Core.Guards;
using UltimateWindows.Modules.Cleaner.Contracts;
using UltimateWindows.Modules.Cleaner.Models;

namespace UltimateWindows.Modules.Cleaner.Scanners;

/// <summary>
/// Обнаруживает все профили популярных браузеров (Chrome, Edge, Яндекс, Brave, Opera/GX, Vivaldi, Firefox)
/// и собирает только безопасные кэш-файлы под жестким контролем BrowserVaultGuard.
/// </summary>
public sealed class BrowserCacheScanner
{
    private static readonly (string Name, string RelativeUserDataPath, string[] ProcessNames)[] ChromiumBrowsers =
    [
        ("Google Chrome", @"Google\Chrome\User Data", ["chrome"]),
        ("Microsoft Edge", @"Microsoft\Edge\User Data", ["msedge"]),
        ("Яндекс Браузер", @"Yandex\YandexBrowser\User Data", ["browser"]),
        ("Brave Browser", @"BraveSoftware\Brave-Browser\User Data", ["brave"]),
        ("Vivaldi", @"Vivaldi\User Data", ["vivaldi"])
    ];

    private static readonly (string Name, string RelativeProfilePath, string[] ProcessNames)[] OperaEditions =
    [
        ("Opera", @"Opera Software\Opera Stable", ["opera"]),
        ("Opera GX", @"Opera Software\Opera GX Stable", ["opera"])
    ];

    private static readonly string[] ChromiumDisposableSubfolders =
    [
        Path.Combine("Cache", "Cache_Data"),
        Path.Combine("Code Cache", "js"),
        Path.Combine("Code Cache", "wasm"),
        "GPUCache",
        "DawnCache",
        "GrShaderCache",
        "ShaderCache",
        Path.Combine("Service Worker", "CacheStorage"),
        Path.Combine("Service Worker", "ScriptCache")
    ];

    private static readonly string[] FirefoxDisposableSubfolders =
    [
        Path.Combine("cache2", "entries"),
        Path.Combine("cache2", "doomed"),
        "startupCache",
        "shader-cache",
        "thumbnails"
    ];

    private readonly ICleanerPlatformBridge _platformBridge;
    private readonly string _localAppData;
    private readonly string _roamingAppData;

    public BrowserCacheScanner(
        ICleanerPlatformBridge platformBridge,
        string? customLocalAppData = null,
        string? customRoamingAppData = null)
    {
        _platformBridge = platformBridge ?? throw new ArgumentNullException(nameof(platformBridge));
        _localAppData = customLocalAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        _roamingAppData = customRoamingAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    }

    public IReadOnlyList<DiscoveredBrowserProfile> DiscoverProfiles()
    {
        var profiles = new List<DiscoveredBrowserProfile>();

        // 1. Стандартные мульти-профильные Chromium браузеры (Default, Profile 1..N)
        foreach (var (name, relPath, procNames) in ChromiumBrowsers)
        {
            var userDataDir = CombineNormalized(_localAppData, relPath);
            if (!Directory.Exists(userDataDir))
            {
                continue;
            }

            var isRunning = _platformBridge.IsProcessRunningByName(procNames);
            foreach (var subDir in SafeEnumerateDirectories(userDataDir))
            {
                var folderName = Path.GetFileName(subDir);
                if (string.Equals(folderName, "Default", StringComparison.OrdinalIgnoreCase) ||
                    folderName.StartsWith("Profile ", StringComparison.OrdinalIgnoreCase))
                {
                    profiles.Add(new DiscoveredBrowserProfile(
                        BrowserName: name,
                        ProfileName: folderName,
                        CacheRootDirectory: subDir,
                        ProfileDataDirectory: subDir,
                        IsGeckoFirefox: false,
                        IsBrowserCurrentlyRunning: isRunning));
                }
            }
        }

        // 2. Opera / Opera GX (кэш в LocalAppData, данные профиля в RoamingAppData)
        foreach (var (name, relPath, procNames) in OperaEditions)
        {
            var localOpera = CombineNormalized(_localAppData, relPath);
            var roamingOpera = CombineNormalized(_roamingAppData, relPath);
            if (!Directory.Exists(localOpera) && !Directory.Exists(roamingOpera))
            {
                continue;
            }

            var isRunning = _platformBridge.IsProcessRunningByName(procNames);
            profiles.Add(new DiscoveredBrowserProfile(
                BrowserName: name,
                ProfileName: "Main",
                CacheRootDirectory: Directory.Exists(localOpera) ? localOpera : roamingOpera,
                ProfileDataDirectory: Directory.Exists(roamingOpera) ? roamingOpera : localOpera,
                IsGeckoFirefox: false,
                IsBrowserCurrentlyRunning: isRunning));
        }

        // 3. Mozilla Firefox (кэш строго в LocalAppData\Mozilla\Firefox\Profiles\*, пароли в Roaming!)
        var ffLocalProfiles = CombineNormalized(_localAppData, @"Mozilla\Firefox\Profiles");
        if (Directory.Exists(ffLocalProfiles))
        {
            var isFfRunning = _platformBridge.IsProcessRunningByName(["firefox"]);
            foreach (var profDir in SafeEnumerateDirectories(ffLocalProfiles))
            {
                var folderName = Path.GetFileName(profDir);
                var roamingTwin = CombineNormalized(_roamingAppData, Path.Combine(@"Mozilla\Firefox\Profiles", folderName));
                profiles.Add(new DiscoveredBrowserProfile(
                    BrowserName: "Mozilla Firefox",
                    ProfileName: folderName,
                    CacheRootDirectory: profDir,
                    ProfileDataDirectory: roamingTwin,
                    IsGeckoFirefox: true,
                    IsBrowserCurrentlyRunning: isFfRunning));
            }
        }

        return profiles;
    }

    public (IReadOnlyList<CleanupCandidateFile> Candidates, IReadOnlyList<string> RunningWarnings) ScanSafeCacheFiles(
        CancellationToken ct = default)
    {
        var profiles = DiscoverProfiles();
        var candidates = new List<CleanupCandidateFile>();
        var warnings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var profile in profiles)
        {
            ct.ThrowIfCancellationRequested();

            if (profile.IsBrowserCurrentlyRunning)
            {
                warnings.Add($"{profile.BrowserName} сейчас открыт — занятые вкладками файлы кэша будут аккуратно пропущены.");
            }

            var targetSubfolders = profile.IsGeckoFirefox
                ? FirefoxDisposableSubfolders
                : ChromiumDisposableSubfolders;

            foreach (var relCache in targetSubfolders)
            {
                var cacheDir = Path.Combine(profile.CacheRootDirectory, relCache);
                if (!Directory.Exists(cacheDir))
                {
                    continue;
                }

                foreach (var file in SafeEnumerateFilesRecursive(cacheDir))
                {
                    ct.ThrowIfCancellationRequested();

                    // Двойной замок безопасности: проверяем каждый файл через инвариант BrowserVaultGuard!
                    if (!BrowserVaultGuard.CanDeleteDuringStandardCleanup(file))
                    {
                        continue;
                    }

                    try
                    {
                        var info = new FileInfo(file);
                        if (info.Exists && info.Length > 0)
                        {
                            candidates.Add(new CleanupCandidateFile(
                                Category: CleanerCategoryKind.BrowserCache,
                                SourceLabel: $"{profile.BrowserName} ({profile.ProfileName})",
                                FullPath: info.FullName,
                                SizeBytes: info.Length));
                        }
                    }
                    catch
                    {
                        // Пропускаем файлы, удаленные самим браузером на лету
                    }
                }
            }
        }

        return (candidates, warnings.ToList());
    }

    private static string CombineNormalized(string basePath, string windowsStyleRelative)
    {
        var segments = windowsStyleRelative.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries);
        var current = basePath;
        foreach (var seg in segments)
        {
            current = Path.Combine(current, seg);
        }

        return current;
    }

    private static IEnumerable<string> SafeEnumerateDirectories(string dir)
    {
        try
        {
            return Directory.EnumerateDirectories(dir);
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    private static IEnumerable<string> SafeEnumerateFilesRecursive(string rootDir)
    {
        var options = new EnumerationOptions
        {
            IgnoreInaccessible = true,
            RecurseSubdirectories = true,
            AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.System
        };

        try
        {
            return Directory.EnumerateFiles(rootDir, "*", options);
        }
        catch
        {
            return Array.Empty<string>();
        }
    }
}
