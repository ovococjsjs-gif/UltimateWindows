using UltimateWindows.Core.Enums;
using UltimateWindows.Core.Guards;

namespace UltimateWindows.Modules.Cleaner.Rules;

/// <summary>
/// Почему защита разрешила или не разрешила удаление.
/// </summary>
public enum CleanupPathVerdict
{
    Allowed = 0,

    /// <summary>Системная или личная папка, куда правилам очистки нельзя.</summary>
    ProtectedZone = 1,

    /// <summary>Пароли, автозаполнение, закладки, настройки или расширения браузера.</summary>
    BrowserPersonalData = 2,

    /// <summary>Данные браузера или приложения из Microsoft Store, которые не являются кэшем.</summary>
    RestrictedArea = 3,

    /// <summary>Ключи, кошельки, базы паролей, почтовые архивы.</summary>
    ValuableFile = 4,

    /// <summary>Правило из подключённого файла: в этом месте ему разрешены только журналы и временные файлы.</summary>
    NotDisposable = 5,

    /// <summary>Ссылка на другую папку: по ссылкам очистка не ходит.</summary>
    ReparsePoint = 6
}

/// <summary>
/// Защита путей при очистке по правилам. Проверяет каждую папку и каждый файл независимо от того,
/// что написано в правиле: ошибка в каталоге или в подключённом файле не должна стоить пользователю данных.
/// <para>
/// Что гарантируется для любого правила:
/// системные папки Windows, хранилища ключей и учётных данных, меню «Пуск», данные почты, кошельки и ключи SSH
/// не затрагиваются; в данных браузеров удаляется только кэш; папки «Документы», «Рабочий стол» и подобные,
/// а также корни дисков и профиля нельзя чистить целиком.
/// </para>
/// <para>
/// Правилам из подключённого файла вне папок данных программ разрешено удалять только журналы и временные файлы.
/// </para>
/// </summary>
public sealed class CleanupPathGuard
{
    private static readonly string[] StrictDisposableExtensions =
    [
        ".log", ".tmp", ".temp", ".dmp", ".mdmp", ".hdmp", ".etl", ".chk", ".gid", ".err", ".trace"
    ];

    private static readonly string[] ExtendedDisposableExtensions = [.. StrictDisposableExtensions, ".old", ".bak"];

    private static readonly string[] ValuableExtensions =
    [
        ".kdbx", ".kdb", ".pfx", ".p12", ".ppk", ".pst", ".ost", ".wallet", ".keystore", ".jks"
    ];

    private static readonly string[] ValuableFileNames =
    [
        "wallet.dat", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "known_hosts", "authorized_keys",
        "ntuser.dat", "usrclass.dat"
    ];

    // Папки внутри каталога Windows, где лежит только то, что можно удалять
    private static readonly string[] WindowsAllowedSubtrees =
    [
        "temp",
        "logs",
        "minidump",
        "livekernelreports",
        "softwaredistribution/download",
        "prefetch",
        "debug",
        "panther",
        "performance/winsat",
        "security/logs",
        "downloaded program files",
        "serviceprofiles/localservice/appdata/local/temp",
        "serviceprofiles/networkservice/appdata/local/temp",
        "serviceprofiles/networkservice/appdata/local/microsoft/windows/deliveryoptimization/cache"
    ];

    private static readonly string[] NeverInRoamingAppData =
    [
        "microsoft/protect", "microsoft/crypto", "microsoft/credentials", "microsoft/vault",
        "microsoft/systemcertificates", "microsoft/windows/start menu", "microsoft/windows/sendto",
        "microsoft/windows/libraries", "microsoft/windows/network shortcuts", "microsoft/windows/printer shortcuts",
        "microsoft/internet explorer/quick launch", "microsoft/templates", "microsoft/signatures",
        "microsoft/stationery", "microsoft/uproof", "microsoft/proof", "microsoft/outlook",
        "gnupg", "keepass", "keepassxc", "1password", "electrum", "bitcoin", "ethereum", "exodus", "atomic",
        "ledger live", "walletwasabi", "monero-project", "authy desktop", "winauth", "ultimatewindows"
    ];

    private static readonly string[] NeverInLocalAppData =
    [
        "microsoft/credentials", "microsoft/vault", "microsoft/outlook", "microsoft/onedrive/settings",
        "1password", "keepassxc", "coinomi", "ultimatewindows"
    ];

    private static readonly string[] NeverInProgramData =
    [
        "package cache", "microsoft/crypto", "microsoft/vault", "microsoft/windows/start menu",
        "microsoft/windows defender", "microsoft/search", "microsoft/windows/apprepository", "microsoft/windows nt",
        "microsoft/network", "microsoft/provisioning", "ssh", "ultimatewindows"
    ];

    private static readonly string[] NeverInUserProfile = [".ssh", ".gnupg", ".aws", ".azure", ".kube"];

    private static readonly string[] NeverInSystemDrive =
    [
        "system volume information", "$recycle.bin", "recovery", "boot", "efi", "config.msi", "msocache",
        "windows.old", "$windows.~bt", "$windows.~ws", "$winreagent", "documents and settings"
    ];

    private static readonly string[] StoreAppDataFolders =
    [
        "localstate", "roamingstate", "settings", "systemappdata", "localcache"
    ];

    private readonly string[] _anchors;
    private readonly string[] _neverZones;
    private readonly string[] _windowsRoots;
    private readonly string[] _windowsAllowed;
    private readonly string[] _programFiles;
    private readonly string[] _programDataAreas;
    private readonly string[] _packagesRoots;

    private string? _cachedDirectory;
    private DirectoryZone _cachedZone;

    public CleanupPathGuard(CleanupEnvironment environment, IEnumerable<string>? extraProtectedDirectories = null)
    {
        ArgumentNullException.ThrowIfNull(environment);

        string[] All(string variable) => environment.Resolve(variable).Select(Normalize).Where(p => p.Length > 0).ToArray();

        var userProfile = All("UserProfile");
        var roaming = All("AppData");
        var local = All("LocalAppData");
        var localLow = All("LocalLowAppData");
        var programData = All("ProgramData");
        var systemDrive = All("SystemDrive");
        _windowsRoots = All("WinDir");
        _programFiles = [.. All("ProgramFiles"), .. All("CommonProgramFiles")];

        var anchors = new List<string>();
        anchors.AddRange(userProfile);
        anchors.AddRange(roaming);
        anchors.AddRange(local);
        anchors.AddRange(localLow);
        anchors.AddRange(programData);
        anchors.AddRange(_windowsRoots);
        anchors.AddRange(_programFiles);
        anchors.AddRange(systemDrive);
        foreach (var variable in new[] { "Documents", "Pictures", "Music", "Video", "Desktop", "Downloads", "Public" })
        {
            anchors.AddRange(All(variable));
        }

        _anchors = anchors.Distinct(StringComparer.Ordinal).ToArray();

        var never = new List<string>();
        AddZones(never, roaming, NeverInRoamingAppData);
        AddZones(never, local, NeverInLocalAppData);
        AddZones(never, programData, NeverInProgramData);
        AddZones(never, userProfile, NeverInUserProfile);
        AddZones(never, systemDrive, NeverInSystemDrive);
        if (extraProtectedDirectories is not null)
        {
            never.AddRange(extraProtectedDirectories.Select(Normalize).Where(p => p.Length > 0));
        }

        _neverZones = never.Distinct(StringComparer.Ordinal).ToArray();

        var windowsAllowed = new List<string>();
        AddZones(windowsAllowed, _windowsRoots, WindowsAllowedSubtrees);
        _windowsAllowed = windowsAllowed.ToArray();

        // Папки данных программ: здесь внешним правилам можно удалять любые файлы
        _programDataAreas = [.. roaming, .. local, .. localLow, .. programData, .. All("Temp")];
        _packagesRoots = local.Select(l => l + "/packages").ToArray();
    }

    /// <summary>
    /// Проверяет папку правила целиком, до перебора файлов.
    /// </summary>
    public CleanupPathVerdict CheckTargetDirectory(string directory, CleanupFileTarget target, CleanupRule rule)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(rule);

        var path = Normalize(directory);
        if (path.Length == 0)
        {
            return CleanupPathVerdict.ProtectedZone;
        }

        // Корень диска, профиля, «Документов» и подобное (или папка над ними): только отдельные журналы и дампы,
        // без вложенных папок
        if (IsAnchorOrAbove(path))
        {
            if (target.Recurse || target.RemoveSelf || target.FilePatterns.Count == 0 ||
                !target.FilePatterns.All(p => IsDisposablePattern(p, ExtendedDisposableExtensions)))
            {
                return CleanupPathVerdict.ProtectedZone;
            }
        }

        var zone = Classify(path);
        if (zone.InNeverZone || (zone.InWindows && !zone.IsWindowsRoot && !zone.WindowsAllowed))
        {
            return CleanupPathVerdict.ProtectedZone;
        }

        return CleanupPathVerdict.Allowed;
    }

    /// <summary>
    /// Проверяет отдельный файл перед тем, как он попадёт в список на удаление, и ещё раз — перед удалением.
    /// </summary>
    public CleanupPathVerdict CheckFile(string filePath, CleanupRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);

        var path = Normalize(filePath);
        var slash = path.LastIndexOf('/');
        if (slash <= 0)
        {
            return CleanupPathVerdict.ProtectedZone;
        }

        var directory = path[..slash];
        var name = path[(slash + 1)..];
        var extension = GetExtension(name);

        if (Array.IndexOf(ValuableFileNames, name) >= 0 || Array.IndexOf(ValuableExtensions, extension) >= 0)
        {
            return CleanupPathVerdict.ValuableFile;
        }

        var browserDecision = BrowserVaultGuard.EvaluatePath(filePath);
        if (browserDecision is VaultPathDecision.ProtectedCredentialsOrAutofill or VaultPathDecision.ProtectedSessionOrExtension)
        {
            return CleanupPathVerdict.BrowserPersonalData;
        }

        var zone = _cachedDirectory == directory ? _cachedZone : Classify(directory);
        _cachedDirectory = directory;
        _cachedZone = zone;

        if (zone.InNeverZone)
        {
            return CleanupPathVerdict.ProtectedZone;
        }

        var isCache = browserDecision == VaultPathDecision.SafeDisposableCache;
        if (zone.InBrowserArea && !isCache)
        {
            return CleanupPathVerdict.RestrictedArea;
        }

        if (zone.InWindows)
        {
            if (zone.IsWindowsRoot)
            {
                return Array.IndexOf(ExtendedDisposableExtensions, extension) >= 0
                    ? CleanupPathVerdict.Allowed
                    : CleanupPathVerdict.ProtectedZone;
            }

            return zone.WindowsAllowed ? CleanupPathVerdict.Allowed : CleanupPathVerdict.ProtectedZone;
        }

        if (rule.Origin == CleanupRuleOrigin.External)
        {
            if (zone.InStoreAppData && !isCache)
            {
                return CleanupPathVerdict.RestrictedArea;
            }

            if (!zone.InProgramDataArea)
            {
                var allowed = zone.InProgramFiles ? ExtendedDisposableExtensions : StrictDisposableExtensions;
                if (Array.IndexOf(allowed, extension) < 0)
                {
                    return CleanupPathVerdict.NotDisposable;
                }
            }
        }

        return CleanupPathVerdict.Allowed;
    }

    public static string Describe(CleanupPathVerdict verdict) => verdict switch
    {
        CleanupPathVerdict.Allowed => "можно удалять",
        CleanupPathVerdict.ProtectedZone => "системная или личная папка, очистке сюда нельзя",
        CleanupPathVerdict.BrowserPersonalData => "пароли, автозаполнение, закладки или настройки браузера",
        CleanupPathVerdict.RestrictedArea => "данные браузера или приложения, которые не являются кэшем",
        CleanupPathVerdict.ValuableFile => "ключи, кошельки, базы паролей или почтовые архивы",
        CleanupPathVerdict.NotDisposable => "правилу из подключённого файла здесь разрешены только журналы и временные файлы",
        CleanupPathVerdict.ReparsePoint => "ссылка на другую папку",
        _ => "защищено"
    };

    /// <summary>
    /// Приводит путь к виду для сравнения: прямые косые черты, без косой черты в конце, строчные буквы.
    /// </summary>
    public static string Normalize(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return "";
        }

        var normalized = path.Trim().Replace('\\', '/');
        while (normalized.Length > 1 && normalized.EndsWith('/'))
        {
            normalized = normalized[..^1];
        }

        return normalized.ToLowerInvariant();
    }

    private static void AddZones(List<string> sink, string[] roots, string[] relative)
    {
        foreach (var root in roots)
        {
            foreach (var item in relative)
            {
                sink.Add(root + "/" + item);
            }
        }
    }

    private static bool IsUnder(string path, string parent) =>
        path.Length > parent.Length &&
        path[parent.Length] == '/' &&
        path.StartsWith(parent, StringComparison.Ordinal);

    private static bool IsSameOrUnder(string path, string parent) =>
        string.Equals(path, parent, StringComparison.Ordinal) || IsUnder(path, parent);

    private bool IsAnchorOrAbove(string path)
    {
        foreach (var anchor in _anchors)
        {
            if (IsSameOrUnder(anchor, path))
            {
                return true;
            }
        }

        // Корень диска вида «d:» не входит в известные папки, но чистить его целиком тоже нельзя
        return path.Length <= 3 && path.Length >= 2 && path[1] == ':';
    }

    private DirectoryZone Classify(string directory)
    {
        var zone = new DirectoryZone();

        foreach (var never in _neverZones)
        {
            if (IsSameOrUnder(directory, never))
            {
                zone.InNeverZone = true;
                break;
            }
        }

        foreach (var windows in _windowsRoots)
        {
            if (IsSameOrUnder(directory, windows))
            {
                zone.InWindows = true;
                zone.IsWindowsRoot = string.Equals(directory, windows, StringComparison.Ordinal);
                break;
            }
        }

        if (zone.InWindows && !zone.IsWindowsRoot)
        {
            foreach (var allowed in _windowsAllowed)
            {
                if (IsSameOrUnder(directory, allowed))
                {
                    zone.WindowsAllowed = true;
                    break;
                }
            }
        }

        foreach (var programFiles in _programFiles)
        {
            if (IsSameOrUnder(directory, programFiles))
            {
                zone.InProgramFiles = true;
                break;
            }
        }

        foreach (var area in _programDataAreas)
        {
            if (IsUnder(directory, area))
            {
                zone.InProgramDataArea = true;
                break;
            }
        }

        foreach (var packages in _packagesRoots)
        {
            if (!IsUnder(directory, packages))
            {
                continue;
            }

            // packages/<приложение>/<папка данных>/…
            var rest = directory[(packages.Length + 1)..].Split('/');
            if (rest.Length >= 2 && Array.IndexOf(StoreAppDataFolders, rest[1]) >= 0)
            {
                zone.InStoreAppData = true;
            }

            break;
        }

        zone.InBrowserArea = BrowserVaultGuard.IsInsideBrowserProfileArea(directory);
        return zone;
    }

    private static bool IsDisposablePattern(string pattern, string[] extensions)
    {
        var extension = GetExtension(pattern.Trim().ToLowerInvariant());
        return extension.Length > 1 &&
               !CleanupPathPattern.IsWildcard(extension) &&
               Array.IndexOf(extensions, extension) >= 0;
    }

    private static string GetExtension(string fileName)
    {
        var dot = fileName.LastIndexOf('.');
        return dot >= 0 ? fileName[dot..] : "";
    }

    private struct DirectoryZone
    {
        public bool InNeverZone;
        public bool InWindows;
        public bool IsWindowsRoot;
        public bool WindowsAllowed;
        public bool InProgramFiles;
        public bool InProgramDataArea;
        public bool InStoreAppData;
        public bool InBrowserArea;
    }
}
