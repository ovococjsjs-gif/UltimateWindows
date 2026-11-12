namespace UltimateWindows.Modules.Cleaner.Rules;

/// <summary>
/// Папки компьютера, на которые ссылаются правила очистки через переменные вида %LocalAppData%.
/// Отделено от системы, чтобы каталог и защиту можно было проверять на условном компьютере внутри обычной папки.
/// </summary>
public sealed class CleanupEnvironment
{
    private static readonly Dictionary<string, string> CanonicalNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ["UserProfile"] = "UserProfile",
        ["AppData"] = "AppData",
        ["LocalAppData"] = "LocalAppData",
        ["LocalLowAppData"] = "LocalLowAppData",
        ["LocalLow"] = "LocalLowAppData",
        ["LocalAppDataLow"] = "LocalLowAppData",
        ["ProgramData"] = "ProgramData",
        ["CommonAppData"] = "ProgramData",
        ["AllUsersProfile"] = "ProgramData",
        ["ProgramFiles"] = "ProgramFiles",
        ["CommonProgramFiles"] = "CommonProgramFiles",
        ["WinDir"] = "WinDir",
        ["SystemRoot"] = "WinDir",
        ["SystemDrive"] = "SystemDrive",
        ["HomeDrive"] = "SystemDrive",
        ["Temp"] = "Temp",
        ["Tmp"] = "Temp",
        ["Documents"] = "Documents",
        ["Pictures"] = "Pictures",
        ["Music"] = "Music",
        ["Video"] = "Video",
        ["Videos"] = "Video",
        ["Desktop"] = "Desktop",
        ["Downloads"] = "Downloads",
        ["Public"] = "Public"
    };

    private readonly Dictionary<string, string[]> _variables;

    public CleanupEnvironment(
        IReadOnlyDictionary<string, IReadOnlyList<string>> variables,
        int windowsBuild = 0,
        Version? windowsVersion = null)
    {
        ArgumentNullException.ThrowIfNull(variables);

        _variables = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, values) in variables)
        {
            if (!CanonicalNames.TryGetValue(name, out var canonical))
            {
                throw new ArgumentException($"Неизвестная переменная «{name}».", nameof(variables));
            }

            _variables[canonical] = values
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .Select(v => v.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        WindowsBuild = windowsBuild;
        WindowsVersion = windowsVersion ?? new Version(10, 0);
    }

    /// <summary>Номер сборки Windows; 0 — неизвестен, условия по сборке не применяются.</summary>
    public int WindowsBuild { get; }

    public Version WindowsVersion { get; }

    public static bool IsKnownVariable(string name) => CanonicalNames.ContainsKey(name);

    public static bool TryGetCanonicalName(string name, out string canonical) =>
        CanonicalNames.TryGetValue(name, out canonical!);

    /// <summary>
    /// Папки, которые обозначает переменная. У %ProgramFiles% их две; у неизвестной или пустой — ни одной.
    /// </summary>
    public IReadOnlyList<string> Resolve(string variableName) =>
        CanonicalNames.TryGetValue(variableName, out var canonical) && _variables.TryGetValue(canonical, out var values)
            ? values
            : [];

    public string? ResolveSingle(string variableName)
    {
        var values = Resolve(variableName);
        return values.Count > 0 ? values[0] : null;
    }

    /// <summary>
    /// Папки настоящего компьютера.
    /// </summary>
    public static CleanupEnvironment FromSystem()
    {
        static string Folder(Environment.SpecialFolder folder) => Environment.GetFolderPath(folder);

        var userProfile = Folder(Environment.SpecialFolder.UserProfile);
        var localAppData = Folder(Environment.SpecialFolder.LocalApplicationData);
        var windows = Folder(Environment.SpecialFolder.Windows);
        var systemDrive = string.IsNullOrWhiteSpace(windows) ? "" : Path.GetPathRoot(windows) ?? "";
        var localLow = string.IsNullOrWhiteSpace(localAppData)
            ? ""
            : Path.Combine(Path.GetDirectoryName(localAppData.TrimEnd('\\', '/')) ?? "", "LocalLow");

        var map = new Dictionary<string, IReadOnlyList<string>>
        {
            ["UserProfile"] = [userProfile],
            ["AppData"] = [Folder(Environment.SpecialFolder.ApplicationData)],
            ["LocalAppData"] = [localAppData],
            ["LocalLowAppData"] = [localLow],
            ["ProgramData"] = [Folder(Environment.SpecialFolder.CommonApplicationData)],
            ["ProgramFiles"] = [Folder(Environment.SpecialFolder.ProgramFiles), Folder(Environment.SpecialFolder.ProgramFilesX86)],
            ["CommonProgramFiles"] = [Folder(Environment.SpecialFolder.CommonProgramFiles), Folder(Environment.SpecialFolder.CommonProgramFilesX86)],
            ["WinDir"] = [windows],
            ["SystemDrive"] = [systemDrive],
            ["Temp"] = [Path.GetTempPath().TrimEnd('\\', '/')],
            ["Documents"] = [Folder(Environment.SpecialFolder.MyDocuments)],
            ["Pictures"] = [Folder(Environment.SpecialFolder.MyPictures)],
            ["Music"] = [Folder(Environment.SpecialFolder.MyMusic)],
            ["Video"] = [Folder(Environment.SpecialFolder.MyVideos)],
            ["Desktop"] = [Folder(Environment.SpecialFolder.DesktopDirectory)],
            ["Downloads"] = [string.IsNullOrWhiteSpace(userProfile) ? "" : Path.Combine(userProfile, "Downloads")],
            ["Public"] = [Environment.GetEnvironmentVariable("PUBLIC") ?? ""]
        };

        var os = Environment.OSVersion.Version;
        return new CleanupEnvironment(
            map,
            OperatingSystem.IsWindows() ? os.Build : 0,
            OperatingSystem.IsWindows() ? new Version(os.Major, os.Minor) : null);
    }

    /// <summary>
    /// Условный компьютер внутри папки <paramref name="root"/>: та же раскладка, что у Windows,
    /// но ничего настоящего не затрагивается. Нужен проверкам каталога и защиты.
    /// </summary>
    public static CleanupEnvironment ForRoot(string root, string userName = "Tester", int windowsBuild = 26100)
    {
        var userProfile = Path.Combine(root, "Users", userName);
        var localAppData = Path.Combine(userProfile, "AppData", "Local");
        var map = new Dictionary<string, IReadOnlyList<string>>
        {
            ["UserProfile"] = [userProfile],
            ["AppData"] = [Path.Combine(userProfile, "AppData", "Roaming")],
            ["LocalAppData"] = [localAppData],
            ["LocalLowAppData"] = [Path.Combine(userProfile, "AppData", "LocalLow")],
            ["ProgramData"] = [Path.Combine(root, "ProgramData")],
            ["ProgramFiles"] = [Path.Combine(root, "Program Files"), Path.Combine(root, "Program Files (x86)")],
            ["CommonProgramFiles"] =
            [
                Path.Combine(root, "Program Files", "Common Files"),
                Path.Combine(root, "Program Files (x86)", "Common Files")
            ],
            ["WinDir"] = [Path.Combine(root, "Windows")],
            ["SystemDrive"] = [root],
            ["Temp"] = [Path.Combine(localAppData, "Temp")],
            ["Documents"] = [Path.Combine(userProfile, "Documents")],
            ["Pictures"] = [Path.Combine(userProfile, "Pictures")],
            ["Music"] = [Path.Combine(userProfile, "Music")],
            ["Video"] = [Path.Combine(userProfile, "Videos")],
            ["Desktop"] = [Path.Combine(userProfile, "Desktop")],
            ["Downloads"] = [Path.Combine(userProfile, "Downloads")],
            ["Public"] = [Path.Combine(root, "Users", "Public")]
        };

        return new CleanupEnvironment(map, windowsBuild);
    }
}

/// <summary>
/// Разобранный путь правила: переменная в начале и части пути после неё.
/// Вместо переменной может стоять значение реестра: «%reg:HKCU\Software\Valve\Steam@SteamPath%\logs» —
/// так находятся программы, установленные не в стандартную папку.
/// </summary>
public sealed record CleanupPathPattern(
    string? Variable,
    string? RegistryKey,
    string? RegistryValue,
    IReadOnlyList<string> Segments)
{
    private static readonly char[] Separators = ['\\', '/'];
    private static readonly char[] ForbiddenSegmentChars = [':', '|', '<', '>', '"'];

    public bool IsRegistryBased => RegistryKey is not null;

    public int WildcardCount => Segments.Count(IsWildcard);

    public static bool IsWildcard(string segment) => segment.Contains('*') || segment.Contains('?');

    public static bool TryParse(string? text, bool allowRegistryVariable, out CleanupPathPattern pattern, out string error)
    {
        pattern = new CleanupPathPattern(null, null, null, []);
        error = "";

        if (string.IsNullOrWhiteSpace(text))
        {
            error = "путь пуст";
            return false;
        }

        text = text.Trim();
        if (text[0] != '%')
        {
            error = "путь должен начинаться с переменной, например %LocalAppData%";
            return false;
        }

        var close = text.IndexOf('%', 1);
        if (close < 0)
        {
            error = "у переменной нет закрывающего знака %";
            return false;
        }

        var name = text[1..close];
        string? variable = null;
        string? registryKey = null;
        string? registryValue = null;

        if (name.StartsWith("reg:", StringComparison.OrdinalIgnoreCase))
        {
            if (!allowRegistryVariable)
            {
                error = "путь из реестра здесь не разрешён";
                return false;
            }

            var body = name[4..];
            var at = body.LastIndexOf('@');
            if (at <= 0)
            {
                error = "путь из реестра пишется как %reg:HKCU\\Раздел@Значение%";
                return false;
            }

            registryKey = body[..at].Trim();
            registryValue = body[(at + 1)..].Trim();
            if (!IsSupportedRegistryKey(registryKey))
            {
                error = "путь из реестра должен начинаться с HKCU\\ или HKLM\\";
                return false;
            }
        }
        else if (!CleanupEnvironment.TryGetCanonicalName(name, out variable!))
        {
            error = $"неизвестная переменная %{name}%";
            return false;
        }

        var rest = text[(close + 1)..];
        if (rest.Length > 0 && Array.IndexOf(Separators, rest[0]) < 0)
        {
            error = "после переменной должна идти косая черта";
            return false;
        }

        var segments = rest.Split(Separators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var segment in segments)
        {
            if (segment is "." or ".." || segment.IndexOfAny(ForbiddenSegmentChars) >= 0 || segment.Contains('%'))
            {
                error = $"недопустимая часть пути «{segment}»";
                return false;
            }
        }

        pattern = new CleanupPathPattern(variable, registryKey, registryValue, segments);
        return true;
    }

    public static bool IsSupportedRegistryKey(string? keyPath) =>
        !string.IsNullOrWhiteSpace(keyPath) &&
        (keyPath.StartsWith(@"HKCU\", StringComparison.OrdinalIgnoreCase) ||
         keyPath.StartsWith(@"HKLM\", StringComparison.OrdinalIgnoreCase)) &&
        keyPath.Length > 5;

    /// <summary>
    /// Приводит маску имени файла к простому виду: «*.*» в правилах означает «все файлы».
    /// </summary>
    public static string NormalizeFilePattern(string pattern)
    {
        pattern = pattern.Trim();
        return pattern is "*.*" or "" ? "*" : pattern;
    }
}
