namespace UltimateWindows.Modules.Cleaner.Utilities;

/// <summary>
/// Безопасный парсер путей исполняемых файлов из командных строк реестра Windows (Run, UninstallString, MuiCache, FirewallRules).
/// Исключает ложные срабатывания на системные хосты (msiexec, rundll32), сетевые UNC-пути и съемные носители.
/// </summary>
public static class CommandLinePathExtractor
{
    private static readonly string[] IgnoredSystemHosts =
    [
        "msiexec",
        "msiexec.exe",
        "rundll32",
        "rundll32.exe",
        "regsvr32",
        "regsvr32.exe",
        "cmd",
        "cmd.exe",
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
        "wscript",
        "wscript.exe",
        "cscript",
        "cscript.exe",
        "svchost",
        "svchost.exe",
        "explorer",
        "explorer.exe",
        "system"
    ];

    /// <summary>
    /// Пытается извлечь абсолютный локальный путь к .exe файлу из командной строки реестра.
    /// Возвращает null, если строка относится к системному хосту (msiexec/rundll32), UNC-сети или не содержит явного пути.
    /// </summary>
    public static string? TryExtractLocalExecutablePath(string? rawCommandLine)
    {
        if (string.IsNullOrWhiteSpace(rawCommandLine))
        {
            return null;
        }

        var expanded = Environment.ExpandEnvironmentVariables(rawCommandLine.Trim());
        if (expanded.StartsWith(@"\\", StringComparison.Ordinal))
        {
            // Никогда не трогаем сетевые пути \\Server\Share — сервер может быть просто временно недоступен
            return null;
        }

        string candidate;
        if (expanded.StartsWith('"'))
        {
            var closingQuote = expanded.IndexOf('"', 1);
            if (closingQuote <= 1)
            {
                return null;
            }

            candidate = expanded[1..closingQuote].Trim();
        }
        else
        {
            var exeIdx = expanded.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            if (exeIdx > 0)
            {
                candidate = expanded[..(exeIdx + 4)].Trim();
            }
            else
            {
                var firstSpace = expanded.IndexOf(' ');
                candidate = (firstSpace > 0 ? expanded[..firstSpace] : expanded).Trim();
            }
        }

        if (string.IsNullOrWhiteSpace(candidate))
        {
            return null;
        }

        var fileName = GetCrossPlatformFileName(candidate);
        foreach (var host in IgnoredSystemHosts)
        {
            if (string.Equals(fileName, host, StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }
        }

        // Проверяем формат локального Windows-пути вида C:\... и расширение исполняемого файла
        if (!LooksLikeWindowsDriveRootedPath(candidate))
        {
            return null;
        }

        if (!candidate.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
            !candidate.EndsWith(".scr", StringComparison.OrdinalIgnoreCase) &&
            !candidate.EndsWith(".bat", StringComparison.OrdinalIgnoreCase) &&
            !candidate.EndsWith(".cmd", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return candidate;
    }

    /// <summary>
    /// Извлекает путь к .exe из имени параметра MuiCache (например, "C:\Games\Old\game.exe.FriendlyAppName").
    /// </summary>
    public static string? TryExtractFromMuiCacheValueName(string? muiValueName)
    {
        if (string.IsNullOrWhiteSpace(muiValueName))
        {
            return null;
        }

        var trimmed = muiValueName.Trim();
        ReadOnlySpan<string> suffixes = [".FriendlyAppName", ".ApplicationCompany"];

        foreach (var suffix in suffixes)
        {
            if (trimmed.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            {
                trimmed = trimmed[..^suffix.Length];
                break;
            }
        }

        return TryExtractLocalExecutablePath(trimmed);
    }

    /// <summary>
    /// Извлекает путь к приложению из строки правила Windows Firewall ("v2.30|Action=Allow|Active=TRUE|...|App=C:\...\app.exe|...").
    /// </summary>
    public static string? TryExtractFromFirewallRule(string? firewallRuleValue)
    {
        if (string.IsNullOrWhiteSpace(firewallRuleValue))
        {
            return null;
        }

        // Пропускаем правила для пакетов UWP/MSIX (содержат Pkg= или AppPkgId=)
        if (firewallRuleValue.Contains("|AppPkgId=", StringComparison.OrdinalIgnoreCase) ||
            firewallRuleValue.Contains("|Pkg=", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        const string marker = "|App=";
        var idx = firewallRuleValue.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (idx < 0)
        {
            return null;
        }

        var start = idx + marker.Length;
        var end = firewallRuleValue.IndexOf('|', start);
        var rawApp = end >= 0 ? firewallRuleValue[start..end] : firewallRuleValue[start..];

        return TryExtractLocalExecutablePath(rawApp);
    }

    /// <summary>
    /// Проверяет, не относится ли запрещенная ветка реестра к системным классам COM / WinRT / WinSxS,
    /// удаление которых запрещено архитектурой UltimateWindows.
    /// </summary>
    public static bool IsForbiddenComOrSystemRegistryKey(string hiveAndSubKey)
    {
        if (string.IsNullOrWhiteSpace(hiveAndSubKey))
        {
            return true;
        }

        var norm = hiveAndSubKey.Replace('/', '\\').ToUpperInvariant();
        return norm.StartsWith(@"HKCR\CLSID", StringComparison.Ordinal) ||
               norm.StartsWith(@"HKEY_CLASSES_ROOT\CLSID", StringComparison.Ordinal) ||
               norm.StartsWith(@"HKCR\TYPELIB", StringComparison.Ordinal) ||
               norm.StartsWith(@"HKCR\INTERFACE", StringComparison.Ordinal) ||
               norm.Contains(@"\CLASSES\CLSID\", StringComparison.Ordinal) ||
               norm.Contains(@"\CLASSES\TYPELIB\", StringComparison.Ordinal) ||
               norm.Contains(@"\CLASSES\INTERFACE\", StringComparison.Ordinal) ||
               norm.Contains(@"COMPONENT BASED SERVICING", StringComparison.Ordinal) ||
               norm.Contains(@"SIDEBYSIDE", StringComparison.Ordinal);
    }

    private static bool LooksLikeWindowsDriveRootedPath(string path)
    {
        return path.Length >= 4 &&
               char.IsLetter(path[0]) &&
               path[1] == ':' &&
               (path[2] == '\\' || path[2] == '/');
    }

    private static string GetCrossPlatformFileName(string path)
    {
        var idx = path.LastIndexOfAny(['\\', '/']);
        return idx >= 0 ? path[(idx + 1)..] : path;
    }
}
