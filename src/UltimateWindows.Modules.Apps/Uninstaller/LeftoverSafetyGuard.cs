using UltimateWindows.Core.Guards;

namespace UltimateWindows.Modules.Apps.Uninstaller;

/// <summary>
/// Защитный фильтр чистого деинсталлятора: запрещает помечать как «хвосты» системные каталоги ОС,
/// общие корневые папки крупных издателей, пользовательские документы и профили браузеров с паролями.
/// </summary>
public static class LeftoverSafetyGuard
{
    private static readonly HashSet<string> SharedVendorOrSystemFolderNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft",
        "Windows",
        "WindowsApps",
        "Packages",
        "Package Cache",
        "Publishers",
        "Temp",
        "ConnectedDevicesPlatform",
        "D3DSCache",
        "Diagnostics",
        "FontCache",
        "IdentityService",
        "Google",
        "Mozilla",
        "Apple",
        "Apple Computer",
        "Intel",
        "NVIDIA",
        "NVIDIA Corporation",
        "AMD",
        "ATI",
        "ATI Technologies",
        "Realtek",
        "Valve",
        "Adobe",
        "Autodesk",
        "Common Files",
        "Internet Explorer",
        "Windows Defender",
        "Windows Mail",
        "Windows NT",
        "Windows Photo Viewer",
        "Windows Portable Devices",
        "WindowsPowerShell",
        "PowerShell",
        "dotnet",
        "UltimateWindows"
    };

    private static readonly HashSet<string> ProtectedRegistryLeafNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Classes",
        "Clients",
        "Microsoft",
        "Policies",
        "RegisteredApplications",
        "WOW6432Node",
        "Windows",
        "Intel",
        "NVIDIA Corporation",
        "AMD",
        "Google",
        "Mozilla",
        "UltimateWindows"
    };

    public static bool IsSafeFilesystemLeftoverCandidate(string candidatePath)
    {
        if (string.IsNullOrWhiteSpace(candidatePath))
        {
            return false;
        }

        if (BrowserVaultGuard.IsInsideBrowserProfileArea(candidatePath) ||
            BrowserVaultGuard.IsProtectedPersonalData(candidatePath))
        {
            return false;
        }

        var normalized = candidatePath.Trim().Replace('/', '\\').TrimEnd('\\');
        if (normalized.Length < 10)
        {
            // Защита корней дисков и коротких системных путей (C:\, C:\Users, C:\Windows)
            return false;
        }

        var segments = normalized.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length < 3)
        {
            // Например C:\Program Files или C:\ProgramData целиком удалять запрещено
            return false;
        }

        // Никогда не трогаем C:\Windows и личные библиотеки пользователя
        if (segments.Length >= 2 &&
            string.Equals(segments[1], "Windows", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // Запрещаем помечать личные папки Documents / Pictures / Videos / Music / Downloads целиком
        if (segments.Length == 4 &&
            string.Equals(segments[1], "Users", StringComparison.OrdinalIgnoreCase) &&
            segments[3] is "Documents" or "Pictures" or "Videos" or "Music" or "Downloads" or "Desktop" or "Favorites" or "OneDrive")
        {
            return false;
        }

        // Если это папка первого уровня в AppData\Local, AppData\Roaming, ProgramData или Program Files —
        // проверяем, что это не общая папка вендора (Microsoft, Google, NVIDIA и т.д.)
        var leaf = segments[^1];
        var parent = segments[^2];
        var isTopLevelInSharedRoot =
            string.Equals(parent, "Local", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(parent, "LocalLow", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(parent, "Roaming", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(parent, "ProgramData", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(parent, "Program Files", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(parent, "Program Files (x86)", StringComparison.OrdinalIgnoreCase);

        if (isTopLevelInSharedRoot && SharedVendorOrSystemFolderNames.Contains(leaf))
        {
            return false;
        }

        return true;
    }

    public static bool IsSafeRegistryLeftoverCandidate(string registryPath)
    {
        if (string.IsNullOrWhiteSpace(registryPath))
        {
            return false;
        }

        var normalized = registryPath.Trim().Replace('/', '\\').TrimEnd('\\');
        var segments = normalized.Split('\\', StringSplitOptions.RemoveEmptyEntries);

        // Ожидаем минимум HKCU\Software\<AppOrVendor> (3 сегмента)
        if (segments.Length < 3)
        {
            return false;
        }

        if (!string.Equals(segments[0], "HKCU", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(segments[0], "HKLM", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(segments[0], "HKEY_CURRENT_USER", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(segments[0], "HKEY_LOCAL_MACHINE", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!string.Equals(segments[1], "Software", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // Ветка первого уровня под Software не должна быть системной или общей папкой крупного вендора
        if (segments.Length == 3 && ProtectedRegistryLeafNames.Contains(segments[2]))
        {
            return false;
        }

        // Ветка второго уровня под WOW6432Node аналогично проверяется на общий вендор
        if (segments.Length == 4 &&
            string.Equals(segments[2], "WOW6432Node", StringComparison.OrdinalIgnoreCase) &&
            ProtectedRegistryLeafNames.Contains(segments[3]))
        {
            return false;
        }

        return true;
    }
}
