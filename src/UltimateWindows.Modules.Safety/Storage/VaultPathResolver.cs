namespace UltimateWindows.Modules.Safety.Storage;

/// <summary>
/// Определяет единую точку хранения бэкапов и карантина (Portable или системный каталог без распыления файлов по ОС).
/// </summary>
public static class VaultPathResolver
{
    public static string ResolveDefaultVaultDirectory(string? explicitBaseDirectory = null)
    {
        if (!string.IsNullOrWhiteSpace(explicitBaseDirectory))
        {
            Directory.CreateDirectory(explicitBaseDirectory);
            return Path.GetFullPath(explicitBaseDirectory);
        }

        var appBase = AppContext.BaseDirectory;
        var portableMarker = Path.Combine(appBase, ".portable");
        if (File.Exists(portableMarker))
        {
            var portableVault = Path.Combine(appBase, "Data", "Vault");
            Directory.CreateDirectory(portableVault);
            return portableVault;
        }

        var commonAppData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        if (string.IsNullOrWhiteSpace(commonAppData))
        {
            commonAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        }

        var vaultDir = Path.Combine(commonAppData, "UltimateWindows", "Vault");
        Directory.CreateDirectory(vaultDir);
        return vaultDir;
    }

    public static long GetVolumeFreeBytes(string directoryPath)
    {
        try
        {
            var fullPath = Path.GetFullPath(directoryPath);
            var root = Path.GetPathRoot(fullPath);
            if (!string.IsNullOrWhiteSpace(root))
            {
                var drive = new DriveInfo(root);
                if (drive.IsReady)
                {
                    return drive.AvailableFreeSpace;
                }
            }
        }
        catch
        {
            // Fallback если том виртуальный или недоступен для чтения метрик DriveInfo
        }

        return 100L * 1024L * 1024L * 1024L; // Консервативный fallback 100 ГБ
    }
}
