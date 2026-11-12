using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32;
using UltimateWindows.Modules.Cleaner.Models;
using UltimateWindows.Modules.Cleaner.Services;
using UltimateWindows.Modules.Cleaner.Utilities;
using UltimateWindows.NativeInterop.Security;

namespace UltimateWindows.NativeInterop.Cleaner;

/// <summary>
/// Полноценный Windows-мост очистки: Restart Manager API (rstrtmgr.dll), Корзина Shell32 (SHFileOperationW / SHEmptyRecycleBinW)
/// и многокатегорийный поиск мертвых ссылок реестра (в стиле CCleaner Registry Cleaner, но со 100% защитой системных ветвей COM/CLSID).
/// </summary>
public sealed class WindowsCleanerPlatformBridge : DefaultCleanerPlatformBridge
{
    public override bool RegistryKeyExists(string keyPath)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(keyPath))
        {
            return false;
        }

        if (!TrySplitHiveAndSubKey(keyPath, out var root, out var sub))
        {
            return false;
        }

        try
        {
            using var k = root.OpenSubKey(sub, writable: false);
            return k is not null;
        }
        catch
        {
            return false;
        }
    }

    public override string? ReadRegistryString(string keyPath, string valueName)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(keyPath))
        {
            return null;
        }

        if (!TrySplitHiveAndSubKey(keyPath, out var root, out var sub))
        {
            return null;
        }

        try
        {
            using var k = root.OpenSubKey(sub, writable: false);
            return k?.GetValue(valueName) as string;
        }
        catch
        {
            return null;
        }
    }

    public override Task<DiskSpaceAnalysisReport?> TryAnalyzeNtfsVolumeViaMftAsync(
        string rootPath,
        int topDirectoryLimit = 12,
        int largestFilesLimit = 15,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult<DiskSpaceAnalysisReport?>(null);
        }

        return Task.Run(
            () => WindowsNtfsMftScanner.TryScanNtfsVolume(rootPath, topDirectoryLimit, largestFilesLimit, ct),
            ct);
    }

    private static bool TrySplitHiveAndSubKey(string full, out RegistryKey hive, out string subKey)
    {
        hive = Registry.CurrentUser;
        subKey = "";
        var clean = full.Trim().Replace('/', '\\').TrimEnd('\\');
        var slash = clean.IndexOf('\\');
        if (slash <= 0 || slash >= clean.Length - 1)
        {
            return false;
        }

        var head = clean[..slash].ToUpperInvariant();
        subKey = clean[(slash + 1)..];
        switch (head)
        {
            case "HKCU":
            case "HKEY_CURRENT_USER":
                hive = Registry.CurrentUser;
                return true;
            case "HKLM":
            case "HKEY_LOCAL_MACHINE":
                hive = Registry.LocalMachine;
                return true;
            default:
                return false;
        }
    }

    public override bool IsFileLockedByAnotherProcess(string filePath)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            return false;
        }

        var sessionKey = Guid.NewGuid().ToString("N");
        if (RmStartSession(out var sessionHandle, 0, sessionKey) == 0)
        {
            try
            {
                string[] resources = [Path.GetFullPath(filePath)];
                if (RmRegisterResources(sessionHandle, (uint)resources.Length, resources, 0, IntPtr.Zero, 0, null) == 0)
                {
                    uint needed = 0;
                    uint count = 0;
                    uint rebootReasons = 0;
                    var res = RmGetList(sessionHandle, out needed, ref count, IntPtr.Zero, ref rebootReasons);
                    if (res == ERROR_MORE_DATA && needed > 0)
                    {
                        return true;
                    }
                }
            }
            finally
            {
                _ = RmEndSession(sessionHandle);
            }
        }

        return base.IsFileLockedByAnotherProcess(filePath);
    }

    public override Task<(long RecycleBinBytes, int RecycleBinItems)> QueryRecycleBinSizeAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult((0L, 0));
        }

        var info = new SHQUERYRBINFO { cbSize = Marshal.SizeOf<SHQUERYRBINFO>() };
        var hr = SHQueryRecycleBinW(null, ref info);
        if (hr == 0 && info.i64Size >= 0)
        {
            return Task.FromResult((info.i64Size, (int)Math.Clamp(info.i64NumItems, 0, int.MaxValue)));
        }

        return Task.FromResult((0L, 0));
    }

    public override Task<bool> EmptyRecycleBinAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult(false);
        }

        const uint flags = SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND;
        var hr = SHEmptyRecycleBinW(IntPtr.Zero, null, flags);
        return Task.FromResult(hr == 0);
    }

    public override Task<bool> SendPathToRecycleBinAsync(string fullPath, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return base.SendPathToRecycleBinAsync(fullPath, ct);
        }

        return Task.Run(() =>
        {
            try
            {
                var trimmed = Path.GetFullPath(fullPath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                if (!File.Exists(trimmed) && !Directory.Exists(trimmed))
                {
                    return false;
                }

                // Двойной нуль-терминатор обязателен для pFrom в SHFileOperationW!
                var op = new SHFILEOPSTRUCTW
                {
                    wFunc = FO_DELETE,
                    pFrom = trimmed + "\0\0",
                    fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT
                };

                var rc = SHFileOperationW(ref op);
                return rc == 0 && !op.fAnyOperationsAborted;
            }
            catch
            {
                return false;
            }
        }, ct);
    }

    public override Task<IReadOnlyList<RegistryOrphanCandidate>> ScanVerifiedRegistryOrphansAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult<IReadOnlyList<RegistryOrphanCandidate>>(Array.Empty<RegistryOrphanCandidate>());
        }

        return Task.Run<IReadOnlyList<RegistryOrphanCandidate>>(() =>
        {
            var fixedDriveRoots = GetReadyFixedDriveRoots();
            var isAdmin = ElevationChecker.IsRunningAsAdministrator();
            var orphans = new List<RegistryOrphanCandidate>();

            // 1. Автозагрузка текущего пользователя (HKCU Run & RunOnce)
            ScanCommandLineSubKey(
                Registry.CurrentUser, "HKCU",
                @"Software\Microsoft\Windows\CurrentVersion\Run",
                RegistryOrphanKind.OrphanedStartupRun,
                "Автозагрузка указывает на удаленный файл",
                fixedDriveRoots, orphans, ct);

            ScanCommandLineSubKey(
                Registry.CurrentUser, "HKCU",
                @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                RegistryOrphanKind.OrphanedStartupRun,
                "Одноразовый автозапуск указывает на удаленный файл",
                fixedDriveRoots, orphans, ct);

            // 2. Правила совместимости (AppCompatFlags\Layers и Compatibility Assistant\Store)
            ScanValueNameAsPathSubKey(
                Registry.CurrentUser, "HKCU",
                @"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
                RegistryOrphanKind.StaleAppCompatFlag,
                "Флаг совместимости для удаленного .exe",
                fixedDriveRoots, extractFromMuiSuffix: false, orphans, ct);

            ScanValueNameAsPathSubKey(
                Registry.CurrentUser, "HKCU",
                @"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
                RegistryOrphanKind.StaleAppCompatFlag,
                "Кэш помощника совместимости для удаленного .exe",
                fixedDriveRoots, extractFromMuiSuffix: false, orphans, ct);

            // 3. Кэш имен MUI (MuiCache)
            ScanValueNameAsPathSubKey(
                Registry.CurrentUser, "HKCU",
                @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
                RegistryOrphanKind.StaleMuiCache,
                "Кэш заголовка удаленной программы (MUI)",
                fixedDriveRoots, extractFromMuiSuffix: true, orphans, ct);

            // 4. Пути приложений пользователя (HKCU App Paths)
            ScanAppPathsSubKey(Registry.CurrentUser, "HKCU", fixedDriveRoots, orphans, ct);

            // 5. История вводимых локальных путей Проводника (TypedPaths)
            ScanCommandLineSubKey(
                Registry.CurrentUser, "HKCU",
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
                RegistryOrphanKind.StaleExplorerHistory,
                "Удаленный путь в адресной строке Проводника",
                fixedDriveRoots, orphans, ct);

            // 6. Звуковые события удаленных приложений (HKCU AppEvents\Schemes\Apps\...\.Current)
            ScanBrokenSoundEvents(fixedDriveRoots, orphans, ct);

            // 7. Пользовательские деинсталляторы с мертвым путем (HKCU Uninstall)
            ScanDeadUninstallValues(Registry.CurrentUser, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\Uninstall", fixedDriveRoots, orphans, ct);

            // 7б. Сироты списка одобренной автозагрузки (HKCU StartupApproved\Run): запись в StartupApproved осталась, а самого значения в Run уже нет
            ScanBrokenStartupApproved(
                Registry.CurrentUser, "HKCU",
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
                @"Software\Microsoft\Windows\CurrentVersion\Run",
                orphans, ct);

            // 7в. Отсутствующие пользовательские шрифты (HKCU Fonts)
            ScanMissingFontsSubKey(
                Registry.CurrentUser, "HKCU",
                @"Software\Microsoft\Windows NT\CurrentVersion\Fonts",
                fixedDriveRoots, orphans, ct);

            // Категории HKLM (сканируем при наличии прав Администратора, чтобы каждая найденная запись гарантированно исправлялась)
            if (isAdmin)
            {
                // 8. Отсутствующие общие DLL (HKLM SharedDlls — классическая категория #1 в CCleaner)
                ScanValueNameAsPathSubKey(
                    Registry.LocalMachine, "HKLM",
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDlls",
                    RegistryOrphanKind.MissingSharedDll,
                    "Отсутствует общая библиотека DLL",
                    fixedDriveRoots, extractFromMuiSuffix: false, orphans, ct);

                // 9. Системные пути приложений (HKLM App Paths)
                ScanAppPathsSubKey(Registry.LocalMachine, "HKLM", fixedDriveRoots, orphans, ct);

                // 10. Системная автозагрузка (HKLM Run)
                ScanCommandLineSubKey(
                    Registry.LocalMachine, "HKLM",
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    RegistryOrphanKind.OrphanedStartupRun,
                    "Системная автозагрузка указывает на удаленный .exe",
                    fixedDriveRoots, orphans, ct);

                // 11. Файлы справки Windows (HKLM Help)
                ScanHelpFilesSubKey(fixedDriveRoots, orphans, ct);

                // 12. Правила брандмауэра для удаленных программ
                ScanFirewallRulesSubKey(fixedDriveRoots, orphans, ct);

                // 13. Отсутствующие системные шрифты (HKLM Fonts)
                ScanMissingFontsSubKey(
                    Registry.LocalMachine, "HKLM",
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts",
                    fixedDriveRoots, orphans, ct);

                // 14. Несуществующие папки установщика Windows Installer (HKLM Installer\Folders)
                ScanMissingInstallerFoldersSubKey(fixedDriveRoots, orphans, ct);

                // 15. Сироты системного StartupApproved\Run
                ScanBrokenStartupApproved(
                    Registry.LocalMachine, "HKLM",
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    orphans, ct);
            }

            return orphans;
        }, ct);
    }

    public override Task<int> DeleteVerifiedRegistryOrphansAsync(
        IReadOnlyList<RegistryOrphanCandidate> candidates,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows() || candidates.Count == 0)
        {
            return Task.FromResult(0);
        }

        return Task.Run(() =>
        {
            var deleted = 0;
            foreach (var item in candidates)
            {
                ct.ThrowIfCancellationRequested();

                if (CommandLinePathExtractor.IsForbiddenComOrSystemRegistryKey($@"{item.HiveName}\{item.SubKeyPath}"))
                {
                    continue;
                }

                try
                {
                    var rootHive = string.Equals(item.HiveName, "HKLM", StringComparison.OrdinalIgnoreCase)
                        ? Registry.LocalMachine
                        : Registry.CurrentUser;

                    if (item.Kind == RegistryOrphanKind.BrokenStartupApprovedEntry)
                    {
                        const string correspondingRunSubKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
                        using var runKey = rootHive.OpenSubKey(correspondingRunSubKey, writable: false);
                        if (runKey?.GetValue(item.ValueName) is not null)
                        {
                            continue;
                        }
                    }
                    else if (File.Exists(item.MissingReferencedFilePath) || Directory.Exists(item.MissingReferencedFilePath))
                    {
                        continue;
                    }

                    using var key = rootHive.OpenSubKey(item.SubKeyPath, writable: true);
                    if (key?.GetValue(item.ValueName) is not null)
                    {
                        key.DeleteValue(item.ValueName, throwOnMissingValue: false);
                        deleted++;
                    }
                }
                catch
                {
                    // Пропускаем защищенные системой ключи
                }
            }

            return deleted;
        }, ct);
    }

    private static void ScanCommandLineSubKey(
        RegistryKey hiveRoot,
        string hiveShortName,
        string subKeyPath,
        RegistryOrphanKind kind,
        string friendlyReason,
        HashSet<string> fixedDrives,
        List<RegistryOrphanCandidate> sink,
        CancellationToken ct)
    {
        try
        {
            using var key = hiveRoot.OpenSubKey(subKeyPath, writable: false);
            if (key is null) return;

            foreach (var valueName in key.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                if (string.IsNullOrEmpty(valueName)) continue;

                var valKind = key.GetValueKind(valueName);
                var rawObj = key.GetValue(valueName);
                if (rawObj is not string strVal) continue;

                var exePath = CommandLinePathExtractor.TryExtractLocalExecutablePath(strVal);
                if (exePath is null || !IsOnReadyFixedDrive(exePath, fixedDrives) || File.Exists(exePath) || Directory.Exists(exePath))
                {
                    continue;
                }

                sink.Add(new RegistryOrphanCandidate(
                    Kind: kind,
                    HiveName: hiveShortName,
                    SubKeyPath: subKeyPath,
                    ValueName: valueName,
                    MissingReferencedFilePath: exePath,
                    PreviousValueSerialized: SerializeRegistryValue(rawObj, valKind),
                    RegistryValueKindCode: (int)valKind,
                    FriendlyReason: friendlyReason));
            }
        }
        catch
        {
            // Безопасный пропуск
        }
    }

    private static void ScanValueNameAsPathSubKey(
        RegistryKey hiveRoot,
        string hiveShortName,
        string subKeyPath,
        RegistryOrphanKind kind,
        string friendlyReason,
        HashSet<string> fixedDrives,
        bool extractFromMuiSuffix,
        List<RegistryOrphanCandidate> sink,
        CancellationToken ct)
    {
        try
        {
            using var key = hiveRoot.OpenSubKey(subKeyPath, writable: false);
            if (key is null) return;

            foreach (var valueName in key.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                if (string.IsNullOrWhiteSpace(valueName)) continue;

                string? candidatePath;
                if (extractFromMuiSuffix)
                {
                    candidatePath = CommandLinePathExtractor.TryExtractFromMuiCacheValueName(valueName);
                }
                else if (kind == RegistryOrphanKind.MissingSharedDll)
                {
                    var expanded = Environment.ExpandEnvironmentVariables(valueName.Trim().Trim('"'));
                    candidatePath = expanded.Length >= 4 && char.IsLetter(expanded[0]) && expanded[1] == ':' ? expanded : null;
                }
                else
                {
                    candidatePath = CommandLinePathExtractor.TryExtractLocalExecutablePath(valueName);
                }

                if (candidatePath is null || !IsOnReadyFixedDrive(candidatePath, fixedDrives) || File.Exists(candidatePath))
                {
                    continue;
                }

                var valKind = key.GetValueKind(valueName);
                var rawObj = key.GetValue(valueName);
                if (rawObj is null) continue;

                sink.Add(new RegistryOrphanCandidate(
                    Kind: kind,
                    HiveName: hiveShortName,
                    SubKeyPath: subKeyPath,
                    ValueName: valueName,
                    MissingReferencedFilePath: candidatePath,
                    PreviousValueSerialized: SerializeRegistryValue(rawObj, valKind),
                    RegistryValueKindCode: (int)valKind,
                    FriendlyReason: friendlyReason));
            }
        }
        catch
        {
            // Безопасный пропуск
        }
    }

    private static void ScanAppPathsSubKey(
        RegistryKey hiveRoot,
        string hiveShortName,
        HashSet<string> fixedDrives,
        List<RegistryOrphanCandidate> sink,
        CancellationToken ct)
    {
        const string appPathsBase = @"Software\Microsoft\Windows\CurrentVersion\App Paths";
        try
        {
            using var baseKey = hiveRoot.OpenSubKey(appPathsBase, writable: false);
            if (baseKey is null) return;

            foreach (var sub in baseKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                var fullSub = $@"{appPathsBase}\{sub}";
                using var appKey = hiveRoot.OpenSubKey(fullSub, writable: false);
                var defVal = appKey?.GetValue("") as string;
                if (string.IsNullOrWhiteSpace(defVal)) continue;

                var exePath = CommandLinePathExtractor.TryExtractLocalExecutablePath(defVal);
                if (exePath is null || !IsOnReadyFixedDrive(exePath, fixedDrives) || File.Exists(exePath))
                {
                    continue;
                }

                sink.Add(new RegistryOrphanCandidate(
                    Kind: RegistryOrphanKind.BrokenAppPath,
                    HiveName: hiveShortName,
                    SubKeyPath: fullSub,
                    ValueName: "",
                    MissingReferencedFilePath: exePath,
                    PreviousValueSerialized: defVal,
                    RegistryValueKindCode: (int)RegistryValueKind.String,
                    FriendlyReason: $"Путь приложения «{sub}» указывает на удаленный файл"));
            }
        }
        catch
        {
            // Пропуск
        }
    }

    private static void ScanHelpFilesSubKey(
        HashSet<string> fixedDrives,
        List<RegistryOrphanCandidate> sink,
        CancellationToken ct)
    {
        const string helpBase = @"SOFTWARE\Microsoft\Windows\Help";
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(helpBase, writable: false);
            if (key is null) return;

            foreach (var vName in key.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                if (string.IsNullOrWhiteSpace(vName)) continue;
                if (key.GetValue(vName) is not string dirPath || string.IsNullOrWhiteSpace(dirPath)) continue;

                var combined = Path.Combine(Environment.ExpandEnvironmentVariables(dirPath.Trim().Trim('"')), vName);
                if (!IsOnReadyFixedDrive(combined, fixedDrives) || File.Exists(combined))
                {
                    continue;
                }

                sink.Add(new RegistryOrphanCandidate(
                    Kind: RegistryOrphanKind.MissingHelpFile,
                    HiveName: "HKLM",
                    SubKeyPath: helpBase,
                    ValueName: vName,
                    MissingReferencedFilePath: combined,
                    PreviousValueSerialized: dirPath,
                    RegistryValueKindCode: (int)RegistryValueKind.String,
                    FriendlyReason: "Файл справки удаленной программы отсутствует"));
            }
        }
        catch
        {
            // Пропуск
        }
    }

    private static void ScanBrokenSoundEvents(
        HashSet<string> fixedDrives,
        List<RegistryOrphanCandidate> sink,
        CancellationToken ct)
    {
        const string appsBase = @"AppEvents\Schemes\Apps";
        try
        {
            using var appsKey = Registry.CurrentUser.OpenSubKey(appsBase, writable: false);
            if (appsKey is null) return;

            foreach (var appName in appsKey.GetSubKeyNames())
            {
                if (appName.StartsWith('.')) continue; // Системная схема .Default
                using var appSub = appsKey.OpenSubKey(appName, writable: false);
                if (appSub is null) continue;

                foreach (var evName in appSub.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    var curSub = $@"{appsBase}\{appName}\{evName}\.Current";
                    using var curKey = Registry.CurrentUser.OpenSubKey(curSub, writable: false);
                    var wavPath = curKey?.GetValue("") as string;
                    if (string.IsNullOrWhiteSpace(wavPath)) continue;

                    var expanded = Environment.ExpandEnvironmentVariables(wavPath.Trim().Trim('"'));
                    if (expanded.Length < 4 || expanded[1] != ':' || !IsOnReadyFixedDrive(expanded, fixedDrives) || File.Exists(expanded))
                    {
                        continue;
                    }

                    sink.Add(new RegistryOrphanCandidate(
                        Kind: RegistryOrphanKind.BrokenSoundEvent,
                        HiveName: "HKCU",
                        SubKeyPath: curSub,
                        ValueName: "",
                        MissingReferencedFilePath: expanded,
                        PreviousValueSerialized: wavPath,
                        RegistryValueKindCode: (int)RegistryValueKind.String,
                        FriendlyReason: $"Звуковой файл события ({appName}) удален"));
                }
            }
        }
        catch
        {
            // Пропуск
        }
    }

    private static void ScanDeadUninstallValues(
        RegistryKey root,
        string hiveName,
        string uninstallBase,
        HashSet<string> fixedDrives,
        List<RegistryOrphanCandidate> sink,
        CancellationToken ct)
    {
        try
        {
            using var baseKey = root.OpenSubKey(uninstallBase, writable: false);
            if (baseKey is null) return;

            foreach (var sub in baseKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                var fullSub = $@"{uninstallBase}\{sub}";
                using var k = root.OpenSubKey(fullSub, writable: false);
                var iconRaw = k?.GetValue("DisplayIcon") as string;
                if (string.IsNullOrWhiteSpace(iconRaw)) continue;

                var iconClean = iconRaw.Split(',')[0].Trim().Trim('"');
                var exePath = CommandLinePathExtractor.TryExtractLocalExecutablePath(iconClean);
                if (exePath is null || !IsOnReadyFixedDrive(exePath, fixedDrives) || File.Exists(exePath))
                {
                    continue;
                }

                // Только если сам UninstallString тоже отсутствует на диске
                var uninstRaw = k?.GetValue("UninstallString") as string;
                var uninstExe = !string.IsNullOrWhiteSpace(uninstRaw)
                    ? CommandLinePathExtractor.TryExtractLocalExecutablePath(uninstRaw)
                    : null;
                if (uninstExe is not null && File.Exists(uninstExe))
                {
                    continue;
                }

                sink.Add(new RegistryOrphanCandidate(
                    Kind: RegistryOrphanKind.DeadUninstallEntry,
                    HiveName: hiveName,
                    SubKeyPath: fullSub,
                    ValueName: "DisplayIcon",
                    MissingReferencedFilePath: exePath,
                    PreviousValueSerialized: iconRaw,
                    RegistryValueKindCode: (int)RegistryValueKind.String,
                    FriendlyReason: $"Ссылка на значок давно удаленной программы ({sub})"));
            }
        }
        catch
        {
            // Пропуск
        }
    }

    private static void ScanFirewallRulesSubKey(
        HashSet<string> fixedDrives,
        List<RegistryOrphanCandidate> sink,
        CancellationToken ct)
    {
        const string fwSubKey = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(fwSubKey, writable: false);
            if (key is null) return;

            foreach (var valueName in key.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                if (key.GetValue(valueName) is not string ruleStr) continue;

                var exePath = CommandLinePathExtractor.TryExtractFromFirewallRule(ruleStr);
                if (exePath is null || !IsOnReadyFixedDrive(exePath, fixedDrives) || File.Exists(exePath))
                {
                    continue;
                }

                sink.Add(new RegistryOrphanCandidate(
                    Kind: RegistryOrphanKind.BrokenFirewallRule,
                    HiveName: "HKLM",
                    SubKeyPath: fwSubKey,
                    ValueName: valueName,
                    MissingReferencedFilePath: exePath,
                    PreviousValueSerialized: ruleStr,
                    RegistryValueKindCode: (int)RegistryValueKind.String,
                    FriendlyReason: "Правило брандмауэра для удаленного приложения"));
            }
        }
        catch
        {
            // Пропуск
        }
    }

    private static void ScanMissingFontsSubKey(
        RegistryKey hiveRoot,
        string hiveShortName,
        string subKeyPath,
        HashSet<string> fixedDrives,
        List<RegistryOrphanCandidate> sink,
        CancellationToken ct)
    {
        try
        {
            using var key = hiveRoot.OpenSubKey(subKeyPath, writable: false);
            if (key is null) return;

            var winFonts = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Fonts");

            foreach (var valueName in key.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                if (string.IsNullOrEmpty(valueName)) continue;

                var valKind = key.GetValueKind(valueName);
                if (key.GetValue(valueName) is not string rawPath || string.IsNullOrWhiteSpace(rawPath))
                {
                    continue;
                }

                var trimmed = Environment.ExpandEnvironmentVariables(rawPath.Trim().Trim('"'));
                var resolved = Path.IsPathRooted(trimmed) ? trimmed : Path.Combine(winFonts, trimmed);
                if (!IsOnReadyFixedDrive(resolved, fixedDrives) || File.Exists(resolved))
                {
                    continue;
                }

                sink.Add(new RegistryOrphanCandidate(
                    Kind: RegistryOrphanKind.MissingFontReference,
                    HiveName: hiveShortName,
                    SubKeyPath: subKeyPath,
                    ValueName: valueName,
                    MissingReferencedFilePath: resolved,
                    PreviousValueSerialized: SerializeRegistryValue(rawPath, valKind),
                    RegistryValueKindCode: (int)valKind,
                    FriendlyReason: $"Шрифт «{valueName}» указывает на удалённый файл"));
            }
        }
        catch
        {
            // Пропуск
        }
    }

    private static void ScanMissingInstallerFoldersSubKey(
        HashSet<string> fixedDrives,
        List<RegistryOrphanCandidate> sink,
        CancellationToken ct)
    {
        const string subKeyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders";
        var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(subKeyPath, writable: false);
            if (key is null) return;

            foreach (var folderPath in key.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                if (string.IsNullOrWhiteSpace(folderPath)) continue;

                // Системный каталог Windows и его вложенные папки в Installer\Folders не трогаем
                if (!string.IsNullOrWhiteSpace(winDir) &&
                    folderPath.StartsWith(winDir, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (!IsOnReadyFixedDrive(folderPath, fixedDrives) || Directory.Exists(folderPath) || File.Exists(folderPath))
                {
                    continue;
                }

                var valKind = key.GetValueKind(folderPath);
                var rawObj = key.GetValue(folderPath) ?? "";

                sink.Add(new RegistryOrphanCandidate(
                    Kind: RegistryOrphanKind.MissingWindowsInstallerFolder,
                    HiveName: "HKLM",
                    SubKeyPath: subKeyPath,
                    ValueName: folderPath,
                    MissingReferencedFilePath: folderPath,
                    PreviousValueSerialized: SerializeRegistryValue(rawObj, valKind),
                    RegistryValueKindCode: (int)valKind,
                    FriendlyReason: "Папка удалённого MSI-пакета больше не существует на диске"));
            }
        }
        catch
        {
            // Пропуск
        }
    }

    private static void ScanBrokenStartupApproved(
        RegistryKey hiveRoot,
        string hiveShortName,
        string startupApprovedSubKey,
        string correspondingRunSubKey,
        List<RegistryOrphanCandidate> sink,
        CancellationToken ct)
    {
        try
        {
            using var approvedKey = hiveRoot.OpenSubKey(startupApprovedSubKey, writable: false);
            if (approvedKey is null) return;

            using var runKey = hiveRoot.OpenSubKey(correspondingRunSubKey, writable: false);
            var liveRunNames = runKey is not null
                ? new HashSet<string>(runKey.GetValueNames(), StringComparer.OrdinalIgnoreCase)
                : new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var valueName in approvedKey.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                if (string.IsNullOrEmpty(valueName) || liveRunNames.Contains(valueName))
                {
                    continue;
                }

                var valKind = approvedKey.GetValueKind(valueName);
                var rawObj = approvedKey.GetValue(valueName);
                if (rawObj is null) continue;

                sink.Add(new RegistryOrphanCandidate(
                    Kind: RegistryOrphanKind.BrokenStartupApprovedEntry,
                    HiveName: hiveShortName,
                    SubKeyPath: startupApprovedSubKey,
                    ValueName: valueName,
                    MissingReferencedFilePath: $@"{hiveShortName}\{correspondingRunSubKey}\{valueName}",
                    PreviousValueSerialized: SerializeRegistryValue(rawObj, valKind),
                    RegistryValueKindCode: (int)valKind,
                    FriendlyReason: $"Флаг автозагрузки «{valueName}» остался после удаления самой записи Run"));
            }
        }
        catch
        {
            // Пропуск
        }
    }

    private static string SerializeRegistryValue(object rawObj, RegistryValueKind kind) => kind switch
    {
        RegistryValueKind.DWord => Convert.ToInt32(rawObj, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture),
        RegistryValueKind.QWord => Convert.ToInt64(rawObj, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture),
        RegistryValueKind.Binary when rawObj is byte[] bytes => Convert.ToBase64String(bytes),
        RegistryValueKind.MultiString when rawObj is string[] arr => JsonSerializer.Serialize(arr),
        _ => rawObj.ToString() ?? ""
    };

    private static HashSet<string> GetReadyFixedDriveRoots()
    {
        var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var d in DriveInfo.GetDrives())
            {
                if (d.IsReady && d.DriveType == DriveType.Fixed)
                {
                    roots.Add(d.Name);
                }
            }
        }
        catch
        {
            roots.Add(@"C:\");
        }

        return roots;
    }

    private static bool IsOnReadyFixedDrive(string filePath, HashSet<string> fixedDrives)
    {
        var root = Path.GetPathRoot(filePath);
        return !string.IsNullOrWhiteSpace(root) && fixedDrives.Contains(root);
    }

    // ==================== WIN32 P/INVOKE ====================
    private const int ERROR_MORE_DATA = 234;
    private const uint SHERB_NOCONFIRMATION = 0x00000001;
    private const uint SHERB_NOPROGRESSUI = 0x00000002;
    private const uint SHERB_NOSOUND = 0x00000004;

    private const uint FO_DELETE = 0x0003;
    private const ushort FOF_SILENT = 0x0004;
    private const ushort FOF_NOCONFIRMATION = 0x0010;
    private const ushort FOF_ALLOWUNDO = 0x0040;
    private const ushort FOF_NOERRORUI = 0x0400;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SHFILEOPSTRUCTW
    {
        public IntPtr hwnd;
        public uint wFunc;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pFrom;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? pTo;
        public ushort fFlags;
        [MarshalAs(UnmanagedType.Bool)]
        public bool fAnyOperationsAborted;
        public IntPtr hNameMappings;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? lpszProgressTitle;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int SHFileOperationW(ref SHFILEOPSTRUCTW lpFileOp);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, string strSessionKey);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int RmRegisterResources(
        uint dwSessionHandle,
        uint nFiles,
        string[]? rgsFilenames,
        uint nApplications,
        IntPtr rgApplications,
        uint nServices,
        string[]? rgsServiceNames);

    [DllImport("rstrtmgr.dll", ExactSpelling = true)]
    private static extern int RmGetList(
        uint dwSessionHandle,
        out uint pnProcInfoNeeded,
        ref uint pnProcInfo,
        IntPtr rgAffectedApps,
        ref uint lpdwRebootReasons);

    [DllImport("rstrtmgr.dll", ExactSpelling = true)]
    private static extern int RmEndSession(uint dwSessionHandle);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int SHQueryRecycleBinW(string? pszRootPath, ref SHQUERYRBINFO pSHQueryRBInfo);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int SHEmptyRecycleBinW(IntPtr hwnd, string? pszRootPath, uint dwFlags);

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct SHQUERYRBINFO
    {
        public int cbSize;
        public long i64Size;
        public long i64NumItems;
    }
}
