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
/// Полноценный Windows-мост очистки: Restart Manager API (rstrtmgr.dll), Корзина Shell32
/// и верифицированный поиск мертвых ссылок реестра только на стационарных дисках (DriveType.Fixed).
/// </summary>
public sealed class WindowsCleanerPlatformBridge : DefaultCleanerPlatformBridge
{
    public override bool IsFileLockedByAnotherProcess(string filePath)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            return false;
        }

        // 1. Быстрая проверка через Restart Manager API (не открывает сам файл на запись!)
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
        // S_OK (0) или E_UNEXPECTED (-2147418113 когда корзина уже пуста)
        return Task.FromResult(hr == 0);
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
            var orphans = new List<RegistryOrphanCandidate>();

            // 1. HKCU\Software\Microsoft\Windows\CurrentVersion\Run
            ScanCommandLineSubKey(
                Registry.CurrentUser,
                "HKCU",
                @"Software\Microsoft\Windows\CurrentVersion\Run",
                RegistryOrphanKind.OrphanedStartupRun,
                "Запись автозагрузки указывает на удаленную программу",
                fixedDriveRoots,
                orphans,
                ct);

            // 2. HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers (имя значения = полный путь к .exe)
            ScanValueNameAsPathSubKey(
                Registry.CurrentUser,
                "HKCU",
                @"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
                RegistryOrphanKind.StaleAppCompatFlag,
                "Настройка совместимости для удаленного .exe файла",
                fixedDriveRoots,
                extractFromMuiSuffix: false,
                orphans,
                ct);

            // 3. HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache
            ScanValueNameAsPathSubKey(
                Registry.CurrentUser,
                "HKCU",
                @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
                RegistryOrphanKind.StaleMuiCache,
                "Устаревшая запись кэша имени давно удаленной программы",
                fixedDriveRoots,
                extractFromMuiSuffix: true,
                orphans,
                ct);

            // 4. Правила брандмауэра для удаленных программ (только если запущено с правами Администратора, чтобы можно было и очистить)
            if (ElevationChecker.IsRunningAsAdministrator())
            {
                ScanFirewallRulesSubKey(fixedDriveRoots, orphans, ct);
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

                // Повторно убеждаемся непосредственно перед удалением, что файл действительно отсутствует
                if (File.Exists(item.MissingReferencedFilePath))
                {
                    continue;
                }

                try
                {
                    var rootHive = string.Equals(item.HiveName, "HKLM", StringComparison.OrdinalIgnoreCase)
                        ? Registry.LocalMachine
                        : Registry.CurrentUser;

                    using var key = rootHive.OpenSubKey(item.SubKeyPath, writable: true);
                    if (key?.GetValue(item.ValueName) is not null)
                    {
                        key.DeleteValue(item.ValueName, throwOnMissingValue: false);
                        deleted++;
                    }
                }
                catch
                {
                    // Пропускаем защищенные системой ключи без аварийного завершения
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
                if (exePath is null || !IsOnReadyFixedDrive(exePath, fixedDrives) || File.Exists(exePath))
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
            // Безопасный пропуск при отсутствии прав
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

                var exePath = extractFromMuiSuffix
                    ? CommandLinePathExtractor.TryExtractFromMuiCacheValueName(valueName)
                    : CommandLinePathExtractor.TryExtractLocalExecutablePath(valueName);

                if (exePath is null || !IsOnReadyFixedDrive(exePath, fixedDrives) || File.Exists(exePath))
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
            // Безопасный пропуск
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
