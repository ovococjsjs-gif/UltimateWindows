using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using UltimateWindows.Core.Contracts;
using UltimateWindows.Core.Enums;
using UltimateWindows.Core.Models;
using UltimateWindows.Modules.Apps.Models;
using UltimateWindows.Modules.Apps.Uninstaller;

namespace UltimateWindows.NativeInterop.Apps;

public sealed partial class WindowsAppsPlatformBridge
{
    private const long SingleFileLimit = 24L * 1024 * 1024;
    private sealed record FileBackup(string Path, string Hash, long Length);
    private sealed record KeyBackup(string Path, string Export, bool IsUninstallEntry);

    public async Task<CleanUninstallResult> QuarantineAndRemoveLeftoversAsync(string appDisplayName,
        InstalledApplicationInfo? forceRemoveUninstallEntry, IReadOnlyList<AppLeftoverItem> leftovers,
        IVaultService vaultService, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return new(false, null, appDisplayName, false, 0, 0, 0, "Поддерживается только в Windows.");

        // Сначала подготовить весь снимок, не изменяя ни одного исходного объекта.
        await using var tx = vaultService.BeginTransaction(SystemDomain.AppsAndAutomation,
            $"Снимок перед очисткой: {appDisplayName}", "Файлы и ветки реестра до очистки. Копия закреплена.");
        var files = new List<FileBackup>();
        var keys = new List<KeyBackup>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var remaining = vaultService.CurrentPolicy.MaxVaultBytes / 3;
        var skipped = 0;
        var reasons = new List<string>();
        void Skip(string path, string reason)
        {
            skipped++;
            if (reasons.Count < 4) reasons.Add($"{path}: {reason}");
        }

        async Task PreparePathAsync(string path)
        {
            ct.ThrowIfCancellationRequested();
            path = Path.GetFullPath(path);
            if (!seen.Add(path)) return;
            try
            {
                if (!LeftoverSafetyGuard.IsSafeFilesystemLeftoverCandidate(path) || HasReparseAncestor(path))
                {
                    Skip(path, "защищённый путь или ссылка");
                    return;
                }
                if (Directory.Exists(path))
                {
                    // Никогда не удаляем деревья целиком: неизвестные/занятые файлы и пустые папки остаются.
                    foreach (var child in Directory.EnumerateFileSystemEntries(path))
                        await PreparePathAsync(child).ConfigureAwait(false);
                    return;
                }
                var length = new FileInfo(path).Length;
                if (length > SingleFileLimit || length > remaining) { Skip(path, "лимит резервной копии"); return; }
                var hash = await tx.BackupFileAsync(path, ct).ConfigureAwait(false);
                files.Add(new(path, hash, length));
                remaining -= length;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
            {
                Skip(path, ex.Message);
            }
        }

        async Task PrepareKeyAsync(string path, bool isUninstallEntry)
        {
            if (!seen.Add(path)) return;
            if (!LeftoverSafetyGuard.IsSafeRegistryLeftoverCandidate(path)) { Skip(path, "защищённая ветка"); return; }
            var exported = await ExportRegistryTreeAsync(path, ct).ConfigureAwait(false);
            if (exported is null) { Skip(path, "нет полного экспорта реестра (лимит 512 КиБ)"); return; }
            keys.Add(new(path, exported, isUninstallEntry));
            tx.RecordStateDelta(StateTargetKind.SystemSetting, $"AppRegistryExport:{path}",
                JsonSerializer.Serialize(new { RegFileContent = exported }), null);
        }

        foreach (var item in leftovers)
        {
            ct.ThrowIfCancellationRequested();
            if (item.Kind == AppLeftoverKind.RegistrySubKey) await PrepareKeyAsync(item.TargetPath, false).ConfigureAwait(false);
            else await PreparePathAsync(item.TargetPath).ConfigureAwait(false);
        }
        if (forceRemoveUninstallEntry is not null && skipped == 0)
            await PrepareKeyAsync(forceRemoveUninstallEntry.RegistryKeyPath, true).ConfigureAwait(false);

        int removedFiles = 0, removedKeys = 0;
        long removedBytes = 0;
        Guid? id = null;
        if (files.Count + keys.Count > 0)
        {
            // Если квота вытеснила файл, хеш не совпал или SQLite не зафиксировал снимок — ничего не удаляем.
            id = (await tx.CommitVerifiedBackupAsync(ct).ConfigureAwait(false)).SessionId;
            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    DeleteMatchingFile(file);
                    removedFiles++;
                    removedBytes += file.Length;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Win32Exception)
                {
                    Skip(file.Path, ex.Message);
                }
            }
            foreach (var key in keys)
            {
                ct.ThrowIfCancellationRequested();
                if (key.IsUninstallEntry && skipped > 0) { Skip(key.Path, "очистка неполна"); continue; }
                if (await ExportRegistryTreeAsync(key.Path, ct).ConfigureAwait(false) != key.Export)
                { Skip(key.Path, "ветка изменилась после экспорта"); continue; }
                try
                {
                    var (hive, subkey) = SplitRegistryPath(key.Path);
                    hive.DeleteSubKeyTree(subkey, throwOnMissingSubKey: true);
                    removedKeys++;
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or ArgumentException or System.Security.SecurityException)
                { Skip(key.Path, ex.Message); }
            }
        }
        var summary = $"{appDisplayName}: удалено файлов {removedFiles} ({ByteFormatter.Format(removedBytes)}), веток реестра {removedKeys}. Пропущено: {skipped}.";
        if (id.HasValue) summary += " Проверенная копия закреплена в Машине времени.";
        if (reasons.Count > 0) summary += "\n" + string.Join("\n", reasons);
        return new(skipped == 0, id, appDisplayName, false, removedFiles, removedKeys, removedBytes, summary);
    }

    private static bool HasReparseAncestor(string path)
    {
        for (string? current = path; current is not null; current = Path.GetDirectoryName(current))
            if (File.GetAttributes(current).HasFlag(FileAttributes.ReparsePoint)) return true;
        return false;
    }

    // FileShare.Read excludes writers and renames. Verify and request deletion on the *same* handle.
    private static void DeleteMatchingFile(FileBackup file)
    {
        if (HasReparseAncestor(file.Path)) throw new IOException("Путь стал ссылкой после анализа.");
        using var handle = CreateFileW(file.Path, 0x80000000u | 0x00010000u /* GENERIC_READ | DELETE */,
            FileShare.Read, IntPtr.Zero, FileMode.Open, 0x00200000 /* OPEN_REPARSE_POINT */, IntPtr.Zero);
        if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        using var input = new FileStream(handle, FileAccess.Read);
        if (input.Length != file.Length || !Convert.ToHexString(SHA256.HashData(input)).Equals(file.Hash, StringComparison.OrdinalIgnoreCase))
            throw new IOException("Файл изменился после создания снимка.");
        byte delete = 1;
        if (!SetFileInformationByHandle(handle, 4 /* FileDispositionInfo */, ref delete, 1))
            throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    private static (RegistryKey Hive, string SubKey) SplitRegistryPath(string path)
    {
        var split = path.IndexOf('\\');
        var hkcu = path[..split].Equals("HKCU", StringComparison.OrdinalIgnoreCase) ||
                   path[..split].Equals("HKEY_CURRENT_USER", StringComparison.OrdinalIgnoreCase);
        return (hkcu ? Registry.CurrentUser : Registry.LocalMachine, path[(split + 1)..]);
    }

    internal static async Task<string?> ExportRegistryTreeAsync(string path, CancellationToken ct)
    {
        var temp = Path.Combine(Path.GetTempPath(), $"uw-reg-{Guid.NewGuid():N}.reg");
        try
        {
            var (code, _, _) = await RunProcessCaptureAsync(Path.Combine(Environment.SystemDirectory, "reg.exe"),
                ["export", path, temp, "/y"], TimeSpan.FromSeconds(8), ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
            if (code != 0 || !File.Exists(temp) || new FileInfo(temp).Length is 0 or > 524288) return null;
            var text = await File.ReadAllTextAsync(temp, ct).ConfigureAwait(false);
            var (hive, subkey) = SplitRegistryPath(path);
            return text.StartsWith("Windows Registry Editor Version 5.00", StringComparison.Ordinal) &&
                text.Contains($"\n[{hive.Name}\\{subkey}]", StringComparison.OrdinalIgnoreCase) ? text : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
        finally { try { File.Delete(temp); } catch (IOException) { } }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, FileShare share, IntPtr security,
        FileMode creation, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle file, int infoClass, ref byte info, uint size);
}
