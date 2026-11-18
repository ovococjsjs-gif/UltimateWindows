using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
using UltimateWindows.Modules.Cleaner.Models;

namespace UltimateWindows.NativeInterop.Files;

/// <summary>Проверка и удаление одного открытого объекта. Не переходим по ссылке и не допускаем
/// запись или подмену имени между проверкой и запросом удаления.</summary>
internal static class CheckedFileDeletion
{
    internal static FileRemovalOutcome Remove(string path, long expectedLength, DateTime? writeTimeUtc, string? hash)
    {
        using var handle = CreateFileW(path, 0x80000000u | 0x10000u /* GENERIC_READ | DELETE */,
            FileShare.Read, IntPtr.Zero, FileMode.Open, 0x00200000 /* OPEN_REPARSE_POINT */, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            if (error is 2 or 3) return FileRemovalOutcome.ChangedOrMissing;
            throw new Win32Exception(error);
        }
        if ((File.GetAttributes(handle) & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0 ||
            RandomAccess.GetLength(handle) != expectedLength ||
            (writeTimeUtc.HasValue && File.GetLastWriteTimeUtc(handle) != writeTimeUtc))
            return FileRemovalOutcome.ChangedOrMissing;

        var final = new StringBuilder(Math.Max(512, path.Length + 16));
        var size = GetFinalPathNameByHandleW(handle, final, (uint)final.Capacity, 0);
        if (size == 0) throw new Win32Exception(Marshal.GetLastWin32Error());
        if (size >= final.Capacity || !NormalName(final.ToString()).Equals(NormalName(Path.GetFullPath(path)), StringComparison.OrdinalIgnoreCase))
            return FileRemovalOutcome.ChangedOrMissing;

        using var stream = new FileStream(handle, FileAccess.Read);
        if (hash is not null && !Convert.ToHexString(SHA256.HashData(stream)).Equals(hash, StringComparison.OrdinalIgnoreCase))
            return FileRemovalOutcome.ChangedOrMissing;
        byte delete = 1;
        if (!SetFileInformationByHandle(handle, 4 /* FileDispositionInfo */, ref delete, 1)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return FileRemovalOutcome.Removed;
    }

    private static string NormalName(string path) => path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)
        ? @"\\" + path[8..] : path.StartsWith(@"\\?\", StringComparison.Ordinal) ? path[4..] : path;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, FileShare share, IntPtr security, FileMode creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder dest, uint length, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle file, int infoClass, ref byte info, uint size);
}
