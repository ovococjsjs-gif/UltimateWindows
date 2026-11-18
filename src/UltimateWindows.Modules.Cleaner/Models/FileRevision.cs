using System.Security.Cryptography;

namespace UltimateWindows.Modules.Cleaner.Models;

/// <summary>Версия объекта в плане. Для персональных данных дополнительно проверяются байты.</summary>
public sealed record FileRevision(string FullPath, long Length, DateTime WriteTimeUtc, string? Sha256 = null)
{
    public static FileRevision Read(string path, bool hash = false)
    {
        for (var entry = Path.GetFullPath(path); entry is not null; entry = Path.GetDirectoryName(entry))
            if (File.GetAttributes(entry).HasFlag(FileAttributes.ReparsePoint))
                throw new IOException("Путь проходит через ссылку или точку подключения.");

        using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return new(path, stream.Length, File.GetLastWriteTimeUtc(stream.SafeFileHandle),
            hash ? Convert.ToHexString(SHA256.HashData(stream)) : null);
    }
}

public enum FileRemovalOutcome { Removed, ChangedOrMissing, Unavailable }
