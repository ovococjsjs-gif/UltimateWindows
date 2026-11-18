using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Optimizer.Network;
using UltimateWindows.Modules.Security.Models;

namespace UltimateWindows.NativeInterop.SecurityHunter;

internal static class ReviewedHostsRepair
{
    private const int Limit = 256 * 1024;
    private static string PathName => Path.Combine(Environment.SystemDirectory, "drivers", "etc", "hosts");
    private static readonly UTF8Encoding Utf8 = new(false, true);

    internal static PreparedSecurityChange Prepare(string reviewedPath)
    {
        if (!string.Equals(Path.GetFullPath(reviewedPath), PathName, StringComparison.OrdinalIgnoreCase)) throw new IOException("Неизвестный путь hosts.");
        byte[] original;
        using (var f = Open(FileAccess.Read)) original = Read(f);
        var bom = original.AsSpan().StartsWith(Encoding.UTF8.Preamble) ? Encoding.UTF8.Preamble.Length : 0;
        string text = Utf8.GetString(original, bom, original.Length - bom);
        // Работать с физическими строками: Split по двум символам считает CRLF двумя переносами.
        var cleaned = new StringBuilder();
        bool removed = false;
        for (int start = 0; start < text.Length;)
        {
            int pos = text.IndexOfAny(['\r', '\n'], start);
            int end = pos < 0 ? text.Length : pos + (text[pos] == '\r' && pos + 1 < text.Length && text[pos + 1] == '\n' ? 2 : 1);
            if (NetworkAndHostsInspector.ParseHostsContent(text[start..end]).Any(r => r.IsSuspiciousSecurityBlock)) removed = true;
            else cleaned.Append(text, start, end - start);
            start = end;
        }
        if (!removed) throw new InvalidOperationException("Блокирующие строки в hosts больше не найдены.");
        byte[] next = [.. original.AsSpan(0, bom), .. Utf8.GetBytes(cleaned.ToString())];
        return new("Очистка hosts", StateTargetKind.SystemSetting, "HostsSabotageCleanup",
            JsonSerializer.Serialize(new { Original = Convert.ToBase64String(original), AfterHash = Hash(next) }),
            ct => Task.Run(() => ReplaceIfMatches(Hash(original), next), ct));
    }

    internal static void Restore(string snapshot)
    {
        using var doc = JsonDocument.Parse(snapshot);
        var before = Convert.FromBase64String(doc.RootElement.GetProperty("Original").GetString()!);
        if (before.Length > Limit || !ReplaceIfMatches(doc.RootElement.GetProperty("AfterHash").GetString()!, before, allowAlreadyRestored: true))
            throw new IOException("Файл hosts изменён после очистки; конфликтующий файл не перезаписан.");
    }

    private static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));
    private static FileStream Open(FileAccess access)
    {
        for (var entry = PathName; entry is not null; entry = Path.GetDirectoryName(entry))
            if ((File.GetAttributes(entry) & FileAttributes.ReparsePoint) != 0) throw new IOException("Путь hosts проходит через ссылку.");
        return File.Open(PathName, FileMode.Open, access, FileShare.None);
    }
    private static byte[] Read(FileStream f)
    {
        if (f.Length > Limit) throw new IOException("Файл hosts превышает лимит снимка.");
        var bytes = new byte[(int)f.Length]; f.ReadExactly(bytes); return bytes;
    }
    private static bool ReplaceIfMatches(string expected, byte[] data, bool allowAlreadyRestored = false)
    {
        using var f = Open(FileAccess.ReadWrite);
        var current = Read(f);
        if (allowAlreadyRestored && current.AsSpan().SequenceEqual(data)) return true;
        if (Hash(current) != expected) return false;
        f.Position = 0; f.Write(data); f.SetLength(data.Length); f.Flush(true);
        f.Position = 0; return Read(f).AsSpan().SequenceEqual(data);
    }
}
