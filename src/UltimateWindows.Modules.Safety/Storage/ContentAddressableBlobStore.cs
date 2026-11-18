using System.IO.Compression;
using System.Security.Cryptography;

namespace UltimateWindows.Modules.Safety.Storage;

public sealed record StoredBlobResult(
    string Sha256Hex,
    long OriginalSizeBytes,
    long CompressedEncryptedBytes,
    bool WasDeduplicated);

// Файл принадлежит сессии до переноса в CAS. Это не ссылка на общий .uwq:
// другую, уже сохранённую копию с таким же хешем в это время можно вытеснить.
internal sealed record PreparedBlob(string TemporaryPath, string Sha256Hex, long OriginalSizeBytes) : IDisposable
{
    public void Dispose() => File.Delete(TemporaryPath);
}

/// <summary>
/// Контентно-адресуемое хранилище файлов карантина и бэкапов (.uwq):
/// 1) Дедупликация по SHA-256 (одинаковые файлы хранятся в одном экземпляре);
/// 2) Сжатие Brotli (Optimal) для минимального расхода диска;
/// 3) Шифрование AES-256-GCM (защита от случайного запуска и ложных срабатываний антивирусов).
/// </summary>
public sealed class ContentAddressableBlobStore
{
    private static readonly byte[] MagicHeader = "UWQ1"u8.ToArray();
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int KeySize = 32;

    private readonly string _blobsDirectory;
    private readonly byte[] _encryptionKey;

    public ContentAddressableBlobStore(string vaultDirectory)
    {
        Directory.CreateDirectory(vaultDirectory);
        _blobsDirectory = Path.Combine(vaultDirectory, "blobs");
        Directory.CreateDirectory(_blobsDirectory);
        _encryptionKey = LoadOrCreateKey(Path.Combine(vaultDirectory, "vault.key"));
    }

    public string BlobsDirectory => _blobsDirectory;

    public async Task<StoredBlobResult> StoreBytesAsync(byte[] plainBytes, CancellationToken ct = default)
    {
        using var prepared = await PrepareBytesAsync(plainBytes, ct).ConfigureAwait(false);
        return Publish(prepared);
    }

    internal async Task<PreparedBlob> PrepareFileAsync(string path, CancellationToken ct) =>
        await PrepareBytesAsync(await File.ReadAllBytesAsync(path, ct).ConfigureAwait(false), ct).ConfigureAwait(false);

    private async Task<PreparedBlob> PrepareBytesAsync(byte[] plainBytes, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(plainBytes);
        ct.ThrowIfCancellationRequested();
        var sha256Hex = Convert.ToHexString(SHA256.HashData(plainBytes)).ToLowerInvariant();
        byte[] compressedBytes;
        using (var compressedStream = new MemoryStream())
        {
            await using (var brotli = new BrotliStream(compressedStream, CompressionLevel.Optimal, leaveOpen: true))
            {
                await brotli.WriteAsync(plainBytes, ct).ConfigureAwait(false);
            }

            compressedBytes = compressedStream.ToArray();
        }

        var nonce = new byte[NonceSize];
        RandomNumberGenerator.Fill(nonce);

        var cipherBytes = new byte[compressedBytes.Length];
        var tag = new byte[TagSize];

        using (var aes = new AesGcm(_encryptionKey, TagSize))
        {
            aes.Encrypt(nonce, compressedBytes, cipherBytes, tag, MagicHeader);
        }

        var temp = Path.Combine(_blobsDirectory, $"capture-{Guid.NewGuid():N}.tmp");
        try
        {
            await using var fs = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            await fs.WriteAsync(MagicHeader, ct).ConfigureAwait(false);
            await fs.WriteAsync(nonce, ct).ConfigureAwait(false);
            await fs.WriteAsync(tag, ct).ConfigureAwait(false);
            await fs.WriteAsync(cipherBytes, ct).ConfigureAwait(false);
            fs.Flush(flushToDisk: true);
            return new PreparedBlob(temp, sha256Hex, plainBytes.LongLength);
        }
        catch
        {
            File.Delete(temp);
            throw;
        }
    }

    internal StoredBlobResult Publish(PreparedBlob prepared)
    {
        var path = GetBlobFilePath(prepared.Sha256Hex);
        bool shared = false;
        try { File.Move(prepared.TemporaryPath, path, overwrite: false); }
        catch (IOException) when (File.Exists(path)) { shared = true; }
        return new(prepared.Sha256Hex, prepared.OriginalSizeBytes, new FileInfo(path).Length, shared);
    }

    public async Task<StoredBlobResult> StoreFileAsync(string filePath, CancellationToken ct = default)
    {
        var bytes = await File.ReadAllBytesAsync(filePath, ct).ConfigureAwait(false);
        return await StoreBytesAsync(bytes, ct).ConfigureAwait(false);
    }

    public async Task<byte[]> RestoreBytesAsync(string sha256Hex, CancellationToken ct = default)
    {
        var blobPath = GetBlobFilePath(sha256Hex);
        if (!File.Exists(blobPath))
        {
            throw new FileNotFoundException($"Блоб карантина '{sha256Hex}' не найден (возможно, истек срок хранения или очищен кэш бэкапов).", blobPath);
        }

        var rawContainer = await File.ReadAllBytesAsync(blobPath, ct).ConfigureAwait(false);
        var headerOffset = MagicHeader.Length + NonceSize + TagSize;
        if (rawContainer.Length < headerOffset)
        {
            throw new InvalidDataException("Поврежден заголовок контейнера карантина .uwq.");
        }

        for (var i = 0; i < MagicHeader.Length; i++)
        {
            if (rawContainer[i] != MagicHeader[i])
            {
                throw new InvalidDataException("Неверная сигнатура контейнера .uwq.");
            }
        }

        var nonce = rawContainer.AsSpan(MagicHeader.Length, NonceSize);
        var tag = rawContainer.AsSpan(MagicHeader.Length + NonceSize, TagSize);
        var cipherSpan = rawContainer.AsSpan(headerOffset);
        var compressedBytes = new byte[cipherSpan.Length];

        using (var aes = new AesGcm(_encryptionKey, TagSize))
        {
            aes.Decrypt(nonce, cipherSpan, tag, compressedBytes, MagicHeader);
        }

        using var inputStream = new MemoryStream(compressedBytes);
        await using var brotli = new BrotliStream(inputStream, CompressionMode.Decompress);
        using var decompressed = new MemoryStream();
        await brotli.CopyToAsync(decompressed, ct).ConfigureAwait(false);

        var restored = decompressed.ToArray();
        var actualHash = Convert.ToHexString(SHA256.HashData(restored)).ToLowerInvariant();
        if (!string.Equals(actualHash, sha256Hex, StringComparison.OrdinalIgnoreCase))
        {
            throw new CryptographicException("Нарушена контрольная сумма SHA-256 при восстановлении блоба.");
        }

        return restored;
    }

    public bool DeleteBlobIfPresent(string sha256Hex)
    {
        var path = GetBlobFilePath(sha256Hex);
        if (!File.Exists(path))
        {
            return false;
        }

        File.Delete(path);
        return true;
    }

    public long ComputeTotalBlobBytesOnDisk()
    {
        if (!Directory.Exists(_blobsDirectory))
        {
            return 0;
        }

        long total = 0;
        foreach (var file in Directory.EnumerateFiles(_blobsDirectory, "*.uwq"))
        {
            total += new FileInfo(file).Length;
        }

        return total;
    }

    public int CountBlobsOnDisk()
    {
        return Directory.Exists(_blobsDirectory)
            ? Directory.EnumerateFiles(_blobsDirectory, "*.uwq").Count()
            : 0;
    }

    public string GetBlobFilePath(string sha256Hex)
    {
        var sanitized = sha256Hex.Trim().ToLowerInvariant();
        if (sanitized.Length != 64 || !sanitized.All(char.IsAsciiHexDigit)) throw new InvalidDataException("Некорректный SHA-256 архива.");
        return Path.Combine(_blobsDirectory, $"{sanitized}.uwq");
    }

    private byte[] LoadOrCreateKey(string keyPath)
    {
        if (!File.Exists(keyPath))
        {
            if (Directory.EnumerateFiles(_blobsDirectory, "*.uwq").Any())
                throw new InvalidDataException("Ключ отсутствует. Восстановите vault.key из копии этого хранилища.");
            var temp = keyPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                File.WriteAllBytes(temp, RandomNumberGenerator.GetBytes(KeySize));
                try { File.Move(temp, keyPath, overwrite: false); }
                catch (IOException) when (File.Exists(keyPath)) { /* Другое окно создало ключ первым. */ }
            }
            finally { File.Delete(temp); }
        }
        var existing = File.ReadAllBytes(keyPath);
        return existing.Length == KeySize ? existing : throw new InvalidDataException(
            "Ключ повреждён. Восстановите vault.key из копии этого хранилища. Ключ и архивы не перезаписаны.");
    }
}
