using System.IO.Compression;
using System.Security.Cryptography;

namespace UltimateWindows.Modules.Safety.Storage;

public sealed record StoredBlobResult(
    string Sha256Hex,
    long OriginalSizeBytes,
    long CompressedEncryptedBytes,
    bool WasDeduplicated);

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
        ArgumentNullException.ThrowIfNull(plainBytes);

        var hashBytes = SHA256.HashData(plainBytes);
        var sha256Hex = Convert.ToHexString(hashBytes).ToLowerInvariant();
        var blobPath = GetBlobFilePath(sha256Hex);

        if (File.Exists(blobPath))
        {
            var existingInfo = new FileInfo(blobPath);
            return new StoredBlobResult(sha256Hex, plainBytes.LongLength, existingInfo.Length, WasDeduplicated: true);
        }

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

        var tempPath = blobPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        await using (var fs = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            await fs.WriteAsync(MagicHeader, ct).ConfigureAwait(false);
            await fs.WriteAsync(nonce, ct).ConfigureAwait(false);
            await fs.WriteAsync(tag, ct).ConfigureAwait(false);
            await fs.WriteAsync(cipherBytes, ct).ConfigureAwait(false);
            await fs.FlushAsync(ct).ConfigureAwait(false);
        }

        File.Move(tempPath, blobPath, overwrite: true);
        var finalInfo = new FileInfo(blobPath);

        return new StoredBlobResult(sha256Hex, plainBytes.LongLength, finalInfo.Length, WasDeduplicated: false);
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
        return Path.Combine(_blobsDirectory, $"{sanitized}.uwq");
    }

    private static byte[] LoadOrCreateKey(string keyPath)
    {
        if (File.Exists(keyPath))
        {
            var existing = File.ReadAllBytes(keyPath);
            if (existing.Length == KeySize)
            {
                return existing;
            }
        }

        var key = new byte[KeySize];
        RandomNumberGenerator.Fill(key);
        File.WriteAllBytes(keyPath, key);
        return key;
    }
}
