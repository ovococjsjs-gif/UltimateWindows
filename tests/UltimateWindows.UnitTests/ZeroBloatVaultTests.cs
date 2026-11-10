using System.Text;
using UltimateWindows.Core.Enums;
using UltimateWindows.Core.Models;
using UltimateWindows.Modules.Safety.Services;
using UltimateWindows.Modules.Safety.Storage;
using Xunit;

namespace UltimateWindows.UnitTests;

public sealed class ZeroBloatVaultTests : IDisposable
{
    private readonly string _tempRoot;

    public ZeroBloatVaultTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), "UltimateWindowsTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempRoot);
    }

    [Fact]
    public void QuotaPolicy_ShrinksAutomaticallyOnLowDiskSpace()
    {
        var policy = new VaultQuotaPolicy
        {
            MaxVaultBytes = 250 * VaultQuotaPolicy.Megabyte,
            MinFloorBytes = 32 * VaultQuotaPolicy.Megabyte,
            MaxFreeSpaceRatio = 0.005
        };

        // 10 ГБ свободно -> 0.5% = ~51.2 МБ (намного меньше верхнего потолка 250 МБ)
        var tenGbFree = 10L * VaultQuotaPolicy.Gigabyte;
        var limit = policy.ComputeEffectiveLimitBytes(tenGbFree);

        Assert.InRange(limit, 50 * VaultQuotaPolicy.Megabyte, 52 * VaultQuotaPolicy.Megabyte);
    }

    [Fact]
    public async Task BlobStore_CompressesEncryptsDeduplicatesAndRestoresExactBytes()
    {
        var vaultDir = Path.Combine(_tempRoot, "cas");
        var store = new ContentAddressableBlobStore(vaultDir);

        var originalText = string.Concat(Enumerable.Repeat("UltimateWindows-ZeroBloat-TestData-12345|", 400));
        var payload = Encoding.UTF8.GetBytes(originalText);

        var first = await store.StoreBytesAsync(payload);
        var second = await store.StoreBytesAsync(payload);

        Assert.False(first.WasDeduplicated);
        Assert.True(second.WasDeduplicated);
        Assert.Equal(first.Sha256Hex, second.Sha256Hex);
        Assert.Equal(1, store.CountBlobsOnDisk());
        Assert.True(first.CompressedEncryptedBytes < first.OriginalSizeBytes);

        var restored = await store.RestoreBytesAsync(first.Sha256Hex);
        Assert.Equal(payload, restored);
    }

    [Fact]
    public async Task VaultService_QuarantinesFileAndRestoresOnOneClickRollback()
    {
        var vaultDir = Path.Combine(_tempRoot, "vault_rollback");
        var workDir = Path.Combine(_tempRoot, "work");
        Directory.CreateDirectory(workDir);

        var sampleFile = Path.Combine(workDir, "suspicious_autorun.cmd");
        var expectedBytes = Encoding.UTF8.GetBytes("@echo off\r\nrem test quarantine file");
        await File.WriteAllBytesAsync(sampleFile, expectedBytes);

        var service = new ZeroBloatVaultService(explicitVaultDirectory: vaultDir);

        Guid sessionId;
        await using (var tx = service.BeginTransaction(
            SystemDomain.AntiMiner,
            "Изоляция подозрительного скрипта автозагрузки",
            "Файл перемещен в защищенный карантин."))
        {
            await tx.QuarantineFileAsync(sampleFile);
            var committed = await tx.CommitAsync();
            sessionId = committed.SessionId;
        }

        Assert.False(File.Exists(sampleFile));

        await service.RollbackTransactionAsync(sessionId);

        Assert.True(File.Exists(sampleFile));
        Assert.Equal(expectedBytes, await File.ReadAllBytesAsync(sampleFile));

        var history = await service.GetHistoryAsync();
        Assert.Single(history);
        Assert.True(history[0].IsReverted);
    }

    [Fact]
    public async Task VaultService_PurgesExpiredUnpinnedBlobsButKeepsPinnedAndRegistryMetadata()
    {
        var clock = new ManualTimeProvider(new DateTimeOffset(2026, 11, 10, 12, 0, 0, TimeSpan.Zero));
        var vaultDir = Path.Combine(_tempRoot, "vault_ttl");
        var workDir = Path.Combine(_tempRoot, "ttl_files");
        Directory.CreateDirectory(workDir);

        var unpinnedFile = Path.Combine(workDir, "temp_cache_1.bin");
        var pinnedFile = Path.Combine(workDir, "important_backup.bin");
        var unpinnedBuffer = new byte[4096];
        Random.Shared.NextBytes(unpinnedBuffer);
        await File.WriteAllBytesAsync(unpinnedFile, unpinnedBuffer);
        await File.WriteAllBytesAsync(pinnedFile, Encoding.UTF8.GetBytes("PinnedImportantContent_Unique_999"));

        var service = new ZeroBloatVaultService(
            explicitVaultDirectory: vaultDir,
            timeProvider: clock);

        // 1. Незакрепленная транзакция с файлом + записью реестра
        await using (var tx1 = service.BeginTransaction(SystemDomain.SmartCleaner, "Очистка временного файла", "Тест TTL"))
        {
            tx1.RecordStateDelta(StateTargetKind.RegistryValue, @"HKCU\Software\Test\Val", "1", "0");
            await tx1.QuarantineFileAsync(unpinnedFile);
            await tx1.CommitAsync(pinTransaction: false);
        }

        // 2. Закрепленная пользователем транзакция
        Guid pinnedSessionId;
        await using (var tx2 = service.BeginTransaction(SystemDomain.HardwareAndDrivers, "Важная точка перед обновлением", "Закреплено"))
        {
            await tx2.QuarantineFileAsync(pinnedFile);
            var rec = await tx2.CommitAsync(pinTransaction: true);
            pinnedSessionId = rec.SessionId;
        }

        // Перематываем время вперед на 15 дней (больше дефолтных 14 дней TTL)
        clock.Advance(TimeSpan.FromDays(15));
        var evictedCount = await service.EnforceQuotaAndRetentionAsync();

        Assert.Equal(1, evictedCount);

        // Закрепленный файл по-прежнему восстанавливается без проблем
        await service.RollbackTransactionAsync(pinnedSessionId);
        Assert.True(File.Exists(pinnedFile));

        // История транзакций (включая микро-запись реестра) осталась в целости!
        var history = await service.GetHistoryAsync();
        Assert.Equal(2, history.Count);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempRoot))
            {
                Directory.Delete(_tempRoot, recursive: true);
            }
        }
        catch
        {
            // Игнорируем возможные задержки закрытия дескрипторов ОС
        }
    }

    private sealed class ManualTimeProvider(DateTimeOffset initialUtc) : TimeProvider
    {
        private DateTimeOffset _utcNow = initialUtc;

        public override DateTimeOffset GetUtcNow() => _utcNow;

        public void Advance(TimeSpan delta) => _utcNow = _utcNow.Add(delta);
    }
}
