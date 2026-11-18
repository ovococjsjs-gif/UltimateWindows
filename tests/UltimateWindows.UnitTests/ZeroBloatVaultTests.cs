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
    public async Task VerifiedBackupOverQuota_RefusesCommitWithoutDeletingTheOriginal()
    {
        var vault = new ZeroBloatVaultService(Path.Combine(_tempRoot, "quota"));
        await vault.UpdatePolicyAsync(vault.CurrentPolicy with { MaxVaultBytes = 4096 });
        var path = Path.Combine(_tempRoot, "original.bin");
        var contents = new byte[16384];
        new Random(17).NextBytes(contents);
        await File.WriteAllBytesAsync(path, contents);
        await using var tx = vault.BeginTransaction(SystemDomain.AppsAndAutomation, "Before", "Backup");
        await tx.BackupFileAsync(path);
        await Assert.ThrowsAsync<IOException>(() => tx.CommitVerifiedBackupAsync());
        Assert.Equal(contents, await File.ReadAllBytesAsync(path));
        Assert.False(Assert.Single(await vault.GetHistoryAsync()).IsPinned);
    }

    [Fact]
    public async Task PreparedBackup_IsReadableAcrossRestart_AndRestoreWillNotReplaceANewerFile()
    {
        var root = Path.Combine(_tempRoot, "state");
        var path = Path.Combine(_tempRoot, "original.dat");
        await File.WriteAllTextAsync(path, "saved");
        var vault = new ZeroBloatVaultService(root);
        await using var tx = vault.BeginTransaction(SystemDomain.AppsAndAutomation, "Before", "Backup only");
        await tx.BackupFileAsync(path);
        var saved = await tx.CommitVerifiedBackupAsync();
        Assert.True(saved.IsPinned);
        Assert.Equal("saved", await File.ReadAllTextAsync(path));
        await File.WriteAllTextAsync(path, "new data");
        var reopened = new ZeroBloatVaultService(root);
        await Assert.ThrowsAsync<IOException>(() => reopened.RollbackTransactionAsync(saved.SessionId));
        Assert.Equal("new data", await File.ReadAllTextAsync(path));
        Assert.False(Assert.Single(await reopened.GetHistoryAsync()).IsReverted);
        File.Delete(path);
        await reopened.RollbackTransactionAsync(saved.SessionId);
        Assert.Equal("saved", await File.ReadAllTextAsync(path));
    }

    [Fact]
    public async Task DamagedBackup_FailsVerification_WithoutRemovingSource()
    {
        var root = Path.Combine(_tempRoot, "state");
        var vault = new ZeroBloatVaultService(root);
        var path = Path.Combine(_tempRoot, "original.dat");
        await File.WriteAllTextAsync(path, "original");
        await using var tx = vault.BeginTransaction(SystemDomain.AppsAndAutomation, "Before", "Backup");
        var hash = await tx.BackupFileAsync(path);
        await File.WriteAllTextAsync(Path.Combine(root, "blobs", hash + ".uwq"), "broken");
        await Assert.ThrowsAsync<InvalidDataException>(() => tx.CommitVerifiedBackupAsync());
        Assert.Equal("original", await File.ReadAllTextAsync(path));
        Assert.False(Assert.Single(await vault.GetHistoryAsync()).IsPinned);
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

    [Fact]
    public async Task ExpirationReleasesOnlyTheOldReferenceToSharedContent()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var vault = new ZeroBloatVaultService(Path.Combine(_tempRoot, "shared"), timeProvider: clock);
        async Task<(string Path, Guid Id)> Save(string name)
        {
            var path = Path.Combine(_tempRoot, name);
            await File.WriteAllTextAsync(path, "same content");
            await using var tx = vault.BeginTransaction(SystemDomain.SmartCleaner, name, "copy");
            await tx.BackupFileAsync(path);
            return (path, (await tx.CommitAsync()).SessionId);
        }
        var older = await Save("first");
        clock.Advance(TimeSpan.FromDays(10));
        var newer = await Save("second");
        clock.Advance(TimeSpan.FromDays(5));
        await vault.EnforceQuotaAndRetentionAsync();
        var history = await vault.GetHistoryAsync();
        Assert.True(history.Single(r => r.SessionId == older.Id).HasExpiredFile);
        Assert.False(history.Single(r => r.SessionId == newer.Id).HasExpiredFile);
        File.Delete(newer.Path);
        await vault.RollbackTransactionAsync(newer.Id);
        Assert.Equal("same content", await File.ReadAllTextAsync(newer.Path));
    }

    [Fact]
    public async Task PurgeByAnotherInstanceBetweenCaptureAndCommitCannotLoseThePendingCopy()
    {
        var root = Path.Combine(_tempRoot, "shared");
        var first = new ZeroBloatVaultService(root);
        var second = new ZeroBloatVaultService(root);
        var path = Path.Combine(_tempRoot, "draft.txt");
        await File.WriteAllTextAsync(path, "reviewed bytes");
        await using (var older = first.BeginTransaction(SystemDomain.SmartCleaner, "Old", "Copy"))
        {
            await older.BackupFileAsync(path);
            await older.CommitAsync();
        }
        await using var newer = second.BeginTransaction(SystemDomain.SmartCleaner, "New", "Copy");
        await newer.BackupFileAsync(path);
        Assert.Equal(1, await first.PurgeAllUnpinnedBlobsAsync());
        // Commit must publish the captured bytes, not reread the source or reuse the evicted reference.
        await File.WriteAllTextAsync(path, "changed since scan");
        var saved = await newer.CommitVerifiedBackupAsync();
        Assert.True(saved.IsPinned);
        Assert.Equal(1, (await first.GetStorageStatsAsync()).BlobCount);
        File.Delete(path);
        await first.RollbackTransactionAsync(saved.SessionId);
        Assert.Equal("reviewed bytes", await File.ReadAllTextAsync(path));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AbandonedOrCancelledQuarantineLeavesOriginalAndNoTemporaryBlob(bool cancel)
    {
        var dir = Path.Combine(_tempRoot, "vault");
        var vault = new ZeroBloatVaultService(dir);
        var path = Path.Combine(_tempRoot, "keep.txt");
        await File.WriteAllTextAsync(path, "keep");
        await using (var tx = vault.BeginTransaction(SystemDomain.DllAndRepair, "Test", "Prepare only"))
        {
            await tx.QuarantineFileAsync(path);
            Assert.Equal("keep", await File.ReadAllTextAsync(path));
            if (cancel) await Assert.ThrowsAnyAsync<OperationCanceledException>(() => tx.CommitAsync(ct: new CancellationToken(true)));
        }
        Assert.Equal("keep", await File.ReadAllTextAsync(path));
        Assert.Empty(Directory.EnumerateFiles(Path.Combine(dir, "blobs")));
        Assert.Empty(await vault.GetHistoryAsync());
    }

    [Fact]
    public async Task QuarantineNeverDeletesAChangedFileOrOneThatDoesNotFit()
    {
        var vault = new ZeroBloatVaultService(Path.Combine(_tempRoot, "state"));
        var path = Path.Combine(_tempRoot, "binary.dat");
        await File.WriteAllTextAsync(path, "AAAA");
        await using (var tx = vault.BeginTransaction(SystemDomain.DllAndRepair, "Changed", "Test"))
        {
            await tx.QuarantineFileAsync(path);
            await File.WriteAllTextAsync(path, "BBBB");
            await Assert.ThrowsAsync<IOException>(() => tx.CommitAsync());
        }
        Assert.Equal("BBBB", await File.ReadAllTextAsync(path));
        await vault.UpdatePolicyAsync(vault.CurrentPolicy with { MaxVaultBytes = 4096 });
        await using var small = vault.BeginTransaction(SystemDomain.DllAndRepair, "No space", "Test");
        await small.QuarantineFileAsync(path);
        await Assert.ThrowsAsync<IOException>(() => small.CommitAsync(pinTransaction: true));
        Assert.Equal("BBBB", await File.ReadAllTextAsync(path));
        Assert.True((await vault.GetHistoryAsync()).Single(r => r.SessionId == small.SessionId).HasExpiredFile);
    }

    [Fact]
    public async Task QuotaDoesNotDetachSharedPinnedContentButManualPurgeCanReleaseTheUnpinnedReference()
    {
        var vault = new ZeroBloatVaultService(Path.Combine(_tempRoot, "pin"));
        var path = Path.Combine(_tempRoot, "shared.txt");
        await File.WriteAllTextAsync(path, "same");
        await using var pinned = vault.BeginTransaction(SystemDomain.DllAndRepair, "Pinned", "Test");
        await pinned.BackupFileAsync(path);
        await pinned.CommitVerifiedBackupAsync();
        await using var other = vault.BeginTransaction(SystemDomain.DllAndRepair, "Other", "Test");
        await other.BackupFileAsync(path);
        await other.CommitAsync();
        await vault.UpdatePolicyAsync(vault.CurrentPolicy with { MaxVaultBytes = 4096 });
        Assert.All(await vault.GetHistoryAsync(), r => Assert.False(r.HasExpiredFile));
        Assert.Equal(0, await vault.PurgeAllUnpinnedBlobsAsync());
        Assert.True((await vault.GetHistoryAsync()).Single(r => r.SessionId == other.SessionId).HasExpiredFile);
        File.Delete(path);
        await vault.RollbackTransactionAsync(pinned.SessionId);
        Assert.Equal("same", await File.ReadAllTextAsync(path));
    }

    [Fact]
    public async Task BrokenOrMissingKeyNeverOverwritesCredentialsForExistingArchives()
    {
        var dir = Path.Combine(_tempRoot, "key");
        var store = new ContentAddressableBlobStore(dir);
        var blob = await store.StoreBytesAsync([1, 2, 3]);
        var key = Path.Combine(dir, "vault.key");
        var goodKey = File.ReadAllBytes(key);
        File.WriteAllBytes(key, [0]);
        Assert.Throws<InvalidDataException>(() => new ContentAddressableBlobStore(dir));
        Assert.Equal(new byte[] { 0 }, File.ReadAllBytes(key));
        File.Delete(key);
        Assert.Throws<InvalidDataException>(() => new ContentAddressableBlobStore(dir));
        Assert.False(File.Exists(key));
        File.WriteAllBytes(key, goodKey);
        Assert.Equal(new byte[] { 1, 2, 3 }, await new ContentAddressableBlobStore(dir).RestoreBytesAsync(blob.Sha256Hex));
    }

    [Theory]
    [InlineData("OfficialRuntime:sample")]
    [InlineData("RepairBatch:sample")]
    [InlineData("RepairPlaybook:sample")]
    public async Task JournalOnlyRecordsCannotBeReportedAsReverted(string target)
    {
        var vault = new ZeroBloatVaultService(Path.Combine(_tempRoot, "history"));
        await using var tx = vault.BeginTransaction(SystemDomain.DllAndRepair, "Report", "No inverse action");
        tx.RecordStateDelta(StateTargetKind.SystemSetting, target, "{}", null);
        var saved = await tx.CommitAsync();
        Assert.True(saved.IsJournalOnly);
        await Assert.ThrowsAsync<InvalidOperationException>(() => vault.RollbackTransactionAsync(saved.SessionId));
        Assert.False(Assert.Single(await vault.GetHistoryAsync()).IsReverted);
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
