using System.Text.Json;
using UltimateWindows.Core.Contracts;
using UltimateWindows.Core.Enums;
using UltimateWindows.Core.Guards;
using UltimateWindows.Core.Models;
using UltimateWindows.Modules.Safety.Storage;

namespace UltimateWindows.Modules.Safety.Services;

/// <summary>
/// Базовый исполнитель отката по умолчанию для файлового карантина (и безопасный no-op для платформенных записей в кроссплатформенных тестах).
/// На Windows расширяется классом WindowsSystemStateApplier.
/// </summary>
public class DefaultFileStateApplier : ISystemStateApplier
{
    public virtual async Task ApplyRollbackDeltaAsync(
        StateDeltaRecord delta,
        Func<string, CancellationToken, Task<byte[]>> restoreBlobBytesAsync,
        CancellationToken ct = default)
    {
        if (delta.TargetKind == StateTargetKind.QuarantinedFile)
        {
            if (string.IsNullOrWhiteSpace(delta.BlobSha256))
            {
                throw new InvalidOperationException(
                    $"Файловый блоб для '{delta.TargetPath}' уже был удален политикой очистки хранилища.");
            }

            var bytes = await restoreBlobBytesAsync(delta.BlobSha256, ct).ConfigureAwait(false);
            var parentDir = Path.GetDirectoryName(delta.TargetPath);
            if (!string.IsNullOrWhiteSpace(parentDir))
            {
                Directory.CreateDirectory(parentDir);
            }

            await File.WriteAllBytesAsync(delta.TargetPath, bytes, ct).ConfigureAwait(false);
        }
    }
}

/// <summary>
/// Сервис управления «Машиной времени» и не засоряющим систему хранилищем бэкапов (Zero-Bloat Vault).
/// </summary>
public sealed class ZeroBloatVaultService : IVaultService
{
    private readonly string _vaultDirectory;
    private readonly SqliteVaultRepository _repository;
    private readonly ContentAddressableBlobStore _blobStore;
    private readonly ISystemStateApplier _stateApplier;
    private readonly Func<long> _freeSpaceBytesProvider;
    private readonly TimeProvider _timeProvider;
    private VaultQuotaPolicy _currentPolicy;

    public ZeroBloatVaultService(
        string? explicitVaultDirectory = null,
        ISystemStateApplier? stateApplier = null,
        Func<long>? freeSpaceBytesProvider = null,
        TimeProvider? timeProvider = null)
    {
        _vaultDirectory = VaultPathResolver.ResolveDefaultVaultDirectory(explicitVaultDirectory);
        _repository = new SqliteVaultRepository(_vaultDirectory);
        _blobStore = new ContentAddressableBlobStore(_vaultDirectory);
        _stateApplier = stateApplier ?? new DefaultFileStateApplier();
        _freeSpaceBytesProvider = freeSpaceBytesProvider ?? (() => VaultPathResolver.GetVolumeFreeBytes(_vaultDirectory));
        _timeProvider = timeProvider ?? TimeProvider.System;
        _currentPolicy = _repository.LoadPolicyOrDefault();
    }

    public string VaultDirectory => _vaultDirectory;

    public VaultQuotaPolicy CurrentPolicy => _currentPolicy;

    public ITransactionSession BeginTransaction(
        SystemDomain domain,
        string friendlyTitle,
        string friendlySummary,
        string technicalDetails = "")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(friendlyTitle);
        return new SafetyTransactionSession(
            this,
            _repository,
            _blobStore,
            _timeProvider,
            domain,
            friendlyTitle,
            friendlySummary,
            technicalDetails);
    }

    public Task<IReadOnlyList<TransactionRecord>> GetHistoryAsync(int limit = 100, CancellationToken ct = default)
        => _repository.GetRecentTransactionsAsync(limit, ct);

    public async Task<VaultStorageStats> GetStorageStatsAsync(CancellationToken ct = default)
    {
        var dbBytes = _repository.GetDatabaseSizeBytes();
        var blobBytes = _blobStore.ComputeTotalBlobBytesOnDisk();
        var blobCount = _blobStore.CountBlobsOnDisk();
        var (activeCount, revertedCount) = await _repository.GetTransactionCountsAsync(ct).ConfigureAwait(false);
        var effectiveLimit = _currentPolicy.ComputeEffectiveLimitBytes(_freeSpaceBytesProvider());

        return new VaultStorageStats(
            DatabaseBytes: dbBytes,
            BlobBytes: blobBytes,
            EffectiveLimitBytes: effectiveLimit,
            BlobCount: blobCount,
            ActiveTransactionCount: activeCount,
            RevertedTransactionCount: revertedCount);
    }

    public async Task RollbackTransactionAsync(Guid sessionId, CancellationToken ct = default)
    {
        var record = await _repository.GetTransactionByIdAsync(sessionId, ct).ConfigureAwait(false)
            ?? throw new KeyNotFoundException($"Транзакция '{sessionId}' не найдена в журнале отката.");

        if (record.IsReverted)
        {
            return;
        }

        // Откат строго в обратном порядке (LIFO), чтобы корректно восстанавливать зависимые ключи и файлы
        foreach (var delta in record.Deltas.OrderByDescending(d => d.SequenceOrder))
        {
            await _stateApplier.ApplyRollbackDeltaAsync(
                delta,
                _blobStore.RestoreBytesAsync,
                ct).ConfigureAwait(false);
        }

        await _repository.MarkRevertedAsync(sessionId, _timeProvider.GetUtcNow(), ct).ConfigureAwait(false);
    }

    public Task SetPinnedAsync(Guid sessionId, bool isPinned, CancellationToken ct = default)
        => _repository.SetPinnedAsync(sessionId, isPinned, ct);

    public async Task UpdatePolicyAsync(VaultQuotaPolicy newPolicy, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(newPolicy);
        _currentPolicy = newPolicy;
        await _repository.SavePolicyAsync(newPolicy, ct).ConfigureAwait(false);
        await EnforceQuotaAndRetentionAsync(ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Применяет политику Zero-Bloat:
    /// 1) Удаляет просроченные файловые блобы старше FileBlobRetentionDays;
    /// 2) При превышении квоты диска вытесняет самые старые незакрепленные блобы (FIFO),
    ///    сохраняя при этом компактные записи отката реестра!
    /// </summary>
    public async Task<int> EnforceQuotaAndRetentionAsync(CancellationToken ct = default)
    {
        var now = _timeProvider.GetUtcNow();
        var effectiveLimit = _currentPolicy.ComputeEffectiveLimitBytes(_freeSpaceBytesProvider());
        var candidates = await _repository.GetUnpinnedBlobReferencesOldestFirstAsync(ct).ConfigureAwait(false);

        var removedBlobs = 0;
        var processedHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Шаг 1: Очистка блобов с истекшим TTL
        foreach (var item in candidates)
        {
            if (item.ExpiresAtUtc.HasValue && item.ExpiresAtUtc.Value <= now)
            {
                if (processedHashes.Add(item.BlobSha256))
                {
                    if (await TryEvictBlobAsync(item.BlobSha256, ct).ConfigureAwait(false))
                    {
                        removedBlobs++;
                    }
                }
            }
        }

        // Шаг 2: Кольцевое вытеснение старых блобов, если суммарный объем превышает бюджет
        foreach (var item in candidates)
        {
            var currentTotal = _repository.GetDatabaseSizeBytes() + _blobStore.ComputeTotalBlobBytesOnDisk();
            if (currentTotal <= effectiveLimit)
            {
                break;
            }

            if (processedHashes.Add(item.BlobSha256))
            {
                if (await TryEvictBlobAsync(item.BlobSha256, ct).ConfigureAwait(false))
                {
                    removedBlobs++;
                }
            }
        }

        return removedBlobs;
    }

    /// <summary>
    /// Ручная кнопка пользователя «Очистить файловый кэш бэкапов» (сохраняет микро-записи отката реестра и закрепленные точки).
    /// </summary>
    public async Task<int> PurgeAllUnpinnedBlobsAsync(CancellationToken ct = default)
    {
        var candidates = await _repository.GetUnpinnedBlobReferencesOldestFirstAsync(ct).ConfigureAwait(false);
        var removed = 0;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var item in candidates)
        {
            if (seen.Add(item.BlobSha256))
            {
                if (await TryEvictBlobAsync(item.BlobSha256, ct).ConfigureAwait(false))
                {
                    removed++;
                }
            }
        }

        return removed;
    }

    private async Task<bool> TryEvictBlobAsync(string sha256Hex, CancellationToken ct)
    {
        if (await _repository.IsBlobReferencedByPinnedTransactionAsync(sha256Hex, ct).ConfigureAwait(false))
        {
            return false;
        }

        var deleted = _blobStore.DeleteBlobIfPresent(sha256Hex);
        await _repository.DetachBlobFromUnpinnedTransactionsAndCompactAsync(sha256Hex, ct).ConfigureAwait(false);
        return deleted;
    }

    private sealed class SafetyTransactionSession : ITransactionSession
    {
        private readonly ZeroBloatVaultService _owner;
        private readonly SqliteVaultRepository _repository;
        private readonly ContentAddressableBlobStore _blobStore;
        private readonly TimeProvider _timeProvider;
        private readonly SystemDomain _domain;
        private readonly string _friendlyTitle;
        private readonly string _friendlySummary;
        private readonly string _technicalDetails;
        private readonly List<StateDeltaRecord> _deltas = [];
        private long _storedBlobBytesDelta;
        private bool _hasFileBlobs;
        private bool _committed;

        public SafetyTransactionSession(
            ZeroBloatVaultService owner,
            SqliteVaultRepository repository,
            ContentAddressableBlobStore blobStore,
            TimeProvider timeProvider,
            SystemDomain domain,
            string friendlyTitle,
            string friendlySummary,
            string technicalDetails)
        {
            _owner = owner;
            _repository = repository;
            _blobStore = blobStore;
            _timeProvider = timeProvider;
            _domain = domain;
            _friendlyTitle = friendlyTitle;
            _friendlySummary = friendlySummary;
            _technicalDetails = technicalDetails;
            SessionId = Guid.NewGuid();
        }

        public Guid SessionId { get; }

        public void RecordStateDelta(
            StateTargetKind targetKind,
            string targetPath,
            string? previousStateJson,
            string? newStateJson)
        {
            EnsureNotCommitted();
            ArgumentException.ThrowIfNullOrWhiteSpace(targetPath);

            var approxMetadataBytes = (previousStateJson?.Length ?? 0) + (newStateJson?.Length ?? 0) + targetPath.Length;
            _deltas.Add(new StateDeltaRecord(
                DeltaId: Guid.NewGuid(),
                SessionId: SessionId,
                SequenceOrder: _deltas.Count,
                TargetKind: targetKind,
                TargetPath: targetPath,
                PreviousStateJson: previousStateJson,
                NewStateJson: newStateJson,
                BlobSha256: null,
                OriginalSizeBytes: approxMetadataBytes));
        }

        public async Task<string> QuarantineFileAsync(string sourceFilePath, CancellationToken ct = default)
        {
            EnsureNotCommitted();
            ArgumentException.ThrowIfNullOrWhiteSpace(sourceFilePath);

            // Жесткая защита: даже карантин не имеет права трогать пароли и автозаполнение браузеров!
            BrowserVaultGuard.ThrowIfProtected(sourceFilePath);

            var fullPath = Path.GetFullPath(sourceFilePath);
            if (!File.Exists(fullPath))
            {
                throw new FileNotFoundException("Исходный файл для помещения в карантин не найден.", fullPath);
            }

            var stored = await _blobStore.StoreFileAsync(fullPath, ct).ConfigureAwait(false);
            File.Delete(fullPath);

            _hasFileBlobs = true;
            if (!stored.WasDeduplicated)
            {
                _storedBlobBytesDelta += stored.CompressedEncryptedBytes;
            }

            _deltas.Add(new StateDeltaRecord(
                DeltaId: Guid.NewGuid(),
                SessionId: SessionId,
                SequenceOrder: _deltas.Count,
                TargetKind: StateTargetKind.QuarantinedFile,
                TargetPath: fullPath,
                PreviousStateJson: JsonSerializer.Serialize(new { Exists = true, Sha256 = stored.Sha256Hex }),
                NewStateJson: JsonSerializer.Serialize(new { Exists = false, Quarantined = true }),
                BlobSha256: stored.Sha256Hex,
                OriginalSizeBytes: stored.OriginalSizeBytes));

            return stored.Sha256Hex;
        }

        public void RecordDriverStoreReference(string deviceInstanceId, string publishedInfName, string driverVersion)
        {
            EnsureNotCommitted();
            var refJson = JsonSerializer.Serialize(new
            {
                DeviceInstanceId = deviceInstanceId,
                PublishedInf = publishedInfName,
                DriverVersion = driverVersion
            });

            // 0 байт копирования тяжелых файлов: ссылаемся на штатный пакет в Windows DriverStore!
            RecordStateDelta(
                StateTargetKind.DriverStoreReference,
                deviceInstanceId,
                previousStateJson: refJson,
                newStateJson: null);
        }

        public async Task<TransactionRecord> CommitAsync(bool pinTransaction = false, CancellationToken ct = default)
        {
            EnsureNotCommitted();
            _committed = true;

            var now = _timeProvider.GetUtcNow();
            DateTimeOffset? expiresAt = _hasFileBlobs
                ? now.AddDays(_owner.CurrentPolicy.FileBlobRetentionDays)
                : null;

            var metadataBytes = _deltas.Sum(d => (long)(d.TargetPath.Length + (d.PreviousStateJson?.Length ?? 0) + 128));
            var totalStoredBytes = _storedBlobBytesDelta + metadataBytes;

            var record = new TransactionRecord(
                SessionId: SessionId,
                Domain: _domain,
                FriendlyTitle: _friendlyTitle,
                FriendlySummary: _friendlySummary,
                TechnicalDetails: _technicalDetails,
                CreatedAtUtc: now,
                BlobExpiresAtUtc: expiresAt,
                IsPinned: pinTransaction,
                IsReverted: false,
                RevertedAtUtc: null,
                TotalStoredBytes: totalStoredBytes,
                Deltas: _deltas.ToList());

            await _repository.SaveTransactionAsync(record, ct).ConfigureAwait(false);
            await _owner.EnforceQuotaAndRetentionAsync(ct).ConfigureAwait(false);

            return record;
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;

        private void EnsureNotCommitted()
        {
            if (_committed)
            {
                throw new InvalidOperationException("Транзакция уже зафиксирована.");
            }
        }
    }
}
