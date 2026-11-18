using System.Security.Cryptography;
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

            // Повтор после частичного отката безопасен; новый файл по старому пути не заменяем.
            if (File.Exists(delta.TargetPath))
            {
                await using var current = File.OpenRead(delta.TargetPath);
                var hash = await SHA256.HashDataAsync(current, ct).ConfigureAwait(false);
                if (Convert.ToHexString(hash).Equals(delta.BlobSha256, StringComparison.OrdinalIgnoreCase)) return;
                throw new IOException($"По пути «{delta.TargetPath}» уже находится другой файл. Переместите его перед повторным восстановлением.");
            }

            var temp = Path.Combine(parentDir!, $".uw-restore-{Guid.NewGuid():N}.tmp");
            try
            {
                await File.WriteAllBytesAsync(temp, bytes, ct).ConfigureAwait(false);
                File.Move(temp, delta.TargetPath, overwrite: false);
            }
            finally
            {
                File.Delete(temp);
            }
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

        if (record.RollbackUnavailableReason is { } reason)
            throw new InvalidOperationException($"Откат недоступен: {reason}.");

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

        var removedBlobs = await CollectPendingDeletesAsync(ct).ConfigureAwait(false);
        var processedHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Шаг 1: Очистка блобов с истекшим TTL
        foreach (var item in candidates)
        {
            if (item.ExpiresAtUtc.HasValue && item.ExpiresAtUtc.Value <= now)
            {
                if (processedHashes.Add(item.BlobSha256))
                {
                    if (await TryEvictBlobAsync(item.BlobSha256, ct, now).ConfigureAwait(false))
                    {
                        removedBlobs++;
                    }
                }
            }
        }

        // Шаг 2: файл с несколькими ссылками вытесняется по возрасту новейшей из них.
        foreach (var group in candidates.GroupBy(c => c.BlobSha256).OrderBy(g => g.Max(c => c.CreatedAtUtc)))
        {
            var currentTotal = _repository.GetDatabaseSizeBytes() + _blobStore.ComputeTotalBlobBytesOnDisk();
            if (currentTotal <= effectiveLimit)
            {
                break;
            }

            if (await TryEvictBlobAsync(group.Key, ct, quotaOnly: true).ConfigureAwait(false)) removedBlobs++;
        }

        return removedBlobs;
    }

    /// <summary>
    /// Ручная кнопка пользователя «Очистить файловый кэш бэкапов» (сохраняет микро-записи отката реестра и закрепленные точки).
    /// </summary>
    public async Task<int> PurgeAllUnpinnedBlobsAsync(CancellationToken ct = default)
    {
        var candidates = await _repository.GetUnpinnedBlobReferencesOldestFirstAsync(ct).ConfigureAwait(false);
        var removed = await CollectPendingDeletesAsync(ct).ConfigureAwait(false);
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

    private async Task<int> CollectPendingDeletesAsync(CancellationToken ct)
    {
        int count = 0;
        foreach (var hash in await _repository.GetPendingDeletesAsync(ct).ConfigureAwait(false))
            if (await _repository.CollectReleasedBlobAsync(hash, _blobStore.DeleteBlobIfPresent, ct).ConfigureAwait(false)) count++;
        return count;
    }

    private async Task<bool> TryEvictBlobAsync(string hash, CancellationToken ct, DateTimeOffset? expiredAt = null, bool quotaOnly = false)
    {
        await _repository.ReleaseBlobReferencesAsync(hash, expiredAt, quotaOnly, ct).ConfigureAwait(false);
        return await _repository.CollectReleasedBlobAsync(hash, _blobStore.DeleteBlobIfPresent, ct).ConfigureAwait(false);
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
        private readonly Dictionary<string, PreparedBlob> _prepared = new(StringComparer.OrdinalIgnoreCase);
        private readonly List<StateDeltaRecord> _toQuarantine = [];
        private bool _finished;

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

        public Task<string> QuarantineFileAsync(string sourceFilePath, CancellationToken ct = default) =>
            CaptureFileAsync(sourceFilePath, removeSource: true, ct);

        public Task<string> BackupFileAsync(string sourceFilePath, CancellationToken ct = default) =>
            CaptureFileAsync(sourceFilePath, removeSource: false, ct);

        private async Task<string> CaptureFileAsync(string sourceFilePath, bool removeSource, CancellationToken ct)
        {
            EnsureNotCommitted();
            ArgumentException.ThrowIfNullOrWhiteSpace(sourceFilePath);

            var fullPath = Path.GetFullPath(sourceFilePath);
            BrowserVaultGuard.ThrowIfProtected(fullPath);
            var vaultPrefix = Path.TrimEndingDirectorySeparator(Path.GetFullPath(_owner.VaultDirectory)) + Path.DirectorySeparatorChar;
            if (fullPath.StartsWith(vaultPrefix, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Файлы самого хранилища нельзя помещать в карантин.");
            for (var entry = fullPath; entry is not null; entry = Path.GetDirectoryName(entry))
                if (File.GetAttributes(entry).HasFlag(FileAttributes.ReparsePoint))
                    throw new IOException("Снимок по пути через ссылку или точку подключения запрещён.");

            var stored = await _blobStore.PrepareFileAsync(fullPath, ct).ConfigureAwait(false);
            if (!_prepared.TryAdd(stored.Sha256Hex, stored)) stored.Dispose();
            var delta = new StateDeltaRecord(
                DeltaId: Guid.NewGuid(),
                SessionId: SessionId,
                SequenceOrder: _deltas.Count,
                TargetKind: StateTargetKind.QuarantinedFile,
                TargetPath: fullPath,
                PreviousStateJson: JsonSerializer.Serialize(new { Exists = true, Sha256 = stored.Sha256Hex }),
                NewStateJson: removeSource ? JsonSerializer.Serialize(new { QuarantineRequested = true }) : null,
                BlobSha256: stored.Sha256Hex,
                OriginalSizeBytes: stored.OriginalSizeBytes);
            _deltas.Add(delta);
            if (removeSource) _toQuarantine.Add(delta);
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

        public Task<TransactionRecord> CommitAsync(bool pinTransaction = false, CancellationToken ct = default) =>
            CommitCoreAsync(pinTransaction, verify: _toQuarantine.Count != 0, ct);

        public Task<TransactionRecord> CommitVerifiedBackupAsync(CancellationToken ct = default) =>
            CommitCoreAsync(pinTransaction: true, verify: true, ct);

        private async Task<TransactionRecord> CommitCoreAsync(bool pinTransaction, bool verify, CancellationToken ct)
        {
            EnsureNotCommitted();
            _finished = true;
            var now = _timeProvider.GetUtcNow();
            var record = new TransactionRecord(
                SessionId, _domain, _friendlyTitle, _friendlySummary, _technicalDetails, now,
                BlobExpiresAtUtc: _prepared.Count != 0 ? now.AddDays(_owner.CurrentPolicy.FileBlobRetentionDays) : null,
                IsPinned: pinTransaction && !verify, IsReverted: false, RevertedAtUtc: null,
                TotalStoredBytes: _deltas.Sum(d => 128L + d.TargetPath.Length + (d.PreviousStateJson?.Length ?? 0) + (d.NewStateJson?.Length ?? 0)),
                Deltas: _deltas.ToArray());
            try
            {
                record = await _repository.SaveTransactionAsync(record, () => _prepared.Values.Select(_blobStore.Publish)
                    .Where(blob => !blob.WasDeduplicated).Sum(blob => blob.CompressedEncryptedBytes), ct).ConfigureAwait(false);
            }
            finally { DiscardPrepared(); }
            await _owner.EnforceQuotaAndRetentionAsync(ct).ConfigureAwait(false);
            if (!verify)
                return record.BlobExpiresAtUtc is null ? record :
                    await _repository.GetTransactionByIdAsync(SessionId, ct).ConfigureAwait(false) ?? throw new IOException("Запись не найдена после сохранения.");

            await _repository.UseRetainedSnapshotAsync(SessionId, pinTransaction, async () =>
            {
                // Бюджет физического хранилища, а не сумма исторических оценок для отдельных записей.
                var limit = _owner.CurrentPolicy.ComputeEffectiveLimitBytes(_owner._freeSpaceBytesProvider());
                if (_repository.GetDatabaseSizeBytes() + _blobStore.ComputeTotalBlobBytesOnDisk() > limit)
                    throw new IOException("Квота исчерпана. Исходные файлы не удалены.");
                foreach (var hash in record.Deltas.Select(d => d.BlobSha256).OfType<string>().Distinct())
                    _ = await _blobStore.RestoreBytesAsync(hash, ct).ConfigureAwait(false);
                foreach (var file in _toQuarantine)
                {
                    ct.ThrowIfCancellationRequested();
                    if (!CheckedFileDeletion.TryRemove(file.TargetPath, file.OriginalSizeBytes, null, file.BlobSha256))
                        throw new IOException($"«{file.TargetPath}» изменился или исчез. Этот файл не удалён. Снимок: {SessionId}.");
                }
            }, ct).ConfigureAwait(false);
            return record with { IsPinned = pinTransaction };
        }

        private void DiscardPrepared()
        {
            foreach (var blob in _prepared.Values) blob.Dispose();
            _prepared.Clear();
        }

        public ValueTask DisposeAsync()
        {
            _finished = true;
            DiscardPrepared();
            return ValueTask.CompletedTask;
        }

        private void EnsureNotCommitted()
        {
            if (_finished)
            {
                throw new InvalidOperationException("Транзакция уже завершена.");
            }
        }
    }
}
