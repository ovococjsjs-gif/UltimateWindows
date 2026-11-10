using UltimateWindows.Core.Enums;
using UltimateWindows.Core.Models;

namespace UltimateWindows.Core.Contracts;

/// <summary>
/// Активная транзакция изменения состояния системы.
/// </summary>
public interface ITransactionSession : IAsyncDisposable
{
    Guid SessionId { get; }

    /// <summary>
    /// Записывает микро-снимок изменения реестра, службы или системной настройки (1-8 КБ).
    /// </summary>
    void RecordStateDelta(
        StateTargetKind targetKind,
        string targetPath,
        string? previousStateJson,
        string? newStateJson);

    /// <summary>
    /// Помещает файл в сжатое дедуплицированное шифрованное хранилище карантина (.uwq)
    /// с автоматическим контролем не засоряющей систему квоты.
    /// </summary>
    Task<string> QuarantineFileAsync(string sourceFilePath, CancellationToken ct = default);

    /// <summary>
    /// Фиксирует ссылку на пакет драйвера в системном DriverStore без лишнего копирования сотен мегабайт.
    /// </summary>
    void RecordDriverStoreReference(string deviceInstanceId, string publishedInfName, string driverVersion);

    /// <summary>
    /// Фиксирует транзакцию в журнале «Машины времени».
    /// </summary>
    Task<TransactionRecord> CommitAsync(bool pinTransaction = false, CancellationToken ct = default);
}

/// <summary>
/// Главный сервис управления хранилищем откатов и квотами (Zero-Bloat Vault).
/// </summary>
public interface IVaultService
{
    VaultQuotaPolicy CurrentPolicy { get; }

    ITransactionSession BeginTransaction(
        SystemDomain domain,
        string friendlyTitle,
        string friendlySummary,
        string technicalDetails = "");

    Task<IReadOnlyList<TransactionRecord>> GetHistoryAsync(int limit = 100, CancellationToken ct = default);

    Task<VaultStorageStats> GetStorageStatsAsync(CancellationToken ct = default);

    Task RollbackTransactionAsync(Guid sessionId, CancellationToken ct = default);

    Task SetPinnedAsync(Guid sessionId, bool isPinned, CancellationToken ct = default);

    Task<int> EnforceQuotaAndRetentionAsync(CancellationToken ct = default);

    Task<int> PurgeAllUnpinnedBlobsAsync(CancellationToken ct = default);

    Task UpdatePolicyAsync(VaultQuotaPolicy newPolicy, CancellationToken ct = default);
}

/// <summary>
/// Платформенный исполнитель возврата предыдущего состояния объекта при откате транзакции.
/// </summary>
public interface ISystemStateApplier
{
    Task ApplyRollbackDeltaAsync(
        StateDeltaRecord delta,
        Func<string, CancellationToken, Task<byte[]>> restoreBlobBytesAsync,
        CancellationToken ct = default);
}

/// <summary>
/// Координатор создания системных точек восстановления Windows VSS с защитой от спама.
/// </summary>
public interface IRestorePointProvider
{
    Task<bool> TryCreateRestorePointIfNeededAsync(string description, bool forceMajorOperation = false, CancellationToken ct = default);
}
