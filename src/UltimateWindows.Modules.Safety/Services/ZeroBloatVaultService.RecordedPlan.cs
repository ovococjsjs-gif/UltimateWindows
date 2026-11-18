using UltimateWindows.Core.Contracts;
using UltimateWindows.Core.Enums;
using UltimateWindows.Core.Models;
using UltimateWindows.Modules.Safety.Storage;

namespace UltimateWindows.Modules.Safety.Services;

public sealed partial class ZeroBloatVaultService
{
    // Не держим глобальный SQLite writer во время ожидания платформы. Другой GUI/CLI
    // может читать историю, но не откатить эту запись или открепить её снимки на полпути.
    private FileStream AcquireSessionLease(Guid id)
    {
        var path = Path.Combine(_vaultDirectory, id.ToString("N") + ".active");
        try { return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.DeleteOnClose); }
        catch (IOException ex) { throw new IOException("Запись занята другой операцией или недоступна для записи.", ex); }
    }

    private sealed partial class SafetyTransactionSession : IRecordedPlan
    {
        private FileStream? _lease;
        private TransactionRecord? _snapshot;
        private bool _retainForReview;
        public TransactionRecord Snapshot => _snapshot ?? throw new InvalidOperationException("Нет активного плана.");

        public async Task<IRecordedPlan> PrepareRecordedPlanAsync(IReadOnlyList<string> labels, CancellationToken ct = default)
        {
            EnsureNotCommitted();
            if (labels.Count == 0 || labels.Count != _deltas.Count || labels.Any(string.IsNullOrWhiteSpace) || _toQuarantine.Count != 0)
                throw new InvalidOperationException("Требуется список именованных шагов и снимки без автоматического удаления.");
            for (int i = 0; i < _deltas.Count; i++) _deltas[i] = _deltas[i] with { Step = new(labels[i], StepState.Planned) };
            _lease = _owner.AcquireSessionLease(SessionId);
            _snapshot = await CommitCoreAsync(pinTransaction: true, verify: true, ct).ConfigureAwait(false);
            return this;
        }

        public async Task<StepExecution> ExecuteAsync(int index, Func<CancellationToken, Task<bool>>? apply, CancellationToken ct = default)
        {
            var delta = Snapshot.Deltas[index];
            if ((delta.TargetKind == StateTargetKind.QuarantinedFile) != (apply is null))
                throw new ArgumentException("Тип действия не совпадает со снимком.", nameof(apply));
            ct.ThrowIfCancellationRequested();
            // Если эта запись не удалась, нативное действие даже не начинается.
            await _repository.AdvanceStepAsync(SessionId, delta.DeltaId, StepState.Planned, StepState.Started, "", ct).ConfigureAwait(false);
            bool applied = false;
            string detail;
            try
            {
                ct.ThrowIfCancellationRequested();
                if (apply is null)
                {
                    using var key = _blobStore.OpenVerifiedKey();
                    _ = await _blobStore.RestoreBytesAsync(delta.BlobSha256!, ct).ConfigureAwait(false);
                    ct.ThrowIfCancellationRequested();
                    applied = CheckedFileDeletion.TryRemove(delta.TargetPath, delta.OriginalSizeBytes, null, delta.BlobSha256);
                    detail = applied ? "" : "файл изменился или исчез";
                }
                else
                {
                    applied = await apply(ct).ConfigureAwait(false);
                    detail = applied ? "" : "платформа не подтвердила изменение";
                }
            }
            catch (OperationCanceledException) { detail = "отмена во время шага; проверьте состояние объекта"; }
            catch (Exception ex) { detail = ex.Message; }

            try
            {
                // Отмена или исключение следующего шага не должны потерять уже полученный ответ.
                await _repository.AdvanceStepAsync(SessionId, delta.DeltaId, StepState.Started,
                    applied ? StepState.Applied : StepState.Unconfirmed, detail, CancellationToken.None).ConfigureAwait(false);
                return new(applied, true, detail);
            }
            catch (Exception ex)
            {
                _retainForReview = true;
                return new(applied, false, $"Итог шага не записан. Снимок закреплён для проверки; не повторяйте действие без проверки объекта. {ex.Message}");
            }
        }

        private async ValueTask CloseRecordedPlanAsync()
        {
            if (_lease is null) return;
            try
            {
                if (_snapshot is not null && !_retainForReview)
                    await _repository.SetPinnedAsync(SessionId, false, CancellationToken.None).ConfigureAwait(false);
            }
            finally { _snapshot = null; _lease.Dispose(); _lease = null; }
        }
    }
}
