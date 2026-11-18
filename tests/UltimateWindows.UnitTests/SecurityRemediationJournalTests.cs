using Microsoft.Data.Sqlite;
using UltimateWindows.Core.Enums;
using UltimateWindows.Core.Models;
using UltimateWindows.Modules.Safety.Services;
using UltimateWindows.Modules.Security.Models;
using UltimateWindows.Modules.Security.Services;
using Xunit;

namespace UltimateWindows.UnitTests;

// Только обычный временный файл и настройки в памяти. PID не соответствует системному вызову.
public sealed class SecurityRemediationJournalTests : IDisposable
{
    private readonly DirectoryInfo _dir = Directory.CreateTempSubdirectory("uw-journal-");
    private string Root => Path.Combine(_dir.FullName, "vault");
    private string Source => Path.Combine(_dir.FullName, "fixture.txt");
    private readonly FixtureBridge _bridge = new();
    private readonly ZeroBloatVaultService _vault;
    private readonly AntiMinerSecurityService _svc;

    public SecurityRemediationJournalTests()
    {
        File.WriteAllText(Source, "before");
        _vault = new ZeroBloatVaultService(Root, new FixtureApplier(_bridge));
        _svc = new(_vault, _bridge);
    }

    private SecurityThreatFinding Finding() => new("fixture", ThreatDetectionVector.SuspiciousRegistryAutorun, RiskLevel.Attention, 50,
        12345, Source, new(ThreatDetectionVector.SuspiciousRegistryAutorun, "fixture", "Setting", "test", Source, false, "before",
            RemediationKind: PersistenceRemediationKind.DeleteRegistryValue), "Проверка журнала", "Тест", "", true);

    [Fact]
    public async Task QuotaFailureBeforeFirstMutationLeavesProcessSettingAndFileAlone()
    {
        await _vault.UpdatePolicyAsync(_vault.CurrentPolicy with { MaxVaultBytes = 4096 });
        var result = await _svc.QuarantineThreatAsync(Finding());
        Assert.False(result.Succeeded); Assert.Equal(0, result.FixedItemsCount); Assert.Null(result.RollbackSessionId);
        Assert.Equal(0, _bridge.Stops); Assert.Equal("before", _bridge.Setting); Assert.Equal("before", File.ReadAllText(Source));
        Assert.True(Assert.Single(await _vault.GetHistoryAsync()).IsJournalOnly);
    }

    [Fact]
    public async Task FileChangedAfterSettingRemoval_RestoresOnlyConfirmedSettingEvenAfterPurgeAndReopen()
    {
        _bridge.AfterSetting = () => File.WriteAllText(Source, "newer!");
        var result = await _svc.QuarantineThreatAsync(Finding());
        Assert.False(result.Succeeded); Assert.Equal(2, result.FixedItemsCount);
        Assert.Equal(new[] {false, true, false}, result.Steps.Select(s => s.CanRollback));
        var id = Assert.IsType<Guid>(result.RollbackSessionId);
        await _vault.PurgeAllUnpinnedBlobsAsync();
        var reopened = new ZeroBloatVaultService(Root, new FixtureApplier(_bridge));
        var record = Assert.Single(await reopened.GetHistoryAsync());
        Assert.Equal(id, record.SessionId); Assert.False(record.IsPinned);
        Assert.Equal(new[] {StepState.Applied, StepState.Applied, StepState.Unconfirmed}, record.Deltas.Select(d => d.Step!.State));
        Assert.Equal(StateTargetKind.RegistryValue, Assert.Single(record.RestorableDeltas).TargetKind);
        Assert.Null(record.RollbackUnavailableReason);
        Assert.Empty(Assert.Single(await _svc.GetQuarantineHistoryAsync()).QuarantinedPaths);
        await reopened.RollbackTransactionAsync(id);
        Assert.Equal("before", _bridge.Setting); Assert.Equal("newer!", File.ReadAllText(Source)); Assert.Equal(1, _bridge.Stops);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NoRollbackForProcessAndUnconfirmedSetting(bool throwsAfterMutation)
    {
        _bridge.Deny = !throwsAfterMutation;
        if (throwsAfterMutation) _bridge.AfterSetting = () => throw new IOException("fixture: reply lost");
        var r = await _svc.QuarantineThreatAsync(Finding());
        Assert.False(r.Succeeded); Assert.Equal(1, r.FixedItemsCount); Assert.Null(r.RollbackSessionId);
        var id = Assert.IsType<Guid>(r.JournalSessionId);
        Assert.False((await _svc.RestoreFromQuarantineAsync(id)).Succeeded);
        var saved = Assert.Single(await _vault.GetHistoryAsync());
        Assert.Equal(new[] {StepState.Applied, StepState.Unconfirmed, StepState.Planned}, saved.Deltas.Select(d => d.Step!.State));
        Assert.False(saved.IsReverted); Assert.Equal("before", saved.Deltas[1].PreviousStateJson);
        Assert.Equal(throwsAfterMutation ? null : "before", _bridge.Setting); Assert.Equal("before", File.ReadAllText(Source));
    }

    [Fact]
    public async Task CancellationAfterPlatformSuccessPersistsReceiptAndDoesNotStartNextStep()
    {
        using var cts = new CancellationTokenSource();
        _bridge.AfterSetting = cts.Cancel;
        var r = await _svc.QuarantineThreatAsync(Finding(), cts.Token);
        Assert.True(r.WasCancelled); Assert.False(r.Succeeded); Assert.Equal(2, r.FixedItemsCount);
        Assert.Equal(StepState.Planned, r.Steps[2].State); Assert.True(File.Exists(Source));
        var undo = await _svc.RestoreFromQuarantineAsync(Assert.IsType<Guid>(r.RollbackSessionId));
        Assert.True(undo.Succeeded); Assert.Equal(1, undo.FixedItemsCount); Assert.Equal("before", _bridge.Setting);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task JournalWriteFailureDoesNotStartOrRepeatUnrecordedAction(bool afterPlatformSuccess)
    {
        // Отказываем только в записи выбранного перехода; файл БД остаётся пригодным для чтения после перезапуска.
        using (var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = Path.Combine(Root, "vault.db"), Pooling = false }.ToString()))
        {
            db.Open(); using var cmd = db.CreateCommand();
            cmd.CommandText = $"CREATE TRIGGER fixture_fail BEFORE UPDATE ON step_receipts WHEN NEW.label = 'Setting' AND NEW.state = {(int)(afterPlatformSuccess ? StepState.Applied : StepState.Started)} BEGIN SELECT RAISE(ABORT,'fixture write failure'); END";
            cmd.ExecuteNonQuery();
        }
        var r = await _svc.QuarantineThreatAsync(Finding());
        Assert.False(r.Succeeded); Assert.Equal(afterPlatformSuccess ? 2 : 1, r.FixedItemsCount); Assert.Null(r.RollbackSessionId);
        var saved = Assert.Single(await new ZeroBloatVaultService(Root).GetHistoryAsync());
        Assert.Equal(afterPlatformSuccess ? StepState.Started : StepState.Planned, saved.Deltas[1].Step!.State);
        Assert.Equal(afterPlatformSuccess ? null : "before", _bridge.Setting); Assert.Empty(saved.RestorableDeltas);
        Assert.Equal(1, _bridge.Stops); Assert.True(File.Exists(Source));
    }

    [Fact]
    public async Task SecondInstanceCannotUndoOrUnpinLiveOperation()
    {
        var other = new ZeroBloatVaultService(Root);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var finish = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        _bridge.Stop = () => { entered.SetResult(); return finish.Task; };
        var running = _svc.QuarantineThreatAsync(Finding());
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var id = Assert.Single(await other.GetHistoryAsync()).SessionId;
            await Assert.ThrowsAsync<IOException>(() => other.RollbackTransactionAsync(id));
            await Assert.ThrowsAsync<IOException>(() => other.SetPinnedAsync(id, false));
            Assert.Equal(0, await other.PurgeAllUnpinnedBlobsAsync());
        }
        finally { finish.TrySetResult(true); }
        Assert.True((await running).Succeeded);
    }

    private sealed class FixtureBridge : DefaultSecurityPlatformBridge
    {
        public int Stops;
        public string? Setting = "before";
        public bool Deny;
        public Action? AfterSetting;
        public Func<Task<bool>>? Stop;
        public override Task<bool> TerminateSuspectProcessAsync(int processId, string? reviewedPath, CancellationToken ct = default)
        { Stops++; return Stop?.Invoke() ?? Task.FromResult(true); }
        public override PreparedSecurityChange PreparePersistence(PersistenceAnomalyRecord p) => new("Setting", StateTargetKind.RegistryValue, "fixture", Setting, _ =>
        {
            if (Deny) return Task.FromResult(false);
            Setting = null; AfterSetting?.Invoke(); return Task.FromResult(true);
        });
    }

    private sealed class FixtureApplier(FixtureBridge bridge) : DefaultFileStateApplier
    {
        public override Task ApplyRollbackDeltaAsync(StateDeltaRecord d, Func<string, CancellationToken, Task<byte[]>> restore, CancellationToken ct = default)
        {
            if (d.TargetKind == StateTargetKind.RegistryValue && d.TargetPath == "fixture") { bridge.Setting = d.PreviousStateJson; return Task.CompletedTask; }
            return base.ApplyRollbackDeltaAsync(d, restore, ct);
        }
    }
    public void Dispose() => _dir.Delete(true);
}
