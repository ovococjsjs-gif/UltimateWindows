using System.Diagnostics;
using System.IO;
using UltimateWindows.Modules.Optimizer.Models;
using UltimateWindows.Modules.Optimizer.Services;
using UltimateWindows.Modules.Safety.Services;
using UltimateWindows.NativeInterop.Optimizer;
using UltimateWindows.NativeInterop.Restore;
using Xunit;

namespace UltimateWindows.WindowsTests;

/// <summary>
/// Настоящая Windows: твики, службы и задания планировщика меняются и возвращаются через «Машину времени».
/// Проверки меняют систему, поэтому выполняются только на одноразовой сборочной машине,
/// а службу и задание для опытов создают свои.
/// </summary>
[Collection("Windows")]
public sealed class RealSystemRollbackTests : IDisposable
{
    private const string ProbeService = "UwCiProbeService";
    private const string ProbeTaskName = "UwCiProbeTask";
    private const string ProbeTaskPath = @"\" + ProbeTaskName;

    private readonly string _vaultDirectory = Path.Combine(Path.GetTempPath(), $"uw_real_tests_{Guid.NewGuid():N}");
    private readonly WindowsOptimizerPlatformBridge _bridge = new();
    private readonly ZeroBloatVaultService _vault;
    private readonly SmartOptimizerService _service;

    public RealSystemRollbackTests()
    {
        _vault = new ZeroBloatVaultService(_vaultDirectory, new WindowsSystemStateApplier());
        _service = new SmartOptimizerService(_vault, _bridge);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_vaultDirectory, recursive: true);
        }
        catch (Exception)
        {
            // Файл базы отката может быть ещё занят — временный каталог очистит система
        }
    }

    [Fact]
    public void Catalog_IsEvaluatedAgainstTheRealSystem()
    {
        if (!TestEnvironment.IsDisposableBuildMachine)
        {
            return;
        }

        var facts = _service.GetSystemFacts();
        var states = _service.EvaluateAllTweaks();
        var actionCount = states.Sum(s => _service.DescribeTweakActions(s.Rule.TweakId).Count);

        TestEnvironment.WriteReport("real-catalog",
        [
            $"сборка Windows: {facts.WindowsBuildNumber}; SSD: {facts.SystemDriveIsSolidState}; батарея: {facts.HasBattery}; администратор: {_service.IsRunningAsAdministrator}",
            "состояния: " + string.Join(", ", states.GroupBy(s => s.State).OrderBy(g => g.Key).Select(g => $"{g.Key} {g.Count()}")),
            "применимость: " + string.Join(", ", states.GroupBy(s => s.Applicability.Status).OrderBy(g => g.Key).Select(g => $"{g.Key} {g.Count()}")),
            "нет целей в системе: " + string.Join(", ", states.Where(s => s.State == TweakStateKind.Unavailable).Select(s => s.Rule.TweakId).Take(40))
        ]);

        Assert.Equal(_service.GetCatalogRules().Count, states.Count);
        Assert.True(actionCount >= states.Count);
        Assert.NotNull(facts.WindowsBuildNumber);
        Assert.True(states.Count(s => s.State == TweakStateKind.Unavailable) < states.Count / 3, "слишком много твиков без целей в системе");
    }

    [Fact]
    public async Task RecommendedPreset_AppliesAndRollsBack_AsOneRecord()
    {
        if (!TestEnvironment.IsDisposableBuildMachine)
        {
            return;
        }

        var preset = _service.GetPresets().Single(p => p.Key == "recommended");
        var before = ReadStates(preset.TweakIds);

        var result = await _service.ApplyPresetBatchAsync(preset.Key, preset.Title);
        var after = ReadStates(preset.TweakIds);
        Guid? session = result.RollbackSessionId;
        if (session is not null)
        {
            await _vault.RollbackTransactionAsync(session.Value);
        }

        var restored = ReadStates(preset.TweakIds);

        TestEnvironment.WriteReport("real-preset",
        [
            result.UserFriendlyMessage,
            "до: " + Summarize(before) + "; после: " + Summarize(after) + "; после отката: " + Summarize(restored),
            "не применились: " + string.Join(", ", after.Where(p => p.Value is not (TweakStateKind.Applied or TweakStateKind.Unavailable)).Select(p => $"{p.Key}={p.Value}"))
        ]);

        Assert.True(result.Succeeded, result.UserFriendlyMessage);
        Assert.NotNull(session);
        Assert.True(after.Count(p => p.Value == TweakStateKind.Applied) >= preset.TweakIds.Count / 2, "набор применился меньше чем наполовину");
        Assert.DoesNotContain(after, p => p.Value == TweakStateKind.Partial);
        Assert.All(preset.TweakIds, id => Assert.Equal(before[id], restored[id]));
    }

    [Fact]
    public async Task ServiceStartupType_ChangesAndRollsBack()
    {
        if (!TestEnvironment.IsDisposableBuildMachine)
        {
            return;
        }

        var notes = new List<string>();
        RunTool("sc.exe", "delete", ProbeService);
        var created = RunTool(
            "sc.exe", "create", ProbeService,
            "binPath=", Path.Combine(Environment.SystemDirectory, "cmd.exe") + " /c exit 0",
            "start=", "demand");
        Assert.True(created.ExitCode == 0, "sc create: " + created.Output);
        try
        {
            Assert.Equal(ServiceStartupMode.Manual, _bridge.QueryServiceConfig(ProbeService)?.Startup);

            var services = await _service.GetServicesAsync();
            notes.Add($"служб в системе: {services.Count}; сторонних: {services.Count(s => !s.IsMicrosoft)}");
            Assert.Contains(services, s => s.ServiceName == ProbeService && !s.IsMicrosoft);

            var disabled = await _service.SetServiceStartupAsync(ProbeService, ServiceStartupMode.Disabled);
            notes.Add("отключение: " + Describe(disabled));
            Assert.True(disabled.Succeeded, Describe(disabled));
            Assert.Equal(ServiceStartupMode.Disabled, _bridge.QueryServiceConfig(ProbeService)?.Startup);

            var delayed = await _service.SetServiceStartupAsync(ProbeService, ServiceStartupMode.AutomaticDelayed);
            notes.Add("отложенный запуск: " + Describe(delayed));
            Assert.True(delayed.Succeeded, Describe(delayed));
            Assert.Equal(ServiceStartupMode.AutomaticDelayed, _bridge.QueryServiceConfig(ProbeService)?.Startup);

            // Откат идёт от последней записи к первой
            Assert.NotNull(delayed.RollbackSessionId);
            await _vault.RollbackTransactionAsync(delayed.RollbackSessionId.Value);
            Assert.Equal(ServiceStartupMode.Disabled, _bridge.QueryServiceConfig(ProbeService)?.Startup);

            Assert.NotNull(disabled.RollbackSessionId);
            await _vault.RollbackTransactionAsync(disabled.RollbackSessionId.Value);
            Assert.Equal(ServiceStartupMode.Manual, _bridge.QueryServiceConfig(ProbeService)?.Startup);
            notes.Add("откат: тип запуска вернулся к «Вручную»");
        }
        finally
        {
            RunTool("sc.exe", "delete", ProbeService);
            TestEnvironment.WriteReport("real-service", notes);
        }
    }

    [Fact]
    public async Task ScheduledTask_DisablesAndRollsBack()
    {
        if (!TestEnvironment.IsDisposableBuildMachine)
        {
            return;
        }

        var notes = new List<string>();
        var created = RunTool("schtasks.exe", "/Create", "/TN", ProbeTaskName, "/TR", "cmd.exe /c exit 0", "/SC", "ONCE", "/ST", "23:59", "/F");
        Assert.True(created.ExitCode == 0, "schtasks /Create: " + created.Output);
        try
        {
            Assert.True(IsTaskEnabled());

            var tasks = await _service.GetScheduledTasksAsync();
            notes.Add($"заданий в системе: {tasks.Count}; сторонних: {tasks.Count(t => !t.IsMicrosoft)}; отключённых: {tasks.Count(t => !t.Enabled)}");
            Assert.Contains(tasks, t => t.TaskPath == ProbeTaskPath && t.Enabled && !t.IsMicrosoft);

            var disabled = await _service.SetScheduledTaskEnabledAsync(ProbeTaskPath, enabled: false);
            notes.Add("отключение: " + Describe(disabled));
            Assert.True(disabled.Succeeded, Describe(disabled));
            Assert.False(IsTaskEnabled());

            Assert.NotNull(disabled.RollbackSessionId);
            await _vault.RollbackTransactionAsync(disabled.RollbackSessionId.Value);
            Assert.True(IsTaskEnabled());
            notes.Add("откат: задание снова включено");
        }
        finally
        {
            RunTool("schtasks.exe", "/Delete", "/TN", ProbeTaskName, "/F");
            TestEnvironment.WriteReport("real-task", notes);
        }
    }

    private bool? IsTaskEnabled() =>
        _bridge.QueryScheduledTasks([ProbeTaskPath]).TryGetValue(ProbeTaskPath, out var task) ? task.Enabled : null;

    private Dictionary<string, TweakStateKind> ReadStates(IEnumerable<string> tweakIds) =>
        tweakIds.ToDictionary(id => id, id => _service.EvaluateTweak(id)!.State);

    private static string Summarize(Dictionary<string, TweakStateKind> states) =>
        string.Join(", ", states.Values.GroupBy(s => s).OrderBy(g => g.Key).Select(g => $"{g.Key} {g.Count()}"));

    private static string Describe(OptimizerOperationResult result) =>
        $"{(result.Succeeded ? "успех" : "неудача")}: {result.UserFriendlyMessage} {result.TechnicalDetails}".Trim();

    private static (int ExitCode, string Output) RunTool(string fileName, params string[] arguments)
    {
        var startInfo = new ProcessStartInfo(fileName)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo)!;
        var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        process.WaitForExit(30_000);
        return (process.ExitCode, output.Trim());
    }
}
