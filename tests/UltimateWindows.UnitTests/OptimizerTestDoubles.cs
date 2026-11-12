using UltimateWindows.Core.Contracts;
using UltimateWindows.Core.Enums;
using UltimateWindows.Core.Models;
using UltimateWindows.Modules.Optimizer.Models;
using UltimateWindows.Modules.Optimizer.Services;

namespace UltimateWindows.UnitTests;

/// <summary>
/// Мост Оптимизатора, который держит «систему» в памяти: значения реестра, службы и задания планировщика.
/// Умеет изображать отказ в доступе и значение, которое Windows молча не сохраняет.
/// </summary>
internal sealed class FakeOptimizerBridge : DefaultOptimizerPlatformBridge
{
    public string? CustomHostsPath { get; set; }
    public SystemFacts Facts { get; set; } = SystemFacts.Unknown;
    public bool IsAdministrator { get; set; } = true;

    /// <summary>Значения реестра: ключ «КУСТ\раздел::имя».</summary>
    public Dictionary<string, (int Kind, string Val)> Store { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Разделы реестра, существующие сами по себе (без значений).</summary>
    public HashSet<string> Keys { get; } = new(StringComparer.OrdinalIgnoreCase);

    public Dictionary<string, ServiceStartupMode> Services { get; } = new(StringComparer.OrdinalIgnoreCase);

    public Dictionary<string, bool> Tasks { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Цели, изменение которых заканчивается отказом в доступе (имя службы, путь задания или «КУСТ\раздел::имя»).</summary>
    public HashSet<string> AccessDenied { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Цели, которые «принимают» изменение, но остаются прежними — как значения, защищённые системой.</summary>
    public HashSet<string> SilentlyIgnored { get; } = new(StringComparer.OrdinalIgnoreCase);

    public List<string> StoppedServices { get; } = [];

    public int TaskSchedulerConnections { get; private set; }

    public override SystemFacts GetSystemFacts() => Facts;

    public override string GetHostsFilePath() => CustomHostsPath ?? base.GetHostsFilePath();

    public override bool IsRunningAsAdministrator() => IsAdministrator;

    private static string ValueKey(string hive, string subKeyPath, string valueName) => $@"{hive}\{subKeyPath}::{valueName}";

    public override (bool Exists, int ValueKindCode, string? SerializedValue) ReadRegistryValue(
        string hive,
        string subKeyPath,
        string valueName)
    {
        return Store.TryGetValue(ValueKey(hive, subKeyPath, valueName), out var item)
            ? (true, item.Kind, item.Val)
            : (false, 1, null);
    }

    public override bool WriteRegistryValue(
        string hive,
        string subKeyPath,
        string valueName,
        RegistryTweakValueKind kind,
        string serializedValue)
    {
        var key = ValueKey(hive, subKeyPath, valueName);
        if (AccessDenied.Contains(key))
        {
            return false;
        }

        if (SilentlyIgnored.Contains(key))
        {
            return true;
        }

        if (kind == RegistryTweakValueKind.DeleteValue)
        {
            Store.Remove(key);
            return true;
        }

        // Запись значения создаёт раздел и всех его родителей
        var path = subKeyPath;
        while (path.Length > 0)
        {
            Keys.Add($@"{hive}\{path}");
            var separator = path.LastIndexOf('\\');
            path = separator < 0 ? "" : path[..separator];
        }

        Store[key] = ((int)kind, serializedValue);
        return true;
    }

    public override bool RegistryKeyExists(string hive, string subKeyPath) => Keys.Contains($@"{hive}\{subKeyPath}");

    public override string? FindFirstMissingRegistryKey(string hive, string subKeyPath)
    {
        var parts = subKeyPath.Split('\\');
        for (var i = 1; i <= parts.Length; i++)
        {
            var path = string.Join('\\', parts.Take(i));
            if (!Keys.Contains($@"{hive}\{path}"))
            {
                return path;
            }
        }

        return null;
    }

    public override bool DeleteRegistryKeyIfEmpty(string hive, string subKeyPath)
    {
        var full = $@"{hive}\{subKeyPath}";
        if (!Keys.Contains(full))
        {
            return false;
        }

        var hasValues = Store.Keys.Any(k => k.StartsWith(full + "::", StringComparison.OrdinalIgnoreCase));
        var hasSubKeys = Keys.Any(k => k.StartsWith(full + @"\", StringComparison.OrdinalIgnoreCase));
        if (hasValues || hasSubKeys)
        {
            return false;
        }

        Keys.Remove(full);
        return true;
    }

    public override ServiceConfigSnapshot? QueryServiceConfig(string serviceName) =>
        Services.TryGetValue(serviceName, out var startup) ? new ServiceConfigSnapshot(serviceName, startup) : null;

    public override PlatformActionResult SetServiceStartup(string serviceName, ServiceStartupMode mode)
    {
        if (!Services.ContainsKey(serviceName))
        {
            return PlatformActionResult.Fail("служба не установлена");
        }

        if (AccessDenied.Contains(serviceName))
        {
            return PlatformActionResult.Fail("отказано в доступе");
        }

        if (!SilentlyIgnored.Contains(serviceName))
        {
            Services[serviceName] = mode;
        }

        return PlatformActionResult.Ok;
    }

    public override Task<PlatformActionResult> ControlServiceAsync(string serviceName, bool start, CancellationToken ct = default)
    {
        if (!start)
        {
            lock (StoppedServices)
            {
                StoppedServices.Add(serviceName);
            }
        }

        return Task.FromResult(PlatformActionResult.Ok);
    }

    public override IReadOnlyDictionary<string, ScheduledTaskSnapshot> QueryScheduledTasks(IReadOnlyCollection<string> taskPaths)
    {
        TaskSchedulerConnections++;
        var found = new Dictionary<string, ScheduledTaskSnapshot>(StringComparer.OrdinalIgnoreCase);
        foreach (var path in taskPaths)
        {
            if (Tasks.TryGetValue(path, out var enabled))
            {
                found[path] = new ScheduledTaskSnapshot(path, enabled);
            }
        }

        return found;
    }

    public override PlatformActionResult SetScheduledTaskEnabled(string taskPath, bool enabled)
    {
        if (!Tasks.ContainsKey(taskPath))
        {
            return PlatformActionResult.Fail("задание не найдено");
        }

        if (AccessDenied.Contains(taskPath))
        {
            return PlatformActionResult.Fail("отказано в доступе");
        }

        if (!SilentlyIgnored.Contains(taskPath))
        {
            Tasks[taskPath] = enabled;
        }

        return PlatformActionResult.Ok;
    }

    public override Task<bool> TryPoliteCloseProcessAsync(int processId, CancellationToken ct = default) =>
        Task.FromResult(processId == 4512);
}

/// <summary>
/// «Машина времени» в памяти: хранит записи и умеет отдать их на проверку. Файлы и базу данных не трогает.
/// </summary>
internal sealed class InMemoryVault : IVaultService
{
    private readonly List<TransactionRecord> _records = [];

    public IReadOnlyList<TransactionRecord> Records => _records;

    /// <summary>Если задано, фиксация записи заканчивается этой ошибкой.</summary>
    public Exception? FailCommitWith { get; set; }

    public VaultQuotaPolicy CurrentPolicy { get; private set; } = new();

    public ITransactionSession BeginTransaction(
        SystemDomain domain,
        string friendlyTitle,
        string friendlySummary,
        string technicalDetails = "") =>
        new Session(this, domain, friendlyTitle, friendlySummary, technicalDetails);

    public Task<IReadOnlyList<TransactionRecord>> GetHistoryAsync(int limit = 100, CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<TransactionRecord>>(_records.AsEnumerable().Reverse().Take(limit).ToList());

    public Task<VaultStorageStats> GetStorageStatsAsync(CancellationToken ct = default) =>
        Task.FromResult(new VaultStorageStats(0, 0, CurrentPolicy.MaxVaultBytes, 0, _records.Count, 0));

    public Task RollbackTransactionAsync(Guid sessionId, CancellationToken ct = default) => Task.CompletedTask;

    public Task SetPinnedAsync(Guid sessionId, bool isPinned, CancellationToken ct = default) => Task.CompletedTask;

    public Task<int> EnforceQuotaAndRetentionAsync(CancellationToken ct = default) => Task.FromResult(0);

    public Task<int> PurgeAllUnpinnedBlobsAsync(CancellationToken ct = default) => Task.FromResult(0);

    public Task UpdatePolicyAsync(VaultQuotaPolicy newPolicy, CancellationToken ct = default)
    {
        CurrentPolicy = newPolicy;
        return Task.CompletedTask;
    }

    private sealed class Session : ITransactionSession
    {
        private readonly InMemoryVault _owner;
        private readonly SystemDomain _domain;
        private readonly string _title;
        private readonly string _summary;
        private readonly string _details;
        private readonly List<StateDeltaRecord> _deltas = [];

        public Session(InMemoryVault owner, SystemDomain domain, string title, string summary, string details)
        {
            _owner = owner;
            _domain = domain;
            _title = title;
            _summary = summary;
            _details = details;
        }

        public Guid SessionId { get; } = Guid.NewGuid();

        public void RecordStateDelta(StateTargetKind targetKind, string targetPath, string? previousStateJson, string? newStateJson) =>
            _deltas.Add(new StateDeltaRecord(Guid.NewGuid(), SessionId, _deltas.Count, targetKind, targetPath, previousStateJson, newStateJson, null, 0));

        public Task<string> QuarantineFileAsync(string sourceFilePath, CancellationToken ct = default) =>
            throw new NotSupportedException("Хранилище в памяти не помещает файлы в карантин.");

        public void RecordDriverStoreReference(string deviceInstanceId, string publishedInfName, string driverVersion) =>
            throw new NotSupportedException("Хранилище в памяти не ведёт ссылки на драйверы.");

        public Task<TransactionRecord> CommitAsync(bool pinTransaction = false, CancellationToken ct = default)
        {
            if (_owner.FailCommitWith is { } failure)
            {
                throw failure;
            }

            var record = new TransactionRecord(
                SessionId,
                _domain,
                _title,
                _summary,
                _details,
                DateTimeOffset.UtcNow,
                BlobExpiresAtUtc: null,
                IsPinned: pinTransaction,
                IsReverted: false,
                RevertedAtUtc: null,
                TotalStoredBytes: 0,
                Deltas: _deltas.ToList());

            _owner._records.Add(record);
            return Task.FromResult(record);
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
