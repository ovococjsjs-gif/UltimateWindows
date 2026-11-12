using UltimateWindows.Modules.Optimizer.Models;

namespace UltimateWindows.Modules.Optimizer.Contracts;

/// <summary>
/// Платформенный мост Оптимизатора: реестр, службы и задания планировщика для твиков,
/// автозагрузка (StartupApproved), обработчики контекстного меню (Shell Extensions\Blocked),
/// поиск процессов, держащих файл (Restart Manager), DNS, файл hosts, приложения Windows и удаление программ.
/// </summary>
public interface IOptimizerPlatformBridge
{
    bool IsRunningAsAdministrator();

    /// <summary>
    /// Сведения о компьютере для проверки применимости твиков: сборка Windows, тип системного диска, наличие батареи.
    /// Факт, который не удалось выяснить, возвращается как null.
    /// </summary>
    SystemFacts GetSystemFacts();

    (bool Exists, int ValueKindCode, string? SerializedValue) ReadRegistryValue(
        string hive,
        string subKeyPath,
        string valueName);

    bool WriteRegistryValue(
        string hive,
        string subKeyPath,
        string valueName,
        RegistryTweakValueKind kind,
        string serializedValue);

    bool RegistryKeyExists(string hive, string subKeyPath);

    /// <summary>
    /// Самый верхний из ещё не существующих разделов на пути к <paramref name="subKeyPath"/>,
    /// либо null, если раздел уже есть. Нужен, чтобы откат удалил ровно те разделы, которые создал твик.
    /// </summary>
    string? FindFirstMissingRegistryKey(string hive, string subKeyPath);

    /// <summary>
    /// Удаляет раздел, только если в нём нет ни значений, ни подразделов. Возвращает true, если раздел удалён.
    /// </summary>
    bool DeleteRegistryKeyIfEmpty(string hive, string subKeyPath);

    // ---------------------------------------------------------------------------------------------
    // Службы Windows
    // ---------------------------------------------------------------------------------------------

    /// <summary>Тип запуска службы, либо null, если такой службы в системе нет.</summary>
    ServiceConfigSnapshot? QueryServiceConfig(string serviceName);

    PlatformActionResult SetServiceStartup(string serviceName, ServiceStartupMode mode);

    /// <summary>Запускает или останавливает службу и ждёт результата.</summary>
    Task<PlatformActionResult> ControlServiceAsync(string serviceName, bool start, CancellationToken ct = default);

    Task<IReadOnlyList<WindowsServiceInfo>> GetServicesAsync(CancellationToken ct = default);

    // ---------------------------------------------------------------------------------------------
    // Планировщик заданий
    // ---------------------------------------------------------------------------------------------

    /// <summary>
    /// Состояние заданий по их полным путям. Заданий, которых в системе нет, в ответе тоже нет.
    /// Один вызов — одно подключение к планировщику, поэтому пути передаются разом.
    /// </summary>
    IReadOnlyDictionary<string, ScheduledTaskSnapshot> QueryScheduledTasks(IReadOnlyCollection<string> taskPaths);

    PlatformActionResult SetScheduledTaskEnabled(string taskPath, bool enabled);

    Task<IReadOnlyList<ScheduledTaskInfo>> GetScheduledTasksAsync(CancellationToken ct = default);

    Task<IReadOnlyList<StartupEntryInfo>> GetStartupEntriesAsync(CancellationToken ct = default);

    Task<(bool Succeeded, string PreviousStartupApprovedBase64)> SetStartupEntryEnabledAsync(
        StartupEntryInfo entry,
        bool enabled,
        CancellationToken ct = default);

    Task<IReadOnlyList<ShellContextMenuHandlerInfo>> GetThirdPartyShellExtensionsAsync(CancellationToken ct = default);

    Task<bool> SetShellExtensionBlockedAsync(
        string clsid,
        string handlerName,
        bool blocked,
        CancellationToken ct = default);

    Task<IReadOnlyList<LockingProcessInfo>> FindLockingProcessesAsync(
        string fileOrDirectoryPath,
        CancellationToken ct = default);

    Task<bool> TryPoliteCloseProcessAsync(int processId, CancellationToken ct = default);

    Task<(bool Succeeded, string AdapterName, string PreviousDnsStateJson)> ApplyDnsPresetAsync(
        DnsPresetDescriptor preset,
        CancellationToken ct = default);

    Task<bool> FlushDnsCacheAsync(CancellationToken ct = default);

    string GetHostsFilePath();

    Task<IReadOnlyList<InstalledApplicationInfo>> GetInstalledApplicationsAsync(CancellationToken ct = default);

    Task<bool> LaunchApplicationUninstallerAsync(InstalledApplicationInfo app, CancellationToken ct = default);

    Task<IReadOnlyList<UwpPackageInfo>> GetInstalledUwpPackagesAsync(CancellationToken ct = default);

    Task<(int RemovedCount, string ErrorSummary)> RemoveUwpPackagesAsync(
        IReadOnlyList<UwpPackageInfo> packages,
        CancellationToken ct = default);
}
