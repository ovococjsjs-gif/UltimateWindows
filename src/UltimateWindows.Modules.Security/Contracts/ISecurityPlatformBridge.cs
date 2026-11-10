using UltimateWindows.Modules.Security.Models;

namespace UltimateWindows.Modules.Security.Contracts;

/// <summary>
/// Платформенный мост Фазы 5 для сбора телеметрии процессов (включая реакцию на проверочное окно Drop-on-Inspect),
/// чтения таблицы TCP-соединений GetExtendedTcpTable, аудита точек закрепления и снятия блокировок майнера.
/// </summary>
public interface ISecurityPlatformBridge
{
    bool IsRunningAsAdministrator();

    string GetWindowsDirectory();

    /// <summary>
    /// Снимает двухфазный профиль нагрузки всех процессов:
    /// Фаза 1 — тихий фоновый замер (майнер не подозревает о проверке);
    /// Фаза 2 — имитация открытия инспектора задач (фиксация резкого сброса нагрузки или самозакрытия майнера).
    /// </summary>
    Task<IReadOnlyList<ProcessTelemetrySample>> CaptureDropOnInspectSamplesAsync(
        bool runDecoyTrigger,
        CancellationToken ct = default);

    /// <summary>
    /// Возвращает активные исходящие TCP-соединения с привязкой к PID процесса (iphlpapi GetExtendedTcpTable).
    /// </summary>
    Task<IReadOnlyList<ProcessTcpConnectionInfo>> GetActiveTcpConnectionsAsync(CancellationToken ct = default);

    /// <summary>
    /// Проверяет реестр и планировщик на вредоносные перехваты IFEO, Winlogon, скрытые задачи без SD и подписки WMI.
    /// </summary>
    Task<IReadOnlyList<PersistenceAnomalyRecord>> ScanPersistenceAnomaliesAsync(CancellationToken ct = default);

    /// <summary>
    /// Проверяет, не заблокировал ли майнер Диспетчер задач, Редактор реестра, командную строку или сайты антивирусов в hosts.
    /// </summary>
    Task<IReadOnlyList<OsSabotageFinding>> ScanOsSabotageLocksAsync(CancellationToken ct = default);

    /// <summary>
    /// Безопасно останавливает некритичный вредоносный процесс перед помещением его исполняемого файла в карантин.
    /// </summary>
    Task<bool> TerminateSuspectProcessAsync(int processId, CancellationToken ct = default);

    /// <summary>
    /// Снимает конкретную блокировку саботажа (удаляет запрещающую политику или лечит файл hosts).
    /// </summary>
    Task<(bool Succeeded, string? OriginalHostsBackupContent)> RepairSabotageLockAsync(
        OsSabotageFinding lockFinding,
        CancellationToken ct = default);

    string GetHostsFilePath();
}
