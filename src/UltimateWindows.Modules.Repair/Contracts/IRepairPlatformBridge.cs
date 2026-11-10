using UltimateWindows.Modules.Repair.Models;

namespace UltimateWindows.Modules.Repair.Contracts;

/// <summary>
/// Платформенный мост Фазы 3 для работы с проверкой подписи WinVerifyTrust,
/// чтением журналов событий Windows, системными каталогами System32/SysWOW64 и запуском ремонтных утилит.
/// </summary>
public interface IRepairPlatformBridge
{
    string GetSystem64Directory();

    string GetSysWow64Directory();

    string GetMinidumpDirectory();

    bool IsRunningAsAdministrator();

    /// <summary>
    /// Проверяет цифровую подпись Authenticode (WinVerifyTrust) указанного файла.
    /// </summary>
    bool VerifyAuthenticodeSignature(string filePath);

    /// <summary>
    /// Читает последние критические сбои программ (Event 1000, SideBySide) и железа/драйверов (TDR 4101, WHEA, Kernel-Power 41).
    /// </summary>
    Task<IReadOnlyList<SystemCrashEventEntry>> ReadRecentCrashEventsAsync(
        int maxEntries = 20,
        CancellationToken ct = default);

    /// <summary>
    /// Устанавливает официальный подписанный пакет среды выполнения через пакетный менеджер Windows (winget).
    /// </summary>
    Task<(bool Succeeded, string OutputLog)> InstallOfficialRuntimeViaWingetAsync(
        OfficialRuntimePackage package,
        CancellationToken ct = default);

    /// <summary>
    /// Выполняет системный рецепт восстановления (DISM/SFC, сброс сети, кэша значков, Центра обновлений, Spooler, WMI).
    /// </summary>
    Task<(bool Succeeded, string OutputLog)> ExecutePlaybookNativeStepsAsync(
        RepairPlaybookId playbookId,
        CancellationToken ct = default);
}
