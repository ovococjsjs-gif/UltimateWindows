using UltimateWindows.Modules.Cleaner.Models;

namespace UltimateWindows.Modules.Cleaner.Contracts;

/// <summary>
/// Платформенный мост для специфичных вызовов Windows в модуле очистки:
/// проверка запущенных браузеров (Restart Manager / процессы), безопасный поиск сирот реестра,
/// очистка Корзины и отправка выбранных элементов в Корзину Windows (Shell32).
/// </summary>
public interface ICleanerPlatformBridge
{
    bool IsProcessRunningByName(ReadOnlySpan<string> processNamesWithoutExtension);

    bool IsFileLockedByAnotherProcess(string filePath);

    Task<IReadOnlyList<RegistryOrphanCandidate>> ScanVerifiedRegistryOrphansAsync(CancellationToken ct = default);

    Task<int> DeleteVerifiedRegistryOrphansAsync(
        IReadOnlyList<RegistryOrphanCandidate> candidates,
        CancellationToken ct = default);

    Task<(long RecycleBinBytes, int RecycleBinItems)> QueryRecycleBinSizeAsync(CancellationToken ct = default);

    Task<bool> EmptyRecycleBinAsync(CancellationToken ct = default);

    Task<bool> SendPathToRecycleBinAsync(string fullPath, CancellationToken ct = default);
}
