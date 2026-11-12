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

    /// <summary>Проверяет наличие раздела реестра вида «HKCU\Software\...» или «HKLM\Software\...».</summary>
    bool RegistryKeyExists(string keyPath) => false;

    /// <summary>Читает строковое значение реестра; пустое имя значения — значение по умолчанию.</summary>
    string? ReadRegistryString(string keyPath, string valueName) => null;

    /// <summary>
    /// Быстрое чтение таблицы файлов NTFS (<c>$MFT</c>) с правами администратора.
    /// Возвращает <c>null</c>, если том не NTFS, нет прав или быстрое чтение недоступно — тогда работает многопоточный обход папок.
    /// </summary>
    Task<DiskSpaceAnalysisReport?> TryAnalyzeNtfsVolumeViaMftAsync(
        string rootPath,
        int topDirectoryLimit = 12,
        int largestFilesLimit = 15,
        CancellationToken ct = default)
        => Task.FromResult<DiskSpaceAnalysisReport?>(null);
}
