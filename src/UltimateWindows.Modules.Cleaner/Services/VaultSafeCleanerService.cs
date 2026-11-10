using System.Diagnostics;
using System.Text.Json;
using UltimateWindows.Core.Contracts;
using UltimateWindows.Core.Enums;
using UltimateWindows.Core.Guards;
using UltimateWindows.Core.Models;
using UltimateWindows.Modules.Cleaner.Contracts;
using UltimateWindows.Modules.Cleaner.DiskMap;
using UltimateWindows.Modules.Cleaner.Models;
using UltimateWindows.Modules.Cleaner.Scanners;
using UltimateWindows.Modules.Cleaner.Utilities;

namespace UltimateWindows.Modules.Cleaner.Services;

/// <summary>
/// Базовый безопасный платформенный мост по умолчанию (используется вне Windows или в изолированных тестах).
/// На Windows подменяется на WindowsCleanerPlatformBridge (с Restart Manager API, SHQueryRecycleBinW и реестром).
/// </summary>
public class DefaultCleanerPlatformBridge : ICleanerPlatformBridge
{
    public virtual bool IsProcessRunningByName(ReadOnlySpan<string> processNamesWithoutExtension)
    {
        foreach (var procName in processNamesWithoutExtension)
        {
            try
            {
                if (Process.GetProcessesByName(procName).Length > 0)
                {
                    return true;
                }
            }
            catch
            {
                // Игнорируем ограничения доступа к таблице процессов
            }
        }

        return false;
    }

    public virtual bool IsFileLockedByAnotherProcess(string filePath)
    {
        if (!File.Exists(filePath))
        {
            return false;
        }

        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            return false;
        }
        catch (IOException)
        {
            return true;
        }
        catch
        {
            return false;
        }
    }

    public virtual Task<IReadOnlyList<RegistryOrphanCandidate>> ScanVerifiedRegistryOrphansAsync(CancellationToken ct = default)
        => Task.FromResult<IReadOnlyList<RegistryOrphanCandidate>>(Array.Empty<RegistryOrphanCandidate>());

    public virtual Task<int> DeleteVerifiedRegistryOrphansAsync(
        IReadOnlyList<RegistryOrphanCandidate> candidates,
        CancellationToken ct = default)
        => Task.FromResult(0);

    public virtual Task<(long RecycleBinBytes, int RecycleBinItems)> QueryRecycleBinSizeAsync(CancellationToken ct = default)
        => Task.FromResult((0L, 0));

    public virtual Task<bool> EmptyRecycleBinAsync(CancellationToken ct = default)
        => Task.FromResult(false);
}

/// <summary>
/// Главный сервис Фазы 2: Бережная очистка диска и браузеров (с защитой паролей и автозаполнения),
/// верифицированная гигиена реестра с записью микро-отката в Машину времени и быстрый анализ места.
/// </summary>
public sealed class VaultSafeCleanerService
{
    private readonly IVaultService _vaultService;
    private readonly ICleanerPlatformBridge _platformBridge;
    private readonly BrowserCacheScanner _browserScanner;
    private readonly SystemJunkScanner _systemJunkScanner;
    private readonly FastDiskSpaceAnalyzer _diskAnalyzer;

    public VaultSafeCleanerService(
        IVaultService vaultService,
        ICleanerPlatformBridge? platformBridge = null,
        BrowserCacheScanner? browserScanner = null,
        SystemJunkScanner? systemJunkScanner = null,
        FastDiskSpaceAnalyzer? diskAnalyzer = null)
    {
        _vaultService = vaultService ?? throw new ArgumentNullException(nameof(vaultService));
        _platformBridge = platformBridge ?? new DefaultCleanerPlatformBridge();
        _browserScanner = browserScanner ?? new BrowserCacheScanner(_platformBridge);
        _systemJunkScanner = systemJunkScanner ?? new SystemJunkScanner();
        _diskAnalyzer = diskAnalyzer ?? new FastDiskSpaceAnalyzer();
    }

    /// <summary>
    /// Выполняет быстрое неразрушающее сканирование (Dry-Run Предпросмотр) без удаления ни единого байта.
    /// </summary>
    public async Task<CleanupScanReport> ScanAsync(CleanupOptions options, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(options);

        var allFiles = new List<CleanupCandidateFile>();
        var browserWarnings = new List<string>();

        if (options.CleanBrowserCaches)
        {
            var (browserFiles, warnings) = await Task.Run(() => _browserScanner.ScanSafeCacheFiles(ct), ct).ConfigureAwait(false);
            allFiles.AddRange(browserFiles);
            browserWarnings.AddRange(warnings);
        }

        var sysJunk = await Task.Run(() => _systemJunkScanner.ScanSystemJunk(options, ct), ct).ConfigureAwait(false);
        allFiles.AddRange(sysJunk);

        IReadOnlyList<RegistryOrphanCandidate> regOrphans = Array.Empty<RegistryOrphanCandidate>();
        if (options.CleanRegistryOrphans)
        {
            var rawOrphans = await _platformBridge.ScanVerifiedRegistryOrphansAsync(ct).ConfigureAwait(false);
            // Дополнительный инвариант: отсекаем любые запрещенные ветки COM/WinRT/CLSID!
            regOrphans = rawOrphans
                .Where(o => !CommandLinePathExtractor.IsForbiddenComOrSystemRegistryKey($@"{o.HiveName}\{o.SubKeyPath}"))
                .ToList();
        }

        long recycleBytes = 0;
        int recycleCount = 0;
        if (options.EmptyRecycleBin)
        {
            (recycleBytes, recycleCount) = await _platformBridge.QueryRecycleBinSizeAsync(ct).ConfigureAwait(false);
        }

        var categories = BuildCategorySummaries(allFiles, regOrphans, options.EmptyRecycleBin, recycleBytes, recycleCount);
        var totalBytes = allFiles.Sum(f => f.SizeBytes) + recycleBytes;

        return new CleanupScanReport(
            ScannedAtUtc: DateTimeOffset.UtcNow,
            TotalReclaimableBytes: totalBytes,
            TotalFilesCount: allFiles.Count + recycleCount,
            TotalRegistryOrphansCount: regOrphans.Count,
            PasswordsAndAutofillProtected: options.PreservePasswordsAndAutofill,
            RunningBrowserWarnings: browserWarnings,
            Categories: categories,
            CandidateFiles: allFiles,
            RegistryOrphans: regOrphans);
    }

    /// <summary>
    /// Безопасно очищает найденные в отчете элементы:
    /// 1) Проверяет каждый файл через BrowserVaultGuard (жесткая защита паролей и форм!);
    /// 2) Аккуратно пропускает занятые открытыми программами файлы без сбоев;
    /// 3) Записывает все очищаемые сироты реестра в единую компактную транзакцию Zero-Bloat Vault для отката в 1 клик!
    /// </summary>
    public async Task<CleanupExecutionResult> ExecuteCleanupAsync(
        CleanupScanReport report,
        CleanupOptions options,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(options);

        long freedBytes = 0;
        int deletedFiles = 0;
        int skippedLocked = 0;

        foreach (var file in report.CandidateFiles)
        {
            ct.ThrowIfCancellationRequested();

            // Финальный барьер безопасности перед каждым File.Delete!
            if (options.PreservePasswordsAndAutofill)
            {
                BrowserVaultGuard.ThrowIfProtected(file.FullPath);
            }

            if (!File.Exists(file.FullPath))
            {
                continue;
            }

            if (_platformBridge.IsFileLockedByAnotherProcess(file.FullPath))
            {
                skippedLocked++;
                continue;
            }

            try
            {
                File.Delete(file.FullPath);
                freedBytes += file.SizeBytes;
                deletedFiles++;
            }
            catch (IOException)
            {
                skippedLocked++;
            }
            catch (UnauthorizedAccessException)
            {
                skippedLocked++;
            }
        }

        if (options.EmptyRecycleBin)
        {
            var (binBytes, binItems) = await _platformBridge.QueryRecycleBinSizeAsync(ct).ConfigureAwait(false);
            if (binBytes > 0 && await _platformBridge.EmptyRecycleBinAsync(ct).ConfigureAwait(false))
            {
                freedBytes += binBytes;
                deletedFiles += binItems;
            }
        }

        int cleanedRegCount = 0;
        Guid? rollbackSessionId = null;

        if (options.CleanRegistryOrphans && report.RegistryOrphans.Count > 0)
        {
            await using var tx = _vaultService.BeginTransaction(
                SystemDomain.SmartCleaner,
                friendlyTitle: $"Безопасная гигиена реестра ({report.RegistryOrphans.Count} устаревших ссылок)",
                friendlySummary: "Очищены ссылки на давно удаленные программы в автозагрузке, кэше имен и правилах совместимости. Можно вернуть в 1 клик.",
                technicalDetails: string.Join("; ", report.RegistryOrphans.Take(10).Select(r => r.FullRegistryDisplayPath)));

            foreach (var orphan in report.RegistryOrphans)
            {
                if (CommandLinePathExtractor.IsForbiddenComOrSystemRegistryKey($@"{orphan.HiveName}\{orphan.SubKeyPath}"))
                {
                    continue;
                }

                // Совместимый формат со структурой RegistryValueSnapshot в WindowsSystemStateApplier!
                var snapshotJson = JsonSerializer.Serialize(new
                {
                    Hive = orphan.HiveName,
                    SubKey = orphan.SubKeyPath,
                    ValueName = orphan.ValueName,
                    ExistedBefore = true,
                    ValueKind = orphan.RegistryValueKindCode,
                    SerializedData = orphan.PreviousValueSerialized
                });

                tx.RecordStateDelta(
                    StateTargetKind.RegistryValue,
                    orphan.FullRegistryDisplayPath,
                    previousStateJson: snapshotJson,
                    newStateJson: null);
            }

            cleanedRegCount = await _platformBridge.DeleteVerifiedRegistryOrphansAsync(report.RegistryOrphans, ct).ConfigureAwait(false);
            if (cleanedRegCount > 0)
            {
                var committed = await tx.CommitAsync(ct: ct).ConfigureAwait(false);
                rollbackSessionId = committed.SessionId;
            }
        }

        var regPart = cleanedRegCount > 0 ? $", исправлено {cleanedRegCount} сирот реестра (точка отката сохранена)" : "";
        var skipPart = skippedLocked > 0 ? $" (пропущено занятых открытыми программами файлов: {skippedLocked})" : "";
        var summaryMsg = $"Освобождено {ByteFormatter.Format(freedBytes)} ({deletedFiles} файлов){regPart}{skipPart}. Пароли и формы браузеров сохранены!";

        return new CleanupExecutionResult(
            FreedBytes: freedBytes,
            DeletedFilesCount: deletedFiles,
            SkippedLockedFilesCount: skippedLocked,
            CleanedRegistryOrphansCount: cleanedRegCount,
            RollbackSessionId: rollbackSessionId,
            UserSummaryMessage: summaryMsg);
    }

    public Task<DiskSpaceAnalysisReport> AnalyzeDiskSpaceAsync(
        string rootPath,
        int topDirectoryLimit = 12,
        int largestFilesLimit = 15,
        CancellationToken ct = default)
        => _diskAnalyzer.AnalyzeDirectoryOrDriveAsync(rootPath, topDirectoryLimit, largestFilesLimit, ct);

    private static IReadOnlyList<CleanupCategorySummary> BuildCategorySummaries(
        List<CleanupCandidateFile> files,
        IReadOnlyList<RegistryOrphanCandidate> regOrphans,
        bool includeRecycleBin,
        long recycleBytes,
        int recycleItems)
    {
        var list = new List<CleanupCategorySummary>();

        var grouped = files.GroupBy(f => f.Category).OrderBy(g => g.Key);
        foreach (var group in grouped)
        {
            var (icon, title, desc) = DescribeCategory(group.Key);
            var total = group.Sum(x => x.SizeBytes);
            var samples = group.Take(8).Select(x => $"{x.SourceLabel}: {x.FullPath} ({ByteFormatter.Format(x.SizeBytes)})").ToList();

            list.Add(new CleanupCategorySummary(
                Category: group.Key,
                IconGlyph: icon,
                FriendlyTitle: title,
                FriendlyDescription: desc,
                TotalBytes: total,
                ItemCount: group.Count(),
                SamplePathsForExpert: samples));
        }

        if (includeRecycleBin && (recycleBytes > 0 || recycleItems > 0))
        {
            list.Add(new CleanupCategorySummary(
                Category: CleanerCategoryKind.RecycleBin,
                IconGlyph: "🗑️",
                FriendlyTitle: "Корзина Windows",
                FriendlyDescription: "Ранее удаленные вами файлы, ожидающие окончательной очистки.",
                TotalBytes: recycleBytes,
                ItemCount: recycleItems,
                SamplePathsForExpert: ["Shell32 SHQueryRecycleBinW / SHEmptyRecycleBinW"]));
        }

        if (regOrphans.Count > 0)
        {
            list.Add(new CleanupCategorySummary(
                Category: CleanerCategoryKind.VerifiedRegistryOrphans,
                IconGlyph: "🧬",
                FriendlyTitle: "Безопасная гигиена реестра (удаленные программы)",
                FriendlyDescription: "Только 100% проверенные ссылки на несуществующие локальные .exe файлы (без затрагивания системных классов COM/WinRT).",
                TotalBytes: 0,
                ItemCount: regOrphans.Count,
                SamplePathsForExpert: regOrphans.Take(10).Select(r => $"{r.FullRegistryDisplayPath} -> нет файла '{r.MissingReferencedFilePath}'").ToList()));
        }

        return list;
    }

    private static (string Icon, string Title, string Desc) DescribeCategory(CleanerCategoryKind kind) => kind switch
    {
        CleanerCategoryKind.BrowserCache => (
            "🌐",
            "Кэш браузеров (Пароли и формы под замком 🔒)",
            "Временные картинки, скрипты и кэш шейдеров страниц без выхода из аккаунтов и без удаления паролей."),
        CleanerCategoryKind.SystemTemp => (
            "🗂️",
            "Временные файлы Windows и программ (старше 24 ч)",
            "Отработанные временные файлы установщиков и системы. Свежие рабочие файлы за последние сутки не затрагиваются."),
        CleanerCategoryKind.GpuShaderCache => (
            "🎮",
            "Старый кэш шейдеров видеокарты (DirectX / NVIDIA / AMD)",
            "Накопленные кэши старых игр и прошлых версий видеодрайверов. Освобождает гигабайты и помогает убрать статтеры."),
        CleanerCategoryKind.WindowsErrorReports => (
            "📋",
            "Архивы старых отчетов об ошибках (WER)",
            "Отправленные или устаревшие диагностические отчеты о сбоях программ."),
        CleanerCategoryKind.WindowsUpdateCache => (
            "📦",
            "Устаревший кэш загрузок Центра обновления",
            "Скачанные установочные пакеты прошлых обновлений Windows (старше 48 часов)."),
        CleanerCategoryKind.DeveloperPackageCache => (
            "🛠️",
            "Кэш скачанных пакетов разработчика (pip / npm / NuGet)",
            "Локальные копии архивов библиотек, которые при необходимости скачиваются заново."),
        _ => ("🧹", "Временные данные", "Безопасные для удаления временные файлы.")
    };
}
