using System.Diagnostics;
using System.Text.Json;
using UltimateWindows.Core.Contracts;
using UltimateWindows.Core.Enums;
using UltimateWindows.Core.Guards;
using UltimateWindows.Core.Models;
using UltimateWindows.Modules.Cleaner.Browsers;
using UltimateWindows.Modules.Cleaner.Contracts;
using UltimateWindows.Modules.Cleaner.DiskMap;
using UltimateWindows.Modules.Cleaner.Models;
using UltimateWindows.Modules.Cleaner.Rules;
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

    public virtual Task<bool> SendPathToRecycleBinAsync(string fullPath, CancellationToken ct = default)
    {
        try
        {
            if (File.Exists(fullPath))
            {
                File.Delete(fullPath);
                return Task.FromResult(true);
            }

            if (Directory.Exists(fullPath))
            {
                Directory.Delete(fullPath, recursive: true);
                return Task.FromResult(true);
            }
        }
        catch
        {
            // Ignore
        }

        return Task.FromResult(false);
    }

    public virtual bool RegistryKeyExists(string keyPath) => false;

    public virtual string? ReadRegistryString(string keyPath, string valueName) => null;

    public virtual Task<DiskSpaceAnalysisReport?> TryAnalyzeNtfsVolumeViaMftAsync(
        string rootPath,
        int topDirectoryLimit = 12,
        int largestFilesLimit = 15,
        CancellationToken ct = default)
        => Task.FromResult<DiskSpaceAnalysisReport?>(null);
}

/// <summary>
/// Главный сервис Фазы 2: Бережная очистка диска и браузеров (с защитой паролей и автозаполнения),
/// многокатегорийная гигиена реестра с записью микро-отката в Машину времени, WizTree-анализатор диска,
/// поиск точных дубликатов SHA-256 и освобождение системных гигабайт.
/// </summary>
public sealed class VaultSafeCleanerService
{
    private readonly IVaultService _vaultService;
    private readonly ICleanerPlatformBridge _platformBridge;
    private readonly BrowserCacheScanner _browserScanner;
    private readonly BrowserDataCleaner _browserDataCleaner;
    private readonly SystemJunkScanner _systemJunkScanner;
    private readonly CleanupRuleEngine _ruleEngine;
    private readonly FastDiskSpaceAnalyzer _diskAnalyzer;
    private readonly DuplicateFileFinder _duplicateFinder;
    private readonly SystemSpaceReclaimer _spaceReclaimer;
    private readonly List<CleanupRule> _externalWinapp2Rules = [];

    public VaultSafeCleanerService(
        IVaultService vaultService,
        ICleanerPlatformBridge? platformBridge = null,
        BrowserCacheScanner? browserScanner = null,
        SystemJunkScanner? systemJunkScanner = null,
        FastDiskSpaceAnalyzer? diskAnalyzer = null,
        CleanupEnvironment? ruleEnvironment = null,
        TimeProvider? timeProvider = null)
    {
        _vaultService = vaultService ?? throw new ArgumentNullException(nameof(vaultService));
        _platformBridge = platformBridge ?? new DefaultCleanerPlatformBridge();
        _browserScanner = browserScanner ?? new BrowserCacheScanner(_platformBridge);
        _browserDataCleaner = new BrowserDataCleaner(_platformBridge);
        _systemJunkScanner = systemJunkScanner ?? new SystemJunkScanner(timeProvider: timeProvider);
        _ruleEngine = new CleanupRuleEngine(
            _platformBridge,
            ruleEnvironment ?? CleanupEnvironment.FromSystem(),
            extraProtectedDirectories: [Path.Combine(AppContext.BaseDirectory, "Data", "Vault")],
            timeProvider: timeProvider);
        _diskAnalyzer = diskAnalyzer ?? new FastDiskSpaceAnalyzer(_platformBridge);
        _duplicateFinder = new DuplicateFileFinder();
        _spaceReclaimer = new SystemSpaceReclaimer();
    }

    public IReadOnlyList<CleanupRule> ExternalRules => _externalWinapp2Rules;

    /// <summary>
    /// Возвращает все активные правила каталога: встроенные + подключённые пользователем из файла формата Winapp2.ini.
    /// </summary>
    public IReadOnlyList<CleanupRule> GetCatalogRules()
    {
        var builtIn = CleanupRuleCatalogLoader.LoadBuiltIn().Rules;
        if (_externalWinapp2Rules.Count == 0)
        {
            return builtIn;
        }

        var combined = new List<CleanupRule>(builtIn.Count + _externalWinapp2Rules.Count);
        combined.AddRange(builtIn);
        combined.AddRange(_externalWinapp2Rules);
        return combined;
    }

    /// <summary>
    /// Подключает внешний файл правил формата Winapp2.ini. Все внешние правила по умолчанию сняты и проходят усиленную проверку <see cref="CleanupPathGuard"/>.
    /// </summary>
    public Winapp2ReadResult ImportExternalWinapp2File(string filePath)
    {
        var parsed = Winapp2Reader.ReadFile(filePath);
        _externalWinapp2Rules.Clear();
        _externalWinapp2Rules.AddRange(parsed.Rules);
        return parsed;
    }

    public void ClearExternalWinapp2Rules() => _externalWinapp2Rules.Clear();

    /// <summary>
    /// Анализ по каталогу правил программ (встроенный каталог + подключённый Winapp2.ini) без удаления файлов.
    /// </summary>
    public Task<CleanupRuleScanResult> ScanAppRulesAsync(CancellationToken ct = default)
    {
        var rules = GetCatalogRules();
        return Task.Run(() => _ruleEngine.Scan(rules, ct), ct);
    }

    /// <summary>
    /// Очистка отмеченных находок каталога правил программ.
    /// </summary>
    public Task<CleanupRuleExecutionResult> ExecuteAppRulesAsync(
        IReadOnlyList<CleanupRuleFinding> selectedFindings,
        CancellationToken ct = default)
        => Task.Run(() => _ruleEngine.Execute(selectedFindings, ct), ct);

    /// <summary>
    /// Анализ данных браузеров по пунктам (история, список загрузок, cookie с учётом списка исключений, вкладки сеансов).
    /// </summary>
    public Task<BrowserDataScanReport> ScanBrowserDataDetailsAsync(
        IReadOnlyList<string>? keepCookieDomains = null,
        CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            var profiles = _browserScanner.DiscoverProfiles();
            return _browserDataCleaner.Scan(profiles, keepCookieDomains, ct);
        }, ct);
    }

    /// <summary>
    /// Выборочная очистка отмеченных пунктов браузеров (история, загрузки, cookie со списком «сохранить», сеансы).
    /// Пароли, автозаполнение и закладки защищены всегда.
    /// </summary>
    public Task<BrowserDataCleanResult> CleanBrowserDataDetailsAsync(
        BrowserCleanupSelection selection,
        CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            var profiles = _browserScanner.DiscoverProfiles();
            return _browserDataCleaner.Clean(profiles, selection, ct);
        }, ct);
    }

    public IReadOnlyList<DiskVolumeSummary> GetMountedVolumes() => FastDiskSpaceAnalyzer.GetReadyVolumes();

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

        if (options.CleanSystemTempAndShaders || options.IncludeDeveloperCaches)
        {
            var sysFiles = await Task.Run(() => _systemJunkScanner.ScanSystemJunk(options, ct), ct).ConfigureAwait(false);
            allFiles.AddRange(sysFiles);
        }

        if (options.PreservePasswordsAndAutofill)
        {
            allFiles.RemoveAll(f => BrowserVaultGuard.IsProtectedPersonalData(f.FullPath));
        }

        IReadOnlyList<RegistryOrphanCandidate> regOrphans = Array.Empty<RegistryOrphanCandidate>();
        if (options.CleanRegistryOrphans)
        {
            var rawOrphans = await _platformBridge.ScanVerifiedRegistryOrphansAsync(ct).ConfigureAwait(false);
            var safeFiltered = rawOrphans
                .Where(r => !CommandLinePathExtractor.IsForbiddenComOrSystemRegistryKey($@"{r.HiveName}\{r.SubKeyPath}"));

            if (options.EnabledRegistryCategories is { Count: > 0 } allowedSet)
            {
                safeFiltered = safeFiltered.Where(r => allowedSet.Contains(r.Kind));
            }

            regOrphans = safeFiltered.ToList();
        }

        long recycleBytes = 0;
        int recycleItems = 0;
        if (options.EmptyRecycleBin)
        {
            (recycleBytes, recycleItems) = await _platformBridge.QueryRecycleBinSizeAsync(ct).ConfigureAwait(false);
        }

        var categories = BuildCategorySummaries(allFiles, regOrphans, options.EmptyRecycleBin, recycleBytes, recycleItems);
        var totalBytes = allFiles.Sum(f => f.SizeBytes) + (options.EmptyRecycleBin ? recycleBytes : 0);

        return new CleanupScanReport(
            ScannedAtUtc: DateTimeOffset.UtcNow,
            TotalReclaimableBytes: totalBytes,
            TotalFilesCount: allFiles.Count + (options.EmptyRecycleBin ? recycleItems : 0),
            TotalRegistryOrphansCount: regOrphans.Count,
            PasswordsAndAutofillProtected: options.PreservePasswordsAndAutofill,
            RunningBrowserWarnings: browserWarnings,
            Categories: categories,
            CandidateFiles: allFiles,
            RegistryOrphans: regOrphans);
    }

    public async Task<IReadOnlyList<RegistryOrphanCandidate>> ScanRegistryCategoriesAsync(
        IReadOnlySet<RegistryOrphanKind> selectedCategories,
        CancellationToken ct = default)
    {
        var raw = await _platformBridge.ScanVerifiedRegistryOrphansAsync(ct).ConfigureAwait(false);
        return raw
            .Where(r => !CommandLinePathExtractor.IsForbiddenComOrSystemRegistryKey($@"{r.HiveName}\{r.SubKeyPath}"))
            .Where(r => selectedCategories.Count == 0 || selectedCategories.Contains(r.Kind))
            .ToList();
    }

    public async Task<(int FixedCount, Guid? RollbackSessionId, string Message)> FixSelectedRegistryOrphansAsync(
        IReadOnlyList<RegistryOrphanCandidate> selectedOrphans,
        CancellationToken ct = default)
    {
        if (selectedOrphans.Count == 0)
        {
            return (0, null, "Не выбрано ни одной записи реестра для исправления.");
        }

        var safeList = selectedOrphans
            .Where(o => !CommandLinePathExtractor.IsForbiddenComOrSystemRegistryKey($@"{o.HiveName}\{o.SubKeyPath}"))
            .ToList();

        if (safeList.Count == 0)
        {
            return (0, null, "Все выбранные записи защищены системным фильтром.");
        }

        await using var tx = _vaultService.BeginTransaction(
            SystemDomain.SmartCleaner,
            friendlyTitle: $"Исправление проблем реестра ({safeList.Count} шт.)",
            friendlySummary: "Очищены устаревшие ссылки на удаленные файлы и приложения. Полная резервная копия сохранена в Машине времени.",
            technicalDetails: string.Join("; ", safeList.Take(12).Select(r => r.FullRegistryDisplayPath)));

        foreach (var orphan in safeList)
        {
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

        var fixedCount = await _platformBridge.DeleteVerifiedRegistryOrphansAsync(safeList, ct).ConfigureAwait(false);
        Guid? sessionId = null;
        if (fixedCount > 0)
        {
            var committed = await tx.CommitAsync(ct: ct).ConfigureAwait(false);
            sessionId = committed.SessionId;
        }

        return (
            fixedCount,
            sessionId,
            fixedCount > 0
                ? $"Исправлено записей реестра: {fixedCount} (точка отката сохранена в Машину времени)."
                : "Записи требуют прав Администратора или уже были исправлены.");
    }

    /// <summary>
    /// Безопасно выполняет очистку по ранее подтвержденному отчету предпросмотра.
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

            if (options.PreservePasswordsAndAutofill && BrowserVaultGuard.IsProtectedPersonalData(file.FullPath))
            {
                throw new InvalidOperationException(
                    $"АВАРИЙНАЯ БЛОКИРОВКА BrowserVaultGuard: попытка затронуть защищенные личные данные '{file.FullPath}' пресечена.");
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
            var (fixedReg, sid, _) = await FixSelectedRegistryOrphansAsync(report.RegistryOrphans, ct).ConfigureAwait(false);
            cleanedRegCount = fixedReg;
            rollbackSessionId = sid;
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
        int topDirectoryLimit = 25,
        int largestFilesLimit = 150,
        CancellationToken ct = default)
        => _diskAnalyzer.AnalyzeDirectoryOrDriveAsync(rootPath, topDirectoryLimit, largestFilesLimit, ct);

    public Task<DuplicateScanReport> FindExactDuplicatesAsync(
        string rootPath,
        long minFileSizeBytes = 1024 * 1024,
        int maxGroups = 150,
        CancellationToken ct = default)
        => _duplicateFinder.FindExactDuplicatesAsync(rootPath, minFileSizeBytes, maxGroups, ct);

    public Task<IReadOnlyList<SystemSpaceReserveItem>> InspectSystemReservesAsync(CancellationToken ct = default)
        => _spaceReclaimer.InspectSystemReservesAsync(ct);

    public Task<(bool Succeeded, string Message)> ExecuteSystemReserveActionAsync(
        SystemSpaceReserveItem item,
        CancellationToken ct = default)
        => _spaceReclaimer.ExecuteReserveActionAsync(item, ct);

    public async Task<(bool Succeeded, string Message)> SafeSendToRecycleBinAsync(
        string targetPath,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(targetPath))
        {
            return (false, "Путь не указан.");
        }

        var full = Path.GetFullPath(targetPath);

        // Запрещаем удалять корни дисков, папку Windows и защищенные хранилища паролей
        var root = Path.GetPathRoot(full);
        if (string.Equals(full.TrimEnd('\\'), root?.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
        {
            return (false, "Удаление корневого раздела диска заблокировано.");
        }

        var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (!string.IsNullOrWhiteSpace(winDir) &&
            full.StartsWith(winDir, StringComparison.OrdinalIgnoreCase))
        {
            return (false, "Защита ОС: удаление файлов напрямую из системного каталога Windows заблокировано.");
        }

        if (BrowserVaultGuard.IsProtectedPersonalData(full))
        {
            return (false, "BrowserVaultGuard: этот файл содержит защищенные пароли или личные данные браузера.");
        }

        var ok = await _platformBridge.SendPathToRecycleBinAsync(full, ct).ConfigureAwait(false);
        return ok
            ? (true, $"Перемещено в Корзину Windows: {Path.GetFileName(full.TrimEnd('\\'))}")
            : (false, "Не удалось переместить элемент в Корзину (возможно, файл занят открытой программой).");
    }

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
                IconGlyph: "RB",
                FriendlyTitle: "Корзина Windows",
                FriendlyDescription: "Ранее удаленные файлы в Корзине, ожидающие окончательной очистки.",
                TotalBytes: recycleBytes,
                ItemCount: recycleItems,
                SamplePathsForExpert: ["Shell32 SHQueryRecycleBinW / SHEmptyRecycleBinW"]));
        }

        if (regOrphans.Count > 0)
        {
            list.Add(new CleanupCategorySummary(
                Category: CleanerCategoryKind.VerifiedRegistryOrphans,
                IconGlyph: "REG",
                FriendlyTitle: "Гигиена реестра (удаленные программы)",
                FriendlyDescription: "Проверенные ссылки на несуществующие локальные файлы без затрагивания системных классов COM/WinRT.",
                TotalBytes: 0,
                ItemCount: regOrphans.Count,
                SamplePathsForExpert: regOrphans.Take(10).Select(r => $"{r.FullRegistryDisplayPath} -> нет '{r.MissingReferencedFilePath}'").ToList()));
        }

        return list;
    }

    private static (string Icon, string Title, string Desc) DescribeCategory(CleanerCategoryKind kind) => kind switch
    {
        CleanerCategoryKind.BrowserCache => (
            "WEB",
            "Кэш браузеров (пароли и формы под защитой)",
            "Временные изображения, скрипты и кэш шейдеров страниц без выхода из аккаунтов и потери паролей."),
        CleanerCategoryKind.SystemTemp => (
            "TMP",
            "Временные файлы Windows и программ (старше 24 ч)",
            "Отработанные временные файлы установщиков и ОС."),
        CleanerCategoryKind.GpuShaderCache => (
            "GPU",
            "Кэш шейдеров видеокарты (DirectX / NVIDIA / AMD)",
            "Накопленные кэши прошлых версий видеодрайверов и старых игр."),
        CleanerCategoryKind.WindowsErrorReports => (
            "WER",
            "Отчеты об ошибках и дампы сбоев (WER)",
            "Архивные диагностические отчеты о закрытии программ."),
        CleanerCategoryKind.WindowsUpdateCache => (
            "WU",
            "Кэш загрузок Центра обновления",
            "Установочные пакеты уже примененных прошлых обновлений Windows."),
        CleanerCategoryKind.DeveloperPackageCache => (
            "DEV",
            "Кэш пакетов разработчика (pip / npm / NuGet)",
            "Локальные копии архивов библиотек разработки."),
        _ => ("CLN", "Временные данные", "Безопасные для удаления временные файлы.")
    };
}
