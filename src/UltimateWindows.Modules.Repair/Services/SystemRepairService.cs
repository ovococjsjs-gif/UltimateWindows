using System.Text.Json;
using UltimateWindows.Core.Contracts;
using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Repair.Bsod;
using UltimateWindows.Modules.Repair.Catalog;
using UltimateWindows.Modules.Repair.Contracts;
using UltimateWindows.Modules.Repair.Models;
using UltimateWindows.Modules.Repair.PeDoctor;
using UltimateWindows.Modules.Repair.Playbooks;

namespace UltimateWindows.Modules.Repair.Services;

/// <summary>
/// Базовый кроссплатформенный мост ремонта по умолчанию (для безопасной работы вне Windows и в модульных тестах).
/// </summary>
public class DefaultRepairPlatformBridge : IRepairPlatformBridge
{
    public virtual string GetSystem64Directory() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32");

    public virtual string GetSysWow64Directory() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64");

    public virtual string GetMinidumpDirectory() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Minidump");

    public virtual bool IsRunningAsAdministrator() => false;

    public virtual bool VerifyAuthenticodeSignature(string filePath) => false;

    public virtual Task<IReadOnlyList<SystemCrashEventEntry>> ReadRecentCrashEventsAsync(
        int maxEntries = 20,
        CancellationToken ct = default)
        => Task.FromResult<IReadOnlyList<SystemCrashEventEntry>>(Array.Empty<SystemCrashEventEntry>());

    public virtual Task<(bool Succeeded, string OutputLog)> InstallOfficialRuntimeViaWingetAsync(
        OfficialRuntimePackage package,
        CancellationToken ct = default)
        => Task.FromResult((false, "Пакетный менеджер Windows (winget) доступен только в среде Windows 10/11."));

    public virtual Task<(bool Succeeded, string OutputLog)> ExecutePlaybookNativeStepsAsync(
        RepairPlaybookId playbookId,
        CancellationToken ct = default)
        => Task.FromResult((false, "Нативные системные утилиты ремонта доступны только в среде Windows 10/11."));
}

/// <summary>
/// Центральный сервис Фазы 3: Доктор ошибок 0xC000007B и зависимостей PE,
/// установка официальных пакетов VC++/DirectX/.NET, расшифровка минидампов BSOD и одно-кликовый ремонт ОС.
/// </summary>
public sealed class SystemRepairService
{
    private readonly IVaultService _vaultService;
    private readonly IRepairPlatformBridge _platformBridge;
    private readonly BinaryPeDependencyDoctor _peDoctor;
    private readonly MinidumpBinaryAnalyzer _minidumpAnalyzer;

    public SystemRepairService(
        IVaultService vaultService,
        IRepairPlatformBridge? platformBridge = null,
        BinaryPeDependencyDoctor? peDoctor = null,
        MinidumpBinaryAnalyzer? minidumpAnalyzer = null)
    {
        _vaultService = vaultService ?? throw new ArgumentNullException(nameof(vaultService));
        _platformBridge = platformBridge ?? new DefaultRepairPlatformBridge();
        _peDoctor = peDoctor ?? new BinaryPeDependencyDoctor();
        _minidumpAnalyzer = minidumpAnalyzer ?? new MinidumpBinaryAnalyzer();
    }

    public IReadOnlyList<RepairPlaybookDescriptor> GetAvailablePlaybooks() =>
        SystemRepairPlaybookCatalog.GetAllPlaybooks();

    public IReadOnlyList<OfficialRuntimePackage> GetOfficialRuntimeCatalog() =>
        OfficialRuntimeCatalog.GetAllPackages();

    /// <summary>
    /// Диагностирует указанный .exe файл на конфликт разрядности 0xC000007B и отсутствие системных библиотек.
    /// </summary>
    public ExecutableDiagnosisReport DiagnoseExecutable(string executablePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        return _peDoctor.DiagnoseExecutable(
            executablePath,
            _platformBridge.GetSystem64Directory(),
            _platformBridge.GetSysWow64Directory());
    }

    /// <summary>
    /// Безопасно лечит ошибку 0xC000007B, вызванную чужеродным локальным .dll файлом неверной разрядности в папке игры/программы:
    /// помещает конфликтный .dll в сжатый зашифрованный карантин Машины времени (с откатом в 1 клик!),
    /// жестко запрещая трогать системную папку C:\Windows.
    /// </summary>
    public async Task<RepairOperationResult> QuarantineConflictingLocalDllAsync(
        string conflictingDllPath,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(conflictingDllPath);
        var fullPath = Path.GetFullPath(conflictingDllPath);

        if (!File.Exists(fullPath))
        {
            return new RepairOperationResult(false, "Указанный DLL-файл уже отсутствует на диске.", fullPath);
        }

        // Жесткий инвариант безопасности: никогда не удаляем и не перемещаем файлы внутри каталога Windows!
        if (IsInsideProtectedWindowsDirectory(fullPath))
        {
            return new RepairOperationResult(
                Succeeded: false,
                UserFriendlySummary: "Защитный барьер: файл находится в системной папке Windows. Системные библиотеки лечатся только через официальный установщик Microsoft или DISM/SFC.",
                TechnicalLogOutput: $"Blocked quarantine attempt inside Windows directory: {fullPath}");
        }

        var fileName = Path.GetFileName(fullPath);
        await using var tx = _vaultService.BeginTransaction(
            SystemDomain.DllAndRepair,
            friendlyTitle: $"Лечение 0xC000007B: изоляция конфликтной {fileName}",
            friendlySummary: $"Локальная библиотека «{fileName}» неверной разрядности перенесена в сжатый карантин, чтобы программа загружала правильную системную версию. Доступен возврат в 1 клик.",
            technicalDetails: fullPath);

        var sha256 = await tx.QuarantineFileAsync(fullPath, ct).ConfigureAwait(false);
        var record = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);

        return new RepairOperationResult(
            Succeeded: true,
            UserFriendlySummary: $"Конфликтная библиотека «{fileName}» безопасно изолирована в Машину времени! Теперь программа сможет загрузить штатную библиотеку нужной разрядности.",
            TechnicalLogOutput: $"Quarantined '{fullPath}' -> Vault Blob SHA-256: {sha256}",
            RollbackSessionId: record.SessionId);
    }

    /// <summary>
    /// Устанавливает официальный подписанный пакет среды выполнения Microsoft / OpenAL через winget
    /// с записью события в журнал Машины времени.
    /// </summary>
    public async Task<RepairOperationResult> InstallOfficialRuntimeAsync(
        OfficialRuntimePackage package,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(package);

        var (ok, log) = await _platformBridge.InstallOfficialRuntimeViaWingetAsync(package, ct).ConfigureAwait(false);
        if (!ok)
        {
            return new RepairOperationResult(
                Succeeded: false,
                UserFriendlySummary: $"Не удалось автоматически установить пакет «{package.FriendlyName}». Проверьте подключение к интернету или наличие winget.",
                TechnicalLogOutput: log);
        }

        await using var tx = _vaultService.BeginTransaction(
            SystemDomain.DllAndRepair,
            friendlyTitle: $"Установка официального пакета: {package.FriendlyName}",
            friendlySummary: $"Установлен подписанный пакет «{package.PublisherName}» ({package.WingetPackageId}).",
            technicalDetails: log);

        tx.RecordStateDelta(
            StateTargetKind.SystemSetting,
            $"OfficialRuntime:{package.WingetPackageId}",
            previousStateJson: JsonSerializer.Serialize(new { Package = package.WingetPackageId, Action = "Install" }),
            newStateJson: JsonSerializer.Serialize(new { Installed = true }));

        var committed = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);

        return new RepairOperationResult(
            Succeeded: true,
            UserFriendlySummary: $"✅ Официальный пакет «{package.FriendlyName}» успешно установлен!",
            TechnicalLogOutput: log,
            RollbackSessionId: committed.SessionId);
    }

    /// <summary>
    /// Разбирает один файл дампа, выбранный пользователем (например, принесённый с другого компьютера).
    /// Возвращает null, если файл не является дампом ядра или дампом программы.
    /// </summary>
    public Task<BsodMinidumpReport?> AnalyzeDumpFileAsync(string dumpFilePath, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dumpFilePath);
        return Task.Run(() => MinidumpBinaryAnalyzer.AnalyzeDumpFile(dumpFilePath), ct);
    }

    /// <summary>
    /// Разбирает дампы синих экранов и последние критические сбои из журнала событий Windows
    /// и сообщает, удалось ли прочитать папку с дампами.
    /// </summary>
    public async Task<CrashHistoryScanResult> ScanCrashHistoryDetailedAsync(
        int maxItems = 15,
        CancellationToken ct = default)
    {
        var scan = await Task.Run(
            () => _minidumpAnalyzer.ScanMinidumpDirectoryDetailed(_platformBridge.GetMinidumpDirectory(), maxItems),
            ct).ConfigureAwait(false);

        var events = await _platformBridge.ReadRecentCrashEventsAsync(maxItems, ct).ConfigureAwait(false);
        return new CrashHistoryScanResult(scan.Reports, events, scan.FolderStatus, scan.UnreadableFileCount);
    }

    /// <summary>
    /// Сканирует минидампы синих экранов (BSOD) и последние критические сбои из Журнала событий Windows.
    /// </summary>
    public async Task<(IReadOnlyList<BsodMinidumpReport> Minidumps, IReadOnlyList<SystemCrashEventEntry> CrashEvents)> ScanBsodAndCrashHistoryAsync(
        int maxItems = 15,
        CancellationToken ct = default)
    {
        var result = await ScanCrashHistoryDetailedAsync(maxItems, ct).ConfigureAwait(false);
        return (result.Minidumps, result.CrashEvents);
    }

    /// <summary>
    /// Выполняет выбранный одно-кликовый рецепт восстановления Windows с проверкой прав и записью в журнал Машины времени.
    /// </summary>
    public async Task<RepairOperationResult> ExecutePlaybookAsync(
        RepairPlaybookId playbookId,
        CancellationToken ct = default)
    {
        var descriptor = SystemRepairPlaybookCatalog.GetById(playbookId);
        if (descriptor.RequiresAdministrator && !_platformBridge.IsRunningAsAdministrator())
        {
            return new RepairOperationResult(
                Succeeded: false,
                UserFriendlySummary: $"Для рецепта «{descriptor.FriendlyTitle}» требуются права Администратора. Перезапустите UltimateWindows от имени Администратора.",
                TechnicalLogOutput: $"Elevation required for playbook {playbookId}.");
        }

        var (ok, log) = await _platformBridge.ExecutePlaybookNativeStepsAsync(playbookId, ct).ConfigureAwait(false);
        var verdict = ExtractVerdictLine(log);
        if (!ok)
        {
            return new RepairOperationResult(
                Succeeded: false,
                UserFriendlySummary: verdict is null
                    ? $"Рецепт «{descriptor.FriendlyTitle}» не выполнен полностью. Откройте технические детали, чтобы увидеть, на каком шаге он остановился."
                    : $"Рецепт «{descriptor.FriendlyTitle}» не выполнен полностью. {verdict}",
                TechnicalLogOutput: log);
        }

        await using var tx = _vaultService.BeginTransaction(
            SystemDomain.DllAndRepair,
            friendlyTitle: $"Выполнен рецепт ремонта: {descriptor.FriendlyTitle}",
            friendlySummary: descriptor.FriendlyDescription,
            technicalDetails: log.Length > 1500 ? log[..1500] : log);

        tx.RecordStateDelta(
            StateTargetKind.SystemSetting,
            $"RepairPlaybook:{playbookId}",
            previousStateJson: JsonSerializer.Serialize(new { Playbook = playbookId.ToString() }),
            newStateJson: JsonSerializer.Serialize(new { CompletedAtUtc = DateTimeOffset.UtcNow }));

        var committed = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);

        return new RepairOperationResult(
            Succeeded: true,
            UserFriendlySummary: verdict is null
                ? $"✅ Рецепт «{descriptor.FriendlyTitle}» успешно выполнен!"
                : $"✅ Рецепт «{descriptor.FriendlyTitle}» выполнен. {verdict}",
            TechnicalLogOutput: log,
            RollbackSessionId: committed.SessionId);
    }

    /// <summary>
    /// Рецепт может завершить журнал строкой «Итог: …» — её показываем пользователю как главный вывод.
    /// </summary>
    private static string? ExtractVerdictLine(string? log)
    {
        if (string.IsNullOrWhiteSpace(log))
        {
            return null;
        }

        const string marker = "Итог:";
        var lines = log.Split('\n');
        for (var i = lines.Length - 1; i >= 0; i--)
        {
            var trimmed = lines[i].Trim();
            if (trimmed.StartsWith(marker, StringComparison.Ordinal))
            {
                var verdict = trimmed[marker.Length..].Trim();
                return verdict.Length > 0 ? verdict : null;
            }
        }

        return null;
    }

    private bool IsInsideProtectedWindowsDirectory(string fullFilePath)
    {
        var candidates = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            _platformBridge.GetSystem64Directory(),
            _platformBridge.GetSysWow64Directory()
        };

        foreach (var dir in candidates)
        {
            if (string.IsNullOrWhiteSpace(dir))
            {
                continue;
            }

            var normDir = Path.GetFullPath(dir).TrimEnd('\\', '/') + Path.DirectorySeparatorChar;
            if (fullFilePath.StartsWith(normDir, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
