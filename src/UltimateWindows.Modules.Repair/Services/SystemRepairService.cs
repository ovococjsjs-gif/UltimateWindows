using System.Text.Json;
using UltimateWindows.Core.Contracts;
using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Repair.Bsod;
using UltimateWindows.Modules.Repair.Catalog;
using UltimateWindows.Modules.Repair.Contracts;
using UltimateWindows.Modules.Repair.Diagnostics;
using UltimateWindows.Modules.Repair.ErrorCodes;
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

    public virtual string GetCbsLogPath() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Logs", "CBS", "CBS.log");

    public virtual int GetWindowsBuildNumber() =>
        OperatingSystem.IsWindows() ? Environment.OSVersion.Version.Build : 0;

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

    public virtual Task<(bool Succeeded, string OutputLog)> InstallOfficialRuntimeDirectOrWingetAsync(
        OfficialRuntimePackage package,
        CancellationToken ct = default)
        => InstallOfficialRuntimeViaWingetAsync(package, ct);

    public virtual Task<IReadOnlyList<OfficialRuntimeStatusReport>> DetectInstalledRuntimesAsync(
        IReadOnlyList<OfficialRuntimePackage> catalog,
        CancellationToken ct = default)
    {
        var list = catalog
            .Select(p => new OfficialRuntimeStatusReport(p, RuntimeInstallStatus.Unknown, "Проверка доступна на ОС Windows"))
            .ToList();
        return Task.FromResult<IReadOnlyList<OfficialRuntimeStatusReport>>(list);
    }

    public virtual Task<IReadOnlyList<InstalledProgramInfo>> EnumerateInstalledProgramsAsync(
        CancellationToken ct = default)
        => Task.FromResult<IReadOnlyList<InstalledProgramInfo>>(Array.Empty<InstalledProgramInfo>());

    public virtual Task<(bool Succeeded, string OutputLog)> ExecutePlaybookNativeStepsAsync(
        RepairPlaybookId playbookId,
        CancellationToken ct = default)
        => Task.FromResult((false, "Нативные системные утилиты ремонта доступны только в среде Windows 10/11."));

    public virtual RepairRegistryValueState ReadRegistryValue(string hive, string subKey, string valueName) =>
        new(false, false, RepairRegistryValueKind.String, null, null, null);

    public virtual (bool Succeeded, string? CreatedKeyPath, string? Error) WriteRegistryValue(
        string hive,
        string subKey,
        string valueName,
        RepairRegistryValueKind kind,
        string? stringValue,
        int? dwordValue)
        => (false, null, "Доступ к реестру поддерживается только на ОС Windows.");

    public virtual (bool Succeeded, string? Error) DeleteRegistryValue(string hive, string subKey, string valueName) =>
        (false, "Доступ к реестру поддерживается только на ОС Windows.");

    public virtual RepairServiceState QueryServiceState(string serviceName) =>
        new(false, RepairServiceStartupKind.Unknown, false);

    public virtual Task<(bool Succeeded, string? Error)> RepairServiceAsync(
        string serviceName,
        RepairServiceStartupKind targetStartup,
        bool startIfStopped,
        CancellationToken ct = default)
        => Task.FromResult<(bool Succeeded, string? Error)>((false, "Управление службами поддерживается только на ОС Windows."));

    public virtual Task<RepairCustomProbeResult> RunCustomProbeAsync(string customProbeId, CancellationToken ct = default) =>
        Task.FromResult(new RepairCustomProbeResult(RepairHealthState.NotApplicable, "Проверка поддерживается только на ОС Windows."));

    public virtual Task<(bool Succeeded, bool RequiresReboot, string OutputLog, string? RollbackTarget, string? RollbackPreviousJson)> ExecuteCustomFixAsync(
        string customProbeId,
        CancellationToken ct = default)
        => Task.FromResult<(bool, bool, string, string?, string?)>((false, false, "Доступно только на Windows.", null, null));

    public virtual InPlaceReinstallReadiness GetInPlaceReinstallReadiness() =>
        new(
            SupportsWindowsUpdateReinstallNow: false,
            OsBuild: GetWindowsBuildNumber(),
            FreeSystemDriveGb: 0,
            HasEnoughDiskSpace: false,
            IsOnBatteryPower: false,
            RecommendedMethodTitle: "Восстановление поверх с сохранением программ и файлов",
            StepByStepInstructions: "Откройте «Параметры → Система → Восстановление» на компьютере с Windows 10 или Windows 11.",
            SettingsUri: "ms-settings:recovery");

    public virtual bool OpenRecoverySettingsOrUrl(string uri) => false;
}

/// <summary>
/// Центральный сервис Этапа 3 («Ремонт и DLL 2.0»):
/// диагностический и ремонтный движок на 100+ правил с откатом в «Машине времени», разбор CBS.log,
/// справочник кодов ошибок Windows, анализатор вылетов программ, PE-доктор 0xC000007B и каталог подписанных сред выполнения.
/// </summary>
public sealed class SystemRepairService
{
    private readonly IVaultService _vaultService;
    private readonly IRepairPlatformBridge _platformBridge;
    private readonly BinaryPeDependencyDoctor _peDoctor;
    private readonly InstalledProgramsDependencyScanner _installedScanner;
    private readonly MinidumpBinaryAnalyzer _minidumpAnalyzer;
    private readonly RepairDiagnosticEngine _diagnosticEngine;

    public SystemRepairService(
        IVaultService vaultService,
        IRepairPlatformBridge? platformBridge = null,
        BinaryPeDependencyDoctor? peDoctor = null,
        MinidumpBinaryAnalyzer? minidumpAnalyzer = null,
        IReadOnlyList<RepairRuleDefinition>? customDiagnosticCatalog = null)
    {
        _vaultService = vaultService ?? throw new ArgumentNullException(nameof(vaultService));
        _platformBridge = platformBridge ?? new DefaultRepairPlatformBridge();
        _peDoctor = peDoctor ?? new BinaryPeDependencyDoctor();
        _installedScanner = new InstalledProgramsDependencyScanner(_peDoctor);
        _minidumpAnalyzer = minidumpAnalyzer ?? new MinidumpBinaryAnalyzer();
        _diagnosticEngine = new RepairDiagnosticEngine(_vaultService, _platformBridge, customDiagnosticCatalog);
    }

    public RepairDiagnosticEngine DiagnosticEngine => _diagnosticEngine;

    public IReadOnlyList<RepairRuleDefinition> GetDiagnosticRules() => _diagnosticEngine.Catalog;

    public Task<IReadOnlyList<RepairCheckFinding>> ScanSystemHealthAsync(
        RepairSectionId? sectionFilter = null,
        CancellationToken ct = default) =>
        _diagnosticEngine.ScanAllAsync(sectionFilter, ct);

    public Task<RepairBatchFixResult> FixIssuesAsync(
        IReadOnlyList<string> ruleIds,
        bool allowRiskyConfirmed = false,
        CancellationToken ct = default) =>
        _diagnosticEngine.FixAndVerifyAsync(ruleIds, allowRiskyConfirmed, ct);

    public CbsLogSummary AnalyzeCbsLog() =>
        CbsLogAnalyzer.AnalyzeFile(_platformBridge.GetCbsLogPath());

    public IReadOnlyList<ErrorCodeEntry> SearchErrorCodes(
        string? query,
        ErrorCodeFamily? familyFilter = null,
        int maxResults = 150) =>
        ErrorCodeCatalog.Search(query, familyFilter, maxResults);

    public IReadOnlyList<RepairPlaybookDescriptor> GetAvailablePlaybooks() =>
        SystemRepairPlaybookCatalog.GetAllPlaybooks();

    public IReadOnlyList<OfficialRuntimePackage> GetOfficialRuntimeCatalog() =>
        OfficialRuntimeCatalog.GetAllPackages();

    public Task<IReadOnlyList<OfficialRuntimeStatusReport>> GetOfficialRuntimeStatusesAsync(CancellationToken ct = default) =>
        _platformBridge.DetectInstalledRuntimesAsync(OfficialRuntimeCatalog.GetAllPackages(), ct);

    public InPlaceReinstallReadiness GetInPlaceReinstallReadiness() =>
        _platformBridge.GetInPlaceReinstallReadiness();

    public bool OpenWindowsRecoveryReinstall() =>
        _platformBridge.OpenRecoverySettingsOrUrl("ms-settings:recovery");

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
    /// Массово сканирует установленные программы на ошибки 0xC000007B и отсутствие официальных пакетов VC++/DirectX/.NET/WebView2.
    /// </summary>
    public async Task<InstalledProgramsScanSummary> ScanInstalledProgramsDependenciesAsync(CancellationToken ct = default)
    {
        var programs = await _platformBridge.EnumerateInstalledProgramsAsync(ct).ConfigureAwait(false);
        return _installedScanner.ScanPrograms(
            programs,
            _platformBridge.GetSystem64Directory(),
            _platformBridge.GetSysWow64Directory(),
            ct);
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
    /// Устанавливает официальный подписанный пакет среды выполнения (прямая HTTPS-загрузка + проверка подписи WinVerifyTrust,
    /// либо включение компонента Windows NetFx3 через DISM, с автоматическим резервом через winget).
    /// </summary>
    public async Task<RepairOperationResult> InstallOfficialRuntimeAsync(
        OfficialRuntimePackage package,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(package);

        var (ok, log) = await _platformBridge.InstallOfficialRuntimeDirectOrWingetAsync(package, ct).ConfigureAwait(false);
        if (!ok)
        {
            return new RepairOperationResult(
                Succeeded: false,
                UserFriendlySummary: $"Не удалось автоматически установить пакет «{package.FriendlyName}». Проверьте права администратора и подключение к интернету.",
                TechnicalLogOutput: log);
        }

        await using var tx = _vaultService.BeginTransaction(
            SystemDomain.DllAndRepair,
            friendlyTitle: $"Установка официального пакета: {package.FriendlyName}",
            friendlySummary: $"Установлен подписанный пакет «{package.PublisherName}» ({package.PackageKey}).",
            technicalDetails: log.Length > 1500 ? log[..1500] : log);

        tx.RecordStateDelta(
            StateTargetKind.SystemSetting,
            $"OfficialRuntime:{package.PackageKey}",
            previousStateJson: JsonSerializer.Serialize(new { Package = package.PackageKey, Action = "Install" }),
            newStateJson: JsonSerializer.Serialize(new { Installed = true, package.WingetPackageId, package.DirectDownloadUrl }));

        var committed = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);

        return new RepairOperationResult(
            Succeeded: true,
            UserFriendlySummary: $"Официальный пакет «{package.FriendlyName}» проверен по цифровой подписи и успешно установлен.",
            TechnicalLogOutput: log,
            RollbackSessionId: committed.SessionId);
    }

    public Task<BsodMinidumpReport?> AnalyzeDumpFileAsync(string dumpFilePath, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dumpFilePath);
        return Task.Run(() => MinidumpBinaryAnalyzer.AnalyzeDumpFile(dumpFilePath), ct);
    }

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

    public async Task<(IReadOnlyList<BsodMinidumpReport> Minidumps, IReadOnlyList<SystemCrashEventEntry> CrashEvents)> ScanBsodAndCrashHistoryAsync(
        int maxItems = 15,
        CancellationToken ct = default)
    {
        var result = await ScanCrashHistoryDetailedAsync(maxItems, ct).ConfigureAwait(false);
        return (result.Minidumps, result.CrashEvents);
    }

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
                ? $"Рецепт «{descriptor.FriendlyTitle}» успешно выполнен."
                : $"Рецепт «{descriptor.FriendlyTitle}» выполнен. {verdict}",
            TechnicalLogOutput: log,
            RollbackSessionId: committed.SessionId);
    }

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
