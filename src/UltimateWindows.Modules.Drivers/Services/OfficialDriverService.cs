using System.IO.Compression;
using System.Text;
using System.Text.Json;
using UltimateWindows.Core.Contracts;
using UltimateWindows.Core.Enums;
using UltimateWindows.Core.Models;
using UltimateWindows.Modules.Drivers.Analyzers;
using UltimateWindows.Modules.Drivers.Catalog;
using UltimateWindows.Modules.Drivers.Contracts;
using UltimateWindows.Modules.Drivers.Models;

namespace UltimateWindows.Modules.Drivers.Services;

public class DefaultDriverPlatformBridge : IDriverPlatformBridge
{
    public virtual bool IsRunningAsAdministrator() => false;

    public virtual bool VerifyFileAuthenticodeSignature(string filePath) => false;

    public virtual Task<IReadOnlyList<SystemDeviceNode>> EnumerateDevicesAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<SystemDeviceNode>>(Array.Empty<SystemDeviceNode>());

    public virtual Task<IReadOnlyList<OfficialDriverCandidate>> SearchWindowsUpdateDriversAsync(
        IReadOnlyList<SystemDeviceNode> devices,
        CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<OfficialDriverCandidate>>(Array.Empty<OfficialDriverCandidate>());

    public virtual Task<(bool Succeeded, IReadOnlyList<string> ExportedFiles, string ErrorMessage)> ExportSingleOemInfAsync(
        string oemInfName,
        string destinationDirectory,
        CancellationToken ct = default) =>
        Task.FromResult<(bool, IReadOnlyList<string>, string)>((false, Array.Empty<string>(), "Не поддерживается в тестовой среде."));

    public virtual Task<(bool Succeeded, int ExportedPackageCount, string ErrorMessage)> ExportAllDriversAsync(
        string destinationDirectory,
        CancellationToken ct = default) =>
        Task.FromResult((false, 0, "Не поддерживается в тестовой среде."));

    public virtual Task<(bool Succeeded, bool RebootRequired, string ErrorMessage)> InstallWindowsUpdateDriverAsync(
        string updateIdentityId,
        CancellationToken ct = default) =>
        Task.FromResult((false, false, "Не поддерживается в тестовой среде."));

    public virtual Task<(bool Succeeded, IReadOnlyList<string> ExtractedFiles, string ErrorMessage)> ExtractCabArchiveAsync(
        string cabFilePath,
        string destinationDirectory,
        CancellationToken ct = default) =>
        Task.FromResult<(bool, IReadOnlyList<string>, string)>((false, Array.Empty<string>(), "Не поддерживается в тестовой среде."));

    public virtual Task<(bool Succeeded, int AddedCount, string OutputMessage)> AddAndInstallDriverFolderAsync(
        string infDirectory,
        bool installOnDevices = true,
        CancellationToken ct = default) =>
        Task.FromResult((false, 0, "Не поддерживается в тестовой среде."));

    public virtual Task<(bool Succeeded, int ExitCode, string ErrorMessage)> RunSignedInstallerAsync(
        string installerPath,
        string? arguments,
        CancellationToken ct = default) =>
        Task.FromResult((false, -1, "Не поддерживается в тестовой среде."));

    public virtual Task<IReadOnlyList<DriverStoreEntry>> EnumerateDriverStoreAsync(
        IReadOnlyList<SystemDeviceNode> activeDevices,
        CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<DriverStoreEntry>>(Array.Empty<DriverStoreEntry>());

    public virtual Task<(bool Succeeded, string ErrorMessage)> DeleteDriverStorePackageAsync(
        string publishedInfName,
        CancellationToken ct = default) =>
        Task.FromResult((false, "Не поддерживается в тестовой среде."));

    public virtual Task<IReadOnlyList<KernelDriverInventoryEntry>> EnumerateKernelDriversAsync(
        CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<KernelDriverInventoryEntry>>(Array.Empty<KernelDriverInventoryEntry>());

    public virtual (bool IsHvciEnabled, bool IsMicrosoftBlocklistEnabled) ReadCodeIntegrityPosture() => (false, false);

    public virtual (bool Succeeded, int? PreviousValue, string ErrorMessage) SetMicrosoftVulnerableDriverBlocklist(bool enabled) =>
        (false, null, "Не поддерживается в тестовой среде.");

    public virtual (bool Succeeded, int PreviousStartType, string ErrorMessage) DisableKernelDriverService(string serviceName) =>
        (false, 3, "Не поддерживается в тестовой среде.");
}

/// <summary>
/// Сервис Этапа 5 («Драйверы 2.0»):
/// - аудит дерева устройств CfgMgr32, версий, дат, поставщиков и цифровых подписей;
/// - поиск и скачивание подписанных WHQL-драйверов из Windows Update и напрямую с серверов Microsoft Update Catalog (.cab);
/// - каталог из 36 основных драйверов на все случаи жизни с прямым скачиванием с серверов вендоров и Microsoft;
/// - ревизия хранилища DriverStore, полный бэкап/восстановление и безопасная очистка старых дублей с откатом в Zero-Bloat Vault;
/// - конструктор офлайн-набора сетевых и NVMe драйверов («после переустановки нет интернета / не виден SSD»);
/// - аудит и нейтрализация уязвимых драйверов ядра (BYOVD / LOLDrivers / список блокировки Microsoft).
/// </summary>
public sealed class OfficialDriverService
{
    private static readonly HashSet<string> NetworkAndBootCriticalClasses = new(StringComparer.OrdinalIgnoreCase)
    {
        "Net", "Bluetooth", "USB", "SCSIAdapter", "HDC"
    };

    private readonly IVaultService _vaultService;
    private readonly IDriverPlatformBridge _platformBridge;
    private readonly MicrosoftUpdateCatalogClient _catalogClient;

    public OfficialDriverService(
        IVaultService vaultService,
        IDriverPlatformBridge? platformBridge = null,
        MicrosoftUpdateCatalogClient? catalogClient = null)
    {
        _vaultService = vaultService ?? throw new ArgumentNullException(nameof(vaultService));
        _platformBridge = platformBridge ?? new DefaultDriverPlatformBridge();
        _catalogClient = catalogClient ?? new MicrosoftUpdateCatalogClient();
    }

    public static string GetDefaultDownloadRootDirectory() =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "UltimateWindows",
            "DriverDownloads");

    public async Task<DriverAuditReport> AuditDevicesAndDriversAsync(
        bool queryWindowsUpdateCatalog = false,
        CancellationToken ct = default)
    {
        var devices = await _platformBridge.EnumerateDevicesAsync(ct).ConfigureAwait(false);
        var wuCandidates = queryWindowsUpdateCatalog
            ? await _platformBridge.SearchWindowsUpdateDriversAsync(devices, ct).ConfigureAwait(false)
            : Array.Empty<OfficialDriverCandidate>();

        var findings = new List<DriverAuditFinding>();
        var problemCount = 0;
        var basicDisplayCount = 0;
        var updatesMatchedCount = 0;
        var thirdPartyCount = 0;
        var unsignedCount = 0;

        foreach (var dev in devices)
        {
            ct.ThrowIfCancellationRequested();

            if (dev.IsThirdPartyOemInf) thirdPartyCount++;
            if (dev.IsDigitallySigned == false) unsignedCount++;

            OfficialDriverCandidate? bestCandidate = null;
            var bestRank = 0;

            foreach (var cand in wuCandidates)
            {
                if (!cand.IsWhqlVerified) continue;

                var rank = HardwareIdAndProblemAnalyzer.ComputeHardwareIdMatchRank(
                    dev.HardwareIds,
                    cand.MatchedHardwareId,
                    dev.CompatibleIds);

                if (rank > bestRank)
                {
                    bestRank = rank;
                    bestCandidate = cand with { HardwareIdMatchRank = rank };
                }
            }

            var vendorInfo = HardwareIdAndProblemAnalyzer.ResolveOfficialVendorPortal(dev.HardwareIds);

            if (dev.HasProblem)
            {
                problemCount++;
                var (sev, title, explanation) = HardwareIdAndProblemAnalyzer.ExplainProblemCode(dev);
                if (bestCandidate is not null) updatesMatchedCount++;

                findings.Add(new DriverAuditFinding(
                    FindingId: $"prob-{dev.InstanceId}",
                    Severity: sev,
                    Device: dev,
                    SimpleTitle: title,
                    SimpleExplanation: explanation,
                    ExpertTechnicalDetails: $"InstanceId={dev.InstanceId} | ProblemCode={dev.ConfigManagerProblemCode} | HWID={dev.HardwareIds.FirstOrDefault() ?? "N/A"} | INF={dev.InfName}",
                    RecommendedWhqlUpdate: bestCandidate,
                    OfficialVendorUrl: vendorInfo?.OfficialPortalUrl));
            }
            else if (dev.IsBasicDisplayFallback)
            {
                basicDisplayCount++;
                if (bestCandidate is not null) updatesMatchedCount++;

                var vendorLabel = vendorInfo?.VendorName ?? "производителя видеокарты";
                findings.Add(new DriverAuditFinding(
                    FindingId: $"basic-gpu-{dev.InstanceId}",
                    Severity: RiskLevel.Attention,
                    Device: dev,
                    SimpleTitle: $"Видеокарта работает на базовом драйвере Microsoft ({vendorLabel})",
                    SimpleExplanation: "Сейчас используется резервный базовый видеодрайвер Windows: игры тормозят, недоступны высокие герцовки монитора и спящий режим. Установите официальный WHQL-драйвер!",
                    ExpertTechnicalDetails: $"InstanceId={dev.InstanceId} | INF={dev.InfName} | HWID={dev.HardwareIds.FirstOrDefault() ?? "N/A"}",
                    RecommendedWhqlUpdate: bestCandidate,
                    OfficialVendorUrl: vendorInfo?.OfficialPortalUrl));
            }
            else if (bestCandidate is not null)
            {
                // Если версия уже установленного драйвера заведомо новее кандидата — не засоряем список ложным обновлением
                if (!string.IsNullOrWhiteSpace(dev.DriverVersion) &&
                    DriverVersionComparer.TryParseDriverVersion(bestCandidate.DriverVersion, out _) &&
                    DriverVersionComparer.Compare(dev.DriverVersion, dev.DriverDate, bestCandidate.DriverVersion, bestCandidate.DriverVerDate) >= 0)
                {
                    continue;
                }

                updatesMatchedCount++;
                findings.Add(new DriverAuditFinding(
                    FindingId: $"wu-upd-{dev.InstanceId}",
                    Severity: RiskLevel.Safe,
                    Device: dev,
                    SimpleTitle: $"Доступен свежий WHQL-драйвер для «{dev.FriendlyName}»",
                    SimpleExplanation: $"В официальном каталоге Microsoft найдена проверенная версия {bestCandidate.DriverVersion} ({bestCandidate.ProviderName}, точность совпадения ID: {bestCandidate.HardwareIdMatchRank}%).",
                    ExpertTechnicalDetails: $"Current={dev.DriverVersion} ({dev.InfName}) -> WHQL={bestCandidate.DriverVersion} | MatchedHWID={bestCandidate.MatchedHardwareId}",
                    RecommendedWhqlUpdate: bestCandidate,
                    OfficialVendorUrl: vendorInfo?.OfficialPortalUrl));
            }
        }

        var penalty = (problemCount * 18) + (basicDisplayCount * 22) + (unsignedCount * 8);
        var score = Math.Clamp(100 - penalty, 15, 100);

        string headline;
        if (problemCount == 0 && basicDisplayCount == 0 && updatesMatchedCount == 0)
        {
            headline = $"Проверено устройств: {devices.Count} (сторонних INF: {thirdPartyCount}). Все драйверы работают исправно, ошибок (Код 28 / 43) нет.";
        }
        else
        {
            headline = $"Устройств: {devices.Count} • Требуют лечения драйвера: {problemCount + basicDisplayCount} • Доступно WHQL-обновлений: {updatesMatchedCount}.";
        }

        return new DriverAuditReport(
            AuditedAtUtc: DateTimeOffset.UtcNow,
            DriverHealthScore: score,
            TotalDevicesScanned: devices.Count,
            ProblemDeviceCount: problemCount,
            BasicFallbackDisplayCount: basicDisplayCount,
            WhqlUpdatesAvailableCount: updatesMatchedCount,
            SummaryHeadline: headline,
            Findings: findings,
            AllDevices: devices,
            ThirdPartyOemDeviceCount: thirdPartyCount,
            UnsignedDriverDeviceCount: unsignedCount);
    }

    // ==================== КАТАЛОГ ОСНОВНЫХ ДРАЙВЕРОВ И КАТАЛОГ MICROSOFT (.CAB) ====================

    public async Task<IReadOnlyList<EssentialDriverEvaluatedItem>> GetEvaluatedEssentialDriversAsync(
        IReadOnlyList<SystemDeviceNode>? cachedDevices = null,
        CancellationToken ct = default)
    {
        var devices = cachedDevices ?? await _platformBridge.EnumerateDevicesAsync(ct).ConfigureAwait(false);
        return EssentialDriverCatalog.EvaluateForDevices(devices);
    }

    public Task<IReadOnlyList<MicrosoftCatalogDriverEntry>> SearchMicrosoftCatalogAsync(
        string query,
        CancellationToken ct = default) =>
        _catalogClient.SearchDriversAsync(query, preferCurrent64BitOs: true, ct);

    /// <summary>
    /// Скачивает с официального сервера Microsoft выбранный WHQL .cab пакет по его UpdateID,
    /// проверяет криптографическую подпись WinVerifyTrust, распаковывает INF-файлы в папку
    /// и (при installOnThisPc = true) устанавливает их через pnputil с предварительным бэкапом старого драйвера.
    /// </summary>
    public async Task<DriverOperationResult> DownloadOrInstallCatalogUpdateAsync(
        MicrosoftCatalogDriverEntry entry,
        string? targetFolder = null,
        bool installOnThisPc = false,
        IProgress<string>? statusProgress = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(entry);

        if (installOnThisPc && !_platformBridge.IsRunningAsAdministrator())
        {
            return new DriverOperationResult(false, "Для установки драйвера в систему требуются права Администратора (скачивание в папку доступно без них).");
        }

        statusProgress?.Report($"Запрос прямой ссылки на пакет «{entry.Title}» в Каталоге Microsoft...");
        var links = await _catalogClient.ResolveDownloadLinksAsync(entry.UpdateId, ct).ConfigureAwait(false);
        if (links.Count == 0)
        {
            return new DriverOperationResult(false, $"Каталог Microsoft не вернул прямых ссылок для пакета {entry.UpdateId}.");
        }

        var chosen = links.FirstOrDefault(l => l.FileName.EndsWith(".cab", StringComparison.OrdinalIgnoreCase)) ?? links[0];
        var safeSlug = SanitizeFolderName($"{entry.Version}-{entry.UpdateId[..8]}");
        var outDir = Path.Combine(
            string.IsNullOrWhiteSpace(targetFolder) ? GetDefaultDownloadRootDirectory() : targetFolder,
            safeSlug);
        Directory.CreateDirectory(outDir);

        var cabPath = Path.Combine(outDir, SanitizeFileName(chosen.FileName));
        statusProgress?.Report($"Скачивание подписанного пакета {chosen.FileName} с сервера Microsoft...");
        var (dlOk, _, dlErr) = await _catalogClient.DownloadFileVerifiedAsync(
            chosen.DownloadUrl,
            cabPath,
            chosen.DigestBase64,
            percentProgress: null,
            ct: ct).ConfigureAwait(false);

        if (!dlOk || !File.Exists(cabPath))
        {
            return new DriverOperationResult(false, $"Ошибка скачивания с сервера Microsoft: {dlErr}");
        }

        if (!_platformBridge.VerifyFileAuthenticodeSignature(cabPath))
        {
            TryDeleteFile(cabPath);
            return new DriverOperationResult(
                false,
                "Защитный барьер: скачанный .cab файл не прошёл проверку цифровой подписи Microsoft Authenticode и был удалён.");
        }

        var extractedDir = Path.Combine(outDir, "inf");
        Directory.CreateDirectory(extractedDir);
        statusProgress?.Report("Распаковка .cab пакета и подготовка INF-файлов...");
        var (extOk, extractedFiles, extErr) = await _platformBridge.ExtractCabArchiveAsync(cabPath, extractedDir, ct).ConfigureAwait(false);
        if (!extOk || extractedFiles.Count == 0)
        {
            return new DriverOperationResult(
                Succeeded: true,
                UserFriendlyMessage: $"Подписанный WHQL-архив скачан в «{cabPath}» (распаковка: {extErr}).",
                TechnicalDetails: chosen.DownloadUrl,
                OutputPath: cabPath);
        }

        WriteOfflineInstallHelperScript(outDir, entry.Title);

        if (!installOnThisPc)
        {
            return new DriverOperationResult(
                Succeeded: true,
                UserFriendlyMessage: $"Пакет «{entry.Title}» скачан с сервера Microsoft и распакован в «{outDir}» (готов к офлайн-установке и подгрузке в установщике ОС).",
                TechnicalDetails: $"UpdateID={entry.UpdateId}; Files={extractedFiles.Count}",
                OutputPath: outDir);
        }

        statusProgress?.Report("Установка подписанных INF-драйверов через pnputil...");
        var (instOk, addedCount, instMsg) = await _platformBridge.AddAndInstallDriverFolderAsync(extractedDir, installOnDevices: true, ct).ConfigureAwait(false);
        if (!instOk)
        {
            return new DriverOperationResult(
                false,
                $"Пакет скачан в «{outDir}», но установка вернула ошибку: {instMsg}",
                TechnicalDetails: instMsg,
                OutputPath: outDir);
        }

        return new DriverOperationResult(
            Succeeded: true,
            UserFriendlyMessage: $"Драйвер «{entry.Title}» успешно скачан с сервера Microsoft, проверен по подписи и установлен (INF: {addedCount}).",
            TechnicalDetails: instMsg,
            OutputPath: outDir);
    }

    /// <summary>
    /// Скачивает (и при необходимости сразу устанавливает) пакет из «Каталога основных драйверов на все случаи жизни»
    /// либо по прямой постоянной HTTPS-ссылке производителя, либо через живой запрос к серверу Microsoft Update Catalog.
    /// </summary>
    public async Task<DriverOperationResult> DownloadOrInstallEssentialPackageAsync(
        EssentialDriverPackage package,
        string? targetFolder = null,
        bool installOnThisPc = false,
        IProgress<string>? statusProgress = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(package);

        var rootDir = string.IsNullOrWhiteSpace(targetFolder) ? GetDefaultDownloadRootDirectory() : targetFolder;

        if (package.DeliveryKind == EssentialDriverDeliveryKind.MicrosoftCatalogWhql)
        {
            if (string.IsNullOrWhiteSpace(package.CatalogSearchQuery))
            {
                return new DriverOperationResult(false, $"Для пакета «{package.Title}» не задан запрос каталога.");
            }

            statusProgress?.Report($"Поиск актуального WHQL-выпуска для «{package.Title}» ({package.CatalogSearchQuery})...");
            var matches = await _catalogClient.SearchDriversAsync(package.CatalogSearchQuery, preferCurrent64BitOs: true, ct).ConfigureAwait(false);
            if (matches.Count == 0)
            {
                return new DriverOperationResult(
                    false,
                    $"Сервер Каталога Microsoft сейчас не вернул пакетов по запросу {package.CatalogSearchQuery}. Вы можете открыть официальную страницу вендора: {package.OfficialPortalUrl}");
            }

            var pkgFolder = Path.Combine(rootDir, SanitizeFolderName(package.Id));
            return await DownloadOrInstallCatalogUpdateAsync(matches[0], pkgFolder, installOnThisPc, statusProgress, ct).ConfigureAwait(false);
        }

        // DirectHttps — прямая вечная HTTPS-ссылка с официального сервера вендора
        if (string.IsNullOrWhiteSpace(package.DirectDownloadUrl) ||
            !package.DirectDownloadUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return new DriverOperationResult(false, "Прямая ссылка должна использовать защищённый протокол HTTPS.");
        }

        if (installOnThisPc && !_platformBridge.IsRunningAsAdministrator())
        {
            return new DriverOperationResult(false, "Для установки драйвера требуются права Администратора (скачивание в папку доступно без них).");
        }

        var destSubDir = Path.Combine(rootDir, SanitizeFolderName(package.Id));
        Directory.CreateDirectory(destSubDir);

        var fileName = GuessFileNameFromUrl(package.DirectDownloadUrl, package.Id);
        var filePath = Path.Combine(destSubDir, fileName);

        statusProgress?.Report($"Прямое скачивание «{package.Title}» с официального сервера {package.Vendor}...");
        var (ok, _, err) = await _catalogClient.DownloadFileVerifiedAsync(
            package.DirectDownloadUrl,
            filePath,
            expectedDigestBase64: null,
            percentProgress: null,
            ct: ct).ConfigureAwait(false);

        if (!ok || !File.Exists(filePath))
        {
            return new DriverOperationResult(false, $"Не удалось скачать пакет с сервера {package.Vendor}: {err}");
        }

        var ext = Path.GetExtension(filePath).ToLowerInvariant();
        if (ext == ".zip")
        {
            var unpackDir = Path.Combine(destSubDir, "extracted");
            TryDeleteDirectory(unpackDir);
            ZipFile.ExtractToDirectory(filePath, unpackDir, overwriteFiles: true);
            WriteOfflineInstallHelperScript(destSubDir, package.Title);

            // Проверяем подпись .cat/.sys/.exe внутри распакованного архива
            var signable = Directory.GetFiles(unpackDir, "*", SearchOption.AllDirectories)
                .Where(f => f.EndsWith(".cat", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (signable.Count > 0 && signable.Any(f => !_platformBridge.VerifyFileAuthenticodeSignature(f)))
            {
                TryDeleteDirectory(unpackDir);
                TryDeleteFile(filePath);
                return new DriverOperationResult(false, "Защитный барьер: файлы внутри скачанного архива не прошли проверку цифровой подписи.");
            }

            if (!installOnThisPc)
            {
                return new DriverOperationResult(
                    true,
                    $"Архив драйвера «{package.Title}» скачан с сервера {package.Vendor} и распакован в «{destSubDir}».",
                    OutputPath: destSubDir);
            }

            var (addOk, added, addMsg) = await _platformBridge.AddAndInstallDriverFolderAsync(unpackDir, installOnDevices: true, ct).ConfigureAwait(false);
            return new DriverOperationResult(
                addOk,
                addOk
                    ? $"Драйвер «{package.Title}» скачан, проверен по подписи и установлен (INF: {added})."
                    : $"Архив скачан в «{destSubDir}», но установка завершилась с ошибкой: {addMsg}",
                TechnicalDetails: addMsg,
                OutputPath: destSubDir);
        }

        if (ext == ".iso")
        {
            return new DriverOperationResult(
                true,
                $"Образ «{fileName}» успешно скачан с официального сервера в «{filePath}». Смонтируйте его двойным щелчком или подключите к ВМ.",
                OutputPath: filePath);
        }

        // .exe / .msi — проверяем цифровую подпись WinVerifyTrust перед любым запуском!
        if (!_platformBridge.VerifyFileAuthenticodeSignature(filePath))
        {
            TryDeleteFile(filePath);
            return new DriverOperationResult(
                false,
                "Защитный барьер: скачанный установщик не прошёл криптографическую проверку подписи Authenticode и был удалён.");
        }

        if (!installOnThisPc)
        {
            return new DriverOperationResult(
                true,
                $"Подписанный установщик «{package.Title}» скачан с сервера {package.Vendor} в «{filePath}».",
                OutputPath: filePath);
        }

        statusProgress?.Report($"Запуск подписанного установщика «{package.Title}»...");
        var (runOk, exitCode, runErr) = await _platformBridge.RunSignedInstallerAsync(filePath, package.SilentInstallArgs, ct).ConfigureAwait(false);
        return new DriverOperationResult(
            runOk,
            runOk
                ? $"Пакет «{package.Title}» успешно установлен (код завершения {exitCode})."
                : $"Установщик скачан в «{filePath}», но вернул код {exitCode}: {runErr}",
            OutputPath: filePath);
    }

    // ==================== ХРАНИЛИЩЕ DRIVERSTORE, БЭКАП И ОЧИСТКА СТАРЫХ ДУБЛЕЙ ====================

    public async Task<DriverStoreAuditSummary> AuditDriverStoreAsync(CancellationToken ct = default)
    {
        var devices = await _platformBridge.EnumerateDevicesAsync(ct).ConfigureAwait(false);
        var rawEntries = await _platformBridge.EnumerateDriverStoreAsync(devices, ct).ConfigureAwait(false);

        // Находим устаревшие дубликаты одного и того же пакета (одинаковые OriginalInfName + ClassName + ProviderName)
        var enriched = new List<DriverStoreEntry>(rawEntries.Count);
        var groups = rawEntries
            .GroupBy(e => $"{e.OriginalInfName.ToLowerInvariant()}|{e.ClassName.ToLowerInvariant()}|{e.ProviderName.ToLowerInvariant()}");

        foreach (var grp in groups)
        {
            var ordered = grp
                .OrderByDescending(e => e, Comparer<DriverStoreEntry>.Create((a, b) =>
                    DriverVersionComparer.Compare(a.DriverVersion, a.DriverDate, b.DriverVersion, b.DriverDate)))
                .ToList();

            var newest = ordered[0];
            enriched.Add(newest with { IsSupersededDuplicate = false, SupersededByVersion = null });

            for (int i = 1; i < ordered.Count; i++)
            {
                var item = ordered[i];
                bool isOldUnused = !item.IsInUseByDevice &&
                                   !string.IsNullOrWhiteSpace(item.OriginalInfName);

                enriched.Add(item with
                {
                    IsSupersededDuplicate = isOldUnused,
                    SupersededByVersion = isOldUnused ? newest.DriverVersion : null
                });
            }
        }

        var sorted = enriched
            .OrderByDescending(e => e.IsSupersededDuplicate)
            .ThenByDescending(e => e.SizeBytes)
            .ToList();

        long totalBytes = sorted.Sum(e => e.SizeBytes);
        var duplicates = sorted.Where(e => e.IsSupersededDuplicate).ToList();
        long dupBytes = duplicates.Sum(e => e.SizeBytes);

        var headline = duplicates.Count > 0
            ? $"Пакетов в DriverStore: {sorted.Count} ({ByteFormatter.Format(totalBytes)}) • Найдено старых дублей: {duplicates.Count} (можно освободить {ByteFormatter.Format(dupBytes)})"
            : $"Пакетов в DriverStore: {sorted.Count} ({ByteFormatter.Format(totalBytes)}) • Старых неиспользуемых дублей не обнаружено.";

        return new DriverStoreAuditSummary(
            Entries: sorted,
            TotalStoreSizeBytes: totalBytes,
            DuplicateOldCount: duplicates.Count,
            ReclaimableDuplicateBytes: dupBytes,
            Headline: headline);
    }

    public async Task<DriverOperationResult> CleanOldDriverStoreDuplicatesAsync(
        IReadOnlyList<DriverStoreEntry>? candidates = null,
        CancellationToken ct = default)
    {
        if (!_platformBridge.IsRunningAsAdministrator())
        {
            return new DriverOperationResult(false, "Для очистки хранилища DriverStore требуются права Администратора.");
        }

        var store = candidates ?? (await AuditDriverStoreAsync(ct).ConfigureAwait(false)).Entries;
        var toRemove = store.Where(e => e.IsSupersededDuplicate && !e.IsInUseByDevice).ToList();
        if (toRemove.Count == 0)
        {
            return new DriverOperationResult(true, "В хранилище DriverStore нет устаревших неиспользуемых дублей для удаления.");
        }

        int removedCount = 0;
        long freedBytes = 0;
        var errors = new List<string>();

        foreach (var entry in toRemove)
        {
            ct.ThrowIfCancellationRequested();

            // Сначала делаем компактный страховочный бэкап пакета в Машину времени!
            var tempExport = Path.Combine(Path.GetTempPath(), "uw-ds-clean-" + Guid.NewGuid().ToString("N"));
            var zipPath = Path.Combine(Path.GetTempPath(), $"uw-ds-{entry.PublishedInfName}-{Guid.NewGuid():N}.zip");

            try
            {
                Directory.CreateDirectory(tempExport);
                var (expOk, expFiles, _) = await _platformBridge.ExportSingleOemInfAsync(entry.PublishedInfName, tempExport, ct).ConfigureAwait(false);
                if (expOk && expFiles.Count > 0)
                {
                    ZipFile.CreateFromDirectory(tempExport, zipPath, CompressionLevel.Optimal, includeBaseDirectory: false);
                    await using var tx = _vaultService.BeginTransaction(
                        SystemDomain.HardwareAndDrivers,
                        friendlyTitle: $"Очистка старого дубля DriverStore: {entry.OriginalInfName} ({entry.DriverVersion})",
                        friendlySummary: $"Удалён неиспользуемый пакет {entry.PublishedInfName} (актуальная версия: {entry.SupersededByVersion}). Доступен откат.",
                        technicalDetails: $"INF={entry.PublishedInfName}; Original={entry.OriginalInfName}; Version={entry.DriverVersion}");

                    var metaJson = JsonSerializer.Serialize(new
                    {
                        InfName = entry.PublishedInfName,
                        DeviceName = entry.OriginalInfName,
                        DriverVersion = entry.DriverVersion,
                        RestoredArchivePath = zipPath
                    });

                    tx.RecordStateDelta(
                        StateTargetKind.SystemSetting,
                        $"DriverInfBackup:{entry.PublishedInfName}",
                        previousStateJson: metaJson,
                        newStateJson: null);

                    _ = await tx.QuarantineFileAsync(zipPath, ct).ConfigureAwait(false);
                    await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);
                }

                var (delOk, delErr) = await _platformBridge.DeleteDriverStorePackageAsync(entry.PublishedInfName, ct).ConfigureAwait(false);
                if (delOk)
                {
                    removedCount++;
                    freedBytes += entry.SizeBytes;
                }
                else
                {
                    errors.Add($"{entry.PublishedInfName}: {delErr}");
                }
            }
            finally
            {
                TryDeleteDirectory(tempExport);
                TryDeleteFile(zipPath);
            }
        }

        return new DriverOperationResult(
            Succeeded: removedCount > 0,
            UserFriendlyMessage: removedCount > 0
                ? $"Очищено старых дублей DriverStore: {removedCount} из {toRemove.Count} (освобождено ~{ByteFormatter.Format(freedBytes)}, страховочные копии сохранены в Машине времени)."
                : $"Не удалось удалить пакеты DriverStore: {string.Join("; ", errors.Take(3))}",
            TechnicalDetails: string.Join("\n", errors));
    }

    public async Task<DriverOperationResult> BackupAllThirdPartyDriversAsync(
        string destinationFolder,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(destinationFolder))
        {
            return new DriverOperationResult(false, "Укажите целевую папку для полного бэкапа драйверов.");
        }

        if (!_platformBridge.IsRunningAsAdministrator())
        {
            return new DriverOperationResult(false, "Для экспорта всех драйверов из DriverStore требуются права Администратора.");
        }

        Directory.CreateDirectory(destinationFolder);
        var (ok, count, err) = await _platformBridge.ExportAllDriversAsync(destinationFolder, ct).ConfigureAwait(false);
        if (!ok)
        {
            return new DriverOperationResult(false, $"Не удалось экспортировать драйверы: {err}");
        }

        var scriptPath = WriteOfflineInstallHelperScript(destinationFolder, "Полная резервная копия всех сторонних драйверов ПК");
        return new DriverOperationResult(
            true,
            $"Полный бэкап драйверов завершён: экспортировано пакетов — {count} в «{destinationFolder}» (создан скрипт {Path.GetFileName(scriptPath)}).",
            OutputPath: destinationFolder);
    }

    public async Task<DriverOperationResult> RestoreDriversFromFolderAsync(
        string sourceFolder,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(sourceFolder) || !Directory.Exists(sourceFolder))
        {
            return new DriverOperationResult(false, "Папка с резервной копией драйверов не найдена.");
        }

        if (!_platformBridge.IsRunningAsAdministrator())
        {
            return new DriverOperationResult(false, "Для установки драйверов из резервной копии требуются права Администратора.");
        }

        var (ok, addedCount, msg) = await _platformBridge.AddAndInstallDriverFolderAsync(sourceFolder, installOnDevices: true, ct).ConfigureAwait(false);
        return new DriverOperationResult(
            ok,
            ok
                ? $"Драйверы успешно восстановлены и установлены из «{sourceFolder}» (обработано INF: {addedCount})."
                : $"Ошибка при восстановлении драйверов: {msg}",
            TechnicalDetails: msg,
            OutputPath: sourceFolder);
    }

    // ==================== ОФЛАЙН-НАБОР СЕТЕВЫХ И NVME ДРАЙВЕРОВ («ПОСЛЕ ПЕРЕУСТАНОВКИ НЕТ ИНТЕРНЕТА») ====================

    public async Task<OfflineRescuePackResult> BuildOfflineNetworkRescuePackAsync(
        string targetDirectory,
        bool downloadUniversalFromServers = false,
        IProgress<string>? statusProgress = null,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(targetDirectory))
        {
            return new OfflineRescuePackResult(false, "", 0, 0, "", "Укажите папку или флешку для сохранения спасательного набора.", []);
        }

        Directory.CreateDirectory(targetDirectory);
        var details = new List<string>();
        int count = 0;

        if (!downloadUniversalFromServers)
        {
            if (!_platformBridge.IsRunningAsAdministrator())
            {
                return new OfflineRescuePackResult(
                    false,
                    targetDirectory,
                    0,
                    0,
                    "",
                    "Для экспорта текущих сетевых драйверов этого ПК требуются права Администратора (либо включите режим скачивания универсального набора с серверов).",
                    []);
            }

            var devices = await _platformBridge.EnumerateDevicesAsync(ct).ConfigureAwait(false);
            var netInfNames = devices
                .Where(d => d.IsThirdPartyOemInf && NetworkAndBootCriticalClasses.Contains(d.DeviceClass))
                .Select(d => (d.InfName, d.FriendlyName, d.DeviceClass))
                .DistinctBy(x => x.InfName, StringComparer.OrdinalIgnoreCase)
                .ToList();

            foreach (var (inf, friendly, cls) in netInfNames)
            {
                ct.ThrowIfCancellationRequested();
                statusProgress?.Report($"Экспорт драйвера «{friendly}» ({inf})...");
                var sub = Path.Combine(targetDirectory, SanitizeFolderName($"{cls}-{inf}"));
                Directory.CreateDirectory(sub);
                var (ok, files, err) = await _platformBridge.ExportSingleOemInfAsync(inf, sub, ct).ConfigureAwait(false);
                if (ok && files.Count > 0)
                {
                    count++;
                    details.Add($"[Экспортирован с ПК] {friendly} ({inf}, файлов: {files.Count})");
                }
                else
                {
                    details.Add($"[Пропуск] {friendly} ({inf}): {err}");
                }
            }

            if (count == 0)
            {
                // На чистой/виртуальной системе сетевые карты могут работать на штатных драйверах Windows (netkvm/e1i65x64/rndis)
                var scriptEmpty = WriteOfflineInstallHelperScript(targetDirectory, "Офлайн-набор сетевых драйверов этого ПК");
                return new OfflineRescuePackResult(
                    Succeeded: true,
                    TargetDirectory: targetDirectory,
                    ExportedOrDownloadedCount: 0,
                    TotalBytes: ComputeDirectorySize(targetDirectory),
                    InstallScriptPath: scriptEmpty,
                    UserFriendlyMessage: "На этом ПК сеть и диски используют встроенные драйверы Windows (сторонних oemXX.inf для сети нет). Вы можете скачать универсальный набор с серверов для любых ПК!",
                    Details: details);
            }
        }
        else
        {
            var rescuePackages = EssentialDriverCatalog.GetAllPackages()
                .Where(p => p.IncludeInUniversalNetworkRescuePack)
                .ToList();

            foreach (var pkg in rescuePackages)
            {
                ct.ThrowIfCancellationRequested();
                var res = await DownloadOrInstallEssentialPackageAsync(
                    pkg,
                    targetFolder: targetDirectory,
                    installOnThisPc: false,
                    statusProgress: statusProgress,
                    ct: ct).ConfigureAwait(false);

                if (res.Succeeded)
                {
                    count++;
                    details.Add($"[Скачан с сервера] {pkg.Title}");
                }
                else
                {
                    details.Add($"[Не удалось скачать] {pkg.Title}: {res.UserFriendlyMessage}");
                }
            }
        }

        var script = WriteOfflineInstallHelperScript(targetDirectory, "Спасательный офлайн-набор сетевых и NVMe драйверов");
        long bytes = ComputeDirectorySize(targetDirectory);

        return new OfflineRescuePackResult(
            Succeeded: count > 0,
            TargetDirectory: targetDirectory,
            ExportedOrDownloadedCount: count,
            TotalBytes: bytes,
            InstallScriptPath: script,
            UserFriendlyMessage: count > 0
                ? $"Готово! Офлайн-набор ({count} пакет(ов), {ByteFormatter.Format(bytes)}) сохранён в «{targetDirectory}». На новом ПК без интернета просто запустите {Path.GetFileName(script)} от имени Администратора!"
                : "Не удалось сформировать пакеты спасательного набора. Проверьте подключение к интернету.",
            Details: details);
    }

    // ==================== АУДИТ И ОБЕЗВРЕЖИВАНИЕ УЯЗВИМЫХ ДРАЙВЕРОВ ЯДРА (BYOVD) ====================

    public async Task<VulnerableDriverAuditReport> AuditVulnerableKernelDriversAsync(CancellationToken ct = default)
    {
        var (hvci, blocklist) = _platformBridge.ReadCodeIntegrityPosture();
        var inventory = await _platformBridge.EnumerateKernelDriversAsync(ct).ConfigureAwait(false);
        var findings = VulnerableDriverCatalog.AuditInventory(inventory);

        string postureText = $"HVCI (Целостность памяти): {(hvci ? "ВКЛ" : "выкл")} • Блок-лист уязвимых драйверов Microsoft: {(blocklist ? "ВКЛ" : "ВЫКЛ (!)")}";
        string headline = findings.Count == 0
            ? $"Проверено драйверов ядра: {inventory.Count}. Уязвимых драйверов (BYOVD / WinRing0 / RTCore64) не обнаружено. {postureText}"
            : $"ВНИМАНИЕ: найдено уязвимых драйверов ядра: {findings.Count} (из {inventory.Count} проверенных)! {postureText}";

        return new VulnerableDriverAuditReport(
            IsHvciEnabled: hvci,
            IsMicrosoftBlocklistEnabled: blocklist,
            TotalKernelDriversScanned: inventory.Count,
            Findings: findings,
            SummaryHeadline: headline);
    }

    public async Task<DriverOperationResult> EnableMicrosoftVulnerableDriverBlocklistAsync(CancellationToken ct = default)
    {
        if (!_platformBridge.IsRunningAsAdministrator())
        {
            return new DriverOperationResult(false, "Для включения системного списка блокировки уязвимых драйверов требуются права Администратора.");
        }

        var (ok, prevVal, err) = _platformBridge.SetMicrosoftVulnerableDriverBlocklist(enabled: true);
        if (!ok)
        {
            return new DriverOperationResult(false, $"Не удалось изменить политику Code Integrity: {err}");
        }

        await using var tx = _vaultService.BeginTransaction(
            SystemDomain.HardwareAndDrivers,
            friendlyTitle: "Включение списка блокировки уязвимых драйверов Microsoft (CI Blocklist)",
            friendlySummary: "Запрещена загрузка эксплуатируемых драйверов ядра (BYOVD). Вступает в силу после перезагрузки.",
            technicalDetails: @"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config\VulnerableDriverBlocklistEnable = 1");

        tx.RecordStateDelta(
            StateTargetKind.SystemSetting,
            "CiVulnerableDriverBlocklist",
            previousStateJson: JsonSerializer.Serialize(new { PreviousValue = prevVal }),
            newStateJson: JsonSerializer.Serialize(new { PreviousValue = 1 }));

        var committed = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);
        return new DriverOperationResult(
            true,
            "Список блокировки уязвимых драйверов Microsoft включён! Защита полностью активируется после перезагрузки (точка отката сохранена).",
            RollbackSessionId: committed.SessionId);
    }

    public async Task<DriverOperationResult> NeutralizeVulnerableKernelDriverAsync(
        VulnerableDriverFinding finding,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(finding);

        if (!finding.CanSafelyNeutralize)
        {
            return new DriverOperationResult(false, "Этот драйвер помечен как загрузочный и не может быть автоматически отключён без риска для старта ОС.");
        }

        if (!_platformBridge.IsRunningAsAdministrator())
        {
            return new DriverOperationResult(false, "Для отключения и изоляции драйвера ядра требуются права Администратора.");
        }

        var drv = finding.InstalledDriver;
        var (svcOk, prevStart, svcErr) = _platformBridge.DisableKernelDriverService(drv.ServiceName);
        if (!svcOk)
        {
            return new DriverOperationResult(false, $"Не удалось отключить службу драйвера «{drv.ServiceName}»: {svcErr}");
        }

        await using var tx = _vaultService.BeginTransaction(
            SystemDomain.HardwareAndDrivers,
            friendlyTitle: $"Изоляция уязвимого драйвера ядра: {finding.MatchedRule.FamilyName} ({drv.ServiceName})",
            friendlySummary: $"Служба «{drv.ServiceName}» отключена ({finding.MatchedRule.CveOrAdvisory}), файл помещён в карантин .uwq с возвратом в 1 клик.",
            technicalDetails: $"Service={drv.ServiceName}; Path={drv.BinaryPath}; PrevStart={prevStart}");

        tx.RecordStateDelta(
            StateTargetKind.SystemSetting,
            $"KernelDriverService:{drv.ServiceName}",
            previousStateJson: JsonSerializer.Serialize(new { ServiceName = drv.ServiceName, StartType = prevStart }),
            newStateJson: JsonSerializer.Serialize(new { ServiceName = drv.ServiceName, StartType = 4 }));

        if (drv.FileExists && !string.IsNullOrWhiteSpace(drv.BinaryPath) && File.Exists(drv.BinaryPath))
        {
            try
            {
                File.SetAttributes(drv.BinaryPath, FileAttributes.Normal);
                _ = await tx.QuarantineFileAsync(drv.BinaryPath, ct).ConfigureAwait(false);
            }
            catch
            {
                // Если драйвер прямо сейчас загружен в ядро и удерживает блокировку .sys — отключение Start=4 обезвредит его после перезагрузки
            }
        }

        var committed = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);
        return new DriverOperationResult(
            true,
            $"Уязвимый драйвер «{finding.MatchedRule.FamilyName}» ({drv.ServiceName}) обезврежен! Точка отката сохранена в Машине времени.",
            RollbackSessionId: committed.SessionId);
    }

    // ==================== СУЩЕСТВУЮЩИЕ МЕТОДЫ БЭКАПА ОДИНОЧНОГО INF И УСТАНОВКИ WINDOWS UPDATE ====================

    public async Task<DriverOperationResult> BackupDeviceDriverToVaultAsync(
        SystemDeviceNode device,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(device);

        if (!device.IsThirdPartyOemInf)
        {
            return new DriverOperationResult(
                false,
                "Устройство использует встроенный системный драйвер Windows (не oemXX.inf) — он уже защищен хранилищем WinSxS и не требует отдельного бэкапа.");
        }

        var tempStaging = Path.Combine(Path.GetTempPath(), "uw-drv-export-" + Guid.NewGuid().ToString("N"));
        var archiveFile = Path.Combine(Path.GetTempPath(), $"uw-drv-{device.InfName}-{Guid.NewGuid():N}.zip");

        try
        {
            Directory.CreateDirectory(tempStaging);
            var (ok, exported, err) = await _platformBridge.ExportSingleOemInfAsync(device.InfName, tempStaging, ct).ConfigureAwait(false);
            if (!ok || exported.Count == 0)
            {
                return new DriverOperationResult(
                    false,
                    $"Не удалось экспортировать пакет {device.InfName}: {(string.IsNullOrWhiteSpace(err) ? "требуются права Администратора." : err)}");
            }

            ZipFile.CreateFromDirectory(tempStaging, archiveFile, CompressionLevel.Optimal, includeBaseDirectory: false);

            await using var tx = _vaultService.BeginTransaction(
                SystemDomain.HardwareAndDrivers,
                friendlyTitle: $"Компактный бэкап драйвера: {device.FriendlyName} ({device.InfName})",
                friendlySummary: $"Сохранен пакет {device.DriverVersion} с автоочисткой по квоте Zero-Bloat Vault.",
                technicalDetails: $"InstanceId={device.InstanceId}; INF={device.InfName}; Files={exported.Count}");

            var metaJson = JsonSerializer.Serialize(new
            {
                InfName = device.InfName,
                DeviceName = device.FriendlyName,
                DriverVersion = device.DriverVersion,
                RestoredArchivePath = archiveFile
            });

            tx.RecordStateDelta(
                StateTargetKind.SystemSetting,
                $"DriverInfBackup:{device.InfName}",
                previousStateJson: metaJson,
                newStateJson: null);

            var archiveSha256 = await tx.QuarantineFileAsync(archiveFile, ct).ConfigureAwait(false);

            var committed = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);
            return new DriverOperationResult(
                Succeeded: true,
                UserFriendlyMessage: $"Драйвер «{device.FriendlyName}» ({device.InfName}) компактно сжат в Машину времени без мусора на диске!",
                TechnicalDetails: $"SHA-256: {archiveSha256}",
                RollbackSessionId: committed.SessionId);
        }
        finally
        {
            TryDeleteDirectory(tempStaging);
            TryDeleteFile(archiveFile);
        }
    }

    public async Task<DriverOperationResult> InstallOfficialWhqlDriverAsync(
        SystemDeviceNode device,
        OfficialDriverCandidate candidate,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(candidate);

        if (!candidate.IsWhqlVerified || candidate.SourceKind != DriverSourceKind.WindowsUpdateWhqlCatalog)
        {
            return new DriverOperationResult(
                false,
                "Защитный барьер: автоматическая установка разрешена только для драйверов с цифровой подписью Microsoft WHQL.");
        }

        var rank = HardwareIdAndProblemAnalyzer.ComputeHardwareIdMatchRank(
            device.HardwareIds,
            candidate.MatchedHardwareId,
            device.CompatibleIds);

        if (rank == 0)
        {
            return new DriverOperationResult(
                false,
                "Защитный барьер OEM SUBSYS: пакет предназначен для другой ревизии платы и заблокирован во избежание сбоя оборудования.");
        }

        if (!_platformBridge.IsRunningAsAdministrator())
        {
            return new DriverOperationResult(
                false,
                "Для установки подписанного системного драйвера перезапустите Ultimate Windows от имени Администратора.");
        }

        Guid? rollbackId = null;
        if (device.IsThirdPartyOemInf)
        {
            var backup = await BackupDeviceDriverToVaultAsync(device, ct).ConfigureAwait(false);
            if (backup.Succeeded)
            {
                rollbackId = backup.RollbackSessionId;
            }
        }

        var (ok, reboot, err) = await _platformBridge
            .InstallWindowsUpdateDriverAsync(candidate.UpdateIdentityId, ct)
            .ConfigureAwait(false);

        if (!ok)
        {
            return new DriverOperationResult(
                false,
                $"Не удалось установить драйвер через службу Windows Update: {err}",
                TechnicalDetails: $"UpdateID={candidate.UpdateIdentityId}",
                RollbackSessionId: rollbackId);
        }

        var rebootNotice = reboot ? " Перезагрузите компьютер для завершения инициализации устройства." : "";
        return new DriverOperationResult(
            Succeeded: true,
            UserFriendlyMessage: $"Официальный WHQL-драйвер «{candidate.Title}» успешно установлен!{rebootNotice}",
            TechnicalDetails: $"UpdateID={candidate.UpdateIdentityId}; Rank={rank}%",
            RollbackSessionId: rollbackId);
    }

    private static string WriteOfflineInstallHelperScript(string targetDirectory, string packTitle)
    {
        var cmdPath = Path.Combine(targetDirectory, "Install-OfflineDrivers.cmd");
        var readmePath = Path.Combine(targetDirectory, "README-КАК-УСТАНОВИТЬ.txt");

        var cmdContent = """
            @echo off
            chcp 65001 >nul
            title Ultimate Windows — Офлайн-установка подписанных драйверов
            echo ============================================================================
            echo   Ultimate Windows — Установка офлайн-пакетов драйверов через pnputil
            echo ============================================================================
            net session >nul 2>&1
            if %errorLevel% neq 0 (
                echo [!] Нажмите правой кнопкой мыши на этот файл и выберите «Запуск от имени администратора»!
                pause
                exit /b 1
            )
            echo Установка всех найденных подписанных INF-пакетов из текущей папки и подпапок...
            "%SystemRoot%\System32\pnputil.exe" /add-driver "%~dp0*.inf" /subdirs /install
            echo.
            echo Готово! При необходимости перезагрузите компьютер.
            pause
            """;

        var readmeContent = $"""
            Ultimate Windows v2.0 — {packTitle}
            Сформировано: {DateTimeOffset.Now:yyyy-MM-dd HH:mm}

            СЦЕНАРИЙ 1 — После переустановки Windows нет интернета (LAN / Wi-Fi / USB-модем):
              1. Скопируйте эту папку на флешку и откройте на целевом ПК.
              2. Нажмите правой кнопкой мыши по файлу Install-OfflineDrivers.cmd -> «Запуск от имени администратора».
              3. Штатная утилита pnputil.exe автоматически подберёт и установит нужные драйверы сети.

            СЦЕНАРИЙ 2 — Установщик Windows 10/11 не видит NVMe SSD («Мы не нашли дисков»):
              1. На экране выбора диска в установщике Windows нажмите «Загрузить драйвер» -> «Обзор».
              2. Укажите папку storage-intel-rst-vmd\inf (или вложенную папку с .inf файлами контроллера).
              3. Выберите контроллер Intel VMD / AMD RAID — список разделов SSD сразу появится!
            """;

        File.WriteAllText(cmdPath, cmdContent, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        File.WriteAllText(readmePath, readmeContent, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
        return cmdPath;
    }

    private static string GuessFileNameFromUrl(string url, string fallbackId)
    {
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            var leaf = Path.GetFileName(uri.AbsolutePath);
            if (!string.IsNullOrWhiteSpace(leaf) && Path.HasExtension(leaf))
            {
                return SanitizeFileName(leaf);
            }
        }

        // Например https://dsadata.intel.com/installer -> Intel-DSA-Installer.exe
        return SanitizeFileName($"{fallbackId}-installer.exe");
    }

    private static string SanitizeFolderName(string raw)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var cleaned = new string(raw.Select(c => invalid.Contains(c) || c == ' ' ? '-' : c).ToArray()).Trim('-');
        return string.IsNullOrWhiteSpace(cleaned) ? "driver-pkg" : cleaned;
    }

    private static string SanitizeFileName(string raw)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var cleaned = new string(raw.Select(c => invalid.Contains(c) ? '_' : c).ToArray());
        return string.IsNullOrWhiteSpace(cleaned) ? "package.bin" : cleaned;
    }

    private static long ComputeDirectorySize(string path)
    {
        if (!Directory.Exists(path)) return 0;
        long sum = 0;
        foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
        {
            try { sum += new FileInfo(file).Length; } catch { }
        }

        return sum;
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path)) File.Delete(path);
        }
        catch
        {
            // Ignore temp cleanup failure
        }
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path)) Directory.Delete(path, recursive: true);
        }
        catch
        {
            // Ignore temp cleanup failure
        }
    }
}
