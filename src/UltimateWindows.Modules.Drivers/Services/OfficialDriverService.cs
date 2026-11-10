using System.IO.Compression;
using System.Text.Json;
using UltimateWindows.Core.Contracts;
using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Drivers.Analyzers;
using UltimateWindows.Modules.Drivers.Contracts;
using UltimateWindows.Modules.Drivers.Models;

namespace UltimateWindows.Modules.Drivers.Services;

public class DefaultDriverPlatformBridge : IDriverPlatformBridge
{
    public virtual bool IsRunningAsAdministrator() => false;

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

    public virtual Task<(bool Succeeded, bool RebootRequired, string ErrorMessage)> InstallWindowsUpdateDriverAsync(
        string updateIdentityId,
        CancellationToken ct = default) =>
        Task.FromResult((false, false, "Не поддерживается в тестовой среде."));
}

/// <summary>
/// Сервис Фазы 6: безопасный поиск, проверка и установка официальных WHQL-драйверов по полному 4-компонентному Hardware ID
/// с компактным селективным бэкапом текущего пакета oemXX.inf в Zero-Bloat Vault (без засорения диска гигабайтными копиями DriverStore).
/// </summary>
public sealed class OfficialDriverService
{
    private readonly IVaultService _vaultService;
    private readonly IDriverPlatformBridge _platformBridge;

    public OfficialDriverService(
        IVaultService vaultService,
        IDriverPlatformBridge? platformBridge = null)
    {
        _vaultService = vaultService ?? throw new ArgumentNullException(nameof(vaultService));
        _platformBridge = platformBridge ?? new DefaultDriverPlatformBridge();
    }

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

        foreach (var dev in devices)
        {
            ct.ThrowIfCancellationRequested();

            OfficialDriverCandidate? bestCandidate = null;
            var bestRank = 0;

            foreach (var cand in wuCandidates)
            {
                if (!cand.IsWhqlVerified) continue;

                var rank = HardwareIdAndProblemAnalyzer.ComputeHardwareIdMatchRank(dev.HardwareIds, cand.MatchedHardwareId);
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

        var penalty = (problemCount * 18) + (basicDisplayCount * 22);
        var score = Math.Clamp(100 - penalty, 15, 100);

        string headline;
        if (problemCount == 0 && basicDisplayCount == 0 && updatesMatchedCount == 0)
        {
            headline = $"✅ Проверено устройств: {devices.Count}. Все драйверы работают исправно, ошибок (Код 28 / Код 43) нет!";
        }
        else
        {
            headline = $"🔍 Устройств: {devices.Count} • Требуют лечения драйвера: {problemCount + basicDisplayCount} • Доступно WHQL-обновлений: {updatesMatchedCount}.";
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
            AllDevices: devices);
    }

    /// <summary>
    /// Делает селективный компактный бэкап ТОЛЬКО одного пакета драйвера (oemXX.inf) в сжатое хранилище Zero-Bloat Vault,
    /// не засоряя диск многогигабайтными копиями всей папки DriverStore.
    /// </summary>
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

            // Записываем системную дельту ПЕРЕД QuarantineFileAsync, чтобы при LIFO-откате
            // сначала распаковался .zip из .uwq, а затем pnputil /add-driver установил его и удалил временный архив!
            tx.RecordStateDelta(
                StateTargetKind.SystemSetting,
                $"DriverInfBackup:{device.InfName}",
                previousStateJson: metaJson,
                newStateJson: null);

            var archiveSha256 = await tx.QuarantineFileAsync(archiveFile, ct).ConfigureAwait(false);

            var committed = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);
            return new DriverOperationResult(
                Succeeded: true,
                UserFriendlyMessage: $"📦 Драйвер «{device.FriendlyName}» ({device.InfName}) компактно сжат в Машину времени без мусора на диске!",
                TechnicalDetails: $"SHA-256: {archiveSha256}",
                RollbackSessionId: committed.SessionId);
        }
        finally
        {
            TryDeleteDirectory(tempStaging);
            TryDeleteFile(archiveFile);
        }
    }

    /// <summary>
    /// Безопасно устанавливает подписанный WHQL-драйвер из официального каталога Microsoft (WUApiLib),
    /// предварительно создавая точку отката текущего oemXX.inf (если он установлен).
    /// </summary>
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

        var rank = HardwareIdAndProblemAnalyzer.ComputeHardwareIdMatchRank(device.HardwareIds, candidate.MatchedHardwareId);
        if (rank == 0)
        {
            return new DriverOperationResult(
                false,
                "Защитный барьер: отклонена установка драйвера из-за несовпадения подсистемы SUBSYS (защита OEM-плат и ноутбуков).");
        }

        Guid? backupSessionId = null;
        if (device.IsThirdPartyOemInf)
        {
            var backup = await BackupDeviceDriverToVaultAsync(device, ct).ConfigureAwait(false);
            backupSessionId = backup.RollbackSessionId;
        }

        var (installed, rebootRequired, err) = await _platformBridge
            .InstallWindowsUpdateDriverAsync(candidate.UpdateIdentityId, ct)
            .ConfigureAwait(false);

        if (!installed)
        {
            return new DriverOperationResult(
                false,
                $"Не удалось установить WHQL-драйвер «{candidate.Title}»: {err}",
                RollbackSessionId: backupSessionId);
        }

        var rebootNote = rebootRequired ? " Перезагрузите ПК для завершения активации драйвера." : "";
        return new DriverOperationResult(
            Succeeded: true,
            UserFriendlyMessage: $"✅ Установлен официальный WHQL-драйвер «{candidate.Title}» ({candidate.DriverVersion}).{rebootNote}",
            RollbackSessionId: backupSessionId);
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch
        {
            // Ignore temp cleanup locks
        }
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // Ignore temp cleanup locks
        }
    }
}
