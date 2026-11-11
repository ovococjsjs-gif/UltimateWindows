using System.Net;
using System.Text;
using System.Text.Json;
using UltimateWindows.Core.Contracts;
using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Optimizer.Catalog;
using UltimateWindows.Modules.Optimizer.Contracts;
using UltimateWindows.Modules.Optimizer.Models;
using UltimateWindows.Modules.Optimizer.Network;

namespace UltimateWindows.Modules.Optimizer.Services;

/// <summary>
/// Базовый безопасный платформенный мост Оптимизатора (для модульных тестов и кроссплатформенного запуска).
/// </summary>
public class DefaultOptimizerPlatformBridge : IOptimizerPlatformBridge
{
    public virtual bool IsRunningAsAdministrator() => false;

    public virtual SystemFacts GetSystemFacts() => SystemFacts.Unknown;

    public virtual (bool Exists, int ValueKindCode, string? SerializedValue) ReadRegistryValue(
        string hive,
        string subKeyPath,
        string valueName) => (false, (int)RegistryTweakValueKind.String, null);

    public virtual bool WriteRegistryValue(
        string hive,
        string subKeyPath,
        string valueName,
        RegistryTweakValueKind kind,
        string serializedValue) => false;

    public virtual Task<IReadOnlyList<StartupEntryInfo>> GetStartupEntriesAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<StartupEntryInfo>>(Array.Empty<StartupEntryInfo>());

    public virtual Task<(bool Succeeded, string PreviousStartupApprovedBase64)> SetStartupEntryEnabledAsync(
        StartupEntryInfo entry,
        bool enabled,
        CancellationToken ct = default) =>
        Task.FromResult((false, ""));

    public virtual Task<IReadOnlyList<ShellContextMenuHandlerInfo>> GetThirdPartyShellExtensionsAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<ShellContextMenuHandlerInfo>>(Array.Empty<ShellContextMenuHandlerInfo>());

    public virtual Task<bool> SetShellExtensionBlockedAsync(string clsid, string handlerName, bool blocked, CancellationToken ct = default) =>
        Task.FromResult(false);

    public virtual Task<IReadOnlyList<LockingProcessInfo>> FindLockingProcessesAsync(string fileOrDirectoryPath, CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<LockingProcessInfo>>(Array.Empty<LockingProcessInfo>());

    public virtual Task<bool> TryPoliteCloseProcessAsync(int processId, CancellationToken ct = default) =>
        Task.FromResult(false);

    public virtual Task<(bool Succeeded, string AdapterName, string PreviousDnsStateJson)> ApplyDnsPresetAsync(
        DnsPresetDescriptor preset,
        CancellationToken ct = default) =>
        Task.FromResult((false, "", ""));

    public virtual Task<bool> FlushDnsCacheAsync(CancellationToken ct = default) =>
        Task.FromResult(false);

    public virtual string GetHostsFilePath() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "drivers", "etc", "hosts");

    public virtual Task<IReadOnlyList<InstalledApplicationInfo>> GetInstalledApplicationsAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<InstalledApplicationInfo>>(Array.Empty<InstalledApplicationInfo>());

    public virtual Task<bool> LaunchApplicationUninstallerAsync(InstalledApplicationInfo app, CancellationToken ct = default) =>
        Task.FromResult(false);

    public virtual Task<IReadOnlyList<UwpPackageInfo>> GetInstalledUwpPackagesAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<UwpPackageInfo>>(Array.Empty<UwpPackageInfo>());

    public virtual Task<(int RemovedCount, string ErrorSummary)> RemoveUwpPackagesAsync(
        IReadOnlyList<UwpPackageInfo> packages,
        CancellationToken ct = default) =>
        Task.FromResult((0, "Доступно только на Windows 10/11."));
}

/// <summary>
/// Центральный сервис Фазы 4: 39 обратимых декларативных твиков ОС, готовые пресеты, YAML-профили,
/// удаление UWP-приложений, деинсталлятор Win32-программ, автозагрузка, контекстное меню Проводника (ShellEx),
/// разблокировка занятых файлов (Restart Manager), переключение DNS и полноценный редактор hosts с бекапом.
/// </summary>
public sealed class SmartOptimizerService
{
    private static readonly HashSet<string> ProtectedCriticalSystemProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "system", "idle", "registry", "smss", "csrss", "wininit", "services",
        "lsass", "lsaiso", "svchost", "fontdrvhost", "winlogon", "dwm", "sihost", "msmpeng"
    };

    private readonly IVaultService _vaultService;
    private readonly IOptimizerPlatformBridge _platformBridge;
    private SystemFacts? _cachedSystemFacts;

    public SmartOptimizerService(
        IVaultService vaultService,
        IOptimizerPlatformBridge? platformBridge = null)
    {
        _vaultService = vaultService ?? throw new ArgumentNullException(nameof(vaultService));
        _platformBridge = platformBridge ?? new DefaultOptimizerPlatformBridge();
    }

    public IReadOnlyList<DnsPresetDescriptor> GetDnsPresets() => NetworkAndHostsInspector.GetDnsPresets();

    /// <summary>
    /// Сведения о компьютере для проверки применимости твиков. Запрашиваются один раз за сеанс.
    /// </summary>
    public SystemFacts GetSystemFacts()
    {
        if (_cachedSystemFacts is not null)
        {
            return _cachedSystemFacts;
        }

        SystemFacts facts;
        try
        {
            facts = _platformBridge.GetSystemFacts() ?? SystemFacts.Unknown;
        }
        catch (Exception)
        {
            // Сбой при сборе сведений не должен ломать список твиков: считаем факты неизвестными
            facts = SystemFacts.Unknown;
        }

        _cachedSystemFacts = facts;
        return facts;
    }

    public IReadOnlyList<EvaluatedTweakState> EvaluateAllTweaks()
    {
        var rules = DeclarativeTweakCatalog.GetAllRules();
        var states = new List<EvaluatedTweakState>(rules.Count);
        var facts = GetSystemFacts();

        foreach (var rule in rules)
        {
            TweakSafetyGuard.ThrowIfUnsafeRule(rule);
            var allMutationsActive = rule.Mutations.Count > 0 && rule.Mutations.All(IsMutationCurrentlyActive);
            states.Add(new EvaluatedTweakState(rule, allMutationsActive, rule.EffectiveRequirements.Evaluate(facts)));
        }

        return states;
    }

    /// <summary>
    /// Включает твик или возвращает стандартное значение Windows.
    /// Твик, который не подходит этой версии Windows, включить нельзя. Не рекомендуемый для этого компьютера
    /// или опасный твик включается только при явном согласии в <paramref name="options"/>;
    /// без согласия возвращается результат с признаком нужного подтверждения.
    /// Возврат к стандарту разрешён всегда.
    /// </summary>
    public async Task<OptimizerOperationResult> SetTweakStateAsync(
        string tweakId,
        bool enableTweak,
        CancellationToken ct = default,
        TweakApplyOptions? options = null)
    {
        var rule = DeclarativeTweakCatalog.FindById(tweakId);
        if (rule is null)
        {
            return new OptimizerOperationResult(false, $"Твик с идентификатором '{tweakId}' не найден в белом каталоге.");
        }

        TweakSafetyGuard.ThrowIfUnsafeRule(rule);
        options ??= TweakApplyOptions.Default;

        var applicability = enableTweak
            ? rule.EffectiveRequirements.Evaluate(GetSystemFacts())
            : TweakApplicability.Applicable;

        if (applicability.Status == TweakApplicabilityStatus.NotApplicable)
        {
            return new OptimizerOperationResult(
                false,
                $"«{rule.FriendlyTitle}» не подходит этому компьютеру. {applicability.Reason}");
        }

        if (rule.RequiresAdministrator && !_platformBridge.IsRunningAsAdministrator())
        {
            return new OptimizerOperationResult(
                false,
                $"Для настройки «{rule.FriendlyTitle}» запустите программу от имени Администратора.");
        }

        if (enableTweak && rule.IsDangerous && !options.AcceptDangerous)
        {
            return new OptimizerOperationResult(
                false,
                $"«{rule.FriendlyTitle}» — опасная настройка: она ослабляет защиту или устойчивость Windows. Включайте её, только если понимаете последствия.",
                ConfirmationRequired: TweakConfirmationKind.DangerousTweak);
        }

        if (applicability.Status == TweakApplicabilityStatus.NotRecommended && !options.AcceptNotRecommended)
        {
            return new OptimizerOperationResult(
                false,
                $"«{rule.FriendlyTitle}» не рекомендуется для этого компьютера. {applicability.Reason}",
                ConfirmationRequired: TweakConfirmationKind.NotRecommendedForThisPc);
        }

        var actionVerb = enableTweak ? "Включен твик" : "Возвращен стандарт";
        await using var tx = _vaultService.BeginTransaction(
            SystemDomain.Optimizer,
            friendlyTitle: $"{actionVerb}: {rule.FriendlyTitle}",
            friendlySummary: rule.FriendlyExplanation,
            technicalDetails: rule.ExpertMutationsPreview);

        var appliedCount = 0;
        foreach (var m in rule.Mutations)
        {
            var (existedBefore, prevKind, prevData) = _platformBridge.ReadRegistryValue(m.Hive, m.SubKeyPath, m.ValueName);

            var snapshotJson = JsonSerializer.Serialize(new
            {
                Hive = m.Hive,
                SubKey = m.SubKeyPath,
                ValueName = m.ValueName,
                ExistedBefore = existedBefore,
                ValueKind = existedBefore ? prevKind : (int)m.ValueKind,
                SerializedData = prevData
            });

            tx.RecordStateDelta(
                StateTargetKind.RegistryValue,
                $@"{m.Hive}\{m.SubKeyPath} :: {m.ValueName}",
                previousStateJson: snapshotJson,
                newStateJson: JsonSerializer.Serialize(new { Enabled = enableTweak }));

            bool writeOk;
            if (enableTweak)
            {
                writeOk = _platformBridge.WriteRegistryValue(m.Hive, m.SubKeyPath, m.ValueName, m.ValueKind, m.DesiredSerializedValue);
            }
            else if (m.ExistedByDefault)
            {
                writeOk = _platformBridge.WriteRegistryValue(m.Hive, m.SubKeyPath, m.ValueName, m.ValueKind, m.DefaultRestoreSerializedValue);
            }
            else
            {
                writeOk = _platformBridge.WriteRegistryValue(m.Hive, m.SubKeyPath, m.ValueName, RegistryTweakValueKind.DeleteValue, "");
            }

            if (writeOk)
            {
                appliedCount++;
            }
        }

        if (appliedCount == 0)
        {
            return new OptimizerOperationResult(false, $"Не удалось записать параметры реестра для «{rule.FriendlyTitle}».");
        }

        var committed = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);
        return new OptimizerOperationResult(
            Succeeded: true,
            UserFriendlyMessage: enableTweak
                ? $"Включено: «{rule.FriendlyTitle}» (точка отката сохранена)."
                : $"Возвращен стандарт Windows: «{rule.FriendlyTitle}».",
            TechnicalDetails: rule.ExpertMutationsPreview,
            RollbackSessionId: committed.SessionId);
    }

    public async Task<OptimizerOperationResult> ApplyPresetBatchAsync(
        string presetKey,
        string presetDisplayTitle,
        CancellationToken ct = default)
    {
        var ids = DeclarativeTweakCatalog.GetPresetIds(presetKey);
        int applied = 0;
        int skippedAdmin = 0;

        foreach (var id in ids)
        {
            ct.ThrowIfCancellationRequested();

            // Наборы применяют только то, что подходит этому компьютеру и не требует отдельного согласия
            var res = await SetTweakStateAsync(id, enableTweak: true, ct).ConfigureAwait(false);
            if (res.Succeeded) applied++;
            else skippedAdmin++;
        }

        var note = skippedAdmin > 0
            ? $" (пропущено: {skippedAdmin} — нет прав администратора либо настройка не подходит этому компьютеру)"
            : "";
        return new OptimizerOperationResult(
            Succeeded: applied > 0,
            UserFriendlyMessage: $"Пресет «{presetDisplayTitle}»: применено твиков — {applied}{note}.");
    }

    public string ExportActiveTweaksToYaml(string profileName = "Мой профиль UltimateWindows")
    {
        var activeIds = EvaluateAllTweaks()
            .Where(t => t.IsCurrentlyApplied)
            .Select(t => t.Rule.TweakId);
        return YamlTweakProfileSerializer.ExportProfileToYaml(profileName, activeIds);
    }

    public async Task<OptimizerOperationResult> ImportAndApplyYamlProfileAsync(
        string yamlContent,
        CancellationToken ct = default)
    {
        var (profileName, ids) = YamlTweakProfileSerializer.ImportProfileFromYaml(yamlContent);
        if (ids.Count == 0)
        {
            return new OptimizerOperationResult(false, "В выбранном YAML-профиле не указано ни одного правила настройки.");
        }

        var applied = 0;
        var skipped = 0;
        foreach (var id in ids)
        {
            ct.ThrowIfCancellationRequested();
            var res = await SetTweakStateAsync(id, enableTweak: true, ct).ConfigureAwait(false);
            if (res.Succeeded) applied++;
            else skipped++;
        }

        return new OptimizerOperationResult(
            Succeeded: applied > 0,
            UserFriendlyMessage: $"Профиль «{profileName}»: применено твиков — {applied}" +
                                 (skipped > 0 ? $" (пропущено: {skipped} — нет прав администратора, настройка неизвестна или не подходит этому компьютеру)." : "."));
    }

    public Task<IReadOnlyList<StartupEntryInfo>> GetStartupEntriesAsync(CancellationToken ct = default) =>
        _platformBridge.GetStartupEntriesAsync(ct);

    public async Task<OptimizerOperationResult> ToggleStartupEntryAsync(
        StartupEntryInfo entry,
        bool enable,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(entry);
        if (entry.RequiresAdminToToggle && !_platformBridge.IsRunningAsAdministrator())
        {
            return new OptimizerOperationResult(false, $"Для изменения системной записи «{entry.DisplayName}» требуются права Администратора.");
        }

        var (ok, prevApprovedBase64) = await _platformBridge.SetStartupEntryEnabledAsync(entry, enable, ct).ConfigureAwait(false);
        if (!ok)
        {
            return new OptimizerOperationResult(false, $"Не удалось переключить автозагрузку для «{entry.DisplayName}».");
        }

        await using var tx = _vaultService.BeginTransaction(
            SystemDomain.Optimizer,
            friendlyTitle: $"{(enable ? "Включена" : "Отключена")} автозагрузка: {entry.DisplayName}",
            friendlySummary: $"Управление флагом StartupApproved для «{entry.DisplayName}».",
            technicalDetails: entry.CommandOrTarget);

        if (!string.IsNullOrEmpty(prevApprovedBase64))
        {
            var hive = entry.RequiresAdminToToggle ? "HKLM" : "HKCU";
            var subKey = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
            var snapJson = JsonSerializer.Serialize(new
            {
                Hive = hive,
                SubKey = subKey,
                ValueName = entry.DisplayName,
                ExistedBefore = true,
                ValueKind = 3,
                SerializedData = prevApprovedBase64
            });

            tx.RecordStateDelta(StateTargetKind.RegistryValue, $@"{hive}\{subKey} :: {entry.DisplayName}", snapJson, null);
        }

        var committed = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);
        return new OptimizerOperationResult(
            Succeeded: true,
            UserFriendlyMessage: enable
                ? $"Программа «{entry.DisplayName}» включена в автозагрузку."
                : $"Программа «{entry.DisplayName}» убрана из автозагрузки.",
            RollbackSessionId: committed.SessionId);
    }

    public Task<IReadOnlyList<ShellContextMenuHandlerInfo>> GetThirdPartyShellExtensionsAsync(CancellationToken ct = default) =>
        _platformBridge.GetThirdPartyShellExtensionsAsync(ct);

    public async Task<OptimizerOperationResult> SetShellExtensionBlockedAsync(
        ShellContextMenuHandlerInfo handler,
        bool blockInContextMenu,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(handler);
        if (!_platformBridge.IsRunningAsAdministrator())
        {
            return new OptimizerOperationResult(
                false,
                "Для управления политикой контекстного меню требуются права Администратора.");
        }

        const string blockedSubKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked";
        var (existedBefore, prevKind, prevVal) = _platformBridge.ReadRegistryValue("HKLM", blockedSubKey, handler.Clsid);

        var ok = await _platformBridge.SetShellExtensionBlockedAsync(handler.Clsid, handler.HandlerName, blockInContextMenu, ct).ConfigureAwait(false);
        if (!ok)
        {
            return new OptimizerOperationResult(false, $"Не удалось изменить состояние пункта меню «{handler.HandlerName}».");
        }

        await using var tx = _vaultService.BeginTransaction(
            SystemDomain.Optimizer,
            friendlyTitle: $"{(blockInContextMenu ? "Скрыто из контекстного меню" : "Возвращено в меню")}: {handler.HandlerName}",
            friendlySummary: "Безопасное переключение через политику Shell Extensions\\Blocked.",
            technicalDetails: $"{handler.Clsid} ({handler.DllPath})");

        var snapJson = JsonSerializer.Serialize(new
        {
            Hive = "HKLM",
            SubKey = blockedSubKey,
            ValueName = handler.Clsid,
            ExistedBefore = existedBefore,
            ValueKind = existedBefore ? prevKind : 1,
            SerializedData = prevVal
        });

        tx.RecordStateDelta(StateTargetKind.RegistryValue, $@"HKLM\{blockedSubKey} :: {handler.Clsid}", snapJson, null);
        var committed = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);

        return new OptimizerOperationResult(
            Succeeded: true,
            UserFriendlyMessage: blockInContextMenu
                ? $"Пункт «{handler.HandlerName}» скрыт из правого клика Проводника."
                : $"Пункт «{handler.HandlerName}» возвращен в контекстное меню.",
            RollbackSessionId: committed.SessionId);
    }

    public Task<IReadOnlyList<LockingProcessInfo>> FindLockingProcessesAsync(
        string fileOrDirectoryPath,
        CancellationToken ct = default) =>
        _platformBridge.FindLockingProcessesAsync(fileOrDirectoryPath, ct);

    public async Task<OptimizerOperationResult> RequestSafeCloseLockingProcessAsync(
        LockingProcessInfo processInfo,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(processInfo);

        var cleanName = Path.GetFileNameWithoutExtension(processInfo.ApplicationName);
        if (processInfo.IsCriticalSystemProcess || ProtectedCriticalSystemProcesses.Contains(cleanName))
        {
            return new OptimizerOperationResult(
                false,
                $"Защитный барьер: системный процесс «{processInfo.ApplicationName}» нельзя завершать.");
        }

        var closed = await _platformBridge.TryPoliteCloseProcessAsync(processInfo.ProcessId, ct).ConfigureAwait(false);
        return closed
            ? new OptimizerOperationResult(true, $"Отправлен запрос закрытия процессу «{processInfo.ApplicationName}» (PID {processInfo.ProcessId}) — файл освобожден.")
            : new OptimizerOperationResult(false, $"Процесс «{processInfo.ApplicationName}» ожидает сохранения данных — закройте его окно вручную.");
    }

    public async Task<OptimizerOperationResult> ApplyDnsPresetAsync(
        DnsPresetId presetId,
        CancellationToken ct = default)
    {
        if (!_platformBridge.IsRunningAsAdministrator())
        {
            return new OptimizerOperationResult(false, "Для изменения DNS-серверов сетевого адаптера требуются права Администратора.");
        }

        var preset = NetworkAndHostsInspector.GetPresetById(presetId);
        var (ok, adapterName, prevDnsJson) = await _platformBridge.ApplyDnsPresetAsync(preset, ct).ConfigureAwait(false);
        if (!ok)
        {
            return new OptimizerOperationResult(false, $"Не удалось применить DNS-профиль «{preset.FriendlyName}».");
        }

        await using var tx = _vaultService.BeginTransaction(
            SystemDomain.Optimizer,
            friendlyTitle: $"Настройка DNS ({adapterName}): {preset.FriendlyName}",
            friendlySummary: preset.FriendlyBenefit,
            technicalDetails: preset.ServersDisplay);

        tx.RecordStateDelta(
            StateTargetKind.SystemSetting,
            $"DnsProfile:{adapterName}",
            previousStateJson: prevDnsJson,
            newStateJson: JsonSerializer.Serialize(new { Preset = preset.Id.ToString(), Primary = preset.PrimaryIpv4 }));

        var committed = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);
        return new OptimizerOperationResult(
            Succeeded: true,
            UserFriendlyMessage: $"Применен DNS «{preset.FriendlyName}» для адаптера «{adapterName}».",
            RollbackSessionId: committed.SessionId);
    }

    public async Task<OptimizerOperationResult> FlushDnsCacheAsync(CancellationToken ct = default)
    {
        var ok = await _platformBridge.FlushDnsCacheAsync(ct).ConfigureAwait(false);
        return ok
            ? new OptimizerOperationResult(true, "Кэш DNS-резолвера Windows успешно очищен (ipconfig /flushdns).")
            : new OptimizerOperationResult(false, "Не удалось очистить кэш DNS.");
    }

    // ==================== HOSTS FILE EDITOR (С БЕКАПОМ В VAULT) ====================

    public string GetHostsFilePath() => _platformBridge.GetHostsFilePath();

    public IReadOnlyList<HostsRedirectEntry> InspectHostsFile()
    {
        var path = _platformBridge.GetHostsFilePath();
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return Array.Empty<HostsRedirectEntry>();
        }

        try
        {
            return NetworkAndHostsInspector.ParseHostsContent(File.ReadAllText(path));
        }
        catch
        {
            return Array.Empty<HostsRedirectEntry>();
        }
    }

    public async Task<OptimizerOperationResult> AddHostsEntryAsync(
        string redirectIp,
        string domainHost,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(redirectIp) || !IPAddress.TryParse(redirectIp.Trim(), out _))
        {
            return new OptimizerOperationResult(false, "Укажите корректный IP-адрес (например, 0.0.0.0 или 127.0.0.1).");
        }

        var cleanDomain = (domainHost ?? "").Trim().ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(cleanDomain) || cleanDomain.Contains(' ') || !cleanDomain.Contains('.'))
        {
            return new OptimizerOperationResult(false, "Укажите корректное доменное имя (например, telemetry.example.com).");
        }

        if (NetworkAndHostsInspector.IsProtectedSecurityDomain(cleanDomain))
        {
            return new OptimizerOperationResult(
                false,
                $"Защитный фильтр заблокировал попытку перенаправить домен безопасности или обновлений «{cleanDomain}».");
        }

        var hostsPath = _platformBridge.GetHostsFilePath();
        try
        {
            var prevText = File.Exists(hostsPath) ? await File.ReadAllTextAsync(hostsPath, ct).ConfigureAwait(false) : "";
            var nextText = NetworkAndHostsInspector.AppendRuleToHostsText(prevText, redirectIp.Trim(), cleanDomain);

            await using var tx = _vaultService.BeginTransaction(
                SystemDomain.Optimizer,
                friendlyTitle: $"Добавлено правило hosts: {redirectIp.Trim()} -> {cleanDomain}",
                friendlySummary: "Изменение системного файла hosts с полной копией предыдущей версии в Машине времени.",
                technicalDetails: hostsPath);

            tx.RecordStateDelta(
                StateTargetKind.SystemSetting,
                "HostsSabotageCleanup",
                previousStateJson: JsonSerializer.Serialize(new { Path = hostsPath, Content = prevText }),
                newStateJson: JsonSerializer.Serialize(new { Path = hostsPath, Added = $"{redirectIp.Trim()} {cleanDomain}" }));

            await File.WriteAllTextAsync(hostsPath, nextText, new UTF8Encoding(false), ct).ConfigureAwait(false);
            var committed = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);
            _ = await _platformBridge.FlushDnsCacheAsync(ct).ConfigureAwait(false);

            return new OptimizerOperationResult(
                true,
                $"Добавлена запись hosts: {redirectIp.Trim()} → {cleanDomain} (бекап сохранен).",
                RollbackSessionId: committed.SessionId);
        }
        catch (UnauthorizedAccessException)
        {
            return new OptimizerOperationResult(false, "Для редактирования системного файла hosts запустите программу от имени Администратора.");
        }
        catch (Exception ex)
        {
            return new OptimizerOperationResult(false, $"Ошибка записи файла hosts: {ex.Message}");
        }
    }

    public async Task<OptimizerOperationResult> RemoveHostsEntryAsync(
        HostsRedirectEntry entry,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(entry);
        var hostsPath = _platformBridge.GetHostsFilePath();
        if (!File.Exists(hostsPath))
        {
            return new OptimizerOperationResult(false, "Файл hosts не найден.");
        }

        try
        {
            var prevText = await File.ReadAllTextAsync(hostsPath, ct).ConfigureAwait(false);
            var nextText = NetworkAndHostsInspector.RemoveDomainFromHostsText(prevText, entry.RedirectIp, entry.DomainHost);

            await using var tx = _vaultService.BeginTransaction(
                SystemDomain.Optimizer,
                friendlyTitle: $"Удалено правило hosts: {entry.RedirectIp} -> {entry.DomainHost}",
                friendlySummary: "Очистка правила перенаправления в файле hosts.",
                technicalDetails: hostsPath);

            tx.RecordStateDelta(
                StateTargetKind.SystemSetting,
                "HostsSabotageCleanup",
                previousStateJson: JsonSerializer.Serialize(new { Path = hostsPath, Content = prevText }),
                newStateJson: JsonSerializer.Serialize(new { Path = hostsPath, Removed = $"{entry.RedirectIp} {entry.DomainHost}" }));

            await File.WriteAllTextAsync(hostsPath, nextText, new UTF8Encoding(false), ct).ConfigureAwait(false);
            var committed = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);
            _ = await _platformBridge.FlushDnsCacheAsync(ct).ConfigureAwait(false);

            return new OptimizerOperationResult(
                true,
                $"Удалена запись hosts: {entry.RedirectIp} → {entry.DomainHost}.",
                RollbackSessionId: committed.SessionId);
        }
        catch (UnauthorizedAccessException)
        {
            return new OptimizerOperationResult(false, "Для изменения системного файла hosts требуются права Администратора.");
        }
        catch (Exception ex)
        {
            return new OptimizerOperationResult(false, $"Ошибка изменения файла hosts: {ex.Message}");
        }
    }

    // ==================== ДЕИНСТАЛЛЯТОР WIN32 И МЕНЕДЖЕР UWP ПРИЛОЖЕНИЙ ====================

    public Task<IReadOnlyList<InstalledApplicationInfo>> GetInstalledApplicationsAsync(CancellationToken ct = default) =>
        _platformBridge.GetInstalledApplicationsAsync(ct);

    public async Task<OptimizerOperationResult> LaunchApplicationUninstallerAsync(
        InstalledApplicationInfo app,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(app);
        if (string.IsNullOrWhiteSpace(app.UninstallString))
        {
            return new OptimizerOperationResult(false, $"У программы «{app.DisplayName}» не указана команда удаления.");
        }

        var ok = await _platformBridge.LaunchApplicationUninstallerAsync(app, ct).ConfigureAwait(false);
        return ok
            ? new OptimizerOperationResult(true, $"Запущен штатный деинсталлятор «{app.DisplayName}».")
            : new OptimizerOperationResult(false, $"Не удалось запустить деинсталлятор «{app.DisplayName}» (проверьте права Администратора).");
    }

    public async Task<IReadOnlyList<UwpPackageInfo>> GetInstalledUwpPackagesAsync(
        bool includeFrameworks = false,
        CancellationToken ct = default)
    {
        var all = await _platformBridge.GetInstalledUwpPackagesAsync(ct).ConfigureAwait(false);
        return includeFrameworks
            ? all
            : all.Where(p => !p.IsFrameworkOrSystem).ToList();
    }

    public async Task<OptimizerOperationResult> RemoveSelectedUwpPackagesAsync(
        IReadOnlyList<UwpPackageInfo> selectedPackages,
        CancellationToken ct = default)
    {
        if (selectedPackages.Count == 0)
        {
            return new OptimizerOperationResult(false, "Отметьте галочками хотя бы одно UWP-приложение для удаления.");
        }

        var removable = selectedPackages.Where(p => p.CanRemoveSafely).ToList();
        if (removable.Count == 0)
        {
            return new OptimizerOperationResult(
                false,
                "Выбранные пакеты являются системными библиотеками (VCLibs / .NET Native / Store) и защищены от удаления.");
        }

        var (removed, err) = await _platformBridge.RemoveUwpPackagesAsync(removable, ct).ConfigureAwait(false);
        var errNote = !string.IsNullOrWhiteSpace(err) ? $" ({err})" : "";
        return new OptimizerOperationResult(
            removed > 0,
            removed > 0
                ? $"Удалено встроенных UWP-приложений: {removed} из {removable.Count}{errNote}."
                : $"Не удалось удалить выбранные UWP-приложения{errNote}.");
    }

    private bool IsMutationCurrentlyActive(TweakRegistryMutation m)
    {
        var (exists, _, currentVal) = _platformBridge.ReadRegistryValue(m.Hive, m.SubKeyPath, m.ValueName);
        if (!exists)
        {
            return false;
        }

        return string.Equals(currentVal ?? "", m.DesiredSerializedValue, StringComparison.OrdinalIgnoreCase);
    }
}
