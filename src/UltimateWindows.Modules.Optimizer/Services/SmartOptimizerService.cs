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

    public virtual string GetHostsFilePath() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "drivers", "etc", "hosts");

    public virtual Task<IReadOnlyList<InstalledApplicationInfo>> GetInstalledApplicationsAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<InstalledApplicationInfo>>(Array.Empty<InstalledApplicationInfo>());
}

/// <summary>
/// Центральный сервис Фазы 4: обратимые декларативные твики ОС (с экспортом/импортом YAML-профилей),
/// управление автозагрузкой и контекстным меню Проводника (ShellEx), разблокировка занятых файлов (File Lock Hunter),
/// переключение проверенных DNS и инспекция файла hosts.
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

    public SmartOptimizerService(
        IVaultService vaultService,
        IOptimizerPlatformBridge? platformBridge = null)
    {
        _vaultService = vaultService ?? throw new ArgumentNullException(nameof(vaultService));
        _platformBridge = platformBridge ?? new DefaultOptimizerPlatformBridge();
    }

    public IReadOnlyList<DnsPresetDescriptor> GetDnsPresets() => NetworkAndHostsInspector.GetDnsPresets();

    /// <summary>
    /// Проверяет текущее состояние всех встроенных твиков на ПК пользователя.
    /// </summary>
    public IReadOnlyList<EvaluatedTweakState> EvaluateAllTweaks()
    {
        var rules = DeclarativeTweakCatalog.GetAllRules();
        var states = new List<EvaluatedTweakState>(rules.Count);

        foreach (var rule in rules)
        {
            TweakSafetyGuard.ThrowIfUnsafeRule(rule);
            var allMutationsActive = rule.Mutations.Count > 0 && rule.Mutations.All(IsMutationCurrentlyActive);
            states.Add(new EvaluatedTweakState(rule, allMutationsActive));
        }

        return states;
    }

    /// <summary>
    /// Применяет или возвращает к штатному значению выбранный твик ОС с автоматической записью
    /// исходных параметров реестра в компактный журнал Машины времени.
    /// </summary>
    public async Task<OptimizerOperationResult> SetTweakStateAsync(
        string tweakId,
        bool enableTweak,
        CancellationToken ct = default)
    {
        var rule = DeclarativeTweakCatalog.FindById(tweakId);
        if (rule is null)
        {
            return new OptimizerOperationResult(false, $"Твик с идентификатором '{tweakId}' не найден в белом каталоге.");
        }

        TweakSafetyGuard.ThrowIfUnsafeRule(rule);

        if (rule.RequiresAdministrator && !_platformBridge.IsRunningAsAdministrator())
        {
            return new OptimizerOperationResult(
                false,
                $"Для настройки «{rule.FriendlyTitle}» требуются права Администратора.");
        }

        var actionVerb = enableTweak ? "Включена настройка" : "Возвращена к стандарту настройка";
        await using var tx = _vaultService.BeginTransaction(
            SystemDomain.Optimizer,
            friendlyTitle: $"{actionVerb}: {rule.FriendlyTitle}",
            friendlySummary: rule.FriendlyExplanation,
            technicalDetails: rule.ExpertMutationsPreview);

        var appliedCount = 0;
        foreach (var m in rule.Mutations)
        {
            var (existedBefore, prevKind, prevData) = _platformBridge.ReadRegistryValue(m.Hive, m.SubKeyPath, m.ValueName);

            // Формат полностью совместим с RegistryValueSnapshot в WindowsSystemStateApplier!
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
            return new OptimizerOperationResult(false, $"Не удалось изменить параметры реестра для «{rule.FriendlyTitle}».");
        }

        var committed = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);
        return new OptimizerOperationResult(
            Succeeded: true,
            UserFriendlyMessage: enableTweak
                ? $"✅ Включено: «{rule.FriendlyTitle}» (сохранена точка отката в Машину времени)."
                : $"↩️ Возвращено к стандарту Windows: «{rule.FriendlyTitle}».",
            TechnicalDetails: rule.ExpertMutationsPreview,
            RollbackSessionId: committed.SessionId);
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
            if (res.Succeeded)
            {
                applied++;
            }
            else
            {
                skipped++;
            }
        }

        return new OptimizerOperationResult(
            Succeeded: applied > 0,
            UserFriendlyMessage: $"Профиль «{profileName}»: применено твиков — {applied}" +
                                 (skipped > 0 ? $" (пропущено без прав админа или неизвестных: {skipped})." : "."));
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
            friendlySummary: $"Управление флагом StartupApproved для «{entry.DisplayName}» без удаления самой программы.",
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
                ValueKind = 3, // RegistryValueKind.Binary
                SerializedData = prevApprovedBase64
            });

            tx.RecordStateDelta(StateTargetKind.RegistryValue, $@"{hive}\{subKey} :: {entry.DisplayName}", snapJson, null);
        }

        var committed = await tx.CommitAsync(pinTransaction: false, ct).ConfigureAwait(false);
        return new OptimizerOperationResult(
            Succeeded: true,
            UserFriendlyMessage: enable
                ? $"⚡ Программа «{entry.DisplayName}» снова включена в автозагрузку."
                : $"💤 Программа «{entry.DisplayName}» убрана из автозагрузки (вход в систему станет быстрее).",
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
                "Для управления политикой контекстного меню Shell Extensions\\Blocked требуются права Администратора.");
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
            friendlyTitle: $"{(blockInContextMenu ? "Скрыто из контекстного меню" : "Возвращено в контекстное меню")}: {handler.HandlerName}",
            friendlySummary: "Безопасное переключение через штатную политику Shell Extensions\\Blocked без удаления классов CLSID.",
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
                ? $"✅ Пункт «{handler.HandlerName}» аккуратно скрыт из правого клика Проводника (без удаления программы)."
                : $"↩️ Пункт «{handler.HandlerName}» снова активен в контекстном меню.",
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
                $"Защитный барьер: системный процесс «{processInfo.ApplicationName}» нельзя завершать принудительно во избежание сбоя Windows.");
        }

        var closed = await _platformBridge.TryPoliteCloseProcessAsync(processInfo.ProcessId, ct).ConfigureAwait(false);
        return closed
            ? new OptimizerOperationResult(true, $"✅ Отправлен корректный запрос закрытия процессу «{processInfo.ApplicationName}» (PID {processInfo.ProcessId}) — файл освобожден.")
            : new OptimizerOperationResult(false, $"Процесс «{processInfo.ApplicationName}» ожидает сохранения несохраненных данных пользователем — закройте его окно вручную.");
    }

    public async Task<OptimizerOperationResult> ApplyDnsPresetAsync(
        DnsPresetId presetId,
        CancellationToken ct = default)
    {
        if (!_platformBridge.IsRunningAsAdministrator())
        {
            return new OptimizerOperationResult(false, "Для изменения системных DNS-серверов сетевого адаптера требуются права Администратора.");
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
            UserFriendlyMessage: $"✅ Применен DNS «{preset.FriendlyName}» для адаптера «{adapterName}».",
            RollbackSessionId: committed.SessionId);
    }

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

    public Task<IReadOnlyList<InstalledApplicationInfo>> GetInstalledApplicationsAsync(CancellationToken ct = default) =>
        _platformBridge.GetInstalledApplicationsAsync(ct);

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
