using UltimateWindows.Core.Enums;

namespace UltimateWindows.Modules.Optimizer.Models;

public enum TweakCategory
{
    UiAndResponsiveness = 0,
    QuietBackgroundAndAds = 1,
    GamingAndLatency = 2,
    SecurityAndClarity = 3
}

public enum RegistryTweakValueKind
{
    DWord = 4,
    String = 1,
    BinaryHex = 3,
    DeleteValue = 99
}

public enum DnsPresetId
{
    AutomaticDhcp = 0,
    CloudflareFast = 1,
    CloudflareMalwareShield = 2,
    Quad9Security = 3,
    GooglePublic = 4,
    AdGuardClean = 5
}

/// <summary>
/// Единичная атомарная операция над параметром реестра внутри обратимого твика.
/// </summary>
public sealed record TweakRegistryMutation(
    string Hive,
    string SubKeyPath,
    string ValueName,
    RegistryTweakValueKind ValueKind,
    string DesiredSerializedValue,
    string DefaultRestoreSerializedValue,
    bool ExistedByDefault = false);

/// <summary>
/// Декларативное правило безопасной настройки Windows (в стиле OptimizerNXT / WinUtil).
/// </summary>
public sealed record DeclarativeTweakRule(
    string TweakId,
    TweakCategory Category,
    string IconGlyph,
    string FriendlyTitle,
    string FriendlyExplanation,
    string ImpactBadge,
    RiskLevel Risk,
    bool RequiresAdministrator,
    IReadOnlyList<TweakRegistryMutation> Mutations)
{
    public string ExpertMutationsPreview => string.Join(
        "  •  ",
        Mutations.Select(m => $@"{m.Hive}\{m.SubKeyPath} :: {(string.IsNullOrEmpty(m.ValueName) ? "(Default)" : m.ValueName)} = {m.DesiredSerializedValue}"));
}

/// <summary>
/// Текущее состояние конкретного твика на ПК пользователя.
/// </summary>
public sealed record EvaluatedTweakState(
    DeclarativeTweakRule Rule,
    bool IsCurrentlyApplied);

/// <summary>
/// Элемент автозагрузки Windows (реестр Run / StartupApproved или папка автозагрузки).
/// </summary>
public sealed record StartupEntryInfo(
    string EntryId,
    string DisplayName,
    string CommandOrTarget,
    string? ResolvedExecutablePath,
    string LocationSource,
    bool IsEnabled,
    bool IsSignedTrusted,
    bool RequiresAdminToToggle)
{
    public string StatusBadge => IsEnabled ? "Включено при входе ⚡" : "Отключено (не тормозит запуск) 💤";
    public string SignatureBadge => IsSignedTrusted ? "Подписан издателем ✅" : "Без цифровой подписи ⚠️";
}

/// <summary>
/// Стороннее расширение контекстного меню Проводника (ShellEx ContextMenuHandler).
/// </summary>
public sealed record ShellContextMenuHandlerInfo(
    string Clsid,
    string HandlerName,
    string TargetScope,
    string? DllPath,
    bool IsMicrosoftBuiltIn,
    bool IsSignedTrusted,
    bool IsBlockedByPolicy)
{
    public string StateBadge => IsBlockedByPolicy ? "Скрыто из меню (ускорено)" : "Активно в правом клике";
}

/// <summary>
/// Сведения о процессе, удерживающем блокировку файла или папки (File Lock Hunter).
/// </summary>
public sealed record LockingProcessInfo(
    int ProcessId,
    string ApplicationName,
    string ExecutablePath,
    string ProcessKindLabel,
    bool IsCriticalSystemProcess)
{
    public string DisplayHeadline => $"{ApplicationName} (PID {ProcessId})";
    public bool CanCloseSafely => !IsCriticalSystemProcess;
}

/// <summary>
/// Предустановка проверенного DNS-сервера.
/// </summary>
public sealed record DnsPresetDescriptor(
    DnsPresetId Id,
    string FriendlyName,
    string PrimaryIpv4,
    string SecondaryIpv4,
    string DohTemplateUrl,
    string FriendlyBenefit)
{
    public string ServersDisplay => Id == DnsPresetId.AutomaticDhcp
        ? "Автоматически от роутера (DHCP)"
        : $"{PrimaryIpv4}  •  {SecondaryIpv4}";
}

/// <summary>
/// Отчет проверки задержки сети, DNS и стабильности канала (джиттер / Bufferbloat-индикатор).
/// </summary>
public sealed record NetworkLatencyReport(
    string TestedEndpoint,
    double DnsLookupMs,
    double MinRttMs,
    double AvgRttMs,
    double MaxRttMs,
    double JitterMs,
    string QualityGradeBadge,
    string FriendlyInterpretation);

/// <summary>
/// Нестандартная активная запись в системном файле C:\Windows\System32\drivers\etc\hosts.
/// </summary>
public sealed record HostsRedirectEntry(
    int LineNumber,
    string RedirectIp,
    string DomainHost,
    bool IsSuspiciousSecurityBlock);

/// <summary>
/// Установленная в системе программа пользователя (Win32 / MSI).
/// </summary>
public sealed record InstalledApplicationInfo(
    string RegistryKeyPath,
    string DisplayName,
    string DisplayVersion,
    string Publisher,
    string? InstallLocation,
    string? UninstallString,
    long EstimatedSizeBytes)
{
    public string PublisherAndVersion => string.IsNullOrWhiteSpace(DisplayVersion)
        ? Publisher
        : $"{Publisher} • v{DisplayVersion}";
}

/// <summary>
/// Универсальный результат операции модуля Оптимизатора.
/// </summary>
public sealed record OptimizerOperationResult(
    bool Succeeded,
    string UserFriendlyMessage,
    string TechnicalDetails = "",
    Guid? RollbackSessionId = null);
