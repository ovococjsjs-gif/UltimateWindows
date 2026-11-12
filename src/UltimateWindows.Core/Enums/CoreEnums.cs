namespace UltimateWindows.Core.Enums;

/// <summary>
/// Основные разделы интерфейса UltimateWindows.
/// </summary>
public enum SystemDomain
{
    HealthOverview = 0,
    SmartCleaner = 1,
    Optimizer = 2,
    AntiMiner = 3,
    DllAndRepair = 4,
    HardwareAndDrivers = 5,
    TimeMachineVault = 6,
    AppsAndAutomation = 7
}

/// <summary>
/// Уровень детализации интерфейса: дружелюбный режим для всех или инженерный для профи.
/// </summary>
public enum UserExperienceMode
{
    Simple = 0,
    Expert = 1
}

/// <summary>
/// Уровень безопасности / критичности системной операции или диагностической находки.
/// </summary>
public enum RiskLevel
{
    Safe = 0,
    Low = 1,
    Moderate = 2,
    Attention = 3,
    Advanced = 4,
    High = 5,
    Critical = 6
}

/// <summary>
/// Тип изменяемого системного объекта в журнале отката.
/// </summary>
public enum StateTargetKind
{
    RegistryValue = 0,
    WindowsService = 1,
    ScheduledTask = 2,
    QuarantinedFile = 3,
    DriverStoreReference = 4,
    SystemSetting = 5
}

/// <summary>
/// Вердикт проверки пути модулем защиты личных данных браузера.
/// </summary>
public enum VaultPathDecision
{
    SafeDisposableCache = 0,
    ProtectedCredentialsOrAutofill = 1,
    ProtectedSessionOrExtension = 2,
    NeutralRequiresExplicitRule = 3
}
