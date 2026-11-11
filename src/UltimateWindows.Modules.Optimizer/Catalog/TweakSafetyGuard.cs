using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Optimizer.Models;

namespace UltimateWindows.Modules.Optimizer.Catalog;

/// <summary>
/// Барьер безопасности Оптимизатора. Делит вмешательства в Windows на три вида:
/// 1) запрещённые всегда — лицензирование Windows и службы, без которых система не загрузится или перестанет работать;
/// 2) ослабляющие защиту (Защитник, SmartScreen, защита ядра, контроль учётных записей, обновления, восстановление) —
///    допустимы только в правилах, честно помеченных как опасные (<see cref="RiskLevel.High"/> и выше);
/// 3) обычные — всё остальное.
/// Опасное правило не входит в наборы и применяется лишь после отдельного подтверждения пользователя,
/// поэтому оно не может включиться «заодно» или под видом безобидной настройки.
/// Те же правила действуют для ручного управления службами и заданиями планировщика.
/// </summary>
public static class TweakSafetyGuard
{
    private static readonly string[] AlwaysForbiddenKeyFragments =
    [
        @"SOFTWAREPROTECTIONPLATFORM",
        @"\SERVICES\SPPSVC",
        @"\SERVICES\CLIPSVC"
    ];

    private static readonly string[] ProtectionWeakeningKeyFragments =
    [
        @"WINDOWS DEFENDER",
        @"DISABLEANTISPYWARE",
        @"DISABLEREALTIMEMONITORING",
        @"WINDEFEND",
        @"SMARTSCREEN",
        @"\DEVICEGUARD",
        @"WINDOWS\CURRENTVERSION\POLICIES\SYSTEM\ENABLELUA",
        @"WINDOWS\CURRENTVERSION\POLICIES\SYSTEM\CONSENTPROMPTBEHAVIOR",
        @"WINDOWS\CURRENTVERSION\POLICIES\SYSTEM\PROMPTONSECUREDESKTOP",
        @"WINDOWSFIREWALL",
        @"\SERVICES\MPSSVC",
        @"\SERVICES\WSCSVC",
        @"\SERVICES\SECURITYHEALTHSERVICE",
        @"\SERVICES\SENSE",
        @"\SERVICES\WDNISSVC",
        @"\SYSTEMRESTORE",
        @"FEATURESETTINGSOVERRIDE",
        @"VULNERABLEDRIVERBLOCKLIST",
        @"WINDOWSUPDATE\AU\NOAUTOUPDATE",
        @"POLICIES\MICROSOFT\MRT"
    ];

    /// <summary>Службы лицензирования Windows: вмешательство запрещено всегда.</summary>
    private static readonly HashSet<string> LicensingServices = new(StringComparer.OrdinalIgnoreCase)
    {
        "sppsvc", "ClipSVC", "LicenseManager"
    };

    /// <summary>Службы, без которых Windows не загрузится, не даст войти или не сможет выполнять программы.</summary>
    private static readonly HashSet<string> VitalServices = new(StringComparer.OrdinalIgnoreCase)
    {
        "RpcSs", "RpcEptMapper", "DcomLaunch", "LSM", "SamSs", "BrokerInfrastructure", "Power", "PlugPlay",
        "ProfSvc", "UserManager", "CoreMessagingRegistrar", "SystemEventsBroker", "Schedule", "EventLog",
        "EventSystem", "gpsvc", "Winmgmt", "CryptSvc", "TrustedInstaller", "AppXSvc", "StateRepository",
        "nsi", "Dhcp", "Dnscache", "BFE", "DeviceInstall", "KeyIso", "TimeBrokerSvc", "TokenBroker",
        "Wcmsvc", "Appinfo", "camsvc", "TextInputManagementService", "WinHttpAutoProxySvc"
    };

    /// <summary>Службы защиты, обновлений и восстановления.</summary>
    private static readonly HashSet<string> ProtectionServices = new(StringComparer.OrdinalIgnoreCase)
    {
        "WinDefend", "WdNisSvc", "WdBoot", "WdFilter", "MDCoreSvc", "Sense", "SecurityHealthService", "wscsvc",
        "mpssvc", "SgrmBroker", "webthreatdefsvc", "webthreatdefusersvc",
        "wuauserv", "UsoSvc", "WaaSMedicSvc", "DoSvc", "BITS",
        "VSS", "swprv", "SDRSVC", "wbengine"
    };

    private static readonly string[] LicensingTaskPrefixes =
    [
        @"\Microsoft\Windows\SoftwareProtectionPlatform\",
        @"\Microsoft\Windows\Clip\",
        @"\Microsoft\Windows\License Manager\"
    ];

    private static readonly string[] ProtectionTaskPrefixes =
    [
        @"\Microsoft\Windows\Windows Defender\",
        @"\Microsoft\Windows\WindowsUpdate\",
        @"\Microsoft\Windows\UpdateOrchestrator\",
        @"\Microsoft\Windows\WaaSMedic\",
        @"\Microsoft\Windows\SystemRestore\",
        @"\Microsoft\Windows\ExploitGuard\",
        @"\Microsoft\Windows\AppID\",
        @"\Microsoft\Windows\TPM\",
        @"\Microsoft\Windows\BitLocker\",
        @"\Microsoft\Windows\RecoveryEnvironment\",
        @"\Microsoft\Windows\CertificateServicesClient\"
    ];

    public static SystemObjectProtection ClassifyService(string? serviceName)
    {
        if (string.IsNullOrWhiteSpace(serviceName))
        {
            return SystemObjectProtection.Critical;
        }

        var name = StripPerUserSuffix(serviceName.Trim());
        if (LicensingServices.Contains(name) || VitalServices.Contains(name))
        {
            return SystemObjectProtection.Critical;
        }

        return ProtectionServices.Contains(name)
            ? SystemObjectProtection.WeakensProtection
            : SystemObjectProtection.None;
    }

    public static SystemObjectProtection ClassifyScheduledTask(string? taskPath)
    {
        if (string.IsNullOrWhiteSpace(taskPath))
        {
            return SystemObjectProtection.Critical;
        }

        var path = taskPath.Trim();
        if (StartsWithAny(path, LicensingTaskPrefixes))
        {
            return SystemObjectProtection.Critical;
        }

        return StartsWithAny(path, ProtectionTaskPrefixes)
            ? SystemObjectProtection.WeakensProtection
            : SystemObjectProtection.None;
    }

    public static SystemObjectProtection Classify(TweakAction? action) => action switch
    {
        TweakRegistryMutation mutation => ClassifyRegistry(mutation),
        TweakServiceAction service => ClassifyService(service.ServiceName),
        TweakScheduledTaskAction task => ClassifyScheduledTask(task.TaskPath),
        _ => SystemObjectProtection.Critical
    };

    /// <summary>
    /// Изменение недопустимо ни при каких условиях.
    /// </summary>
    public static bool IsAlwaysForbidden(TweakAction? action) => Classify(action) == SystemObjectProtection.Critical;

    /// <summary>
    /// Изменение ослабляет защиту Windows и допустимо только в опасном правиле.
    /// </summary>
    public static bool WeakensSystemProtection(TweakAction? action) =>
        Classify(action) == SystemObjectProtection.WeakensProtection;

    /// <summary>
    /// Изменение безопасно: оно не трогает ни защиту Windows, ни лицензирование, ни жизненно важные службы.
    /// </summary>
    public static bool IsSafeAllowedMutation(TweakAction? action) => Classify(action) == SystemObjectProtection.None;

    public static void ThrowIfUnsafeRule(DeclarativeTweakRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        foreach (var action in rule.Actions)
        {
            if (action is null || !HasTarget(action))
            {
                throw new InvalidOperationException(
                    $"В правиле '{rule.TweakId}' есть действие без цели (раздела реестра, службы или задания).");
            }

            var protection = Classify(action);
            if (protection == SystemObjectProtection.Critical)
            {
                throw new InvalidOperationException(
                    $"Защитный фильтр TweakSafetyGuard заблокировал правило '{rule.TweakId}': {DescribeForbidden(action)}");
            }

            if (protection == SystemObjectProtection.WeakensProtection && !rule.IsDangerous)
            {
                throw new InvalidOperationException(
                    $"Защитный фильтр TweakSafetyGuard заблокировал правило '{rule.TweakId}': оно ослабляет защиту Windows ({DescribeTarget(action)}) и должно быть помечено как опасное.");
            }
        }
    }

    /// <summary>
    /// Пояснение для пользователя, почему объект нельзя менять или почему нужно подтверждение.
    /// </summary>
    public static string DescribeProtection(SystemObjectProtection protection) => protection switch
    {
        SystemObjectProtection.Critical => "Защищено: без этого Windows не загрузится или перестанет работать.",
        SystemObjectProtection.WeakensProtection => "Часть защиты, обновлений или восстановления Windows. Изменение требует отдельного подтверждения.",
        _ => ""
    };

    private static SystemObjectProtection ClassifyRegistry(TweakRegistryMutation mutation)
    {
        if (string.IsNullOrWhiteSpace(mutation.SubKeyPath))
        {
            return SystemObjectProtection.Critical;
        }

        var combined = $@"{mutation.Hive}\{mutation.SubKeyPath}\{mutation.ValueName}"
            .Replace('/', '\\')
            .ToUpperInvariant();

        if (ContainsAny(combined, AlwaysForbiddenKeyFragments))
        {
            return SystemObjectProtection.Critical;
        }

        // Тип запуска службы, записанный напрямую в реестр, подчиняется тем же правилам, что и сама служба
        var viaService = ClassifyServiceRegistryPath(mutation.SubKeyPath);
        if (viaService != SystemObjectProtection.None)
        {
            return viaService;
        }

        return ContainsAny(combined, ProtectionWeakeningKeyFragments)
            ? SystemObjectProtection.WeakensProtection
            : SystemObjectProtection.None;
    }

    private static SystemObjectProtection ClassifyServiceRegistryPath(string subKeyPath)
    {
        var name = TryGetServiceNameFromRegistryPath(subKeyPath);
        return name is null ? SystemObjectProtection.None : ClassifyService(name);
    }

    /// <summary>
    /// Имя службы, если путь ведёт в её раздел (<c>SYSTEM\CurrentControlSet\Services\Имя\...</c>), иначе null.
    /// </summary>
    public static string? TryGetServiceNameFromRegistryPath(string? subKeyPath)
    {
        if (string.IsNullOrWhiteSpace(subKeyPath))
        {
            return null;
        }

        var parts = subKeyPath.Replace('/', '\\').Split('\\', StringSplitOptions.RemoveEmptyEntries);
        for (var i = 0; i + 1 < parts.Length; i++)
        {
            if (parts[i].Equals("Services", StringComparison.OrdinalIgnoreCase) &&
                i >= 1 &&
                (parts[i - 1].StartsWith("ControlSet", StringComparison.OrdinalIgnoreCase) ||
                 parts[i - 1].Equals("CurrentControlSet", StringComparison.OrdinalIgnoreCase)))
            {
                return parts[i + 1];
            }
        }

        return null;
    }

    private static bool HasTarget(TweakAction action) => action switch
    {
        TweakRegistryMutation m => !string.IsNullOrWhiteSpace(m.SubKeyPath),
        TweakServiceAction s => !string.IsNullOrWhiteSpace(s.ServiceName),
        TweakScheduledTaskAction t => !string.IsNullOrWhiteSpace(t.TaskPath),
        _ => false
    };

    private static string DescribeTarget(TweakAction action) => action switch
    {
        TweakRegistryMutation m => m.SubKeyPath,
        TweakServiceAction s => $"служба {s.ServiceName}",
        TweakScheduledTaskAction t => $"задание {t.TaskPath}",
        _ => "неизвестная цель"
    };

    private static string DescribeForbidden(TweakAction action)
    {
        switch (action)
        {
            case TweakRegistryMutation m:
                var serviceName = TryGetServiceNameFromRegistryPath(m.SubKeyPath);
                if (serviceName is not null && VitalServices.Contains(StripPerUserSuffix(serviceName)))
                {
                    return $"служба {serviceName} нужна для работы Windows, менять её нельзя ({m.SubKeyPath}).";
                }

                return $"вмешательство в лицензирование Windows запрещено ({m.SubKeyPath}).";

            case TweakServiceAction s when LicensingServices.Contains(StripPerUserSuffix(s.ServiceName)):
                return $"вмешательство в лицензирование Windows запрещено (служба {s.ServiceName}).";

            case TweakServiceAction s:
                return $"служба {s.ServiceName} нужна для работы Windows, менять её тип запуска нельзя.";

            case TweakScheduledTaskAction t:
                return $"вмешательство в лицензирование Windows запрещено (задание {t.TaskPath}).";

            default:
                return "действие неизвестного вида.";
        }
    }

    /// <summary>
    /// Службы отдельных пользователей называются «Имя_суффикс» (например CDPUserSvc_3f2a1); правила задаются по имени без суффикса.
    /// </summary>
    private static string StripPerUserSuffix(string serviceName)
    {
        var underscore = serviceName.LastIndexOf('_');
        if (underscore <= 0 || underscore == serviceName.Length - 1)
        {
            return serviceName;
        }

        var suffix = serviceName.AsSpan(underscore + 1);
        foreach (var ch in suffix)
        {
            if (!Uri.IsHexDigit(ch))
            {
                return serviceName;
            }
        }

        return serviceName[..underscore];
    }

    private static bool ContainsAny(string upperText, string[] fragments)
    {
        foreach (var fragment in fragments)
        {
            if (upperText.Contains(fragment, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static bool StartsWithAny(string text, string[] prefixes)
    {
        var withSeparator = text.EndsWith('\\') ? text : text + "\\";
        foreach (var prefix in prefixes)
        {
            if (withSeparator.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
