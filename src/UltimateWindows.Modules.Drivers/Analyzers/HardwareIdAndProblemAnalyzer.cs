using System.Text.RegularExpressions;
using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Drivers.Models;

namespace UltimateWindows.Modules.Drivers.Analyzers;

/// <summary>
/// Анализатор 4-компонентных аппаратных ID (VEN/DEV/SUBSYS/REV + CompatibleIDs), кодов ошибок CfgMgr32
/// и сопоставления с официальными WHQL-порталами производителей без использования сторонних «драйвер-паков».
/// </summary>
public sealed class HardwareIdAndProblemAnalyzer
{
    private static readonly Regex VendorRegex = new(@"(?:VEN_|VID_)([0-9A-Fa-f]{4})", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex DeviceRegex = new(@"(?:DEV_|PID_)([0-9A-Fa-f]{4})", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex SubsysRegex = new(@"SUBSYS_([0-9A-Fa-f]{8})", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex RevRegex = new(@"REV_([0-9A-Fa-f]{2,4})", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Dictionary<string, (string VendorName, string OfficialUrl)> TrustedVendorPortals = new(StringComparer.OrdinalIgnoreCase)
    {
        ["10DE"] = ("NVIDIA", "https://www.nvidia.com/Download/index.aspx"),
        ["1002"] = ("AMD", "https://www.amd.com/en/support"),
        ["1022"] = ("AMD Chipset", "https://www.amd.com/en/support"),
        ["8086"] = ("Intel", "https://www.intel.com/content/www/us/en/download-center/home.html"),
        ["8087"] = ("Intel Wireless Bluetooth", "https://www.intel.com/content/www/us/en/download-center/home.html"),
        ["10EC"] = ("Realtek", "https://www.realtek.com/Download/Index"),
        ["0BDA"] = ("Realtek USB", "https://www.realtek.com/Download/Index"),
        ["14E4"] = ("Broadcom", "https://www.broadcom.com/support/download-search"),
        ["14C3"] = ("MediaTek", "https://www.mediatek.com/products/broadband-wifi"),
        ["0E8D"] = ("MediaTek USB", "https://www.mediatek.com/products/broadband-wifi"),
        ["17CB"] = ("Qualcomm", "https://www.qualcomm.com/support"),
        ["168C"] = ("Qualcomm Atheros", "https://www.qualcomm.com/support"),
        ["1969"] = ("Killer / Qualcomm Ethernet", "https://www.intel.com/content/www/us/en/download-center/home.html"),
        ["1D6A"] = ("Marvell / Aquantia", "https://www.marvell.com/support/downloads.html"),
        ["1B21"] = ("ASMedia", "https://www.asmedia.com.tw/"),
        ["144D"] = ("Samsung", "https://semiconductor.samsung.com/consumer-storage/support/tools/"),
        ["10C4"] = ("Silicon Labs", "https://www.silabs.com/developers/usb-to-uart-bridge-vcp-drivers"),
        ["0403"] = ("FTDI", "https://ftdichip.com/drivers/vcp-drivers/"),
        ["1A86"] = ("WCH (CH340/CH341)", "https://www.wch-ic.com/downloads/CH341SER_ZIP.html"),
        ["1AF4"] = ("Red Hat VirtIO", "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/"),
        ["0B95"] = ("ASIX Electronics", "https://www.asix.com.tw/en/support/download"),
        ["18D1"] = ("Google Android USB", "https://developer.android.com/studio/run/win-usb"),
        ["05AC"] = ("Apple Inc.", "https://support.apple.com/downloads"),
        ["045E"] = ("Microsoft Hardware / Xbox", "https://www.catalog.update.microsoft.com/")
    };

    /// <summary>
    /// Разбирает строку Hardware ID вида PCI\VEN_10DE&amp;DEV_2684&amp;SUBSYS_16A11043&amp;REV_A1 на составные части.
    /// </summary>
    public static HardwareIdParts? ParseHardwareId(string? rawHardwareId)
    {
        if (string.IsNullOrWhiteSpace(rawHardwareId))
        {
            return null;
        }

        var trimmed = rawHardwareId.Trim();
        var slashIdx = trimmed.IndexOf('\\');
        var bus = slashIdx > 0 ? trimmed[..slashIdx].ToUpperInvariant() : "UNKNOWN";

        var venMatch = VendorRegex.Match(trimmed);
        var devMatch = DeviceRegex.Match(trimmed);
        if (!venMatch.Success || !devMatch.Success)
        {
            return null;
        }

        var subsysMatch = SubsysRegex.Match(trimmed);
        var revMatch = RevRegex.Match(trimmed);

        return new HardwareIdParts(
            RawHardwareId: trimmed,
            BusEnumerator: bus,
            VendorId: venMatch.Groups[1].Value.ToUpperInvariant(),
            DeviceId: devMatch.Groups[1].Value.ToUpperInvariant(),
            SubsystemId: subsysMatch.Success ? subsysMatch.Groups[1].Value.ToUpperInvariant() : null,
            RevisionId: revMatch.Success ? revMatch.Groups[1].Value.ToUpperInvariant() : null);
    }

    /// <summary>
    /// Возвращает оптимальный поисковый запрос Hardware ID для Каталога Microsoft Update (например, PCI\VEN_10EC&amp;DEV_8125).
    /// </summary>
    public static string BuildCatalogSearchQuery(SystemDeviceNode device)
    {
        foreach (var raw in device.HardwareIds)
        {
            var parsed = ParseHardwareId(raw);
            if (parsed is not null)
            {
                return parsed.TwoPartQuery;
            }
        }

        return device.HardwareIds.FirstOrDefault() ?? device.FriendlyName;
    }

    /// <summary>
    /// Оценивает точность совпадения Hardware ID кандидата с реальным устройством:
    /// 100 = полное 4-компонентное совпадение (VEN + DEV + SUBSYS + REV),
    ///  90 = 3-компонентное совпадение OEM-платы (VEN + DEV + SUBSYS),
    ///  65 = базовое 2-компонентное совпадение чипа (VEN + DEV, только если сам кандидат универсальный и не требует чужой SUBSYS!),
    ///  45 = совпадение по Compatible IDs,
    ///   0 = несовпадение или конфликт чужой OEM-подсистемы SUBSYS.
    /// </summary>
    public static int ComputeHardwareIdMatchRank(
        IReadOnlyList<string> deviceHwIds,
        string candidateHwId,
        IReadOnlyList<string>? compatibleIds = null)
    {
        var cand = ParseHardwareId(candidateHwId);
        if (cand is null)
        {
            foreach (var raw in deviceHwIds)
            {
                if (string.Equals(raw.Trim(), candidateHwId?.Trim(), StringComparison.OrdinalIgnoreCase))
                {
                    return 85;
                }
            }

            if (compatibleIds is not null)
            {
                foreach (var compat in compatibleIds)
                {
                    if (string.Equals(compat.Trim(), candidateHwId?.Trim(), StringComparison.OrdinalIgnoreCase))
                    {
                        return 45;
                    }
                }
            }

            return 0;
        }

        var bestRank = 0;
        foreach (var rawDevId in deviceHwIds)
        {
            var dev = ParseHardwareId(rawDevId);
            if (dev is null) continue;

            if (!string.Equals(dev.BusEnumerator, cand.BusEnumerator, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(dev.VendorId, cand.VendorId, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(dev.DeviceId, cand.DeviceId, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            // Критическая защита ноутбуков и OEM-плат: если кандидат предназначен для КОНКРЕТНОГО SUBSYS,
            // который отличается от SUBSYS устройства пользователя — строго отвергаем (Rank = 0)!
            if (!string.IsNullOrWhiteSpace(cand.SubsystemId))
            {
                if (!string.Equals(dev.SubsystemId, cand.SubsystemId, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (!string.IsNullOrWhiteSpace(cand.RevisionId) &&
                    string.Equals(dev.RevisionId, cand.RevisionId, StringComparison.OrdinalIgnoreCase))
                {
                    bestRank = Math.Max(bestRank, 100);
                }
                else
                {
                    bestRank = Math.Max(bestRank, 90);
                }
            }
            else
            {
                bestRank = Math.Max(bestRank, 65);
            }
        }

        if (bestRank == 0 && compatibleIds is not null)
        {
            foreach (var rawCompat in compatibleIds)
            {
                if (string.Equals(rawCompat.Trim(), candidateHwId.Trim(), StringComparison.OrdinalIgnoreCase))
                {
                    bestRank = 45;
                    break;
                }
            }
        }

        return bestRank;
    }

    public static (string VendorName, string OfficialPortalUrl)? ResolveOfficialVendorPortal(IReadOnlyList<string> hardwareIds)
    {
        foreach (var raw in hardwareIds)
        {
            var parsed = ParseHardwareId(raw);
            if (parsed is not null && TrustedVendorPortals.TryGetValue(parsed.VendorId, out var portal))
            {
                return (portal.VendorName, portal.OfficialUrl);
            }
        }

        return null;
    }

    public static (RiskLevel Severity, string SimpleTitle, string SimpleExplanation) ExplainProblemCode(SystemDeviceNode device)
    {
        var name = string.IsNullOrWhiteSpace(device.FriendlyName) ? device.InstanceId : device.FriendlyName;
        return device.ConfigManagerProblemCode switch
        {
            28 => (
                RiskLevel.Attention,
                $"Отсутствует драйвер для «{name}» (Код 28)",
                "Для этого компонента в Windows еще не установлен драйвер, поэтому он сейчас не работает. Скачайте подписанный WHQL-драйвер из Каталога Microsoft на вкладке «Каталог с серверов»."),
            43 => (
                RiskLevel.Critical,
                $"Сбой работы устройства «{name}» (Код 43)",
                "Устройство сообщило Windows об ошибке запуска (повреждение драйвера, сбой питания PCIe/USB или аппаратная неполадка). Выполните чистое переустановление WHQL-драйвера."),
            10 => (
                RiskLevel.Attention,
                $"Устройство «{name}» не смогло запуститься (Код 10)",
                "Драйвер установлен, но не смог инициализировать устройство при загрузке. Помогает обновление до свежей WHQL-версии."),
            1 or 18 => (
                RiskLevel.Attention,
                $"Требуется переустановка драйвера «{name}» (Код {device.ConfigManagerProblemCode})",
                "Конфигурация драйвера нарушена или не завершена. Рекомендуется переустановить подписанный драйвер."),
            19 => (
                RiskLevel.Critical,
                $"Повреждены фильтры реестра устройства «{name}» (Код 19)",
                "Windows не может запустить устройство из-за некорректных UpperFilters/LowerFilters в реестре класса."),
            22 => (
                RiskLevel.Safe,
                $"Устройство «{name}» отключено вручную (Код 22)",
                "Адаптер был отключен в Диспетчере устройств пользователем или политикой энергосбережения."),
            31 or 37 or 39 => (
                RiskLevel.Attention,
                $"Windows не удается загрузить драйвер ядра для «{name}» (Код {device.ConfigManagerProblemCode})",
                "Файл системного драйвера (.sys) отсутствует, поврежден или несовместим с текущей сборкой Windows."),
            48 => (
                RiskLevel.Critical,
                $"Драйвер «{name}» заблокирован защитой Windows (Код 48)",
                "Драйвер вызывает сбои стабильности или входит в список заблокированных уязвимых драйверов Microsoft (HVCI). Требуется актуальная версия от производителя."),
            52 => (
                RiskLevel.Critical,
                $"Нарушена цифровая подпись драйвера «{name}» (Код 52)",
                "Windows заблокировала загрузку неподписанного или модифицированного драйвера ядра. Замените его официальным WHQL-пакетом."),
            _ => (
                RiskLevel.Attention,
                $"Проблема в работе устройства «{name}» (Код {device.ConfigManagerProblemCode})",
                "Диспетчер устройств зафиксировал код ошибки. Проверьте наличие подписанного WHQL-обновления в Каталоге Microsoft.")
        };
    }
}
