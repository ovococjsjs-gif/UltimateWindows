using System.Text.RegularExpressions;
using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Drivers.Models;

namespace UltimateWindows.Modules.Drivers.Analyzers;

/// <summary>
/// Анализатор 4-компонентных аппаратных ID (VEN/DEV/SUBSYS/REV), кодов ошибок CfgMgr32 (Code 1, 10, 18, 28, 31, 43)
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
        ["10EC"] = ("Realtek", "https://www.realtek.com/Download/Index"),
        ["14E4"] = ("Broadcom", "https://www.broadcom.com/support/download-search"),
        ["14C3"] = ("MediaTek", "https://www.mediatek.com/products/broadband-wifi"),
        ["17CB"] = ("Qualcomm", "https://www.qualcomm.com/support")
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
    /// Оценивает точность совпадения Hardware ID кандидата с реальным устройством:
    /// 100 = полное 4-компонентное совпадение (VEN + DEV + SUBSYS + REV),
    ///  90 = 3-компонентное совпадение OEM-платы (VEN + DEV + SUBSYS),
    ///  65 = базовое 2-компонентное совпадение чипа (VEN + DEV, только если сам кандидат универсальный и не требует чужой SUBSYS!),
    ///   0 = несовпадение или конфликт чужой OEM-подсистемы SUBSYS.
    /// </summary>
    public static int ComputeHardwareIdMatchRank(IReadOnlyList<string> deviceHwIds, string candidateHwId)
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
                "Для этого компонента в Windows еще не установлен драйвер, поэтому он сейчас не работает. Рекомендуется установить подписанный WHQL-драйвер из каталога Microsoft или с сайта производителя."),
            43 => (
                RiskLevel.Critical,
                $"Сбой работы устройства «{name}» (Код 43)",
                "Устройство сообщило Windows об ошибке запуска (часто возникает при повреждении видеодрайвера, сбое кабеля питания PCIe или аппаратной неполадке). Попробуйте чистое переустановление официального WHQL-драйвера."),
            10 => (
                RiskLevel.Attention,
                $"Устройство «{name}» не смогло запуститься (Код 10)",
                "Драйвер установлен, но не смог инициализировать устройство при загрузке. Помогает обновление до свежей WHQL-версии драйвера."),
            1 or 18 => (
                RiskLevel.Attention,
                $"Требуется переустановка драйвера «{name}» (Код {device.ConfigManagerProblemCode})",
                "Конфигурация драйвера нарушена или не завершена. Рекомендуется переустановить подписанный драйвер."),
            31 => (
                RiskLevel.Attention,
                $"Windows не удается загрузить драйвер для «{name}» (Код 31)",
                "Зависимый системный драйвер поврежден или несовместим с текущей сборкой Windows."),
            _ => (
                RiskLevel.Attention,
                $"Проблема в работе устройства «{name}» (Код {device.ConfigManagerProblemCode})",
                "Диспетчер устройств зафиксировал нестандартный код ошибки. Проверьте наличие подписанного WHQL-обновления.")
        };
    }
}
