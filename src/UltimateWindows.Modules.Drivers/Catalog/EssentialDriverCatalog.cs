using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using UltimateWindows.Modules.Drivers.Models;

namespace UltimateWindows.Modules.Drivers.Catalog;

/// <summary>
/// Декларативный каталог основных драйверов на все случаи жизни (essential-drivers.json),
/// поддерживающий прямое скачивание с серверов вендоров (HTTPS) и серверов Microsoft Update Catalog (.cab WHQL).
/// </summary>
public static class EssentialDriverCatalog
{
    private static readonly Lazy<IReadOnlyList<EssentialDriverPackage>> CachedPackages = new(LoadEmbeddedCatalog);

    private static readonly Dictionary<EssentialDriverCategory, string> CategoryLabels = new()
    {
        [EssentialDriverCategory.EthernetLan] = "Проводной интернет (LAN 1G / 2.5G / USB)",
        [EssentialDriverCategory.WiFiWireless] = "Беспроводные сети Wi-Fi 5 / 6 / 6E / 7",
        [EssentialDriverCategory.BluetoothAndTethering] = "Bluetooth и модемы смартфонов (USB)",
        [EssentialDriverCategory.GpuAndAssistants] = "Видеокарты и автоподборщики (GPU)",
        [EssentialDriverCategory.ChipsetAndMotherboard] = "Чипсеты, питание и тачпады ноутбуков",
        [EssentialDriverCategory.StorageNvmeRaid] = "Диски NVMe / VMD / RAID (для установки ОС)",
        [EssentialDriverCategory.AudioSound] = "Звук и микрофоны (Realtek / Intel SST)",
        [EssentialDriverCategory.UsbSerialIoT] = "USB-COM, прошивка, Arduino и сканеры авто",
        [EssentialDriverCategory.VirtualizationVm] = "Виртуальные машины (Proxmox / KVM VirtIO)",
        [EssentialDriverCategory.InputAndSensors] = "Геймпады и датчики HVCI (PawnIO)"
    };

    public static IReadOnlyList<EssentialDriverPackage> GetAllPackages() => CachedPackages.Value;

    public static EssentialDriverPackage? FindById(string id) =>
        GetAllPackages().FirstOrDefault(p => string.Equals(p.Id, id, StringComparison.OrdinalIgnoreCase));

    public static IReadOnlyList<EssentialDriverPackage> GetUniversalRescuePackages() =>
        GetAllPackages().Where(p => p.IncludeInUniversalNetworkRescuePack).ToList();

    public static IReadOnlyList<(EssentialDriverCategory? Category, string Title)> GetCategoryFilterOptions()
    {
        var list = new List<(EssentialDriverCategory?, string)> { (null, "Все сценарии и категории") };
        foreach (var kv in CategoryLabels)
        {
            list.Add((kv.Key, kv.Value));
        }

        return list;
    }

    public static string GetCategoryTitle(EssentialDriverCategory category) =>
        CategoryLabels.TryGetValue(category, out var title) ? title : category.ToString();

    public static IReadOnlyList<EssentialDriverEvaluatedItem> EvaluateForDevices(
        IReadOnlyList<SystemDeviceNode> devices)
    {
        var packages = GetAllPackages();
        var results = new List<EssentialDriverEvaluatedItem>(packages.Count);

        foreach (var pkg in packages)
        {
            SystemDeviceNode? matchedDevice = null;
            bool needsAttention = false;

            if (pkg.HardwareIdPrefixes.Count > 0 && devices.Count > 0)
            {
                foreach (var dev in devices)
                {
                    if (MatchesAnyPrefix(dev, pkg.HardwareIdPrefixes))
                    {
                        if (matchedDevice is null || dev.HasProblem || dev.IsBasicDisplayFallback)
                        {
                            matchedDevice = dev;
                        }

                        if (dev.HasProblem || dev.IsBasicDisplayFallback)
                        {
                            needsAttention = true;
                        }
                    }
                }
            }

            string? summary = matchedDevice is null
                ? null
                : (needsAttention
                    ? $"Требуется драйвер: {matchedDevice.FriendlyName} ({matchedDevice.StatusBadge})"
                    : $"Обнаружено в ПК: {matchedDevice.FriendlyName} ({(string.IsNullOrWhiteSpace(matchedDevice.DriverVersion) ? "штатный" : matchedDevice.DriverVersion)})");

            results.Add(new EssentialDriverEvaluatedItem(
                Package: pkg,
                MatchesCurrentPcHardware: matchedDevice is not null,
                NeedsAttentionOnCurrentPc: needsAttention,
                MatchedDeviceSummary: summary));
        }

        return results
            .OrderByDescending(x => x.NeedsAttentionOnCurrentPc)
            .ThenByDescending(x => x.MatchesCurrentPcHardware)
            .ThenBy(x => x.Package.Category)
            .ToList();
    }

    private static bool MatchesAnyPrefix(SystemDeviceNode dev, IReadOnlyList<string> prefixes)
    {
        foreach (var prefix in prefixes)
        {
            foreach (var hwId in dev.HardwareIds)
            {
                if (hwId.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            if (dev.InstanceId.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static IReadOnlyList<EssentialDriverPackage> LoadEmbeddedCatalog()
    {
        var asm = typeof(EssentialDriverCatalog).Assembly;
        var resName = asm.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith("essential-drivers.json", StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException("Встроенный ресурс essential-drivers.json не найден.");

        using var stream = asm.GetManifestResourceStream(resName)!;
        var dto = JsonSerializer.Deserialize<EssentialCatalogRootDto>(stream, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase, allowIntegerValues: true) }
        }) ?? throw new InvalidOperationException("Не удалось разобрать essential-drivers.json.");

        return dto.Packages.Select(p => new EssentialDriverPackage(
            Id: p.Id,
            Title: p.Title,
            Category: p.Category,
            CategoryLabel: GetCategoryTitle(p.Category),
            Vendor: p.Vendor,
            ScenarioSummary: p.ScenarioSummary,
            DeliveryKind: p.DeliveryKind,
            DirectDownloadUrl: p.DirectDownloadUrl,
            CatalogSearchQuery: p.CatalogSearchQuery,
            OfficialPortalUrl: p.OfficialPortalUrl,
            WingetPackageId: p.WingetPackageId,
            SilentInstallArgs: p.SilentInstallArgs,
            HardwareIdPrefixes: p.HardwareIdPrefixes ?? [],
            IncludeInUniversalNetworkRescuePack: p.IncludeInUniversalNetworkRescuePack,
            EstimatedSizeLabel: p.EstimatedSizeLabel)).ToList();
    }

    private sealed class EssentialCatalogRootDto
    {
        public int SchemaVersion { get; set; }
        public List<EssentialPackageDto> Packages { get; set; } = [];
    }

    private sealed class EssentialPackageDto
    {
        public string Id { get; set; } = "";
        public string Title { get; set; } = "";
        public EssentialDriverCategory Category { get; set; }
        public string Vendor { get; set; } = "";
        public string ScenarioSummary { get; set; } = "";
        public EssentialDriverDeliveryKind DeliveryKind { get; set; }
        public string? DirectDownloadUrl { get; set; }
        public string? CatalogSearchQuery { get; set; }
        public string OfficialPortalUrl { get; set; } = "";
        public string? WingetPackageId { get; set; }
        public string? SilentInstallArgs { get; set; }
        public List<string>? HardwareIdPrefixes { get; set; }
        public bool IncludeInUniversalNetworkRescuePack { get; set; }
        public string EstimatedSizeLabel { get; set; } = "";
    }
}
