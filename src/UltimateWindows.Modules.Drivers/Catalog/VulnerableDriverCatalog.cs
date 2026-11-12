using System.Text.Json;
using System.Text.Json.Serialization;
using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Drivers.Models;

namespace UltimateWindows.Modules.Drivers.Catalog;

/// <summary>
/// База известных уязвимых и эксплуатируемых драйверов ядра (BYOVD — LOLDrivers + Microsoft Vulnerable Driver Blocklist).
/// </summary>
public static class VulnerableDriverCatalog
{
    private static readonly Lazy<IReadOnlyList<VulnerableDriverCatalogEntry>> CachedEntries = new(LoadEmbeddedCatalog);

    private static readonly HashSet<string> CriticalBootDriverServices = new(StringComparer.OrdinalIgnoreCase)
    {
        "acpi", "atapi", "cng", "disk", "EhStorClass", "fltmgr", "fvevol", "iaStorV", "iaStorVD",
        "iorate", "ksecdd", "ksecpkg", "mountmgr", "mpio", "msisadrv", "mup", "ndis", "netio",
        "ntfs", "nvraid", "partmgr", "pci", "pcw", "pdc", "rdyboost", "spaceport", "storahci",
        "stornvme", "storport", "tcpip", "volmgr", "volmgrx", "volsnap", "vmbus", "vpci", "Wdf01000"
    };

    public static IReadOnlyList<VulnerableDriverCatalogEntry> GetAllEntries() => CachedEntries.Value;

    public static IReadOnlyList<VulnerableDriverFinding> AuditInventory(
        IReadOnlyList<KernelDriverInventoryEntry> inventory)
    {
        var rules = GetAllEntries();
        var findings = new List<VulnerableDriverFinding>();

        var byHash = new Dictionary<string, VulnerableDriverCatalogEntry>(StringComparer.OrdinalIgnoreCase);
        var byFileName = new Dictionary<string, VulnerableDriverCatalogEntry>(StringComparer.OrdinalIgnoreCase);

        foreach (var rule in rules)
        {
            foreach (var hash in rule.KnownVulnerableSha256)
            {
                if (!string.IsNullOrWhiteSpace(hash))
                {
                    byHash[hash.Trim()] = rule;
                }
            }

            foreach (var fn in rule.FileNamesLower)
            {
                if (!string.IsNullOrWhiteSpace(fn))
                {
                    byFileName[fn.Trim().ToLowerInvariant()] = rule;
                }
            }
        }

        foreach (var drv in inventory)
        {
            VulnerableDriverCatalogEntry? matched = null;
            string reason = "";

            if (!string.IsNullOrWhiteSpace(drv.Sha256Hex) && byHash.TryGetValue(drv.Sha256Hex, out var hashRule))
            {
                matched = hashRule;
                reason = $"Точное совпадение криптохэша SHA-256 ({drv.Sha256Hex[..12]}…)";
            }
            else if (!string.IsNullOrWhiteSpace(drv.FileName) &&
                     byFileName.TryGetValue(drv.FileName.ToLowerInvariant(), out var nameRule))
            {
                matched = nameRule;
                reason = $"Известный уязвимый модуль ядра ({drv.FileName})";
            }

            if (matched is not null)
            {
                bool canNeutralize = !CriticalBootDriverServices.Contains(drv.ServiceName) &&
                                     drv.StartType != 0; // SERVICE_BOOT_START = 0 никогда не трогаем автоматически!

                findings.Add(new VulnerableDriverFinding(
                    FindingId: $"vuln-{drv.ServiceName}-{drv.FileName}",
                    InstalledDriver: drv,
                    MatchedRule: matched,
                    MatchReason: reason,
                    CanSafelyNeutralize: canNeutralize));
            }
        }

        return findings
            .OrderByDescending(f => f.InstalledDriver.IsRunning)
            .ThenByDescending(f => f.MatchedRule.Severity)
            .ToList();
    }

    private static IReadOnlyList<VulnerableDriverCatalogEntry> LoadEmbeddedCatalog()
    {
        var asm = typeof(VulnerableDriverCatalog).Assembly;
        var resName = asm.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith("vulnerable-drivers.json", StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException("Встроенный ресурс vulnerable-drivers.json не найден.");

        using var stream = asm.GetManifestResourceStream(resName)!;
        var dto = JsonSerializer.Deserialize<VulnCatalogRootDto>(stream, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase, allowIntegerValues: true) }
        }) ?? throw new InvalidOperationException("Не удалось разобрать vulnerable-drivers.json.");

        return dto.Entries.Select(e => new VulnerableDriverCatalogEntry(
            Id: e.Id,
            FamilyName: e.FamilyName,
            FileNamesLower: e.FileNamesLower ?? [],
            KnownVulnerableSha256: e.KnownVulnerableSha256 ?? [],
            VendorOrOrigin: e.VendorOrOrigin,
            CveOrAdvisory: e.CveOrAdvisory,
            Severity: e.Severity,
            AbuseExplanation: e.AbuseExplanation,
            SafeAlternative: e.SafeAlternative,
            BlockedByMicrosoftList: e.BlockedByMicrosoftList)).ToList();
    }

    private sealed class VulnCatalogRootDto
    {
        public int SchemaVersion { get; set; }
        public List<VulnEntryDto> Entries { get; set; } = [];
    }

    private sealed class VulnEntryDto
    {
        public string Id { get; set; } = "";
        public string FamilyName { get; set; } = "";
        public List<string>? FileNamesLower { get; set; }
        public List<string>? KnownVulnerableSha256 { get; set; }
        public string VendorOrOrigin { get; set; } = "";
        public string CveOrAdvisory { get; set; } = "";
        public RiskLevel Severity { get; set; } = RiskLevel.Attention;
        public string AbuseExplanation { get; set; } = "";
        public string SafeAlternative { get; set; } = "";
        public bool BlockedByMicrosoftList { get; set; }
    }
}
