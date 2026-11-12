using System.Reflection;
using System.Text.Json;

namespace UltimateWindows.Modules.Security.Catalog;

/// <summary>
/// Встроенный декларативный каталог индикаторов майнеров, пулов Stratum, маскирующихся служб и опасных драйверов.
/// Не содержит сырого вредоносного кода или шеллкодов, поэтому полностью безопасен для антивирусов.
/// </summary>
public sealed class ThreatIndicatorCatalog
{
    private static readonly Lazy<ThreatIndicatorCatalog> SharedLazy = new(LoadEmbeddedCatalog);

    public static ThreatIndicatorCatalog Shared => SharedLazy.Value;

    public ThreatIndicatorCatalog(
        int schemaVersion,
        string catalogVersion,
        IReadOnlyCollection<string> miningPoolDomains,
        IReadOnlyCollection<int> stratumPorts,
        IReadOnlyList<string> minerCliMarkers,
        IReadOnlyCollection<string> criticalSystemBinaries,
        IReadOnlyCollection<string> hollowTargetBinaries,
        IReadOnlyCollection<string> knownRogueServiceAndTaskNames,
        IReadOnlyCollection<string> abusedDriverFileNames,
        IReadOnlyList<string> minerConfigMarkers,
        IReadOnlyCollection<string> defenderCriticalProcessNames)
    {
        SchemaVersion = schemaVersion;
        CatalogVersion = catalogVersion;
        MiningPoolDomains = new HashSet<string>(miningPoolDomains, StringComparer.OrdinalIgnoreCase);
        StratumPorts = new HashSet<int>(stratumPorts);
        MinerCliMarkers = minerCliMarkers;
        CriticalSystemBinaries = new HashSet<string>(criticalSystemBinaries, StringComparer.OrdinalIgnoreCase);
        HollowTargetBinaries = new HashSet<string>(hollowTargetBinaries, StringComparer.OrdinalIgnoreCase);
        KnownRogueServiceAndTaskNames = new HashSet<string>(knownRogueServiceAndTaskNames, StringComparer.OrdinalIgnoreCase);
        AbusedDriverFileNames = new HashSet<string>(abusedDriverFileNames, StringComparer.OrdinalIgnoreCase);
        MinerConfigMarkers = minerConfigMarkers;
        DefenderCriticalProcessNames = new HashSet<string>(defenderCriticalProcessNames, StringComparer.OrdinalIgnoreCase);
    }

    public int SchemaVersion { get; }
    public string CatalogVersion { get; }
    public HashSet<string> MiningPoolDomains { get; }
    public HashSet<int> StratumPorts { get; }
    public IReadOnlyList<string> MinerCliMarkers { get; }
    public HashSet<string> CriticalSystemBinaries { get; }
    public HashSet<string> HollowTargetBinaries { get; }
    public HashSet<string> KnownRogueServiceAndTaskNames { get; }
    public HashSet<string> AbusedDriverFileNames { get; }
    public IReadOnlyList<string> MinerConfigMarkers { get; }
    public HashSet<string> DefenderCriticalProcessNames { get; }

    public bool MatchesMiningPoolDomain(string? candidateHostOrLine, out string matchedDomain)
    {
        matchedDomain = "";
        if (string.IsNullOrWhiteSpace(candidateHostOrLine))
        {
            return false;
        }

        var text = candidateHostOrLine.Trim();
        foreach (var domain in MiningPoolDomains)
        {
            if (text.Equals(domain, StringComparison.OrdinalIgnoreCase) ||
                text.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase) ||
                text.Contains(domain, StringComparison.OrdinalIgnoreCase))
            {
                matchedDomain = domain;
                return true;
            }
        }

        return false;
    }

    private static ThreatIndicatorCatalog LoadEmbeddedCatalog()
    {
        var asm = typeof(ThreatIndicatorCatalog).Assembly;
        var resourceName = asm.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith("threat-indicators.json", StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException("Не найден встроенный ресурс каталога threat-indicators.json.");

        using var stream = asm.GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException($"Не удалось открыть ресурс {resourceName}.");

        var dto = JsonSerializer.Deserialize<ThreatIndicatorDto>(stream, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        }) ?? throw new InvalidOperationException("Не удалось десериализовать threat-indicators.json.");

        return new ThreatIndicatorCatalog(
            dto.SchemaVersion,
            dto.CatalogVersion ?? "2026.11",
            dto.MiningPoolDomains ?? [],
            dto.StratumPorts ?? [],
            dto.MinerCliMarkers ?? [],
            dto.CriticalSystemBinaries ?? [],
            dto.HollowTargetBinaries ?? [],
            dto.KnownRogueServiceAndTaskNames ?? [],
            dto.AbusedDriverFileNames ?? [],
            dto.MinerConfigMarkers ?? [],
            dto.DefenderCriticalProcessNames ?? []);
    }

    private sealed class ThreatIndicatorDto
    {
        public int SchemaVersion { get; set; }
        public string? CatalogVersion { get; set; }
        public List<string>? MiningPoolDomains { get; set; }
        public List<int>? StratumPorts { get; set; }
        public List<string>? MinerCliMarkers { get; set; }
        public List<string>? CriticalSystemBinaries { get; set; }
        public List<string>? HollowTargetBinaries { get; set; }
        public List<string>? KnownRogueServiceAndTaskNames { get; set; }
        public List<string>? AbusedDriverFileNames { get; set; }
        public List<string>? MinerConfigMarkers { get; set; }
        public List<string>? DefenderCriticalProcessNames { get; set; }
    }
}
