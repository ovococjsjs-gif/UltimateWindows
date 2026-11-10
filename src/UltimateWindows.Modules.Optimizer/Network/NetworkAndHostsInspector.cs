using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using UltimateWindows.Modules.Optimizer.Models;

namespace UltimateWindows.Modules.Optimizer.Network;

/// <summary>
/// Каталог проверенных публичных DNS-серверов, инспектор файла hosts и анализатор стабильности сети (джиттер / задержки).
/// </summary>
public static class NetworkAndHostsInspector
{
    private static readonly IReadOnlyList<DnsPresetDescriptor> DnsPresets =
    [
        new(
            Id: DnsPresetId.AutomaticDhcp,
            FriendlyName: "Автоматический DNS провайдера (по умолчанию)",
            PrimaryIpv4: "",
            SecondaryIpv4: "",
            DohTemplateUrl: "",
            FriendlyBenefit: "Штатные настройки домашнего роутера или провайдера."),

        new(
            Id: DnsPresetId.CloudflareFast,
            FriendlyName: "Cloudflare 1.1.1.1 (Максимальная скорость отклика)",
            PrimaryIpv4: "1.1.1.1",
            SecondaryIpv4: "1.0.0.1",
            DohTemplateUrl: "https://cloudflare-dns.com/dns-query",
            FriendlyBenefit: "Один из самых быстрых DNS в мире — ускоряет первое открытие сайтов и игровых лобби."),

        new(
            Id: DnsPresetId.CloudflareMalwareShield,
            FriendlyName: "Cloudflare 1.1.1.2 (Защита от фишинга и вредоносных сайтов)",
            PrimaryIpv4: "1.1.1.2",
            SecondaryIpv4: "1.0.0.2",
            DohTemplateUrl: "https://security.cloudflare-dns.com/dns-query",
            FriendlyBenefit: "Автоматически блокирует известные вредоносные и фишинговые домены на уровне DNS."),

        new(
            Id: DnsPresetId.Quad9Security,
            FriendlyName: "Quad9 Security 9.9.9.9 (Швейцарский фильтр ботнетов и майнеров)",
            PrimaryIpv4: "9.9.9.9",
            SecondaryIpv4: "149.112.112.112",
            DohTemplateUrl: "https://dns.quad9.net/dns-query",
            FriendlyBenefit: "Некоммерческий защитный DNS с фильтрацией серверов управления троянами и скрытыми майнерами."),

        new(
            Id: DnsPresetId.GooglePublic,
            FriendlyName: "Google Public DNS 8.8.8.8",
            PrimaryIpv4: "8.8.8.8",
            SecondaryIpv4: "8.8.4.4",
            DohTemplateUrl: "https://dns.google/dns-query",
            FriendlyBenefit: "Высокая глобальная надежность и стабильность разрешения сложных доменов."),

        new(
            Id: DnsPresetId.AdGuardClean,
            FriendlyName: "AdGuard DNS (Защита от трекеров и рекламных сетей)",
            PrimaryIpv4: "94.140.14.14",
            SecondaryIpv4: "94.140.15.15",
            DohTemplateUrl: "https://dns.adguard-dns.com/dns-query",
            FriendlyBenefit: "Снижает количество всплывающих баннеров и фоновых рекламных трекеров.")
    ];

    private static readonly string[] SecurityAndUpdateDomains =
    [
        "windowsupdate.com",
        "update.microsoft.com",
        "defender",
        "smartscreen",
        "kaspersky",
        "drweb",
        "malwarebytes",
        "eset",
        "virustotal"
    ];

    public static IReadOnlyList<DnsPresetDescriptor> GetDnsPresets() => DnsPresets;

    public static DnsPresetDescriptor GetPresetById(DnsPresetId id) =>
        DnsPresets.First(p => p.Id == id);

    /// <summary>
    /// Разбирает содержимое системного файла hosts, игнорируя стандартные комментарии и localhost,
    /// и помечает подозрительные блокировки сайтов антивирусов и обновлений Windows (признак майнера/вируса).
    /// </summary>
    public static IReadOnlyList<HostsRedirectEntry> ParseHostsContent(string? hostsText)
    {
        if (string.IsNullOrWhiteSpace(hostsText))
        {
            return Array.Empty<HostsRedirectEntry>();
        }

        var entries = new List<HostsRedirectEntry>();
        var lines = hostsText.Split(['\r', '\n']);

        for (int i = 0; i < lines.Length; i++)
        {
            var raw = lines[i];
            var hashIdx = raw.IndexOf('#');
            var clean = (hashIdx >= 0 ? raw[..hashIdx] : raw).Trim();
            if (string.IsNullOrWhiteSpace(clean))
            {
                continue;
            }

            var tokens = clean.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length < 2)
            {
                continue;
            }

            var ip = tokens[0];
            for (int t = 1; t < tokens.Length; t++)
            {
                var domain = tokens[t].Trim().ToLowerInvariant();
                if (IsStandardLocalhostEntry(ip, domain))
                {
                    continue;
                }

                var isSuspicious = (ip is "0.0.0.0" or "127.0.0.1") &&
                                   SecurityAndUpdateDomains.Any(sec => domain.Contains(sec, StringComparison.OrdinalIgnoreCase));

                entries.Add(new HostsRedirectEntry(
                    LineNumber: i + 1,
                    RedirectIp: ip,
                    DomainHost: domain,
                    IsSuspiciousSecurityBlock: isSuspicious));
            }
        }

        return entries;
    }

    /// <summary>
    /// Проводит серию замеров TCP-рукопожатий и DNS-разрешения для оценки среднего пинга и джиттера (стабильности канала).
    /// </summary>
    public static async Task<NetworkLatencyReport> MeasureLatencyAndJitterAsync(
        string targetHost = "1.1.1.1",
        int port = 443,
        int sampleCount = 5,
        CancellationToken ct = default)
    {
        sampleCount = Math.Clamp(sampleCount, 2, 12);
        double dnsMs = 0;

        if (!IPAddress.TryParse(targetHost, out var targetIp))
        {
            var dnsSw = Stopwatch.StartNew();
            var addresses = await Dns.GetHostAddressesAsync(targetHost, ct).ConfigureAwait(false);
            dnsSw.Stop();
            dnsMs = Math.Round(dnsSw.Elapsed.TotalMilliseconds, 1);
            targetIp = addresses.FirstOrDefault() ?? IPAddress.Loopback;
        }

        var samples = new List<double>(sampleCount);
        for (int i = 0; i < sampleCount; i++)
        {
            ct.ThrowIfCancellationRequested();
            using var socket = new Socket(targetIp.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(3));

            var sw = Stopwatch.StartNew();
            await socket.ConnectAsync(new IPEndPoint(targetIp, port), timeoutCts.Token).ConfigureAwait(false);
            sw.Stop();

            samples.Add(sw.Elapsed.TotalMilliseconds);
            if (i + 1 < sampleCount)
            {
                await Task.Delay(60, ct).ConfigureAwait(false);
            }
        }

        var min = Math.Round(samples.Min(), 1);
        var avg = Math.Round(samples.Average(), 1);
        var max = Math.Round(samples.Max(), 1);

        // Джиттер = среднее абсолютное отклонение между соседними пакетами
        double jitterSum = 0;
        for (int i = 1; i < samples.Count; i++)
        {
            jitterSum += Math.Abs(samples[i] - samples[i - 1]);
        }

        var jitter = Math.Round(jitterSum / (samples.Count - 1), 1);

        var (grade, explanation) = (avg, jitter) switch
        {
            (<= 45, <= 8) => (
                "A+ Идеально для игр",
                $"Стабильный канал с минимальным разбросом задержки ({jitter} мс). Микролаги сети и Bufferbloat отсутствуют."),
            (<= 90, <= 20) => (
                "B Стабильная норма",
                $"Хорошее соединение для работы, видеозвонков и большинства игр (разброс пакетов {jitter} мс)."),
            _ => (
                "C Заметный джиттер / нагрузка",
                $"Обнаружены скачки задержки до {max} мс (джиттер {jitter} мс). Проверьте фоновые загрузки торрентов или включите QoS/SQM на роутере.")
        };

        return new NetworkLatencyReport(
            TestedEndpoint: $"{targetHost}:{port}",
            DnsLookupMs: dnsMs,
            MinRttMs: min,
            AvgRttMs: avg,
            MaxRttMs: max,
            JitterMs: jitter,
            QualityGradeBadge: grade,
            FriendlyInterpretation: explanation);
    }

    private static bool IsStandardLocalhostEntry(string ip, string domain)
    {
        return (ip is "127.0.0.1" or "::1") &&
               domain is "localhost" or "localhost.localdomain" or "local" or "ip6-localhost" or "ip6-loopback";
    }
}
