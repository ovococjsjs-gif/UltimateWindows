using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using UltimateWindows.Modules.Optimizer.Models;

namespace UltimateWindows.Modules.Optimizer.Network;

/// <summary>
/// Каталог проверенных публичных DNS-серверов, редактор файла hosts с защитой от блокировки антивирусов
/// и многопакетный анализатор задержки сети (ICMP Ping + TCP fallback + джиттер).
/// </summary>
public static class NetworkAndHostsInspector
{
    private static readonly IReadOnlyList<DnsPresetDescriptor> DnsPresets =
    [
        new(
            Id: DnsPresetId.AutomaticDhcp,
            FriendlyName: "Автоматический DNS (DHCP роутера)",
            PrimaryIpv4: "",
            SecondaryIpv4: "",
            DohTemplateUrl: "",
            FriendlyBenefit: "Штатные настройки домашнего роутера или провайдера."),

        new(
            Id: DnsPresetId.CloudflareFast,
            FriendlyName: "Cloudflare 1.1.1.1 (Минимальный пинг)",
            PrimaryIpv4: "1.1.1.1",
            SecondaryIpv4: "1.0.0.1",
            DohTemplateUrl: "https://cloudflare-dns.com/dns-query",
            FriendlyBenefit: "Сверхбыстрый глобальный DNS — ускоряет открытие сайтов и вход в игровые лобби."),

        new(
            Id: DnsPresetId.CloudflareMalwareShield,
            FriendlyName: "Cloudflare 1.1.1.2 (Фильтр вредоносных сайтов)",
            PrimaryIpv4: "1.1.1.2",
            SecondaryIpv4: "1.0.0.2",
            DohTemplateUrl: "https://security.cloudflare-dns.com/dns-query",
            FriendlyBenefit: "Блокирует фишинговые и вредоносные домены на уровне DNS."),

        new(
            Id: DnsPresetId.Quad9Security,
            FriendlyName: "Quad9 Security 9.9.9.9 (Анти-ботнет и майнеры)",
            PrimaryIpv4: "9.9.9.9",
            SecondaryIpv4: "149.112.112.112",
            DohTemplateUrl: "https://dns.quad9.net/dns-query",
            FriendlyBenefit: "Швейцарский защитный DNS с фильтрацией серверов управления троянами и пулов майнеров."),

        new(
            Id: DnsPresetId.GooglePublic,
            FriendlyName: "Google Public DNS 8.8.8.8",
            PrimaryIpv4: "8.8.8.8",
            SecondaryIpv4: "8.8.4.4",
            DohTemplateUrl: "https://dns.google/dns-query",
            FriendlyBenefit: "Высокая стабильность и доступность по всему миру."),

        new(
            Id: DnsPresetId.AdGuardClean,
            FriendlyName: "AdGuard DNS 94.140.14.14 (Без рекламы и трекеров)",
            PrimaryIpv4: "94.140.14.14",
            SecondaryIpv4: "94.140.15.15",
            DohTemplateUrl: "https://dns.adguard-dns.com/dns-query",
            FriendlyBenefit: "Блокирует рекламные баннеры, счетчики и трекеры на системном уровне."),

        new(
            Id: DnsPresetId.YandexBasic,
            FriendlyName: "Яндекс.DNS 77.88.8.8 (Быстрый доступ в РФ/СНГ)",
            PrimaryIpv4: "77.88.8.8",
            SecondaryIpv4: "77.88.8.1",
            DohTemplateUrl: "https://common.dot.dns.yandex.net/dns-query",
            FriendlyBenefit: "Низкая задержка узлов внутри РФ и СНГ.")
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

    public static bool IsProtectedSecurityDomain(string domain) =>
        !string.IsNullOrWhiteSpace(domain) &&
        SecurityAndUpdateDomains.Any(sec => domain.Contains(sec, StringComparison.OrdinalIgnoreCase));

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

                var isSuspicious = (ip is "0.0.0.0" or "127.0.0.1") && IsProtectedSecurityDomain(domain);

                entries.Add(new HostsRedirectEntry(
                    LineNumber: i + 1,
                    RedirectIp: ip,
                    DomainHost: domain,
                    IsSuspiciousSecurityBlock: isSuspicious));
            }
        }

        return entries;
    }

    public static string AppendRuleToHostsText(string existingContent, string ipAddress, string domainHost)
    {
        var sb = new StringBuilder(existingContent ?? "");
        if (sb.Length > 0 && sb[^1] is not '\n' and not '\r')
        {
            sb.AppendLine();
        }

        sb.AppendLine($"{ipAddress.Trim()}\t{domainHost.Trim().ToLowerInvariant()}");
        return sb.ToString();
    }

    public static string RemoveDomainFromHostsText(string existingContent, string ipAddress, string domainHost)
    {
        if (string.IsNullOrWhiteSpace(existingContent))
        {
            return "";
        }

        var outLines = new List<string>();
        foreach (var raw in existingContent.Split(["\r\n", "\n"], StringSplitOptions.None))
        {
            var hashIdx = raw.IndexOf('#');
            var clean = (hashIdx >= 0 ? raw[..hashIdx] : raw).Trim();
            if (!string.IsNullOrWhiteSpace(clean))
            {
                var tokens = clean.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
                if (tokens.Length == 2 &&
                    string.Equals(tokens[0], ipAddress.Trim(), StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(tokens[1], domainHost.Trim(), StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
            }

            outLines.Add(raw);
        }

        return string.Join(Environment.NewLine, outLines);
    }

    /// <summary>
    /// Выполняет полноценный пинг узла (ICMP Echo с автоматическим откатом на TCP 443, если узел закрыл ICMP).
    /// </summary>
    public static async Task<NetworkLatencyReport> MeasureLatencyAndJitterAsync(
        string targetHost = "1.1.1.1",
        int port = 443,
        int sampleCount = 6,
        CancellationToken ct = default)
    {
        sampleCount = Math.Clamp(sampleCount, 2, 25);
        targetHost = string.IsNullOrWhiteSpace(targetHost) ? "1.1.1.1" : targetHost.Trim();

        // Убираем http(s):// если пользователь вставил URL целиком
        if (Uri.TryCreate(targetHost, UriKind.Absolute, out var parsedUri) && !string.IsNullOrWhiteSpace(parsedUri.Host))
        {
            targetHost = parsedUri.Host;
        }

        double dnsMs = 0;
        if (!IPAddress.TryParse(targetHost, out var targetIp))
        {
            var dnsSw = Stopwatch.StartNew();
            var addresses = await Dns.GetHostAddressesAsync(targetHost, ct).ConfigureAwait(false);
            dnsSw.Stop();
            dnsMs = Math.Round(dnsSw.Elapsed.TotalMilliseconds, 1);
            targetIp = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                       ?? addresses.FirstOrDefault()
                       ?? IPAddress.Loopback;
        }

        var samples = new List<double>(sampleCount);
        var packetLines = new List<string>(sampleCount);
        int sent = sampleCount;

        // 1. Сначала пробуем классический ICMP Ping (как в Optimizer Pinger)
        bool icmpWorked = false;
        try
        {
            using var ping = new Ping();
            for (int i = 0; i < sampleCount; i++)
            {
                ct.ThrowIfCancellationRequested();
                var reply = await ping.SendPingAsync(targetIp, TimeSpan.FromMilliseconds(2000), cancellationToken: ct).ConfigureAwait(false);
                if (reply.Status == IPStatus.Success)
                {
                    icmpWorked = true;
                    var ms = Math.Max(0.5, reply.RoundtripTime);
                    samples.Add(ms);
                    packetLines.Add($"Ответ от {targetIp}: время={ms:F0} мс TTL={reply.Options?.Ttl ?? 64}");
                }
                else
                {
                    packetLines.Add($"Пакет #{i + 1}: {reply.Status}");
                }

                if (i + 1 < sampleCount)
                {
                    await Task.Delay(80, ct).ConfigureAwait(false);
                }
            }
        }
        catch
        {
            icmpWorked = false;
        }

        // 2. Если сервер блокирует ICMP — прозрачно измеряем по TCP-рукопожатию порта 443/80
        if (!icmpWorked || samples.Count == 0)
        {
            samples.Clear();
            packetLines.Clear();
            for (int i = 0; i < sampleCount; i++)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var socket = new Socket(targetIp.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                    using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    timeoutCts.CancelAfter(TimeSpan.FromSeconds(2.5));

                    var sw = Stopwatch.StartNew();
                    await socket.ConnectAsync(new IPEndPoint(targetIp, port), timeoutCts.Token).ConfigureAwait(false);
                    sw.Stop();

                    var ms = Math.Round(sw.Elapsed.TotalMilliseconds, 1);
                    samples.Add(ms);
                    packetLines.Add($"TCP {targetIp}:{port} — время отклика = {ms:F1} мс");
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    packetLines.Add($"TCP {targetIp}:{port} — таймаут / закрыт");
                }

                if (i + 1 < sampleCount)
                {
                    await Task.Delay(70, ct).ConfigureAwait(false);
                }
            }
        }

        if (samples.Count == 0)
        {
            return new NetworkLatencyReport(
                TestedEndpoint: targetHost,
                DnsLookupMs: dnsMs,
                MinRttMs: 0,
                AvgRttMs: 0,
                MaxRttMs: 0,
                JitterMs: 0,
                QualityGradeBadge: "Нет ответа",
                FriendlyInterpretation: $"Узел {targetHost} ({targetIp}) не ответил на пакеты (100% потерь или закрыт фаерволом).",
                ResolvedIp: targetIp.ToString(),
                SentCount: sent,
                ReceivedCount: 0,
                PacketLines: packetLines);
        }

        var min = Math.Round(samples.Min(), 1);
        var avg = Math.Round(samples.Average(), 1);
        var max = Math.Round(samples.Max(), 1);

        double jitter = 0;
        if (samples.Count >= 2)
        {
            double jitterSum = 0;
            for (int i = 1; i < samples.Count; i++)
            {
                jitterSum += Math.Abs(samples[i] - samples[i - 1]);
            }

            jitter = Math.Round(jitterSum / (samples.Count - 1), 1);
        }

        var (grade, explanation) = (avg, jitter) switch
        {
            (<= 45, <= 8) => (
                "A+ Отличный пинг",
                $"Стабильный канал ({avg:F1} мс, джиттер {jitter:F1} мс, потерь {sent - samples.Count} из {sent})."),
            (<= 95, <= 22) => (
                "B Стабильная норма",
                $"Хорошее соединение ({avg:F1} мс, джиттер {jitter:F1} мс, DNS {dnsMs:F1} мс)."),
            _ => (
                "C Повышенный джиттер",
                $"Скачки задержки до {max:F1} мс (джиттер {jitter:F1} мс). Проверьте фоновые загрузки.")
        };

        return new NetworkLatencyReport(
            TestedEndpoint: targetHost,
            DnsLookupMs: dnsMs,
            MinRttMs: min,
            AvgRttMs: avg,
            MaxRttMs: max,
            JitterMs: jitter,
            QualityGradeBadge: grade,
            FriendlyInterpretation: explanation,
            ResolvedIp: targetIp.ToString(),
            SentCount: sent,
            ReceivedCount: samples.Count,
            PacketLines: packetLines);
    }

    private static bool IsStandardLocalhostEntry(string ip, string domain)
    {
        return (ip is "127.0.0.1" or "::1") &&
               domain is "localhost" or "localhost.localdomain" or "local" or "ip6-localhost" or "ip6-loopback";
    }
}
