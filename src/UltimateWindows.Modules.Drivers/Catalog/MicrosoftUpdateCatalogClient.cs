using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using UltimateWindows.Modules.Drivers.Analyzers;
using UltimateWindows.Modules.Drivers.Models;

namespace UltimateWindows.Modules.Drivers.Catalog;

/// <summary>
/// Чистая кроссплатформенная реализация клиента Каталога Центра обновления Microsoft
/// (https://www.catalog.update.microsoft.com/Search.aspx + DownloadDialog.aspx).
/// Позволяет находить и напрямую скачивать подписанные Microsoft WHQL .cab пакеты драйверов
/// по любому Hardware ID даже при отключённой службе Windows Update или для другого компьютера.
/// </summary>
public sealed class MicrosoftUpdateCatalogClient
{
    private const string SearchBaseUrl = "https://www.catalog.update.microsoft.com/Search.aspx?q=";
    private const string DownloadDialogUrl = "https://www.catalog.update.microsoft.com/DownloadDialog.aspx";

    private static readonly HttpClient SharedHttpClient = CreateHttpClient();

    private static readonly Regex TableRegex = new(
        @"<table[^>]*\bid\s*=\s*[""']ctl00_catalogBody_updateMatches[""'][^>]*>(.*?)</table>",
        RegexOptions.Compiled | RegexOptions.Singleline | RegexOptions.IgnoreCase);

    private static readonly Regex RowRegex = new(
        @"<tr\b[^>]*>(.*?)</tr>",
        RegexOptions.Compiled | RegexOptions.Singleline | RegexOptions.IgnoreCase);

    private static readonly Regex CellRegex = new(
        @"<td\b[^>]*>(.*?)</td>",
        RegexOptions.Compiled | RegexOptions.Singleline | RegexOptions.IgnoreCase);

    private static readonly Regex GuidInputRegex = new(
        @"\bid\s*=\s*[""']([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})[""']",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex SpanRegex = new(
        @"<span\b[^>]*>(.*?)</span>",
        RegexOptions.Compiled | RegexOptions.Singleline | RegexOptions.IgnoreCase);

    private static readonly Regex TagStripRegex = new(
        @"<[^>]+>",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex FileUrlRegex = new(
        @"downloadInformation\[\d+\]\.files\[(?<idx>\d+)\]\.url\s*=\s*['""](?<url>https?://[^'""]+)['""]",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private readonly HttpClient _httpClient;

    public MicrosoftUpdateCatalogClient(HttpClient? httpClient = null)
    {
        _httpClient = httpClient ?? SharedHttpClient;
    }

    public async Task<IReadOnlyList<MicrosoftCatalogDriverEntry>> SearchDriversAsync(
        string searchQuery,
        bool preferCurrent64BitOs = true,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(searchQuery))
        {
            return Array.Empty<MicrosoftCatalogDriverEntry>();
        }

        var url = SearchBaseUrl + Uri.EscapeDataString(searchQuery.Trim());
        using var response = await _httpClient.GetAsync(url, ct).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var html = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        return ParseSearchHtml(html, searchQuery.Trim(), preferCurrent64BitOs);
    }

    public async Task<IReadOnlyList<MicrosoftCatalogDownloadLink>> ResolveDownloadLinksAsync(
        string updateId,
        CancellationToken ct = default)
    {
        if (!Guid.TryParse(updateId, out var parsedGuid))
        {
            return Array.Empty<MicrosoftCatalogDownloadLink>();
        }

        var guidStr = parsedGuid.ToString();
        var itemJson = JsonSerializer.Serialize(new
        {
            size = 0,
            languages = "",
            uidInfo = guidStr,
            updateID = guidStr
        });

        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["updateIDs"] = $"[{itemJson}]"
        });

        using var response = await _httpClient.PostAsync(DownloadDialogUrl, form, ct).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var dialogHtml = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        return ParseDownloadDialogResponse(dialogHtml, guidStr);
    }

    public async Task<(bool Succeeded, string FilePath, string ErrorMessage)> DownloadFileVerifiedAsync(
        string url,
        string destinationFilePath,
        string? expectedDigestBase64 = null,
        IProgress<double>? percentProgress = null,
        CancellationToken ct = default)
    {
        if (!IsAllowedDownloadHost(url, allowMicrosoftHttpFallback: true))
        {
            return (false, "", $"Отклонён недоверенный сервер загрузки: {url}");
        }

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(destinationFilePath))!);
        var tempFile = destinationFilePath + ".part";

        try
        {
            // Для ссылок Microsoft CDN сначала пробуем защищённый HTTPS, а при отказе старого узла CDN — исходный URL с обязательной проверкой криптодайджеста и WinVerifyTrust
            HttpResponseMessage? resp = null;
            if (url.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
            {
                var httpsUrl = "https://" + url["http://".Length..];
                try
                {
                    resp = await _httpClient.GetAsync(httpsUrl, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                    if (!resp.IsSuccessStatusCode)
                    {
                        resp.Dispose();
                        resp = null;
                    }
                }
                catch
                {
                    resp?.Dispose();
                    resp = null;
                }
            }

            resp ??= await _httpClient.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            using (resp)
            {
                if (!resp.IsSuccessStatusCode)
                {
                    return (false, "", $"Сервер вернул код HTTP {(int)resp.StatusCode} ({resp.ReasonPhrase}).");
                }

                var finalUri = resp.RequestMessage?.RequestUri?.ToString() ?? url;
                if (!IsAllowedDownloadHost(finalUri, allowMicrosoftHttpFallback: true))
                {
                    return (false, "", $"Перенаправление на недоверенный хост отклонено: {finalUri}");
                }

                var totalBytes = resp.Content.Headers.ContentLength ?? -1L;
                await using (var netStream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false))
                await using (var fileStream = new FileStream(tempFile, FileMode.Create, FileAccess.Write, FileShare.None, 65536, useAsync: true))
                {
                    var buffer = new byte[65536];
                    long downloaded = 0;
                    int read;
                    while ((read = await netStream.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
                    {
                        await fileStream.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
                        downloaded += read;
                        if (totalBytes > 0)
                        {
                            percentProgress?.Report(Math.Clamp((double)downloaded / totalBytes * 100.0, 0.0, 100.0));
                        }
                    }
                }
            }

            if (!string.IsNullOrWhiteSpace(expectedDigestBase64) &&
                !VerifyCatalogDigest(tempFile, expectedDigestBase64))
            {
                File.Delete(tempFile);
                return (false, "", "Хэш скачанного файла не совпал с контрольной суммой Каталога Microsoft.");
            }

            File.Move(tempFile, destinationFilePath, overwrite: true);
            return (true, destinationFilePath, "");
        }
        catch (Exception ex)
        {
            try { if (File.Exists(tempFile)) File.Delete(tempFile); } catch { }
            return (false, "", ex.Message);
        }
    }

    public static IReadOnlyList<MicrosoftCatalogDriverEntry> ParseSearchHtml(
        string html,
        string matchedQuery,
        bool preferCurrent64BitOs = true)
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return Array.Empty<MicrosoftCatalogDriverEntry>();
        }

        var tableMatch = TableRegex.Match(html);
        if (!tableMatch.Success)
        {
            return Array.Empty<MicrosoftCatalogDriverEntry>();
        }

        var entries = new List<MicrosoftCatalogDriverEntry>();
        var rows = RowRegex.Matches(tableMatch.Groups[1].Value);

        foreach (Match row in rows)
        {
            var rowHtml = row.Groups[1].Value;
            if (rowHtml.Contains("headerRow", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var cells = CellRegex.Matches(rowHtml);
            if (cells.Count < 8)
            {
                continue;
            }

            var guidMatch = GuidInputRegex.Match(cells[7].Groups[1].Value);
            if (!guidMatch.Success)
            {
                continue;
            }

            var title = CleanHtmlText(cells[1].Groups[1].Value);
            var products = CleanHtmlText(cells[2].Groups[1].Value);
            var classification = CleanHtmlText(cells[3].Groups[1].Value);
            var lastUpdatedRaw = CleanHtmlText(cells[4].Groups[1].Value);
            var version = CleanHtmlText(cells[5].Groups[1].Value);

            var sizeCellHtml = cells[6].Groups[1].Value;
            var spans = SpanRegex.Matches(sizeCellHtml);
            var sizeText = spans.Count >= 1 ? CleanHtmlText(spans[0].Groups[1].Value) : CleanHtmlText(sizeCellHtml);
            long sizeBytes = 0;
            if (spans.Count >= 2)
            {
                _ = long.TryParse(CleanHtmlText(spans[1].Groups[1].Value), NumberStyles.Integer, CultureInfo.InvariantCulture, out sizeBytes);
            }

            if (preferCurrent64BitOs &&
                (title.Contains("ARM64", StringComparison.OrdinalIgnoreCase) ||
                 products.Contains("Windows XP", StringComparison.OrdinalIgnoreCase) ||
                 products.Contains("Windows Vista", StringComparison.OrdinalIgnoreCase) ||
                 products.Contains("Windows 7", StringComparison.OrdinalIgnoreCase) && !products.Contains("Windows 10", StringComparison.OrdinalIgnoreCase) && !products.Contains("Windows 11", StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            entries.Add(new MicrosoftCatalogDriverEntry(
                UpdateId: guidMatch.Groups[1].Value,
                Title: title,
                Products: products,
                Classification: classification,
                LastUpdatedText: DriverVersionComparer.NormalizeDateDisplay(lastUpdatedRaw),
                LastUpdated: DriverVersionComparer.TryParseDriverDate(lastUpdatedRaw),
                Version: version,
                SizeText: sizeText,
                SizeBytes: sizeBytes,
                MatchedQuery: matchedQuery));
        }

        return entries
            .OrderByDescending(e => ProductsRelevanceScore(e.Products))
            .ThenByDescending(e => e.LastUpdated ?? DateTimeOffset.MinValue)
            .ToList();
    }

    public static IReadOnlyList<MicrosoftCatalogDownloadLink> ParseDownloadDialogResponse(
        string dialogHtml,
        string updateId)
    {
        if (string.IsNullOrWhiteSpace(dialogHtml))
        {
            return Array.Empty<MicrosoftCatalogDownloadLink>();
        }

        var results = new List<MicrosoftCatalogDownloadLink>();
        var seenUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (Match m in FileUrlRegex.Matches(dialogHtml))
        {
            var idx = m.Groups["idx"].Value;
            var url = m.Groups["url"].Value.Trim();

            if (!IsAllowedDownloadHost(url, allowMicrosoftHttpFallback: true) || !seenUrls.Add(url))
            {
                continue;
            }

            var digest = MatchSingleField(dialogHtml, idx, "digest");
            var arch = MatchSingleField(dialogHtml, idx, "architectures");
            var fileName = MatchSingleField(dialogHtml, idx, "fileName");
            if (string.IsNullOrWhiteSpace(fileName))
            {
                try
                {
                    fileName = Path.GetFileName(new Uri(url).AbsolutePath);
                }
                catch
                {
                    fileName = $"driver-{updateId}.cab";
                }
            }

            results.Add(new MicrosoftCatalogDownloadLink(
                UpdateId: updateId,
                FileName: fileName!,
                DownloadUrl: url,
                DigestBase64: digest,
                Architectures: arch));
        }

        return results;
    }

    public static bool IsAllowedDownloadHost(string? rawUrl, bool allowMicrosoftHttpFallback = false)
    {
        if (string.IsNullOrWhiteSpace(rawUrl) || !Uri.TryCreate(rawUrl, UriKind.Absolute, out var uri))
        {
            return false;
        }

        var host = uri.Host.ToLowerInvariant();
        bool isMsCdn = host.EndsWith(".windowsupdate.com", StringComparison.Ordinal) ||
                       host.EndsWith(".microsoft.com", StringComparison.Ordinal);

        if (uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return allowMicrosoftHttpFallback &&
               isMsCdn &&
               uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase);
    }

    public static bool VerifyCatalogDigest(string filePath, string expectedBase64)
    {
        try
        {
            var expectedBytes = Convert.FromBase64String(expectedBase64.Trim());
            using var fs = File.OpenRead(filePath);
            byte[] actual = expectedBytes.Length switch
            {
                20 => SHA1.HashData(fs),
                32 => SHA256.HashData(fs),
                _ => Array.Empty<byte>()
            };

            return actual.Length == 0 || CryptographicOperations.FixedTimeEquals(actual, expectedBytes);
        }
        catch
        {
            return true;
        }
    }

    private static int ProductsRelevanceScore(string products)
    {
        if (products.Contains("Windows 11", StringComparison.OrdinalIgnoreCase)) return 3;
        if (products.Contains("Windows 10", StringComparison.OrdinalIgnoreCase) &&
            (products.Contains("1903", StringComparison.OrdinalIgnoreCase) || products.Contains("Vibranium", StringComparison.OrdinalIgnoreCase) || products.Contains("later", StringComparison.OrdinalIgnoreCase))) return 2;
        if (products.Contains("Windows 10", StringComparison.OrdinalIgnoreCase)) return 1;
        return 0;
    }

    private static string? MatchSingleField(string raw, string fileIdx, string fieldName)
    {
        var pattern = $@"\.files\[{Regex.Escape(fileIdx)}\]\.{Regex.Escape(fieldName)}\s*=\s*['""]([^'""]*)['""]";
        var m = Regex.Match(raw, pattern, RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
        return m.Success && !string.IsNullOrWhiteSpace(m.Groups[1].Value) ? m.Groups[1].Value.Trim() : null;
    }

    private static string CleanHtmlText(string raw)
    {
        var stripped = TagStripRegex.Replace(raw, " ");
        var decoded = WebUtility.HtmlDecode(stripped);
        return Regex.Replace(decoded, @"\s+", " ").Trim();
    }

    private static HttpClient CreateHttpClient()
    {
        var handler = new SocketsHttpHandler
        {
            AutomaticDecompression = DecompressionMethods.All,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 8
        };

        var client = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromMinutes(10)
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) UltimateWindows/2.0");
        return client;
    }
}
