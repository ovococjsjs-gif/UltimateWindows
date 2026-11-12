using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using UltimateWindows.Modules.Repair.Models;

namespace UltimateWindows.Modules.Repair.Diagnostics;

/// <summary>
/// Разбор системного журнала обслуживания компонентов C:\Windows\Logs\CBS\CBS.log:
/// извлекает повреждённые, восстановленные и не поддающиеся восстановлению системные файлы из последнего прогона SFC/CSI.
/// </summary>
public static partial class CbsLogAnalyzer
{
    private const int MaxTailBytes = 4 * 1024 * 1024;

    [GeneratedRegex(@"\[SR\]\s+Cannot repair member file[^\r\n]*?""([^""]+)""", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex CannotRepairRegex();

    [GeneratedRegex(@"\[SR\]\s+Repairing corrupted file[^\r\n]*?""([^""]+)""", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RepairingFileRegex();

    [GeneratedRegex(@"^(?<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}),\s+Info\s+CSI\b", RegexOptions.CultureInvariant)]
    private static partial Regex TimestampPrefixRegex();

    public static CbsLogSummary AnalyzeFile(string cbsLogPath)
    {
        if (string.IsNullOrWhiteSpace(cbsLogPath) || !File.Exists(cbsLogPath))
        {
            return new CbsLogSummary(
                LogExists: false,
                LogAccessible: false,
                LastServicingTimestampUtc: null,
                UnrepairableFiles: [],
                RepairedFiles: [],
                TotalCorruptMentions: 0,
                HumanVerdict: "Журнал CBS.log пока не создан — проверка системных файлов ещё не запускалась.");
        }

        try
        {
            using var fs = new FileStream(cbsLogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (fs.Length == 0)
            {
                return new CbsLogSummary(
                    LogExists: true,
                    LogAccessible: true,
                    LastServicingTimestampUtc: null,
                    UnrepairableFiles: [],
                    RepairedFiles: [],
                    TotalCorruptMentions: 0,
                    HumanVerdict: "Журнал CBS.log пуст — следов повреждения системных файлов нет.");
            }

            if (fs.Length > MaxTailBytes)
            {
                fs.Seek(-MaxTailBytes, SeekOrigin.End);
            }

            using var reader = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            if (fs.Position > 0)
            {
                // Пропускаем возможный обрезанный хвост первой строки
                _ = reader.ReadLine();
            }

            var tailText = reader.ReadToEnd();
            return AnalyzeText(tailText);
        }
        catch (UnauthorizedAccessException)
        {
            return new CbsLogSummary(
                LogExists: true,
                LogAccessible: false,
                LastServicingTimestampUtc: null,
                UnrepairableFiles: [],
                RepairedFiles: [],
                TotalCorruptMentions: 0,
                HumanVerdict: "Для чтения журнала C:\\Windows\\Logs\\CBS\\CBS.log требуются права администратора.");
        }
        catch (Exception ex)
        {
            return new CbsLogSummary(
                LogExists: true,
                LogAccessible: false,
                LastServicingTimestampUtc: null,
                UnrepairableFiles: [],
                RepairedFiles: [],
                TotalCorruptMentions: 0,
                HumanVerdict: $"Не удалось прочитать CBS.log: {ex.Message}");
        }
    }

    public static CbsLogSummary AnalyzeText(string logContent)
    {
        if (string.IsNullOrWhiteSpace(logContent))
        {
            return new CbsLogSummary(
                LogExists: true,
                LogAccessible: true,
                LastServicingTimestampUtc: null,
                UnrepairableFiles: [],
                RepairedFiles: [],
                TotalCorruptMentions: 0,
                HumanVerdict: "Следов повреждения системных файлов в CBS.log не обнаружено.");
        }

        // Если в хвосте журнала несколько запусков sfc /scannow, оцениваем самую свежую сессию проверки,
        // чтобы уже вылеченные в последнем прогоне файлы не считались до сих пор сломанными.
        var lastSessionMarker = logContent.LastIndexOf("[SR] Beginning Verify and Repair transaction", StringComparison.OrdinalIgnoreCase);
        var scope = lastSessionMarker >= 0 ? logContent[lastSessionMarker..] : logContent;

        var unrepairable = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var repaired = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var totalMentions = 0;
        DateTimeOffset? lastTs = null;

        foreach (var rawLine in scope.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r');
            if (line.Length == 0) continue;

            if (line.Contains("[SR]", StringComparison.OrdinalIgnoreCase))
            {
                var tsMatch = TimestampPrefixRegex().Match(line);
                if (tsMatch.Success &&
                    DateTime.TryParseExact(
                        tsMatch.Groups["ts"].Value,
                        "yyyy-MM-dd HH:mm:ss",
                        CultureInfo.InvariantCulture,
                        DateTimeStyles.AssumeLocal,
                        out var localDt))
                {
                    lastTs = new DateTimeOffset(localDt).ToUniversalTime();
                }

                foreach (Match m in CannotRepairRegex().Matches(line))
                {
                    var name = NormalizeComponentFileName(m.Groups[1].Value);
                    if (!string.IsNullOrWhiteSpace(name))
                    {
                        unrepairable.Add(name);
                        totalMentions++;
                    }
                }

                foreach (Match m in RepairingFileRegex().Matches(line))
                {
                    var name = NormalizeComponentFileName(m.Groups[1].Value);
                    if (!string.IsNullOrWhiteSpace(name))
                    {
                        repaired.Add(name);
                        totalMentions++;
                    }
                }
            }
            else if (line.Contains("CSI    000", StringComparison.Ordinal) &&
                     line.Contains("corrupt", StringComparison.OrdinalIgnoreCase) &&
                     line.Contains("store", StringComparison.OrdinalIgnoreCase))
            {
                totalMentions++;
            }
        }

        // Если в рамках той же сессии файл был успешно восстановлен, убираем его из неисправимых
        foreach (var rep in repaired)
        {
            unrepairable.Remove(rep);
        }

        var unrepList = unrepairable.OrderBy(s => s, StringComparer.OrdinalIgnoreCase).ToList();
        var repList = repaired.OrderBy(s => s, StringComparer.OrdinalIgnoreCase).ToList();

        string verdict;
        if (unrepList.Count > 0)
        {
            var sample = string.Join(", ", unrepList.Take(5));
            verdict = $"В CBS.log найдены повреждённые системные файлы, которые SFC не смог починить сам ({unrepList.Count}): {sample}. Требуется восстановление хранилища DISM /RestoreHealth.";
        }
        else if (repList.Count > 0)
        {
            var sample = string.Join(", ", repList.Take(5));
            verdict = $"В последнем прогоне SFC обнаружены и успешно восстановлены системные файлы ({repList.Count}): {sample}.";
        }
        else
        {
            verdict = "В последней сессии CBS.log повреждённых и невосстановленных системных файлов не обнаружено.";
        }

        return new CbsLogSummary(
            LogExists: true,
            LogAccessible: true,
            LastServicingTimestampUtc: lastTs,
            UnrepairableFiles: unrepList,
            RepairedFiles: repList,
            TotalCorruptMentions: totalMentions,
            HumanVerdict: verdict);
    }

    private static string NormalizeComponentFileName(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return string.Empty;
        var trimmed = raw.Trim().Replace('/', '\\');
        var slash = trimmed.LastIndexOf('\\');
        return slash >= 0 && slash + 1 < trimmed.Length ? trimmed[(slash + 1)..] : trimmed;
    }
}
