using System.Diagnostics;
using System.Text;
using System.Text.Json;
using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Security.Models;

namespace UltimateWindows.Modules.Security.Scanners;

/// <summary>
/// Подключаемый координатор внешних сканеров памяти и сигнатур с совместимыми пермиссивными лицензиями:
/// - PE-sieve (BSD-2-Clause) — детект Process Hollowing, Process Doppelgänging, шеллкодов и патчей IAT в памяти;
/// - YARA (BSD-3-Clause) — проверка процессов и папок по правилам .yar/.yara.
/// Инструменты не вшиваются принудительно в базовую сборку: модуль автоматически подхватывает их из папки tools\ или пути пользователя.
/// </summary>
public sealed class ExternalScannerCoordinator
{
    private string? _customPeSievePath;
    private string? _customYaraPath;
    private string? _customYaraRulesPath;

    public string? CustomPeSievePath
    {
        get => _customPeSievePath;
        set => _customPeSievePath = string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }

    public string? CustomYaraPath
    {
        get => _customYaraPath;
        set => _customYaraPath = string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }

    public string? CustomYaraRulesPath
    {
        get => _customYaraRulesPath;
        set => _customYaraRulesPath = string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }

    public IReadOnlyList<ExternalScannerStatus> ProbeAvailableScanners()
    {
        var peSieve = ResolveBinaryPath(
            _customPeSievePath,
            ["pe-sieve64.exe", "pe-sieve.exe", "pe-sieve32.exe"]);

        var yara = ResolveBinaryPath(
            _customYaraPath,
            ["yara64.exe", "yara.exe", "yr.exe"]);

        return
        [
            new ExternalScannerStatus(
                ScannerId: "pe-sieve",
                DisplayName: "PE-sieve (анализ памяти и Hollowing)",
                IsAvailable: peSieve is not null,
                ResolvedBinaryPath: peSieve ?? "",
                LicenseSpdx: "BSD-2-Clause",
                StatusText: peSieve is not null
                    ? $"Подключён: {peSieve}"
                    : "Опционально: поместите pe-sieve64.exe в папку tools\\ рядом с программой или укажите путь."),
            new ExternalScannerStatus(
                ScannerId: "yara",
                DisplayName: "YARA (сигнатурные правила .yar)",
                IsAvailable: yara is not null,
                ResolvedBinaryPath: yara ?? "",
                LicenseSpdx: "BSD-3-Clause",
                StatusText: yara is not null
                    ? $"Подключён: {yara}"
                    : "Опционально: поместите yara64.exe и файлы .yar в папку tools\\ или укажите путь.")
        ];
    }

    /// <summary>
    /// Запускает PE-sieve по списку подозрительных PID и возвращает подтвержденные импланты памяти.
    /// </summary>
    public async Task<IReadOnlyList<SecurityThreatFinding>> ScanProcessesWithPeSieveAsync(
        IEnumerable<int> targetPids,
        string windowsDirectory,
        CancellationToken ct = default)
    {
        var binary = ResolveBinaryPath(_customPeSievePath, ["pe-sieve64.exe", "pe-sieve.exe"]);
        if (binary is null)
        {
            return [];
        }

        var findings = new List<SecurityThreatFinding>();
        foreach (var pid in targetPids.Where(p => p > 4).Distinct().Take(16))
        {
            ct.ThrowIfCancellationRequested();
            var psi = new ProcessStartInfo
            {
                FileName = binary,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8
            };
            psi.ArgumentList.Add("/pid");
            psi.ArgumentList.Add(pid.ToString(System.Globalization.CultureInfo.InvariantCulture));
            psi.ArgumentList.Add("/threads");
            psi.ArgumentList.Add("/dmode");
            psi.ArgumentList.Add("0");
            psi.ArgumentList.Add("/quiet");
            psi.ArgumentList.Add("/json");

            try
            {
                using var proc = Process.Start(psi);
                if (proc is null) continue;

                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeoutCts.CancelAfter(TimeSpan.FromSeconds(12));

                var stdout = await proc.StandardOutput.ReadToEndAsync(timeoutCts.Token).ConfigureAwait(false);
                await proc.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);

                var parsed = ParsePeSieveJsonReport(stdout, windowsDirectory);
                if (parsed is not null)
                {
                    findings.Add(parsed);
                }
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                // Один процесс превысил таймаут — переходим к следующему
            }
            catch
            {
                // Безопасный пропуск недоступного защищенного процесса
            }
        }

        return findings;
    }

    /// <summary>
    /// Запускает YARA по указанной папке или процессу с пользовательским набором правил .yar.
    /// </summary>
    public async Task<IReadOnlyList<SecurityThreatFinding>> RunYaraScanAsync(
        string targetPathOrPid,
        string windowsDirectory,
        CancellationToken ct = default)
    {
        var binary = ResolveBinaryPath(_customYaraPath, ["yara64.exe", "yara.exe"]);
        var rulesPath = ResolveYaraRulesFile();
        if (binary is null || rulesPath is null || string.IsNullOrWhiteSpace(targetPathOrPid))
        {
            return [];
        }

        var psi = new ProcessStartInfo
        {
            FileName = binary,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8
        };

        if (Directory.Exists(targetPathOrPid))
        {
            psi.ArgumentList.Add("-r");
        }

        psi.ArgumentList.Add("-w");
        psi.ArgumentList.Add(rulesPath);
        psi.ArgumentList.Add(targetPathOrPid);

        try
        {
            using var proc = Process.Start(psi);
            if (proc is null) return [];

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(30));

            var stdout = await proc.StandardOutput.ReadToEndAsync(timeoutCts.Token).ConfigureAwait(false);
            await proc.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);

            return ParseYaraStdout(stdout, windowsDirectory);
        }
        catch
        {
            return [];
        }
    }

    /// <summary>
    /// Чистый детерминированный парсер JSON-отчета PE-sieve (покрывается модульными тестами без запуска .exe).
    /// </summary>
    public static SecurityThreatFinding? ParsePeSieveJsonReport(string? rawOutput, string windowsDirectory)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
        {
            return null;
        }

        var braceStart = rawOutput.IndexOf('{');
        var braceEnd = rawOutput.LastIndexOf('}');
        if (braceStart < 0 || braceEnd <= braceStart)
        {
            return null;
        }

        try
        {
            using var doc = JsonDocument.Parse(rawOutput[braceStart..(braceEnd + 1)]);
            var root = doc.RootElement;

            var pid = root.TryGetProperty("pid", out var pidEl) && pidEl.TryGetInt32(out var p) ? p : 0;
            var imagePath = root.TryGetProperty("main_image_path", out var pathEl) ? pathEl.GetString() ?? "" : "";

            if (!root.TryGetProperty("scanned", out var scannedEl) ||
                !scannedEl.TryGetProperty("modified", out var modEl))
            {
                return null;
            }

            int GetModInt(string prop) =>
                modEl.TryGetProperty(prop, out var el) && el.TryGetInt32(out var v) ? v : 0;

            int implantedPe = GetModInt("implanted_pe") + GetModInt("implanted");
            int implantedShc = GetModInt("implanted_shc");
            int hollowed = GetModInt("replaced") + GetModInt("hollowed");
            int hdrModified = GetModInt("hdr_modified");
            int iatHooked = GetModInt("iat_hooked");
            int patched = GetModInt("patched");

            // Игнорируем единичные inline-патчи без имплантов и без подмены образа (например, оверлеи Discord/Steam)
            if (implantedPe == 0 && implantedShc == 0 && hollowed == 0 && hdrModified == 0)
            {
                return null;
            }

            bool isUnderWin = !string.IsNullOrWhiteSpace(imagePath) &&
                              imagePath.StartsWith(windowsDirectory.TrimEnd('\\') + @"\", StringComparison.OrdinalIgnoreCase);

            var procName = string.IsNullOrWhiteSpace(imagePath) ? $"PID {pid}" : Path.GetFileName(imagePath);

            return new SecurityThreatFinding(
                FindingId: $"pesieve-{pid}",
                Vector: ThreatDetectionVector.ExternalPeSieveImplant,
                Severity: RiskLevel.Critical,
                ConfidenceScorePercent: hollowed > 0 || implantedPe > 0 ? 97 : 90,
                SuspectProcessId: pid > 4 ? pid : null,
                SuspectFilePath: string.IsNullOrWhiteSpace(imagePath) ? null : imagePath,
                PersistenceRecord: null,
                SimpleTitle: $"PE-sieve обнаружил внедрённый код в памяти процесса «{procName}»",
                SimpleExplanation: isUnderWin
                    ? $"В легитимный системный процесс «{procName}» (PID {pid}) внедрён чужеродный модуль памяти (Process Hollowing / PE Implant). Сам системный файл удалять не нужно — достаточно завершить заражённый экземпляр и убрать загрузчик."
                    : $"В памяти процесса «{procName}» (PID {pid}) найдены подменённые или распакованные исполняемые секции.",
                ExpertTechnicalEvidence: $"PE-sieve JSON PID={pid}: hollowed/replaced={hollowed}, implanted_pe={implantedPe}, implanted_shc={implantedShc}, hdr_modified={hdrModified}, iat_hooked={iatHooked}, patched={patched} | Image='{imagePath}'",
                CanQuarantineFileSafely: !isUnderWin && !string.IsNullOrWhiteSpace(imagePath),
                CategoryLabel: "Память (PE-sieve)",
                RecommendedActionLabel: isUnderWin ? "Завершить процесс" : "В карантин");
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Чистый детерминированный парсер текстового вывода YARA: &lt;RuleName&gt; &lt;TargetFileOrPid&gt;.
    /// </summary>
    public static IReadOnlyList<SecurityThreatFinding> ParseYaraStdout(string? rawOutput, string windowsDirectory)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
        {
            return [];
        }

        var findings = new List<SecurityThreatFinding>();
        var lines = rawOutput.Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        foreach (var line in lines)
        {
            if (line.StartsWith("warning:", StringComparison.OrdinalIgnoreCase) ||
                line.StartsWith("error:", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var spaceIdx = line.IndexOf(' ');
            if (spaceIdx <= 0 || spaceIdx >= line.Length - 1)
            {
                continue;
            }

            var ruleName = line[..spaceIdx].Trim();
            var target = line[(spaceIdx + 1)..].Trim().Trim('"');

            int? pid = int.TryParse(target, out var parsedPid) && parsedPid > 4 ? parsedPid : null;
            string? filePath = pid is null ? target : null;
            bool isUnderWin = filePath is not null &&
                              filePath.StartsWith(windowsDirectory.TrimEnd('\\') + @"\", StringComparison.OrdinalIgnoreCase);

            findings.Add(new SecurityThreatFinding(
                FindingId: $"yara-{ruleName}-{target.GetHashCode(StringComparison.OrdinalIgnoreCase):X8}",
                Vector: ThreatDetectionVector.ExternalYaraMatch,
                Severity: RiskLevel.Critical,
                ConfidenceScorePercent: 95,
                SuspectProcessId: pid,
                SuspectFilePath: filePath,
                PersistenceRecord: null,
                SimpleTitle: $"Сигнатура YARA «{ruleName}» сработала на «{(pid is not null ? $"PID {pid}" : Path.GetFileName(target))}»",
                SimpleExplanation: $"Внешний сканер YARA подтвердил совпадение с правилом «{ruleName}» на объекте «{target}».",
                ExpertTechnicalEvidence: $"YARA match: rule='{ruleName}', target='{target}'",
                CanQuarantineFileSafely: filePath is not null && !isUnderWin,
                CategoryLabel: "Сигнатура YARA",
                RecommendedActionLabel: filePath is not null && !isUnderWin ? "В карантин" : "Завершить"));
        }

        return findings;
    }

    private string? ResolveYaraRulesFile()
    {
        if (!string.IsNullOrWhiteSpace(_customYaraRulesPath) && File.Exists(_customYaraRulesPath))
        {
            return _customYaraRulesPath;
        }

        foreach (var dir in EnumerateToolDirectories())
        {
            if (!Directory.Exists(dir)) continue;
            var yar = Directory.EnumerateFiles(dir, "*.yar*", SearchOption.AllDirectories).FirstOrDefault();
            if (yar is not null)
            {
                return yar;
            }
        }

        return null;
    }

    private static string? ResolveBinaryPath(string? customPath, IReadOnlyList<string> candidateFileNames)
    {
        if (!string.IsNullOrWhiteSpace(customPath) && File.Exists(customPath))
        {
            return Path.GetFullPath(customPath);
        }

        foreach (var dir in EnumerateToolDirectories())
        {
            foreach (var name in candidateFileNames)
            {
                var full = Path.Combine(dir, name);
                if (File.Exists(full))
                {
                    return full;
                }
            }
        }

        var pathEnv = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var part in pathEnv.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            foreach (var name in candidateFileNames)
            {
                try
                {
                    var full = Path.Combine(part, name);
                    if (File.Exists(full))
                    {
                        return full;
                    }
                }
                catch
                {
                    // Игнорируем некорректный сегмент PATH
                }
            }
        }

        return null;
    }

    private static IEnumerable<string> EnumerateToolDirectories()
    {
        var baseDir = AppContext.BaseDirectory;
        if (!string.IsNullOrWhiteSpace(baseDir))
        {
            yield return Path.Combine(baseDir, "tools");
            yield return baseDir;
        }

        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (!string.IsNullOrWhiteSpace(localAppData))
        {
            yield return Path.Combine(localAppData, "UltimateWindows", "Tools");
        }
    }
}
