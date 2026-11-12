using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using UltimateWindows.Modules.Optimizer.Network;
using UltimateWindows.Modules.Security.Analyzers;
using UltimateWindows.Modules.Security.Catalog;
using UltimateWindows.Modules.Security.Models;

namespace UltimateWindows.NativeInterop.SecurityHunter;

public sealed partial class WindowsSecurityPlatformBridge
{
    private static readonly string[] CriticalAdminTools =
    [
        "taskmgr.exe", "regedit.exe", "cmd.exe", "mmc.exe", "powershell.exe",
        "pwsh.exe", "msconfig.exe", "MpCmdRun.exe", "MsMpEng.exe", "mrt.exe"
    ];

    private static readonly HashSet<string> BuiltInSystemAccounts = new(StringComparer.OrdinalIgnoreCase)
    {
        "Administrator", "Администратор",
        "Guest", "Гость",
        "DefaultAccount",
        "WDAGUtilityAccount",
        "HomeGroupUser$"
    };

    // ==================== 1. АУДИТ И ОЧИСТКА ИСКЛЮЧЕНИЙ ЗАЩИТНИКА WINDOWS ====================

    public override Task<IReadOnlyList<DefenderExclusionFinding>> ScanDefenderExclusionsAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult<IReadOnlyList<DefenderExclusionFinding>>([]);
        }

        return Task.Run<IReadOnlyList<DefenderExclusionFinding>>(() =>
        {
            var list = new List<DefenderExclusionFinding>();
            var winDir = GetWindowsDirectory();

            var roots = new (string BaseSubKey, bool IsPolicy)[]
            {
                (@"SOFTWARE\Microsoft\Windows Defender\Exclusions", false),
                (@"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions", true)
            };

            var subKinds = new (string SubName, DefenderExclusionKind Kind)[]
            {
                ("Paths", DefenderExclusionKind.Path),
                ("Processes", DefenderExclusionKind.Process),
                ("Extensions", DefenderExclusionKind.Extension),
                ("IpAddresses", DefenderExclusionKind.IpAddress)
            };

            foreach (var (baseSubKey, isPolicy) in roots)
            {
                foreach (var (subName, kind) in subKinds)
                {
                    ct.ThrowIfCancellationRequested();
                    var fullSubKey = $@"{baseSubKey}\{subName}";
                    try
                    {
                        using var key = Registry.LocalMachine.OpenSubKey(fullSubKey, writable: false);
                        if (key is null) continue;

                        foreach (var valName in key.GetValueNames())
                        {
                            if (string.IsNullOrWhiteSpace(valName)) continue;
                            list.Add(PersistenceZoneCatalog.ClassifyDefenderExclusion(
                                kind,
                                valName,
                                isPolicy,
                                $@"HKLM\{fullSubKey}",
                                winDir));
                        }
                    }
                    catch
                    {
                        // На части систем чтение ветки Exclusions без прав администратора закрыто — пропускаем без падения
                    }
                }
            }

            return list
                .OrderByDescending(e => e.IsDangerousMinerExclusion)
                .ThenByDescending(e => e.Severity)
                .ThenBy(e => e.Value, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }, ct);
    }

    public override Task<bool> RemoveDefenderExclusionAsync(DefenderExclusionFinding exclusion, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult(false);
        }

        return Task.Run(() =>
        {
            bool removedAny = false;
            var escaped = exclusion.Value.Replace("'", "''", StringComparison.Ordinal);

            // 1. Для групповых политик удаляем значение напрямую из HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions
            if (exclusion.IsPolicyEnforced)
            {
                try
                {
                    var subKey = exclusion.RegistryPath.StartsWith(@"HKLM\", StringComparison.OrdinalIgnoreCase)
                        ? exclusion.RegistryPath[5..]
                        : exclusion.RegistryPath;
                    using var key = Registry.LocalMachine.OpenSubKey(subKey, writable: true);
                    if (key is not null)
                    {
                        key.DeleteValue(exclusion.Value, throwOnMissingValue: false);
                        removedAny = true;
                    }
                }
                catch { }
            }

            // 2. Штатное удаление через командлет Защитника Remove-MpPreference
            string paramName = exclusion.Kind switch
            {
                DefenderExclusionKind.Path => "ExclusionPath",
                DefenderExclusionKind.Process => "ExclusionProcess",
                DefenderExclusionKind.Extension => "ExclusionExtension",
                DefenderExclusionKind.IpAddress => "ExclusionIpAddress",
                _ => "ExclusionPath"
            };

            if (RunShortPowerShell($"Remove-MpPreference -{paramName} '{escaped}' -ErrorAction Stop", timeoutMs: 6000))
            {
                removedAny = true;
            }

            return removedAny;
        }, ct);
    }

    public override async Task<(bool Succeeded, string OutputMessage)> StartDefenderScanAsync(
        DefenderScanMode mode,
        string? customTargetPath = null,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return (false, "Запуск проверки Microsoft Defender доступен только в Windows 10 и Windows 11.");
        }

        var mpCmdRun = ResolveMpCmdRunExecutable();
        if (mpCmdRun is null)
        {
            return (false, "Не найден штатный клиент MpCmdRun.exe (возможно, в системе установлен сторонний антивирус).");
        }

        if (mode == DefenderScanMode.CustomPathScan && (string.IsNullOrWhiteSpace(customTargetPath) || (!File.Exists(customTargetPath) && !Directory.Exists(customTargetPath))))
        {
            return (false, "Указанный путь для выборочной проверки Защитником Windows не существует.");
        }

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = mpCmdRun,
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            psi.ArgumentList.Add("-Scan");
            psi.ArgumentList.Add("-ScanType");
            psi.ArgumentList.Add(((int)mode).ToString(CultureInfo.InvariantCulture));

            if (mode == DefenderScanMode.CustomPathScan && !string.IsNullOrWhiteSpace(customTargetPath))
            {
                psi.ArgumentList.Add("-File");
                psi.ArgumentList.Add(Path.GetFullPath(customTargetPath));
            }

            var proc = Process.Start(psi);
            if (proc is null)
            {
                return (false, "Не удалось запустить процесс проверки MpCmdRun.exe.");
            }

            if (mode == DefenderScanMode.CustomPathScan)
            {
                // Для точечной проверки конкретной папки ждём до 45 секунд, чтобы сразу показать вердикт
                using var waitCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                waitCts.CancelAfter(TimeSpan.FromSeconds(45));
                try
                {
                    var stdout = await proc.StandardOutput.ReadToEndAsync(waitCts.Token).ConfigureAwait(false);
                    await proc.WaitForExitAsync(waitCts.Token).ConfigureAwait(false);
                    proc.Dispose();
                    bool clean = proc.ExitCode == 0;
                    string summary = string.IsNullOrWhiteSpace(stdout)
                        ? (clean ? "Угроз в выбранном пути не обнаружено." : $"Защитник Windows завершил проверку с кодом {proc.ExitCode}.")
                        : stdout.Trim().Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries).LastOrDefault() ?? "Проверка завершена.";
                    return (clean, $"Выборочная проверка Defender («{customTargetPath}»): {summary}");
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    return (true, $"Выборочная проверка «{customTargetPath}» продолжается в фоне (PID {proc.Id}).");
                }
            }

            // Быстрая / полная проверка всей системы идёт в фоновом режиме штатной службы Защитника
            int bgPid = proc.Id;
            proc.Dispose();
            return (true, mode == DefenderScanMode.QuickScan
                ? $"Запущена быстрая проверка системы Защитником Windows в фоне (MpCmdRun PID {bgPid})."
                : $"Запущена полная проверка системы Защитником Windows в фоне (MpCmdRun PID {bgPid}).");
        }
        catch (Exception ex)
        {
            return (false, $"Ошибка запуска Защитника Windows: {ex.Message}");
        }
    }

    private static string? ResolveMpCmdRunExecutable()
    {
        try
        {
            var platformRoot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Microsoft", "Windows Defender", "Platform");

            if (Directory.Exists(platformRoot))
            {
                var latest = Directory.GetDirectories(platformRoot)
                    .OrderByDescending(d => d, StringComparer.OrdinalIgnoreCase)
                    .Select(d => Path.Combine(d, "MpCmdRun.exe"))
                    .FirstOrDefault(File.Exists);

                if (latest is not null)
                {
                    return latest;
                }
            }

            var fallback = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "Windows Defender", "MpCmdRun.exe");

            return File.Exists(fallback) ? fallback : null;
        }
        catch
        {
            return null;
        }
    }

    // ==================== 2. АУДИТ САБОТАЖНЫХ ПРАВИЛ БРАНДМАУЭРА WINDOWS ====================

    public override Task<IReadOnlyList<FirewallRuleAnomaly>> ScanFirewallRuleAnomaliesAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult<IReadOnlyList<FirewallRuleAnomaly>>([]);
        }

        return Task.Run<IReadOnlyList<FirewallRuleAnomaly>>(() =>
        {
            const string fwRulesPath = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
            var list = new List<FirewallRuleAnomaly>();
            var protectedProcs = ThreatIndicatorCatalog.Shared.DefenderCriticalProcessNames;

            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(fwRulesPath, writable: false);
                if (key is null) return list;

                foreach (var ruleId in key.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    var raw = key.GetValue(ruleId)?.ToString();
                    if (string.IsNullOrWhiteSpace(raw)) continue;

                    var parsed = ParseFirewallRuleFields(raw);
                    if (!parsed.TryGetValue("Active", out var active) || !active.Equals("TRUE", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    var action = parsed.GetValueOrDefault("Action", "");
                    var dir = parsed.GetValueOrDefault("Dir", "");
                    var app = Environment.ExpandEnvironmentVariables(parsed.GetValueOrDefault("App", ""));
                    var name = parsed.GetValueOrDefault("Name", ruleId);
                    var rPort = parsed.GetValueOrDefault("RPort", "");
                    var lPort = parsed.GetValueOrDefault("LPort", "");
                    var rAddr = parsed.GetValueOrDefault("RA4", parsed.GetValueOrDefault("RA6", ""));

                    // Вектор A: Исходящее правило Block, отрезающее антивирус / Защитника / Центр обновления от сети
                    if (action.Equals("Block", StringComparison.OrdinalIgnoreCase) &&
                        dir.Equals("Out", StringComparison.OrdinalIgnoreCase) &&
                        !string.IsNullOrWhiteSpace(app))
                    {
                        var appFile = Path.GetFileName(app);
                        if (protectedProcs.Contains(appFile) ||
                            app.Contains(@"\Windows Defender\", StringComparison.OrdinalIgnoreCase))
                        {
                            list.Add(new FirewallRuleAnomaly(
                                RuleId: ruleId,
                                DisplayName: name,
                                Direction: "Исходящее (Out)",
                                Action: "Блокировать (Block)",
                                ApplicationPath: app,
                                RemoteAddresses: rAddr,
                                RemotePorts: rPort,
                                RawRegistryValue: raw,
                                SimpleExplanation: $"Правило блокирует выход в сеть защитной службе «{appFile}», не давая ей скачивать обновления сигнатур и проверять облачную репутацию."));
                        }
                    }

                    // Вектор B: Разрешающее правило для исполняемого файла во временной/пользовательской папке майнера
                    if (action.Equals("Allow", StringComparison.OrdinalIgnoreCase) &&
                        !string.IsNullOrWhiteSpace(app) &&
                        PersistenceZoneCatalog.IsUserWritableOrStagingPath(app) &&
                        File.Exists(app) &&
                        !VerifySignedCached(app))
                    {
                        list.Add(new FirewallRuleAnomaly(
                            RuleId: ruleId,
                            DisplayName: name,
                            Direction: dir.Equals("In", StringComparison.OrdinalIgnoreCase) ? "Входящее (In)" : "Исходящее (Out)",
                            Action: "Разрешить (Allow)",
                            ApplicationPath: app,
                            RemoteAddresses: rAddr,
                            RemotePorts: string.IsNullOrWhiteSpace(rPort) ? lPort : rPort,
                            RawRegistryValue: raw,
                            SimpleExplanation: $"Правило открывает сетевой доступ неподписанной программе во временной/пользовательской папке «{app}»."));
                    }
                }
            }
            catch { }

            return list;
        }, ct);
    }

    public override Task<bool> RemoveFirewallRuleAsync(FirewallRuleAnomaly rule, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult(false);
        }

        return Task.Run(() =>
        {
            const string fwRulesPath = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(fwRulesPath, writable: true);
                if (key is null) return false;
                key.DeleteValue(rule.RuleId, throwOnMissingValue: false);
                return true;
            }
            catch
            {
                return false;
            }
        }, ct);
    }

    private static Dictionary<string, string> ParseFirewallRuleFields(string raw)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in raw.Split('|', StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = part.IndexOf('=');
            if (eq > 0 && eq < part.Length - 1)
            {
                dict[part[..eq]] = part[(eq + 1)..];
            }
        }

        return dict;
    }

    // ==================== 3. АУДИТ СКРЫТЫХ И ПОДОЗРИТЕЛЬНЫХ УЧЁТНЫХ ЗАПИСЕЙ ====================

    public override Task<IReadOnlyList<SuspiciousUserAccountFinding>> ScanSuspiciousUserAccountsAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult<IReadOnlyList<SuspiciousUserAccountFinding>>([]);
        }

        return Task.Run<IReadOnlyList<SuspiciousUserAccountFinding>>(() =>
        {
            var findings = new List<SuspiciousUserAccountFinding>();
            var hiddenInWinlogon = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // 1. Читаем список намеренно скрытых с экрана входа пользователей SpecialAccounts\UserList
            const string specialAccPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList";
            try
            {
                using var sa = Registry.LocalMachine.OpenSubKey(specialAccPath, writable: false);
                if (sa is not null)
                {
                    foreach (var name in sa.GetValueNames())
                    {
                        if (sa.GetValue(name) is int flag && flag == 0)
                        {
                            hiddenInWinlogon.Add(name);
                        }
                    }
                }
            }
            catch { }

            // 2. Перечисляем локальные учетные записи через нативный NetUserEnum (netapi32.dll, без парсинга локализованного net user)
            IntPtr bufPtr = IntPtr.Zero;
            try
            {
                uint status = NetUserEnum(
                    null,
                    level: 1,
                    filter: FILTER_NORMAL_ACCOUNT,
                    out bufPtr,
                    prefmaxlen: uint.MaxValue,
                    out uint entriesRead,
                    out _,
                    IntPtr.Zero);

                if (status != 0 || bufPtr == IntPtr.Zero)
                {
                    return findings;
                }

                int structSize = Marshal.SizeOf<USER_INFO_1>();
                var ptr = bufPtr;

                for (uint i = 0; i < entriesRead && i < 256; i++)
                {
                    var u = Marshal.PtrToStructure<USER_INFO_1>(ptr);
                    ptr += structSize;

                    var name = Marshal.PtrToStringUni(u.usri1_name) ?? "";
                    if (string.IsNullOrWhiteSpace(name) || BuiltInSystemAccounts.Contains(name))
                    {
                        continue;
                    }

                    bool isEnabled = (u.usri1_flags & UF_ACCOUNTDISABLE) == 0;
                    bool isAdmin = u.usri1_priv == USER_PRIV_ADMIN;
                    bool dollarSuffix = name.EndsWith('$');
                    bool hiddenSpecial = hiddenInWinlogon.Contains(name);
                    var comment = Marshal.PtrToStringUni(u.usri1_comment) ?? "";

                    if (isEnabled && (dollarSuffix || hiddenSpecial))
                    {
                        findings.Add(new SuspiciousUserAccountFinding(
                            UserName: name,
                            IsAdministrator: isAdmin,
                            IsEnabled: isEnabled,
                            EndsWithDollarSign: dollarSuffix,
                            IsHiddenInWinlogonSpecialAccounts: hiddenSpecial,
                            Comment: comment,
                            Reason: hiddenSpecial
                                ? $"Аккаунт «{name}» скрыт с экрана приветствия Windows через ветку SpecialAccounts\\UserList{(isAdmin ? " и обладает правами Администратора" : "")}."
                                : $"Аккаунт «{name}» оканчивается на символ '$' для маскировки в оснастках управления{(isAdmin ? " и имеет права Администратора" : "")}."));
                    }
                }
            }
            catch { }
            finally
            {
                if (bufPtr != IntPtr.Zero)
                {
                    _ = NetApiBufferFree(bufPtr);
                }
            }

            return findings;
        }, ct);
    }

    // ==================== 4. ПРОВЕРКА STAGING-ПАПОК МАЙНЕРОВ И РАЗДУТЫХ ДРОППЕРОВ (>250 МБ) ====================

    public override Task<IReadOnlyList<DirectoryThreatArtifact>> ScanStagingDirectoriesAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult<IReadOnlyList<DirectoryThreatArtifact>>([]);
        }

        return Task.Run<IReadOnlyList<DirectoryThreatArtifact>>(() =>
        {
            var results = new List<DirectoryThreatArtifact>();
            var catalog = ThreatIndicatorCatalog.Shared;

            var roots = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Path.GetTempPath(),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                @"C:\Users\Public"
            };

            int inspectedFiles = 0;
            foreach (var root in roots.Where(r => !string.IsNullOrWhiteSpace(r) && Directory.Exists(r)).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                ScanStagingFolderBounded(root, depth: 0, maxDepth: 2, ref inspectedFiles, maxFiles: 1200, catalog, results, ct);
                if (inspectedFiles >= 1200) break;
            }

            return results;
        }, ct);
    }

    private void ScanStagingFolderBounded(
        string folder,
        int depth,
        int maxDepth,
        ref int inspectedFiles,
        int maxFiles,
        ThreatIndicatorCatalog catalog,
        List<DirectoryThreatArtifact> sink,
        CancellationToken ct)
    {
        if (depth > maxDepth || inspectedFiles >= maxFiles) return;
        ct.ThrowIfCancellationRequested();

        // Пропускаем доверенные системные кэши и пакеты
        if (!PersistenceZoneCatalog.IsUserWritableOrStagingPath(folder + @"\probe.exe"))
        {
            return;
        }

        try
        {
            foreach (var file in Directory.EnumerateFiles(folder))
            {
                if (++inspectedFiles > maxFiles) return;

                var fileName = Path.GetFileName(file);
                var ext = Path.GetExtension(file);

                // A. Конфигурационные файлы майнеров (config.json / pools.txt / xmrig.json)
                if ((fileName.Equals("config.json", StringComparison.OrdinalIgnoreCase) ||
                     fileName.Equals("pools.txt", StringComparison.OrdinalIgnoreCase) ||
                     fileName.Contains("xmrig", StringComparison.OrdinalIgnoreCase)) &&
                    ext is ".json" or ".txt" or ".conf")
                {
                    var fi = new FileInfo(file);
                    if (fi.Length is > 32 and <= 512 * 1024)
                    {
                        var text = File.ReadAllText(file);
                        var matched = catalog.MinerConfigMarkers.FirstOrDefault(m => text.Contains(m, StringComparison.OrdinalIgnoreCase));
                        if (matched is not null)
                        {
                            sink.Add(new DirectoryThreatArtifact(
                                FilePath: file,
                                ArtifactKind: "Конфигурация пула майнинга",
                                FileSizeBytes: fi.Length,
                                IsBloatedPaddingSuspect: false,
                                MatchedIndicator: matched,
                                SimpleExplanation: $"Файл настроек содержит прямые параметры криптомайнера ({matched})."));
                        }
                    }
                }
                // B. Драйвер WinRing0 / MSR внутри пользовательских папок (SilentCryptoMiner / XMRig)
                else if (catalog.AbusedDriverFileNames.Contains(fileName))
                {
                    var fi = new FileInfo(file);
                    sink.Add(new DirectoryThreatArtifact(
                        FilePath: file,
                        ArtifactKind: "Драйвер прямого доступа к MSR/памяти",
                        FileSizeBytes: fi.Length,
                        IsBloatedPaddingSuspect: false,
                        MatchedIndicator: fileName,
                        SimpleExplanation: $"Низкоуровневый драйвер «{fileName}» размещён во временной/пользовательской папке — типичный компонент скрытых RandomX-майнеров."));
                }
                // C. Искусственно раздутые неподписанные .exe (>= 250 МБ с нулевым/повторяющимся хвостом для обхода антивирусов)
                else if (ext.Equals(".exe", StringComparison.OrdinalIgnoreCase))
                {
                    var fi = new FileInfo(file);
                    if (fi.Length >= 250L * 1024 * 1024 && fi.Length <= 1024L * 1024 * 1024)
                    {
                        if (HasArtificialTailPadding(file, fi.Length) && !VerifySignedCached(file))
                        {
                            sink.Add(new DirectoryThreatArtifact(
                                FilePath: file,
                                ArtifactKind: "Раздутый неподписанный дроппер (File Bloating)",
                                FileSizeBytes: fi.Length,
                                IsBloatedPaddingSuspect: true,
                                MatchedIndicator: $"Zero/Repeat tail padding ({fi.Length / (1024 * 1024)} МБ)",
                                SimpleExplanation: $"Неподписанный исполняемый файл искусственно раздут пустыми байтами до {fi.Length / (1024 * 1024)} МБ, чтобы обойти облачную проверку антивирусов."));
                        }
                    }
                }
            }

            if (depth < maxDepth)
            {
                foreach (var subDir in Directory.EnumerateDirectories(folder))
                {
                    var dirName = Path.GetFileName(subDir);
                    // Не углубляемся в тяжёлые кэши браузеров, Steam, NuGet и node_modules
                    if (dirName.Equals("Packages", StringComparison.OrdinalIgnoreCase) ||
                        dirName.Equals("Microsoft", StringComparison.OrdinalIgnoreCase) ||
                        dirName.Equals("Google", StringComparison.OrdinalIgnoreCase) ||
                        dirName.Equals("Mozilla", StringComparison.OrdinalIgnoreCase) ||
                        dirName.Equals("Steam", StringComparison.OrdinalIgnoreCase) ||
                        dirName.Equals("node_modules", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    ScanStagingFolderBounded(subDir, depth + 1, maxDepth, ref inspectedFiles, maxFiles, catalog, sink, ct);
                }
            }
        }
        catch { }
    }

    /// <summary>
    /// Проверяет последние 64 КБ крупного .exe-файла: если >= 98% хвоста заполнено одним и тем же байтом (обычно 0x00),
    /// файл искусственно раздут техникой File Bloating.
    /// </summary>
    public static bool HasArtificialTailPadding(string filePath, long fileLength)
    {
        if (fileLength < 250L * 1024 * 1024)
        {
            return false;
        }

        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            byte[] mz = new byte[2];
            if (fs.Read(mz, 0, 2) != 2 || mz[0] != 0x4D || mz[1] != 0x5A)
            {
                return false;
            }

            const int tailSampleBytes = 65536;
            fs.Seek(-tailSampleBytes, SeekOrigin.End);
            byte[] tail = new byte[tailSampleBytes];
            int read = fs.Read(tail, 0, tailSampleBytes);
            if (read < tailSampleBytes) return false;

            byte anchor = tail[read - 1];
            int sameCount = 0;
            for (int i = 0; i < read; i++)
            {
                if (tail[i] == anchor) sameCount++;
            }

            return sameCount >= (int)(read * 0.98);
        }
        catch
        {
            return false;
        }
    }

    // ==================== 5. БЛОКИРОВКИ И САБОТАЖ СИСТЕМЫ ПОСЛЕ МАЙНЕРА ====================

    public override Task<IReadOnlyList<OsSabotageFinding>> ScanOsSabotageLocksAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult<IReadOnlyList<OsSabotageFinding>>([]);
        }

        return Task.Run<IReadOnlyList<OsSabotageFinding>>(() =>
        {
            var findings = new List<OsSabotageFinding>();

            CheckPolicyIntLock(
                Registry.CurrentUser, "HKCU",
                @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr",
                OsSabotageKind.TaskManagerDisabledByPolicy,
                "Диспетчер задач заблокирован политикой",
                "Установлен запрет на открытие Диспетчера задач, чтобы скрыть нагрузку CPU и GPU.",
                findings);

            CheckPolicyIntLock(
                Registry.LocalMachine, "HKLM",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr",
                OsSabotageKind.TaskManagerDisabledByPolicy,
                "Диспетчер задач заблокирован на уровне системы",
                "Системная политика запрещает запуск Диспетчера задач.",
                findings);

            CheckPolicyIntLock(
                Registry.CurrentUser, "HKCU",
                @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableRegistryTools",
                OsSabotageKind.RegistryEditorDisabledByPolicy,
                "Редактор реестра (regedit) заблокирован",
                "Установлен запрет на просмотр и редактирование реестра Windows.",
                findings);

            CheckPolicyIntLock(
                Registry.LocalMachine, "HKLM",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "DisableRegistryTools",
                OsSabotageKind.RegistryEditorDisabledByPolicy,
                "Редактор реестра заблокирован системной политикой",
                "Системная политика запрещает открытие regedit.exe.",
                findings);

            CheckPolicyIntLock(
                Registry.CurrentUser, "HKCU",
                @"Software\Policies\Microsoft\Windows\System", "DisableCMD",
                OsSabotageKind.CommandPromptDisabledByPolicy,
                "Командная строка (cmd.exe) заблокирована",
                "Политика запрещает выполнение диагностических команд в консоли.",
                findings);

            CheckPolicyIntLock(
                Registry.LocalMachine, "HKLM",
                @"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware",
                OsSabotageKind.DefenderDisabledByPolicy,
                "Защитник Windows принудительно отключён политикой",
                "Ключ DisableAntiSpyware блокирует работу встроенного антивируса Microsoft Defender.",
                findings);

            CheckPolicyIntLock(
                Registry.LocalMachine, "HKLM",
                @"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring",
                OsSabotageKind.DefenderRealtimeDisabledByPolicy,
                "Отключена защита в реальном времени Защитника Windows",
                "Политика DisableRealtimeMonitoring отключает перехват вредоносных файлов на лету.",
                findings);

            CheckPolicyIntLock(
                Registry.LocalMachine, "HKLM",
                @"SOFTWARE\Policies\Microsoft\MRT", "DontOfferThroughWUAU",
                OsSabotageKind.MrtBlockedByPolicy,
                "Заблокировано средство удаления вредоносных программ (MSRT)",
                "Троян установил ключ DontOfferThroughWUAU = 1, чтобы Windows Update не скачивал сканер MSRT (типично для SilentCryptoMiner).",
                findings);

            // Проверка блокировки системных утилит через IFEO Debugger
            const string ifeoBase = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
            try
            {
                using var ifeo = Registry.LocalMachine.OpenSubKey(ifeoBase, writable: false);
                if (ifeo is not null)
                {
                    foreach (var tool in CriticalAdminTools)
                    {
                        using var sub = ifeo.OpenSubKey(tool, writable: false);
                        var dbg = sub?.GetValue("Debugger")?.ToString();
                        if (!string.IsNullOrWhiteSpace(dbg))
                        {
                            findings.Add(new OsSabotageFinding(
                                Kind: OsSabotageKind.SystemToolIfeoBlocked,
                                TargetDisplayPath: $@"HKLM\{ifeoBase}\{tool} :: Debugger",
                                Hive: "HKLM",
                                SubKeyPath: $@"{ifeoBase}\{tool}",
                                ValueName: "Debugger",
                                CurrentMaliciousValue: dbg,
                                SimpleTitle: $"Перехвачен запуск системной утилиты «{tool}»",
                                SimpleExplanation: $"При попытке открыть «{tool}» система перенаправляется на «{dbg}»."));
                        }
                    }
                }
            }
            catch { }

            // Проверка блокировок антивирусов и Центра обновления в файле hosts
            var hostsPath = GetHostsFilePath();
            if (File.Exists(hostsPath))
            {
                try
                {
                    var text = File.ReadAllText(hostsPath);
                    var suspicious = NetworkAndHostsInspector.ParseHostsContent(text)
                        .Where(h => h.IsSuspiciousSecurityBlock)
                        .ToList();

                    if (suspicious.Count > 0)
                    {
                        var sampleDomains = string.Join(", ", suspicious.Take(4).Select(s => s.DomainHost));
                        findings.Add(new OsSabotageFinding(
                            Kind: OsSabotageKind.SecurityDomainsBlockedInHosts,
                            TargetDisplayPath: hostsPath,
                            Hive: "FILE",
                            SubKeyPath: hostsPath,
                            ValueName: "hosts",
                            CurrentMaliciousValue: sampleDomains,
                            SimpleTitle: $"В файле hosts заблокированы сайты антивирусов и обновлений ({suspicious.Count} шт.)",
                            SimpleExplanation: $"Обнаружена блокировка доступа к защитным серверам ({sampleDomains})."));
                    }
                }
                catch { }
            }

            return findings;
        }, ct);
    }

    public override Task<(bool Succeeded, string? OriginalHostsBackupContent)> RepairSabotageLockAsync(
        OsSabotageFinding lockFinding,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult((false, (string?)null));
        }

        return Task.Run(() =>
        {
            if (lockFinding.Kind == OsSabotageKind.SecurityDomainsBlockedInHosts)
            {
                try
                {
                    var hostsPath = GetHostsFilePath();
                    if (!File.Exists(hostsPath)) return (false, (string?)null);

                    var original = File.ReadAllText(hostsPath);
                    var suspiciousLines = NetworkAndHostsInspector.ParseHostsContent(original)
                        .Where(h => h.IsSuspiciousSecurityBlock)
                        .Select(h => h.LineNumber)
                        .ToHashSet();

                    var rawLines = original.Split(["\r\n", "\n"], StringSplitOptions.None);
                    var cleaned = new StringBuilder();
                    for (int i = 0; i < rawLines.Length; i++)
                    {
                        if (!suspiciousLines.Contains(i + 1))
                        {
                            cleaned.AppendLine(rawLines[i]);
                        }
                    }

                    File.WriteAllText(hostsPath, cleaned.ToString(), Encoding.UTF8);
                    return (true, original);
                }
                catch
                {
                    return (false, (string?)null);
                }
            }

            try
            {
                var root = string.Equals(lockFinding.Hive, "HKLM", StringComparison.OrdinalIgnoreCase)
                    ? Registry.LocalMachine
                    : Registry.CurrentUser;

                using var key = root.OpenSubKey(lockFinding.SubKeyPath, writable: true);
                if (key is null) return (false, (string?)null);
                key.DeleteValue(lockFinding.ValueName, throwOnMissingValue: false);
                return (true, (string?)null);
            }
            catch
            {
                return (false, (string?)null);
            }
        }, ct);
    }

    private static void CheckPolicyIntLock(
        RegistryKey root,
        string hiveName,
        string subKeyPath,
        string valueName,
        OsSabotageKind kind,
        string title,
        string explanation,
        List<OsSabotageFinding> sink)
    {
        try
        {
            using var key = root.OpenSubKey(subKeyPath, writable: false);
            if (key?.GetValue(valueName) is int flag && flag != 0)
            {
                sink.Add(new OsSabotageFinding(
                    Kind: kind,
                    TargetDisplayPath: $@"{hiveName}\{subKeyPath} :: {valueName}",
                    Hive: hiveName,
                    SubKeyPath: subKeyPath,
                    ValueName: valueName,
                    CurrentMaliciousValue: flag.ToString(CultureInfo.InvariantCulture),
                    SimpleTitle: title,
                    SimpleExplanation: explanation));
            }
        }
        catch { }
    }

    private static string GetHostsFilePath() =>
        Path.Combine(Environment.SystemDirectory, "drivers", "etc", "hosts");

    // ==================== NETAPI32 P/INVOKE (УЧЁТНЫЕ ЗАПИСИ) ====================
    private const uint FILTER_NORMAL_ACCOUNT = 0x0002;
    private const uint UF_ACCOUNTDISABLE = 0x0002;
    private const uint USER_PRIV_ADMIN = 2;

    [StructLayout(LayoutKind.Sequential)]
    private struct USER_INFO_1
    {
        public IntPtr usri1_name;
        public IntPtr usri1_password;
        public uint usri1_password_age;
        public uint usri1_priv;
        public IntPtr usri1_home_dir;
        public IntPtr usri1_comment;
        public uint usri1_flags;
        public IntPtr usri1_script_path;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint NetUserEnum(
        string? servername,
        uint level,
        uint filter,
        out IntPtr bufptr,
        uint prefmaxlen,
        out uint entriesread,
        out uint totalentries,
        IntPtr resume_handle);

    [DllImport("netapi32.dll", ExactSpelling = true)]
    private static extern uint NetApiBufferFree(IntPtr buffer);
}
