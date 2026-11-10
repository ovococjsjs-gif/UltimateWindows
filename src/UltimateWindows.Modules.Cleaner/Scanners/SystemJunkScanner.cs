using UltimateWindows.Core.Guards;
using UltimateWindows.Modules.Cleaner.Models;

namespace UltimateWindows.Modules.Cleaner.Scanners;

public sealed record SystemJunkPathsConfig(
    string UserTempDirectory,
    string SystemTempDirectory,
    string LocalAppDataDirectory,
    string RoamingAppDataDirectory,
    string CommonAppDataDirectory,
    string WindowsDirectory);

/// <summary>
/// Безопасный сканер системного мусора, кэшей шейдеров GPU, старых отчетов о сбоях WER и неактивного кэша обновлений.
/// Соблюдает возрастной ценз файлов (по умолчанию >= 24 ч для Temp), чтобы не ломать активные установщики и рабочие программы.
/// </summary>
public sealed class SystemJunkScanner
{
    private readonly SystemJunkPathsConfig _paths;
    private readonly TimeProvider _timeProvider;

    public SystemJunkScanner(
        SystemJunkPathsConfig? customPaths = null,
        TimeProvider? timeProvider = null)
    {
        _paths = customPaths ?? CreateDefaultOsPaths();
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public IReadOnlyList<CleanupCandidateFile> ScanSystemJunk(
        CleanupOptions options,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(options);

        var list = new List<CleanupCandidateFile>();
        var nowUtc = _timeProvider.GetUtcNow();
        var minTempAge = TimeSpan.FromHours(Math.Max(0, options.MinimumTempFileAgeHours));

        if (options.CleanSystemTempAndShaders)
        {
            // 1. Пользовательский и системный Temp (с защитой свежих файлов моложе 24 часов!)
            var seenTempRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var tempDir in new[] { _paths.UserTempDirectory, _paths.SystemTempDirectory })
            {
                if (string.IsNullOrWhiteSpace(tempDir) || !Directory.Exists(tempDir))
                {
                    continue;
                }

                var fullTemp = Path.GetFullPath(tempDir);
                if (!seenTempRoots.Add(fullTemp))
                {
                    continue;
                }

                CollectFilesOlderThan(
                    fullTemp,
                    CleanerCategoryKind.SystemTemp,
                    "Временные файлы системы (Temp)",
                    nowUtc,
                    minTempAge,
                    list,
                    ct);
            }

            // 2. Кэши скомпилированных шейдеров видеокарт (DirectX, NVIDIA, AMD, Intel)
            var shaderTargets = new (string Label, string Dir)[]
            {
                ("Кэш шейдеров DirectX", Path.Combine(_paths.LocalAppDataDirectory, "D3DSCache")),
                ("Кэш шейдеров NVIDIA DXCache", Path.Combine(_paths.LocalAppDataDirectory, "NVIDIA", "DXCache")),
                ("Кэш шейдеров NVIDIA GLCache", Path.Combine(_paths.LocalAppDataDirectory, "NVIDIA", "GLCache")),
                ("Кэш вычислений NVIDIA", Path.Combine(_paths.RoamingAppDataDirectory, "NVIDIA", "ComputeCache")),
                ("Кэш шейдеров AMD DxCache", Path.Combine(_paths.LocalAppDataDirectory, "AMD", "DxCache")),
                ("Кэш шейдеров AMD DxcCache", Path.Combine(_paths.LocalAppDataDirectory, "AMD", "DxcCache")),
                ("Кэш шейдеров AMD GLCache", Path.Combine(_paths.LocalAppDataDirectory, "AMD", "GLCache")),
                ("Кэш шейдеров Intel", Path.Combine(_paths.LocalAppDataDirectory, "Intel", "ShaderCache"))
            };

            foreach (var (label, dir) in shaderTargets)
            {
                CollectFilesOlderThan(dir, CleanerCategoryKind.GpuShaderCache, label, nowUtc, TimeSpan.FromHours(2), list, ct);
            }

            // 3. Архивы отчетов об ошибках Windows Error Reporting (WER)
            var werTargets = new[]
            {
                Path.Combine(_paths.CommonAppDataDirectory, "Microsoft", "Windows", "WER", "ReportArchive"),
                Path.Combine(_paths.CommonAppDataDirectory, "Microsoft", "Windows", "WER", "ReportQueue"),
                Path.Combine(_paths.LocalAppDataDirectory, "Microsoft", "Windows", "WER", "ReportArchive"),
                Path.Combine(_paths.LocalAppDataDirectory, "Microsoft", "Windows", "WER", "ReportQueue")
            };

            foreach (var werDir in werTargets)
            {
                CollectFilesOlderThan(werDir, CleanerCategoryKind.WindowsErrorReports, "Старые отчеты об ошибках (WER)", nowUtc, TimeSpan.FromHours(12), list, ct);
            }

            // 4. Неактивный кэш загрузок Центра обновления Windows (старше 48 часов, чтобы не задеть текущую установку)
            if (!string.IsNullOrWhiteSpace(_paths.WindowsDirectory))
            {
                var wuDownload = Path.Combine(_paths.WindowsDirectory, "SoftwareDistribution", "Download");
                CollectFilesOlderThan(
                    wuDownload,
                    CleanerCategoryKind.WindowsUpdateCache,
                    "Старый кэш пакетов Windows Update",
                    nowUtc,
                    TimeSpan.FromHours(48),
                    list,
                    ct);
            }
        }

        // 5. Опционально для разработчиков: кэши скачанных архивов pip / npm / NuGet
        if (options.IncludeDeveloperCaches)
        {
            var devTargets = new (string Label, string Dir)[]
            {
                ("Кэш пакетов Python pip", Path.Combine(_paths.LocalAppDataDirectory, "pip", "cache")),
                ("Кэш пакетов Node.js npm", Path.Combine(_paths.LocalAppDataDirectory, "npm-cache", "_cacache")),
                ("HTTP-кэш пакетов .NET NuGet", Path.Combine(_paths.LocalAppDataDirectory, "NuGet", "v3-cache"))
            };

            foreach (var (label, dir) in devTargets)
            {
                CollectFilesOlderThan(dir, CleanerCategoryKind.DeveloperPackageCache, label, nowUtc, TimeSpan.FromHours(1), list, ct);
            }
        }

        return list;
    }

    private static void CollectFilesOlderThan(
        string directory,
        CleanerCategoryKind category,
        string sourceLabel,
        DateTimeOffset nowUtc,
        TimeSpan minimumAge,
        List<CleanupCandidateFile> sink,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
        {
            return;
        }

        var enumOpts = new EnumerationOptions
        {
            IgnoreInaccessible = true,
            RecurseSubdirectories = true,
            AttributesToSkip = FileAttributes.ReparsePoint
        };

        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(directory, "*", enumOpts);
        }
        catch
        {
            return;
        }

        foreach (var filePath in files)
        {
            ct.ThrowIfCancellationRequested();

            // Защита от случайного захвата защищенных путей браузера, если кто-то перенаправил папку профиля
            var vaultVerdict = BrowserVaultGuard.EvaluatePath(filePath);
            if (vaultVerdict is UltimateWindows.Core.Enums.VaultPathDecision.ProtectedCredentialsOrAutofill
                or UltimateWindows.Core.Enums.VaultPathDecision.ProtectedSessionOrExtension)
            {
                continue;
            }

            try
            {
                var info = new FileInfo(filePath);
                if (!info.Exists || info.Length <= 0)
                {
                    continue;
                }

                var age = nowUtc - new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero);
                if (age >= minimumAge)
                {
                    sink.Add(new CleanupCandidateFile(
                        Category: category,
                        SourceLabel: sourceLabel,
                        FullPath: info.FullName,
                        SizeBytes: info.Length));
                }
            }
            catch
            {
                // Пропускаем недоступные дескрипторы
            }
        }
    }

    private static SystemJunkPathsConfig CreateDefaultOsPaths()
    {
        var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var sysTemp = !string.IsNullOrWhiteSpace(winDir) ? Path.Combine(winDir, "Temp") : "";

        return new SystemJunkPathsConfig(
            UserTempDirectory: Path.GetTempPath(),
            SystemTempDirectory: sysTemp,
            LocalAppDataDirectory: Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            RoamingAppDataDirectory: Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            CommonAppDataDirectory: Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            WindowsDirectory: winDir);
    }
}
