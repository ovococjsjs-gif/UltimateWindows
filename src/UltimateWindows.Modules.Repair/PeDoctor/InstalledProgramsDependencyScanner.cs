using System.Diagnostics;
using UltimateWindows.Modules.Repair.Models;

namespace UltimateWindows.Modules.Repair.PeDoctor;

/// <summary>
/// Пакетный сканер зависимостей всех установленных программ Windows:
/// проверяет основные исполняемые файлы .exe на конфликты разрядности 0xC000007B и отсутствие официальных пакетов VC++ / DirectX / .NET / WebView2,
/// учитывая локальные подпапки установки (bin, lib, x64, x86), чтобы не выдавать ложных срабатываний.
/// </summary>
public sealed class InstalledProgramsDependencyScanner
{
    private readonly BinaryPeDependencyDoctor _peDoctor;

    public InstalledProgramsDependencyScanner(BinaryPeDependencyDoctor? peDoctor = null)
    {
        _peDoctor = peDoctor ?? new BinaryPeDependencyDoctor();
    }

    public InstalledProgramsScanSummary ScanPrograms(
        IReadOnlyList<InstalledProgramInfo> programs,
        string system64Directory,
        string sysWow64Directory,
        CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var broken = new List<InstalledProgramDependencyFinding>();
        var distinctPackages = new Dictionary<string, OfficialRuntimePackage>(StringComparer.OrdinalIgnoreCase);
        var inspected = 0;

        foreach (var prog in programs)
        {
            ct.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(prog.ExecutablePath) || !File.Exists(prog.ExecutablePath))
            {
                continue;
            }

            var extraDirs = CollectSiblingSearchDirectories(prog.ExecutablePath, prog.InstallDirectory);
            var report = _peDoctor.DiagnoseExecutable(
                prog.ExecutablePath,
                system64Directory,
                sysWow64Directory,
                extraDirs);

            if (!report.BinaryHeader.IsValidPeFile)
            {
                continue;
            }

            inspected++;

            // В массовом режиме сообщаем о подтверждённых проблемах сред выполнения и конфликтах 0xC000007B
            // (динамически подгружаемые внутренние плагины в глубине папок программы отфильтровываются).
            var actionableIssues = report.Issues
                .Where(i => i.Kind is DependencyIssueKind.ArchitectureMismatch0xC000007B or DependencyIssueKind.MissingOfficialRuntimeDll)
                .ToList();

            if (actionableIssues.Count == 0)
            {
                continue;
            }

            foreach (var pkg in report.RecommendedPackages)
            {
                distinctPackages[pkg.PackageKey] = pkg;
            }

            var filteredReport = report with
            {
                IsHealthy = false,
                Has0xC000007BConflict = actionableIssues.Any(i => i.Kind == DependencyIssueKind.ArchitectureMismatch0xC000007B),
                Issues = actionableIssues
            };

            broken.Add(new InstalledProgramDependencyFinding(prog, filteredReport));
        }

        sw.Stop();
        return new InstalledProgramsScanSummary(
            TotalProgramsFound: programs.Count,
            ExecutablesInspected: inspected,
            Elapsed: sw.Elapsed,
            BrokenPrograms: broken,
            DistinctRecommendedPackages: distinctPackages.Values.ToList());
    }

    private static List<string> CollectSiblingSearchDirectories(string exePath, string installDirectory)
    {
        var dirs = new List<string>(8);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void TryAdd(string? dir)
        {
            if (!string.IsNullOrWhiteSpace(dir) && Directory.Exists(dir) && seen.Add(dir))
            {
                dirs.Add(dir);
            }
        }

        var exeDir = Path.GetDirectoryName(exePath);
        TryAdd(installDirectory);
        if (!string.IsNullOrWhiteSpace(exeDir))
        {
            TryAdd(Path.GetDirectoryName(exeDir));
            TryAddSubfolders(exeDir, TryAdd);
        }

        if (!string.IsNullOrWhiteSpace(installDirectory))
        {
            TryAddSubfolders(installDirectory, TryAdd);
        }

        return dirs;
    }

    private static void TryAddSubfolders(string root, Action<string?> add)
    {
        try
        {
            var count = 0;
            foreach (var sub in Directory.EnumerateDirectories(root))
            {
                add(sub);
                if (++count >= 12) break;
            }
        }
        catch
        {
            // Пропуск защищённых папок
        }
    }
}
