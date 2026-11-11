using System.Diagnostics;
using System.IO.Enumeration;
using System.Text.RegularExpressions;
using UltimateWindows.Modules.Cleaner.Contracts;

namespace UltimateWindows.Modules.Cleaner.Rules;

/// <summary>
/// Движок очистки по правилам: находит файлы, которые описывает каталог, и удаляет отмеченное.
/// <para>
/// Анализ ничего не меняет. Каждый файл проходит защиту (<see cref="CleanupPathGuard"/>) дважды:
/// когда попадает в список и ещё раз перед удалением. По ссылкам на другие папки движок не ходит.
/// Файл достаётся первому правилу, которое его нашло, поэтому два правила не посчитают его дважды.
/// </para>
/// </summary>
public sealed class CleanupRuleEngine
{
    private const int MaxExpandedDirectories = 20000;
    private const int MaxNotesPerFinding = 4;

    private static readonly Regex StorePackageSuffix = new("_[a-z0-9]{13}$", RegexOptions.CultureInvariant);

    private readonly ICleanerPlatformBridge _bridge;
    private readonly CleanupEnvironment _environment;
    private readonly string[] _extraProtectedDirectories;
    private readonly TimeProvider _timeProvider;

    public CleanupRuleEngine(
        ICleanerPlatformBridge bridge,
        CleanupEnvironment environment,
        IEnumerable<string>? extraProtectedDirectories = null,
        TimeProvider? timeProvider = null)
    {
        _bridge = bridge ?? throw new ArgumentNullException(nameof(bridge));
        _environment = environment ?? throw new ArgumentNullException(nameof(environment));
        _extraProtectedDirectories = extraProtectedDirectories?.ToArray() ?? [];
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public CleanupEnvironment Environment => _environment;

    /// <summary>
    /// Анализ: ничего не удаляет. Возвращает находки по каждому правилу, включая неотмеченные,
    /// чтобы пользователь видел, сколько места освободит каждое.
    /// </summary>
    public CleanupRuleScanResult Scan(IReadOnlyList<CleanupRule> rules, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(rules);

        var stopwatch = Stopwatch.StartNew();
        var context = new ScanContext(new CleanupPathGuard(_environment, _extraProtectedDirectories), _timeProvider.GetUtcNow().UtcDateTime);
        var findings = new List<CleanupRuleFinding>();

        foreach (var rule in rules)
        {
            ct.ThrowIfCancellationRequested();
            findings.AddRange(ScanRule(rule, context, ct));
        }

        return new CleanupRuleScanResult(_timeProvider.GetUtcNow(), findings, stopwatch.Elapsed);
    }

    /// <summary>
    /// Удаляет файлы выбранных находок. Занятые файлы пропускаются, защищённые не трогаются.
    /// </summary>
    public CleanupRuleExecutionResult Execute(IReadOnlyList<CleanupRuleFinding> findings, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(findings);

        var guard = new CleanupPathGuard(_environment, _extraProtectedDirectories);
        var running = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        var nowUtc = _timeProvider.GetUtcNow().UtcDateTime;
        var outcomes = new List<CleanupFindingOutcome>();

        long freed = 0;
        int deleted = 0, inUse = 0, blocked = 0, folders = 0;

        foreach (var finding in findings)
        {
            ct.ThrowIfCancellationRequested();
            var rule = finding.Rule;

            if (rule.MustBeClosed && IsAnyProcessRunning(rule, running))
            {
                outcomes.Add(new CleanupFindingOutcome(finding.Key, 0, 0, 0, 0, 0, $"{finding.Application}: программа запущена, правило пропущено."));
                continue;
            }

            var roots = new HashSet<string>(finding.PruneRoots.Select(r => CleanupPathGuard.Normalize(r.Directory)), StringComparer.Ordinal);
            var linkFree = new Dictionary<string, bool>(StringComparer.Ordinal);

            long findingFreed = 0;
            int findingDeleted = 0, findingInUse = 0, findingBlocked = 0, findingFolders = 0;

            foreach (var file in finding.Files)
            {
                ct.ThrowIfCancellationRequested();

                if (guard.CheckFile(file.FullPath, rule) != CleanupPathVerdict.Allowed ||
                    !IsInsideRootsWithoutLinks(file.FullPath, roots, linkFree))
                {
                    findingBlocked++;
                    continue;
                }

                switch (TryDeleteFile(file.FullPath))
                {
                    case DeleteOutcome.Deleted:
                        findingDeleted++;
                        findingFreed += file.SizeBytes;
                        break;
                    case DeleteOutcome.InUse:
                        findingInUse++;
                        break;
                }
            }

            DateTime? cutoff = rule.MinimumAgeHours > 0 ? nowUtc.AddHours(-rule.MinimumAgeHours) : null;
            foreach (var root in finding.PruneRoots)
            {
                findingFolders += PruneEmptyFolders(root, cutoff);
            }

            freed += findingFreed;
            deleted += findingDeleted;
            inUse += findingInUse;
            blocked += findingBlocked;
            folders += findingFolders;
            outcomes.Add(new CleanupFindingOutcome(finding.Key, findingFreed, findingDeleted, findingInUse, findingBlocked, findingFolders, null));
        }

        return new CleanupRuleExecutionResult(freed, deleted, inUse, blocked, folders, outcomes);
    }

    // ---------------------------------------------------------------------------------------------
    // Анализ одного правила
    // ---------------------------------------------------------------------------------------------

    private List<CleanupRuleFinding> ScanRule(CleanupRule rule, ScanContext context, CancellationToken ct)
    {
        var isRunning = IsAnyProcessRunning(rule, context.RunningProcesses);

        if (!MatchesWindowsBuild(rule))
        {
            return [EmptyFinding(rule, isRunning)];
        }

        var hasExplicitDetection = rule.Detection is { } d && (d.AnyPath.Count > 0 || d.AnyRegistryKey.Count > 0);
        var detected = hasExplicitDetection && IsDetected(rule.Detection!, context);
        if (hasExplicitDetection && !detected)
        {
            return [EmptyFinding(rule, isRunning)];
        }

        var exclusions = BuildExclusions(rule, context);
        DateTime? cutoff = rule.MinimumAgeHours > 0 ? context.NowUtc.AddHours(-rule.MinimumAgeHours) : null;
        var buckets = new Dictionary<string, Bucket>(StringComparer.OrdinalIgnoreCase);
        var anyTargetExists = false;

        foreach (var target in rule.Files)
        {
            if (!CleanupPathPattern.TryParse(target.PathPattern, allowRegistryVariable: true, out var pattern, out _))
            {
                continue;
            }

            foreach (var (directory, captures) in ExpandDirectories(pattern, context))
            {
                ct.ThrowIfCancellationRequested();
                anyTargetExists = true;

                var label = target.GroupCaptures > 0 ? string.Join('\\', captures.Take(target.GroupCaptures)) : "";
                if (!buckets.TryGetValue(label, out var bucket))
                {
                    bucket = new Bucket();
                    buckets[label] = bucket;
                }

                var targetVerdict = context.Guard.CheckTargetDirectory(directory, target, rule);
                if (targetVerdict != CleanupPathVerdict.Allowed)
                {
                    bucket.Block($"{directory} — {CleanupPathGuard.Describe(targetVerdict)}");
                    continue;
                }

                bucket.PruneRoots.Add(new CleanupPruneRoot(directory, target.RemoveEmptyFolders, target.RemoveSelf));

                foreach (var file in EnumerateFiles(directory, target.Recurse))
                {
                    ct.ThrowIfCancellationRequested();

                    var name = file.Name;
                    if (name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase) || !MatchesAny(target.FilePatterns, name))
                    {
                        continue;
                    }

                    var fullPath = file.FullName;
                    if (exclusions.Count > 0 && IsExcluded(exclusions, fullPath, name))
                    {
                        continue;
                    }

                    long size;
                    try
                    {
                        if (cutoff is { } limit && (file.LastWriteTimeUtc > limit || file.CreationTimeUtc > limit))
                        {
                            continue;
                        }

                        size = file.Length;
                    }
                    catch (Exception ex) when (IsFileSystemError(ex))
                    {
                        continue;
                    }

                    var verdict = context.Guard.CheckFile(fullPath, rule);
                    if (verdict != CleanupPathVerdict.Allowed)
                    {
                        bucket.Block($"{fullPath} — {CleanupPathGuard.Describe(verdict)}");
                        continue;
                    }

                    if (!context.Claimed.Add(fullPath))
                    {
                        continue;
                    }

                    bucket.Files.Add(new CleanupFoundFile(fullPath, size));
                    bucket.Bytes += size;
                }
            }
        }

        var isPresent = hasExplicitDetection ? detected : anyTargetExists;
        if (!isPresent)
        {
            return [EmptyFinding(rule, isRunning)];
        }

        if (!rule.IsGrouped)
        {
            buckets.TryGetValue("", out var single);
            single ??= new Bucket();
            return [BuildFinding(rule, rule.Id, rule.Application, single, isRunning)];
        }

        var findings = new List<CleanupRuleFinding>();
        foreach (var (label, bucket) in buckets.OrderBy(b => b.Key, StringComparer.OrdinalIgnoreCase))
        {
            if (bucket.Files.Count == 0 && bucket.Blocked == 0)
            {
                continue;
            }

            var application = rule.GroupLabels.TryGetValue(label, out var known) ? known : PrettifyLabel(label);
            findings.Add(BuildFinding(rule, $"{rule.Id}|{label}", application, bucket, isRunning));
        }

        return findings.Count > 0 ? findings : [EmptyFinding(rule, isRunning)];
    }

    private static CleanupRuleFinding BuildFinding(CleanupRule rule, string key, string application, Bucket bucket, bool isRunning)
    {
        var notes = new List<string>();
        if (isRunning)
        {
            notes.Add(rule.MustBeClosed
                ? $"Закройте программу «{application}», чтобы очистить."
                : $"Программа «{application}» запущена: занятые ею файлы останутся.");
        }

        notes.AddRange(bucket.Notes);
        return new CleanupRuleFinding(rule, key, application, true, bucket.Files, bucket.Bytes, bucket.PruneRoots, bucket.Blocked, isRunning, notes);
    }

    private static CleanupRuleFinding EmptyFinding(CleanupRule rule, bool isRunning) =>
        new(rule, rule.Id, rule.Application, false, [], 0, [], 0, isRunning, []);

    private static string PrettifyLabel(string label)
    {
        // Папки приложений Microsoft Store называются «Издатель.Программа_кодиздателя»
        var name = StorePackageSuffix.Replace(label, "");
        return name.Length > 0 ? name : label;
    }

    private bool MatchesWindowsBuild(CleanupRule rule)
    {
        var build = _environment.WindowsBuild;
        if (build <= 0 || rule.Detection is not { } detection)
        {
            return true;
        }

        return (detection.MinWindowsBuild is not { } min || build >= min) &&
               (detection.MaxWindowsBuild is not { } max || build <= max);
    }

    private bool IsDetected(CleanupDetection detection, ScanContext context)
    {
        foreach (var key in detection.AnyRegistryKey)
        {
            if (SafeRegistryKeyExists(key))
            {
                return true;
            }
        }

        foreach (var text in detection.AnyPath)
        {
            if (CleanupPathPattern.TryParse(text, allowRegistryVariable: true, out var pattern, out _) && PathExists(pattern, context))
            {
                return true;
            }
        }

        return false;
    }

    private bool PathExists(CleanupPathPattern pattern, ScanContext context)
    {
        if (pattern.Segments.Count == 0)
        {
            return ResolveRoots(pattern, context).Any(Directory.Exists);
        }

        // Последняя часть пути может быть и файлом, и папкой
        var parent = pattern with { Segments = pattern.Segments.Take(pattern.Segments.Count - 1).ToArray() };
        var last = pattern.Segments[^1];
        foreach (var (directory, _) in ExpandDirectories(parent, context))
        {
            try
            {
                if (CleanupPathPattern.IsWildcard(last))
                {
                    if (Directory.EnumerateFileSystemEntries(directory, last).Any())
                    {
                        return true;
                    }
                }
                else
                {
                    var candidate = Path.Combine(directory, last);
                    if (File.Exists(candidate) || Directory.Exists(candidate))
                    {
                        return true;
                    }
                }
            }
            catch (Exception ex) when (IsFileSystemError(ex))
            {
                // Папка недоступна — считаем, что признака нет
            }
        }

        return false;
    }

    private List<(string DirectoryNorm, IReadOnlyList<string> Masks)> BuildExclusions(CleanupRule rule, ScanContext context)
    {
        var list = new List<(string, IReadOnlyList<string>)>();
        foreach (var exclusion in rule.Exclusions)
        {
            if (!CleanupPathPattern.TryParse(exclusion.PathPattern, allowRegistryVariable: true, out var pattern, out _))
            {
                continue;
            }

            foreach (var (directory, _) in ExpandDirectories(pattern, context))
            {
                list.Add((CleanupPathGuard.Normalize(directory), exclusion.FilePatterns));
            }
        }

        return list;
    }

    private static bool IsExcluded(List<(string DirectoryNorm, IReadOnlyList<string> Masks)> exclusions, string fullPath, string name)
    {
        var path = CleanupPathGuard.Normalize(fullPath);
        foreach (var (directory, masks) in exclusions)
        {
            if (path.Length > directory.Length &&
                path[directory.Length] == '/' &&
                path.StartsWith(directory, StringComparison.Ordinal) &&
                (masks.Count == 0 || MatchesAny(masks, name)))
            {
                return true;
            }
        }

        return false;
    }

    private static bool MatchesAny(IReadOnlyList<string> masks, string name)
    {
        foreach (var mask in masks)
        {
            if (mask == "*" || FileSystemName.MatchesSimpleExpression(mask, name, ignoreCase: true))
            {
                return true;
            }
        }

        return false;
    }

    // ---------------------------------------------------------------------------------------------
    // Раскрытие путей
    // ---------------------------------------------------------------------------------------------

    private IEnumerable<string> ResolveRoots(CleanupPathPattern pattern, ScanContext context)
    {
        if (!pattern.IsRegistryBased)
        {
            return _environment.Resolve(pattern.Variable!);
        }

        var cacheKey = $"{pattern.RegistryKey}@{pattern.RegistryValue}";
        if (!context.RegistryRoots.TryGetValue(cacheKey, out var root))
        {
            root = ReadRegistryDirectory(pattern.RegistryKey!, pattern.RegistryValue ?? "");
            context.RegistryRoots[cacheKey] = root;
        }

        return root is null ? Array.Empty<string>() : new[] { root };
    }

    private string? ReadRegistryDirectory(string key, string valueName)
    {
        string? raw;
        try
        {
            raw = _bridge.ReadRegistryString(key, valueName);
        }
        catch (Exception)
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        var path = raw.Trim().Trim('"').Replace('/', Path.DirectorySeparatorChar).TrimEnd('\\', '/');

        // Корень диска или относительный путь — не папка программы
        return path.Length > 3 && Path.IsPathRooted(path) ? path : null;
    }

    /// <summary>
    /// Раскрывает путь правила в существующие папки. Звёздочки в частях пути перебирают вложенные папки;
    /// для каждой найденной папки возвращаются значения звёздочек по порядку.
    /// </summary>
    private IEnumerable<(string Directory, string[] Captures)> ExpandDirectories(CleanupPathPattern pattern, ScanContext context)
    {
        foreach (var root in ResolveRoots(pattern, context))
        {
            if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
            {
                continue;
            }

            var current = new List<(string Directory, string[] Captures)> { (root, Array.Empty<string>()) };
            foreach (var segment in pattern.Segments)
            {
                var next = new List<(string Directory, string[] Captures)>();
                var isWildcard = CleanupPathPattern.IsWildcard(segment);

                foreach (var (directory, captures) in current)
                {
                    // Список вложенных папок не содержит ссылок на другие места и запоминается на время анализа,
                    // поэтому общие правила с десятками похожих путей не перечитывают диск
                    var names = context.GetSubdirectories(directory);
                    if (!isWildcard)
                    {
                        foreach (var name in names)
                        {
                            if (name.Equals(segment, StringComparison.OrdinalIgnoreCase))
                            {
                                next.Add((Path.Combine(directory, name), captures));
                                break;
                            }
                        }

                        continue;
                    }

                    foreach (var name in names)
                    {
                        if (!FileSystemName.MatchesSimpleExpression(segment, name, ignoreCase: true))
                        {
                            continue;
                        }

                        var extended = new string[captures.Length + 1];
                        captures.CopyTo(extended, 0);
                        extended[^1] = name;
                        next.Add((Path.Combine(directory, name), extended));
                    }

                    if (next.Count >= MaxExpandedDirectories)
                    {
                        break;
                    }
                }

                current = next;
                if (current.Count == 0)
                {
                    break;
                }
            }

            foreach (var item in current)
            {
                if (context.IsReachableWithoutLinks(item.Directory, root))
                {
                    yield return item;
                }
            }
        }
    }

    private static IEnumerable<FileInfo> EnumerateFiles(string directory, bool recurse)
    {
        var options = new EnumerationOptions
        {
            RecurseSubdirectories = recurse,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.ReparsePoint,
            ReturnSpecialDirectories = false
        };

        IEnumerator<FileInfo>? enumerator = null;
        try
        {
            enumerator = new DirectoryInfo(directory).EnumerateFiles("*", options).GetEnumerator();
        }
        catch (Exception ex) when (IsFileSystemError(ex))
        {
            // Папка исчезла или недоступна
        }

        if (enumerator is null)
        {
            yield break;
        }

        using (enumerator)
        {
            while (true)
            {
                FileInfo? current = null;
                try
                {
                    if (enumerator.MoveNext())
                    {
                        current = enumerator.Current;
                    }
                }
                catch (Exception ex) when (IsFileSystemError(ex))
                {
                    // Папку меняют прямо сейчас: останавливаемся на том, что успели увидеть
                }

                if (current is null)
                {
                    yield break;
                }

                yield return current;
            }
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Удаление
    // ---------------------------------------------------------------------------------------------

    private enum DeleteOutcome
    {
        Deleted,
        InUse,
        Missing
    }

    private static DeleteOutcome TryDeleteFile(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return DeleteOutcome.Missing;
            }

            File.Delete(path);
            return DeleteOutcome.Deleted;
        }
        catch (UnauthorizedAccessException)
        {
            // Чаще всего это пометка «только чтение»: снимаем её и пробуем ещё раз
            try
            {
                File.SetAttributes(path, FileAttributes.Normal);
                File.Delete(path);
                return DeleteOutcome.Deleted;
            }
            catch (Exception ex) when (IsFileSystemError(ex))
            {
                return DeleteOutcome.InUse;
            }
        }
        catch (DirectoryNotFoundException)
        {
            return DeleteOutcome.Missing;
        }
        catch (Exception ex) when (IsFileSystemError(ex))
        {
            return DeleteOutcome.InUse;
        }
    }

    private static int PruneEmptyFolders(CleanupPruneRoot root, DateTime? cutoffUtc)
    {
        if (!root.RemoveEmptyFolders && !root.RemoveSelf)
        {
            return 0;
        }

        var removed = 0;
        if (root.RemoveEmptyFolders)
        {
            List<string> folders;
            try
            {
                folders = Directory.EnumerateDirectories(root.Directory, "*", new EnumerationOptions
                {
                    RecurseSubdirectories = true,
                    IgnoreInaccessible = true,
                    AttributesToSkip = FileAttributes.ReparsePoint,
                    ReturnSpecialDirectories = false
                }).ToList();
            }
            catch (Exception ex) when (IsFileSystemError(ex))
            {
                folders = [];
            }

            // Сначала самые глубокие: папка пустеет, когда удалены её вложенные
            folders.Sort((a, b) => b.Length.CompareTo(a.Length));
            foreach (var folder in folders)
            {
                if (TryRemoveEmptyFolder(folder, cutoffUtc))
                {
                    removed++;
                }
            }
        }

        if (root.RemoveSelf && TryRemoveEmptyFolder(root.Directory, cutoffUtc))
        {
            removed++;
        }

        return removed;
    }

    private static bool TryRemoveEmptyFolder(string folder, DateTime? cutoffUtc)
    {
        try
        {
            var info = new DirectoryInfo(folder);
            if (!info.Exists || (info.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                return false;
            }

            // Время изменения папки обновилось, когда мы удаляли её файлы, поэтому возраст считается по созданию
            if (cutoffUtc is { } limit && info.CreationTimeUtc > limit)
            {
                return false;
            }

            if (Directory.EnumerateFileSystemEntries(folder).Any())
            {
                return false;
            }

            Directory.Delete(folder, recursive: false);
            return true;
        }
        catch (Exception ex) when (IsFileSystemError(ex))
        {
            return false;
        }
    }

    /// <summary>
    /// Файл должен лежать внутри одной из папок находки, и по дороге к нему не должно быть ссылок на другие папки.
    /// </summary>
    private static bool IsInsideRootsWithoutLinks(string filePath, HashSet<string> rootsNorm, Dictionary<string, bool> cache)
    {
        var directory = Path.GetDirectoryName(filePath);
        var visited = new List<string>();
        var result = false;

        while (!string.IsNullOrEmpty(directory))
        {
            var norm = CleanupPathGuard.Normalize(directory);
            if (cache.TryGetValue(norm, out var known))
            {
                result = known;
                break;
            }

            visited.Add(norm);
            if (IsReparsePoint(directory))
            {
                result = false;
                break;
            }

            if (rootsNorm.Contains(norm))
            {
                result = true;
                break;
            }

            directory = Path.GetDirectoryName(directory);
        }

        foreach (var norm in visited)
        {
            cache[norm] = result;
        }

        return result;
    }

    private static bool IsReparsePoint(string directory)
    {
        try
        {
            return (File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0;
        }
        catch (Exception ex) when (IsFileSystemError(ex))
        {
            return true;
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Процессы, реестр, ошибки
    // ---------------------------------------------------------------------------------------------

    private bool IsAnyProcessRunning(CleanupRule rule, Dictionary<string, bool> cache)
    {
        foreach (var name in rule.Processes)
        {
            if (!cache.TryGetValue(name, out var running))
            {
                try
                {
                    running = _bridge.IsProcessRunningByName(new[] { name });
                }
                catch (Exception)
                {
                    running = false;
                }

                cache[name] = running;
            }

            if (running)
            {
                return true;
            }
        }

        return false;
    }

    private bool SafeRegistryKeyExists(string key)
    {
        try
        {
            return _bridge.RegistryKeyExists(key);
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static bool IsFileSystemError(Exception ex) =>
        ex is IOException or UnauthorizedAccessException or System.Security.SecurityException or NotSupportedException;

    private sealed class Bucket
    {
        public List<CleanupFoundFile> Files { get; } = [];
        public List<CleanupPruneRoot> PruneRoots { get; } = [];
        public List<string> Notes { get; } = [];
        public long Bytes { get; set; }
        public int Blocked { get; private set; }

        public void Block(string note)
        {
            Blocked++;
            if (Notes.Count < MaxNotesPerFinding)
            {
                Notes.Add("Защита: " + note);
            }
        }
    }

    private sealed class ScanContext(CleanupPathGuard guard, DateTime nowUtc)
    {
        private readonly Dictionary<string, string[]> _subdirectories = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, bool> _linkFree = new(StringComparer.OrdinalIgnoreCase);

        public CleanupPathGuard Guard { get; } = guard;
        public DateTime NowUtc { get; } = nowUtc;
        public HashSet<string> Claimed { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, bool> RunningProcesses { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string?> RegistryRoots { get; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Имена вложенных папок, кроме ссылок. Запоминаются на время анализа.</summary>
        public string[] GetSubdirectories(string directory)
        {
            if (_subdirectories.TryGetValue(directory, out var names))
            {
                return names;
            }

            try
            {
                names = new DirectoryInfo(directory)
                    .EnumerateDirectories("*", new EnumerationOptions
                    {
                        IgnoreInaccessible = true,
                        AttributesToSkip = FileAttributes.ReparsePoint,
                        ReturnSpecialDirectories = false
                    })
                    .Select(d => d.Name)
                    .ToArray();
            }
            catch (Exception ex) when (IsFileSystemError(ex))
            {
                names = [];
            }

            _subdirectories[directory] = names;
            return names;
        }

        /// <summary>
        /// Между папкой, на которую указывает переменная, и найденной папкой не должно быть ссылок на другие места.
        /// </summary>
        public bool IsReachableWithoutLinks(string directory, string root)
        {
            var rootNorm = CleanupPathGuard.Normalize(root);
            var visited = new List<string>();
            var result = true;
            var current = directory;

            while (!string.IsNullOrEmpty(current))
            {
                if (string.Equals(CleanupPathGuard.Normalize(current), rootNorm, StringComparison.Ordinal))
                {
                    break;
                }

                if (_linkFree.TryGetValue(current, out var known))
                {
                    result = known;
                    break;
                }

                visited.Add(current);
                if (IsReparsePoint(current))
                {
                    result = false;
                    break;
                }

                current = Path.GetDirectoryName(current);
            }

            foreach (var path in visited)
            {
                _linkFree[path] = result;
            }

            return result;
        }
    }
}
