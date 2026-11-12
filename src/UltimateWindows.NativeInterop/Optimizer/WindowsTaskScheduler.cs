using System.Runtime.InteropServices;
using UltimateWindows.Modules.Optimizer.Models;

namespace UltimateWindows.NativeInterop.Optimizer;

/// <summary>
/// Планировщик заданий Windows через его штатный COM-интерфейс (Schedule.Service): список заданий,
/// состояние «включено / отключено» и его изменение. Разбор вывода schtasks.exe не используется —
/// он зависит от языка Windows.
/// </summary>
public static class WindowsTaskScheduler
{
    private const int TASK_ENUM_HIDDEN = 1;
    private const int TASK_STATE_RUNNING = 4;
    private const int TASK_ACTION_EXEC = 0;
    private const int TASK_ACTION_COM_HANDLER = 5;

    private const int E_ACCESSDENIED = unchecked((int)0x80070005);

    /// <summary>
    /// Состояние заданий по полным путям. Заданий, которых нет (или которые нельзя прочитать), в ответе нет.
    /// </summary>
    public static IReadOnlyDictionary<string, ScheduledTaskSnapshot> Query(IReadOnlyCollection<string> taskPaths)
    {
        var found = new Dictionary<string, ScheduledTaskSnapshot>(StringComparer.OrdinalIgnoreCase);
        if (!OperatingSystem.IsWindows() || taskPaths.Count == 0)
        {
            return found;
        }

        WithService(service =>
        {
            foreach (var path in taskPaths)
            {
                var taskObject = TryGetTask(service, path);
                if (taskObject is null)
                {
                    continue;
                }

                try
                {
                    dynamic task = taskObject;
                    bool enabled = task.Enabled;
                    found[path] = new ScheduledTaskSnapshot(path, enabled);
                }
                catch (Exception)
                {
                    // Задание есть, но его состояние прочитать нельзя — считаем, что управлять им мы не можем
                }
                finally
                {
                    Release(taskObject);
                }
            }

            return true;
        });

        return found;
    }

    public static PlatformActionResult SetEnabled(string taskPath, bool enabled)
    {
        if (!OperatingSystem.IsWindows())
        {
            return PlatformActionResult.Fail("планировщик заданий доступен только в Windows");
        }

        var result = WithService(service =>
        {
            var taskObject = TryGetTask(service, taskPath);
            if (taskObject is null)
            {
                return PlatformActionResult.Fail("задание не найдено");
            }

            try
            {
                dynamic task = taskObject;
                task.Enabled = enabled;
                return PlatformActionResult.Ok;
            }
            catch (Exception ex)
            {
                return PlatformActionResult.Fail(DescribeError(ex));
            }
            finally
            {
                Release(taskObject);
            }
        });

        return result ?? PlatformActionResult.Fail("не удалось подключиться к планировщику заданий");
    }

    /// <summary>
    /// Все задания планировщика, включая скрытые.
    /// </summary>
    public static IReadOnlyList<ScheduledTaskInfo> List(CancellationToken ct = default)
    {
        var tasks = new List<ScheduledTaskInfo>();
        if (!OperatingSystem.IsWindows())
        {
            return tasks;
        }

        WithService(service =>
        {
            dynamic scheduler = service;
            object root = scheduler.GetFolder(@"\");
            try
            {
                Walk(root, tasks, ct);
            }
            finally
            {
                Release(root);
            }

            return true;
        });

        return tasks
            .OrderBy(t => t.Folder, StringComparer.OrdinalIgnoreCase)
            .ThenBy(t => t.Name, StringComparer.CurrentCultureIgnoreCase)
            .ToList();
    }

    private static void Walk(object folderObject, List<ScheduledTaskInfo> sink, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        dynamic folder = folderObject;

        try
        {
            object tasksObject = folder.GetTasks(TASK_ENUM_HIDDEN);
            try
            {
                dynamic tasks = tasksObject;
                int count = tasks.Count;
                for (var i = 1; i <= count; i++)
                {
                    object? taskObject = null;
                    try
                    {
                        taskObject = tasks[i];
                        if (taskObject is not null)
                        {
                            sink.Add(Describe(taskObject));
                        }
                    }
                    catch (Exception)
                    {
                        // Одно нечитаемое задание не должно прятать остальные
                    }
                    finally
                    {
                        Release(taskObject);
                    }
                }
            }
            finally
            {
                Release(tasksObject);
            }
        }
        catch (Exception)
        {
            // Папка недоступна — идём дальше
        }

        try
        {
            object foldersObject = folder.GetFolders(0);
            try
            {
                dynamic folders = foldersObject;
                int count = folders.Count;
                for (var i = 1; i <= count; i++)
                {
                    object? child = null;
                    try
                    {
                        child = folders[i];
                        if (child is not null)
                        {
                            Walk(child, sink, ct);
                        }
                    }
                    finally
                    {
                        Release(child);
                    }
                }
            }
            finally
            {
                Release(foldersObject);
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception)
        {
            // Вложенные папки недоступны
        }
    }

    private static ScheduledTaskInfo Describe(object taskObject)
    {
        dynamic task = taskObject;
        string path = task.Path;
        string name = task.Name;
        var separator = path.LastIndexOf('\\');
        var folder = separator <= 0 ? @"\" : path[..separator];

        var enabled = false;
        var running = false;
        DateTime? lastRun = null;
        DateTime? nextRun = null;
        var author = "";
        var actionSummary = "";

        try { enabled = (bool)task.Enabled; } catch (Exception) { }
        try { running = (int)task.State == TASK_STATE_RUNNING; } catch (Exception) { }
        try { lastRun = ToMeaningfulDate((DateTime)task.LastRunTime); } catch (Exception) { }
        try { nextRun = ToMeaningfulDate((DateTime)task.NextRunTime); } catch (Exception) { }

        try
        {
            object definitionObject = task.Definition;
            try
            {
                dynamic definition = definitionObject;
                try { author = (string?)definition.RegistrationInfo.Author ?? ""; } catch (Exception) { }
                actionSummary = DescribeActions(definitionObject);
            }
            finally
            {
                Release(definitionObject);
            }
        }
        catch (Exception)
        {
            // Определение задания недоступно — оставляем то, что уже узнали
        }

        var isMicrosoft = path.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase) ||
                          author.Contains("Microsoft", StringComparison.OrdinalIgnoreCase);

        // Автор системных заданий записан ссылкой на ресурс вида «$(@%SystemRoot%\system32\x.dll,-100)»
        if (author.StartsWith("$(@", StringComparison.Ordinal))
        {
            author = isMicrosoft ? "Microsoft" : "";
        }

        return new ScheduledTaskInfo(path, name, folder, enabled, running, lastRun, nextRun, author, actionSummary, isMicrosoft);
    }

    private static string DescribeActions(object definitionObject)
    {
        var parts = new List<string>();
        dynamic definition = definitionObject;
        object actionsObject = definition.Actions;
        try
        {
            dynamic actions = actionsObject;
            int count = actions.Count;
            for (var i = 1; i <= count && parts.Count < 3; i++)
            {
                object? actionObject = null;
                try
                {
                    actionObject = actions[i];
                    dynamic action = actionObject!;
                    int type = action.Type;
                    if (type == TASK_ACTION_EXEC)
                    {
                        string program = (string?)action.Path ?? "";
                        string arguments = (string?)action.Arguments ?? "";
                        parts.Add(string.IsNullOrWhiteSpace(arguments) ? program : $"{program} {arguments}");
                    }
                    else if (type == TASK_ACTION_COM_HANDLER)
                    {
                        parts.Add("обработчик Windows (COM)");
                    }
                    else
                    {
                        parts.Add("другое действие");
                    }
                }
                catch (Exception)
                {
                    // Действие не читается
                }
                finally
                {
                    Release(actionObject);
                }
            }
        }
        finally
        {
            Release(actionsObject);
        }

        return string.Join("; ", parts);
    }

    /// <summary>
    /// Задание по полному пути, либо null, если нет папки, нет задания или нет прав на чтение.
    /// </summary>
    private static object? TryGetTask(object service, string taskPath)
    {
        if (string.IsNullOrWhiteSpace(taskPath))
        {
            return null;
        }

        var separator = taskPath.LastIndexOf('\\');
        var folderPath = separator <= 0 ? @"\" : taskPath[..separator];
        var name = separator < 0 ? taskPath : taskPath[(separator + 1)..];

        object? folderObject = null;
        try
        {
            dynamic scheduler = service;
            folderObject = scheduler.GetFolder(folderPath);
            dynamic folder = folderObject!;
            object? task = folder.GetTask(name);
            return task;
        }
        catch (Exception)
        {
            return null;
        }
        finally
        {
            Release(folderObject);
        }
    }

    private static T? WithService<T>(Func<object, T> action)
    {
        var type = Type.GetTypeFromProgID("Schedule.Service", throwOnError: false);
        if (type is null)
        {
            return default;
        }

        object? service = null;
        try
        {
            service = Activator.CreateInstance(type);
            if (service is null)
            {
                return default;
            }

            dynamic scheduler = service;
            scheduler.Connect();
            return action(service);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception)
        {
            return default;
        }
        finally
        {
            Release(service);
        }
    }

    private static void Release(object? comObject)
    {
        try
        {
            if (comObject is not null && Marshal.IsComObject(comObject))
            {
                Marshal.ReleaseComObject(comObject);
            }
        }
        catch (Exception)
        {
            // Объект уже освобождён
        }
    }

    private static DateTime? ToMeaningfulDate(DateTime value) => value.Year < 1980 ? null : value;

    private static string DescribeError(Exception ex)
    {
        if (ex is UnauthorizedAccessException || ex.HResult == E_ACCESSDENIED)
        {
            return "отказано в доступе (задание защищено Windows)";
        }

        return ex.Message;
    }
}
