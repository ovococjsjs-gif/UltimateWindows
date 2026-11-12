using System.Diagnostics;
using System.Runtime.ExceptionServices;
using System.Windows;
using System.Windows.Threading;
using UltimateWindows.App.Infrastructure;

namespace UltimateWindows.WindowsTests;

/// <summary>
/// Один поток интерфейса на все проверки: WPF допускает только один объект Application на процесс
/// и требует, чтобы элементы создавались в потоке с однопоточным подразделением (STA).
/// </summary>
internal static class WpfHost
{
    private static readonly Lazy<Dispatcher> UiDispatcher = new(Start, LazyThreadSafetyMode.ExecutionAndPublication);
    private static readonly List<Exception> BackgroundErrors = [];

    /// <summary>
    /// Выполняет проверку в потоке интерфейса и ждёт её завершения. Ошибка, которая произошла в потоке интерфейса
    /// вне самой проверки (при раскладке, в привязке, в команде), тоже считается провалом.
    /// </summary>
    public static async Task RunAsync(Func<Task> body)
    {
        var dispatcher = UiDispatcher.Value;
        TakeBackgroundErrors();

        Exception? failure = null;
        try
        {
            await dispatcher.InvokeAsync(body).Task.Unwrap();
        }
        catch (Exception ex)
        {
            failure = ex;
        }

        var background = TakeBackgroundErrors();
        if (background.Count > 0)
        {
            var all = new List<Exception>(background);
            if (failure is not null)
            {
                all.Add(failure);
            }

            throw new AggregateException(
                "Ошибки в потоке интерфейса: " + string.Join(" | ", all.Select(e => e.Message)),
                all);
        }

        if (failure is not null)
        {
            ExceptionDispatchInfo.Capture(failure).Throw();
        }
    }

    /// <summary>
    /// Отдаёт управление диспетчеру, пока он не выполнит всё накопившееся: привязки, раскладку, отрисовку.
    /// </summary>
    public static async Task IdleAsync()
    {
        await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);
        await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);
    }

    /// <summary>
    /// Ждёт, пока условие не выполнится, не блокируя поток интерфейса.
    /// </summary>
    public static async Task<bool> WaitUntilAsync(Func<bool> condition, TimeSpan timeout)
    {
        var watch = Stopwatch.StartNew();
        while (!condition())
        {
            if (watch.Elapsed > timeout)
            {
                return false;
            }

            await Task.Delay(100);
        }

        await IdleAsync();
        return true;
    }

    private static void RecordBackgroundError(Exception error)
    {
        lock (BackgroundErrors)
        {
            BackgroundErrors.Add(error);
        }
    }

    private static List<Exception> TakeBackgroundErrors()
    {
        lock (BackgroundErrors)
        {
            var taken = new List<Exception>(BackgroundErrors);
            BackgroundErrors.Clear();
            return taken;
        }
    }

    private static Dispatcher Start()
    {
        using var ready = new ManualResetEventSlim();
        Dispatcher? dispatcher = null;
        ExceptionDispatchInfo? failure = null;

        var thread = new Thread(() =>
        {
            try
            {
                dispatcher = Dispatcher.CurrentDispatcher;
                SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(dispatcher));

                // Ошибка в потоке интерфейса не должна обрушить процесс проверок: её запоминаем и показываем в итоге
                dispatcher.UnhandledException += (_, args) =>
                {
                    RecordBackgroundError(args.Exception);
                    args.Handled = true;
                };
                AsyncRelayCommand.UnhandledError = RecordBackgroundError;

                // Настоящее приложение со всеми его словарями ресурсов, но без главного окна и запроса прав
                UltimateWindows.App.App.StartWithoutMainWindow = true;
                var app = new UltimateWindows.App.App { ShutdownMode = ShutdownMode.OnExplicitShutdown };
                app.InitializeComponent();
            }
            catch (Exception ex)
            {
                failure = ExceptionDispatchInfo.Capture(ex);
            }
            finally
            {
                ready.Set();
            }

            if (failure is null)
            {
                Dispatcher.Run();
            }
        })
        {
            IsBackground = true,
            Name = "UltimateWindows UI test thread"
        };

        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        ready.Wait();

        failure?.Throw();
        return dispatcher!;
    }
}
