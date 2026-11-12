using System.Windows;
using UltimateWindows.Core.Elevation;
using UltimateWindows.NativeInterop.Security;

namespace UltimateWindows.App;

public partial class App : Application
{
    public bool IsDarkTheme { get; private set; } = true;

    /// <summary>
    /// Запуск без главного окна и без запроса прав: приложение только загружает свои ресурсы и стили.
    /// Так его создают автоматические проверки интерфейса; при обычном запуске значение не меняется.
    /// </summary>
    public static bool StartWithoutMainWindow { get; set; }

    /// <summary>
    /// Главное окно создаётся здесь, а не через StartupUri: сначала нужно решить,
    /// продолжает ли работу этот экземпляр или его сменяет экземпляр с правами администратора.
    /// </summary>
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        if (StartWithoutMainWindow)
        {
            return;
        }

        // Непредвиденная ошибка в интерфейсе не должна закрывать программу посреди работы с системой
        DispatcherUnhandledException += (_, args) =>
        {
            args.Handled = true;
            MessageBox.Show(
                $"Произошла непредвиденная ошибка. Программа продолжает работать.\n\n{args.Exception.Message}",
                "UltimateWindows",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        };

        if (TryHandOverToElevatedInstance(e.Args))
        {
            Shutdown(0);
            return;
        }

        var window = new MainWindow();
        window.Show();
    }

    /// <summary>
    /// Почти все исправления системы требуют прав администратора, поэтому при запуске программа
    /// просит их через штатное окно UAC. Если пользователь отказал, работа продолжается
    /// в ограниченном режиме: диагностика доступна, а исправления сообщат, что нужны права.
    /// Ключ «--no-elevate» отключает запрос.
    /// </summary>
    private static bool TryHandOverToElevatedInstance(string[] args)
    {
        var isElevated = ElevationChecker.IsRunningAsAdministrator();
        if (!ElevationStartupPolicy.ShouldRequestElevationOnStartup(args, isElevated))
        {
            return false;
        }

        var relaunchArguments = ElevationStartupPolicy.BuildRelaunchArguments(args);
        var result = ProcessElevation.TryRelaunchElevated(relaunchArguments, out _);
        return result == ElevationRequestResult.RelaunchStarted;
    }

    public void ToggleTheme()
    {
        IsDarkTheme = !IsDarkTheme;
        var themeUri = new Uri(
            IsDarkTheme ? "Themes/FluentDarkTheme.xaml" : "Themes/FluentLightTheme.xaml",
            UriKind.Relative);

        var dictionaries = Resources.MergedDictionaries;
        if (dictionaries.Count > 0)
        {
            dictionaries[0] = new ResourceDictionary { Source = themeUri };
        }
    }
}
