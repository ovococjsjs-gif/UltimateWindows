using System.Windows;

namespace UltimateWindows.App;

public partial class App : Application
{
    public bool IsDarkTheme { get; private set; } = true;

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
