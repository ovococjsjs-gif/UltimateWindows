using System.Windows;

namespace UltimateWindows.App;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
    }

    private void OnToggleThemeClick(object sender, RoutedEventArgs e)
    {
        if (Application.Current is App app)
        {
            app.ToggleTheme();
        }
    }
}
