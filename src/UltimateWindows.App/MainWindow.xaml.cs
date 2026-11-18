using System.ComponentModel;
using System.Windows;
using System.Windows.Input;
using UltimateWindows.App.ViewModels;
using UltimateWindows.App.Views;
using UltimateWindows.Core.Enums;

namespace UltimateWindows.App;

public partial class MainWindow : Window
{
    public static readonly DependencyProperty CompactNavigationProperty = DependencyProperty.Register(
        nameof(CompactNavigation), typeof(bool), typeof(MainWindow), new PropertyMetadata(false));
    public bool CompactNavigation { get => (bool)GetValue(CompactNavigationProperty); private set => SetValue(CompactNavigationProperty, value); }
    private readonly Dictionary<SystemDomain, FrameworkElement> _views = [];

    public MainWindow()
    {
        InitializeComponent();
        Width = Math.Min(Width, SystemParameters.WorkArea.Width);
        Height = Math.Min(Height, SystemParameters.WorkArea.Height);
        var model = (MainViewModel)DataContext;
        model.PropertyChanged += OnSectionChanged;
        Closed += (_, _) => model.PropertyChanged -= OnSectionChanged;
        ShowWorkspace(model);
    }

    private void OnSectionChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MainViewModel.SelectedDomain) && sender is MainViewModel model) ShowWorkspace(model);
    }

    private void ShowWorkspace(MainViewModel model)
    {
        if (!_views.TryGetValue(model.SelectedDomain, out var view))
        {
            view = model.SelectedDomain switch
            {
                SystemDomain.HealthOverview => new OverviewWorkspaceView { DataContext = model },
                SystemDomain.SmartCleaner => new DiskAndCleanerWorkspaceView { DataContext = model.CleanerStudio },
                SystemDomain.Optimizer => new OptimizerWorkspaceView { DataContext = model.OptimizerStudio },
                SystemDomain.AntiMiner => new SecurityWorkspaceView { DataContext = model.AntiMinerStudio },
                SystemDomain.DllAndRepair => new RepairWorkspaceView { DataContext = model.RepairStudio },
                SystemDomain.HardwareAndDrivers => new HardwareWorkspaceView { DataContext = model },
                SystemDomain.AppsAndAutomation => new AppsWorkspaceView { DataContext = model.AppsStudio },
                SystemDomain.TimeMachineVault => new VaultWorkspaceView { DataContext = model },
                _ => throw new ArgumentOutOfRangeException(nameof(model.SelectedDomain))
            };
            _views.Add(model.SelectedDomain, view);
        }
        Workspace.Content = view;
    }

    private void OnWindowSizeChanged(object sender, SizeChangedEventArgs e)
    {
        if (RailColumn is null || BrandText is null) return;
        CompactNavigation = e.NewSize.Width < 980;
        RailColumn.Width = new GridLength(CompactNavigation ? 70 : e.NewSize.Width < 1200 ? 195 : 220);
        NavLabel.Visibility = BrandText.Visibility = ThemeLabel.Visibility = CompactNavigation ? Visibility.Collapsed : Visibility.Visible;
    }

    private void OnFindTool(object sender, ExecutedRoutedEventArgs e)
    {
        var picker = new ToolFinderWindow { Owner = this };
        if (picker.ShowDialog() == true && picker.Selection is { } tool) ((MainViewModel)DataContext).OpenTool(tool);
    }

    private void OnToggleThemeClick(object sender, RoutedEventArgs e)
    {
        if (Application.Current is App app) app.ToggleTheme();
    }
}
