using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using UltimateWindows.App.ViewModels;

namespace UltimateWindows.App.Views;

public partial class ToolFinderWindow : Window
{
    public ToolDestination? Selection => Results.SelectedItem as ToolDestination;
    public ToolFinderWindow()
    {
        InitializeComponent();
        Loaded += (_, _) => QueryBox.Focus();
        ((System.Collections.Specialized.INotifyCollectionChanged)Results.Items).CollectionChanged += (_, _) =>
        {
            if (Results.HasItems) Results.SelectedIndex = 0;
        };
    }
    private void OnKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key is not (Key.Down or Key.Up) || !Results.HasItems || !QueryBox.IsKeyboardFocusWithin) return;
        Results.SelectedIndex = Math.Clamp(Results.SelectedIndex + (e.Key == Key.Down ? 1 : -1), 0, Results.Items.Count - 1);
        Results.ScrollIntoView(Results.SelectedItem);
        e.Handled = true;
    }
    private void OpenSelection(object sender, RoutedEventArgs e) { if (Selection is not null) DialogResult = true; }
    private void OnResultDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (e.OriginalSource is DependencyObject hit && ItemsControl.ContainerFromElement(Results, hit) is ListBoxItem) OpenSelection(sender, e);
    }
}
