using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using UltimateWindows.App.ViewModels;
using UltimateWindows.Modules.Cleaner.Models;

namespace UltimateWindows.App.Views;

public partial class DiskAndCleanerWorkspaceView : UserControl
{
    public DiskAndCleanerWorkspaceView()
    {
        InitializeComponent();
    }

    private void OnTreeSelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
    {
        if (DataContext is CleanerStudioViewModel vm && e.NewValue is DiskTreeNode node)
        {
            vm.SelectedTreeNode = node;
        }
    }

    private void OnTreeMouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (DataContext is CleanerStudioViewModel vm
            && vm.SelectedTreeNode is { IsDirectory: true } dir
            && vm.DrillDownNodeCommand.CanExecute(dir))
        {
            vm.DrillDownNodeCommand.Execute(dir);
            e.Handled = true;
        }
    }
}
