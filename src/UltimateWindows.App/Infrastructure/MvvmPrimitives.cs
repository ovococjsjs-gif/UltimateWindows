using System.ComponentModel;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;

namespace UltimateWindows.App.Infrastructure;

public abstract class ObservableObject : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

    protected bool SetProperty<T>(ref T storage, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(storage, value))
        {
            return false;
        }

        storage = value;
        OnPropertyChanged(propertyName);
        return true;
    }
}

public sealed class RelayCommand : ICommand
{
    private readonly Action<object?> _execute;
    private readonly Predicate<object?>? _canExecute;

    public RelayCommand(Action<object?> execute, Predicate<object?>? canExecute = null)
    {
        _execute = execute ?? throw new ArgumentNullException(nameof(execute));
        _canExecute = canExecute;
    }

    public event EventHandler? CanExecuteChanged;

    public bool CanExecute(object? parameter) => _canExecute?.Invoke(parameter) ?? true;

    public void Execute(object? parameter) => _execute(parameter);

    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}

public sealed class AsyncRelayCommand : ICommand
{
    private readonly Func<object?, Task> _executeAsync;
    private readonly Predicate<object?>? _canExecute;
    private bool _isRunning;

    public AsyncRelayCommand(Func<object?, Task> executeAsync, Predicate<object?>? canExecute = null)
    {
        _executeAsync = executeAsync ?? throw new ArgumentNullException(nameof(executeAsync));
        _canExecute = canExecute;
    }

    public event EventHandler? CanExecuteChanged;

    public bool CanExecute(object? parameter) => !_isRunning && (_canExecute?.Invoke(parameter) ?? true);

    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);

    /// <summary>
    /// Куда сообщать об ошибке, которую команда не обработала сама. Без этого необработанное исключение
    /// в асинхронной команде закрыло бы программу.
    /// </summary>
    public static Action<Exception>? UnhandledError { get; set; }

    public async void Execute(object? parameter)
    {
        if (!CanExecute(parameter))
        {
            return;
        }

        try
        {
            _isRunning = true;
            CanExecuteChanged?.Invoke(this, EventArgs.Empty);
            await _executeAsync(parameter);
        }
        catch (OperationCanceledException)
        {
            // Отмена — штатное завершение
        }
        catch (Exception ex)
        {
            var handler = UnhandledError;
            if (handler is null)
            {
                throw;
            }

            handler(ex);
        }
        finally
        {
            _isRunning = false;
            CanExecuteChanged?.Invoke(this, EventArgs.Empty);
        }
    }
}

/// <summary>
/// Вопрос пользователю с ответом «да / нет».
/// </summary>
public sealed record ConfirmationRequest(string Title, string Message, bool IsWarning = false);

/// <summary>
/// Диалоги программы. Модели представления обращаются к пользователю через эти функции,
/// поэтому в автоматических проверках интерфейса диалоги можно подменить.
/// </summary>
public static class UserPrompts
{
    public static Func<ConfirmationRequest, bool> Confirm { get; set; } = ShowConfirmation;

    private static bool ShowConfirmation(ConfirmationRequest request)
    {
        var answer = MessageBox.Show(
            request.Message,
            request.Title,
            MessageBoxButton.YesNo,
            request.IsWarning ? MessageBoxImage.Warning : MessageBoxImage.Question,
            MessageBoxResult.No);

        return answer == MessageBoxResult.Yes;
    }
}

public sealed class BoolToVisibilityConverterEx : IValueConverter
{
    public bool Invert { get; set; }

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var flag = value is true;
        if (Invert)
        {
            flag = !flag;
        }

        return flag ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is Visibility.Visible != Invert;
}

public sealed class PercentToBarWidthConverter : IValueConverter
{
    public double MaxPixels { get; set; } = 92.0;

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        double maxPx = MaxPixels;
        if (parameter is string s && double.TryParse(s, NumberStyles.Any, CultureInfo.InvariantCulture, out var custom))
        {
            maxPx = custom;
        }

        double pct = value switch
        {
            double d => d,
            float f => f,
            int i => i,
            _ => 0.0
        };

        pct = Math.Clamp(pct, 0.0, 100.0);
        return Math.Max(pct > 0.1 ? 2.5 : 0.0, pct / 100.0 * maxPx);
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => Binding.DoNothing;
}

public sealed class HexToSolidBrushConverter : IValueConverter
{
    private static readonly Dictionary<string, SolidColorBrush> Cache = new(StringComparer.OrdinalIgnoreCase);

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var hex = value as string;
        if (string.IsNullOrWhiteSpace(hex))
        {
            return Brushes.SlateBlue;
        }

        if (Cache.TryGetValue(hex, out var cached))
        {
            return cached;
        }

        try
        {
            if (ColorConverter.ConvertFromString(hex) is Color c)
            {
                var brush = new SolidColorBrush(c);
                brush.Freeze();
                Cache[hex] = brush;
                return brush;
            }
        }
        catch
        {
            // Ignore
        }

        return Brushes.SlateBlue;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => Binding.DoNothing;
}

public sealed class IntEqualsConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is int current && parameter is string s && int.TryParse(s, out var target))
        {
            return current == target;
        }

        return false;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is true && parameter is string s && int.TryParse(s, out var target))
        {
            return target;
        }

        return Binding.DoNothing;
    }
}
