using System.IO;
using System.IO.Compression;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace UltimateWindows.WindowsTests;

/// <summary>
/// Поверхность, на которой проверка показывает представление: настоящее окно за пределами экрана,
/// а если рабочего стола нет — раскладка вручную без окна.
/// </summary>
internal sealed class UiSurface : IDisposable
{
    private const int SnapshotColors = 32;

    private readonly Window? _window;
    private readonly double _width;
    private readonly double _height;

    private UiSurface(FrameworkElement root, Window? window, double width, double height)
    {
        Root = root;
        _window = window;
        _width = width;
        _height = height;
    }

    /// <summary>Корневой элемент: он же попадает на снимок.</summary>
    public FrameworkElement Root { get; }

    /// <summary>Показано ли представление в настоящем окне (иначе — только раскладка без окна).</summary>
    public bool IsRealWindow => _window is not null;

    /// <summary>
    /// Помещает представление в контейнер с фоном и цветом текста главного окна и показывает его.
    /// </summary>
    public static UiSurface Show(FrameworkElement view, double width, double height)
    {
        var host = new Border
        {
            Child = view,
            SnapsToDevicePixels = true,
            UseLayoutRounding = true
        };

        host.SetResourceReference(Border.BackgroundProperty, "AppBackgroundBrush");
        host.SetResourceReference(TextElement.ForegroundProperty, "TextPrimaryBrush");
        TextOptions.SetTextFormattingMode(host, TextFormattingMode.Display);

        return Present(host, hostWindow: null, width, height);
    }

    /// <summary>
    /// Показывает готовое окно программы за пределами экрана.
    /// </summary>
    public static UiSurface Show(Window window, double width, double height) =>
        Present((FrameworkElement)window.Content, window, width, height);

    private static UiSurface Present(FrameworkElement root, Window? hostWindow, double width, double height)
    {
        Window? window = null;
        try
        {
            window = hostWindow ?? new Window { Content = root };
            window.WindowStyle = WindowStyle.None;
            window.ResizeMode = ResizeMode.NoResize;
            window.WindowStartupLocation = WindowStartupLocation.Manual;
            window.SizeToContent = SizeToContent.Manual;
            window.ShowInTaskbar = false;
            window.ShowActivated = false;
            window.Left = -20000;
            window.Top = -20000;
            window.Width = width;
            window.Height = height;
            window.Show();
            window.UpdateLayout();
            return new UiSurface(root, window, width, height);
        }
        catch (Exception) when (hostWindow is null)
        {
            // Окно показать не удалось (например, нет рабочего стола). Раскладываем содержимое вручную:
            // шаблоны и привязки срабатывают так же, а ошибка самой разметки при этом проявится снова.
            if (window is not null)
            {
                window.Content = null;
                try
                {
                    window.Close();
                }
                catch (InvalidOperationException)
                {
                    // Окно так и не открылось
                }
            }

            var surface = new UiSurface(root, window: null, width, height);
            surface.Layout();
            return surface;
        }
    }

    /// <summary>
    /// Даёт интерфейсу довести до конца привязки и раскладку.
    /// </summary>
    public async Task SettleAsync()
    {
        await WpfHost.IdleAsync();
        Layout();
        await WpfHost.IdleAsync();
    }

    private void Layout()
    {
        if (_window is not null)
        {
            _window.UpdateLayout();
            return;
        }

        Root.Measure(new Size(_width, _height));
        Root.Arrange(new Rect(0, 0, _width, _height));
        Root.UpdateLayout();
    }

    /// <summary>
    /// Сколько элементов данного вида построено внутри корня и не скрыто свойством Visibility.
    /// </summary>
    public int CountShown<T>()
        where T : UIElement
    {
        var count = 0;
        var pending = new Stack<DependencyObject>();
        pending.Push(Root);
        while (pending.Count > 0)
        {
            var current = pending.Pop();
            if (current is UIElement { Visibility: not Visibility.Visible })
            {
                continue;
            }

            if (current is T)
            {
                count++;
            }

            for (var i = VisualTreeHelper.GetChildrenCount(current) - 1; i >= 0; i--)
            {
                pending.Push(VisualTreeHelper.GetChild(current, i));
            }
        }

        return count;
    }

    /// <summary>
    /// Сохраняет снимок поверхности, если он запрошен (см. <see cref="TestEnvironment.IsShotRequested"/>).
    /// Сборочная машина не выгружает файлы, поэтому снимок записывается текстом, который помещается
    /// в аннотации запуска: палитра до 32 цветов, сжатые индексы пикселей, 15 бит на знак.
    /// Обратно в PNG его превращает scripts/read-ui-shots.py.
    /// </summary>
    public void Save(string name)
    {
        if (!TestEnvironment.IsShotRequested(name))
        {
            return;
        }

        try
        {
            var width = (int)Math.Ceiling(Root.ActualWidth);
            var height = (int)Math.Ceiling(Root.ActualHeight);
            if (width <= 0 || height <= 0)
            {
                return;
            }

            var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
            bitmap.Render(Root);
            bitmap.Freeze();

            var palette = new BitmapPalette(bitmap, SnapshotColors);
            var indexed = new FormatConvertedBitmap(bitmap, PixelFormats.Indexed8, palette, 0);
            var pixels = new byte[width * height];
            indexed.CopyPixels(pixels, width, 0);

            using var payload = new MemoryStream();
            using (var header = new BinaryWriter(payload, Encoding.ASCII, leaveOpen: true))
            {
                header.Write("UWS1"u8);
                header.Write((ushort)width);
                header.Write((ushort)height);
                header.Write((byte)palette.Colors.Count);
                foreach (var color in palette.Colors)
                {
                    header.Write(color.R);
                    header.Write(color.G);
                    header.Write(color.B);
                }
            }

            using (var brotli = new BrotliStream(payload, CompressionLevel.SmallestSize, leaveOpen: true))
            {
                brotli.Write(pixels, 0, pixels.Length);
            }

            var directory = TestEnvironment.ShotDirectory!;
            Directory.CreateDirectory(directory);
            File.WriteAllText(
                Path.Combine(directory, name + ".txt"),
                CompactText.Encode(payload.ToArray()),
                new UTF8Encoding(false));
        }
        catch (Exception ex)
        {
            // Снимок — вспомогательные сведения: проверку он ронять не должен
            TestEnvironment.WriteReport("ui-shot-error-" + name, [ex.ToString()]);
        }
    }

    public void Dispose()
    {
        try
        {
            _window?.Close();
        }
        catch (InvalidOperationException)
        {
            // Окно уже закрыто
        }
    }
}

/// <summary>
/// Запись байтов текстом по 15 бит на знак. Знаки — иероглифы и слоги хангыля из основной плоскости Юникода:
/// они проходят через аннотации без искажений и вмещают в 2,5 раза больше, чем Base64.
/// </summary>
internal static class CompactText
{
    public static string Encode(byte[] data)
    {
        var text = new StringBuilder(data.Length * 8 / 15 + 16);
        text.Append(data.Length).Append(':');

        var buffer = 0;
        var bits = 0;
        foreach (var value in data)
        {
            buffer = (buffer << 8) | value;
            bits += 8;
            while (bits >= 15)
            {
                bits -= 15;
                text.Append(ToChar((buffer >> bits) & 0x7FFF));
            }

            buffer &= (1 << bits) - 1;
        }

        if (bits > 0)
        {
            text.Append(ToChar((buffer << (15 - bits)) & 0x7FFF));
        }

        return text.ToString();
    }

    private static char ToChar(int value) => value switch
    {
        < 6592 => (char)(0x3400 + value),
        < 27584 => (char)(0x4E00 + (value - 6592)),
        _ => (char)(0xAC00 + (value - 27584))
    };
}
