using System.Collections;
using System.Collections.Specialized;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using UltimateWindows.Core.Models;
using UltimateWindows.Modules.Cleaner.Models;

namespace UltimateWindows.App.Controls;

/// <summary>
/// Аппаратно-ускоренный интерактивный элемент визуализации карты диска Squarified Treemap (в стиле нижней панели WizTree).
/// Отрисовывает пропорциональные блоки каталогов и вложенных подкаталогов с градиентом глубины,
/// подсветкой при наведении, информационной подсказкой и кликом для выбора/углубления.
/// </summary>
public sealed class DiskTreemapControl : FrameworkElement
{
    public static readonly DependencyProperty ItemsSourceProperty =
        DependencyProperty.Register(
            nameof(ItemsSource),
            typeof(IEnumerable),
            typeof(DiskTreemapControl),
            new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender, OnItemsSourceChanged));

    public static readonly DependencyProperty SelectedNodeProperty =
        DependencyProperty.Register(
            nameof(SelectedNode),
            typeof(DiskTreeNode),
            typeof(DiskTreemapControl),
            new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender | FrameworkPropertyMetadataOptions.BindsTwoWayByDefault));

    public static readonly DependencyProperty DrillDownCommandProperty =
        DependencyProperty.Register(
            nameof(DrillDownCommand),
            typeof(ICommand),
            typeof(DiskTreemapControl),
            new PropertyMetadata(null));

    private readonly List<TreemapCell> _hitCells = [];
    private TreemapCell? _hoveredCell;
    private readonly ToolTip _liveToolTip;

    private sealed record TreemapCell(Rect Bounds, DiskTreeNode Node, Color BaseColor, bool IsGroupHeader);

    public DiskTreemapControl()
    {
        ClipToBounds = true;
        Cursor = Cursors.Hand;
        _liveToolTip = new ToolTip { Placement = System.Windows.Controls.Primitives.PlacementMode.Mouse };
        ToolTip = _liveToolTip;
    }

    public IEnumerable? ItemsSource
    {
        get => (IEnumerable?)GetValue(ItemsSourceProperty);
        set => SetValue(ItemsSourceProperty, value);
    }

    public DiskTreeNode? SelectedNode
    {
        get => (DiskTreeNode?)GetValue(SelectedNodeProperty);
        set => SetValue(SelectedNodeProperty, value);
    }

    public ICommand? DrillDownCommand
    {
        get => (ICommand?)GetValue(DrillDownCommandProperty);
        set => SetValue(DrillDownCommandProperty, value);
    }

    private static void OnItemsSourceChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not DiskTreemapControl ctrl) return;
        if (e.OldValue is INotifyCollectionChanged oldIncc)
        {
            oldIncc.CollectionChanged -= ctrl.OnCollectionChanged;
        }

        if (e.NewValue is INotifyCollectionChanged newIncc)
        {
            newIncc.CollectionChanged += ctrl.OnCollectionChanged;
        }

        ctrl.InvalidateVisual();
    }

    private void OnCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e) => InvalidateVisual();

    protected override void OnRender(DrawingContext dc)
    {
        base.OnRender(dc);
        _hitCells.Clear();

        var fullRect = new Rect(0, 0, ActualWidth, ActualHeight);
        if (fullRect.Width < 16 || fullRect.Height < 16)
        {
            return;
        }

        var bgBrush = new SolidColorBrush(Color.FromRgb(14, 17, 24));
        bgBrush.Freeze();
        dc.DrawRectangle(bgBrush, null, fullRect);

        var nodes = ExtractValidNodes();
        if (nodes.Count == 0)
        {
            var emptyText = new FormattedText(
                "Нажмите «Анализ», чтобы построить интерактивную карту блоков диска (Treemap)",
                CultureInfo.CurrentUICulture,
                FlowDirection.LeftToRight,
                new Typeface("Segoe UI"),
                12.5,
                new SolidColorBrush(Color.FromRgb(148, 163, 184)),
                VisualTreeHelper.GetDpi(this).PixelsPerDip);

            dc.DrawText(
                emptyText,
                new Point(
                    Math.Max(12, (fullRect.Width - emptyText.Width) / 2),
                    Math.Max(8, (fullRect.Height - emptyText.Height) / 2)));
            return;
        }

        var dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        var typefaceBold = new Typeface(new FontFamily("Segoe UI"), FontStyles.Normal, FontWeights.SemiBold, FontStretches.Normal);
        var typefaceReg = new Typeface("Segoe UI");

        var topRects = ComputeSquarifiedLayout(nodes, new Rect(2, 2, fullRect.Width - 4, fullRect.Height - 4));

        foreach (var (node, rect) in topRects)
        {
            if (rect.Width < 3 || rect.Height < 3) continue;

            var baseColor = ParseHexColor(node.ColorHex, Color.FromRgb(99, 102, 241));

            // Если блок достаточно большой и имеет подпапки — рисуем заголовок группы и вложенные подуровни (как в WizTree!)
            var validChildren = node.Children.Where(c => c.SizeBytes > 0).OrderByDescending(c => c.SizeBytes).Take(24).ToList();
            if (validChildren.Count > 0 && rect.Width >= 78 && rect.Height >= 48)
            {
                const double headerH = 19.0;
                var groupPen = new Pen(new SolidColorBrush(Color.FromRgb(12, 14, 20)), 1.5);
                groupPen.Freeze();

                var groupFill = CreateCushionBrush(Darken(baseColor, 0.55), Darken(baseColor, 0.78));
                dc.DrawRectangle(groupFill, groupPen, rect);

                DrawClippedLabel(dc, $"{node.Name} ({node.FormattedSize})", new Rect(rect.X + 4, rect.Y + 2, rect.Width - 8, headerH - 2), typefaceBold, 11.0, Colors.White, dpi);
                _hitCells.Add(new TreemapCell(new Rect(rect.X, rect.Y, rect.Width, headerH), node, baseColor, IsGroupHeader: true));

                var innerArea = new Rect(rect.X + 2, rect.Y + headerH, rect.Width - 4, rect.Height - headerH - 2);
                var subRects = ComputeSquarifiedLayout(validChildren, innerArea);

                int subIdx = 0;
                foreach (var (subNode, subRect) in subRects)
                {
                    if (subRect.Width < 2 || subRect.Height < 2) continue;
                    var subTone = VaryColor(baseColor, subIdx++);
                    DrawLeafBlock(dc, subNode, subRect, subTone, typefaceReg, dpi);
                    _hitCells.Add(new TreemapCell(subRect, subNode, subTone, IsGroupHeader: false));
                }
            }
            else
            {
                DrawLeafBlock(dc, node, rect, baseColor, typefaceBold, dpi);
                _hitCells.Add(new TreemapCell(rect, node, baseColor, IsGroupHeader: false));
            }
        }

        // Рамка выделенного или наведенного блока
        var activeNode = _hoveredCell?.Node ?? SelectedNode;
        if (activeNode is not null)
        {
            var match = _hitCells.LastOrDefault(c => ReferenceEquals(c.Node, activeNode));
            if (match is not null)
            {
                var hiPen = new Pen(Brushes.White, 2.0);
                hiPen.Freeze();
                dc.DrawRectangle(null, hiPen, match.Bounds);
            }
        }
    }

    private static void DrawLeafBlock(
        DrawingContext dc,
        DiskTreeNode node,
        Rect rect,
        Color color,
        Typeface typeface,
        double dpi)
    {
        var brush = CreateCushionBrush(Lighten(color, 0.16), Darken(color, 0.38));
        var pen = new Pen(new SolidColorBrush(Color.FromRgb(14, 17, 24)), 1.0);
        pen.Freeze();

        dc.DrawRectangle(brush, pen, rect);

        if (rect.Width >= 46 && rect.Height >= 18)
        {
            var label = rect.Height >= 32
                ? $"{node.Name}\n{node.FormattedSize}"
                : $"{node.Name} ({node.FormattedSize})";
            DrawClippedLabel(dc, label, new Rect(rect.X + 4, rect.Y + 2, rect.Width - 6, rect.Height - 4), typeface, 10.5, Colors.White, dpi);
        }
    }

    private static void DrawClippedLabel(
        DrawingContext dc,
        string text,
        Rect clipBounds,
        Typeface typeface,
        double fontSize,
        Color fg,
        double dpi)
    {
        if (clipBounds.Width < 12 || clipBounds.Height < 11) return;

        dc.PushClip(new RectangleGeometry(clipBounds));
        try
        {
            var fgBrush = new SolidColorBrush(fg);
            fgBrush.Freeze();
            var ft = new FormattedText(
                text,
                CultureInfo.CurrentUICulture,
                FlowDirection.LeftToRight,
                typeface,
                fontSize,
                fgBrush,
                dpi)
            {
                MaxTextWidth = Math.Max(8, clipBounds.Width),
                MaxTextHeight = Math.Max(10, clipBounds.Height),
                Trimming = TextTrimming.CharacterEllipsis
            };
            dc.DrawText(ft, clipBounds.TopLeft);
        }
        finally
        {
            dc.Pop();
        }
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        var pt = e.GetPosition(this);
        var hit = HitTestCell(pt);

        if (!ReferenceEquals(hit, _hoveredCell))
        {
            _hoveredCell = hit;
            if (hit is not null)
            {
                _liveToolTip.Content =
                    $"{hit.Node.Name}\n" +
                    $"Путь: {hit.Node.FullPath}\n" +
                    $"Размер: {hit.Node.FormattedSize} ({hit.Node.ShareLabel} от сканируемого объема)\n" +
                    $"Файлов: {hit.Node.FilesFormatted} • Двойной клик — углубиться в папку";
                _liveToolTip.IsOpen = true;
            }
            else
            {
                _liveToolTip.IsOpen = false;
            }

            InvalidateVisual();
        }
    }

    protected override void OnMouseLeave(MouseEventArgs e)
    {
        base.OnMouseLeave(e);
        _hoveredCell = null;
        _liveToolTip.IsOpen = false;
        InvalidateVisual();
    }

    protected override void OnMouseLeftButtonDown(MouseButtonEventArgs e)
    {
        base.OnMouseLeftButtonDown(e);
        var hit = HitTestCell(e.GetPosition(this));
        if (hit is null) return;

        SelectedNode = hit.Node;
        if (e.ClickCount == 2 && hit.Node.IsDirectory && DrillDownCommand?.CanExecute(hit.Node) == true)
        {
            DrillDownCommand.Execute(hit.Node);
        }
    }

    private TreemapCell? HitTestCell(Point pt)
    {
        for (int i = _hitCells.Count - 1; i >= 0; i--)
        {
            if (_hitCells[i].Bounds.Contains(pt))
            {
                return _hitCells[i];
            }
        }

        return null;
    }

    private List<DiskTreeNode> ExtractValidNodes()
    {
        var list = new List<DiskTreeNode>();
        if (ItemsSource is null) return list;

        foreach (var item in ItemsSource)
        {
            if (item is DiskTreeNode n && n.SizeBytes > 0)
            {
                list.Add(n);
            }
        }

        list.Sort((a, b) => b.SizeBytes.CompareTo(a.SizeBytes));
        return list.Count > 45 ? list.GetRange(0, 45) : list;
    }

    /// <summary>
    /// Классический алгоритм Squarified Treemap (Bruls, Huizing, van Wijk) для близких к квадрату читаемых блоков.
    /// </summary>
    public static List<(DiskTreeNode Node, Rect Bounds)> ComputeSquarifiedLayout(
        IReadOnlyList<DiskTreeNode> items,
        Rect bounds)
    {
        var result = new List<(DiskTreeNode, Rect)>(items.Count);
        if (items.Count == 0 || bounds.Width <= 1 || bounds.Height <= 1)
        {
            return result;
        }

        double totalSize = items.Sum(x => (double)Math.Max(1L, x.SizeBytes));
        double totalArea = bounds.Width * bounds.Height;
        if (totalSize <= 0 || totalArea <= 0)
        {
            return result;
        }

        var scaledAreas = items.Select(x => (Node: x, Area: Math.Max(1L, x.SizeBytes) / totalSize * totalArea)).ToList();
        var currentRow = new List<(DiskTreeNode Node, double Area)>();
        var remaining = bounds;

        foreach (var entry in scaledAreas)
        {
            if (remaining.Width <= 0.5 || remaining.Height <= 0.5) break;

            double shortSide = Math.Min(remaining.Width, remaining.Height);
            if (currentRow.Count == 0 ||
                WorstAspectRatio(currentRow, entry.Area, shortSide) <= WorstAspectRatio(currentRow, null, shortSide))
            {
                currentRow.Add(entry);
            }
            else
            {
                remaining = LayoutRow(currentRow, remaining, result);
                currentRow.Clear();
                currentRow.Add(entry);
            }
        }

        if (currentRow.Count > 0 && remaining.Width > 0.5 && remaining.Height > 0.5)
        {
            _ = LayoutRow(currentRow, remaining, result);
        }

        return result;
    }

    private static double WorstAspectRatio(
        List<(DiskTreeNode Node, double Area)> row,
        double? candidateArea,
        double sideLength)
    {
        if (sideLength <= 0.001) return double.MaxValue;

        double sum = 0;
        double minA = double.MaxValue;
        double maxA = 0;

        foreach (var r in row)
        {
            sum += r.Area;
            if (r.Area < minA) minA = r.Area;
            if (r.Area > maxA) maxA = r.Area;
        }

        if (candidateArea.HasValue)
        {
            var c = candidateArea.Value;
            sum += c;
            if (c < minA) minA = c;
            if (c > maxA) maxA = c;
        }

        if (sum <= 0 || minA <= 0) return double.MaxValue;
        double s2 = sum * sum;
        double w2 = sideLength * sideLength;
        return Math.Max((w2 * maxA) / s2, s2 / (w2 * minA));
    }

    private static Rect LayoutRow(
        List<(DiskTreeNode Node, double Area)> row,
        Rect rect,
        List<(DiskTreeNode, Rect)> output)
    {
        double rowArea = row.Sum(x => x.Area);
        bool horizontalSplit = rect.Width >= rect.Height;

        if (horizontalSplit)
        {
            double stripWidth = Math.Min(rect.Width, rowArea / Math.Max(0.5, rect.Height));
            double y = rect.Y;
            foreach (var (node, area) in row)
            {
                double h = stripWidth > 0.01 ? area / stripWidth : 0;
                h = Math.Min(h, rect.Bottom - y);
                output.Add((node, new Rect(rect.X, y, stripWidth, Math.Max(0, h))));
                y += h;
            }

            return new Rect(rect.X + stripWidth, rect.Y, Math.Max(0, rect.Width - stripWidth), rect.Height);
        }
        else
        {
            double stripHeight = Math.Min(rect.Height, rowArea / Math.Max(0.5, rect.Width));
            double x = rect.X;
            foreach (var (node, area) in row)
            {
                double w = stripHeight > 0.01 ? area / stripHeight : 0;
                w = Math.Min(w, rect.Right - x);
                output.Add((node, new Rect(x, rect.Y, Math.Max(0, w), stripHeight)));
                x += w;
            }

            return new Rect(rect.X, rect.Y + stripHeight, rect.Width, Math.Max(0, rect.Height - stripHeight));
        }
    }

    private static LinearGradientBrush CreateCushionBrush(Color topLeft, Color bottomRight)
    {
        var b = new LinearGradientBrush(topLeft, bottomRight, new Point(0, 0), new Point(1, 1));
        b.Freeze();
        return b;
    }

    private static Color ParseHexColor(string? hex, Color fallback)
    {
        if (string.IsNullOrWhiteSpace(hex)) return fallback;
        try
        {
            if (ColorConverter.ConvertFromString(hex) is Color c) return c;
        }
        catch
        {
            // Ignore
        }

        return fallback;
    }

    private static Color Lighten(Color c, double amount) => Color.FromRgb(
        (byte)Math.Clamp(c.R + (255 - c.R) * amount, 0, 255),
        (byte)Math.Clamp(c.G + (255 - c.G) * amount, 0, 255),
        (byte)Math.Clamp(c.B + (255 - c.B) * amount, 0, 255));

    private static Color Darken(Color c, double amount) => Color.FromRgb(
        (byte)Math.Clamp(c.R * (1.0 - amount), 0, 255),
        (byte)Math.Clamp(c.G * (1.0 - amount), 0, 255),
        (byte)Math.Clamp(c.B * (1.0 - amount), 0, 255));

    private static Color VaryColor(Color c, int index)
    {
        double shift = (index % 4) * 0.08;
        return index % 2 == 0 ? Lighten(c, shift) : Darken(c, shift);
    }
}
