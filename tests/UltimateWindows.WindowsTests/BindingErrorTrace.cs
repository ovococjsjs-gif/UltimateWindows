using System.Diagnostics;

namespace UltimateWindows.WindowsTests;

/// <summary>
/// Собирает сообщения WPF об ошибках привязки данных. Опечатка в имени свойства в разметке не мешает сборке
/// и не роняет программу — элемент просто остаётся пустым, — поэтому такие ошибки ловятся здесь.
/// </summary>
internal sealed class BindingErrorTrace : TraceListener, IDisposable
{
    private readonly SourceLevels _previousLevel;

    private BindingErrorTrace()
    {
        PresentationTraceSources.Refresh();
        _previousLevel = PresentationTraceSources.DataBindingSource.Switch.Level;
        PresentationTraceSources.DataBindingSource.Switch.Level = SourceLevels.Warning;
        PresentationTraceSources.DataBindingSource.Listeners.Add(this);
    }

    public List<string> Errors { get; } = [];

    public List<string> Warnings { get; } = [];

    public static BindingErrorTrace Start() => new();

    public override void TraceEvent(TraceEventCache? eventCache, string source, TraceEventType eventType, int id, string? format, params object?[]? args)
    {
        var message = args is { Length: > 0 } && format is not null ? string.Format(format, args) : format ?? "";
        Record(eventType, message);
    }

    public override void TraceEvent(TraceEventCache? eventCache, string source, TraceEventType eventType, int id, string? message) =>
        Record(eventType, message ?? "");

    public override void Write(string? message)
    {
    }

    public override void WriteLine(string? message)
    {
    }

    private void Record(TraceEventType eventType, string message)
    {
        var text = message.ReplaceLineEndings(" ");

        // Известный шум WPF: элемент списка, уже убранный из дерева, ещё раз ищет своего предка.
        // На работу интерфейса это не влияет.
        var isContainerNoise = text.Contains("FindAncestor", StringComparison.Ordinal) &&
                               text.Contains("ContentAlignment", StringComparison.Ordinal);

        if (eventType is TraceEventType.Error or TraceEventType.Critical && !isContainerNoise)
        {
            Errors.Add(text);
        }
        else if (eventType is TraceEventType.Warning or TraceEventType.Error or TraceEventType.Critical)
        {
            Warnings.Add(text);
        }
    }

    void IDisposable.Dispose()
    {
        PresentationTraceSources.DataBindingSource.Listeners.Remove(this);
        PresentationTraceSources.DataBindingSource.Switch.Level = _previousLevel;
    }
}
