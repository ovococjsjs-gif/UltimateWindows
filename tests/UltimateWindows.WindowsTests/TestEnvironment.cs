using System.IO;
using System.Text;

namespace UltimateWindows.WindowsTests;

/// <summary>
/// Где выполняются проверки и куда складывать их отчёты.
/// </summary>
internal static class TestEnvironment
{
    /// <summary>
    /// Проверки, которые меняют настоящую систему (тип запуска службы, задание планировщика, реестр),
    /// выполняются только на одноразовой сборочной машине GitHub Actions. На компьютере разработчика
    /// или пользователя они ничего не делают.
    /// </summary>
    public static bool IsDisposableBuildMachine =>
        string.Equals(Environment.GetEnvironmentVariable("GITHUB_ACTIONS"), "true", StringComparison.OrdinalIgnoreCase);

    private static string? ReportDirectory => Environment.GetEnvironmentVariable("UW_TEST_REPORT_DIR");

    /// <summary>Каталог снимков интерфейса (переменная UW_UI_SHOT_DIR). Не задан — снимки не делаются.</summary>
    public static string? ShotDirectory => Environment.GetEnvironmentVariable("UW_UI_SHOT_DIR");

    /// <summary>
    /// Нужен ли снимок с таким именем и в каком качестве. Имена перечислены в переменной UW_UI_SHOTS через «;».
    /// Имя со знаком «+» в конце — снимок со сглаженным текстом и большей палитрой (он в несколько раз крупнее).
    /// Если переменная пуста или равна «*», делаются все снимки в компактном виде.
    /// </summary>
    public static SnapshotQuality? GetShotRequest(string name)
    {
        if (string.IsNullOrWhiteSpace(ShotDirectory))
        {
            return null;
        }

        var requested = Environment.GetEnvironmentVariable("UW_UI_SHOTS");
        if (string.IsNullOrWhiteSpace(requested) || requested.Trim() == "*")
        {
            return SnapshotQuality.Compact;
        }

        foreach (var entry in requested.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (string.Equals(entry.TrimEnd('+'), name, StringComparison.OrdinalIgnoreCase))
            {
                return entry.EndsWith('+') ? SnapshotQuality.Fine : SnapshotQuality.Compact;
            }
        }

        return null;
    }

    /// <summary>
    /// Текстовый отчёт проверки. Сборочный сценарий показывает такие отчёты в итогах запуска.
    /// Если каталог отчётов не задан, отчёт никуда не пишется.
    /// </summary>
    public static void WriteReport(string name, IEnumerable<string> lines)
    {
        var directory = ReportDirectory;
        if (string.IsNullOrWhiteSpace(directory))
        {
            return;
        }

        try
        {
            Directory.CreateDirectory(directory);
            File.WriteAllLines(Path.Combine(directory, name + ".txt"), lines, new UTF8Encoding(false));
        }
        catch (Exception)
        {
            // Отчёт — вспомогательные сведения; его отсутствие не должно ронять проверку
        }
    }
}

/// <summary>Качество снимка интерфейса.</summary>
internal enum SnapshotQuality
{
    /// <summary>Текст без сглаживания, 32 цвета: по снимку видно раскладку, цвета и надписи.</summary>
    Compact,

    /// <summary>Сглаженный текст, 64 цвета: снимок близок к тому, что видит пользователь.</summary>
    Fine
}
