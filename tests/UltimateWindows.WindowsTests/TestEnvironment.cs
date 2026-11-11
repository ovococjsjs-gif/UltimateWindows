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
    /// Нужен ли снимок с таким именем. Имена перечислены в переменной UW_UI_SHOTS через «;»;
    /// если она пуста или равна «*», делаются все снимки.
    /// </summary>
    public static bool IsShotRequested(string name)
    {
        if (string.IsNullOrWhiteSpace(ShotDirectory))
        {
            return false;
        }

        var requested = Environment.GetEnvironmentVariable("UW_UI_SHOTS");
        if (string.IsNullOrWhiteSpace(requested) || requested.Trim() == "*")
        {
            return true;
        }

        return requested
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Contains(name, StringComparer.OrdinalIgnoreCase);
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
