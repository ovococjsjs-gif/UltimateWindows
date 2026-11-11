namespace UltimateWindows.Core.Elevation;

/// <summary>
/// Правила запроса прав администратора при запуске. Здесь только логика без обращений к Windows,
/// чтобы её можно было проверить модульными тестами.
/// </summary>
public static class ElevationStartupPolicy
{
    /// <summary>Ключ командной строки: не запрашивать права администратора при запуске.</summary>
    public const string NoElevateSwitch = "--no-elevate";

    /// <summary>
    /// Служебный ключ: экземпляр уже был перезапущен с запросом прав.
    /// Защищает от бесконечного перезапуска, если права получить не удалось.
    /// </summary>
    public const string ElevatedRelaunchSwitch = "--elevated-relaunch";

    /// <summary>
    /// Нужно ли при запуске просить права администратора.
    /// </summary>
    public static bool ShouldRequestElevationOnStartup(IEnumerable<string> commandLineArguments, bool isAlreadyElevated)
    {
        ArgumentNullException.ThrowIfNull(commandLineArguments);

        if (isAlreadyElevated)
        {
            return false;
        }

        foreach (var argument in commandLineArguments)
        {
            if (IsSwitch(argument, NoElevateSwitch) || IsSwitch(argument, ElevatedRelaunchSwitch))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Готовит аргументы для перезапуска: сохраняет пользовательские, убирает служебные ключи
    /// и добавляет отметку о том, что перезапуск уже был.
    /// </summary>
    public static IReadOnlyList<string> BuildRelaunchArguments(IEnumerable<string> commandLineArguments)
    {
        ArgumentNullException.ThrowIfNull(commandLineArguments);

        var result = new List<string>();
        foreach (var argument in commandLineArguments)
        {
            if (IsSwitch(argument, NoElevateSwitch) || IsSwitch(argument, ElevatedRelaunchSwitch))
            {
                continue;
            }

            result.Add(argument);
        }

        result.Add(ElevatedRelaunchSwitch);
        return result;
    }

    private static bool IsSwitch(string? argument, string expected) =>
        string.Equals(argument?.Trim(), expected, StringComparison.OrdinalIgnoreCase);
}
