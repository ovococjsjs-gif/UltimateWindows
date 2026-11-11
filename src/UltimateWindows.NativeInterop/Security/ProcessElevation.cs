using System.ComponentModel;
using System.Diagnostics;

namespace UltimateWindows.NativeInterop.Security;

/// <summary>
/// Итог попытки перезапустить программу с правами администратора.
/// </summary>
public enum ElevationRequestResult
{
    /// <summary>Программа уже работает с правами администратора, перезапуск не нужен.</summary>
    AlreadyElevated = 0,

    /// <summary>Запущен новый экземпляр с правами администратора; текущий экземпляр должен завершиться.</summary>
    RelaunchStarted = 1,

    /// <summary>Пользователь отклонил запрос контроля учётных записей (UAC).</summary>
    DeclinedByUser = 2,

    /// <summary>Перезапуск не удался по другой причине.</summary>
    Failed = 3
}

/// <summary>
/// Перезапуск программы с правами администратора через штатный запрос UAC.
/// Почти все исправления системы (реестр HKLM, службы, драйверы, системные папки) требуют этих прав.
/// Правила, когда просить права, находятся в <see cref="UltimateWindows.Core.Elevation.ElevationStartupPolicy"/>.
/// </summary>
public static class ProcessElevation
{
    private const int ErrorCancelled = 1223;

    public static bool IsRunningAsAdministrator() => ElevationChecker.IsRunningAsAdministrator();

    /// <summary>
    /// Запускает новый экземпляр этой же программы с правами администратора (Windows покажет запрос UAC).
    /// </summary>
    /// <param name="arguments">Аргументы командной строки нового экземпляра.</param>
    /// <param name="errorMessage">Текст ошибки, если результат — <see cref="ElevationRequestResult.Failed"/>.</param>
    public static ElevationRequestResult TryRelaunchElevated(IEnumerable<string> arguments, out string? errorMessage)
    {
        errorMessage = null;

        if (!OperatingSystem.IsWindows())
        {
            errorMessage = "Повышение прав поддерживается только в Windows.";
            return ElevationRequestResult.Failed;
        }

        if (IsRunningAsAdministrator())
        {
            return ElevationRequestResult.AlreadyElevated;
        }

        var executablePath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(executablePath))
        {
            errorMessage = "Не удалось определить путь к исполняемому файлу программы.";
            return ElevationRequestResult.Failed;
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = executablePath,
            UseShellExecute = true,
            Verb = "runas",
            WorkingDirectory = AppContext.BaseDirectory
        };

        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        try
        {
            using var process = Process.Start(startInfo);
            if (process is null)
            {
                errorMessage = "Windows не запустила новый экземпляр программы.";
                return ElevationRequestResult.Failed;
            }

            return ElevationRequestResult.RelaunchStarted;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == ErrorCancelled)
        {
            return ElevationRequestResult.DeclinedByUser;
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException)
        {
            errorMessage = ex.Message;
            return ElevationRequestResult.Failed;
        }
    }
}
