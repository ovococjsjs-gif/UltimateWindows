using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml.Linq;
using UltimateWindows.Modules.Repair.Models;
using UltimateWindows.Modules.Repair.Services;
using UltimateWindows.NativeInterop.Security;

namespace UltimateWindows.NativeInterop.Repair;

/// <summary>
/// Полноценный нативный мост Фазы 3 для Windows 10/11:
/// чтение журналов сбоев через Win32 EvtQuery (wevtapi.dll), проверка подписи Authenticode (WinVerifyTrust),
/// тихая установка официальных пакетов через winget и безопасное выполнение рецептов восстановления ОС.
/// </summary>
public sealed class WindowsRepairPlatformBridge : DefaultRepairPlatformBridge
{
    public override string GetSystem64Directory()
    {
        var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (!string.IsNullOrWhiteSpace(winDir))
        {
            // Если процесс вдруг запущен под WOW64, Sysnative ведет в настоящий 64-битный System32
            if (Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess)
            {
                return Path.Combine(winDir, "Sysnative");
            }

            return Path.Combine(winDir, "System32");
        }

        return base.GetSystem64Directory();
    }

    public override string GetSysWow64Directory()
    {
        var sysX86 = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);
        return !string.IsNullOrWhiteSpace(sysX86) ? sysX86 : base.GetSysWow64Directory();
    }

    public override bool IsRunningAsAdministrator() => ElevationChecker.IsRunningAsAdministrator();

    public override bool VerifyAuthenticodeSignature(string filePath) =>
        AuthenticodeVerifier.IsFileTrustedSigned(filePath);

    public override Task<IReadOnlyList<SystemCrashEventEntry>> ReadRecentCrashEventsAsync(
        int maxEntries = 20,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult<IReadOnlyList<SystemCrashEventEntry>>(Array.Empty<SystemCrashEventEntry>());
        }

        return Task.Run<IReadOnlyList<SystemCrashEventEntry>>(() =>
        {
            var items = new List<SystemCrashEventEntry>();
            var half = Math.Max(4, maxEntries / 2);

            // 1. Журнал Application: падения программ (Event ID 1000) и ошибки манифестов VC++ SideBySide (33, 59)
            QueryChannelEvents(
                channelPath: "Application",
                xpathQuery: "*[System[(EventID=1000 or EventID=33 or EventID=59)]]",
                maxCount: half,
                sink: items,
                ct: ct);

            // 2. Журнал System: сброс видеодрайвера TDR (4101), внезапное выключение Kernel-Power (41), BSOD BugCheck (1001), WHEA (17, 18, 19)
            QueryChannelEvents(
                channelPath: "System",
                xpathQuery: "*[System[(EventID=41 or EventID=1001 or EventID=4101 or EventID=18 or EventID=19)]]",
                maxCount: half,
                sink: items,
                ct: ct);

            return items
                .OrderByDescending(e => e.TimestampUtc)
                .Take(maxEntries)
                .ToList();
        }, ct);
    }

    public override async Task<(bool Succeeded, string OutputLog)> InstallOfficialRuntimeViaWingetAsync(
        OfficialRuntimePackage package,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return (false, "Установка через winget поддерживается только в Windows.");
        }

        var args = new[]
        {
            "install",
            "--exact",
            "--id", package.WingetPackageId,
            "--silent",
            "--accept-package-agreements",
            "--accept-source-agreements"
        };

        var (exitCode, output) = await RunProcessCaptureAsync("winget.exe", args, TimeSpan.FromMinutes(10), ct).ConfigureAwait(false);
        return (exitCode == 0, output);
    }

    public override async Task<(bool Succeeded, string OutputLog)> ExecutePlaybookNativeStepsAsync(
        RepairPlaybookId playbookId,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return (false, "Нативный ремонт ОС поддерживается только на Windows 10/11.");
        }

        var log = new StringBuilder();

        switch (playbookId)
        {
            case RepairPlaybookId.DismAndSfcIntegrity:
            {
                var (dismCode, dismOut) = await RunProcessCaptureAsync(
                    "DISM.exe",
                    ["/Online", "/Cleanup-Image", "/RestoreHealth"],
                    TimeSpan.FromMinutes(25),
                    ct).ConfigureAwait(false);
                log.AppendLine("[DISM /RestoreHealth]").AppendLine(dismOut);

                var (sfcCode, sfcOut) = await RunProcessCaptureAsync(
                    "sfc.exe",
                    ["/scannow"],
                    TimeSpan.FromMinutes(20),
                    ct).ConfigureAwait(false);
                log.AppendLine("[SFC /scannow]").AppendLine(sfcOut);

                return (dismCode == 0 && sfcCode == 0, log.ToString());
            }

            case RepairPlaybookId.NetworkAndDnsStackReset:
            {
                var (_, flushOut) = await RunProcessCaptureAsync("ipconfig.exe", ["/flushdns"], TimeSpan.FromSeconds(30), ct).ConfigureAwait(false);
                log.AppendLine(flushOut);
                var (_, regOut) = await RunProcessCaptureAsync("ipconfig.exe", ["/registerdns"], TimeSpan.FromSeconds(45), ct).ConfigureAwait(false);
                log.AppendLine(regOut);
                var (wsCode, wsOut) = await RunProcessCaptureAsync("netsh.exe", ["winsock", "reset"], TimeSpan.FromSeconds(45), ct).ConfigureAwait(false);
                log.AppendLine(wsOut);
                return (wsCode == 0, log.ToString());
            }

            case RepairPlaybookId.IconAndThumbnailCacheRebuild:
            {
                var explorerCacheDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Microsoft", "Windows", "Explorer");

                var deleted = 0;
                var skipped = 0;
                if (Directory.Exists(explorerCacheDir))
                {
                    foreach (var pattern in new[] { "iconcache_*.db", "thumbcache_*.db" })
                    {
                        foreach (var file in Directory.EnumerateFiles(explorerCacheDir, pattern))
                        {
                            try
                            {
                                File.Delete(file);
                                deleted++;
                            }
                            catch
                            {
                                skipped++;
                            }
                        }
                    }
                }

                _ = await RunProcessCaptureAsync("ie4uinit.exe", ["-show"], TimeSpan.FromSeconds(20), ct).ConfigureAwait(false);
                log.AppendLine($"Очищено кэш-баз иконок/эскизов: {deleted} (занято Проводником и обновится при входе: {skipped}).");
                return (true, log.ToString());
            }

            case RepairPlaybookId.WindowsUpdateReset:
            {
                foreach (var svc in new[] { "bits", "wuauserv" })
                {
                    var (_, sOut) = await RunProcessCaptureAsync("net.exe", ["stop", svc], TimeSpan.FromSeconds(45), ct).ConfigureAwait(false);
                    log.AppendLine(sOut);
                }

                foreach (var svc in new[] { "cryptSvc", "bits", "wuauserv" })
                {
                    var (_, sOut) = await RunProcessCaptureAsync("net.exe", ["start", svc], TimeSpan.FromSeconds(45), ct).ConfigureAwait(false);
                    log.AppendLine(sOut);
                }

                return (true, log.ToString());
            }

            case RepairPlaybookId.MicrosoftStoreAndAppxRepair:
            {
                var (code, outText) = await RunProcessCaptureAsync("wsreset.exe", ["-i"], TimeSpan.FromMinutes(2), ct).ConfigureAwait(false);
                log.AppendLine("Выполнен тихий сброс кэша Microsoft Store (wsreset -i).").AppendLine(outText);
                return (code == 0, log.ToString());
            }

            case RepairPlaybookId.PrintSpoolerCleanup:
            {
                var (_, stopOut) = await RunProcessCaptureAsync("net.exe", ["stop", "spooler"], TimeSpan.FromSeconds(45), ct).ConfigureAwait(false);
                log.AppendLine(stopOut);

                var spoolDir = Path.Combine(GetSystem64Directory(), "spool", "PRINTERS");
                var clearedJobs = 0;
                if (Directory.Exists(spoolDir))
                {
                    foreach (var jobFile in Directory.EnumerateFiles(spoolDir))
                    {
                        try
                        {
                            File.Delete(jobFile);
                            clearedJobs++;
                        }
                        catch
                        {
                            // Пропускаем защищенный файл
                        }
                    }
                }

                var (startCode, startOut) = await RunProcessCaptureAsync("net.exe", ["start", "spooler"], TimeSpan.FromSeconds(45), ct).ConfigureAwait(false);
                log.AppendLine($"Удалено зависших заданий печати: {clearedJobs}.").AppendLine(startOut);
                return (startCode == 0, log.ToString());
            }

            case RepairPlaybookId.WmiRepositoryVerifyAndSalvage:
            {
                var (vCode, vOut) = await RunProcessCaptureAsync("winmgmt.exe", ["/verifyrepository"], TimeSpan.FromMinutes(2), ct).ConfigureAwait(false);
                log.AppendLine("[winmgmt /verifyrepository]").AppendLine(vOut);

                // Если репозиторий требует сверки, выполняем только мягкий /salvagerepository (никогда не разрушительный /resetrepository!)
                if (vCode != 0)
                {
                    var (sCode, sOut) = await RunProcessCaptureAsync("winmgmt.exe", ["/salvagerepository"], TimeSpan.FromMinutes(3), ct).ConfigureAwait(false);
                    log.AppendLine("[winmgmt /salvagerepository]").AppendLine(sOut);
                    return (sCode == 0, log.ToString());
                }

                return (true, log.ToString());
            }

            default:
                return (false, $"Неизвестный идентификатор рецепта: {playbookId}");
        }
    }

    private static async Task<(int ExitCode, string Output)> RunProcessCaptureAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        foreach (var arg in arguments)
        {
            psi.ArgumentList.Add(arg);
        }

        try
        {
            using var proc = Process.Start(psi);
            if (proc is null)
            {
                return (-1, $"Не удалось запустить системный процесс '{fileName}'.");
            }

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(timeout);

            var stdOutTask = proc.StandardOutput.ReadToEndAsync(timeoutCts.Token);
            var stdErrTask = proc.StandardError.ReadToEndAsync(timeoutCts.Token);

            await proc.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);
            var stdOut = await stdOutTask.ConfigureAwait(false);
            var stdErr = await stdErrTask.ConfigureAwait(false);

            var combined = string.IsNullOrWhiteSpace(stdErr) ? stdOut.Trim() : $"{stdOut}\n{stdErr}".Trim();
            return (proc.ExitCode, combined);
        }
        catch (OperationCanceledException)
        {
            return (-2, $"Операция '{fileName}' прервана по таймауту или запросу пользователя.");
        }
        catch (Exception ex)
        {
            return (-3, $"Ошибка вызова '{fileName}': {ex.Message}");
        }
    }

    private static void QueryChannelEvents(
        string channelPath,
        string xpathQuery,
        int maxCount,
        List<SystemCrashEventEntry> sink,
        CancellationToken ct)
    {
        var hQuery = EvtQuery(IntPtr.Zero, channelPath, xpathQuery, EVT_QUERY_CHANNEL_PATH | EVT_QUERY_REVERSE_DIRECTION);
        if (hQuery == IntPtr.Zero)
        {
            return;
        }

        try
        {
            var handles = new IntPtr[Math.Clamp(maxCount, 1, 32)];
            if (!EvtNext(hQuery, handles.Length, handles, 2000, 0, out var returned) || returned <= 0)
            {
                return;
            }

            for (int i = 0; i < returned; i++)
            {
                ct.ThrowIfCancellationRequested();
                var hEvent = handles[i];
                if (hEvent == IntPtr.Zero) continue;

                try
                {
                    var xml = RenderEventXml(hEvent);
                    if (!string.IsNullOrWhiteSpace(xml) && TryParseCrashEventXml(xml, out var entry))
                    {
                        sink.Add(entry);
                    }
                }
                finally
                {
                    _ = EvtClose(hEvent);
                }
            }
        }
        finally
        {
            _ = EvtClose(hQuery);
        }
    }

    private static string? RenderEventXml(IntPtr hEvent)
    {
        _ = EvtRender(IntPtr.Zero, hEvent, EVT_RENDER_EVENT_XML, 0, IntPtr.Zero, out var bufferUsed, out _);
        if (bufferUsed <= 0 || bufferUsed > 256 * 1024)
        {
            return null;
        }

        var buffer = Marshal.AllocHGlobal(bufferUsed);
        try
        {
            if (!EvtRender(IntPtr.Zero, hEvent, EVT_RENDER_EVENT_XML, bufferUsed, buffer, out _, out _))
            {
                return null;
            }

            return Marshal.PtrToStringUni(buffer);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static bool TryParseCrashEventXml(string xml, out SystemCrashEventEntry entry)
    {
        entry = null!;
        try
        {
            var doc = XDocument.Parse(xml);
            XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
            var sys = doc.Root?.Element(ns + "System");
            if (sys is null) return false;

            var provider = sys.Element(ns + "Provider")?.Attribute("Name")?.Value ?? "Windows";
            var eventIdStr = sys.Element(ns + "EventID")?.Value ?? "0";
            _ = int.TryParse(eventIdStr, NumberStyles.Integer, CultureInfo.InvariantCulture, out var eventId);

            var timeStr = sys.Element(ns + "TimeCreated")?.Attribute("SystemTime")?.Value;
            var timestamp = DateTimeOffset.TryParse(timeStr, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var ts)
                ? ts
                : DateTimeOffset.UtcNow;

            var dataItems = doc.Root?.Element(ns + "EventData")?.Elements(ns + "Data")
                .Select(d => d.Value?.Trim() ?? "")
                .Where(v => !string.IsNullOrEmpty(v))
                .ToArray() ?? [];

            var joinedData = string.Join(" | ", dataItems);

            var (kind, summary) = ClassifyCrashEvent(eventId, provider, dataItems);
            entry = new SystemCrashEventEntry(
                Kind: kind,
                TimestampUtc: timestamp,
                EventId: eventId,
                SourceProvider: provider,
                SimpleSummary: summary,
                TechnicalRawDetails: string.IsNullOrWhiteSpace(joinedData) ? provider : joinedData);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static (SystemCrashEventKind Kind, string Summary) ClassifyCrashEvent(
        int eventId,
        string provider,
        string[] dataItems)
    {
        if (eventId == 1000)
        {
            var appName = dataItems.Length > 0 ? dataItems[0] : "Приложение";
            var faultMod = dataItems.Length > 3 ? dataItems[3] : "неизвестный модуль";
            return (
                SystemCrashEventKind.ApplicationCrash1000,
                $"Сбой программы «{appName}» в модуле «{faultMod}». Вы можете проверить .exe этой программы в Докторе зависимостей выше.");
        }

        if (eventId is 33 or 59)
        {
            return (
                SystemCrashEventKind.SideBySideManifestError,
                "Ошибка сборки SideBySide: программе не хватает официального пакета Microsoft Visual C++ Redistributable.");
        }

        if (eventId == 4101)
        {
            return (
                SystemCrashEventKind.GpuTdrReset4101,
                "Видеодрайвер перестал отвечать и был перезапущен Windows (TDR 4101). Проверьте перегрев GPU и стабильность видеодрайвера.");
        }

        if (eventId == 41)
        {
            return (
                SystemCrashEventKind.UnexpectedKernelPower41,
                "Внезапная перезагрузка или отключение питания ПК без штатного завершения работы (Kernel-Power 41).");
        }

        if (eventId == 1001)
        {
            return (
                SystemCrashEventKind.BsodBugCheck1001,
                "Система была перезагружена после критической ошибки синего экрана (BugCheck 1001).");
        }

        return (
            SystemCrashEventKind.HardwareWheaError,
            $"Аппаратное предупреждение подсистемы {provider} (WHEA): проверьте стабильность процессора, памяти или шины PCIe.");
    }

    // ==================== WIN32 WEVTAPI P/INVOKE ====================
    private const int EVT_QUERY_CHANNEL_PATH = 0x1;
    private const int EVT_QUERY_REVERSE_DIRECTION = 0x200;
    private const int EVT_RENDER_EVENT_XML = 1;

    [DllImport("wevtapi.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr EvtQuery(IntPtr session, string path, string query, int flags);

    [DllImport("wevtapi.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EvtNext(
        IntPtr resultSet,
        int eventArraySize,
        [Out] IntPtr[] eventArray,
        int timeout,
        int flags,
        out int returned);

    [DllImport("wevtapi.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EvtRender(
        IntPtr context,
        IntPtr fragment,
        int flags,
        int bufferSize,
        IntPtr buffer,
        out int bufferUsed,
        out int propertyCount);

    [DllImport("wevtapi.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EvtClose(IntPtr handle);
}
