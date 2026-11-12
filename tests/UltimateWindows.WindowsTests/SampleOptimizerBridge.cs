using System.IO;
using UltimateWindows.Modules.Optimizer.Models;
using UltimateWindows.Modules.Optimizer.Services;

namespace UltimateWindows.WindowsTests;

/// <summary>
/// Мост Оптимизатора с придуманным, но правдоподобным компьютером: Windows 11 24H2 на SSD, набор служб,
/// заданий, программ и приложений. Всё состояние хранится в памяти, настоящая система не затрагивается.
/// </summary>
internal sealed class SampleOptimizerBridge : DefaultOptimizerPlatformBridge
{
    private readonly string _hostsPath;
    private readonly Dictionary<string, (int Kind, string Val)> _values = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _keys = new(StringComparer.OrdinalIgnoreCase)
    {
        @"HKCU\Software",
        @"HKCU\Software\Classes",
        @"HKCU\Software\Classes\CLSID",
        @"HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe",
        @"HKLM\SOFTWARE\Microsoft\Office\ClickToRun\Configuration",
        @"HKLM\SOFTWARE\NVIDIA Corporation\Global"
    };

    private readonly List<WindowsServiceInfo> _services =
    [
        SampleService("DiagTrack", "Функциональные возможности для подключённых пользователей и телеметрия", ServiceStartupMode.Automatic, true, "Собирает и отправляет диагностические данные."),
        SampleService("dmwappushservice", "Служба маршрутизации push-сообщений WAP", ServiceStartupMode.Manual, false, "Маршрутизирует push-сообщения протокола WAP."),
        SampleService("MapsBroker", "Диспетчер скачанных карт", ServiceStartupMode.AutomaticDelayed, false, "Доступ приложений к скачанным картам."),
        SampleService("Fax", "Факс", ServiceStartupMode.Manual, false, "Отправка и получение факсов."),
        SampleService("Spooler", "Диспетчер печати", ServiceStartupMode.Automatic, true, "Ставит задания печати в очередь."),
        SampleService("SysMain", "SysMain", ServiceStartupMode.Automatic, true, "Поддерживает и улучшает производительность системы."),
        SampleService("WSearch", "Windows Search", ServiceStartupMode.AutomaticDelayed, true, "Индексирование содержимого и кэширование свойств."),
        SampleService("XblAuthManager", "Диспетчер проверки подлинности Xbox Live", ServiceStartupMode.Manual, false, "Проверка подлинности в Xbox Live."),
        SampleService("RpcSs", "Удалённый вызов процедур (RPC)", ServiceStartupMode.Automatic, true, "Диспетчер служб COM и DCOM."),
        SampleService("WinDefend", "Антивирусная программа Microsoft Defender", ServiceStartupMode.Automatic, true, "Защита от вредоносных программ."),
        SampleService("wuauserv", "Центр обновления Windows", ServiceStartupMode.Manual, false, "Обнаружение, скачивание и установка обновлений."),
        SampleService("Schedule", "Планировщик заданий", ServiceStartupMode.Automatic, true, "Запуск заданий по расписанию."),
        SampleService("AdobeARMservice", "Adobe Acrobat Update Service", ServiceStartupMode.Automatic, true, "Keeps Adobe software up to date.", "Adobe Inc.", @"C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\armsvc.exe"),
        SampleService("Steam Client Service", "Steam Client Service", ServiceStartupMode.Manual, false, "Steam Client Service monitors and updates Steam content.", "Valve Corporation", @"C:\Program Files (x86)\Common Files\Steam\steamservice.exe"),
        SampleService("NvContainerLocalSystem", "NVIDIA LocalSystem Container", ServiceStartupMode.Automatic, true, "Container service for NVIDIA root features.", "NVIDIA Corporation", @"C:\Program Files\NVIDIA Corporation\NvContainer\nvcontainer.exe"),
        SampleService("YandexBrowserService", "Yandex.Browser Update Service", ServiceStartupMode.Disabled, false, "", "YANDEX LLC", @"C:\Program Files (x86)\Yandex\YandexBrowser\service_update.exe")
    ];

    private readonly List<ScheduledTaskInfo> _tasks =
    [
        SampleTask(@"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser", true, false, @"%windir%\system32\compattelrunner.exe"),
        SampleTask(@"\Microsoft\Windows\Application Experience\ProgramDataUpdater", true, false, @"%windir%\system32\compattelrunner.exe -maintenance"),
        SampleTask(@"\Microsoft\Windows\Customer Experience Improvement Program\Consolidator", true, false, @"%SystemRoot%\System32\wsqmcons.exe"),
        SampleTask(@"\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip", false, false, "обработчик Windows (COM)"),
        SampleTask(@"\Microsoft\Windows\Maps\MapsUpdateTask", true, false, "обработчик Windows (COM)"),
        SampleTask(@"\Microsoft\Windows\Maintenance\WinSAT", true, false, "обработчик Windows (COM)"),
        SampleTask(@"\Microsoft\Windows\Defrag\ScheduledDefrag", true, true, @"%windir%\system32\defrag.exe -c -h -o -$"),
        SampleTask(@"\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan", true, false, @"C:\ProgramData\Microsoft\Windows Defender\Platform\MpCmdRun.exe Scan -ScheduleJob"),
        SampleTask(@"\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask", true, false, "обработчик Windows (COM)"),
        SampleTask(@"\GoogleUpdaterTaskSystem140.0.7273.0{9B5B0A31-2B63-4B8A-9A0C-2C7E5F3B6A11}", true, false, @"C:\Program Files (x86)\Google\GoogleUpdater\140.0.7273.0\updater.exe --wake --system", "Google LLC"),
        SampleTask(@"\Adobe Acrobat Update Task", true, false, @"C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\AdobeARM.exe", "Adobe Systems Incorporated"),
        SampleTask(@"\NvTmRep_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}", true, false, @"C:\Program Files\NVIDIA Corporation\NvBackend\NvTmRep.exe", "NVIDIA Corporation")
    ];

    public SampleOptimizerBridge(string workDirectory)
    {
        _hostsPath = Path.Combine(workDirectory, "hosts");
        File.WriteAllText(
            _hostsPath,
            "# Образец файла hosts\r\n127.0.0.1 localhost\r\n0.0.0.0 ads.tracker-example.net\r\n0.0.0.0 telemetry.vendor-example.com\r\n127.0.0.1 www.virustotal.com\r\n");
    }

    public IReadOnlyDictionary<string, (int Kind, string Val)> Values => _values;

    public ServiceStartupMode StartupOf(string serviceName) =>
        _services.Single(s => s.ServiceName.Equals(serviceName, StringComparison.OrdinalIgnoreCase)).Startup;

    public bool TaskEnabled(string taskPath) =>
        _tasks.Single(t => t.TaskPath.Equals(taskPath, StringComparison.OrdinalIgnoreCase)).Enabled;

    public override bool IsRunningAsAdministrator() => true;

    public override SystemFacts GetSystemFacts() =>
        new(WindowsBuildNumber: 26100, SystemDriveIsSolidState: true, HasBattery: false, TotalMemoryBytes: 32L * 1024 * 1024 * 1024);

    public override string GetHostsFilePath() => _hostsPath;

    // ---------------------------------------------------------------------------------------------
    // Реестр
    // ---------------------------------------------------------------------------------------------

    private static string ValueKey(string hive, string subKeyPath, string valueName) => $@"{hive}\{subKeyPath}::{valueName}";

    public override (bool Exists, int ValueKindCode, string? SerializedValue) ReadRegistryValue(string hive, string subKeyPath, string valueName) =>
        _values.TryGetValue(ValueKey(hive, subKeyPath, valueName), out var item) ? (true, item.Kind, item.Val) : (false, 1, null);

    public override bool WriteRegistryValue(string hive, string subKeyPath, string valueName, RegistryTweakValueKind kind, string serializedValue)
    {
        var key = ValueKey(hive, subKeyPath, valueName);
        if (kind == RegistryTweakValueKind.DeleteValue)
        {
            _values.Remove(key);
            return true;
        }

        var path = subKeyPath;
        while (path.Length > 0)
        {
            _keys.Add($@"{hive}\{path}");
            var separator = path.LastIndexOf('\\');
            path = separator < 0 ? "" : path[..separator];
        }

        _values[key] = ((int)kind, serializedValue);
        return true;
    }

    public override bool RegistryKeyExists(string hive, string subKeyPath) => _keys.Contains($@"{hive}\{subKeyPath}");

    public override string? FindFirstMissingRegistryKey(string hive, string subKeyPath)
    {
        var parts = subKeyPath.Split('\\');
        for (var i = 1; i <= parts.Length; i++)
        {
            var path = string.Join('\\', parts.Take(i));
            if (!_keys.Contains($@"{hive}\{path}"))
            {
                return path;
            }
        }

        return null;
    }

    public override bool DeleteRegistryKeyIfEmpty(string hive, string subKeyPath)
    {
        var full = $@"{hive}\{subKeyPath}";
        if (!_keys.Contains(full) ||
            _values.Keys.Any(k => k.StartsWith(full + "::", StringComparison.OrdinalIgnoreCase)) ||
            _keys.Any(k => k.StartsWith(full + @"\", StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        return _keys.Remove(full);
    }

    // ---------------------------------------------------------------------------------------------
    // Службы и задания
    // ---------------------------------------------------------------------------------------------

    public override ServiceConfigSnapshot? QueryServiceConfig(string serviceName)
    {
        var service = _services.FirstOrDefault(s => s.ServiceName.Equals(serviceName, StringComparison.OrdinalIgnoreCase));
        return service is null ? null : new ServiceConfigSnapshot(service.ServiceName, service.Startup);
    }

    public override PlatformActionResult SetServiceStartup(string serviceName, ServiceStartupMode mode)
    {
        var index = _services.FindIndex(s => s.ServiceName.Equals(serviceName, StringComparison.OrdinalIgnoreCase));
        if (index < 0)
        {
            return PlatformActionResult.Fail("служба не установлена");
        }

        _services[index] = _services[index] with { Startup = mode };
        return PlatformActionResult.Ok;
    }

    public override Task<PlatformActionResult> ControlServiceAsync(string serviceName, bool start, CancellationToken ct = default)
    {
        var index = _services.FindIndex(s => s.ServiceName.Equals(serviceName, StringComparison.OrdinalIgnoreCase));
        if (index >= 0)
        {
            _services[index] = _services[index] with { State = start ? ServiceRunState.Running : ServiceRunState.Stopped };
        }

        return Task.FromResult(PlatformActionResult.Ok);
    }

    public override Task<IReadOnlyList<WindowsServiceInfo>> GetServicesAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<WindowsServiceInfo>>(_services.ToList());

    public override IReadOnlyDictionary<string, ScheduledTaskSnapshot> QueryScheduledTasks(IReadOnlyCollection<string> taskPaths)
    {
        var found = new Dictionary<string, ScheduledTaskSnapshot>(StringComparer.OrdinalIgnoreCase);
        foreach (var path in taskPaths)
        {
            var task = _tasks.FirstOrDefault(t => t.TaskPath.Equals(path, StringComparison.OrdinalIgnoreCase));
            if (task is not null)
            {
                found[path] = new ScheduledTaskSnapshot(task.TaskPath, task.Enabled);
            }
        }

        return found;
    }

    public override PlatformActionResult SetScheduledTaskEnabled(string taskPath, bool enabled)
    {
        var index = _tasks.FindIndex(t => t.TaskPath.Equals(taskPath, StringComparison.OrdinalIgnoreCase));
        if (index < 0)
        {
            return PlatformActionResult.Fail("задание не найдено");
        }

        _tasks[index] = _tasks[index] with { Enabled = enabled };
        return PlatformActionResult.Ok;
    }

    public override Task<IReadOnlyList<ScheduledTaskInfo>> GetScheduledTasksAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<ScheduledTaskInfo>>(_tasks.ToList());

    // ---------------------------------------------------------------------------------------------
    // Автозагрузка, меню, программы, приложения
    // ---------------------------------------------------------------------------------------------

    public override Task<IReadOnlyList<StartupEntryInfo>> GetStartupEntriesAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<StartupEntryInfo>>(
        [
            new("HKCU::Steam", "Steam", "\"C:\\Program Files (x86)\\Steam\\steam.exe\" -silent", @"C:\Program Files (x86)\Steam\steam.exe", "HKCU (Текущий пользователь)", true, true, false),
            new("HKCU::Discord", "Discord", @"C:\Users\User\AppData\Local\Discord\Update.exe --processStart Discord.exe", @"C:\Users\User\AppData\Local\Discord\Update.exe", "HKCU (Текущий пользователь)", true, true, false),
            new("HKLM::SecurityHealth", "SecurityHealth", @"%windir%\system32\SecurityHealthSystray.exe", @"C:\Windows\system32\SecurityHealthSystray.exe", "HKLM (Все пользователи)", true, true, true),
            new("HKCU::FreeDownloadHelper", "FreeDownloadHelper", @"C:\Users\User\AppData\Roaming\fdh\helper.exe /tray", @"C:\Users\User\AppData\Roaming\fdh\helper.exe", "HKCU (Текущий пользователь)", true, false, false),
            new("HKLM::AdobeUpdater", "Adobe Acrobat Updater", "\"C:\\Program Files (x86)\\Common Files\\Adobe\\ARM\\1.0\\AdobeARM.exe\"", @"C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\AdobeARM.exe", "HKLM (Все пользователи)", false, true, true)
        ]);

    public override Task<(bool Succeeded, string PreviousStartupApprovedBase64)> SetStartupEntryEnabledAsync(StartupEntryInfo entry, bool enabled, CancellationToken ct = default) =>
        Task.FromResult((true, ""));

    public override Task<IReadOnlyList<ShellContextMenuHandlerInfo>> GetThirdPartyShellExtensionsAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<ShellContextMenuHandlerInfo>>(
        [
            new("{23170F69-40C1-278A-1000-000100020000}", "7-Zip", "Файлы и папки", @"C:\Program Files\7-Zip\7-zip.dll", false, true, false),
            new("{B41DB860-64E4-11D2-9906-E49FADC173CA}", "WinRAR", "Файлы и папки", @"C:\Program Files\WinRAR\rarext.dll", false, true, false),
            new("{0F8604A5-4ECE-4DE1-BA7D-CF10F8AA4F48}", "Неизвестный обработчик", "Папки", null, false, false, true)
        ]);

    public override Task<IReadOnlyList<InstalledApplicationInfo>> GetInstalledApplicationsAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<InstalledApplicationInfo>>(
        [
            new(@"HKLM\...\Uninstall\7-Zip", "7-Zip 24.08 (x64)", "24.08", "Igor Pavlov", @"C:\Program Files\7-Zip", "\"C:\\Program Files\\7-Zip\\Uninstall.exe\"", 5_800_000),
            new(@"HKLM\...\Uninstall\Steam", "Steam", "2.10.91.91", "Valve Corporation", @"C:\Program Files (x86)\Steam", "\"C:\\Program Files (x86)\\Steam\\uninstall.exe\"", 1_240_000_000),
            new(@"HKLM\...\Uninstall\Chrome", "Google Chrome", "140.0.7339.81", "Google LLC", @"C:\Program Files\Google\Chrome\Application", "\"C:\\Program Files\\Google\\Chrome\\Application\\setup.exe\" --uninstall", 720_000_000),
            new(@"HKLM\...\Uninstall\Office", "Microsoft 365 для семьи — ru-ru", "16.0.19127.20154", "Microsoft Corporation", @"C:\Program Files\Microsoft Office", "\"C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\OfficeClickToRun.exe\" scenario=install", 0),
            new(@"HKLM\...\Uninstall\NVIDIA", "NVIDIA Графический драйвер 581.29", "581.29", "NVIDIA Corporation", null, "\"C:\\Windows\\SysWOW64\\RunDll32.EXE\" nvinstaller", 1_900_000_000),
            new(@"HKCU\...\Uninstall\Telegram", "Telegram Desktop", "6.1.3", "Telegram FZ-LLC", @"C:\Users\User\AppData\Roaming\Telegram Desktop", null, 310_000_000)
        ]);

    public override Task<IReadOnlyList<UwpPackageInfo>> GetInstalledUwpPackagesAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<UwpPackageInfo>>(
        [
            new("Microsoft.BingWeather", "Microsoft.BingWeather_4.54_x64__8wekyb3d8bbwe", "4.54.63029.0", "CN=Microsoft", @"C:\Program Files\WindowsApps\Microsoft.BingWeather", false, false),
            new("Microsoft.BingNews", "Microsoft.BingNews_1.0_x64__8wekyb3d8bbwe", "1.0.6.0", "CN=Microsoft", @"C:\Program Files\WindowsApps\Microsoft.BingNews", false, false),
            new("Microsoft.MicrosoftSolitaireCollection", "Microsoft.MicrosoftSolitaireCollection_4.21_x64__8wekyb3d8bbwe", "4.21.9100.0", "CN=Microsoft", @"C:\Program Files\WindowsApps\Solitaire", false, false),
            new("Clipchamp.Clipchamp", "Clipchamp.Clipchamp_4.4_x64__yxz26nhyzhsrt", "4.4.10420.0", "CN=Clipchamp", @"C:\Program Files\WindowsApps\Clipchamp", false, false),
            new("Microsoft.GamingApp", "Microsoft.GamingApp_2509.1001_x64__8wekyb3d8bbwe", "2509.1001.21.0", "CN=Microsoft", @"C:\Program Files\WindowsApps\GamingApp", false, false),
            new("Microsoft.WindowsStore", "Microsoft.WindowsStore_22509_x64__8wekyb3d8bbwe", "22509.1401.4.0", "CN=Microsoft", @"C:\Program Files\WindowsApps\Store", true, false),
            new("Microsoft.VCLibs.140.00", "Microsoft.VCLibs.140.00_14.0_x64__8wekyb3d8bbwe", "14.0.33728.0", "CN=Microsoft", @"C:\Program Files\WindowsApps\VCLibs", true, true)
        ]);

    private static WindowsServiceInfo SampleService(
        string name,
        string displayName,
        ServiceStartupMode startup,
        bool running,
        string description,
        string publisher = "Microsoft Corporation",
        string? binaryPath = null) =>
        new(
            name,
            displayName,
            description,
            startup,
            running ? ServiceRunState.Running : ServiceRunState.Stopped,
            binaryPath ?? @"C:\Windows\system32\svchost.exe -k netsvcs -p",
            publisher,
            publisher.Contains("Microsoft", StringComparison.OrdinalIgnoreCase),
            "LocalSystem");

    private static ScheduledTaskInfo SampleTask(string path, bool enabled, bool running, string action, string author = "Microsoft")
    {
        var separator = path.LastIndexOf('\\');
        return new ScheduledTaskInfo(
            path,
            path[(separator + 1)..],
            separator <= 0 ? @"\" : path[..separator],
            enabled,
            running,
            new DateTime(2026, 11, 10, 3, 12, 0),
            enabled ? new DateTime(2026, 11, 12, 3, 0, 0) : null,
            author,
            action,
            path.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase));
    }
}
