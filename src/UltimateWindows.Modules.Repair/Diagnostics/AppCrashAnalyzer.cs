using System.Globalization;
using UltimateWindows.Modules.Repair.Catalog;
using UltimateWindows.Modules.Repair.Models;

namespace UltimateWindows.Modules.Repair.Diagnostics;

/// <summary>
/// Анализатор записей журнала событий Windows о сбоях программ (Event 1000, 1002, 1026, SideBySide 33/59/78, AppModel-Runtime, TDR 4101, WHEA):
/// определяет вероятную причину падения и связывает запись с пакетом среды выполнения или правилом ремонта.
/// </summary>
public static class AppCrashAnalyzer
{
    public static SystemCrashEventEntry BuildAnalyzedEntry(
        int eventId,
        string provider,
        DateTimeOffset timestampUtc,
        IReadOnlyList<string> dataItems)
    {
        var joinedData = string.Join(" | ", dataItems.Where(s => !string.IsNullOrWhiteSpace(s)));
        var rawTech = string.IsNullOrWhiteSpace(joinedData) ? provider : joinedData;

        // 1. Application Error — Event ID 1000
        // Стандартный порядок полей EventData в Windows 10/11:
        // [0]=AppName, [1]=AppVersion, [2]=AppTimeStamp, [3]=FaultingModuleName, [4]=ModVersion, [5]=ModTimeStamp,
        // [6]=ExceptionCode (напр. c0000005 / 0xc0000409), [7]=FaultOffset, [8]=ProcessId, [9]=StartTime, [10]=AppPath, [11]=ModPath
        if (eventId == 1000)
        {
            var appName = GetAt(dataItems, 0) ?? "Приложение";
            var modName = GetAt(dataItems, 3) ?? "unknown";
            var exCodeStr = GetAt(dataItems, 6);
            var appPath = FindExePath(dataItems, preferredIndex: 10);
            var exCode = TryParseHexCode(exCodeStr);

            var (hint, runtimeKey, ruleId) = DiagnoseAppCrash1000(appName, modName, exCode);
            var summary = exCode.HasValue
                ? $"Сбой «{appName}» в модуле «{modName}» (код 0x{exCode.Value:X8}). {hint}"
                : $"Сбой «{appName}» в модуле «{modName}». {hint}";

            return new SystemCrashEventEntry(
                Kind: SystemCrashEventKind.ApplicationCrash1000,
                TimestampUtc: timestampUtc,
                EventId: eventId,
                SourceProvider: provider,
                SimpleSummary: summary,
                TechnicalRawDetails: rawTech,
                FaultingExecutablePath: appPath,
                FaultingModuleName: modName,
                ExceptionCode: exCode,
                RootCauseHint: hint,
                RecommendedRuntimeKey: runtimeKey,
                RecommendedRepairRuleId: ruleId);
        }

        // 2. Application Hang — Event ID 1002
        if (eventId == 1002)
        {
            var appName = GetAt(dataItems, 0) ?? "Приложение";
            var appPath = FindExePath(dataItems, preferredIndex: 5);
            var isExplorer = appName.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase);
            var hint = isExplorer
                ? "Проводник перестал отвечать — часто виноваты медленные сторонние расширения контекстного меню или повреждённый кэш эскизов."
                : "Программа перестала отвечать на сообщения окна (зависание UI-потока при обращении к диску, сети или видеодрайверу).";

            return new SystemCrashEventEntry(
                Kind: SystemCrashEventKind.ApplicationHang1002,
                TimestampUtc: timestampUtc,
                EventId: eventId,
                SourceProvider: provider,
                SimpleSummary: $"Зависание программы «{appName}» (Application Hang 1002). {hint}",
                TechnicalRawDetails: rawTech,
                FaultingExecutablePath: appPath,
                RootCauseHint: hint,
                RecommendedRepairRuleId: isExplorer ? "explorer.icon-thumb-cache" : null);
        }

        // 3. .NET Runtime unhandled exception — Event ID 1026
        if (eventId == 1026 || provider.Contains(".NET Runtime", StringComparison.OrdinalIgnoreCase))
        {
            var firstLine = joinedData.Length > 220 ? joinedData[..220] + "…" : joinedData;
            var hint = DiagnoseDotNet1026(joinedData);
            return new SystemCrashEventEntry(
                Kind: SystemCrashEventKind.DotNetUnhandledException1026,
                TimestampUtc: timestampUtc,
                EventId: eventId,
                SourceProvider: provider,
                SimpleSummary: $"Необработанное исключение .NET: {hint}",
                TechnicalRawDetails: firstLine,
                ExceptionCode: 0xE0434352u,
                RootCauseHint: hint,
                RecommendedRuntimeKey: joinedData.Contains("WindowsDesktop", StringComparison.OrdinalIgnoreCase) ? "dotnet-desktop-8-x64" : null);
        }

        // 4. SideBySide — Event ID 33 / 59 / 78
        if (eventId is 33 or 59 or 78 || provider.Contains("SideBySide", StringComparison.OrdinalIgnoreCase))
        {
            var (hint, runtimeKey) = DiagnoseSideBySide(joinedData);
            return new SystemCrashEventEntry(
                Kind: SystemCrashEventKind.SideBySideManifestError,
                TimestampUtc: timestampUtc,
                EventId: eventId,
                SourceProvider: provider,
                SimpleSummary: hint,
                TechnicalRawDetails: rawTech,
                ExceptionCode: 0x800736B1u,
                RootCauseHint: hint,
                RecommendedRuntimeKey: runtimeKey);
        }

        // 5. Сбой запуска системных UWP/XAML приложений (AppModel-Runtime)
        if (provider.Contains("AppModel-Runtime", StringComparison.OrdinalIgnoreCase) ||
            provider.Contains("Immersive-Shell", StringComparison.OrdinalIgnoreCase))
        {
            const string hint = "Ошибка активации пакета UWP/XAML оболочки Windows. Помогает перерегистрация пакетов Microsoft Store и оболочки «Пуск».";
            return new SystemCrashEventEntry(
                Kind: SystemCrashEventKind.AppxActivationFailure,
                TimestampUtc: timestampUtc,
                EventId: eventId,
                SourceProvider: provider,
                SimpleSummary: hint,
                TechnicalRawDetails: rawTech,
                RootCauseHint: hint,
                RecommendedRepairRuleId: "store.reset-cache-and-register");
        }

        // 6. TDR 4101 — сброс видеодрайвера
        if (eventId == 4101)
        {
            const string hint = "Видеодрайвер перестал отвечать (TDR 4101) и был перезапущен Windows. Проверьте температуру GPU, снизьте разгон и переустановите видеодрайвер начисто.";
            return new SystemCrashEventEntry(
                Kind: SystemCrashEventKind.GpuTdrReset4101,
                TimestampUtc: timestampUtc,
                EventId: eventId,
                SourceProvider: provider,
                SimpleSummary: hint,
                TechnicalRawDetails: rawTech,
                RootCauseHint: hint);
        }

        // 7. Kernel-Power 41
        if (eventId == 41)
        {
            const string hint = "Внезапное отключение питания или жёсткая перезагрузка ПК (Kernel-Power 41). Проверьте дампы синих экранов, перегрев и блок питания.";
            return new SystemCrashEventEntry(
                Kind: SystemCrashEventKind.UnexpectedKernelPower41,
                TimestampUtc: timestampUtc,
                EventId: eventId,
                SourceProvider: provider,
                SimpleSummary: hint,
                TechnicalRawDetails: rawTech,
                RootCauseHint: hint,
                RecommendedRepairRuleId: "sys.enable-minidumps");
        }

        // 8. BugCheck 1001
        if (eventId == 1001)
        {
            const string hint = "Система перезагрузилась после синего экрана (BugCheck 1001). Разберите дамп выше для определения виновного драйвера.";
            return new SystemCrashEventEntry(
                Kind: SystemCrashEventKind.BsodBugCheck1001,
                TimestampUtc: timestampUtc,
                EventId: eventId,
                SourceProvider: provider,
                SimpleSummary: hint,
                TechnicalRawDetails: rawTech,
                RootCauseHint: hint);
        }

        // 9. WHEA
        var wheaHint = $"Аппаратная ошибка подсистемы {provider} (WHEA): проверьте разгон/андервольтинг CPU, профиль XMP/EXPO памяти и температуру NVMe/PCIe.";
        return new SystemCrashEventEntry(
            Kind: SystemCrashEventKind.HardwareWheaError,
            TimestampUtc: timestampUtc,
            EventId: eventId,
            SourceProvider: provider,
            SimpleSummary: wheaHint,
            TechnicalRawDetails: rawTech,
            RootCauseHint: wheaHint);
    }

    public static (string Hint, string? RuntimeKey, string? RepairRuleId) DiagnoseAppCrash1000(
        string appName,
        string faultModule,
        uint? exceptionCode)
    {
        var modLower = Path.GetFileName(faultModule.Trim()).ToLowerInvariant();
        var appLower = Path.GetFileName(appName.Trim()).ToLowerInvariant();

        // Оболочка Windows 11 / Пуск / Поиск
        if (appLower is "startmenuexperiencehost.exe" or "searchhost.exe" or "shellexperiencehost.exe" or "systemsettings.exe")
        {
            return (
                "Сбой системного XAML-компонента оболочки Windows («Пуск», Поиск или Параметры). Рекомендуется перерегистрация системных пакетов оболочки.",
                null,
                "shell.win11-xaml-packages");
        }

        // Код 0xC000007B — конфликт разрядности DLL
        if (exceptionCode == 0xC000007Bu)
        {
            var pkg = OfficialRuntimeCatalog.FindMatchingPackage(modLower, PeArchitecture.X64);
            return (
                "Конфликт разрядности x86/x64 (0xC000007B): рядом с .exe лежит чужеродная DLL неверной архитектуры. Откройте этот .exe в PE-Докторе для точной изоляции.",
                pkg?.PackageKey ?? "vcredist-2015-2022-x64",
                null);
        }

        // Код 0xC0000135 — отсутствует обязательная DLL
        if (exceptionCode == 0xC0000135u)
        {
            var pkg = OfficialRuntimeCatalog.FindMatchingPackage(modLower, PeArchitecture.X64);
            return (
                $"Не найдена обязательная библиотека ({modLower}). Проверьте .exe в PE-Докторе и установите пакет среды выполнения.",
                pkg?.PackageKey ?? "vcredist-2015-2022-x64",
                null);
        }

        // Прямая привязка модуля сбоя к пакету VC++ / DirectX / WebView2
        var matchedRuntime = OfficialRuntimeCatalog.FindMatchingPackage(modLower, PeArchitecture.X64)
            ?? OfficialRuntimeCatalog.FindMatchingPackage(modLower, PeArchitecture.X86);
        if (matchedRuntime is not null)
        {
            return (
                $"Сбой произошёл внутри библиотеки среды выполнения «{modLower}». Переустановите пакет «{matchedRuntime.FriendlyName}».",
                matchedRuntime.PackageKey,
                null);
        }

        if (modLower is "ucrtbase.dll")
        {
            return (
                "Программа завершилась аварийно в базовой библиотеке Си (ucrtbase.dll) — обычно из-за некорректных входных данных, битых настроек программы или устаревшего пакета Visual C++.",
                "vcredist-2015-2022-x64",
                "sfc.cbs-component-store");
        }

        // Графический стек и видеодрайверы
        if (modLower is "d3d11.dll" or "d3d12.dll" or "d3d12core.dll" or "dxgi.dll" or "vulkan-1.dll" ||
            modLower.StartsWith("nvwgf2", StringComparison.Ordinal) ||
            modLower.StartsWith("nvoglv", StringComparison.Ordinal) ||
            modLower.StartsWith("amdxn", StringComparison.Ordinal) ||
            modLower.StartsWith("amdxc", StringComparison.Ordinal) ||
            modLower.StartsWith("igd10", StringComparison.Ordinal) ||
            modLower.StartsWith("igd12", StringComparison.Ordinal))
        {
            return (
                $"Сбой в графическом драйвере или рендерере ({modLower}). Отключите игровые оверлеи (Discord/GeForce/RivaTuner), очистите кэш шейдеров и обновите драйвер видеокарты.",
                modLower == "vulkan-1.dll" ? "vulkan-runtime-x64" : "directx-june-2010",
                null);
        }

        // .NET CLR (0xE0434352 или coreclr/clr.dll)
        if (exceptionCode == 0xE0434352u || modLower is "clr.dll" or "coreclr.dll" or "hostfxr.dll")
        {
            return (
                "Необработанное исключение среды .NET (0xE0434352). Проверьте наличие нужной версии .NET Desktop Runtime и соседнюю запись Event ID 1026.",
                "dotnet-desktop-8-x64",
                null);
        }

        // C++ исключение (0xE06D7363 в KERNELBASE.dll)
        if (exceptionCode == 0xE06D7363u)
        {
            return (
                "Неперехваченное исключение C++ (0xE06D7363) — программа столкнулась с отсутствующим файлом ресурсов, правами доступа к %TEMP%/AppData или нехваткой библиотек VC++.",
                "vcredist-2015-2022-x64",
                "disk.dirty-and-temp-health");
        }

        if (exceptionCode == 0xC0000374u)
        {
            return (
                "Повреждение кучи памяти (STATUS_HEAP_CORRUPTION, 0xC0000374) — ошибка в самой программе, стороннем плагине или расширении оболочки.",
                null,
                null);
        }

        if (exceptionCode == 0xC0000409u)
        {
            return (
                "Аварийная остановка защиты стека (__fastfail, 0xC0000409) — сработала встроенная защита Windows от переполнения буфера или неверного состояния потока.",
                null,
                "sfc.cbs-component-store");
        }

        if (exceptionCode == 0xC0000005u)
        {
            return (
                "Нарушение прав доступа к памяти (ACCESS_VIOLATION, 0xC0000005) — обращение по нулевому/неверному указателю, конфликт с антивирусом/оверлеем или повреждение DLL.",
                null,
                null);
        }

        return (
            "Проверьте .exe файл программы в PE-Докторе на целостность зависимостей DLL и наличие обновлений самой программы.",
            null,
            null);
    }

    private static string DiagnoseDotNet1026(string text)
    {
        if (text.Contains("DllNotFoundException", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("BadImageFormatException", StringComparison.OrdinalIgnoreCase))
        {
            return "Программе .NET не удалось загрузить нативную DLL (отсутствует пакет Visual C++ или не совпадает разрядность x86/x64).";
        }

        if (text.Contains("UnauthorizedAccessException", StringComparison.OrdinalIgnoreCase))
        {
            return "Отказ в доступе к файлу или разделу реестра — попробуйте запуск от имени администратора или проверьте права на папку %TEMP%.";
        }

        if (text.Contains("FileNotFoundException", StringComparison.OrdinalIgnoreCase))
        {
            return "Не найден файл сборки или конфигурации программы — переустановите программу или требуемый пакет .NET Runtime.";
        }

        return "Внутренняя ошибка .NET-приложения (подробный стек в технических деталях записи).";
    }

    private static (string Hint, string RuntimeKey) DiagnoseSideBySide(string text)
    {
        if (text.Contains("VC80", StringComparison.OrdinalIgnoreCase) || text.Contains("8.0.50727", StringComparison.OrdinalIgnoreCase))
        {
            return ("Ошибка SideBySide: программе требуется пакет Microsoft Visual C++ 2005 SP1 Redistributable.", "vcredist-2005-x86");
        }

        if (text.Contains("VC90", StringComparison.OrdinalIgnoreCase) || text.Contains("9.0.21022", StringComparison.OrdinalIgnoreCase) || text.Contains("9.0.30729", StringComparison.OrdinalIgnoreCase))
        {
            return ("Ошибка SideBySide: программе требуется пакет Microsoft Visual C++ 2008 SP1 Redistributable.", "vcredist-2008-x86");
        }

        return ("Ошибка конфигурации SideBySide (0x800736B1): установите пакеты Microsoft Visual C++ 2005 / 2008 / 2015–2026.", "vcredist-2015-2022-x64");
    }

    private static string? GetAt(IReadOnlyList<string> items, int index) =>
        index >= 0 && index < items.Count && !string.IsNullOrWhiteSpace(items[index])
            ? items[index].Trim()
            : null;

    private static string? FindExePath(IReadOnlyList<string> items, int preferredIndex)
    {
        var preferred = GetAt(items, preferredIndex);
        if (LooksLikeLocalExePath(preferred))
        {
            return preferred;
        }

        foreach (var item in items)
        {
            if (LooksLikeLocalExePath(item))
            {
                return item.Trim();
            }
        }

        return null;
    }

    private static bool LooksLikeLocalExePath(string? value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length >= 6 &&
        char.IsLetter(value[0]) &&
        value[1] == ':' &&
        (value[2] == '\\' || value[2] == '/') &&
        value.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);

    private static uint? TryParseHexCode(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var clean = raw.Trim();
        if (clean.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            clean = clean[2..];
        }

        return uint.TryParse(clean, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : null;
    }
}
