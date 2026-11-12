using UltimateWindows.Core.Models;
using UltimateWindows.Modules.Apps.Models;

namespace UltimateWindows.Modules.Apps.Readiness;

/// <summary>
/// Оценщик аппаратной готовности ПК к Windows 11 (включая требования 24H2/25H2 к инструкциям SSE4.2 и POPCNT)
/// и статуса жизненного цикла Windows 10 (обычная поддержка завершена 14.10.2025, потребительский ESU до 12.10.2027).
/// </summary>
public static class Windows11ReadinessEvaluator
{
    private const long MinRamBytes = 3_800_000_000L;         // допуск для 4 ГБ ОЗУ с учётом резерва видеопамяти BIOS
    private const long MinSystemDiskBytes = 60_000_000_000L; // допуск для 64 ГБ накопителя в десятичных ГБ

    public static Windows11ReadinessReport Evaluate(Win11RawHardwareFacts facts)
    {
        ArgumentNullException.ThrowIfNull(facts);

        var isWin11 = facts.OsBuildNumber >= 22000;
        var checks = new List<Win11CheckItem>(7);

        // 1. Процессор: 64-бит, >= 2 ядра, >= 1 ГГц + инструкции SSE4.2 и POPCNT (обязательны с Windows 11 24H2)
        var cpuBasicOk = facts.Is64BitArchitecture &&
                         facts.CpuCores >= 2 &&
                         (facts.CpuMaxClockMhz <= 0 || facts.CpuMaxClockMhz >= 1000);
        var cpuIsaOk = facts.Sse42Supported && facts.PopcntSupported;
        var cpuPassed = cpuBasicOk && cpuIsaOk;

        var clockDisplay = facts.CpuMaxClockMhz > 0 ? $", {facts.CpuMaxClockMhz / 1000.0:F2} ГГц" : string.Empty;
        var isaBadge = cpuIsaOk ? "SSE4.2 + POPCNT есть" : "нет SSE4.2 / POPCNT";
        checks.Add(new Win11CheckItem(
            CheckId: "cpu",
            Title: "64-разрядный процессор и инструкции 24H2",
            CurrentValue: $"{facts.CpuBrand} ({facts.CpuCores} ядр.{clockDisplay}, {isaBadge})",
            RequirementText: "64-бит, от 2 ядер, от 1 ГГц, SSE4.2 + POPCNT",
            Passed: cpuPassed,
            CanEnableWithoutNewHardware: false,
            ActionHint: cpuPassed
                ? "Процессор поддерживает инструкции современных выпусков Windows 11 (24H2/25H2)."
                : "Процессор не соответствует минимальным аппаратным требованиям Windows 11."));

        // 2. Оперативная память >= 4 ГБ
        var ramPassed = facts.TotalRamBytes >= MinRamBytes;
        checks.Add(new Win11CheckItem(
            CheckId: "ram",
            Title: "Оперативная память (ОЗУ)",
            CurrentValue: ByteFormatter.Format(facts.TotalRamBytes),
            RequirementText: "Не менее 4 ГБ ОЗУ",
            Passed: ramPassed,
            CanEnableWithoutNewHardware: false,
            ActionHint: ramPassed
                ? (facts.TotalRamBytes >= 8L * 1024 * 1024 * 1024
                    ? "Объём памяти комфортен для Windows 11."
                    : "Минимум 4 ГБ выполнен, но для комфортной работы желательно 8–16 ГБ.")
                : "Для установки Windows 11 требуется минимум 4 ГБ оперативной памяти."));

        // 3. Системный накопитель >= 64 ГБ
        var diskPassed = facts.SystemDriveTotalBytes >= MinSystemDiskBytes;
        checks.Add(new Win11CheckItem(
            CheckId: "storage",
            Title: "Ёмкость системного накопителя",
            CurrentValue: ByteFormatter.Format(facts.SystemDriveTotalBytes),
            RequirementText: "Не менее 64 ГБ",
            Passed: diskPassed,
            CanEnableWithoutNewHardware: false,
            ActionHint: diskPassed
                ? "Системный том вмещает образ и обновления Windows 11."
                : "Требуется системный накопитель объёмом от 64 ГБ."));

        // 4. Загрузчик UEFI и разметка GPT
        var uefiGptPassed = facts.IsUefiBoot && facts.IsSystemDiskGpt;
        var bootModeText = $"{(facts.IsUefiBoot ? "UEFI" : "Legacy BIOS (CSM)")} • {(facts.IsSystemDiskGpt ? "GPT" : "MBR")}";
        checks.Add(new Win11CheckItem(
            CheckId: "uefi_gpt",
            Title: "Загрузка UEFI и таблица разделов GPT",
            CurrentValue: bootModeText,
            RequirementText: "Режим UEFI + разметка диска GPT",
            Passed: uefiGptPassed,
            CanEnableWithoutNewHardware: true,
            ActionHint: uefiGptPassed
                ? "Система уже загружается в современном режиме UEFI с диска GPT."
                : "Конвертируйте системный диск штатной утилитой «mbr2gpt /validate /allowFullOS» и отключите CSM в настройках BIOS/UEFI."));

        // 5. Безопасная загрузка Secure Boot
        checks.Add(new Win11CheckItem(
            CheckId: "secure_boot",
            Title: "Безопасная загрузка (Secure Boot)",
            CurrentValue: facts.IsSecureBootEnabled ? "Включена" : "Отключена",
            RequirementText: "Поддержка и активность UEFI Secure Boot",
            Passed: facts.IsSecureBootEnabled,
            CanEnableWithoutNewHardware: true,
            ActionHint: facts.IsSecureBootEnabled
                ? "Secure Boot активен и защищает цепочку загрузки ядра."
                : "Откройте настройки BIOS/UEFI (раздел Boot / Security), выключите CSM и переведите Secure Boot в состояние Enabled."));

        // 6. Доверенный платформенный модуль TPM 2.0
        var tpmPassed = facts.TpmPresent &&
                        facts.TpmSpecVersion.StartsWith("2.", StringComparison.OrdinalIgnoreCase);
        var tpmCurrent = !facts.TpmPresent
            ? "Не обнаружен / отключён в BIOS"
            : $"TPM {facts.TpmSpecVersion}";
        checks.Add(new Win11CheckItem(
            CheckId: "tpm",
            Title: "Модуль доверенной платформы TPM 2.0",
            CurrentValue: tpmCurrent,
            RequirementText: "TPM версии 2.0 (дискретный или встроенный fTPM / PTT)",
            Passed: tpmPassed,
            CanEnableWithoutNewHardware: true,
            ActionHint: tpmPassed
                ? "Модуль TPM 2.0 активен и готов к работе."
                : "На платах AMD включите «AMD CPU fTPM», на платах Intel — «Intel Platform Trust Technology (PTT)» в настройках BIOS/UEFI."));

        // 7. Графика DirectX 12 / WDDM 2.0
        checks.Add(new Win11CheckItem(
            CheckId: "dx12_wddm2",
            Title: "Видеоадаптер DirectX 12 и драйвер WDDM 2.0+",
            CurrentValue: facts.DirectX12AndWddm2Ready ? "Поддерживается (DirectX 12 / WDDM 2.x+)" : "Базовый или устаревший видеодрайвер",
            RequirementText: "DirectX 12 с моделью драйвера WDDM 2.0 и выше",
            Passed: facts.DirectX12AndWddm2Ready,
            CanEnableWithoutNewHardware: true,
            ActionHint: facts.DirectX12AndWddm2Ready
                ? "Графическая подсистема полностью совместима с Windows 11."
                : "Установите актуальный видеодрайвер AMD, Intel или NVIDIA во вкладке «Железо и Драйверы»."));

        var passedCount = checks.Count(c => c.Passed);
        var fullyCompatible = passedCount == checks.Count;
        var lifecycle = BuildLifecycleStatus(facts, isWin11, fullyCompatible, checks);

        var headline = isWin11
            ? (fullyCompatible
                ? $"Установлена {facts.OsCaption} (сборка {facts.OsBuildNumber}): все {checks.Count}/{checks.Count} аппаратных требований соблюдены"
                : $"Установлена {facts.OsCaption} (сборка {facts.OsBuildNumber}): пройдено {passedCount} из {checks.Count} проверок новых выпусков 24H2/25H2")
            : (fullyCompatible
                ? $"ПК полностью готов к бесплатному обновлению до Windows 11 ({passedCount}/{checks.Count} проверок пройдено)"
                : $"Для перехода на Windows 11 требуется внимание ({passedCount} из {checks.Count} проверок пройдено)");

        return new Windows11ReadinessReport(
            IsFullyCompatible: fullyCompatible,
            PassedCount: passedCount,
            TotalCount: checks.Count,
            OverallHeadline: headline,
            Lifecycle: lifecycle,
            Checks: checks);
    }

    private static WindowsLifecycleStatus BuildLifecycleStatus(
        Win11RawHardwareFacts facts,
        bool isWin11,
        bool fullyCompatible,
        IReadOnlyList<Win11CheckItem> checks)
    {
        if (isWin11)
        {
            var modernBuild = facts.OsBuildNumber >= 26100;
            return new WindowsLifecycleStatus(
                CurrentOsName: facts.OsCaption,
                BuildNumber: facts.OsBuildNumber,
                IsWindows11: true,
                IsMainstreamSupported: modernBuild,
                SupportDeadlineText: modernBuild
                    ? "Актуальная ветка Windows 11 (24H2/25H2) на активной поддержке"
                    : $"Сборка Windows 11 ({facts.OsBuildNumber}) устарела — рекомендуется обновление через Центр обновления Windows",
                EsuStatusHeadline: "Программа Windows 10 ESU не требуется (установлена Windows 11)",
                RecommendationText: modernBuild
                    ? "Система получает ежемесячные накопительные обновления безопасности."
                    : "Откройте «Параметры → Центр обновления Windows» для перехода на актуальный выпуск Windows 11.");
        }

        // Windows 10: базовая поддержка завершилась 14 октября 2025, потребительская программа ESU действует до 12 октября 2027
        var onlyBiosSettingsMissing = !fullyCompatible && checks.Where(c => !c.Passed).All(c => c.CanEnableWithoutNewHardware);
        var esuHeadline = facts.HasConsumerEsuMarker
            ? "Подключены расширенные обновления безопасности Windows 10 ESU (защита продлена)"
            : "Обычная поддержка Windows 10 завершилась 14.10.2025 • Доступна программа ESU (до 12.10.2027)";

        var recommendation = fullyCompatible
            ? "Компьютер полностью совместим с Windows 11: вы можете обновиться штатно через Центр обновления Windows или Помощник по установке Microsoft с сохранением всех файлов и лицензии."
            : onlyBiosSettingsMissing
                ? "Железо подходит для Windows 11, но в BIOS/UEFI выключены TPM 2.0, Secure Boot или режим UEFI. Включите их по подсказкам ниже либо подключите официальную программу Windows 10 ESU в Центре обновления."
                : "Компьютер имеет аппаратные ограничения для Windows 11: рекомендуется оставаться на стабильной Windows 10 22H2 с официальной программой расширенных обновлений безопасности ESU (до 12.10.2027).";

        return new WindowsLifecycleStatus(
            CurrentOsName: facts.OsCaption,
            BuildNumber: facts.OsBuildNumber,
            IsWindows11: false,
            IsMainstreamSupported: false,
            SupportDeadlineText: "Базовая поддержка Windows 10 22H2 завершена 14 октября 2025 г. (потребительская ESU — до 12 октября 2027 г.)",
            EsuStatusHeadline: esuHeadline,
            RecommendationText: recommendation);
    }
}
