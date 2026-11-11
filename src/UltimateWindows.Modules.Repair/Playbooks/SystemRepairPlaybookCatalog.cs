using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Repair.Models;

namespace UltimateWindows.Modules.Repair.Playbooks;

/// <summary>
/// Каталог безопасных рецептов восстановления штатных компонентов Windows 10/11
/// без деструктивного вмешательства в пользовательские файлы и лицензии.
/// </summary>
public static class SystemRepairPlaybookCatalog
{
    private static readonly IReadOnlyList<RepairPlaybookDescriptor> Playbooks =
    [
        new(
            Id: RepairPlaybookId.DismAndSfcIntegrity,
            IconGlyph: "🩺",
            FriendlyTitle: "Проверка и лечение системных файлов Windows (DISM + SFC)",
            FriendlyDescription: "Проверяет целостность системного хранилища компонентов WinSxS и автоматически восстанавливает поврежденные системные библиотеки Microsoft.",
            ExpertCommandsPreview: "DISM.exe /Online /Cleanup-Image /RestoreHealth  &&  sfc.exe /scannow",
            RequiresAdministrator: true,
            Risk: RiskLevel.Safe),

        new(
            Id: RepairPlaybookId.NetworkAndDnsStackReset,
            IconGlyph: "🌐",
            FriendlyTitle: "Лечение интернета, DNS и сетевых сокетов (без сброса паролей Wi-Fi)",
            FriendlyDescription: "Очищает поврежденный кэш DNS и перезагружает каталог Winsock и стек TCP/IP при ошибках открытия сайтов или обрывах в играх.",
            ExpertCommandsPreview: "ipconfig /flushdns  &&  ipconfig /registerdns  &&  netsh winsock reset",
            RequiresAdministrator: true,
            Risk: RiskLevel.Low),

        new(
            Id: RepairPlaybookId.IconAndThumbnailCacheRebuild,
            IconGlyph: "🖼️",
            FriendlyTitle: "Починка белых/пропавших ярлыков и эскизов Проводника",
            FriendlyDescription: "Безопасно пересобирает поврежденные базы кэша иконок и миниатюр (iconcache_*.db, thumbcache_*.db) в профиле пользователя.",
            ExpertCommandsPreview: @"Очистка незаблокированных iconcache_*.db / thumbcache_*.db в %LocalAppData%\Microsoft\Windows\Explorer + ie4uinit.exe -show",
            RequiresAdministrator: false,
            Risk: RiskLevel.Safe),

        new(
            Id: RepairPlaybookId.WindowsUpdateReset,
            IconGlyph: "🔄",
            FriendlyTitle: "Сброс компонентов Центра обновления Windows",
            FriendlyDescription: "Помогает, когда обновления не скачиваются или не устанавливаются: останавливает службы обновления, откладывает в сторону кэш загрузок и каталог подписей, очищает очередь загрузок и запускает службы заново. Прежние папки сохраняются с суффиксом «.uw-old».",
            ExpertCommandsPreview: @"net stop usosvc, wuauserv, bits, dosvc, cryptsvc  ->  ren %SystemRoot%\SoftwareDistribution и %SystemRoot%\System32\catroot2 в *.uw-old  ->  del qmgr*.dat  ->  net start",
            RequiresAdministrator: true,
            Risk: RiskLevel.Low),

        new(
            Id: RepairPlaybookId.MicrosoftStoreAndAppxRepair,
            IconGlyph: "🛍️",
            FriendlyTitle: "Починка Microsoft Store и стандартных приложений Windows",
            FriendlyDescription: "Очищает зависший кэш магазина Microsoft Store без удаления ваших игр, программ и учетных записей.",
            ExpertCommandsPreview: "wsreset.exe -i (фоновый сброс кэша Store без потери данных приложений)",
            RequiresAdministrator: false,
            Risk: RiskLevel.Safe),

        new(
            Id: RepairPlaybookId.PrintSpoolerCleanup,
            IconGlyph: "🖨️",
            FriendlyTitle: "Очистка намертво зависшей очереди печати принтера",
            FriendlyDescription: "Решает проблему бесконечного статуса «Удаление — Печать», аккуратно перезапуская диспетчер печати и удаляя битые задания .SPL/.SHD.",
            ExpertCommandsPreview: @"net stop spooler  ->  очистка %SystemRoot%\System32\spool\PRINTERS\*  ->  net start spooler",
            RequiresAdministrator: true,
            Risk: RiskLevel.Safe),

        new(
            Id: RepairPlaybookId.WmiRepositoryVerifyAndSalvage,
            IconGlyph: "⚙️",
            FriendlyTitle: "Проверка и мягкое лечение репозитория WMI",
            FriendlyDescription: "Проверяет целостность базы инструментария управления Windows (WMI) и выполняет мягкую сверку без опасного полного сброса.",
            ExpertCommandsPreview: "winmgmt /verifyrepository  ->  (при ошибках) winmgmt /salvagerepository",
            RequiresAdministrator: true,
            Risk: RiskLevel.Low)
    ];

    public static IReadOnlyList<RepairPlaybookDescriptor> GetAllPlaybooks() => Playbooks;

    public static RepairPlaybookDescriptor GetById(RepairPlaybookId id) =>
        Playbooks.First(p => p.Id == id);
}
