# Каталог диагностики и ремонта ОС («Ремонт и DLL 2.0» — Этап 3)

Документ описывает архитектуру, правила диагностики и восстановления, каталог официальных сред выполнения и справочник кодов ошибок Windows модуля `UltimateWindows.Modules.Repair` (`src/UltimateWindows.Modules.Repair/`).

---

## 1. Принципы работы

1. **Цикл «Обнаружить → Объяснить → Исправить → Проверить» (`RepairDiagnosticEngine`)**:
   - Каждое правило сначала считывает фактическое состояние реестра, служб или файловой системы Windows (`EvaluateRuleAsync`).
   - В интерфейсе и CLI отображается обнаруженное значение, бытовой симптом, причина сбоя и описание предстоящего действия.
   - Перед изменением реестра или режима запуска служб прежнее состояние сохраняется в единую транзакцию **«Машины времени»** (`ZeroBloatVaultService`), поддерживающую откат в 1 клик через `WindowsSystemStateApplier`.
   - Сразу после исправления повторно вызывается `EvaluateRuleAsync`, подтверждающий, что узел действительно перешёл в состояние `Healthy` (или честно сообщающий о необходимости перезагрузки).
2. **Равноправная поддержка Windows 10 (22H2+) и Windows 11**:
   - Правила учитывают номер сборки ОС (`MinBuild` / `MaxBuild`) и редакцию Windows (включая аккуратную отметку `NotApplicable` на серверных и LTSC-редакциях без предустановленного Store).
3. **Жёсткие барьеры безопасности**:
   - Валидатор `RepairCatalogLoader` запрещает любые правила, затрагивающие подсистему лицензирования и активации Windows (`SoftwareProtectionPlatform`, `sppsvc`, `ClipSVC`, `LicenseManager`).
   - Сетевые среды выполнения загружаются только по HTTPS с доверенных доменов издателей и **обязательно** проходят криптографическую проверку цифровой подписи `WinVerifyTrust` (`AuthenticodeVerifier.IsFileTrustedSigned`) до запуска установщика.
   - Изоляция конфликтных DLL неверной разрядности (`0xC000007B`) жёстко запрещена внутри `C:\Windows`.

---

## 2. Каталог диагностики и ремонта (107 правил в 16 разделах)

Правила хранятся во встроенных JSON-ресурсах `src/UltimateWindows.Modules.Repair/Diagnostics/Data/*.json` (`schemaVersion: 1`):

| Файл ресурса | Раздел (`RepairSectionId`) | Примеры проверяемых и восстанавливаемых узлов |
|---|---|---|
| `10-windows-update.json` | `WindowsUpdate` | Службы `wuauserv`, `BITS`, `UsoSvc`, `TrustedInstaller`, `DoSvc`, `WaaSMedicSvc`, политики блокировки обновлений, перехват `UseWUServer` на фиктивный WSUS, маркеры `RebootRequired`, сброс `SoftwareDistribution` / `catroot2` |
| `15-network.json` | `Network` | Зависший локальный прокси `127.0.0.1` после закрытия VPN (с проверкой живого TCP-слушателя!), базовые службы `Dhcp`/`Dnscache`/`nsi`/`NlaSvc`, `WlanSvc`, `LanmanWorkstation` (SMB), `WinHttpAutoProxySvc`, очистка саботажа в `drivers\etc\hosts` с откатом, сброс DNS/Winsock |
| `20-store-appx.json` | `StoreAndAppx` | Службы `AppXSvc`, `StateRepository`, `InstallService`, `TokenBroker`, политики `RemoveWindowsStore`, `DisableStoreApps`, `AllowAllTrustedApps`, сброс кэша `wsreset -i` |
| `25-start-search-shell.json` | `StartAndSearch` | Неработающий ввод с клавиатуры в Поиске и «Пуске» (`ctfmon.exe`), перерегистрация XAML-пакетов оболочки (`StartMenuExperienceHost`, `MicrosoftWindows.Client.CBS`, `Microsoft.UI.Xaml.CBS`), `WSearch`, `SystemEventsBroker`, `CoreMessagingRegistrar`, скрытые страницы Параметров (`SettingsPageVisibility`) |
| `30-explorer.json` | `ExplorerAndShell` | Чёрный экран после входа (`Winlogon\Shell = explorer.exe`), цикл выхода из системы (`Userinit`), скрытый Рабочий стол (`NoDesktop`), заблокированный правый клик (`NoViewContextMenu`), скрытые диски (`NoDrives`), Корзина, фильтры `UpperFilters`/`LowerFilters` приводов, базы `iconcache_*.db` |
| `35-blocked-tools-policies.json` | `SystemToolsAndPolicies` | Разблокировка `TaskMgr`, `regedit`, `cmd`, Панели управления и Параметров (`NoControlPanel`), `Win+R` (`NoRun`), Параметров папок (`NoFolderOptions`), консолей `MMC`, `DisallowRun`, снятие перехватчиков `IFEO\Debugger`, разблокировка Восстановления системы |
| `40-file-associations.json` | `FileAssociations` | Восстановление ассоциаций `.exe`, `.lnk` (включая удаление ошибочного `UserChoice\ProgId`, превращающего все ярлыки в Блокнот), `.msi`, `.bat`, `.cmd`, `.reg`, `.com`, сервера сценариев WSH и политики `NoFileAssociate` |
| `50-audio.json` | `AudioAndMedia` | Службы `AudioEndpointBuilder`, `Audiosrv`, `MMCSS`, Bluetooth-профили `bthserv`/`BTAGService`, снятие групповых запретов микрофона и веб-камеры (`ConsentStore` / `AppPrivacy`), `FrameServer` |
| `55-print.json` | `PrintingAndDevices` | Служба `Spooler` (включая «Print to PDF»), очистка зависших заданий в `spool\PRINTERS`, `PlugPlay`/`DeviceInstall`, служба сканеров `stisvc` (WIA) |
| `60-time.json` | `TimeAndRegion` | Служба `W32Time`, режим `Type != NoSync`, пересинхронизация часов с NTP-сервером при ошибках SSL-сертификатов (`0x800B0101`) |
| `65-security-firewall.json` | `SecurityAndFirewall` | Службы `BFE` и `mpssvc`, удаление троянских политик отключения Защитника (`DisableAntiSpyware`, `DisableRealtimeMonitoring`, `UILockdown`), восстановление `EnableLUA = 1`, `CryptSvc` и `KeyIso` |
| `70-wmi-installer.json` | `WmiAndInstaller` | Служба `msiserver`, политика `DisableMSI`, очистка `AlwaysInstallElevated`, `Winmgmt`, `EnableDCOM = Y`, проверка и мягкое восстановление `winmgmt /verifyrepository` -> `/salvagerepository` |
| `75-services-baseline.json` | `CriticalServices` | Базовые службы `Appinfo` (UAC), `EventLog`, `Schedule`, `VSS`/`swprv`, `Power`, `ProfSvc`, `Themes`, `XblAuthManager`/`XblGameSave` |
| `80-input-clipboard-fonts.json` | `InputClipboardAndFonts` | Буфер обмена `Win+V` (`AllowClipboardHistory`), снимки экрана `Win+Shift+S` (`DisableSnippingTool`), мультимедийные клавиши `hidserv`, служба и кэш шрифтов `FontCache`, перехват клавиш `Scancode Map` |
| `85-gaming-display-virtualization.json` | `DisplayGamingAndVirtualization` | Опасное отключение TDR видеодрайвера (`TdrLevel = 0`), принудительный софтверный рендеринг WPF, запуск гипервизора и `vmcompute` для WSL2 / Песочницы Windows, `PcaSvc` |
| `90-system-files-disk.json` | `SystemFilesAndDisk` | Анализ хвоста `CBS.log` + связка `DISM` / `SFC`, флаг «грязного тома» NTFS и запись в `%TEMP%`, контроль критической нехватки места на `C:\`, включение `TRIM` для SSD, запись малых дампов `Minidump`, восстановление `System32` в системном `PATH` |

---

## 3. Официальные среды выполнения (23 подписанных пакета)

Каталог `OfficialRuntimeCatalog` (`src/UltimateWindows.Modules.Repair/Catalog/OfficialRuntimeCatalog.cs`) включает:
- **Microsoft Visual C++ Redistributable**: 2005 SP1 (x86/x64), 2008 SP1 (x86/x64), 2010 SP1 (x86/x64), 2012 Update 4 (x86/x64), 2013 (x86/x64), 2015–2026 v14 (x86, x64, ARM64).
- **.NET и WebView2**: .NET Framework 3.5 (`DISM /FeatureName:NetFx3`), .NET Framework 4.8.1, .NET Desktop Runtime 6 LTS (x64), 8 LTS (x64/x86), 9 (x64), 10 LTS (x64), Microsoft Edge WebView2 Evergreen.
- **Игровые и графические библиотеки**: DirectX End-User Runtimes (June 2010), Microsoft XNA Framework 4.0 Refresh, OpenAL, Vulkan Runtime.

Пакетный сканер `InstalledProgramsDependencyScanner` проверяет основные `.exe` установленных программ из веток `Uninstall`, учитывая локальные подпапки установки (`bin\`, `lib\`) и сборки `WinSxS` (`vc80`/`vc90`), чтобы находить реальные ошибки `0xC000007B` и недостающие пакеты без ложных срабатываний.

---

## 4. Справочник кодов ошибок, анализатор сбоев и крайняя ступень восстановления

- **`ErrorCodeCatalog` (146+ кодов)**: поиск по шестнадцатеричной (`0xC000007B`, `0x80070005`, `0x800F081F`), знаковой десятичной (`-2147024891`), обычной десятичной (`1603`, `2503`) записи и тексту ошибки, автоматическая расшифровка кодов `0x8007XXXX` (Win32 в HRESULT) и все 76 кодов остановки синего экрана `BugCheckCatalog` с прямыми ссылками на правила ремонта и пакеты сред выполнения.
- **`AppCrashAnalyzer`**: чтение событий `Application` (`Event ID 1000`, `1002`, `1026`, `SideBySide 33/59/78`), `Microsoft-Windows-AppModel-Runtime/Admin` и `System` (`TDR 4101`, `WHEA 17/18/19`, `Kernel-Power 41`, `BugCheck 1001`) с переходом в `PE-Доктор` или к связанному правилу ремонта в 1 клик.
- **`CbsLogAnalyzer` и переустановка поверх (`ms-settings:recovery`)**: потоковое чтение последних 4 МБ `C:\Windows\Logs\CBS\CBS.log` в рамках последней транзакции `[SR]`; если хранилище компонентов повреждено глубже, чем способны исправить `DISM` и `SFC`, модуль оценивает свободное место и питание (`GetInPlaceReinstallReadiness`) и открывает штатное «Устранение неполадок с помощью Центра обновления Windows → Переустановить сейчас» без потери программ и личных файлов.

---

## 5. Команды CLI

```powershell
UltimateWindows.Cli repair-scan [раздел] [--issues]
UltimateWindows.Cli repair-fix <rule-id...> [--force]
UltimateWindows.Cli repair-fix --all-found [--force]
UltimateWindows.Cli error-lookup 0x80070005
UltimateWindows.Cli runtime-list
UltimateWindows.Cli runtime-install vcredist-2015-2022-x64
UltimateWindows.Cli deps-scan-installed
UltimateWindows.Cli cbs-scan
```
