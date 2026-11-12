# 12. Программы, Автоматизация, Готовность к Windows 11 и Выпуск (Этап 7)

Завершающий 7-й этап развития **UltimateWindows v2.0** реализован в модуле `UltimateWindows.Modules.Apps` (`net10.0`), платформенном мосту `WindowsAppsPlatformBridge` (`UltimateWindows.NativeInterop`), разделе интерфейса **«Программы и Автопилот»** (`AppsWorkspaceView`) и CLI (`UltimateWindows.Cli`).

---

## 1. Обновление всех программ и Каталог первой необходимости (`winget`)

- **Локаленезависимый парсер `WingetOutputParser`** разбирает табличный вывод `winget upgrade --include-unknown --accept-source-agreements` и `winget list` независимо от языка интерфейса Windows (русский, английский и др.), корректно отсекая символы индикатора прогресса (`\r`, `█`, `-`, `\`, `|`, `/`), разделители колонок `---`, секцию закреплённых пакетов (`pinned`) и итоговые строки сводки.
- **Пакетное и выборочное тихое обновление** запускает `winget upgrade --id <Id> --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity`.
- **Встроенный каталог `essential-apps.json` (36 проверенных пакетов в 6 категориях)** включает только официальные дистрибутивы без рекламных установщиков:
  1. **Архиваторы и Утилиты (10):** `7-Zip`, `Notepad++`, `Everything`, `ShareX`, `Greenshot`, `Rufus`, `CPU-Z`, `GPU-Z`, `CrystalDiskInfo`, `HWiNFO`.
  2. **Браузеры (5):** `Mozilla Firefox`, `Google Chrome`, `Brave`, `Vivaldi`, `LibreWolf`.
  3. **Медиа и Документы (9):** `VLC`, `MPC-HC`, `AIMP`, `HandBrake`, `LibreOffice`, `SumatraPDF`, `FastStone Image Viewer`, `Audacity`, `GIMP 3`.
  4. **Общение и Доступ (4):** `Telegram Desktop`, `Discord`, `Zoom Workplace`, `RustDesk`.
  5. **Игры и Стриминг (4):** `Steam`, `Epic Games Launcher`, `GOG GALAXY`, `OBS Studio`.
  6. **Система и Разработка (4):** `Git for Windows`, `Visual Studio Code`, `Microsoft PowerToys`, `WireGuard`.
- Поддерживаются три готовых набора подбора в 1 клик (пропускающие уже установленные приложения): **«Чистая ОС»**, **«Игровой ПК»** и **«Разработка»**.

---

## 2. Чистый деинсталлятор с поиском хвостов и Принудительное удаление

- **`LeftoverSafetyGuard`** жестко блокирует пометку и удаление:
  - любых путей внутри профилей браузеров и баз паролей/куки (`BrowserVaultGuard`);
  - системных папок (`C:\Windows`, `C:\Program Files`, личных библиотек `Documents`, `Desktop`, `Pictures`);
  - общих корневых каталогов и веток реестра крупных издателей (`Microsoft`, `Google`, `Mozilla`, `NVIDIA`, `AMD`, `Intel`, `Valve` и др.).
- **`LeftoverScanner`** сопоставляет токены названия приложения, папки установки и ключа деинсталляции с каталогами `%LOCALAPPDATA%`, `%APPDATA%`, `%PROGRAMDATA%`, ярлыками `.lnk` и ветками `HKCU\Software\...` / `HKLM\Software\...`, исключая папки соседних всё ещё установленных программ.
- **100% обратимость через `ZeroBloatVaultService`**: удаляемые файлы помещаются в сжатый карантин `.uwq`, а удаляемые ветки реестра экспортируются в `.reg` (`AppRegistryExport:`) и восстанавливаются через `reg.exe import` при откате в «Машине времени».
- **Принудительное удаление (`ForceRemoveBrokenAppAsync`)** предназначено для программ с повреждённым или отсутствующим `uninstall.exe`: аккуратно останавливает процессы из папки установки, архивирует ветку `Uninstall\<Key>` и файлы в `ZeroBloatVaultService` и вычищает хвосты.

---

## 3. Готовность к Windows 11 (24H2/25H2), статус Windows 10 ESU, Батарея, Сон и Память

- **`Windows11ReadinessEvaluator`** проверяет 7 аппаратных и системных критериев:
  1. 64-разрядный процессор (`>= 2` ядер, `>= 1 ГГц`) + наличие инструкций **`SSE4.2` и `POPCNT`** (обязательных начиная с Windows 11 24H2);
  2. Оперативная память (`>= 4 ГБ`);
  3. Системный накопитель (`>= 64 ГБ`);
  4. Режим загрузки **UEFI** (`GetFirmwareType`) и таблица разделов **GPT** (`IOCTL_DISK_GET_DRIVE_LAYOUT_EX`);
  5. Активность **Secure Boot**;
  6. Наличие и версия **TPM 2.0** (`tbs.dll` `Tbsi_GetDeviceInfo`);
  7. Видеодрайвер **DirectX 12 / WDDM 2.0+**.
- **Честный статус жизненного цикла Windows 10**: информирует о завершении базовой поддержки `14.10.2025` и действии официальной потребительской программы расширенных обновлений безопасности **ESU до `12.10.2027`** без какого-либо обхода лицензирования.
- **Батарея, Сон и ОЗУ**: рассчитывает износ аккумулятора ноутбука (`DesignCapacity` vs `FullChargeCapacity`), выводит источник последнего пробуждения (`powercfg /lastwake`), активные блокировщики сна (`powercfg /requests`), сохраняет `powercfg /batteryreport` и разбирает события `Microsoft-Windows-MemoryDiagnostics-Results` из системного журнала (`mdsched.exe`).

---

## 4. Фоновый Автопилот и Единый диагностический архив (`.zip`)

- **Расписание обслуживания (`\UltimateWindows\AutoMaintenance`)**: настраиваемое штатное задание Планировщика Windows (ежедневно / еженедельно / ежемесячно, без постоянно висящих в фоне резидентных служб) с записью предыдущего XML-состояния в `ZeroBloatVaultService` (`MaintenanceScheduleTask`).
- **`SupportBundleExporter`**: одним кликом формирует компактный `.zip`-архив из трёх файлов (`01-DiagnosticSummary.html`, `02-HardwarePassport.html`, `03-DiagnosticData.json`), объединяющий индекс здоровья, паспорт железа и датчиков, проблемные драйверы, историю BSOD, готовность к Windows 11 и состояние защиты — **без паролей, куки и личных файлов**.

---

## 5. Команды CLI Этапа 7

```powershell
UltimateWindows.Cli apps-upgrades
UltimateWindows.Cli apps-upgrade --all
UltimateWindows.Cli apps-catalog --preset home
UltimateWindows.Cli apps-install 7zip
UltimateWindows.Cli apps-leftovers "ShareX"
UltimateWindows.Cli win11-check
UltimateWindows.Cli power-sleep
UltimateWindows.Cli auto-maintenance
UltimateWindows.Cli schedule-maintenance weekly --hour 12
UltimateWindows.Cli support-bundle --out "C:\Temp\Diag.zip"
```
