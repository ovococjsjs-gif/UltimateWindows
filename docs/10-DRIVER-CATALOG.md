# 10. Архитектура «Драйверы 2.0» и Каталог основных драйверов с серверов

Документ описывает устройство **Этапа 5 («Драйверы 2.0»)** модуля `UltimateWindows.Modules.Drivers` и нативного моста `WindowsDriverPlatformBridge`.

---

## 1. Ключевая идея: максимум пользы на все случаи жизни без раздувания портативного архива

Обычные «драйвер-паки» страдают двумя крайностями:
1. Либо весят 25–45 ГБ и тянут с собой рекламное ПО и неподписанные перепаковки.
2. Либо умеют опрашивать только локальную службу Windows Update, которая бесполезна при подготовке флешки для другого ПК, установке драйвера Intel VMD в установщике ОС или поиске редкого чипа по `Hardware ID`.

В **UltimateWindows («Драйверы 2.0»)** сам исполняемый архив остаётся компактным (~92 МБ), а внутри встроен выверенный **серверный каталог из 39 ключевых пакетов драйверов в 10 жизненных категориях** (`Data/essential-drivers.json`) + **прямой HTTP-клиент Каталога Microsoft Update** (`MicrosoftUpdateCatalogClient`), позволяющий скачивать официальные подписанные `.cab`, `.zip`, `.msi` и `.exe` пакеты напрямую с серверов Microsoft (`*.download.windowsupdate.com`), Intel, Red Hat Fedora, Google и GitHub с обязательной проверкой цифровой подписи `WinVerifyTrust` / `CatRoot` и контрольной суммы SHA-1/SHA-256.

---

## 2. Полный опрос всех устройств ПК (`CfgMgr32` + реестр классов + подписи `.sys`)

`WindowsDriverPlatformBridge.EnumerateDevicesAsync` обходит всё дерево устройств Windows (`CM_Locate_DevNodeW`, `CM_Get_Child`, `CM_Get_Sibling`) и для каждого узла собирает:
- понятное имя (`CM_DRP_FRIENDLYNAME` / `CM_DRP_DEVICEDESC`), класс, изготовителя и физическое расположение (`CM_DRP_LOCATION_INFORMATION`);
- полные списки `HardwareIds` (`VEN_xxxx&DEV_xxxx&SUBSYS_xxxxxxxx&REV_xx`) и `CompatibleIds`;
- реального поставщика (`ProviderName`), версию (`DriverVersion`), нормализованную дату (`DriverDate` в ISO `yyyy-MM-dd`), пакет `oemXX.inf` и `MatchingDeviceId` из `HKLM\SYSTEM\CurrentControlSet\Control\Class`;
- привязанную ядерную службу (`CM_DRP_SERVICE`), путь к `.sys` файлу и статус доверенной подписи `AuthenticodeVerifier.IsFileTrustedSigned` (встроенная PE-подпись + системные каталоги `CatRoot`);
- коды проблем диспетчера устройств, включая **Код 28** (драйвер не установлен), **Код 43** (сбой устройства/питания), **Код 48** (заблокирован уязвимый драйвер) и **Код 52** (отсутствует цифровая подпись WHQL), а также базовый аварийный видеодрайвер `basicdisplay.inf`.

Из таблицы устройств в 1 клик доступна кнопка **«В Каталог»**, которая автоматически формирует точный поисковый ключ `PCI\VEN_xxxx&DEV_xxxx` / `USB\VID_xxxx&PID_xxxx` и ищет пакеты `.cab` на сервере `catalog.update.microsoft.com`.

---

## 3. Серверный каталог из 39 драйверов на все случаи жизни (`Data/essential-drivers.json`)

Каждый пакет оценивается относительно оборудования текущего ПК (`Требуется этому ПК!` / `Есть в этом ПК` / `Универсальный в копилку`), может быть как **скачан и распакован в папку** (для переноса на флешке), так и **сразу установлен** через `pnputil /add-driver /subdirs /install` с предварительной точкой отката в «Машине времени».

| Категория | Пакеты в каталоге | Сценарии применения |
|---|---|---|
| **1. Проводная сеть (LAN)** | Realtek 2.5GbE (`RTL8125`), Realtek 1GbE (`RTL8111/8168`), Intel 2.5GbE (`I225-V / I226-V`), Intel 1GbE (`I219-V / I217 / I211`), Realtek USB 2.5G/1G (`RTL8156 / RTL8153`), ASIX USB-LAN (`AX88179`), Qualcomm Killer (`E2600 / E3100`) | Нет интернета после чистой установки Windows на платах B550/B650/B760/Z790 или ультрабуках с USB-C док-станцией |
| **2. Беспроводная сеть (Wi-Fi)** | Intel Wi-Fi 6/6E/7 (`AX200 / AX201 / AX210 / AX211 / BE200`), MediaTek (`MT7921 / MT7922 / RZ616`), Realtek Wi-Fi 6 (`RTL8852AE/BE/CE`), Realtek Wi-Fi 5 (`RTL8821CE / RTL8822CE`), Qualcomm (`QCA6174 / WCN685x`), Broadcom (`BCM4360`) | Включение Wi-Fi на ноутбуках ASUS, Lenovo, MSI, Acer, HP и платах AMD/Intel со встроенным Wi-Fi |
| **3. Bluetooth и USB-модемы смартфонов** | Intel Wireless Bluetooth, Realtek Bluetooth, MediaTek Bluetooth, **Android USB RNDIS Tethering**, **Apple iPhone USB Mobile Device Ethernet**, **Google Android ADB & Fastboot USB** | Раздача интернета с телефона по кабелю, когда драйверов сетевой карты под рукой ещё нет, а также прошивка Android |
| **4. Видеокарты и автоподбор** | **Intel Driver & Support Assistant (DSA)**, базовый WHQL-драйвер NVIDIA GeForce, базовый WHQL-драйвер AMD Radeon | Включение родного разрешения и герцовки монитора вместо `Microsoft Basic Display Adapter`, автоопределение всех чипов Intel |
| **5. Чипсеты и тачпады ноутбуков** | Intel Chipset INF (`SMBus / LPC / SPI`), Intel Management Engine (`MEI`), Intel Serial IO (`I2C / GPIO` для тачпадов!), AMD PCI / SMBus | Устранение «Неизвестных устройств PCI» в диспетчере устройств и оживление неработающего тачпада ноутбука после переустановки ОС |
| **6. Диски NVMe и контроллеры VMD/RAID** | **Intel RST VMD Controller (11th–14th Gen / Core Ultra)**, AMD Bottom/RAID NVMe, Samsung NVMe Controller | Решение главной проблемы современных ноутбуков: **«Установщик Windows не видит SSD NVMe»** (подсовывание распакованных INF на этапе выбора диска) |
| **7. Звук и аудиокодеки** | Realtek High Definition Audio, Intel Smart Sound Technology (`SST` — микрофоны ноутбуков) | Восстановление звука и встроенного массива микрофонов на современных ультрабуках |
| **8. USB-COM, Arduino, ESP32 и диагностика** | **WCH CH340 / CH341**, **Silicon Labs CP210x**, **FTDI FT232R** | Прошивка микроконтроллеров ESP32/Arduino, 3D-принтеров, сканеров OBD-II, кассового и сетевого оборудования (консольные кабели Cisco/MikroTik) |
| **9. Виртуальные машины (KVM / Proxmox)** | **Red Hat VirtIO Guest Tools (`.msi`)**, **Полный ISO-образ `virtio-win.iso`** | Установка и настройка гостевых Windows 10/11 в Proxmox VE, QEMU/KVM и облачных VPS (`NetKVM`, `viostor`, `qxl`) |
| **10. Периферия и безопасные датчики** | **Microsoft Xbox Wireless / USB Controller**, **PawnIO (`PawnIO_setup.exe`)** | Подключение геймпадов и легальная подписанная замена уязвимому драйверу `WinRing0x64.sys` при включённой изоляции ядра HVCI |

---

## 4. Прямой клиент Каталога Microsoft Update (`MicrosoftUpdateCatalogClient`)

1. Выполняет поиск по `https://www.catalog.update.microsoft.com/Search.aspx?q=<запрос>` и разбирает строки таблицы обновлений (название, список поддерживаемых версий Windows, классификация, дата выпуска, 4-компонентная версия, точный размер в байтах и `Update GUID`).
2. Разрешает прямую ссылку через `POST https://www.catalog.update.microsoft.com/DownloadDialog.aspx` и проверяет, что URL указывает строго на доверенные домены Microsoft (`*.download.windowsupdate.com` / `*.microsoft.com`).
3. Скачивает `.cab`, сверяет криптографический дайджест `SHA-1` с ответом каталога Microsoft, проверяет цифровую подпись `AuthenticodeVerifier.IsFileTrustedSigned` (как самого `.cab`, так и распакованного `.cat`), распаковывает штатным `expand.exe -F:*` и при необходимости устанавливает через `pnputil.exe /add-driver *.inf /subdirs /install`.

---

## 5. Хранилище `DriverStore`, полный бэкап и Офлайн-набор спасения сети

- **Локаленезависимая ревизия `DriverStore` (`EnumerateDriverStoreAsync`):** объединяет XML-вывод `pnputil /enum-drivers /format xml` (Windows 11 / Server 2025) с прямым разбором секций `[Version]` и `[Strings]` в `C:\Windows\INF\oem*.inf` и подсчётом точного объёма папок `C:\Windows\System32\DriverStore\FileRepository\*`. Одинаково работает на русской, английской и любой другой локали Windows 10 и Windows 11.
- **Безопасная очистка старых дублей (`CleanOldDriverStoreDuplicatesAsync`):** группирует сторонние пакеты по исходному имени INF и классу, **никогда не трогает** пакеты, привязанные к текущим устройствам, и сохраняет самую свежую резервную версию каждого драйвера. Старые неиспользуемые дубли перед удалением (`pnputil /delete-driver oemXX.inf` без `/force`) архивируются в транзакцию `ZeroBloatVaultService` (`DriverInfBackup:oemXX.inf`) с возможностью отката.
- **Офлайн-набор спасения («после переустановки нет интернета / не виден SSD»):**
  1. **Экспорт с этого ПК** — мгновенно выгружает текущие драйверы классов `Net`, `Bluetooth`, `Modem`, `USB`, `SCSIAdapter`, `HDC` этого компьютера.
  2. **Универсальный серверный набор для флешки** — скачивает и распаковывает с серверов Microsoft и Google 12 самых частых драйверов проводных карт 1G/2.5G, Wi-Fi 6/6E, USB-модемов Android/iPhone и контроллера Intel VMD NVMe.
  В обоих режимах автоматически создаётся пакетный скрипт `Install-OfflineDrivers.cmd` для установки всех драйверов в 1 клик без интернета.

---

## 6. Аудит уязвимых и заблокированных драйверов ядра (`BYOVD` / `LOLDrivers`)

Встроенный каталог `Data/vulnerable-drivers.json` содержит **18 семейств уязвимых драйверов ядра** (более 50 имён `.sys` и известных хешей SHA-256), активно используемых вредоносным ПО в атаках **BYOVD (Bring Your Own Vulnerable Driver)** для отключения защитных механизмов ядра, а также вызывающих проблемы с HVCI и античитами:
- `WinRing0x64.sys` / `WinRing0.sys` (`CVE-2020-14979`) — с рекомендацией перехода на подписанный `PawnIO`;
- `RTCore64.sys` (`CVE-2019-16098`), `gdrv.sys` (`CVE-2018-19320`), `dbutil_2_3.sys` (`CVE-2021-21551`), `iqvw64e.sys` (`CVE-2015-2291`);
- `EneIo64.sys` / `ene.sys` (`CVE-2020-12446`), `AsrDrv103.sys` / `AsrDrv106.sys`, `asio64.sys` / `glckio2.sys`, `atillk64.sys`, `capcom.sys`, `mhyprot2.sys`, `procEXP152.sys`, `phymemx64.sys`, `winio64.sys`, `rwdrv.sys`, `zam64.sys`, `speedfan.sys`, `cpuz141_x64.sys`.

Модуль проверяет все службы ядра (`Type = 1` / `2`), сверяет статус изоляции ядра `HVCI` и ключа `VulnerableDriverBlocklistEnable`, позволяет в 1 клик включить блок-лист Microsoft или обезвредить уязвимый драйвер (перевод службы в `Start = 4` + шифрование `.sys` в карантин `.uwq` с полным откатом через «Машину времени»).
