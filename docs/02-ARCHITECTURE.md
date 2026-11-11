# 02. Техническая архитектура системы (Architecture)

Документ описывает выбор технологического стека, многоуровневую архитектуру, модели данных, системные API и механизмы безопасности проекта **UltimateWindows**.

---

## 1. Выбор технологического стека

Все ключевые эталонные open-source проекты экосистемы Windows (`hellzerg/optimizer`, `optimizerNXT`, `BlendLog/MinerSearch`, `LibreHardwareMonitor`, `lucasg/Dependencies`) написаны на **C# / .NET**. Для `UltimateWindows` выбран современный высокопроизводительный нативный стек без тяжеловесного браузерного движка (отказ от Electron/WebView в основном UI ради минимального потребления ОЗУ и мгновенного старта):

| Слой | Технология | Обоснование выбора |
|---|---|---|
| **Язык и рантайм** | **C# 14 / .NET 10 LTS (поддержка до ноября 2028)** | Высокая скорость работы, строгая типизация, встроенный `Span<T>` для парсинга бинарных структур (PE, Minidump, `$MFT`, SMBIOS), прямая интеграция с `LibreHardwareMonitorLib`, возможность сборки **Self-Contained Portable** (работает даже на «голой» сломанной Windows без установленного .NET!). |
| **Графический интерфейс (UI)** | **WPF + собственные Fluent-темы и стили + собственные примитивы MVVM** | В отличие от WinUI 3, который имеет известные ограничения при запуске от имени Администратора в портативном (Unpackaged) режиме и на Windows 10, связка `.NET 10 + WPF` с собственными Fluent-темами дает современный дизайн Windows 11, аппаратное ускорение DirectX, мгновенный запуск с флешки и 100% стабильность под `RunAs Administrator` как на Windows 10 (19045+), так и на Windows 11 (22H2–25H2+). |
| **Системные вызовы Win32 / Native** | **Ручные `DllImport`-обёртки в `UltimateWindows.NativeInterop` (без сторонних генераторов и без собственной C++-DLL)** | Обёртки для `SetupAPI`, `CfgMgr32`, `Advapi32`, `Iphlpapi`, `RestartManager`, `Wevtapi`, `WinTrust`, `IOCTL`; разбор PE, дампов ядра (`PAGEDU64`) и структур SMBIOS написан на C# со `Span<byte>`, поэтому отдельная нативная библиотека не нужна. |
| **Хранение журналов откатов и баз знаний** | **`Microsoft.Data.Sqlite` + подписанные JSON/YAML-манифесты** | Атомарное хранение истории транзакций отката, кэша сканирования и версионируемых правил очистки, оптимизации и сигнатур майнеров. |
| **Пакетный и CLI-режим** | **Собственный разбор аргументов в `UltimateWindows.Cli` + YAML-профили (собственный сериализатор)** | Поддержка безголового запуска (`ultimatewindows.exe --audit --profile gaming-safe.yaml`) для системных администраторов и быстрой настройки ПК после переустановки ОС. |

---

## 2. Высокоуровневая схема компонентов

Архитектура строится по принципу **модульного ядра с разделением привилегий и обязательным шлюзом транзакций (`Safety Gate`)**:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                   UltimateWindows.App (WPF Fluent UI / CLI)                 │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌────────────────────┐  │
│  │ Smart Audit  │ │  Optimizer   │ │ Vault-Safe   │ │ Hardware & Sensor  │  │
│  │  Dashboard   │ │ & Autoruns   │ │   Cleaner    │ │  Studio (AIDA-Pro) │  │
│  └──────────────┘ └──────────────┘ └──────────────┘ └────────────────────┘  │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌────────────────────┐  │
│  │  Anti-Miner  │ │   DLL &      │ │   Official   │ │  BSOD & System     │  │
│  │   Security   │ │ Runtime Doc  │ │ Driver Mgr   │ │   Error Doctor     │  │
│  └──────────────┘ └──────────────┘ └──────────────┘ └────────────────────┘  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Строго типизированная шина команд (MediatR / Command Pipeline)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                  SAFETY & TRANSACTION GATEWAY (Ядро защиты)                 │
│  1. Dry-Run Simulator (расчет списка изменений до выполнения)               │
│  2. VSS Restore Point Creator (SRSetRestorePointW с защитой от троттлинга)  │
│  3. State Snapshot & Rollback Journal (SQLite + .reg diff + .uwq карантин)  │
│  4. Authenticode & SHA-256 Verifier (WinVerifyTrust для всех загрузок)      │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
         ┌─────────────────────────────┼─────────────────────────────┐
         ▼                             ▼                             ▼
┌─────────────────────┐   ┌─────────────────────────┐   ┌─────────────────────┐
│ Read-Only Telemetry │   │ System Mutation Engine  │   │ Trusted Downloader  │
│  & Forensics Core   │   │ (Elevated Execution)    │   │ & Package Resolver  │
│ - CPUID / SMBIOS    │   │ - Registry Transactions │   │ - Winget / CDN      │
│ - NVAPI/ADLX/IGCL   │   │ - Service / Task / WMI  │   │ - WUApiLib Drivers  │
│ - S.M.A.R.T. IOCTL  │   │ - DISM / SFC / PnPUtil  │   │ - VC++ / DirectX /  │
│ - ETW / TCP / PE    │   │ - Quarantine Isolation  │   │   .NET Runtimes     │
└─────────────────────┘   └─────────────────────────┘   └─────────────────────┘
```

---

## 3. Структура репозитория (Target Solution Structure)

```text
UltimateWindows/
├── docs/
│   ├── 01-RESEARCH.md                  # Аналитика аналогов и инженерные выводы
│   ├── 02-ARCHITECTURE.md              # Архитектура и спецификация подсистем
│   └── 03-ROADMAP.md                   # План разработки по фазам и спринтам
├── rules/                              # Декларативные базы знаний (обновляемые без перекомпиляции)
│   ├── tweaks/                         # JSON/YAML описания обратимых твиков ОС
│   ├── cleaners/                       # Правила очистки с белыми списками защиты паролей/форм
│   ├── runtimes/                       # Карта DLL -> официальные подписанные пакеты Microsoft/Khronos
│   ├── miner-indicators/               # Эвристики майнеров, порты Stratum, домены пулов, пути маскировки
│   └── repair-playbooks/               # Сценарии лечения типовых кодов ошибок ОС и BSOD
├── src/
│   ├── UltimateWindows.Core/           # Базовые контракты, журнал транзакций, движок откатов, криптопроверка
│   ├── UltimateWindows.NativeInterop/  # P/Invoke обертки (SetupAPI, CfgMgr32, RestartMgr, Wevtapi, IOCTL)
│   ├── UltimateWindows.Modules.Safety/         # VSS точки восстановления, карантин .uwq, откат состояния
│   ├── UltimateWindows.Modules.Optimizer/      # Твики приватности/производительности, службы, UWP, Hosts, DNS/DoH
│   ├── UltimateWindows.Modules.Cleaner/        # Очистка диска, браузеров (Vault-Safe), гигиена реестра, MFT-карта диска
│   ├── UltimateWindows.Modules.AntiMiner/      # Поведенческий и сигнатурный поиск майнеров, WMI/Task/IFEO ревизия
│   ├── UltimateWindows.Modules.DllDoctor/      # PE-анализатор зависимостей (0xc000007b), автоустановщик VC++/DX/.NET
│   ├── UltimateWindows.Modules.Drivers/        # Инвентаризация PnP-устройств, WUApiLib, бэкап DriverStore
│   ├── UltimateWindows.Modules.SystemRepair/   # Анализатор BSOD минидампов, Event Log, ремонт подсистем ОС
│   ├── UltimateWindows.Modules.Hardware/       # Датчики (GPU/CPU/NVMe/SMBIOS/EDID), стресс-тест, Hardware Advisor
│   ├── UltimateWindows.Modules.AppsAndNet/     # Деинсталлятор с зачисткой следов, Winget-центр, автозагрузка, сеть
│   ├── UltimateWindows.Cli/            # Консольный интерфейс и автоматизация по YAML-шаблонам
│   └── UltimateWindows.App/            # Главное графическое приложение (WPF + Fluent Design)
└── tests/
    ├── UltimateWindows.UnitTests/      # Модульные тесты парсеров (PE, браузеры, реестр, правила твиков)
    └── UltimateWindows.IntegrationTests/ # Интеграционные тесты на изолированных виртуальных стендах Windows
```

---

## 4. Детальное проектирование ключевых подсистем

### 4.1. Ядро транзакций и отката (`UltimateWindows.Modules.Safety`)
Ни один модуль не имеет права напрямую удалять файл или перезаписывать ключ реестра в обход `ITransactionSession`:

```csharp
public interface ITransactionSession : IAsyncDisposable
{
    Guid SessionId { get; }
    string Title { get; }
    Task CreateSystemRestorePointAsync(CancellationToken ct);
    Task RecordRegistryChangeAsync(RegistryHive hive, string subKey, string? valueName, CancellationToken ct);
    Task QuarantineFileAsync(string filePath, QuarantineReason reason, CancellationToken ct);
    Task QuarantineScheduledTaskAsync(string taskPath, CancellationToken ct);
    Task ExportDriverBackupAsync(string publishedInfName, CancellationToken ct);
    Task CommitAsync(CancellationToken ct);
    Task RollbackAsync(CancellationToken ct);
}
```

- **Хранилище транзакций:** `%ProgramData%\UltimateWindows\Vault\transactions.db` (SQLite с защищенным ACL `SYSTEM` + `Administrators`).
- **Карантинный контейнер (`.uwq`):** при лечении майнера или очистке сомнительного объекта файл не просто удаляется, а сжимается (`Zstd`/`Deflate`), шифруется локальным ключом (чтобы антивирус не срабатывал на лежащий в карантине образец, и образец не мог запуститься) и снабжается JSON-манифестом с исходным путем, правами NTFS ACL, хэшем SHA-256 и связанными ключами реестра.

---

### 4.2. Модуль бережной очистки и гигиены реестра (`UltimateWindows.Modules.Cleaner`)

#### Архитектура защиты паролей и форм (`BrowserVaultGuard`)
Перед запуском любого правила очистки браузера срабатывает жесткий инвариант на уровне кода (`Hardcoded Safety Invariant`), который **перехватывает и блокирует** попытку удаления защищенных путей, даже если в JSON-правиле допущена ошибка:
- Защищенный список имен файлов Chromium: `Login Data*`, `Web Data*`, `Bookmarks*`, `Preferences`, `Secure Preferences`, `Local State`, `Extension Cookies*`, каталоги `Local Extension Settings`, `Sync Extension Settings`, `Managed Extension Settings`.
- Защищенный список Firefox: `logins.json`, `logins-backup.json`, `key3.db`, `key4.db`, `cert9.db`, `formhistory.sqlite`, `places.sqlite`, `favicons.sqlite`, `prefs.js`.
- **Проверка блокировки процесса:** перед очисткой кэша браузера через `Restart Manager API` проверяется, не открыт ли браузер. Если открыт — выводится аккуратное уведомление с предложением пропустить его или мягко закрыть с сохранением сессии вкладок (без `Kill`, ломающего профиль!).

#### Сканер диска `$MFT`
- Для локальных томов NTFS открывается дескриптор тома `\\.\C:` с правами чтения, вызывается `FSCTL_GET_NTFS_VOLUME_DATA` и `FSCTL_ENUM_USN_DATA`, что позволяет построить полное дерево размеров всех папок на диске 1 ТБ за ~2 секунды и показать пользователю наглядную интерактивную карту занятого места.

---

### 4.3. Модуль поиска майнеров и скрытых угроз (`UltimateWindows.Modules.AntiMiner`)

Конвейер состоит из **4 эшелонов детекта** с расчетом суммарного индекса подозрительности (`Risk Score 0..100`):

1. **Эшелон 1 — Стелс-профилирование нагрузки (`Pre-Scan Telemetry`):**
   - При старте сканирования до открытия любых подозрительных заголовков в течение 3 секунд снимается срез загрузки `GPU Compute/3D` и потоков CPU через `ETW` / `NtQuerySystemInformation(SystemProcessInformation)`.
   - Затем создается фантомное невидимое окно с заголовком `Диспетчер задач` / `Task Manager`. Если у какого-либо процесса потребление CPU/GPU падает более чем на 60% за 500 мс после появления этого окна — процесс получает флаг **`EvasiveMinerBehavior (Score +85)`**!
2. **Эшелон 2 — Сетевая и криптографическая инспекция процессов:**
   - Проверка `GetExtendedTcpTable` + DNS-кэша на соединения с пулами и Stratum-портами;
   - Проверка цифровой подписи (`WinVerifyTrust` + `CryptCATAdmin` для системных бинарников Windows);
   - Поиск исполняемых файлов с высокой энтропией секций или характерными строками (`rx/0`, `randomx`, `kawpow`, `ethash`, `stratum+tcp`, `donate-level`, `opencl-platform`, `cuda-loader`) в нестандартных путях (`%AppData%`, `%LocalAppData%\Temp`, `%ProgramData%`, `C:\Users\Public`).
3. **Эшелон 3 — Аудит механизмов закрепления (`Persistence Graph`):**
   - Службы Windows (`HKLM\SYSTEM\CurrentControlSet\Services`) с путями вне `System32`/`Program Files` или без подписи;
   - Задачи планировщика (`TaskCache\Tree` + XML в `System32\Tasks`), включая скрытые задачи с удаленным `SD` и задачи, запускающие `powershell -enc`, `mshta`, `wscript`, `cmd /c`, `curl`;
   - Постоянные подписки WMI (`root\subscription`);
   - Ветки `Run`, `RunOnce`, `Winlogon\Shell`, `Winlogon\Userinit`, `AppInit_DLLs`, `IFEO Debugger`.
4. **Эшелон 4 — Реабилитация системы после майнера (`Post-Infection Healer`):**
   - Автоматическая очистка вредоносных записей `hosts`, разблокировка запуска `taskmgr`/`regedit` (снятие `IFEO` и политик `DisableTaskMgr` / `DisableRegistryTools`), удаление блокирующих правил брандмауэра и восстановление службы `SecurityHealthService` / `wuauserv`, если майнер их повредил.

---

### 4.4. Модуль правильной установки DLL и сред выполнения (`UltimateWindows.Modules.DllDoctor`)

Архитектура работы модуля исключает ручное копирование сомнительных DLL:

```text
[Проблемный .exe или событие сбоя в Event Log (ID 1000 / SideBySide ID 33)]
        │
        ▼
[PE Header & Import Table Analyzer]
  ├─ Определение архитектуры .exe (x86 / x64 / ARM64)
  ├─ Построение графа зависимостей с учетом системного поиска (KnownDLLs, ApiSets, SxS, System32/SysWOW64, AppDir)
  ├─ Проверка разрядности каждой найденной DLL -> Детект ошибки 0xc000007b (например, x86 DLL лежит в папке с x64 игрой!)
  └─ Формирование списка отсутствующих или поврежденных модулей
        │
        ▼
[Runtime Catalog Matcher (rules/runtimes/catalog.json)]
  ├─ Сопоставление отсутствующей DLL с официальным пакетом (VC++ 2005..2022, DirectX June 2010, .NET, OpenAL, XNA, Vulkan)
  ├─ Проверка, касается ли поломка системной библиотеки ОС (kernelbase, ntdll, d3d11, urlmon и т.д.)
  │     └─ Если системная ОС DLL битая -> Запуск конвейера DISM RestoreHealth + SFC
  └─ Скачивание официального установщика с CDN Microsoft / через Winget -> Проверка подписи WinVerifyTrust -> Тихая установка нужной пары x86+x64
```

Также предусмотрен режим **«Полная профилактика игровых и рабочих библиотек (All-in-One Runtimes)»**, который за один проход проверяет наличие всех актуальных выпусков Visual C++ (2005–2022 x86/x64), DirectX 9.0c Legacy, .NET Framework 3.5/4.8 и .NET Desktop 6/8, устанавливая только недостающие или устаревшие пакеты.

---

### 4.5. Модуль поиска и установки драйверов (`UltimateWindows.Modules.Drivers`)

1. **Сканирование дерева PnP:**
   - Чтение всех узлов через `CM_Get_Child` / `CM_Get_Sibling`, извлечение `DEVPKEY_Device_HardwareIds`, `DEVPKEY_Device_CompatibleIds`, `DEVPKEY_Device_DriverVersion`, `DEVPKEY_Device_DriverDate`, `DEVPKEY_Device_DriverInfPath` и кода проблемы `CM_Get_DevNode_Status`.
2. **Поиск обновлений и недостающих драйверов:**
   - Запрос к `WUApiLib.UpdateSession` (`Type='Driver'`) — находит как обязательные, так и скрытые в недрах настроек Windows «Дополнительные обновления драйверов» (чипсеты Intel/AMD, контроллеры SMBus, MEI, картридеры, принтеры, Bluetooth-адаптеры).
   - Модуль профилей OEM для видеокарт и сетевых адаптеров (с различением ноутбучных гибридных графических систем Optimus / AMD SmartShift и десктопных карт).
3. **Безопасная установка:**
   - Точка восстановления + экспорт старого драйвера через `pnputil /export-driver` в `%ProgramData%\UltimateWindows\DriverBackups\<Date>_<Device>\`;
   - Проверка `WinVerifyTrust` скачанного пакета (`.cat` файл драйвера обязан иметь валидную WHQL / Authenticode подпись!);
   - Установка через `DiInstallDriverW` / `pnputil /add-driver ... /install` с отслеживанием кода возврата и необходимости перезагрузки.

---

### 4.6. Аппаратный комплекс и настройка комплектующих (`UltimateWindows.Modules.Hardware`)

Модуль объединяет возможности **AIDA64** (инвентаризация + стресс-тестирование), **HWiNFO** (точные датчики) и **Умного советника по железу**:

1. **Паспорт системы (`Deep Hardware Inventory`):**
   - Полная расшифровка CPU (микроархитектура, техпроцесс, ревизия степпинга, уровни кэша L1/L2/L3, инструкции SSE4.2/AVX2/AVX-512, лимиты PL1/PL2 или PPT/TDC/EDC);
   - Материнская плата и BIOS/UEFI (версия AGESA / микрокода CPU, статус Secure Boot, TPM 2.0, HVCI, Resizable BAR);
   - Подсистема памяти (объем, частота, эффективная скорость МТ/с, режим каналов Single/Dual/Quad, первичные тайминги `CL-tRCD-tRP-tRAS`, профили JEDEC vs XMP/EXPO по слотам);
   - Видеоподсистема (GPU чип, ревизия, ROP/TMU/Shaders, тип и производитель VRAM, текущая и максимальная скорость шины `PCIe Gen X @ xY`);
   - Дисковая подсистема (протокол NVMe 1.3/1.4/2.0 vs AHCI SATA, скорость линий PCIe накопителя, полный S.M.A.R.T., остаток ресурса в %, объем прочитанных/записанных ТБ, счетчик ошибок CRC шлейфа `UDMA CRC Error Count`!).
2. **Автоматический аудит узких мест (`Hardware Bottleneck & Misconfiguration Engine`):**
   - Программа автоматически выдает список карточек «Потерянная производительность / Риск поломки», например:
     - *«Внимание: Ваша память DDR5-6000 работает на базовой частоте 4800 МГц (не включен профиль XMP/EXPO в BIOS)»*;
     - *«Планки ОЗУ установлены в слоты A1 и A2 (одноканальный режим). Переставьте вторую планку в слот B2 для двухканального режима (+20% пропускной способности)»*;
     - *«Монитор поддерживает 165 Гц, но в Windows установлено 60 Гц -> [Включить 165 Гц в 1 клик]»*;
     - *«На диске SATA обнаружено 142 ошибки передачи данных `UltraDMA CRC Error` — замените кабель SATA или проверьте разъем»*;
     - *«Температура Hotspot видеокарты под нагрузкой достигает 104°C (дельта с GPU Core > 25°C) — высохла термопаста на кристалле GPU»* (реальная диагностика уровня опытного сервисного инженера!).
3. **Модуль стресс-тестирования и бенчмарков:**
   - Встроенный тест стабильности CPU / FPU / Cache / RAM / GPU / Storage с защитным предохранителем (`Thermal Cutoff`: автоматическая остановка теста, если температура превышает заданный безопасный порог, чтобы не перегреть проблемный ноутбук).
4. **Тонкая настройка комплектующих (`Safe Hardware Tuning`):**
   - Управление профилями питания Windows и скрытыми настройками процессора (Boost Policy, Core Parking, Energy Performance Preference `EPP`);
   - Настройка кривых вентиляторов и безопасных лимитов энергопотребления видеокарты через официальные API вендоров.

---

## 5. UX-концепция: «Одна кнопка для новичка — полная прозрачность для профи»

Главный экран программы строится в двух режимах переключения:

1. **Режим «Комплексный Умный Аудит» (1-Click Health Check):**
   - Нажатие одной кнопки запускает параллельное неразрушающее сканирование за 15–30 секунд по 6 направлениям: *Безопасность и майнеры*, *Целостность ОС и ошибки/BSOD*, *Мусор и кэш*, *Драйверы и библиотеки DLL*, *Оптимизация и автозагрузка*, *Здоровье и настройка железа*.
   - Система выставляет понятный индекс состояния ПК (`0–100 баллов`), группирует найденные проблемы по критичности, показывает точный список того, что будет сделано (никаких скрытых правок!), создает точку восстановления и исправляет выбранные пункты.
2. **Инженерный режим (Expert Studio):**
   - Левое навигационное меню с прямым доступом ко всем глубоким инструментам: графикам датчиков, карте диска `$MFT`, анализатору PE-зависимостей DLL, просмотрщику минидампов BSOD, редактору автозагрузки и контекстного меню, конструктору YAML-профилей настройки и истории откатов `Time-Machine`.

---

## 6. Ограничения области применения (Security & Legal Non-Goals)

- Приложение **не содержит и не поддерживает** модули обхода лицензионной защиты (DRM), эмуляторы KMS, модификаторы системных файлов лицензирования (`sppobjs`, `ospp`, `ClipSVC`) или неофициальные активаторы Windows / Office / ESU.
- Приложение **не использует** уязвимые драйверы из черного списка Microsoft (`DriverBlockList`) и не отключает `Windows Defender` / `Tamper Protection`.
- Любые сетевые загрузки выполняются строго по `HTTPS` (TLS 1.2/1.3) с обязательной проверкой цепочки сертификатов и цифровой подписи исполняемых пакетов перед запуском.
