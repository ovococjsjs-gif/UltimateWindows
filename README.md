# UltimateWindows

**UltimateWindows** — модульный центр комплексного обслуживания, диагностики, восстановления, очистки, защиты и тонкой настройки Windows 10 / Windows 11 (x64 / ARM64).

Цель проекта — объединить лучшие инженерные решения разрозненных системных утилит (оптимизаторов, детекторов скрытых майнеров, очистителей диска и реестра, менеджеров драйверов и системных библиотек, аппаратных анализаторов уровня AIDA64/HWiNFO) в едином быстром нативном приложении с **гарантией безопасности и 100% обратимости каждого действия**.

---

## Ключевые архитектурные принципы

1. **Принцип «Не навреди» и транзакционный откат (Time-Machine Rollback)**
   Каждое изменение реестра, служб, планировщика задач или файловой системы записывается в локальный журнал транзакций с автоматическим созданием точки восстановления VSS и экспортом затронутых ключей/файлов. Любое действие отменяется в один клик.
2. **Бережная очистка с защитой личных данных (Vault-Safe Cleaning)**
   Гранулярный разбор профилей браузеров (Chromium и Gecko): агрессивное удаление гигабайтов кэша шейдеров, Service Worker и медиа-кэша при **жесткой блокировке удаления** баз паролей (`Login Data`, `logins.json`), автозаполнения форм (`Web Data`, `formhistory.sqlite`), закладок и данных расширений (включая 2FA и криптокошельки), если пользователь явно не запросил иное.
3. **Правильное лечение DLL и сред выполнения (No Loose DLLs)**
   Полный отказ от опасной практики скачивания одиночных `.dll` из сомнительных источников. Вместо этого — разбор PE-заголовков и таблиц импорта проблемного `.exe` (выявление `0xc000007b` x86/x64 несовместимости), автоматический подбор и установка официальных подписанных пакетов Microsoft Visual C++ (2005–2022), DirectX End-User Runtime, .NET, Vulkan/OpenAL и восстановление системного хранилища через `DISM` + `SFC`.
4. **Совместимость с современной защитой ядра (HVCI / Core Isolation / Anti-Cheat)**
   Отказ от устаревших уязвимых драйверов вроде `WinRing0x64.sys`, блокируемых Windows 11 и античитами (Vanguard/FaceIt). Использование современных подписанных интерфейсов (`PawnIO`, `NVAPI`, `AMD ADLX`, `Intel IGCL`, `SMBIOS`, `NVMe IOCTL`, `ETW`/`PDH`).
5. **Строгая легальность и прозрачность**
   Проект работает исключительно в рамках легальных механизмов администрирования Windows: используются только подписанные WHQL/Authenticode драйверы и официальные дистрибутивы библиотек, не отключаются базовые защитные механизмы ОС (Windows Defender / Tamper Protection) и **не включаются** функции обхода лицензирования/DRM или неавторизованной активации ПО.

---

## Модули системы

| № | Модуль | Референсы | Ключевые улучшения в UltimateWindows |
|---|---|---|---|
| **1** | **Rollback & Safety Core** | Системное восстановление Windows | Автоматический журнал транзакций (JSON + `.reg` diff + VSS), режим предпросмотра (`Dry-Run`) перед применением любых правок |
| **2** | **Smart Optimizer & Privacy** | `hellzerg/optimizer`, `optimizerNXT`, `WinUtil` | Обратимые профили приватности и производительности, индикатор реального эффекта каждого твика, YAML-шаблоны настройки без поломки Windows Update/Xbox/Store |
| **3** | **Anti-Miner & Persistence Hunter** | `BlendLog/MinerSearch`, `Sysinternals Autoruns` | Детект майнеров, прячущихся при открытии диспетчера задач (анализ падения загрузки GPU/CPU через ETW), поиск Stratum-соединений, IFEO-перехватов, WMI-подписок, скрытых задач без `SD` и обратимый карантин |
| **4** | **Vault-Safe Cleaner & Registry Hygiene** | `CCleaner`, `BleachBit`, `WizTree` | Очистка кэша ОС, шейдеров GPU и браузеров с гарантированным сохранением паролей и автозаполнения форм; безопасная верифицированная чистка сирот реестра без поломки COM/WinRT; мгновенная карта диска по NTFS `$MFT` |
| **5** | **Official Driver Engine** | `WUApiLib`, `SDIO`, OEM-каталоги | Поиск по полному 4-компонентному Hardware ID (`VEN/DEV/SUBSYS/REV`), проверка цифровой подписи `WinVerifyTrust`, авто-бэкап текущих драйверов через `pnputil /export-driver` |
| **6** | **DLL & Runtime Doctor** | `lucasg/Dependencies`, `abbodi1406/vcredist` | Диагностика ошибок `0xc000007b` и отсутствующих DLL по PE-таблице импорта, автоустановка официальных пакетов VC++, DirectX, .NET, XNA, OpenAL и проверка целостности `WinSxS` (`DISM` + `SFC`) |
| **7** | **System & BSOD Auto-Fixer** | `WhoCrashed`, Windows Troubleshooters | Расшифровка минидампов BSOD (`C:\Windows\Minidump`), анализ критических событий `WHEA-Logger` / `Kernel-Power` / `TDR`, одно-кликовые рецепты починки сети, центра обновлений, WMI, печати и хранилища Appx |
| **8** | **Hardware Diagnostics & Tuner** | `AIDA64`, `LibreHardwareMonitor`, `HWiNFO` | Глубокий аудит железа, S.M.A.R.T. NVMe/SSD, детектор скрытых узких мест (не включен XMP/EXPO, видеокарта в режиме PCIe x8 вместо x16, монитор 144 Гц работает на 60 Гц, отключен Resizable BAR, перегрев/троттлинг) и безопасная настройка энергопотребления и кривых вентиляторов |
| **9** | **App Lifecycle, Startup & Network** | `Bulk Crap Uninstaller`, `Winget` | Пакетная установка и обновление программ через `winget`, полное удаление программ с зачисткой хвостов, менеджер автозагрузки и медленных расширений контекстного меню Проводника, тест задержек сети (Bufferbloat / DoH DNS) |

---

## Документация проекта

Вся аналитическая и архитектурная документация расположена в каталоге [`docs/`](./docs):

- [**`docs/01-RESEARCH.md`**](./docs/01-RESEARCH.md) — Детальное исследование существующих решений (`Optimizer` / `OptimizerNXT`, `MinerSearch`, `CCleaner` / `BleachBit`, менеджеров драйверов и DLL, `AIDA64` / `LibreHardwareMonitor`), разбор их кодовой базы, ограничений, рисков и конкретных точек роста.
- [**`docs/02-ARCHITECTURE.md`**](./docs/02-ARCHITECTURE.md) — Техническая архитектура `UltimateWindows`, выбор технологического стека (`.NET 8`, `C#`, `WPF Fluent`, `CsWin32`), структура модулей, схемы баз знаний и механизмов безопасности.
- [**`docs/03-ROADMAP.md`**](./docs/03-ROADMAP.md) — Поэтапный план разработки (от ядра транзакций и MVP до релиза `v1.0` и `v2.0`), стратегия тестирования на виртуальных стендах, CI/CD и цифровая подпись.
- [**`docs/04-UX-AND-VAULT-DESIGN.md`**](./docs/04-UX-AND-VAULT-DESIGN.md) — Дизайн дружелюбного двухуровневого интерфейса (`Простой ↔ Эксперт`) и система не засоряющих ОС бэкапов (`Zero-Bloat Vault`).
- [**`docs/05-AUDIT-AND-GAP-ANALYSIS.md`**](./docs/05-AUDIT-AND-GAP-ANALYSIS.md) — Аудит текущего кода (ноябрь 2026), измеренное сравнение с эталонами, матрица разрывов и поэтапный план доведения до их уровня.

---

## Быстрый старт и сборка (Релиз v1.0 — Все Фазы 0–6 Реализованы ✅)

Требования: **.NET 8.0 SDK** на Windows 10 / Windows 11.

```powershell
# Восстановление зависимостей и сборка всего решения (12 проектов)
dotnet build UltimateWindows.sln -c Release

# Запуск всех модульных тестов (Vault, Hardware, Cleaner, PE/BSOD Repair, Optimizer, Anti-Miner & WHQL Drivers / Smart Audit)
dotnet test UltimateWindows.sln -c Release

# Запуск графического интерфейса (User-Friendly Fluent GUI с переключателем Простой ↔ Эксперт)
dotnet run --project src/UltimateWindows.App/UltimateWindows.App.csproj

# Примеры использования консольного интерфейса (CLI)
dotnet run --project src/UltimateWindows.Cli/UltimateWindows.Cli.csproj -- smart-audit
dotnet run --project src/UltimateWindows.Cli/UltimateWindows.Cli.csproj -- hardware-audit
dotnet run --project src/UltimateWindows.Cli/UltimateWindows.Cli.csproj -- drivers-audit --online
dotnet run --project src/UltimateWindows.Cli/UltimateWindows.Cli.csproj -- driver-backup oem42.inf
dotnet run --project src/UltimateWindows.Cli/UltimateWindows.Cli.csproj -- clean-scan
dotnet run --project src/UltimateWindows.Cli/UltimateWindows.Cli.csproj -- pe-doctor "C:\Games\App\game.exe"
dotnet run --project src/UltimateWindows.Cli/UltimateWindows.Cli.csproj -- bsod-scan
dotnet run --project src/UltimateWindows.Cli/UltimateWindows.Cli.csproj -- tweak-list
dotnet run --project src/UltimateWindows.Cli/UltimateWindows.Cli.csproj -- tweak-export "my-profile.yaml"
dotnet run --project src/UltimateWindows.Cli/UltimateWindows.Cli.csproj -- unlock-check "D:\LockedFolder"
dotnet run --project src/UltimateWindows.Cli/UltimateWindows.Cli.csproj -- miner-scan
dotnet run --project src/UltimateWindows.Cli/UltimateWindows.Cli.csproj -- miner-heal-os
```

### Сборка автономной портативной версии (`Single-File Portable .exe`)

В репозитории настроен одно-кликовый сборщик `scripts/build-portable-release.ps1` (и ярлык двойного клика `scripts/build-portable-release.cmd`), который прогоняет модульные тесты, компилирует самодостаточные однофайловые `UltimateWindows.exe` + `UltimateWindows.Cli.exe` (не требующие установленного `.NET 8`), кладет рядом маркер `.portable` (чтобы хранилище `Zero-Bloat Vault` работало строго внутри папки `.\Data\Vault\` на флешке без следов на диске `C:\`), считает `SHA-256` и упаковывает релиз в `.zip`:

```powershell
# Локальная сборка портативного архива artifacts\UltimateWindows-v1.0.0-win-x64-portable.zip
.\scripts\build-portable-release.ps1

# Сборка и автоматическая привязка бинарного архива к релизу v1.0.0 в GitHub Releases
.\scripts\build-portable-release.ps1 -UploadToGitHubRelease -ReleaseTag "v1.0.0"
```

