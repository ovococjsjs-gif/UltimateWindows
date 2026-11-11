# UltimateWindows

**UltimateWindows** — модульный центр комплексного обслуживания, диагностики, восстановления, очистки, защиты и тонкой настройки Windows 10 / Windows 11 (x64 / ARM64).

> **Статус (ноябрь 2026):** базовый каркас и первые версии всех модулей готовы, но до уровня топовых программ проект пока не доведён. Честный разбор того, что работает, а что пока только заявлено, — в [`docs/05-AUDIT-AND-GAP-ANALYSIS.md`](./docs/05-AUDIT-AND-GAP-ANALYSIS.md); работа идёт поэтапно по плану из его раздела 6.

Цель проекта — объединить лучшие инженерные решения разрозненных системных утилит (оптимизаторов, детекторов скрытых майнеров, очистителей диска и реестра, менеджеров драйверов и системных библиотек, аппаратных анализаторов уровня AIDA64/HWiNFO) в едином быстром нативном приложении с **гарантией безопасности и 100% обратимости каждого действия**.

---

## Ключевые архитектурные принципы

1. **Принцип «Не навреди» и транзакционный откат (Time-Machine Rollback)**
   Изменения параметров реестра, файлов и карантина записываются в локальный журнал транзакций (SQLite) вместе с прежними значениями, а крупные операции дополнительно подкрепляются точкой восстановления VSS. Откат — в один клик из раздела «Машина времени».
   Границы честно: откат покрывает изменения реестра, карантин файлов и установку пакетов. Такие действия, как удаление кэша, очистка очереди печати, сброс сети и сброс Центра обновления, записываются в журнал как факт, но вернуть удалённый мусор невозможно по своей природе.
2. **Бережная очистка с защитой личных данных (Vault-Safe Cleaning)**
   Гранулярный разбор профилей браузеров (Chromium и Gecko): агрессивное удаление гигабайтов кэша шейдеров, Service Worker и медиа-кэша при **жесткой блокировке удаления** баз паролей (`Login Data`, `logins.json`), автозаполнения форм (`Web Data`, `formhistory.sqlite`), закладок и данных расширений (включая 2FA и криптокошельки), если пользователь явно не запросил иное.
3. **Правильное лечение DLL и сред выполнения (No Loose DLLs)**
   Полный отказ от опасной практики скачивания одиночных `.dll` из сомнительных источников. Вместо этого — разбор PE-заголовков и таблиц импорта проблемного `.exe` (выявление `0xc000007b` x86/x64 несовместимости), автоматический подбор и установка официальных подписанных пакетов Microsoft Visual C++ (2005–2022), DirectX End-User Runtime, .NET, Vulkan/OpenAL и восстановление системного хранилища через `DISM` + `SFC`.
4. **Совместимость с современной защитой ядра (HVCI / Core Isolation / Anti-Cheat)**
   Отказ от устаревших уязвимых драйверов вроде `WinRing0x64.sys`, блокируемых Windows 11 и античитами. Используются только штатные интерфейсы пользовательского режима: `SMBIOS`, `NVMe IOCTL`, `CPUID`, `EDID`, `PDH`, `nvml.dll`.
   Обратная сторона честно: без ядерного драйвера (например, `PawnIO`) температура процессора, обороты вентиляторов и напряжения недоступны. Сейчас из датчиков читается только температура видеокарт NVIDIA; для остального интерфейс прямо пишет «датчик недоступен», а не показывает выдуманные числа.
5. **Легальность, прозрачность и честные пометки об опасном**
   Проект работает только в рамках легального администрирования Windows: подписанные WHQL/Authenticode драйверы, официальные дистрибутивы библиотек. Обход активации и лицензирования Windows заблокирован на уровне кода (`TweakSafetyGuard`) и не появится никогда.
   Настройки, которые ослабляют защиту системы (например, отключение Защитника Windows или SmartScreen), в проекте разрешены, но помечены как **опасные**: они не входят ни в один готовый набор, включаются только после отдельного подтверждения в интерфейсе и требуют явного ключа `--force` в CLI. Пользователь вправе распоряжаться своей системой, но не должен делать это случайно.

---

## Модули системы

| № | Модуль | Референсы | Ключевые улучшения в UltimateWindows |
|---|---|---|---|
| **1** | **Rollback & Safety Core** | Системное восстановление Windows | Автоматический журнал транзакций (JSON + `.reg` diff + VSS), режим предпросмотра (`Dry-Run`) перед применением любых правок |
| **2** | **Smart Optimizer & Privacy** | `hellzerg/optimizer`, `optimizerNXT`, `WinUtil` | Обратимые профили приватности и производительности, индикатор реального эффекта каждого твика, YAML-шаблоны настройки без поломки Windows Update/Xbox/Store |
| **3** | **Anti-Miner & Persistence Hunter** | `BlendLog/MinerSearch`, `Sysinternals Autoruns` | Детект майнеров, прячущихся при открытии диспетчера задач (анализ падения загрузки GPU/CPU через ETW), поиск Stratum-соединений, IFEO-перехватов, WMI-подписок, скрытых задач без `SD` и обратимый карантин |
| **4** | **Vault-Safe Cleaner & Registry Hygiene** | `CCleaner`, `BleachBit`, `WizTree` | Очистка кэша ОС, шейдеров GPU и браузеров с гарантированным сохранением паролей и автозаполнения форм; безопасная чистка сирот реестра без поломки COM/WinRT; карта диска обходом папок (чтение `$MFT` напрямую — в плане этапа 2) |
| **5** | **Official Driver Engine** | `WUApiLib`, `SDIO`, OEM-каталоги | Поиск по полному 4-компонентному Hardware ID (`VEN/DEV/SUBSYS/REV`), проверка цифровой подписи `WinVerifyTrust`, авто-бэкап текущих драйверов через `pnputil /export-driver` |
| **6** | **DLL & Runtime Doctor** | `lucasg/Dependencies`, `abbodi1406/vcredist` | Диагностика ошибок `0xc000007b` и отсутствующих DLL по PE-таблице импорта, автоустановка официальных пакетов VC++, DirectX, .NET, XNA, OpenAL и проверка целостности `WinSxS` (`DISM` + `SFC`) |
| **7** | **System & BSOD Auto-Fixer** | `WhoCrashed`, Windows Troubleshooters | Разбор дампов ядра (`PAGEDU64`/`PAGEDUMP`): код остановки из справочника из 76 кодов, список драйверов, стек вызовов и вероятный виновник с пометкой надёжности; отдельно распознаются дампы упавших программ (`MDMP`). Плюс анализ событий `WHEA-Logger` / `Kernel-Power` / `TDR` и рецепты починки сети, Центра обновления, WMI, печати и хранилища Appx |
| **8** | **Hardware Diagnostics & Tuner** | `AIDA64`, `LibreHardwareMonitor`, `HWiNFO` | Паспорт железа, S.M.A.R.T. NVMe/SSD, детектор скрытых узких мест (не включён XMP/EXPO, видеокарта в режиме PCIe x8 вместо x16, монитор 144 Гц работает на 60 Гц, троттлинг) и нагрузочный тест процессора. Датчики: только температура NVIDIA GPU; вентиляторы, напряжения и температура CPU — этап 6 (нужен подписанный драйвер `PawnIO`) |
| **9** | **App Lifecycle, Startup & Network** | `Bulk Crap Uninstaller`, `Winget` | Пакетная установка и обновление программ через `winget`, полное удаление программ с зачисткой хвостов, менеджер автозагрузки и медленных расширений контекстного меню Проводника, тест задержек сети (Bufferbloat / DoH DNS) |

---

## Документация проекта

Вся аналитическая и архитектурная документация расположена в каталоге [`docs/`](./docs):

- [**`docs/01-RESEARCH.md`**](./docs/01-RESEARCH.md) — Детальное исследование существующих решений (`Optimizer` / `OptimizerNXT`, `MinerSearch`, `CCleaner` / `BleachBit`, менеджеров драйверов и DLL, `AIDA64` / `LibreHardwareMonitor`), разбор их кодовой базы, ограничений, рисков и конкретных точек роста.
- [**`docs/02-ARCHITECTURE.md`**](./docs/02-ARCHITECTURE.md) — Техническая архитектура `UltimateWindows`, выбор технологического стека (`.NET 10`, `C#`, `WPF Fluent`), структура модулей, схемы баз знаний и механизмов безопасности.
- [**`docs/03-ROADMAP.md`**](./docs/03-ROADMAP.md) — Поэтапный план разработки (от ядра транзакций и MVP до релиза `v1.0` и `v2.0`), стратегия тестирования на виртуальных стендах, CI/CD и цифровая подпись.
- [**`docs/04-UX-AND-VAULT-DESIGN.md`**](./docs/04-UX-AND-VAULT-DESIGN.md) — Дизайн дружелюбного двухуровневого интерфейса (`Простой ↔ Эксперт`) и система не засоряющих ОС бэкапов (`Zero-Bloat Vault`).
- [**`docs/05-AUDIT-AND-GAP-ANALYSIS.md`**](./docs/05-AUDIT-AND-GAP-ANALYSIS.md) — Аудит текущего кода (ноябрь 2026), измеренное сравнение с эталонами, матрица разрывов и поэтапный план доведения до их уровня.

---

## Быстрый старт и сборка (Релиз v1.0 — Все Фазы 0–6 Реализованы ✅)

Требования: **.NET 10 SDK** на Windows 10 (22H2) или Windows 11. Версия SDK закреплена в [`global.json`](./global.json).

Проверка изменения одной командой (то же самое запускает GitHub Actions на каждый pull request):

```powershell
.\scripts\ci.ps1              # сборка + тесты + пробная сборка портативной версии
.\scripts\ci.ps1 -Step Test   # только тесты
```

```powershell
# Восстановление зависимостей и сборка всего решения
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

В репозитории настроен одно-кликовый сборщик `scripts/build-portable-release.ps1` (и ярлык двойного клика `scripts/build-portable-release.cmd`), который прогоняет модульные тесты, компилирует самодостаточные однофайловые `UltimateWindows.exe` + `UltimateWindows.Cli.exe` (не требующие установленного `.NET`), кладет рядом маркер `.portable` (чтобы хранилище `Zero-Bloat Vault` работало строго внутри папки `.\Data\Vault\` на флешке без следов на диске `C:\`), считает `SHA-256` и упаковывает релиз в `.zip`:

```powershell
# Локальная сборка портативного архива artifacts\UltimateWindows-v2.0.0-win-x64-portable.zip
.\scripts\build-portable-release.ps1

# Сборка и автоматическая привязка бинарного архива к релизу v2.0.0 в GitHub Releases
.\scripts\build-portable-release.ps1 -UploadToGitHubRelease -ReleaseTag "v2.0.0"
```

---

## Права администратора

Большинство исправлений (реестр `HKLM`, службы, драйверы, системные папки) невозможны без прав администратора, поэтому при запуске программа сама показывает штатный запрос UAC. Если пользователь откажется, программа продолжит работу в ограниченном режиме: диагностика и чтение доступны, исправления сообщат, что нужны права, а в верхней панели появится кнопка «получить права администратора».

- `UltimateWindows.exe --no-elevate` (с двумя дефисами) — запуск без запроса прав;
- `UltimateWindows.Cli.exe ...` — консольная версия прав не запрашивает и не показывает UAC.

## Проверка изменений (CI)

`.github/workflows/ci.yml` на каждый push и pull request запускает на `windows-latest` скрипт `scripts/ci.ps1`: сборка всего решения, модульные тесты и пробная сборка портативной версии. Итог каждого шага попадает в сводку запуска, а ошибки компиляции и упавшие тесты — в аннотации с файлом и строкой.

Пока файл рабочего процесса не добавлен в `.github/workflows/`, его готовое содержимое лежит в [`docs/ci-workflow-template.yml`](./docs/ci-workflow-template.yml) — скопируйте его в `.github/workflows/ci.yml`. Тот же скрипт можно запустить локально: `\.\scripts\ci.ps1`.

## Лицензия

Проект распространяется по лицензии **MIT** (см. [`LICENSE`](./LICENSE)): вы можете свободно использовать, изменять и распространять его, сохраняя уведомление об авторских правах.

Чужой код в проект не копируется. Из открытых программ (Optimizer, MinerSearch, BleachBit, privacy.sexy и других) берутся только идеи, приёмы и проверенные факты — например, имена кодов остановки Windows или расположение полей в дампах ядра, — а код пишется свой. Исключение — библиотеки и пакеты с совместимыми лицензиями, подключаемые как обычные зависимости NuGet.
