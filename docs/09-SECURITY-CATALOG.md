# 09. Архитектура и каталог «Анти-майнер и Защита 2.0» (Этап 4)

Документ описывает собственную чистую реализацию модуля охоты на скрытые криптомайнеры, дропперы, бесфайловое закрепление и послевирусный саботаж Windows 10 (22H2+) и Windows 11. Весь код написан с нуля под лицензией MIT без заимствования чужого исходного кода.

---

## 1. Многоуровневая модель обнаружения

Модуль объединяет 7 независимых уровней телеметрии в единую карточку находки `SecurityThreatFinding`:

1. **Двухфазный поведенческий детектор `Drop-on-Inspect` по CPU + GPU + системный монитор (`WindowsSecurityPlatformBridge`)**
   - **Фаза 1 (Тихий фон, 600 мс):** снимает процессорное время всех процессов и загрузку вычислительных/3D-движков видеокарты по каждому PID через нативный английский счётчик `pdh.dll` `\GPU Engine(*)\Utilization Percentage` (`PdhAddEnglishCounterW` — не зависит от языка интерфейса Windows).
   - **Фаза 2 (Активный мониторинг, 650 мс):** создаёт невидимые окна-приманки верхнего уровня и (на интерактивном рабочем столе вне CI) кратковременно запускает штатный системный монитор в свёрнутом режиме, после чего повторно замеряет нагрузку CPU и GPU. Ловит как RandomX CPU-майнеры, так и видеокарточные майнеры (`KawPow`, `Ethash`, `Autolykos`), сбрасывающие нагрузку при появлении Диспетчера задач.
2. **Анализ процессов, аргументов запуска и `Process Hollowing`**
   - Читает полный путь (`QueryFullProcessImageNameW`), родительский PID и полную командную строку каждого процесса напрямую через `NtQueryInformationProcess` (`ProcessBasicInformation = 0`, `ProcessCommandLineInformation = 60`) без накладных расходов WMI.
   - Обнаруживает маскировку под системные процессы (`svchost.exe`, `dwm.exe`, `conhost.exe`, `wuauclt.exe` вне `System32` / `SysWOW64` / `WinSxS`).
   - Проверяет виртуальную память процессов-доноров (`VirtualQueryEx`) на наличие не привязанных к файлам приватных исполняемых секций (`MEM_PRIVATE` + `PAGE_EXECUTE_*` >= 64 КБ) и аномальных неподписанных процессов-родителей из пользовательских папок (типичный почерк `SilentCryptoMiner` при внедрении в `dwm.exe`, `conhost.exe`, `RegAsm.exe`, `MSBuild.exe`).
3. **Сетевой охотник Stratum (IPv4 + IPv6) и DNS-кэш**
   - Читает таблицы активных TCP-соединений `AF_INET` и `AF_INET6` (`GetExtendedTcpTable`), сопоставляя порты протокола Stratum с PID процессов и отсекая обычные веб-браузеры.
   - Проверяет системный кэш DNS-резолвера на следы обращений к 60+ пулам майнинга (`supportxmr.com`, `hashvault.pro`, `nanopool.org`, `2miners.com`, `herominers.com`, `moneroocean.stream`, `nicehash.com`, `kryptex.network` и др.), даже если сокет временно закрыт.
4. **Полная ревизия 18 зон автозакрепления (`PersistenceZoneCatalog`)**
5. **Аудит слепых зон Microsoft Defender, правил Брандмауэра, `hosts`, скрытых учётных записей и staging-каталогов**
6. **Подключаемые внешние сканеры с пермиссивными лицензиями (`PE-sieve`, `YARA`)**
7. **Комплексное обезвреживание в 1 клик и шифрованный карантин `.uwq` (`Zero-Bloat Vault`)**

---

## 2. Все 18 проверяемых зон автозакрепления

| № | Зона (`PersistenceZone`) | Проверяемые ветки и подсистемы |
|---|---|---|
| 1 | `RunAndRunOnceKeys` | `HKLM` (`64` + `WOW6432Node`) и `HKCU` `CurrentVersion\Run`, `RunOnce`, `RunOnceEx`, `RunServices` |
| 2 | `PoliciesExplorerRun` | `HKLM` и `HKCU` `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run` |
| 3 | `StartupFoldersAndShellRedirection` | Папки `Startup` / `Common Startup` (разбор `.lnk`, `.vbs`, `.bat`, `.ps1`, `.exe`) + перенаправление `User Shell Folders` |
| 4 | `WinlogonShellAndUserinit` | `HKLM` и `HKCU` `Winlogon`: `Shell`, `Userinit`, `Taskman` |
| 5 | `IfeoAndSilentProcessExit` | `Image File Execution Options\*\Debugger` и теневой перезапуск `SilentProcessExit\*\MonitorProcess` |
| 6 | `BootExecuteAndSessionManager` | `SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute` и `AppCertDlls` |
| 7 | `AppInitDlls` | `HKLM` (`64` + `WOW6432Node`) `Windows NT\CurrentVersion\Windows`: `LoadAppInit_DLLs` + `AppInit_DLLs` |
| 8 | `ActiveSetupInstalledComponents` | `HKLM` и `HKCU` `Software\Microsoft\Active Setup\Installed Components\*\StubPath` |
| 9 | `ComInprocAndLocalServerHijack` | Перехват COM-классов без прав администратора: `HKCU\Software\Classes\CLSID\*\InprocServer32` и `LocalServer32` (включая `scrobj.dll`) |
| 10 | `DotNetCorProfilerEnvironment` | Перехват всех .NET-процессов (`COR_ENABLE_PROFILING`, `COR_PROFILER_PATH`, `CORECLR_PROFILER_PATH`, `DOTNET_STARTUP_HOOKS`) |
| 11 | `LsaAndSecurityPackages` | `SYSTEM\CurrentControlSet\Control\Lsa`: `Authentication Packages`, `Notification Packages`, `Security Packages` |
| 12 | `PrintMonitorsAndNetshHelpers` | `Control\Print\Monitors\*\Driver` и вспомогательные DLL `SOFTWARE\Microsoft\NetSh` |
| 13 | `WindowsServicesAndDrivers` | Службы в пользовательских/временных путях, подмена `Parameters\ServiceDll`, маскирующиеся имена (`DrvSvc`, `GoogleUpdateTaskMachineQC`) и драйверы `WinRing0x64.sys` |
| 14 | `ScheduledTasksAndGhostSd` | Все задачи через нативный COM `Schedule.Service` (`TASK_ENUM_HIDDEN`) + скрытые задачи с удалённым дескриптором `SD` в `TaskCache\Tree` |
| 15 | `WmiPermanentSubscriptions` | Бесфайловые постоянные подписки WMI в `root\subscription` (`CommandLineEventConsumer`, `ActiveScriptEventConsumer`) |
| 16 | `BitsPersistentJobs` | Незавершённые фоновые задания передачи `BITS` на сторонние узлы |
| 17 | `ShellExtensionsAndBrowserHooks` | `HKCU\...\Explorer\ShellServiceObjectDelayLoad` с неподписанными обработчиками |
| 18 | `PowerShellProfiles` | Стартовые сценарии `$PROFILE` (`Microsoft.PowerShell_profile.ps1`, `profile.ps1`) |

---

## 3. Интеграция с Microsoft Defender, Брандмауэром, пользователями и staging-папками

- **Аудит исключений Microsoft Defender (`ScanDefenderExclusionsAsync`):** читает рабочие ветки `Windows Defender\Exclusions` и групповые политики `Policies\Microsoft\Windows Defender\Exclusions` (`Paths`, `Processes`, `Extensions`, `IpAddresses`). Безопасные папки проектов разработчика помечаются как штатные, а слепые зоны майнеров (`C:\`, `AppData`, `ProgramData`, `Temp`, `Users\Public`, расширения `.exe`/`.dll`/`.bat`/`.ps1`, системные процессы-доноры `dwm.exe`/`svchost.exe`/`conhost.exe`) выделяются как критические и удаляются в один клик с сохранением отката в «Машине времени».
- **Запуск проверки Microsoft Defender (`StartDefenderScanAsync`):** запускает актуальный `MpCmdRun.exe` из `ProgramData\Microsoft\Windows Defender\Platform\<версия>` в режиме быстрой проверки системы (`-ScanType 1`) или принудительной проверки выбранного пути (`-ScanType 3 -File <путь>`).
- **Саботаж Брандмауэра Windows (`ScanFirewallRuleAnomaliesAsync`):** разбирает правила `SharedAccess\Parameters\FirewallPolicy\FirewallRules` и находит исходящие блокировки (`Action=Block|Dir=Out`), ослепляющие `MsMpEng.exe`, `MpCmdRun.exe`, `SecurityHealthService.exe`, `mrt.exe` и службы Центра обновления.
- **Скрытые учётные записи (`ScanSuspiciousUserAccountsAsync`):** через нативный `NetUserEnum` (`netapi32.dll`, без зависимости от языка ОС) и ветку `Winlogon\SpecialAccounts\UserList` выявляет скрытые аккаунты с суффиксом `$` и теневых администраторов.
- **Staging-каталоги и File Bloating (`ScanStagingDirectoriesAsync`):** проверяет пользовательские и временные каталоги на конфиги пулов (`config.json` со `stratum+`), драйверы `WinRing0x64.sys` и искусственно раздутые неподписанные `.exe` объёмом **250–1024 МБ** с заполненным пустыми байтами хвостом (`HasArtificialTailPadding`).

---

## 4. Подключаемые сканеры PE-sieve и YARA

Внешние утилиты с пермиссивными лицензиями подключаются без вшивания чужого кода в бинарник:
- **PE-sieve** (`BSD-2-Clause`): автоматически подхватывается из `tools\pe-sieve64.exe` (или по выбранному пути), запускается с `/pid <pid> /threads /dmode 0 /quiet /json`, разбираются поля `replaced`/`hollowed`, `implanted_pe`, `implanted_shc`, `hdr_modified`.
- **YARA** (`BSD-3-Clause`): подхватывается из `tools\yara64.exe` вместе с файлами правил `.yar`/`.yara` для сигнатурной проверки папок и процессов.

---

## 5. Команды CLI

```powershell
UltimateWindows.Cli security-scan [--fast] [--json]   # Полный аудит (с приманкой Drop-on-Inspect или быстрый)
UltimateWindows.Cli persistence-audit [--anomalies]   # Ревизия всех 18 зон автозакрепления
UltimateWindows.Cli defender-audit                    # Аудит исключений Microsoft Defender
UltimateWindows.Cli defender-clean-exclusions         # Удаление опасных слепых зон Defender с записью отката
UltimateWindows.Cli defender-scan [--path <путь>]     # Быстрая или выборочная проверка через MpCmdRun.exe
UltimateWindows.Cli security-heal                     # Снятие всех послевирусных блокировок ОС и hosts
UltimateWindows.Cli quarantine-list                   # Список изолированных объектов .uwq
UltimateWindows.Cli quarantine-restore <GUID>         # Восстановление объекта из карантина в 1 клик
```
