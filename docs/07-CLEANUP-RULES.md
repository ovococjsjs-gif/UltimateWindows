# Каталог правил очистки программ (схема 1) и совместимость с Winapp2.ini

Документ описывает формат файлов данных встроенного каталога правил очистки (`src/UltimateWindows.Modules.Cleaner/Rules/Data/*.json`), правила его проверки при загрузке и работу с внешними файлами формата `Winapp2.ini`.

---

## 1. Где лежат файлы встроенного каталога

Все файлы встроенного каталога лежат в папке `src/UltimateWindows.Modules.Cleaner/Rules/Data/` и вшиваются в сборку `UltimateWindows.Modules.Cleaner` как ресурсы `UltimateWindows.Cleaner.Rules.<имя>.json`:

| Файл | Раздел (`section`) | Что внутри |
|---|---|---|
| `10-windows.json` | `Windows` | Temp пользователя, системы и служб, отчёты WER, дампы программ и ядра, скачанные пакеты обновлений, кэш оптимизации доставки, журналы CBS/DISM/Panther/winget/.NET, кэш RDP, эскизы и недавние документы |
| `20-browsers.json` | `Browsers` | Кэш и отчёты о сбоях Chrome, Edge, Яндекс Браузера, Brave, Vivaldi, Chromium, Opera, Opera GX, Firefox; локальная модель ИИ Chrome |
| `30-graphics.json` | `Graphics` | Кэш шейдеров DirectX, NVIDIA, AMD, Intel; распакованные установщики драйверов; кэш приложения NVIDIA |
| `40-messengers.json` | `Messengers` | Кэш Telegram (без сессии входа), кэш Thunderbird, журналы Zoom |
| `50-games.json` | `Games` | Steam (веб-кэш, журналы, шейдеры с путём из реестра), Epic Games Launcher, Battle.net, Ubisoft Connect, GOG Galaxy, Minecraft, Roblox |
| `60-media.json` | `Media` | Spotify, VLC, Adobe Media Cache, OBS Studio, DaVinci Resolve |
| `70-office.json` | `Office` | Веб-кэш Microsoft Office, журналы OneDrive, кэш Adobe Acrobat |
| `80-development.json` | `Development` | npm, Yarn, pip, NuGet, Gradle, Cargo, Go, VS Code, Visual Studio, JetBrains, Unreal Engine DDC |
| `90-utilities.json` | `Utilities` | Java, qBittorrent, AnyDesk, PowerToys, Google Диск, Chocolatey, Scoop и общее групповое правило `app.embedded-browser-cache` для программ на движке Chromium / Edge WebView2 (Discord, Slack, Teams, Obsidian, Notion, Figma, Postman и др.) |

Порядок файлов по префиксу (`10-` … `90-`) важен: каждый найденный файл закрепляется за первым правилом, которое его обнаружило. Поэтому точные правила конкретных программ всегда идут раньше общего группового правила в `90-utilities.json`.

---

## 2. Схема файла JSON (`schemaVersion: 1`)

```json
{
  "schemaVersion": 1,
  "rules": [
    {
      "id": "game.steam.logs",
      "section": "Games",
      "app": "Steam",
      "title": "Журналы и отчёты о сбоях",
      "explanation": "Журналы работы Steam и отчёты о его сбоях. Нужны только при поиске причин неполадок.",
      "kind": "Logs",
      "default": true,
      "processes": ["steam"],
      "files": [
        { "path": "%reg:HKCU\\Software\\Valve\\Steam@SteamPath%\\logs" },
        { "path": "%reg:HKCU\\Software\\Valve\\Steam@SteamPath%\\dumps" }
      ]
    }
  ]
}
```

### Поля правила

- `id` — уникальный идентификатор (`раздел.имя`, строчные латинские буквы, цифры и дефисы).
- `section` — раздел: `Windows`, `Browsers`, `Graphics`, `Messengers`, `Games`, `Media`, `Office`, `Development`, `Utilities`.
- `app` — название программы для пользователя.
- `title` — что именно очищает правило.
- `explanation` — простое объяснение без запугивания: что удалится и создастся ли заново.
- `kind` — вид данных: `Cache`, `Temp`, `Logs`, `Dumps`, `Leftovers`, `History`, `Cookies`, `Sessions`, `Other`.
- `default` (`true` / `false`) — отмечено ли правило по умолчанию. Правила, после которых программе придётся перекачивать гигабайты (шейдеры, пакеты `nuget`/`gradle`, офлайн-музыка Spotify, дампы BSOD), всегда имеют `"default": false` и пояснение в `warning`.
- `warning` *(необязательно)* — предупреждение о побочном эффекте.
- `detect` *(необязательно)* — условие присутствия программы (`anyPath`, `anyRegistryKey`, `minWindowsBuild`, `maxWindowsBuild`). Если `detect` не указан, программа считается присутствующей, когда существует хотя бы одна целевая папка из `files`.
- `processes` *(необязательно)* — имена процессов без `.exe` для предупреждения о запущенной программе.
- `skipWhileRunning` *(необязательно)* — не чистить правило, пока программа запущена (для видов `History`, `Cookies`, `Sessions` действует всегда).
- `minAgeHours` *(необязательно)* — удалять только файлы старше указанного числа часов.
- `files` — непустой список целевых папок:
  - `path` — путь, начинающийся с известной переменной (`%LocalAppData%`, `%AppData%`, `%LocalLow%`, `%ProgramData%`, `%UserProfile%`, `%WinDir%`, `%SystemDrive%`, `%Temp%`, `%ProgramFiles%`, `%CommonProgramFiles%` и др.) или со ссылки на строковое значение реестра `%reg:HKCU\Раздел@Значение%\подпапка`. В сегментах допустимы маски `*` и `?`.
  - `match` *(по умолчанию `["*"]`)* — маски имён файлов без слэшей.
  - `recurse` *(по умолчанию `true`)* — обходить вложенные папки.
  - `removeEmptyFolders` *(по умолчанию равно `recurse`)* — удалять опустевшие вложенные папки.
  - `removeSelf` *(по умолчанию `false`)* — удалить и саму целевую папку, если она опустела.
  - `group` *(необязательно)* — сколько первых сегментов со звёздочками образуют имя найденной программы в групповом правиле.
- `exclude` *(необязательно)* — список исключений `{ "path": "...", "match": ["..."] }`.
- `groupLabels` *(необязательно)* — словарь понятных названий программ по имени папки для групповых правил.

Загрузчик `CleanupRuleCatalogLoader` отвергает неизвестные поля, дублирующиеся `id`, пустые списки `files` и любые попытки указать корень переменной без подпапки с маской `*`.

---

## 3. Подключение внешних файлов `Winapp2.ini`

Пользователь может подключить собственный файл в формате сообщества `Winapp2.ini` (в интерфейсе на вкладке «Программы (каталог + Winapp2)» или ключом `--winapp2 <путь>` в CLI). Сам `Winapp2.ini` распространяется под лицензией CC-BY-SA-4.0 и внутрь репозитория не встраивается.

`Winapp2Reader` разбирает секции `[Название*]`, ключи `FileKey1..N` (`путь|маска1;маска2|RECURSE|REMOVESELF`), `ExcludeKey1..N`, `Detect1..N`, `DetectFile1..N`, `SpecialDetect`, `DetectOS`, `LangSecRef`, `Section`, `Warning`. Все внешние правила получают `Origin = External` и `SelectedByDefault = false`.

---

## 4. Многослойная защита (`BrowserVaultGuard` + `CleanupPathGuard`)

Независимо от того, что написано во встроенном или внешнем правиле, каждый путь проходит проверку до добавления в список и повторно перед удалением:

1. **Защита браузеров (`BrowserVaultGuard`).** Файлы паролей (`Login Data`, `Ya Passman Data`, `logins.json`, `key4.db`, `Local State`), автозаполнения (`Web Data`, `formhistory.sqlite`), закладок (`Bookmarks`, `places.sqlite`) и настроек расширений заблокированы жёстко. Внутри папок профилей браузеров и `EBWebView` правилам каталога разрешены только подпапки кэша и дампов.
2. **Неприкосновенные системные и личные зоны (`CleanupPathGuard`).** Заблокированы системные ветки `Windows` (кроме явно перечисленных временных и журнальных подпапок), хранилища ключей и сертификатов (`Microsoft\Protect`, `Crypto`, `Credentials`, `Vault`), `.ssh`, `.gnupg`, файлы кошельков и баз паролей (`.kdbx`, `.pfx`, `.pst`, `wallet.dat`), а также собственное хранилище точек отката `UltimateWindows`.
3. **Усиленный фильтр для внешних правил.** Правилам из подключённого `Winapp2.ini` за пределами `AppData` / `ProgramData` / `Temp` разрешены только одноразовые расширения журналов и дампов (`.log`, `.tmp`, `.dmp`, `.etl` и т.п.).
4. **Защита от симлинков и соединений.** По точкам повторной обработки (`ReparsePoint`) движок не переходит ни при поиске, ни при удалении.
