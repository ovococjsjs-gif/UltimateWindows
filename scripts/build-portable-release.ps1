<#
.SYNOPSIS
    Сборка полностью автономной портативной версии UltimateWindows (Single-File Self-Contained win-x64)
    с прогоном всех модульных тестов, включением портативного режима (.portable), расчётом SHA-256
    и необязательной загрузкой готового .zip-архива в GitHub Releases.

.DESCRIPTION
    Нужен .NET 10 SDK. Если указан тег релиза старше версии исходников (Directory.Build.props),
    сборка останавливается: иначе файлы старого релиза были бы перезаписаны сборкой из новых исходников.

.EXAMPLE
    .\scripts\build-portable-release.ps1
    .\scripts\build-portable-release.ps1 -Version 2.0.0 -ReleaseTag "v2.0.0" -UploadToGitHubRelease
#>
[CmdletBinding()]
param(
    [string]$Version = "2.1.0",
    [string]$Runtime = "win-x64",
    [string]$ReleaseTag = "v2.1.0",
    [switch]$SkipTests,
    [switch]$UploadToGitHubRelease,
    [switch]$AllowOlderReleaseTag
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$script:DotnetExe = "dotnet"

function Ensure-Dotnet10Sdk {
    $hasNet10 = $false
    if (Get-Command dotnet -ErrorAction SilentlyContinue) {
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $sdks = & dotnet --list-sdks 2>&1 | ForEach-Object { "$_" }
        $ErrorActionPreference = $prevEap
        if (@($sdks | Where-Object { $_ -match "^10\.0\." }).Count -gt 0) {
            $hasNet10 = $true
        }
    }

    if ($hasNet10) {
        return
    }

    # Если старый workflow настроил DOTNET_ROOT на .NET 8, проверим системный каталог C:\Program Files\dotnet
    $sysDotnet = "C:\Program Files\dotnet"
    if (Test-Path -LiteralPath (Join-Path $sysDotnet "sdk")) {
        $sysSdks = Get-ChildItem -LiteralPath (Join-Path $sysDotnet "sdk") -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "10.0.*" }
        if (@($sysSdks).Count -gt 0) {
            Write-Host "Обнаружен предустановленный .NET 10 SDK в $sysDotnet — переключаем окружение." -ForegroundColor Cyan
            $env:DOTNET_ROOT = $sysDotnet
            $env:PATH = "$sysDotnet;$env:PATH"
            $script:DotnetExe = Join-Path $sysDotnet "dotnet.exe"
            return
        }
    }

    # Автоматическая доустановка официального .NET 10.0 SDK (актуально для старого release-workflow)
    $baseTemp = if (-not [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) { $env:RUNNER_TEMP } else { [System.IO.Path]::GetTempPath() }
    $installDir = Join-Path $baseTemp "uw-dotnet10"
    $installerScript = Join-Path $baseTemp "dotnet-install.ps1"

    Write-Host "Текущий SDK старше .NET 10 — загружаем официальный .NET 10.0 SDK в $installDir..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    Invoke-WebRequest -Uri "https://dot.net/v1/dotnet-install.ps1" -OutFile $installerScript -UseBasicParsing
    & $installerScript -Channel "10.0" -Quality "GA" -InstallDir $installDir -NoPath
    if ($LASTEXITCODE -ne 0) {
        throw "Не удалось автоматически установить .NET 10.0 SDK."
    }

    $env:DOTNET_ROOT = $installDir
    $env:PATH = "$installDir;$env:PATH"
    $script:DotnetExe = Join-Path $installDir "dotnet.exe"
    Write-Host "Активирован .NET SDK: $(& $script:DotnetExe --version)" -ForegroundColor Green
}

function Invoke-LoggedDotnet {
    param(
        [string]$StepLabel,
        [string[]]$DotnetArgs
    )

    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $outputLines = & $script:DotnetExe @DotnetArgs 2>&1 | ForEach-Object { "$_" }
    $code = $LASTEXITCODE
    $ErrorActionPreference = $prevEap

    foreach ($line in $outputLines) {
        Write-Host $line
    }

    if ($code -ne 0) {
        if ($env:GITHUB_ACTIONS -eq "true") {
            $interesting = $outputLines | Where-Object {
                $_ -match "error " -or $_ -match "Failed" -or $_ -match " Assert\." -or $_ -match "Exception" -or $_ -match "XAML" -or $_ -match "MC\d+" -or $_ -match "CS\d+" -or $_ -match "\[FAIL\]"
            }
            if (-not $interesting -or @($interesting).Count -eq 0) {
                $interesting = $outputLines | Select-Object -Last 35
            }
            $joined = (@($interesting) | Select-Object -First 40) -join " || "
            $safe = $joined.Replace("%", "%25").Replace("`r", "").Replace("`n", " ")
            Write-Host "::error title=$StepLabel::$safe"
        }
        throw "$StepLabel завершился с ошибкой (код $code)."
    }
}

function Get-SourceVersionText {
    param([string]$Root)

    $propsPath = Join-Path $Root "Directory.Build.props"
    if (-not (Test-Path -LiteralPath $propsPath)) {
        return $null
    }

    $text = Get-Content -LiteralPath $propsPath -Raw
    $match = [regex]::Match($text, '<Version>\s*([^<\s]+)\s*</Version>')
    if ($match.Success) {
        return $match.Groups[1].Value
    }

    return $null
}

function ConvertTo-ComparableVersion {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }

    # "v2.1.0-beta" -> "2.1.0"
    $core = ($Text.Trim().TrimStart('v', 'V') -split '[-+]')[0]
    $parsed = $null
    if ([version]::TryParse($core, [ref]$parsed)) {
        return $parsed
    }

    return $null
}

$RepoRoot = Split-Path -Parent $PSScriptRoot
$ReleaseTagWasGiven = $PSBoundParameters.ContainsKey("ReleaseTag")
Push-Location $RepoRoot

try {
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host " UltimateWindows Portable Builder — v$Version ($Runtime)" -ForegroundColor Cyan
    Write-Host "=================================================================" -ForegroundColor Cyan

    Ensure-Dotnet10Sdk

    if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
        throw "Не найден .NET 10 SDK (dotnet). Установите с https://dotnet.microsoft.com/download/dotnet/10.0"
    }

    # Защита от случайной перезаписи старого релиза (например, ручной запуск сборки с тегом по умолчанию):
    # сборка из новых исходников не должна ложиться в релиз с более старым тегом.
    if ($ReleaseTagWasGiven -and -not $AllowOlderReleaseTag) {
        $sourceVersion = ConvertTo-ComparableVersion (Get-SourceVersionText -Root $RepoRoot)
        $tagVersion = ConvertTo-ComparableVersion $ReleaseTag
        if ($null -ne $sourceVersion -and $null -ne $tagVersion -and $tagVersion -lt $sourceVersion) {
            throw "Тег релиза $ReleaseTag старше версии исходников ($sourceVersion в Directory.Build.props). Сборка остановлена, чтобы не перезаписать файлы старого релиза. Укажите тег текущей версии или добавьте ключ -AllowOlderReleaseTag."
        }
    }

    $ArtifactsDir = Join-Path $RepoRoot "artifacts"
    $StagingName  = "UltimateWindows-v$Version-$Runtime-portable"
    $StagingDir   = Join-Path $ArtifactsDir $StagingName
    $ZipPath      = Join-Path $ArtifactsDir "$StagingName.zip"
    $ShaPath      = Join-Path $ArtifactsDir "SHA256SUMS-$Runtime.txt"

    if (Test-Path $StagingDir) { Remove-Item $StagingDir -Recurse -Force }
    if (Test-Path $ZipPath)    { Remove-Item $ZipPath -Force }
    New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null

    if (-not $SkipTests) {
        Write-Host "`n[1/4] Прогон всех модульных тестов xUnit..." -ForegroundColor Yellow
        Invoke-LoggedDotnet -StepLabel "DotnetTest" -DotnetArgs @("test", "$RepoRoot\UltimateWindows.sln", "-c", "Release", "--nologo", "--logger", "console;verbosity=normal")
    }

    Write-Host "`n[2/4] Сборка портативного GUI-приложения UltimateWindows.exe (Single-File Self-Contained)..." -ForegroundColor Yellow
    $GuiOut = Join-Path $ArtifactsDir "publish-gui-$Runtime"
    if (Test-Path $GuiOut) { Remove-Item $GuiOut -Recurse -Force }

    Invoke-LoggedDotnet -StepLabel "PublishGUI" -DotnetArgs @(
        "publish", "$RepoRoot\src\UltimateWindows.App\UltimateWindows.App.csproj",
        "-c", "Release",
        "-r", $Runtime,
        "--self-contained", "true",
        "-p:PublishSingleFile=true",
        "-p:IncludeNativeLibrariesForSelfExtract=true",
        "-p:EnableCompressionInSingleFile=true",
        "-p:DebugType=embedded",
        "-p:Version=$Version",
        "-o", $GuiOut,
        "--nologo"
    )

    Write-Host "`n[3/4] Сборка портативной консольной утилиты UltimateWindows.Cli.exe..." -ForegroundColor Yellow
    $CliOut = Join-Path $ArtifactsDir "publish-cli-$Runtime"
    if (Test-Path $CliOut) { Remove-Item $CliOut -Recurse -Force }

    Invoke-LoggedDotnet -StepLabel "PublishCLI" -DotnetArgs @(
        "publish", "$RepoRoot\src\UltimateWindows.Cli\UltimateWindows.Cli.csproj",
        "-c", "Release",
        "-r", $Runtime,
        "--self-contained", "true",
        "-p:PublishSingleFile=true",
        "-p:IncludeNativeLibrariesForSelfExtract=true",
        "-p:EnableCompressionInSingleFile=true",
        "-p:DebugType=embedded",
        "-p:Version=$Version",
        "-o", $CliOut,
        "--nologo"
    )

    Copy-Item (Join-Path $GuiOut "UltimateWindows.exe") -Destination $StagingDir -Force
    Copy-Item (Join-Path $CliOut "UltimateWindows.Cli.exe") -Destination $StagingDir -Force

    # Создаем маркер .portable — VaultPathResolver автоматически переключит Zero-Bloat Vault
    # в локальную папку .\Data\Vault\ рядом с .exe (не оставляя следов на диске C:\)!
    Set-Content -Path (Join-Path $StagingDir ".portable") -Value "UltimateWindows Portable Mode Enabled" -Encoding UTF8

    $PortableReadme = @"
UltimateWindows v$Version — портативная версия ($Runtime, .NET 10)
============================================================
Установка не нужна: среда .NET 10 и все библиотеки уже внутри.

Что входит в выпуск:
  • Оптимизатор 2.0: 191 обратимая настройка Windows 10/11 в 13 разделах, готовые наборы с предпросмотром,
    менеджер служб и заданий Планировщика, автозагрузка, UWP, сеть, DNS и файл hosts (импорт/экспорт YAML).
  • Диск и Очистка 2.0: сверхбыстрая карта диска через прямое чтение NTFS `$MFT, 86 встроенных правил очистки
    программ + поддержка баз Winapp2.ini, 5-уровневая очистка браузеров с защитой паролей (BrowserVaultGuard),
    8 системных резервов C:\, дубли SHA-256 и 13 категорий реестра с откатом.
  • Ремонт ОС и DLL 2.0: 107 проверок и рецептов лечения Windows, 23 пакета сред выполнения Microsoft
    (VC++ 2005–2022, .NET, DirectX, WebView2), рекурсивный PE-доктор (0xC000007B), 160 кодов ошибок и разбор BSOD.
  • Анти-Майнер и Защита 2.0: ревизия 18 зон автозакрепления, поведенческий детектор скрытых майнеров CPU+GPU,
    проверка исключений Защитника и правил брандмауэра, снятие блокировок системы и карантин .uwq.
  • Железо 2.0, Бенчмарки и Драйверы 2.0: паспорт SMBIOS 3.x, датчики без WinRing0 (+ опциональный PawnIO),
    экспресс-бенчмарк CPU SIMD / GPU DirectCompute / ОЗУ / Диска (~5 сек), живой поиск Microsoft Update Catalog,
    серверный каталог из 39 основных драйверов, очистка DriverStore и аудит уязвимых драйверов ядра (BYOVD).
  • Программы winget, Windows 11 и Автопилот: обновление всех программ в 1 клик, каталог из 36 утилит без рекламы,
    чистый деинсталлятор с поиском хвостов в AppData/реестре, проверка готовности к Windows 11 (24H2/25H2)
    и статуса Windows 10 ESU, диагностика батареи/сна/ОЗУ, расписание обслуживания и единый .zip-архив диагностики.
  • «Машина времени» (Zero-Bloat Vault): транзакционный откат изменений в 1 клик.

Файлы в комплекте:
  1. UltimateWindows.exe     — графический интерфейс (Fluent Design, Тёмная / Светлая тема).
  2. UltimateWindows.Cli.exe — полная командная строка и движок фонового автообслуживания.
  3. .portable               — метка портативного режима: точки отката хранятся локально в .\Data\Vault\
"@
    Set-Content -Path (Join-Path $StagingDir "PORTABLE-README.txt") -Value $PortableReadme -Encoding UTF8

    Write-Host "`n[4/4] Упаковка портативного архива и расчет контрольных сумм SHA-256..." -ForegroundColor Yellow
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory(
        $StagingDir,
        $ZipPath,
        [System.IO.Compression.CompressionLevel]::Optimal,
        $false)

    Remove-Item $GuiOut -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $CliOut -Recurse -Force -ErrorAction SilentlyContinue

    $GuiHash = (Get-FileHash (Join-Path $StagingDir "UltimateWindows.exe") -Algorithm SHA256).Hash.ToLowerInvariant()
    $CliHash = (Get-FileHash (Join-Path $StagingDir "UltimateWindows.Cli.exe") -Algorithm SHA256).Hash.ToLowerInvariant()
    $ZipHash = (Get-FileHash $ZipPath -Algorithm SHA256).Hash.ToLowerInvariant()

    @(
        "$ZipHash  $(Split-Path -Leaf $ZipPath)"
        "$GuiHash  UltimateWindows.exe"
        "$CliHash  UltimateWindows.Cli.exe"
    ) | Set-Content -Path $ShaPath -Encoding UTF8

    Write-Host "`nГОТОВО! Портативный архив собран:" -ForegroundColor Green
    Write-Host "  Архив   : $ZipPath" -ForegroundColor Green
    Write-Host "  SHA-256 : $ZipHash" -ForegroundColor Green

    if ($UploadToGitHubRelease) {
        if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
            throw "Для автозагрузки в GitHub Releases установите GitHub CLI (gh)."
        }
        Write-Host "`nЗагрузка бинарного портативного архива в GitHub Release $ReleaseTag..." -ForegroundColor Cyan
        gh release upload $ReleaseTag $ZipPath $ShaPath --clobber
        if ($LASTEXITCODE -ne 0) { throw "Не удалось загрузить ассеты в релиз $ReleaseTag." }
        Write-Host "Ассеты успешно прикреплены к GitHub Release $ReleaseTag!" -ForegroundColor Green
    }
}
catch {
    if ($env:GITHUB_ACTIONS -eq "true") {
        $errMsg = "$($_.Exception.Message)".Replace("%", "%25").Replace("`r", "").Replace("`n", " ")
        Write-Host "::error title=ScriptException::$errMsg"
    }
    throw
}
finally {
    Pop-Location
}
