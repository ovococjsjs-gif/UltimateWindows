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
    [string]$Version = "2.0.0",
    [string]$Runtime = "win-x64",
    [string]$ReleaseTag = "v2.0.0",
    [switch]$SkipTests,
    [switch]$UploadToGitHubRelease,
    [switch]$AllowOlderReleaseTag
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Invoke-LoggedDotnet {
    param(
        [string]$StepLabel,
        [string[]]$DotnetArgs
    )

    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $outputLines = & dotnet @DotnetArgs 2>&1 | ForEach-Object { "$_" }
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
UltimateWindows v$Version — портативная версия ($Runtime)
============================================================
Установка не нужна: .NET и все библиотеки уже внутри.

Что умеет программа:
  • Оптимизатор: около 190 настроек Windows в 13 разделах (реестр, службы, задания планировщика). У каждой есть
    пояснение и уровень риска. Готовые наборы показывают список изменений до применения. Рядом — службы,
    планировщик, автозагрузка, удаление программ и встроенных приложений, проверка сети, DNS и файл hosts.
  • Диск и очистка: карта диска (дерево папок, типы файлов, блоки), поиск дубликатов, очистка кэша Windows
    и браузеров без потери паролей и автозаполнения, чистка реестра по 10 категориям.
  • Поиск майнеров, разбор синих экранов и ошибок запуска программ, драйверы, сведения о железе.
  • «Машина времени»: изменения настроек, служб и заданий записываются, и любое из них можно отменить.

Файлы в комплекте:
  1. UltimateWindows.exe     — программа с окнами. При запуске просит права администратора.
  2. UltimateWindows.Cli.exe — командная строка: smart-audit, tweak-list, preset-apply, service-list, task-list, clean-scan и другие.
  3. .portable               — метка портативного режима: точки отката хранятся рядом с программой, в папке .\Data\Vault\
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
