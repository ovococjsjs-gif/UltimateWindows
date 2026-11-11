<#
.SYNOPSIS
    Сборка полностью автономной портативной версии UltimateWindows v1.0.0 (Single-File Self-Contained win-x64)
    с автоматическим прогоном всех модульных тестов, активацией флеш-режима (.portable), расчетом SHA-256
    и опциональной загрузкой готового .zip-архива в GitHub Releases (v1.0.0).

.EXAMPLE
    .\scripts\build-portable-release.ps1
    .\scripts\build-portable-release.ps1 -UploadToGitHubRelease -ReleaseTag "v1.0.0"
#>
[CmdletBinding()]
param(
    [string]$Version = "2.0.0",
    [string]$Runtime = "win-x64",
    [string]$ReleaseTag = "v2.0.0",
    [switch]$SkipTests,
    [switch]$UploadToGitHubRelease
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

$RepoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $RepoRoot

try {
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host " UltimateWindows Portable Builder — v$Version ($Runtime)" -ForegroundColor Cyan
    Write-Host "=================================================================" -ForegroundColor Cyan

    if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
        throw "Не найден .NET 8.0 SDK (dotnet). Установите с https://dotnet.microsoft.com/download/dotnet/8.0"
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
        Write-Host "`n[1/4] Прогон всех модульных тестов xUnit (Фазы 0–6)..." -ForegroundColor Yellow
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
UltimateWindows v$Version PRO — Портативная версия ($Runtime)
============================================================
Автономная сборка (не требует установки .NET 8 или сторонних библиотек).

Что нового в версии 2.0 PRO:
  • Анализатор пространства диска уровня WizTree: дерево папок с полосами %, таблица типов файлов с цветами
    и интерактивная карта блоков диска Squarified Treemap (клик / 2×клик / отправка в Корзину).
  • Поиск дубликатов файлов по SHA-256 и освобождение системных резервов C:\ (hiberfil.sys, WinSxS, Windows.old).
  • Системный Оптимизатор (39 живых переключателей системы, диска, телеметрии Office/Chrome/Firefox/Edge/NVIDIA и игр),
    удаление UWP-приложений, деинсталлятор программ Win32, интерактивный Пингер, DNS и редактор файла Hosts.
  • Очистка кэша браузеров с броней паролей/автозаполнения + гранулярная чистка 10 категорий реестра с откатом.
  • Полностью новый плотный Desktop-интерфейс (Pro Dark Obsidian & Light Slate) без стандартных контролов Windows 7.

Файлы в комплекте:
  1. UltimateWindows.exe     — Графический интерфейс (Windows 10 / 11 Pro Desktop GUI)
  2. UltimateWindows.Cli.exe — Консольная утилита автоматизации (smart-audit, miner-scan, clean-scan, pe-doctor)
  3. .portable               — Маркер портативного режима: все компактные точки отката сохраняются внутри .\Data\Vault\
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
