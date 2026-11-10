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
    [string]$Version = "1.0.0",
    [string]$Runtime = "win-x64",
    [string]$ReleaseTag = "v1.0.0",
    [switch]$SkipTests,
    [switch]$UploadToGitHubRelease
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

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
        dotnet test "$RepoRoot\UltimateWindows.sln" -c Release --nologo
        if ($LASTEXITCODE -ne 0) { throw "Модульные тесты завершились с ошибкой (код $LASTEXITCODE)." }
    }

    Write-Host "`n[2/4] Сборка портативного GUI-приложения UltimateWindows.exe (Single-File Self-Contained)..." -ForegroundColor Yellow
    $GuiOut = Join-Path $ArtifactsDir "publish-gui-$Runtime"
    if (Test-Path $GuiOut) { Remove-Item $GuiOut -Recurse -Force }

    dotnet publish "$RepoRoot\src\UltimateWindows.App\UltimateWindows.App.csproj" `
        -c Release `
        -r $Runtime `
        --self-contained true `
        -p:PublishSingleFile=true `
        -p:IncludeNativeLibrariesForSelfExtract=true `
        -p:EnableCompressionInSingleFile=true `
        -p:DebugType=embedded `
        -p:Version=$Version `
        -o $GuiOut --nologo
    if ($LASTEXITCODE -ne 0) { throw "Ошибка сборки UltimateWindows.App." }

    Write-Host "`n[3/4] Сборка портативной консольной утилиты UltimateWindows.Cli.exe..." -ForegroundColor Yellow
    $CliOut = Join-Path $ArtifactsDir "publish-cli-$Runtime"
    if (Test-Path $CliOut) { Remove-Item $CliOut -Recurse -Force }

    dotnet publish "$RepoRoot\src\UltimateWindows.Cli\UltimateWindows.Cli.csproj" `
        -c Release `
        -r $Runtime `
        --self-contained true `
        -p:PublishSingleFile=true `
        -p:IncludeNativeLibrariesForSelfExtract=true `
        -p:EnableCompressionInSingleFile=true `
        -p:DebugType=embedded `
        -p:Version=$Version `
        -o $CliOut --nologo
    if ($LASTEXITCODE -ne 0) { throw "Ошибка сборки UltimateWindows.Cli." }

    Copy-Item (Join-Path $GuiOut "UltimateWindows.exe") -Destination $StagingDir -Force
    Copy-Item (Join-Path $CliOut "UltimateWindows.Cli.exe") -Destination $StagingDir -Force

    # Создаем маркер .portable — VaultPathResolver автоматически переключит Zero-Bloat Vault
    # в локальную папку .\Data\Vault\ рядом с .exe (не оставляя следов на диске C:\)!
    Set-Content -Path (Join-Path $StagingDir ".portable") -Value "UltimateWindows Portable Mode Enabled" -Encoding UTF8

    $PortableReadme = @"
UltimateWindows v$Version — Портативная версия ($Runtime)
============================================================
Автономная сборка (не требует установки .NET 8 или сторонних библиотек).

Файлы в комплекте:
  1. UltimateWindows.exe     — Графический интерфейс (Windows 10 / 11 Fluent GUI, режимы Простой / Эксперт)
  2. UltimateWindows.Cli.exe — Консольная утилита автоматизации (smart-audit, miner-scan, clean-scan, pe-doctor и др.)
  3. .portable               — Маркер портативного режима: все компактные точки отката и карантин (.uwq)
                               сохраняются строго внутри локальной папки .\Data\Vault\ рядом с программой,
                               не засоряя системный диск C:\!

Быстрый запуск:
  • Обычный запуск (просмотр железа, умный аудит, бережная очистка кэша без потери паролей):
    дважды откройте UltimateWindows.exe
  • Полный режим ремонта ОС, разблокировки после майнеров и установки WHQL-драйверов:
    запустите UltimateWindows.exe от имени Администратора.
"@
    Set-Content -Path (Join-Path $StagingDir "PORTABLE-README.txt") -Value $PortableReadme -Encoding UTF8

    Write-Host "`n[4/4] Упаковка портативного архива и расчет контрольных сумм SHA-256..." -ForegroundColor Yellow
    Compress-Archive -Path "$StagingDir\*" -DestinationPath $ZipPath -CompressionLevel Optimal -Force

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
finally {
    Pop-Location
}
