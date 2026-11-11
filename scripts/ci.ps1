<#
.SYNOPSIS
    Проверка изменения: сборка всего решения, модульные тесты и пробная сборка портативной версии.

.DESCRIPTION
    Скрипт ничего не публикует и не трогает релизы. Его вызывает GitHub Actions
    (.github/workflows/ci.yml) на каждый pull request, и его же можно запустить у себя:

        .\scripts\ci.ps1                 # все шаги подряд
        .\scripts\ci.ps1 -Step Build     # только сборка
        .\scripts\ci.ps1 -Step Test      # только тесты
        .\scripts\ci.ps1 -Step Publish   # только пробная сборка портативной версии

    В GitHub Actions итог каждого шага дублируется в аннотации запуска и в сводку задания,
    чтобы причину сбоя было видно без чтения полного журнала.
#>
[CmdletBinding()]
param(
    [ValidateSet("All", "Build", "Test", "Publish")]
    [string]$Step = "All",
    [string]$Configuration = "Release",
    [string]$Runtime = "win-x64"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$Solution = Join-Path $RepoRoot "UltimateWindows.sln"
$ResultsDir = Join-Path $RepoRoot "TestResults"
$InActions = ($env:GITHUB_ACTIONS -eq "true")

# ---------------------------------------------------------------------------------------------
# Вывод: аннотации GitHub Actions, сводка задания, журнал
# ---------------------------------------------------------------------------------------------

function ConvertTo-CommandData {
    param([string]$Text)
    if ($null -eq $Text) { return "" }
    return $Text.Replace("%", "%25").Replace("`r", "").Replace("`n", "%0A")
}

function ConvertTo-CommandProperty {
    param([string]$Text)
    if ($null -eq $Text) { return "" }
    return $Text.Replace("%", "%25").Replace("`r", "").Replace("`n", " ").Replace(":", "%3A").Replace(",", "%2C")
}

function Write-Annotation {
    param(
        [ValidateSet("error", "warning", "notice")]
        [string]$Level,
        [string]$Title,
        [string]$Message
    )

    if ($InActions) {
        Write-Host ("::{0} title={1}::{2}" -f $Level, (ConvertTo-CommandProperty $Title), (ConvertTo-CommandData $Message))
    }
    else {
        Write-Host ("[{0}] {1}" -f $Level.ToUpperInvariant(), $Title)
        Write-Host $Message
    }
}

function Write-ChunkedAnnotations {
    param(
        [string]$Level,
        [string]$Title,
        [string[]]$Lines,
        [int]$MaxAnnotations = 8,
        [int]$MaxChars = 3000
    )

    $chunks = New-Object 'System.Collections.Generic.List[string]'
    $current = New-Object System.Text.StringBuilder

    foreach ($line in @($Lines)) {
        if ($null -eq $line) { continue }
        $text = [string]$line
        if ($text.Length -gt $MaxChars) { $text = $text.Substring(0, $MaxChars) + " ..." }

        if ($current.Length -gt 0 -and ($current.Length + $text.Length + 1) -gt $MaxChars) {
            $chunks.Add($current.ToString())
            $current = New-Object System.Text.StringBuilder
        }

        if ($current.Length -gt 0) { [void]$current.Append("`n") }
        [void]$current.Append($text)
    }

    if ($current.Length -gt 0) { $chunks.Add($current.ToString()) }

    $total = $chunks.Count
    $shown = [Math]::Min($total, $MaxAnnotations)
    for ($i = 0; $i -lt $shown; $i++) {
        Write-Annotation -Level $Level -Title ("{0} ({1}/{2})" -f $Title, ($i + 1), $total) -Message $chunks[$i]
    }
}

function Add-JobSummary {
    param([string[]]$MarkdownLines)
    if ($InActions -and -not [string]::IsNullOrWhiteSpace($env:GITHUB_STEP_SUMMARY)) {
        Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value $MarkdownLines -Encoding utf8
    }
}

function Write-LogGroup {
    param([string]$Title, [string[]]$Lines)
    if ($InActions) { Write-Host "::group::$Title" }
    foreach ($line in @($Lines)) { Write-Host $line }
    if ($InActions) { Write-Host "::endgroup::" }
}

# ---------------------------------------------------------------------------------------------
# Запуск dotnet и разбор его вывода
# ---------------------------------------------------------------------------------------------

function Invoke-Dotnet {
    param([string[]]$Arguments)

    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $lines = @(& dotnet @Arguments 2>&1 | ForEach-Object { "$_" })
    $code = $LASTEXITCODE
    $ErrorActionPreference = $previous

    return [pscustomobject]@{
        ExitCode = $code
        Lines    = $lines
    }
}

function Get-DistinctDiagnostics {
    param(
        [string[]]$Lines,
        [ValidateSet("error", "warning")]
        [string]$Kind
    )

    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $result = New-Object 'System.Collections.Generic.List[string]'
    $rootPrefix = $RepoRoot.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    $pattern = "(^|[\s:])$Kind\s+[A-Za-z]+[0-9]+\s*:"

    foreach ($raw in @($Lines)) {
        if ([string]::IsNullOrWhiteSpace($raw)) { continue }
        if ($raw -notmatch $pattern) { continue }

        $line = $raw.Trim()
        # MSBuild дописывает в конец строки путь проекта в квадратных скобках — он только мешает читать
        $line = [regex]::Replace($line, '\s*\[[^\[\]]*proj[^\[\]]*\]\s*$', '')
        $line = $line.Replace($rootPrefix, '')

        if ($seen.Add($line)) { $result.Add($line) }
    }

    return $result.ToArray()
}

function Write-StepFailure {
    param([string]$Title, [string[]]$Lines)

    $errors = @(Get-DistinctDiagnostics -Lines $Lines -Kind "error")
    if ($errors.Count -eq 0) {
        # Строк вида "error XX0000:" нет — показываем хвост журнала
        $errors = @($Lines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Last 40)
    }

    Write-ChunkedAnnotations -Level "error" -Title $Title -Lines $errors

    $summary = New-Object 'System.Collections.Generic.List[string]'
    $summary.Add("### ❌ $Title")
    $summary.Add("")
    $summary.Add('```text')
    foreach ($e in ($errors | Select-Object -First 60)) { $summary.Add([string]$e) }
    $summary.Add('```')
    $summary.Add("")
    Add-JobSummary -MarkdownLines $summary.ToArray()
}

# ---------------------------------------------------------------------------------------------
# Шаги
# ---------------------------------------------------------------------------------------------

function Invoke-BuildStep {
    Write-Host "== Сборка решения ($Configuration) =="

    $sdkVersion = "неизвестно"
    $versionRun = Invoke-Dotnet -Arguments @("--version")
    if ($versionRun.ExitCode -eq 0 -and @($versionRun.Lines).Count -gt 0) {
        $sdkVersion = [string](@($versionRun.Lines)[-1])
    }
    Write-Host ".NET SDK: $sdkVersion"

    $restore = Invoke-Dotnet -Arguments @("restore", $Solution, "--nologo")
    if ($restore.ExitCode -ne 0) {
        Write-StepFailure -Title "Не удалось восстановить пакеты NuGet" -Lines $restore.Lines
        Write-LogGroup -Title "dotnet restore: полный журнал" -Lines $restore.Lines
        throw "dotnet restore завершился с кодом $($restore.ExitCode)."
    }

    $build = Invoke-Dotnet -Arguments @("build", $Solution, "-c", $Configuration, "--no-restore", "--nologo")
    $warnings = @(Get-DistinctDiagnostics -Lines $build.Lines -Kind "warning")

    if ($build.ExitCode -ne 0) {
        Write-StepFailure -Title "Ошибки компиляции" -Lines $build.Lines
        Write-LogGroup -Title "dotnet build: полный журнал" -Lines $build.Lines
        throw "dotnet build завершился с кодом $($build.ExitCode)."
    }

    $message = "SDK $sdkVersion • ошибок: 0 • предупреждений: $($warnings.Count)"
    Write-Annotation -Level "notice" -Title "Сборка прошла" -Message $message
    if ($warnings.Count -gt 0) {
        Write-ChunkedAnnotations -Level "notice" -Title "Предупреждения компилятора" -Lines $warnings -MaxAnnotations 1
    }

    Add-JobSummary -MarkdownLines @("### ✅ Сборка прошла", "", $message, "")
    Write-LogGroup -Title "dotnet build: полный журнал" -Lines $build.Lines
}

function Read-TrxSummary {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $null }

    $trx = New-Object System.Xml.XmlDocument
    $trx.Load($Path)

    $ns = New-Object System.Xml.XmlNamespaceManager($trx.NameTable)
    $ns.AddNamespace("t", "http://microsoft.com/schemas/VisualStudio/TeamTest/2010")

    $counters = $trx.SelectSingleNode("//t:ResultSummary/t:Counters", $ns)
    if ($null -eq $counters) { return $null }

    $failedLines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($node in $trx.SelectNodes("//t:UnitTestResult[@outcome='Failed']", $ns)) {
        $name = $node.GetAttribute("testName")
        $messageNode = $node.SelectSingleNode("t:Output/t:ErrorInfo/t:Message", $ns)
        $stackNode = $node.SelectSingleNode("t:Output/t:ErrorInfo/t:StackTrace", $ns)

        $failedLines.Add("[FAIL] $name")
        if ($null -ne $messageNode) {
            $failedLines.Add("  " + $messageNode.InnerText.Trim())
        }
        if ($null -ne $stackNode) {
            $frames = @($stackNode.InnerText -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -First 3)
            if ($frames.Count -gt 0) { $failedLines.Add("  " + ($frames -join " <- ")) }
        }
    }

    return [pscustomobject]@{
        Total       = [int]$counters.GetAttribute("total")
        Executed    = [int]$counters.GetAttribute("executed")
        Passed      = [int]$counters.GetAttribute("passed")
        Failed      = [int]$counters.GetAttribute("failed")
        FailedLines = $failedLines.ToArray()
    }
}

function Invoke-TestStep {
    Write-Host "== Модульные тесты ($Configuration) =="

    if (Test-Path -LiteralPath $ResultsDir) {
        Remove-Item -LiteralPath $ResultsDir -Recurse -Force
    }

    $test = Invoke-Dotnet -Arguments @(
        "test", $Solution,
        "-c", $Configuration,
        "--nologo",
        "--logger", "trx;LogFileName=unit-tests.trx",
        "--logger", "console;verbosity=normal",
        "--results-directory", $ResultsDir
    )

    $summary = Read-TrxSummary -Path (Join-Path $ResultsDir "unit-tests.trx")

    if ($test.ExitCode -ne 0) {
        if ($null -ne $summary -and $summary.Failed -gt 0) {
            $title = "Тесты не прошли: $($summary.Failed) из $($summary.Total)"
            Write-ChunkedAnnotations -Level "error" -Title $title -Lines $summary.FailedLines

            $md = New-Object 'System.Collections.Generic.List[string]'
            $md.Add("### ❌ $title")
            $md.Add("")
            $md.Add('```text')
            foreach ($l in ($summary.FailedLines | Select-Object -First 120)) { $md.Add([string]$l) }
            $md.Add('```')
            $md.Add("")
            Add-JobSummary -MarkdownLines $md.ToArray()
        }
        else {
            Write-StepFailure -Title "dotnet test завершился с ошибкой" -Lines $test.Lines
        }

        Write-LogGroup -Title "dotnet test: полный журнал" -Lines $test.Lines
        throw "dotnet test завершился с кодом $($test.ExitCode)."
    }

    if ($null -eq $summary) {
        $message = "dotnet test завершился успешно, но отчёт unit-tests.trx не найден."
        Write-Annotation -Level "warning" -Title "Тесты: нет отчёта" -Message $message
        Add-JobSummary -MarkdownLines @("### ⚠️ Тесты: нет отчёта", "", $message, "")
    }
    elseif ($summary.Total -eq 0) {
        Write-Annotation -Level "error" -Title "Тесты не найдены" -Message "В решении не выполнено ни одного теста."
        Write-LogGroup -Title "dotnet test: полный журнал" -Lines $test.Lines
        throw "Не выполнено ни одного теста."
    }
    else {
        $message = "всего: $($summary.Total) • пройдено: $($summary.Passed) • не пройдено: $($summary.Failed)"
        Write-Annotation -Level "notice" -Title "Тесты прошли" -Message $message
        Add-JobSummary -MarkdownLines @("### ✅ Тесты прошли", "", $message, "")
    }

    Write-LogGroup -Title "dotnet test: полный журнал" -Lines $test.Lines
}

function Invoke-PublishStep {
    Write-Host "== Пробная сборка портативной версии ($Runtime), без выгрузки =="

    $builder = Join-Path $PSScriptRoot "build-portable-release.ps1"
    & $builder -Version "0.0.0-ci" -Runtime $Runtime -SkipTests

    $zip = Join-Path $RepoRoot "artifacts\UltimateWindows-v0.0.0-ci-$Runtime-portable.zip"
    if (-not (Test-Path -LiteralPath $zip)) {
        throw "Портативный архив не создан: $zip"
    }

    $sizeMb = [Math]::Round((Get-Item -LiteralPath $zip).Length / 1048576.0, 1)
    $message = "архив собран, размер $sizeMb МБ (никуда не выгружен)"
    Write-Annotation -Level "notice" -Title "Портативная сборка прошла" -Message $message
    Add-JobSummary -MarkdownLines @("### ✅ Портативная сборка прошла", "", $message, "")
}

# ---------------------------------------------------------------------------------------------
# Точка входа
# ---------------------------------------------------------------------------------------------

$failed = $false
Push-Location $RepoRoot
try {
    switch ($Step) {
        "Build" { Invoke-BuildStep }
        "Test" { Invoke-TestStep }
        "Publish" { Invoke-PublishStep }
        default {
            Invoke-BuildStep
            Invoke-TestStep
            Invoke-PublishStep
        }
    }
}
catch {
    $failed = $true
    $detail = "$($_.Exception.Message)`n$($_.ScriptStackTrace)"
    Write-Annotation -Level "error" -Title "Шаг проверки «$Step» не пройден" -Message $detail
}
finally {
    Pop-Location
}

if ($failed) {
    exit 1
}

Write-Host "Готово: шаг «$Step» пройден."
exit 0
