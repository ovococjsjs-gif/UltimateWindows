<#
.SYNOPSIS
    Проверка изменения: сборка всего решения, тесты и пробная сборка портативной версии.

.DESCRIPTION
    Скрипт ничего не публикует и не трогает релизы. Его вызывает GitHub Actions
    (.github/workflows/ci.yml) на каждый pull request, и его же можно запустить у себя:

        .\scripts\ci.ps1                 # все шаги подряд
        .\scripts\ci.ps1 -Step Build     # только сборка
        .\scripts\ci.ps1 -Step Test      # только тесты
        .\scripts\ci.ps1 -Step Publish   # только пробная сборка портативной версии

    В GitHub Actions итог каждого шага дублируется в аннотации запуска и в сводку задания,
    чтобы причину сбоя было видно без чтения полного журнала.

    Тесты лежат в двух проектах: UltimateWindows.UnitTests (логика, без обращения к системе) и
    UltimateWindows.WindowsTests (интерфейс WPF и работа с настоящей Windows). Вторые пишут короткие
    отчёты, которые попадают в аннотацию «Проверки на Windows». Снимки интерфейса, перечисленные в
    tests/UltimateWindows.WindowsTests/ui-snapshots.txt, передаются аннотациями «uwshot …»:
    сборочная машина файлы не выгружает. В PNG их превращает scripts/read-ui-shots.py.
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
$ReportsDir = Join-Path $ResultsDir "reports"
$UiShotsDir = Join-Path $ResultsDir "ui-shots"
$UiShotRequestFile = Join-Path $RepoRoot "tests/UltimateWindows.WindowsTests/ui-snapshots.txt"
$InActions = ($env:GITHUB_ACTIONS -eq "true")

# Аннотация вмещает 4096 знаков, а шаг — десять аннотаций одного вида.
# Снимки идут в шаге тестов и в шаге пробной сборки, где свободны 8 и 9 аннотаций.
$UiShotChunkChars = 4000
$UiShotNoticesInTestStep = 8
$UiShotNoticesInPublishStep = 9

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

function Get-FailureLines {
    param([string[]]$Lines)

    $errors = @(Get-DistinctDiagnostics -Lines $Lines -Kind "error")
    if ($errors.Count -eq 0) {
        # Строк вида "error XX0000:" нет — показываем хвост журнала
        $errors = @($Lines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Last 40)
    }

    return $errors
}

function Write-StepFailure {
    param([string]$Title, [string[]]$Lines)

    $errors = @(Get-FailureLines -Lines $Lines)

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

# ---------------------------------------------------------------------------------------------
# Отчёты и снимки интерфейса от проверок на Windows
# ---------------------------------------------------------------------------------------------

function Get-RequestedUiShots {
    if (-not (Test-Path -LiteralPath $UiShotRequestFile)) { return @() }

    $names = New-Object 'System.Collections.Generic.List[string]'
    foreach ($raw in @(Get-Content -LiteralPath $UiShotRequestFile -Encoding utf8)) {
        $line = ([string]$raw).Trim()
        if ($line.Length -eq 0 -or $line.StartsWith("#")) { continue }
        if (-not $names.Contains($line)) { $names.Add($line) }
    }

    return $names.ToArray()
}

function New-UiShotQueue {
    # Делит запрошенные снимки на части по размеру аннотации. В очередь попадают только снимки,
    # которые помещаются целиком: от половины снимка пользы нет.
    param([string[]]$Names)

    $budget = $UiShotNoticesInTestStep + $UiShotNoticesInPublishStep
    $queue = New-Object 'System.Collections.Generic.List[string]'
    $report = New-Object 'System.Collections.Generic.List[string]'

    foreach ($name in @($Names)) {
        $path = Join-Path $UiShotsDir "$name.txt"
        if (-not (Test-Path -LiteralPath $path)) {
            $report.Add("${name}: снимок не сделан")
            continue
        }

        $text = ([string](Get-Content -LiteralPath $path -Raw -Encoding utf8)).Trim()
        $parts = [int][Math]::Ceiling($text.Length / [double]$UiShotChunkChars)
        if ($parts -gt ($budget - $queue.Count)) {
            $report.Add("${name}: не поместился ($parts частей)")
            continue
        }

        for ($i = 0; $i -lt $parts; $i++) {
            $start = $i * $UiShotChunkChars
            $length = [Math]::Min($UiShotChunkChars, $text.Length - $start)
            $queue.Add(("uwshot {0} {1}/{2}`t{3}" -f $name, ($i + 1), $parts, $text.Substring($start, $length)))
        }

        $report.Add("${name}: передан, частей $parts")
    }

    if (-not (Test-Path -LiteralPath $UiShotsDir)) { New-Item -ItemType Directory -Path $UiShotsDir -Force | Out-Null }
    Set-Content -LiteralPath (Join-Path $UiShotsDir "queue.tsv") -Value $queue.ToArray() -Encoding utf8

    if (-not (Test-Path -LiteralPath $ReportsDir)) { New-Item -ItemType Directory -Path $ReportsDir -Force | Out-Null }
    Set-Content -LiteralPath (Join-Path $ReportsDir "ui-shots.txt") -Value $report.ToArray() -Encoding utf8
}

function Send-UiShotQueue {
    # Отправляет очередные части снимков аннотациями и запоминает, на чём остановился
    param([int]$MaxNotices)

    $queuePath = Join-Path $UiShotsDir "queue.tsv"
    if (-not $InActions -or -not (Test-Path -LiteralPath $queuePath)) { return }

    $entries = @(Get-Content -LiteralPath $queuePath -Encoding utf8 | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $cursorPath = Join-Path $UiShotsDir "queue.sent"
    $sent = 0
    if (Test-Path -LiteralPath $cursorPath) {
        $sent = [int](([string](Get-Content -LiteralPath $cursorPath -Raw)).Trim())
    }

    $count = [Math]::Min($MaxNotices, $entries.Count - $sent)
    for ($i = 0; $i -lt $count; $i++) {
        $parts = ([string]$entries[$sent + $i]) -split "`t", 2
        Write-Annotation -Level "notice" -Title $parts[0] -Message $parts[1]
    }

    if ($count -gt 0) {
        Set-Content -LiteralPath $cursorPath -Value ([string]($sent + $count))
    }
}

function Write-WindowsTestReports {
    if (-not (Test-Path -LiteralPath $ReportsDir)) { return }

    $lines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($file in @(Get-ChildItem -LiteralPath $ReportsDir -Filter "*.txt" | Sort-Object Name)) {
        $lines.Add("[$($file.BaseName)]")
        foreach ($line in @(Get-Content -LiteralPath $file.FullName -Encoding utf8)) {
            $text = [string]$line
            if ($text.Length -gt 600) { $text = $text.Substring(0, 600) + " ..." }
            $lines.Add("  " + $text)
        }
    }

    if ($lines.Count -eq 0) { return }

    Write-ChunkedAnnotations -Level "notice" -Title "Проверки на Windows" -Lines $lines.ToArray() -MaxAnnotations 1 -MaxChars 3800
    Write-LogGroup -Title "Проверки на Windows: отчёты" -Lines $lines.ToArray()
}

function Invoke-TestStep {
    Write-Host "== Тесты ($Configuration) =="

    if (Test-Path -LiteralPath $ResultsDir) {
        Remove-Item -LiteralPath $ResultsDir -Recurse -Force
    }

    # Проверки на Windows пишут сюда отчёты; снимки интерфейса делаются, только если они запрошены
    $env:UW_TEST_REPORT_DIR = $ReportsDir
    $requestedShots = @(Get-RequestedUiShots)
    if ($requestedShots.Count -gt 0) {
        $env:UW_UI_SHOT_DIR = $UiShotsDir
        $env:UW_UI_SHOTS = ($requestedShots -join ";")
    }

    $projects = @(Get-ChildItem -LiteralPath (Join-Path $RepoRoot "tests") -Filter "*.csproj" -Recurse | Sort-Object Name)
    if ($projects.Count -eq 0) {
        throw "В каталоге tests нет проектов с тестами."
    }

    $logLines = New-Object 'System.Collections.Generic.List[string]'
    $failedLines = New-Object 'System.Collections.Generic.List[string]'
    $perProject = New-Object 'System.Collections.Generic.List[string]'
    $total = 0
    $passed = 0
    $failed = 0
    $exitCode = 0

    # Проекты запускаются по очереди: у каждого свой отчёт, а проверки на Windows не мешают остальным
    foreach ($project in $projects) {
        $name = $project.BaseName
        $run = Invoke-Dotnet -Arguments @(
            "test", $project.FullName,
            "-c", $Configuration,
            "--nologo",
            "--logger", "trx;LogFileName=$name.trx",
            "--logger", "console;verbosity=normal",
            "--results-directory", $ResultsDir
        )

        $logLines.Add("===== $name =====")
        foreach ($line in @($run.Lines)) { $logLines.Add([string]$line) }
        if ($run.ExitCode -ne 0) { $exitCode = $run.ExitCode }

        $summary = Read-TrxSummary -Path (Join-Path $ResultsDir "$name.trx")
        if ($null -ne $summary) {
            $total += $summary.Total
            $passed += $summary.Passed
            $failed += $summary.Failed
            $perProject.Add("$name $($summary.Passed)/$($summary.Total)")
            foreach ($line in @($summary.FailedLines)) { $failedLines.Add([string]$line) }
        }

        if ($run.ExitCode -ne 0 -and ($null -eq $summary -or $summary.Failed -eq 0)) {
            # Тесты не дошли до результата: ошибка сборки или падение процесса. Причина — в журнале
            $failedLines.Add("[$name] dotnet test завершился с кодом $($run.ExitCode)")
            foreach ($line in @(Get-FailureLines -Lines $run.Lines)) { $failedLines.Add("  " + [string]$line) }
        }
    }

    if ($requestedShots.Count -gt 0) {
        New-UiShotQueue -Names $requestedShots
    }

    Write-WindowsTestReports
    Send-UiShotQueue -MaxNotices $UiShotNoticesInTestStep

    $counts = "всего: $total • пройдено: $passed • не пройдено: $failed"
    $breakdown = ($perProject.ToArray() -join "; ")

    if ($exitCode -ne 0) {
        $title = "Тесты не прошли: $failed из $total"
        Write-ChunkedAnnotations -Level "error" -Title $title -Lines $failedLines.ToArray()

        $md = New-Object 'System.Collections.Generic.List[string]'
        $md.Add("### ❌ $title")
        $md.Add("")
        $md.Add('```text')
        foreach ($line in ($failedLines.ToArray() | Select-Object -First 120)) { $md.Add([string]$line) }
        $md.Add('```')
        $md.Add("")
        Add-JobSummary -MarkdownLines $md.ToArray()

        Write-LogGroup -Title "dotnet test: полный журнал" -Lines $logLines.ToArray()
        throw "dotnet test завершился с кодом $exitCode."
    }

    if ($total -eq 0) {
        Write-Annotation -Level "error" -Title "Тесты не найдены" -Message "Не выполнено ни одного теста."
        Write-LogGroup -Title "dotnet test: полный журнал" -Lines $logLines.ToArray()
        throw "Не выполнено ни одного теста."
    }

    $message = "$counts ($breakdown)"
    Write-Annotation -Level "notice" -Title "Тесты прошли" -Message $message
    Add-JobSummary -MarkdownLines @("### ✅ Тесты прошли", "", $message, "")

    Write-LogGroup -Title "dotnet test: полный журнал" -Lines $logLines.ToArray()
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

    # Части снимков интерфейса, которые не поместились в шаг тестов
    Send-UiShotQueue -MaxNotices $UiShotNoticesInPublishStep
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
