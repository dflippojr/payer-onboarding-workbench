# Exports a static replay bundle for embedding on a website: builds the workbench,
# starts it on a free port, records a fixed set of runs through the REST API and
# writes site-dist\ (gitignored). See scripts/export-replays.sh for the layout.
#
#   scripts\export-replays.ps1                                build, then record
#   $env:EXPORT_SKIP_BUILD = '1'; scripts\export-replays.ps1   reuse workbench-app\target\*.jar
#
# Copy the bundle into a site with: node scripts/vendor-into-site.mjs <site>/public/workbench
# Needs JDK 21 (JAVA_HOME or java on PATH) and git. Synthetic payers only.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root 'site-dist'
$work = Join-Path $root 'target\export-replays'
Set-Location $root

$java = if ($env:JAVA_HOME) { Join-Path $env:JAVA_HOME 'bin\java.exe' } else { 'java' }

if ($env:EXPORT_SKIP_BUILD -ne '1') {
    Write-Host '==> Building (tests skipped; run .\mvnw.cmd verify for those)'
    & .\mvnw.cmd -B -q -pl workbench-app -am package -DskipTests
    if ($LASTEXITCODE -ne 0) { throw "Build failed with exit code $LASTEXITCODE" }
}
$jar = Get-ChildItem 'workbench-app\target\workbench-app-*.jar' | Where-Object { $_.Name -notlike '*.original' } |
    Select-Object -First 1
if (-not $jar) { throw 'No workbench-app jar; run without EXPORT_SKIP_BUILD' }

foreach ($dir in $out, $work) {
    if (Test-Path $dir) { Remove-Item -Recurse -Force $dir }
}
New-Item -ItemType Directory -Force (Join-Path $out 'runs'), $work | Out-Null
$log = Join-Path $work 'app.log'
$utf8 = New-Object System.Text.UTF8Encoding $false

Write-Host '==> Starting the workbench on a free port'
$app = Start-Process -FilePath $java -ArgumentList @('-jar', "`"$($jar.FullName)`"", '--server.port=0') `
    -RedirectStandardOutput $log -RedirectStandardError (Join-Path $work 'app.err.log') -NoNewWindow -PassThru

$script:failures = 0
$script:runs = @()
$script:version = $null

function Invoke-Record {
    param([string]$Id, [string]$Title, [string]$Description, [string]$Payer, [string]$Fault, [string[]]$Expect)
    Write-Host ''
    Write-Host "==> $Title"
    $faults = if ($Fault) { "[`"$Fault`"]" } else { '[]' }
    $request = "{`"payerId`":`"$Payer`",`"sampleId`":`"order-sign-hospital-bed`",`"faults`":$faults}"
    $run = Invoke-RestMethod -Method Post -Uri "$base/api/runs" -ContentType 'application/json' -Body $request
    $file = Join-Path $out "runs\$Id.json"
    Invoke-WebRequest -UseBasicParsing -Uri "$base/api/runs/$($run.runId)/report?format=json" -OutFile $file
    $report = [System.IO.File]::ReadAllText($file, $utf8) | ConvertFrom-Json
    if (-not $script:version) { $script:version = $report.workbenchVersion }
    $found = @($report.findings | ForEach-Object { "$($_.severity) $($_.checkId)" })
    Write-Host "    Verdict: $($report.verdict.status)"
    Write-Host "    FAIL/WARN: $(($found | Where-Object { $_ -match '^(FAIL|WARN) ' }) -join ', ')"
    $hasFail = [bool]($found | Where-Object { $_ -like 'FAIL *' })
    foreach ($expected in $Expect) {
        if ($expected -eq 'no FAIL') {
            if ($hasFail) {
                Write-Host '    MISSING: expected no FAIL findings' -ForegroundColor Red
                $script:failures++
            }
        } elseif ($expected -eq 'a FAIL') {
            if (-not $hasFail) {
                Write-Host '    MISSING: expected at least one FAIL finding' -ForegroundColor Red
                $script:failures++
            }
        } elseif ($found -notcontains $expected) {
            Write-Host "    MISSING: expected finding $expected" -ForegroundColor Red
            $script:failures++
        }
    }
    $script:runs += [ordered]@{
        id = $Id; title = $Title; description = $Description; payerId = $Payer
        fault = if ($Fault) { $Fault } else { $null }
        verdict = $report.verdict.status; file = "runs/$Id.json"
    }
    Write-Host "    site-dist\runs\$Id.json"
}

try {
    $port = $null
    for ($i = 0; $i -lt 120 -and -not $port; $i++) {
        if (Test-Path $log) {
            $m = Select-String -Path $log -Pattern 'started on port (\d+)' | Select-Object -First 1
            if ($m) { $port = $m.Matches[0].Groups[1].Value }
        }
        if (-not $port) {
            if ($app.HasExited) { throw "The workbench exited during startup; see $log" }
            Start-Sleep -Seconds 1
        }
    }
    if (-not $port) { throw "The workbench did not start within 120 s; see $log" }
    $base = "http://127.0.0.1:$port"
    Write-Host "    $base"

    Invoke-Record 'northwind-healthy' 'Northwind, healthy' `
        'OAuth2 client credentials payer; every step passes.' `
        'northwind-synthetic' $null @('no FAIL', 'PASS auth.token')

    Invoke-Record 'fabrikam-healthy' 'Fabrikam, healthy' `
        'CDS Hooks JWT payer; every step passes.' `
        'fabrikam-synthetic' $null @('no FAIL', 'PASS response.schema')

    Invoke-Record 'fabrikam-wrong-audience-reject' 'Fabrikam rejects the token audience' `
        'The payer checks the JWT aud against a different URL and rejects the hook call.' `
        'fabrikam-synthetic' 'wrong-audience-reject' @('a FAIL')

    Invoke-Record 'northwind-expired-token-401' 'Northwind says the token expired' `
        'Hook calls get 401 invalid_token with an expired-token message.' `
        'northwind-synthetic' 'expired-token-401' @('a FAIL')

    Invoke-Record 'fabrikam-malformed-card' 'Fabrikam returns malformed cards' `
        'Cards come back without summary and indicator.' `
        'fabrikam-synthetic' 'malformed-card' @('FAIL response.schema')

    Write-Host ''
    Write-Host '    (the next run holds every payer response for about 11 s)'
    Invoke-Record 'northwind-slow-response' 'Northwind is slow' `
        'Every payer response is held past the latency budget.' `
        'northwind-synthetic' 'slow-response' @('FAIL perf.latency')
} finally {
    if (-not $app.HasExited) { Stop-Process -Id $app.Id -Force }
}

foreach ($name in 'replay.js', 'replay.css', 'index.html') {
    Copy-Item (Join-Path $root "replay\$name") (Join-Path $out $name)
}

$commit = 'unknown'
try {
    $head = (& git rev-parse --short=12 HEAD 2>$null)
    if ($LASTEXITCODE -eq 0 -and $head) {
        $commit = if (& git status --porcelain --untracked-files=no) { "$head-dirty" } else { "$head" }
    }
} catch {
    $commit = 'unknown'
}
$manifest = [ordered]@{
    name = 'payer-onboarding-workbench replay bundle'
    workbenchVersion = $script:version
    gitCommit = "$commit"
    generatedAt = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    disclaimer = 'Recorded run against a synthetic mock payer. Passing here does not prove real-payer interoperability.'
    runs = $script:runs
}
[System.IO.File]::WriteAllText((Join-Path $out 'manifest.json'), (ConvertTo-Json -Depth 5 $manifest), $utf8)

$leaks = Get-ChildItem $out -Recurse -File | Select-String -Pattern 'PRIVATE KEY|client_secret=[^\[]' -List
if ($leaks) {
    Write-Host 'The bundle contains unredacted key or secret material' -ForegroundColor Red
    $script:failures++
}

Write-Host ''
if ($script:failures -gt 0) {
    Write-Host "Export FAILED: $($script:failures) expectation(s) not met. The partial bundle is in site-dist\." -ForegroundColor Red
    exit 1
}
Write-Host "Export done: $($script:runs.Count) runs in site-dist\. Check it with: node --test replay/test/bundle.test.mjs"
