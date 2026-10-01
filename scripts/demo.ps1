# Repeatable demo: builds the workbench, starts it on a free port, runs a scripted
# tour through the REST API and writes each run's report to demo-output\ as
# Markdown, HTML and JSON. Exits non-zero if any expected finding is missing.
#
#   scripts\demo.ps1                          build, then run the tour
#   $env:DEMO_SKIP_BUILD = '1'; scripts\demo.ps1   reuse workbench-app\target\*.jar
#
# Needs JDK 21 (JAVA_HOME or java on PATH). Synthetic payers only.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root 'demo-output'
Set-Location $root

$java = if ($env:JAVA_HOME) { Join-Path $env:JAVA_HOME 'bin\java.exe' } else { 'java' }

if ($env:DEMO_SKIP_BUILD -ne '1') {
    Write-Host '==> Building (tests skipped; run .\mvnw.cmd verify for those)'
    & .\mvnw.cmd -B -q -pl workbench-app -am package -DskipTests
    if ($LASTEXITCODE -ne 0) { throw "Build failed with exit code $LASTEXITCODE" }
}
$jar = Get-ChildItem 'workbench-app\target\workbench-app-*.jar' | Select-Object -First 1
if (-not $jar) { throw 'No workbench-app jar; run without DEMO_SKIP_BUILD' }

if (Test-Path $out) { Remove-Item -Recurse -Force $out }
New-Item -ItemType Directory -Force $out | Out-Null
$log = Join-Path $out 'app.log'

Write-Host '==> Starting the workbench on a free port'
$app = Start-Process -FilePath $java -ArgumentList @('-jar', "`"$($jar.FullName)`"", '--server.port=0') `
    -RedirectStandardOutput $log -RedirectStandardError (Join-Path $out 'app.err.log') -NoNewWindow -PassThru

$script:failures = 0
$script:step = 0

function Invoke-Tour {
    param([string]$Name, [string]$Title, [string]$Request, [string[]]$Expect)
    $script:step++
    $prefix = '{0:D2}-{1}' -f $script:step, $Name
    Write-Host ''
    Write-Host "==> $($script:step). $Title"
    $run = Invoke-RestMethod -Method Post -Uri "$base/api/runs" -ContentType 'application/json' -Body $Request
    foreach ($format in 'md', 'html', 'json') {
        Invoke-WebRequest -UseBasicParsing -Uri "$base/api/runs/$($run.runId)/report?format=$format" `
            -OutFile (Join-Path $out "$prefix.$format")
    }
    $report = Get-Content -Raw -Encoding UTF8 (Join-Path $out "$prefix.json") | ConvertFrom-Json
    $found = @($report.findings | ForEach-Object { "$($_.severity) $($_.checkId)" })
    Write-Host "    Verdict: $($report.verdict.status)"
    Write-Host "    FAIL/WARN: $(($found | Where-Object { $_ -match '^(FAIL|WARN) ' }) -join ', ')"
    foreach ($expected in $Expect) {
        if ($expected -eq 'no FAIL') {
            if ($found | Where-Object { $_ -like 'FAIL *' }) {
                Write-Host '    MISSING: expected no FAIL findings' -ForegroundColor Red
                $script:failures++
            }
        } elseif ($found -notcontains $expected) {
            Write-Host "    MISSING: expected finding $expected" -ForegroundColor Red
            $script:failures++
        }
    }
    Write-Host "    reports: demo-output\$prefix.{md,html,json}"
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

    Invoke-Tour 'healthy-northwind' 'Northwind (OAuth2 client credentials), healthy' `
        '{"payerId":"northwind-synthetic","sampleId":"order-sign-hospital-bed"}' `
        @('no FAIL', 'PASS discovery.reachable', 'PASS auth.token', 'PASS response.schema')

    Invoke-Tour 'healthy-fabrikam' 'Fabrikam (CDS Hooks JWT), healthy' `
        '{"payerId":"fabrikam-synthetic","sampleId":"order-sign-hospital-bed"}' `
        @('no FAIL', 'PASS discovery.reachable', 'PASS ig.version', 'PASS response.schema')

    Invoke-Tour 'fabrikam-wrong-audience' 'Fabrikam with wrong-audience-reject: the payer rejects the JWT audience' `
        '{"payerId":"fabrikam-synthetic","sampleId":"order-sign-hospital-bed","faults":["wrong-audience-reject"]}' `
        @('FAIL auth.jwt-audience')

    Write-Host ''
    Write-Host '    (the next run holds every payer response for about 11 s)'
    Invoke-Tour 'northwind-slow-response' 'Northwind with slow-response: every response is past the latency budget' `
        '{"payerId":"northwind-synthetic","sampleId":"order-sign-hospital-bed","faults":["slow-response"]}' `
        @('FAIL perf.latency')

    $leaks = Get-ChildItem $out -Include '*.md', '*.html', '*.json' -Recurse |
        Select-String -Pattern 'PRIVATE KEY|client_secret=[^\[]' -List
    if ($leaks) {
        Write-Host 'A report contains unredacted key or secret material' -ForegroundColor Red
        $script:failures++
    }
} finally {
    if (-not $app.HasExited) { Stop-Process -Id $app.Id -Force }
}

Write-Host ''
if ($script:failures -gt 0) {
    Write-Host "Demo FAILED: $($script:failures) expectation(s) not met. Reports are in demo-output\." -ForegroundColor Red
    exit 1
}
Write-Host "Demo passed: $($script:step) runs, every expected finding present. Reports are in demo-output\."
