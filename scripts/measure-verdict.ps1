# Synthetic verdict microbenchmark for #62. Build first: .\mvnw.cmd verify
# Run with JDK 21: .\scripts\measure-verdict.ps1
# No server or network calls. Five batches after 300 warmups; heap fixed at 256 MiB.
param([string]$BaselineRef)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$jar = Get-ChildItem "$root/workbench-app/target/workbench-app-*.jar" | Select-Object -First 1
if (-not $jar) { throw 'Build the app with Maven verify first' }
$jdkBin = if ($env:JAVA_HOME) { Join-Path $env:JAVA_HOME 'bin' } else { '' }
$java = if ($jdkBin) { Join-Path $jdkBin 'java.exe' } else { 'java' }
$javac = if ($jdkBin) { Join-Path $jdkBin 'javac.exe' } else { 'javac' }
$jarTool = if ($jdkBin) { Join-Path $jdkBin 'jar.exe' } else { 'jar' }
$temp = Join-Path ([IO.Path]::GetTempPath()) ("verdict-bench-" + [guid]::NewGuid())
New-Item -ItemType Directory $temp | Out-Null
Push-Location $temp
try {
    & $jarTool xf $jar.FullName
    if ($LASTEXITCODE -ne 0) { throw 'Jar extraction failed' }
    $classpath = "$temp/BOOT-INF/classes;$temp/BOOT-INF/lib/*"
    if ($BaselineRef) {
        # Override only RunReport with the baseline source; shared helper remains the new implementation.
        $source = & git -C $root show "${BaselineRef}:workbench-app/src/main/java/io/github/dflippojr/payerworkbench/app/RunReport.java"
        if ($LASTEXITCODE -ne 0) { throw 'Cannot read baseline RunReport' }
        [IO.File]::WriteAllText("$temp/RunReport.java", ($source -join "`n"))
        & $javac -cp $classpath -d $temp "$temp/RunReport.java"
        if ($LASTEXITCODE -ne 0) { throw 'Baseline report compilation failed' }
    }
    & $javac -cp "$temp;$classpath" -d $temp "$root/scripts/VerdictBench.java"
    if ($LASTEXITCODE -ne 0) { throw 'Benchmark compilation failed' }
    & $java -Xmx256m -cp "$temp;$classpath" io.github.dflippojr.payerworkbench.app.VerdictBench
    if ($LASTEXITCODE -ne 0) { throw 'Benchmark failed' }
} finally {
    Pop-Location
    # Keep the isolated temp directory for inspection; no repository output is changed.
    Write-Host "Compiled benchmark: $temp"
}
