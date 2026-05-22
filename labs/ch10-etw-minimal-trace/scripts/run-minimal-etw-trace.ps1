param(
    [string]$OutRoot = "$env:TEMP\InternalsNoteBookEtwTrace",
    [string]$SessionName = "InternalsNoteBookEtwLab",
    [string]$Provider = "Microsoft-Windows-PowerShell"
)

$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path $OutRoot $timestamp
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$etlPath = Join-Path $outDir "trace.etl"
$summaryPath = Join-Path $outDir "trace-summary.txt"

"timestamp=$(Get-Date -Format o)" | Out-File -FilePath $summaryPath -Encoding utf8
"session=$SessionName" | Out-File -FilePath $summaryPath -Append -Encoding utf8
"provider=$Provider" | Out-File -FilePath $summaryPath -Append -Encoding utf8
"pid=$PID" | Out-File -FilePath $summaryPath -Append -Encoding utf8

cmd /c logman stop $SessionName -ets > (Join-Path $outDir "pre-clean-stop.txt") 2>&1

cmd /c logman start $SessionName -p $Provider 0xFFFFFFFF 0x5 -o "$etlPath" -ets > (Join-Path $outDir "logman-start.txt") 2>&1
$startExit = $LASTEXITCODE
"start_exit=$startExit" | Out-File -FilePath $summaryPath -Append -Encoding utf8

if ($startExit -ne 0) {
    Write-Host "[lab] logman start failed. See logman-start.txt in $outDir"
    Write-Host "[lab] Try running PowerShell as administrator."
    exit 1
}

Write-Host "[lab] trace started: $SessionName"

Write-Output "InternalsNoteBook ETW controlled activity" | Out-Null
Get-Command Get-Process | Out-Null
Get-Process -Id $PID | Out-Null
Start-Sleep -Milliseconds 500

cmd /c logman stop $SessionName -ets > (Join-Path $outDir "logman-stop.txt") 2>&1
$stopExit = $LASTEXITCODE
"stop_exit=$stopExit" | Out-File -FilePath $summaryPath -Append -Encoding utf8

if (Test-Path $etlPath) {
    $etl = Get-Item $etlPath
    "etl_size=$($etl.Length)" | Out-File -FilePath $summaryPath -Append -Encoding utf8
}

cmd /c tracerpt "$etlPath" -o (Join-Path $outDir "trace-report.csv") -of CSV > (Join-Path $outDir "tracerpt.txt") 2>&1
"tracerpt_exit=$LASTEXITCODE" | Out-File -FilePath $summaryPath -Append -Encoding utf8

Write-Host "[lab] trace artifacts written to: $outDir"
Write-Host "[lab] evidence is scoped to this session/provider/capture window."

