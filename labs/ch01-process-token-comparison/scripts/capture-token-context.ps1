param(
    [string]$Label = "context"
)

$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path $env:TEMP "InternalsNoteBookTokenLab"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$outFile = Join-Path $outDir "$timestamp-$Label-token.txt"

"label=$Label" | Out-File -FilePath $outFile -Encoding utf8
"timestamp=$(Get-Date -Format o)" | Out-File -FilePath $outFile -Append -Encoding utf8
"pid=$PID" | Out-File -FilePath $outFile -Append -Encoding utf8
"user=$env:USERNAME" | Out-File -FilePath $outFile -Append -Encoding utf8
"computer=$env:COMPUTERNAME" | Out-File -FilePath $outFile -Append -Encoding utf8
"" | Out-File -FilePath $outFile -Append -Encoding utf8

whoami /all | Out-File -FilePath $outFile -Append -Encoding utf8

Write-Host "[lab] wrote $outFile"
Write-Host "[lab] pid=$PID"

