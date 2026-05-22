$ErrorActionPreference = "Stop"

$labName = "InternalsNoteBookProcmonLab"
$root = Join-Path $env:TEMP $labName
$file = Join-Path $root "controlled-file.txt"
$regPath = "HKCU:\Software\$labName"

Write-Host "[lab] pid=$PID"
Write-Host "[lab] root=$root"
Write-Host "[lab] registry=$regPath"

New-Item -ItemType Directory -Force -Path $root | Out-Null

$content = @(
    "Windows Internals VN Procmon controlled trace"
    "timestamp=$(Get-Date -Format o)"
    "pid=$PID"
)

Set-Content -Path $file -Value $content -Encoding UTF8
Get-Content -Path $file | Out-Null

New-Item -Path $regPath -Force | Out-Null
New-ItemProperty -Path $regPath -Name "LabName" -Value $labName -PropertyType String -Force | Out-Null
New-ItemProperty -Path $regPath -Name "ProcessId" -Value $PID -PropertyType DWord -Force | Out-Null
Get-ItemProperty -Path $regPath | Out-Null

Start-Sleep -Milliseconds 500

Remove-Item -Path $file -Force -ErrorAction SilentlyContinue
Remove-Item -Path $root -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path $regPath -Force -Recurse -ErrorAction SilentlyContinue

Write-Host "[lab] done"

