param(
    [ValidateSet("Create", "Remove")]
    [string]$Action = "Create"
)

$ErrorActionPreference = "Stop"

$root = Join-Path $env:TEMP "InternalsNoteBookAdsLab"
$file = Join-Path $root "sample.txt"
$streamName = "research"

if ($Action -eq "Remove") {
    Remove-Item -Path $root -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[lab] removed $root if present"
    exit 0
}

New-Item -ItemType Directory -Force -Path $root | Out-Null

Set-Content -Path $file -Value "default stream content" -Encoding UTF8
Set-Content -Path $file -Stream $streamName -Value "alternate stream content" -Encoding UTF8

Write-Host "[lab] file=$file"
Write-Host "[lab] default stream written"
Write-Host "[lab] ads=$streamName written"
Write-Host "[lab] run: Get-Item `"$file`" -Stream *"

