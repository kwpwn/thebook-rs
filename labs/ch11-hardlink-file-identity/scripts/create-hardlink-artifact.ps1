param(
    [ValidateSet("Create", "Remove")]
    [string]$Action = "Create"
)

$ErrorActionPreference = "Stop"

$root = Join-Path $env:TEMP "InternalsNoteBookHardlinkLab"
$original = Join-Path $root "original.txt"
$alias = Join-Path $root "alias.txt"

if ($Action -eq "Remove") {
    Remove-Item -Path $root -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[lab] removed $root if present"
    exit 0
}

New-Item -ItemType Directory -Force -Path $root | Out-Null
Set-Content -Path $original -Value "original content" -Encoding UTF8

if (Test-Path $alias) {
    Remove-Item -Path $alias -Force
}

New-Item -ItemType HardLink -Path $alias -Target $original | Out-Null

Write-Host "[lab] original=$original"
Write-Host "[lab] alias=$alias"
Write-Host "[lab] run: fsutil hardlink list `"$original`""

