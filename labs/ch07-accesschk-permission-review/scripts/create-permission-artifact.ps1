param(
    [ValidateSet("Create", "Remove")]
    [string]$Action = "Create"
)

$ErrorActionPreference = "Stop"

$root = Join-Path $env:TEMP "InternalsNoteBookAclLab"
$file = Join-Path $root "controlled.txt"

if ($Action -eq "Remove") {
    Remove-Item -Path $root -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[lab] removed $root if present"
    exit 0
}

New-Item -ItemType Directory -Force -Path $root | Out-Null
Set-Content -Path $file -Value "permission review artifact" -Encoding UTF8

Write-Host "[lab] root=$root"
Write-Host "[lab] file=$file"
Write-Host "[lab] run: icacls `"$file`""
Write-Host "[lab] run: Get-Acl `"$file`" | Format-List"

