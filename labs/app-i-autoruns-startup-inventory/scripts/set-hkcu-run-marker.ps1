param(
    [ValidateSet("Create", "Remove")]
    [string]$Action = "Create"
)

$ErrorActionPreference = "Stop"

$runPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$name = "InternalsNoteBookRunMarker"
$command = "$env:SystemRoot\System32\cmd.exe /c rem InternalsNoteBookRunMarker"

if ($Action -eq "Create") {
    New-Item -Path $runPath -Force | Out-Null
    New-ItemProperty -Path $runPath -Name $name -Value $command -PropertyType String -Force | Out-Null
    Write-Host "[lab] created HKCU Run marker"
    Write-Host "[lab] name=$name"
    Write-Host "[lab] value=$command"
    exit 0
}

Remove-ItemProperty -Path $runPath -Name $name -ErrorAction SilentlyContinue
Write-Host "[lab] removed HKCU Run marker if present"

