param(
    [string]$OutRoot = "$env:TEMP\InternalsNoteBookEtwInventory",
    [string[]]$Providers = @(
        "Microsoft-Windows-Kernel-Process",
        "Microsoft-Windows-Kernel-File",
        "Microsoft-Windows-Security-Auditing",
        "Microsoft-Windows-PowerShell"
    )
)

$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path $OutRoot $timestamp
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

"timestamp=$(Get-Date -Format o)" | Out-File -FilePath (Join-Path $outDir "context.txt") -Encoding utf8
"computer=$env:COMPUTERNAME" | Out-File -FilePath (Join-Path $outDir "context.txt") -Append -Encoding utf8
"user=$env:USERNAME" | Out-File -FilePath (Join-Path $outDir "context.txt") -Append -Encoding utf8
"pid=$PID" | Out-File -FilePath (Join-Path $outDir "context.txt") -Append -Encoding utf8

Get-ComputerInfo -Property WindowsProductName,WindowsVersion,OsBuildNumber,OsArchitecture |
    Format-List | Out-File -FilePath (Join-Path $outDir "windows-version.txt") -Encoding utf8

cmd /c logman query providers > (Join-Path $outDir "logman-providers.txt") 2>&1
cmd /c logman query -ets > (Join-Path $outDir "active-trace-sessions.txt") 2>&1

Get-WinEvent -ListProvider * |
    Select-Object Name,LogLinks |
    Export-Csv -NoTypeInformation -Encoding utf8 -Path (Join-Path $outDir "eventlog-providers.csv")

foreach ($provider in $Providers) {
    $safe = $provider -replace '[^A-Za-z0-9_.-]', '_'
    $target = Join-Path $outDir "selected-provider-$safe.txt"
    "provider=$provider" | Out-File -FilePath $target -Encoding utf8
    Get-WinEvent -ListProvider $provider -ErrorAction Continue |
        Format-List * | Out-File -FilePath $target -Append -Encoding utf8
}

Write-Host "[lab] ETW inventory written to: $outDir"
Write-Host "[lab] This is provider/session inventory, not coverage proof."

