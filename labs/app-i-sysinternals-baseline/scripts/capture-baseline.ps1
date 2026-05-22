param(
    [string]$OutRoot = "C:\Labs\Logs\SysinternalsBaseline"
)

$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path $OutRoot $timestamp
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

function Write-Section {
    param([string]$Title)
    "`n=== $Title ==="
}

$contextPath = Join-Path $outDir "system-context.txt"

Write-Section "Capture time" | Out-File -FilePath $contextPath -Encoding utf8
Get-Date | Out-File -FilePath $contextPath -Append -Encoding utf8

Write-Section "Computer" | Out-File -FilePath $contextPath -Append -Encoding utf8
"COMPUTERNAME=$env:COMPUTERNAME" | Out-File -FilePath $contextPath -Append -Encoding utf8
"USERNAME=$env:USERNAME" | Out-File -FilePath $contextPath -Append -Encoding utf8

Write-Section "Windows version" | Out-File -FilePath $contextPath -Append -Encoding utf8
Get-ComputerInfo -Property WindowsProductName,WindowsVersion,OsBuildNumber,OsArchitecture |
    Format-List | Out-File -FilePath $contextPath -Append -Encoding utf8

Write-Section "Identity" | Out-File -FilePath $contextPath -Append -Encoding utf8
whoami /all | Out-File -FilePath $contextPath -Append -Encoding utf8

Write-Section "Security services" | Out-File -FilePath $contextPath -Append -Encoding utf8
Get-Service WinDefend,SecurityHealthService -ErrorAction SilentlyContinue |
    Format-Table -AutoSize | Out-File -FilePath $contextPath -Append -Encoding utf8

Get-Process |
    Select-Object Id,ProcessName,Path,StartTime,CPU,WorkingSet64 |
    Export-Csv -NoTypeInformation -Encoding utf8 -Path (Join-Path $outDir "process-list.csv")

Get-Service |
    Sort-Object Name |
    Select-Object Name,DisplayName,Status,StartType,ServiceType |
    Export-Csv -NoTypeInformation -Encoding utf8 -Path (Join-Path $outDir "services.csv")

Get-CimInstance Win32_SystemDriver |
    Sort-Object Name |
    Select-Object Name,DisplayName,State,StartMode,PathName |
    Export-Csv -NoTypeInformation -Encoding utf8 -Path (Join-Path $outDir "drivers.csv")

cmd /c fltmc > (Join-Path $outDir "fltmc.txt") 2>&1
cmd /c driverquery /v > (Join-Path $outDir "driverquery-v.txt") 2>&1
cmd /c sc query type^= driver state^= all > (Join-Path $outDir "sc-query-drivers.txt") 2>&1
cmd /c netstat -ano > (Join-Path $outDir "netstat-ano.txt") 2>&1
cmd /c tasklist /v > (Join-Path $outDir "tasklist-v.txt") 2>&1

Write-Host "Baseline written to: $outDir"
Write-Host "Review system-context.txt first, then add Sysinternals GUI/CLI exports if available."

