param(
    [string]$OutRoot = "$env:TEMP\InternalsNoteBookServiceInventory",
    [string[]]$SelectedServices = @("WinDefend", "EventLog", "Schedule", "W32Time")
)

$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path $OutRoot $timestamp
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

"timestamp=$(Get-Date -Format o)" | Out-File -FilePath (Join-Path $outDir "context.txt") -Encoding utf8
"computer=$env:COMPUTERNAME" | Out-File -FilePath (Join-Path $outDir "context.txt") -Append -Encoding utf8
"user=$env:USERNAME" | Out-File -FilePath (Join-Path $outDir "context.txt") -Append -Encoding utf8
"pid=$PID" | Out-File -FilePath (Join-Path $outDir "context.txt") -Append -Encoding utf8

Get-Service |
    Sort-Object Name |
    Select-Object Name,DisplayName,Status,StartType,ServiceType |
    Export-Csv -NoTypeInformation -Encoding utf8 -Path (Join-Path $outDir "services.csv")

Get-Service |
    Where-Object { $_.Status -eq "Running" } |
    Sort-Object Name |
    Select-Object Name,DisplayName,Status,StartType,ServiceType |
    Export-Csv -NoTypeInformation -Encoding utf8 -Path (Join-Path $outDir "running-services.csv")

Get-CimInstance Win32_Service |
    Sort-Object Name |
    Select-Object Name,DisplayName,State,StartMode,ProcessId,PathName,StartName |
    Export-Csv -NoTypeInformation -Encoding utf8 -Path (Join-Path $outDir "service-processes.csv")

cmd /c sc query type^= service state^= all > (Join-Path $outDir "sc-query-all.txt") 2>&1

$selectedOut = Join-Path $outDir "sc-qc-selected.txt"
foreach ($svc in $SelectedServices) {
    "=== $svc ===" | Out-File -FilePath $selectedOut -Append -Encoding utf8
    cmd /c sc qc $svc | Out-File -FilePath $selectedOut -Append -Encoding utf8
    cmd /c sc queryex $svc | Out-File -FilePath $selectedOut -Append -Encoding utf8
}

Get-WinEvent -FilterHashtable @{LogName="System"; ProviderName="Service Control Manager"; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue |
    Select-Object -First 200 TimeCreated,Id,ProviderName,LevelDisplayName,Message |
    Export-Clixml -Path (Join-Path $outDir "system-service-events.xml")

Write-Host "[lab] service inventory written to: $outDir"
Write-Host "[lab] configuration, state, process, and event evidence are separate."

