#Requires -Version 5.1
<#
.SYNOPSIS
    CMMC Level 2 / NIST 800-171 r2 - MP.3.8.7
    Control use of removable media on system components.
    (See also AC.3.1.21 — this script adds USB device event log review)
#>
$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$Hostname  = $env:COMPUTERNAME
$OutDir    = "$PSScriptRoot\output"
$OutFile   = "$OutDir\MP_3_8_7_${Hostname}_${Timestamp}.csv"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$Results = [System.Collections.Generic.List[PSCustomObject]]::new()
function Add-Result { param($Source,$Setting,$Value,$Pass,$Notes)
    $Results.Add([PSCustomObject]@{Source=$Source;Setting=$Setting;Value=$Value;Pass=$Pass;Notes=$Notes
    Hostname=$Hostname;Collected=(Get-Date -Format 'o')}) }

# Registry policy checks
Write-Host "`n[REGISTRY] Checking removable storage policies..." -ForegroundColor Cyan
$BasePath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices'
@(
    @{Class='{53f56307-b6bf-11d0-94f2-00a0c91efb8b}';Label='USB Disks';Keys=@('Deny_Write','Deny_Read')},
    @{Class='{6AC27878-A6FA-4155-BA85-F98F491D4F33}';Label='WPD/MTP';Keys=@('Deny_Write')}
) | ForEach-Object {
    $C = $_
    $C.Keys | ForEach-Object {
        try {
            $Val = (Get-ItemProperty "$BasePath\$($C.Class)" -ErrorAction Stop).$_
            Add-Result "RemovableStorage:$($C.Label)" $_ $Val ($Val -eq 1) ''
        } catch {
            Add-Result "RemovableStorage:$($C.Label)" $_ 'Not set' $false 'Policy not configured'
        }
    }
}

# USB connection history (from registry — last 10)
Write-Host "[REGISTRY] Querying USB device connection history..." -ForegroundColor Cyan
$USBPath = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
try {
    Get-ChildItem $USBPath -ErrorAction Stop | Select-Object -First 10 | ForEach-Object {
        $DeviceType = $_.PSChildName
        Get-ChildItem $_.PSPath | ForEach-Object {
            $FriendlyName = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).FriendlyName
            Add-Result 'USBHistory' $DeviceType $FriendlyName 'N/A' 'Historical connection — review for unauthorized devices'
        }
    }
} catch { Write-Warning "USB history query failed: $_" }

# Event log — USB insertions (last 7 days, Event 20001 from DriverFrameworks)
Write-Host "[EVENTS] Checking USB insertion events (last 7 days)..." -ForegroundColor Cyan
try {
    $Events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-DriverFrameworks-UserMode/Operational'
        Id        = 2003
        StartTime = (Get-Date).AddDays(-7)
    } -ErrorAction Stop | Select-Object -First 20
    $Events | ForEach-Object { Add-Result 'EventLog:USBInsert' $_.TimeCreated $_.Message 'N/A' 'USB device connected — review against authorized list' }
} catch { Write-Warning "USB event log not available or no events found." }

$Results | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
Write-Host "[DONE] $($Results.Count) records -> $OutFile" -ForegroundColor Green
