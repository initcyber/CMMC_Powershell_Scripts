#Requires -Version 5.1
<#
.SYNOPSIS
    CMMC Level 2 / NIST 800-171 r2 - AC.3.1.21
    Limit use of portable storage devices on external systems.
.NOTES
    Checks GPO/registry keys controlling removable storage access.
#>

$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$Hostname  = $env:COMPUTERNAME
$OutDir    = "$PSScriptRoot\output"
$OutFile   = "$OutDir\AC_3_1_21_${Hostname}_${Timestamp}.csv"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$Results = [System.Collections.Generic.List[PSCustomObject]]::new()
function Add-Result { param($Setting,$Value,$Expected,$Pass,$Notes)
    $Results.Add([PSCustomObject]@{Setting=$Setting;Value=$Value;Expected=$Expected;Pass=$Pass;Notes=$Notes
    Hostname=$Hostname;Collected=(Get-Date -Format 'o')}) }

Write-Host "`n[REGISTRY] Checking removable storage device policies..." -ForegroundColor Cyan

$BasePath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices'

$Checks = @(
    @{Class='{53f56307-b6bf-11d0-94f2-00a0c91efb8b}'; Name='USB Disks (Deny Write)'; Key='Deny_Write'},
    @{Class='{53f56307-b6bf-11d0-94f2-00a0c91efb8b}'; Name='USB Disks (Deny Read)';  Key='Deny_Read'},
    @{Class='{6AC27878-A6FA-4155-BA85-F98F491D4F33}'; Name='WPD/MTP Devices (Deny Write)'; Key='Deny_Write'},
    @{Class='All'; Name='All Removable Storage (Deny All)'; Key='Deny_All'}
)

foreach ($C in $Checks) {
    $Path = if ($C.Class -eq 'All') { "$BasePath\All" } else { "$BasePath\$($C.Class)" }
    try {
        $Val = (Get-ItemProperty -Path $Path -ErrorAction Stop).$($C.Key)
        Add-Result $C.Name $Val '1 (restricted)' ($Val -eq 1) ''
    } catch {
        Add-Result $C.Name 'Not configured' '1 (restricted)' $false 'Policy not set — removable storage unrestricted'
    }
}

# Also check if AutoPlay is disabled (related hardening)
$AutoPlay = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
Add-Result 'AutoPlay disabled' $AutoPlay '255 (all drives)' ($AutoPlay -eq 255) ''

$Results | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
$Results | Format-Table Setting, Value, Pass -AutoSize
Write-Host "[DONE] Written to: $OutFile" -ForegroundColor Green
