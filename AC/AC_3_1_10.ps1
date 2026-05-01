#Requires -Version 5.1
<#
.SYNOPSIS
    CMMC Level 2 / NIST 800-171 r2 - AC.3.1.10
    Use session lock with pattern-hiding displays after inactivity.
.NOTES
    Checks screen saver policy (timeout, password-on-resume) via registry and GPO.
#>

$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$Hostname  = $env:COMPUTERNAME
$OutDir    = "$PSScriptRoot\output"
$OutFile   = "$OutDir\AC_3_1_10_${Hostname}_${Timestamp}.csv"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$Results = [System.Collections.Generic.List[PSCustomObject]]::new()
function Add-Result {
    param($Source, $Setting, $Value, $Expected, $Pass, $Notes)
    $Results.Add([PSCustomObject]@{
        Source=$Source;Setting=$Setting;Value=$Value;Expected=$Expected;Pass=$Pass;Notes=$Notes
        Hostname=$Hostname;Collected=(Get-Date -Format 'o')
    })
}

Write-Host "`n[REGISTRY] Checking screen saver / session lock settings..." -ForegroundColor Cyan

# Machine policy (GPO-enforced) takes precedence over user policy
$PolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop'
$UserPath   = 'HKCU:\Control Panel\Desktop'

foreach ($Path in @($PolicyPath, $UserPath)) {
    $Source = if ($Path -match 'HKLM') { 'MachinePolicy' } else { 'UserHKCU' }
    try {
        $Key = Get-ItemProperty -Path $Path -ErrorAction Stop

        $Timeout   = $Key.ScreenSaveTimeOut
        $Active    = $Key.ScreenSaveActive
        $Secure    = $Key.ScreenSaverIsSecure

        Add-Result $Source 'ScreenSaveActive (enabled)'    $Active   '1'     ($Active -eq '1')    ''
        Add-Result $Source 'ScreenSaveTimeOut (seconds)'   $Timeout  '<=900' ([int]$Timeout -le 900 -and [int]$Timeout -gt 0) '15 min max recommended'
        Add-Result $Source 'ScreenSaverIsSecure (lock on resume)' $Secure '1' ($Secure -eq '1') ''
    } catch {
        Add-Result $Source '(key not present)' 'N/A' 'N/A' 'N/A' "Path: $Path"
    }
}

# Check GPO-enforced lock workstation policy
$LockPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
try {
    $LockVal = (Get-ItemProperty -Path $LockPath -ErrorAction Stop).DisableLockWorkstation
    Add-Result 'MachinePolicy' 'DisableLockWorkstation' $LockVal '0 or absent' ($null -eq $LockVal -or $LockVal -eq 0) 'Must not prevent Ctrl+Alt+Del lock'
} catch {
    Add-Result 'MachinePolicy' 'DisableLockWorkstation' 'key absent' '0 or absent' $true ''
}

$Results | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
Write-Host "[DONE] Written to: $OutFile" -ForegroundColor Green

$Fails = $Results | Where-Object { $_.Pass -eq $false }
if ($Fails) { $Fails | ForEach-Object { Write-Host "FAIL: [$($_.Source)] $($_.Setting) = $($_.Value)" -ForegroundColor Red } }
else        { Write-Host "All session lock settings PASS." -ForegroundColor Green }
