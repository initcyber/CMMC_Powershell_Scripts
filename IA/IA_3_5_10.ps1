#Requires -Version 5.1
<#
.SYNOPSIS
    CMMC Level 2 / NIST 800-171 r2 - IA.3.5.10
    Store and transmit only cryptographically protected passwords.
.NOTES
    Checks LM hash storage disabled, NTLMv2 minimum, reversible encryption off.
#>
$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$Hostname  = $env:COMPUTERNAME
$OutDir    = "$PSScriptRoot\output"
$OutFile   = "$OutDir\IA_3_5_10_${Hostname}_${Timestamp}.csv"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$Results = [System.Collections.Generic.List[PSCustomObject]]::new()
function Add-Result { param($Setting,$Value,$Expected,$Pass,$Notes)
    $Results.Add([PSCustomObject]@{Setting=$Setting;Value=$Value;Expected=$Expected;Pass=$Pass;Notes=$Notes
    Hostname=$Hostname;Collected=(Get-Date -Format 'o')}) }

Write-Host "`n[REGISTRY] Checking credential protection settings..." -ForegroundColor Cyan

$LsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$Lsa     = Get-ItemProperty -Path $LsaPath -ErrorAction SilentlyContinue

# No LM hash storage (1 = disabled = good)
$NoLM = $Lsa.NoLMHash
Add-Result 'NoLMHash (LM hash disabled)' $NoLM '1' ($NoLM -eq 1) 'Prevents LM hash storage — must be 1'

# NTLMv2 minimum (LmCompatibilityLevel >= 3)
$NTLM = $Lsa.LmCompatibilityLevel
Add-Result 'LmCompatibilityLevel (NTLMv2)' $NTLM '>=3' ($NTLM -ge 3) '3=NTLMv2 only, 5=NTLMv2+extended session security'

# Credential Guard
$DevGuard = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -ErrorAction SilentlyContinue
$CredGuard = $DevGuard.EnableVirtualizationBasedSecurity
Add-Result 'Credential Guard (VBS)' $CredGuard '1' ($CredGuard -eq 1) 'Strongly recommended for CUI systems'

# WDigest (plaintext creds in memory — must be off)
$WDigest = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -ErrorAction SilentlyContinue).UseLogonCredential
Add-Result 'WDigest UseLogonCredential' $WDigest '0 or absent' ($null -eq $WDigest -or $WDigest -eq 0) 'Must be 0 — prevents plaintext in LSASS'

# Reversible encryption (via secedit)
$Cfg = "$env:TEMP\secpol_$Timestamp.cfg"
secedit /export /cfg $Cfg /quiet
if (Test-Path $Cfg) {
    $RevEnc = ((Get-Content $Cfg | Select-String 'ClearTextPassword') -replace '.*=\s*','').Trim()
    Add-Result 'Reversible Encryption (ClearTextPassword)' $RevEnc '0' ($RevEnc -eq '0') 'Must be 0'
    Remove-Item $Cfg -Force
}

$Results | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
$Results | Format-Table Setting, Value, Expected, Pass -AutoSize
Write-Host "[DONE] Written to: $OutFile" -ForegroundColor Green
$Fails = $Results | Where-Object { $_.Pass -eq $false }
if ($Fails) { $Fails | ForEach-Object { Write-Host "FAIL: $($_.Setting) = $($_.Value)" -ForegroundColor Red } }
