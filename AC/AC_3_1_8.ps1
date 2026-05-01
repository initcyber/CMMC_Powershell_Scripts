#Requires -Version 5.1
<#
.SYNOPSIS
    CMMC Level 2 / NIST 800-171 r2 - AC.3.1.8
    Limit unsuccessful logon attempts.
.NOTES
    Scope  : Local policy + Domain policy (if AD available)
    Output : Console + timestamped CSV artifact
#>

$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$Hostname  = $env:COMPUTERNAME
$OutDir    = "$PSScriptRoot\output"
$OutFile   = "$OutDir\AC_3_1_8_${Hostname}_${Timestamp}.csv"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$Results = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Result {
    param($Source, $Setting, $Value, $Expected, $Pass, $Notes)
    $Results.Add([PSCustomObject]@{
        Source    = $Source
        Setting   = $Setting
        Value     = $Value
        Expected  = $Expected
        Pass      = $Pass
        Notes     = $Notes
        Hostname  = $Hostname
        Collected = (Get-Date -Format 'o')
    })
}

# ── 1. LOCAL SECURITY POLICY (secedit) ───────────────────────────────────────
Write-Host "`n[LOCAL] Exporting local security policy..." -ForegroundColor Cyan
$SecExport = "$env:TEMP\secpol_$Timestamp.cfg"
secedit /export /cfg $SecExport /quiet

if (Test-Path $SecExport) {
    $SecContent = Get-Content $SecExport
    $LockoutThreshold = ($SecContent | Select-String 'LockoutBadCount').ToString() -replace '.*=\s*',''
    $LockoutDuration  = ($SecContent | Select-String 'LockoutDuration').ToString()  -replace '.*=\s*',''
    $ObservationWindow = ($SecContent | Select-String 'ResetLockoutCount').ToString() -replace '.*=\s*',''

    # NIST 800-171 does not set a specific number but CMMC assessors typically look for <= 10
    $ThresholdPass = [int]$LockoutThreshold -gt 0 -and [int]$LockoutThreshold -le 10

    Add-Result 'LocalPolicy' 'LockoutBadCount (threshold)'  $LockoutThreshold.Trim() '1-10'  $ThresholdPass ''
    Add-Result 'LocalPolicy' 'LockoutDuration (minutes)'    $LockoutDuration.Trim()  '>=15'  ($([int]$LockoutDuration.Trim()) -ge 15 -or $([int]$LockoutDuration.Trim()) -eq 0) $(if ($LockoutDuration.Trim() -eq '0') {'0 = until admin unlocks'} else {''})
    Add-Result 'LocalPolicy' 'ResetLockoutCount (minutes)'  $ObservationWindow.Trim() '>=15' ($([int]$ObservationWindow.Trim()) -ge 15) ''

    Remove-Item $SecExport -Force
} else {
    Write-Warning "secedit export failed — may need elevation."
}

# ── 2. AUDIT POLICY (failed logon auditing) ───────────────────────────────────
Write-Host "[LOCAL] Checking logon failure auditing..." -ForegroundColor Cyan
$AuditOutput = (auditpol /get /subcategory:"Logon" 2>&1) -join ' '
$LogonAuditPass = $AuditOutput -match 'Failure'
Add-Result 'AuditPolicy' 'Logon Failure Auditing' $AuditOutput 'Failure enabled' $LogonAuditPass ''

# ── 3. RECENT FAILED LOGON EVENTS (4625) ─────────────────────────────────────
Write-Host "[EVENTS] Querying Security log for failed logons (Event 4625, last 24h)..." -ForegroundColor Cyan
try {
    $FailedLogons = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4625
        StartTime = (Get-Date).AddHours(-24)
    } -ErrorAction Stop

    $FailedLogons | Group-Object {
        ($_.Properties[5].Value) # Target username
    } | Sort-Object Count -Descending | Select-Object -First 20 | ForEach-Object {
        Add-Result 'EventLog:4625' "Failed logon - $($_.Name)" $_.Count 'Informational' 'N/A' 'Review for brute force'
    }
    Write-Host "  $($FailedLogons.Count) failed logon events in last 24h." -ForegroundColor $(if ($FailedLogons.Count -gt 50) {'Red'} else {'Green'})
} catch {
    Write-Warning "Could not query Security event log (may need elevation): $_"
}

# ── 4. DOMAIN POLICY (if AD available) ────────────────────────────────────────
Write-Host "[AD] Checking domain password/lockout policy..." -ForegroundColor Cyan
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    try {
        $DomPolicy = Get-ADDefaultDomainPasswordPolicy
        Add-Result 'DomainPolicy' 'LockoutThreshold'       $DomPolicy.LockoutThreshold       '1-10' ($DomPolicy.LockoutThreshold -gt 0 -and $DomPolicy.LockoutThreshold -le 10) ''
        Add-Result 'DomainPolicy' 'LockoutDuration'        $DomPolicy.LockoutDuration         '>=15m' ($DomPolicy.LockoutDuration.TotalMinutes -ge 15) ''
        Add-Result 'DomainPolicy' 'LockoutObservationWindow' $DomPolicy.LockoutObservationWindow '>=15m' ($DomPolicy.LockoutObservationWindow.TotalMinutes -ge 15) ''
    } catch {
        Write-Warning "Domain policy query failed: $_"
    }
} else {
    Write-Host "  ActiveDirectory module not available." -ForegroundColor Yellow
}

# ── 5. OUTPUT ─────────────────────────────────────────────────────────────────
$Results | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
Write-Host "`n[DONE] Written to: $OutFile" -ForegroundColor Green

Write-Host "`n── SUMMARY ──────────────────────────────────────────" -ForegroundColor White
$Fails = $Results | Where-Object { $_.Pass -eq $false }
if ($Fails) {
    Write-Host "  FAIL items:" -ForegroundColor Red
    $Fails | ForEach-Object { Write-Host "    [$($_.Source)] $($_.Setting) = $($_.Value) (expected $($_.Expected))" -ForegroundColor Red }
} else {
    Write-Host "  All checked settings PASS." -ForegroundColor Green
}
Write-Host "─────────────────────────────────────────────────────`n" -ForegroundColor White
