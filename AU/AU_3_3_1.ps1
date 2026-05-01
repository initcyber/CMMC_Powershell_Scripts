#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CMMC Level 2 / NIST 800-171 r2 - AU.L2-3.3.1
    Create and retain system audit logs to enable monitoring, analysis,
    investigation, and reporting of unlawful or unauthorized activity.

.DESCRIPTION
    Enumerates all enabled Windows Event Logs and documents:
      - Log name, mode (Circular/Retain/AutoBackup), max size, record count
      - Whether critical audit subcategories are enabled (via auditpol)

    Output: two timestamped CSVs in .\output\
      1. AU_3_3_1_EventLogs_*.csv     -- log configuration
      2. AU_3_3_1_AuditPolicy_*.csv   -- auditpol subcategory settings

.NOTES
    Requires: Run as Administrator (Security log access + auditpol)
#>

$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$Hostname  = $env:COMPUTERNAME
$OutDir    = Join-Path $PSScriptRoot 'output'
$LogCsvOut = Join-Path $OutDir "AU_3_3_1_EventLogs_${Hostname}_${Timestamp}.csv"
$AuditOut  = Join-Path $OutDir "AU_3_3_1_AuditPolicy_${Hostname}_${Timestamp}.csv"

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

# ── 1. EVENT LOG ENUMERATION ──────────────────────────────────────────────────
Write-Host "`n[EVENT LOGS] Enumerating all enabled Windows Event Logs..." -ForegroundColor Cyan

$LogResults = [System.Collections.Generic.List[PSCustomObject]]::new()

Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
    Where-Object { $_.IsEnabled -eq $true } |
    ForEach-Object {
        $SizeMB = [math]::Round($_.MaximumSizeInBytes / 1MB, 2)
        $LogResults.Add([PSCustomObject]@{
            LogName      = $_.LogName
            IsEnabled    = $_.IsEnabled
            LogMode      = $_.LogMode           # Circular | Retain | AutoBackup
            MaxSizeMB    = $SizeMB
            RecordCount  = $_.RecordCount
            LogFilePath  = $_.LogFilePath
            ModeRetains  = ($_.LogMode -ne 'Circular')
            SizeAdequate = ($SizeMB -ge 20)
            Hostname     = $Hostname
            Collected    = Get-Date -Format 'o'
        })
    }

$LogResults | Export-Csv -Path $LogCsvOut -NoTypeInformation -Encoding UTF8
Write-Host "  $($LogResults.Count) enabled logs -> $LogCsvOut" -ForegroundColor Green

$Circular   = $LogResults | Where-Object { $_.LogMode -eq 'Circular' }
$Undersized = $LogResults | Where-Object { -not $_.SizeAdequate }
Write-Host "  Circular (overwrites) : $($Circular.Count)"   -ForegroundColor $(if($Circular.Count){'Yellow'}else{'Green'})
Write-Host "  Undersized (<20MB)    : $($Undersized.Count)" -ForegroundColor $(if($Undersized.Count){'Yellow'}else{'Green'})

# ── 2. KEY LOG SPOT-CHECK ─────────────────────────────────────────────────────
Write-Host "`n[SPOT CHECK] Key security-relevant logs:" -ForegroundColor Cyan
$KeyLogs = @('Security','System','Application',
             'Microsoft-Windows-PowerShell/Operational',
             'Microsoft-Windows-Sysmon/Operational')

foreach ($Name in $KeyLogs) {
    $L = $LogResults | Where-Object { $_.LogName -eq $Name }
    if ($L) {
        $Status = if ($L.ModeRetains -and $L.SizeAdequate) {'OK'} else {'REVIEW'}
        Write-Host ("  {0,-55} {1,8}MB  Mode:{2,-12} [{3}]" -f $L.LogName,$L.MaxSizeMB,$L.LogMode,$Status) `
            -ForegroundColor $(if($Status -eq 'OK'){'Green'}else{'Yellow'})
    } else {
        Write-Host "  $Name -- not present on this system" -ForegroundColor DarkGray
    }
}

# ── 3. AUDIT POLICY (auditpol) ────────────────────────────────────────────────
Write-Host "`n[AUDITPOL] Retrieving audit policy for all subcategories..." -ForegroundColor Cyan

$AuditResults = [System.Collections.Generic.List[PSCustomObject]]::new()
$CurrentCategory = ''
$RawAudit = auditpol /get /category:* 2>&1

foreach ($Line in $RawAudit) {
    $Trimmed = $Line.Trim()
    if ([string]::IsNullOrWhiteSpace($Trimmed))  { continue }
    if ($Trimmed -match '^-+$')                   { continue }
    if ($Trimmed -eq 'System audit policy')        { continue }
    if ($Trimmed -match '^Category/')              { continue }

    if ($Trimmed -match '^(.+?)\s{2,}(No Auditing|Success and Failure|Success|Failure)$') {
        $Sub     = $Matches[1].Trim()
        $Setting = $Matches[2].Trim()
        $Pass    = $Setting -ne 'No Auditing'
        $AuditResults.Add([PSCustomObject]@{
            Category    = $CurrentCategory
            Subcategory = $Sub
            Setting     = $Setting
            Pass        = $Pass
            Notes       = if(-not $Pass){'WARNING: No auditing -- gap finding'}else{''}
            Hostname    = $Hostname
            Collected   = Get-Date -Format 'o'
        })
    } else {
        $CurrentCategory = $Trimmed
    }
}

$AuditResults | Export-Csv -Path $AuditOut -NoTypeInformation -Encoding UTF8
Write-Host "  $($AuditResults.Count) subcategories -> $AuditOut" -ForegroundColor Green

$NoAudit = $AuditResults | Where-Object { -not $_.Pass }
Write-Host "  Subcategories with 'No Auditing': $($NoAudit.Count)" `
    -ForegroundColor $(if($NoAudit.Count -gt 10){'Red'}elseif($NoAudit.Count){'Yellow'}else{'Green'})

# ── 4. SUMMARY ────────────────────────────────────────────────────────────────
Write-Host "`n-- AU.3.3.1 SUMMARY ----------------------------------------" -ForegroundColor White
Write-Host "  Enabled event logs documented : $($LogResults.Count)"
Write-Host "  Audit subcategories checked   : $($AuditResults.Count)"
Write-Host "  Audit gaps (No Auditing)      : $($NoAudit.Count)"
Write-Host "  Artifacts:"
Write-Host "    $LogCsvOut"
Write-Host "    $AuditOut"
Write-Host "------------------------------------------------------------`n" -ForegroundColor White
