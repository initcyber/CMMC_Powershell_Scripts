#Requires -Version 5.1
<#
.SYNOPSIS
    CMMC Level 2 / NIST 800-171 r2 - AU.3.3.7
    Provide a system capability that compares and synchronizes internal clocks
    with authoritative sources to generate time stamps for audit records.
#>
$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$Hostname  = $env:COMPUTERNAME
$OutDir    = "$PSScriptRoot\output"
$OutFile   = "$OutDir\AU_3_3_7_${Hostname}_${Timestamp}.csv"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

Write-Host "`n[W32TM] Checking time synchronization..." -ForegroundColor Cyan
$W32Source = (w32tm /query /source 2>&1) -join ' '
$W32Status = (w32tm /query /status 2>&1) -join '; '
$W32Config = (w32tm /query /configuration 2>&1) -join '; '
$SvcStatus = (Get-Service W32Time -ErrorAction SilentlyContinue).Status

$Pass = $SvcStatus -eq 'Running' -and $W32Source -notmatch 'Local CMOS|Free-running'

[PSCustomObject]@{
    Hostname       = $Hostname
    TimeSource     = $W32Source.Trim()
    W32TMService   = $SvcStatus
    NTPConfig      = ($W32Config | Select-String 'NtpServer') -replace '.*NtpServer:\s*',''
    StatusSummary  = $W32Status
    SystemTime     = Get-Date -Format 'o'
    Pass           = $Pass
    Collected      = Get-Date -Format 'o'
} | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8

Write-Host "  Source  : $W32Source"
Write-Host "  Service : $SvcStatus"
Write-Host "$(if($Pass){'PASS'}else{'FAIL'}): NTP sync" -ForegroundColor $(if($Pass){'Green'}else{'Red'})
Write-Host "[DONE] Written to: $OutFile" -ForegroundColor Green
