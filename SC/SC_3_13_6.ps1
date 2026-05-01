#Requires -Version 5.1
<#
.SYNOPSIS
    CMMC Level 2 / NIST 800-171 r2 - SC.3.13.6
    Deny network communications traffic by default; allow by exception.
    (Default deny firewall posture)
#>
$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$Hostname  = $env:COMPUTERNAME
$OutDir    = "$PSScriptRoot\output"
$OutFile   = "$OutDir\SC_3_13_6_${Hostname}_${Timestamp}.csv"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

Write-Host "`n[FIREWALL] Checking default deny posture across all profiles..." -ForegroundColor Cyan
$Report = Get-NetFirewallProfile | Select-Object `
    Name,
    Enabled,
    DefaultInboundAction,
    DefaultOutboundAction,
    @{N='Pass';E={$_.Enabled -and $_.DefaultInboundAction -eq 'Block'}},
    @{N='Hostname';E={$env:COMPUTERNAME}},
    @{N='Collected';E={Get-Date -Format 'o'}}

$Report | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction, Pass -AutoSize
$Report | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8

$Fails = $Report | Where-Object { -not $_.Pass }
if ($Fails) { Write-Host "FAIL: Some profiles do not enforce default inbound BLOCK." -ForegroundColor Red }
else        { Write-Host "PASS: All profiles block inbound by default." -ForegroundColor Green }
Write-Host "[DONE] Written to: $OutFile" -ForegroundColor Green
