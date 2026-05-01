#Requires -Version 5.1
<#
.SYNOPSIS
    CMMC Level 2 / NIST 800-171 r2 - SC.3.13.1
    Monitor, control, and protect communications at external boundaries and
    key internal boundaries of organizational systems.
#>
$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$Hostname  = $env:COMPUTERNAME
$OutDir    = "$PSScriptRoot\output"
$OutFile   = "$OutDir\SC_3_13_1_${Hostname}_${Timestamp}.csv"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$Results = [System.Collections.Generic.List[PSCustomObject]]::new()
function Add-Result { param($Source,$Setting,$Value,$Pass,$Notes)
    $Results.Add([PSCustomObject]@{Source=$Source;Setting=$Setting;Value=$Value;Pass=$Pass;Notes=$Notes
    Hostname=$Hostname;Collected=(Get-Date -Format 'o')}) }

Write-Host "`n[FIREWALL] Checking Windows Firewall profiles..." -ForegroundColor Cyan
Get-NetFirewallProfile | ForEach-Object {
    Add-Result "Firewall:$($_.Name)" 'Enabled'              $_.Enabled              $_.Enabled                         ''
    Add-Result "Firewall:$($_.Name)" 'DefaultInboundAction' $_.DefaultInboundAction ($_.DefaultInboundAction -eq 'Block') 'Must be Block'
    Add-Result "Firewall:$($_.Name)" 'DefaultOutboundAction' $_.DefaultOutboundAction 'N/A'                            'Review outbound policy'
    Add-Result "Firewall:$($_.Name)" 'LogFilePath'          $_.LogFileName          ($_.LogFileName -ne '')            ''
    Add-Result "Firewall:$($_.Name)" 'LogMaxSizeKilobytes'  $_.LogMaxSizeKilobytes  ($_.LogMaxSizeKilobytes -ge 16384) 'Min 16MB recommended'
}

# Active firewall rules count
$RuleCount = (Get-NetFirewallRule | Where-Object Enabled -eq 'True').Count
Add-Result 'FirewallRules' 'EnabledRuleCount' $RuleCount ($RuleCount -gt 0) ''

# Listening ports
Write-Host "[PORTS] Enumerating listening services..." -ForegroundColor Cyan
Get-NetTCPConnection -State Listen | ForEach-Object {
    $Proc = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
    Add-Result 'ListeningPort' "TCP:$($_.LocalPort)" $_.LocalAddress 'Review' "Process: $Proc"
}

$Results | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
Write-Host "[DONE] $($Results.Count) records -> $OutFile" -ForegroundColor Green
$Fails = $Results | Where-Object { $_.Pass -eq $false }
if ($Fails) { $Fails | ForEach-Object { Write-Host "FAIL: [$($_.Source)] $($_.Setting) = $($_.Value)" -ForegroundColor Red } }
