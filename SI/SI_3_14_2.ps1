#Requires -Version 5.1
<#
.SYNOPSIS
    CMMC Level 2 / NIST 800-171 r2 - SI.3.14.2 / SI.3.14.4 / SI.3.14.5
    Provide protection from malicious code at appropriate locations.
    Update malicious code protection. Perform periodic and real-time scans.
#>
$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$Hostname  = $env:COMPUTERNAME
$OutDir    = "$PSScriptRoot\output"
$OutFile   = "$OutDir\SI_3_14_2_${Hostname}_${Timestamp}.csv"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$Results = [System.Collections.Generic.List[PSCustomObject]]::new()
function Add-Result { param($Control,$Setting,$Value,$Pass,$Notes)
    $Results.Add([PSCustomObject]@{Control=$Control;Setting=$Setting;Value=$Value;Pass=$Pass;Notes=$Notes
    Hostname=$Hostname;Collected=(Get-Date -Format 'o')}) }

Write-Host "`n[DEFENDER] Querying Windows Defender status..." -ForegroundColor Cyan
try {
    $S = Get-MpComputerStatus -ErrorAction Stop
    $P = Get-MpPreference -ErrorAction Stop

    # 3.14.2 — protection installed and enabled
    Add-Result 'SI.3.14.2' 'AntivirusEnabled'           $S.AntivirusEnabled             $S.AntivirusEnabled         ''
    Add-Result 'SI.3.14.2' 'AntispywareEnabled'         $S.AntispywareEnabled           $S.AntispywareEnabled       ''
    Add-Result 'SI.3.14.2' 'AMServiceEnabled'           $S.AMServiceEnabled             $S.AMServiceEnabled         ''
    Add-Result 'SI.3.14.2' 'BehaviorMonitorEnabled'     $S.BehaviorMonitorEnabled       $S.BehaviorMonitorEnabled   ''
    Add-Result 'SI.3.14.2' 'IoavProtectionEnabled'      $S.IoavProtectionEnabled        $S.IoavProtectionEnabled    ''
    Add-Result 'SI.3.14.2' 'NISEnabled'                 $S.NISEnabled                   $S.NISEnabled               'Network Inspection Service'

    # 3.14.4 — definitions current
    $DefAge = (New-TimeSpan -Start $S.AntivirusSignatureLastUpdated).Days
    Add-Result 'SI.3.14.4' 'AntivirusSignatureVersion'  $S.AntivirusSignatureVersion    'N/A'                       ''
    Add-Result 'SI.3.14.4' 'SignatureAge(days)'         $DefAge                         ($DefAge -le 1)             'Should be updated daily; >1 day is a finding'
    Add-Result 'SI.3.14.4' 'SignatureLastUpdated'       $S.AntivirusSignatureLastUpdated ($DefAge -le 1)            ''

    # 3.14.5 — real-time and scheduled scans configured
    Add-Result 'SI.3.14.5' 'RealTimeProtectionEnabled'  $S.RealTimeProtectionEnabled    $S.RealTimeProtectionEnabled ''
    Add-Result 'SI.3.14.5' 'DisableRealtimeMonitoring'  $P.DisableRealtimeMonitoring    (-not $P.DisableRealtimeMonitoring) 'Must be $false'
    Add-Result 'SI.3.14.5' 'ScanScheduleDay'            $P.ScanScheduleDay              ($P.ScanScheduleDay -ne 8)  '8=Never; any other value = scheduled'
    Add-Result 'SI.3.14.5' 'QuickScanSignatureVersion'  $S.QuickScanSignatureVersion    'N/A'                       ''
    Add-Result 'SI.3.14.5' 'LastQuickScanTime'          $S.QuickScanAge                 ($S.QuickScanAge -le 1)     'Days since last quick scan'

} catch { Write-Warning "Get-MpComputerStatus failed (may need elevation): $_" }

$Results | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
$Results | Format-Table Control, Setting, Value, Pass -AutoSize
Write-Host "[DONE] Written to: $OutFile" -ForegroundColor Green
$Fails = $Results | Where-Object { $_.Pass -eq $false }
if ($Fails) { $Fails | ForEach-Object { Write-Host "FAIL: [$($_.Control)] $($_.Setting) = $($_.Value)" -ForegroundColor Red } }
else        { Write-Host "All AV/malware protection checks PASS." -ForegroundColor Green }
