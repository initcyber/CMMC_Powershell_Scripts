#Requires -Version 5.1
<#
.SYNOPSIS
    CMMC Level 2 / NIST 800-171 r2 - CM.3.4.2
    Establish and enforce security configuration settings for IT products
    employed in organizational systems.
.NOTES
    Exports current DSC configuration and applied GPO settings for evidence.
#>
$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$Hostname  = $env:COMPUTERNAME
$OutDir    = "$PSScriptRoot\output"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

Write-Host "`n[GPO] Generating applied GPO report..." -ForegroundColor Cyan
$GpoOut = "$OutDir\CM_3_4_2_GPOReport_${Hostname}_${Timestamp}.xml"
try {
    gpresult /X $GpoOut /F 2>&1 | Out-Null
    Write-Host "  GPO report: $GpoOut" -ForegroundColor Green
} catch { Write-Warning "gpresult failed: $_" }

Write-Host "[SECEDIT] Exporting security configuration baseline..." -ForegroundColor Cyan
$SecOut = "$OutDir\CM_3_4_2_SecBaseline_${Hostname}_${Timestamp}.cfg"
secedit /export /cfg $SecOut /quiet
if (Test-Path $SecOut) { Write-Host "  Security baseline: $SecOut" -ForegroundColor Green }

Write-Host "[WINFEATURES] Listing installed Windows features..." -ForegroundColor Cyan
$FeatOut = "$OutDir\CM_3_4_2_Features_${Hostname}_${Timestamp}.csv"
try {
    Get-WindowsFeature | Where-Object Installed |
        Select-Object Name, DisplayName, InstallState |
        Export-Csv -Path $FeatOut -NoTypeInformation -Encoding UTF8
    Write-Host "  Features: $FeatOut" -ForegroundColor Green
} catch {
    # Workstation fallback
    Get-WindowsOptionalFeature -Online | Where-Object State -eq 'Enabled' |
        Select-Object FeatureName, State |
        Export-Csv -Path $FeatOut -NoTypeInformation -Encoding UTF8
    Write-Host "  Optional features (workstation): $FeatOut" -ForegroundColor Green
}

Write-Host "[SERVICES] Listing running services..." -ForegroundColor Cyan
$SvcOut = "$OutDir\CM_3_4_2_Services_${Hostname}_${Timestamp}.csv"
Get-Service | Where-Object Status -eq Running |
    Select-Object Name, DisplayName, StartType, Status |
    Export-Csv -Path $SvcOut -NoTypeInformation -Encoding UTF8
Write-Host "  Services: $SvcOut" -ForegroundColor Green

Write-Host "`n[DONE] CM.3.4.2 artifact files written to: $OutDir" -ForegroundColor Green
