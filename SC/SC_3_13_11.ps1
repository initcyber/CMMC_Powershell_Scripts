#Requires -Version 5.1
<#
.SYNOPSIS
    CMMC Level 2 / NIST 800-171 r2 - SC.3.13.11
    Employ FIPS-validated cryptography when used to protect the confidentiality of CUI.
#>
$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$Hostname  = $env:COMPUTERNAME
$OutDir    = "$PSScriptRoot\output"
$OutFile   = "$OutDir\SC_3_13_11_${Hostname}_${Timestamp}.csv"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$Results = [System.Collections.Generic.List[PSCustomObject]]::new()
function Add-Result { param($Setting,$Value,$Pass,$Notes)
    $Results.Add([PSCustomObject]@{Setting=$Setting;Value=$Value;Pass=$Pass;Notes=$Notes
    Hostname=$Hostname;Collected=(Get-Date -Format 'o')}) }

Write-Host "`n[FIPS] Checking FIPS algorithm policy..." -ForegroundColor Cyan

# Primary FIPS registry key
$FipsEnabled = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' -ErrorAction SilentlyContinue).Enabled
Add-Result 'FipsAlgorithmPolicy\Enabled' $FipsEnabled '1' ($FipsEnabled -eq 1) 'Must be 1 for FIPS mode'

# Group policy path (may override)
$GPOFips = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue).EnableFIPS
Add-Result 'GPO EnableFIPS' $GPOFips '1 or N/A' ($null -eq $GPOFips -or $GPOFips -eq 1) 'GPO path for FIPS enforcement'

# TLS cipher suites — verify only FIPS-approved present
Write-Host "[TLS] Checking TLS cipher suites..." -ForegroundColor Cyan
$NonFIPS = @('RC4','DES','3DES','NULL','ANON','EXPORT','MD5')
Get-TlsCipherSuite | ForEach-Object {
    $Name = $_.Name
    $BadAlgo = $NonFIPS | Where-Object { $Name -match $_ }
    Add-Result "TLS CipherSuite: $Name" $_.Protocol ($null -eq $BadAlgo) $(if($BadAlgo){"WARNING: Non-FIPS algorithm: $BadAlgo"}else{''})
}

# SCHANNEL protocols — verify TLS 1.2+ only
$SchannelBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
@('SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1') | ForEach-Object {
    $ProtoPath = "$SchannelBase\$_\Client"
    try {
        $Disabled = (Get-ItemProperty $ProtoPath -ErrorAction Stop).DisabledByDefault
        $Enabled  = (Get-ItemProperty $ProtoPath -ErrorAction Stop).Enabled
        Add-Result "SCHANNEL Protocol: $_" "Disabled=$Disabled,Enabled=$Enabled" 'Disabled=1,Enabled=0' ($Disabled -eq 1 -and $Enabled -eq 0) 'Legacy protocols must be disabled'
    } catch {
        Add-Result "SCHANNEL Protocol: $_" 'Not explicitly set' 'Verify OS default' 'N/A' 'Windows 2016+ disables these by default'
    }
}

$Results | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
Write-Host "[DONE] $($Results.Count) records -> $OutFile" -ForegroundColor Green
$Fails = $Results | Where-Object { $_.Pass -eq $false }
if ($Fails) { $Fails | ForEach-Object { Write-Host "FAIL: $($_.Setting) = $($_.Value)" -ForegroundColor Red } }
else        { Write-Host "All FIPS/TLS checks PASS." -ForegroundColor Green }
