#Requires -Version 5.1
<#
.SYNOPSIS
    CMMC Level 2 / NIST 800-171 r2 - SC.3.13.16
    Protect the confidentiality of CUI at rest.
    (Same BitLocker check as AC.3.1.19 — run as standalone or link artifacts)
#>
$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$Hostname  = $env:COMPUTERNAME
$OutDir    = "$PSScriptRoot\output"
$OutFile   = "$OutDir\SC_3_13_16_${Hostname}_${Timestamp}.csv"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

Write-Host "`n[BITLOCKER] Checking encryption at rest for all volumes..." -ForegroundColor Cyan
try {
    $Volumes = Get-BitLockerVolume -ErrorAction Stop
    $Report = $Volumes | Select-Object `
        MountPoint, VolumeType, VolumeStatus, EncryptionPercentage, EncryptionMethod, ProtectionStatus,
        @{N='KeyProtectors';E={($_.KeyProtector | Select-Object -ExpandProperty KeyProtectorType) -join ', '}},
        @{N='Pass';E={$_.ProtectionStatus -eq 'On'}},
        @{N='Hostname';E={$env:COMPUTERNAME}},
        @{N='Collected';E={Get-Date -Format 'o'}}
    $Report | Format-Table MountPoint, VolumeType, EncryptionPercentage, ProtectionStatus, Pass -AutoSize
    $Report | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8

    $Unprotected = $Report | Where-Object { -not $_.Pass }
    if ($Unprotected) { Write-Host "FAIL: Unprotected volumes found." -ForegroundColor Red ; $Unprotected | ForEach-Object { Write-Host "  $($_.MountPoint)" -ForegroundColor Red } }
    else              { Write-Host "PASS: All volumes protected." -ForegroundColor Green }
} catch { Write-Warning "BitLocker query failed (elevation required): $_" }
Write-Host "[DONE] Written to: $OutFile" -ForegroundColor Green
