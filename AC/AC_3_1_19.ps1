#Requires -Version 5.1
<#
.SYNOPSIS
    CMMC Level 2 / NIST 800-171 r2 - AC.3.1.19
    Encrypt CUI on mobile devices and mobile computing platforms.
    (Also covers 3.13.16 - CUI at rest on all volumes)
.NOTES
    Checks BitLocker status on all fixed + removable volumes.
#>

$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$Hostname  = $env:COMPUTERNAME
$OutDir    = "$PSScriptRoot\output"
$OutFile   = "$OutDir\AC_3_1_19_${Hostname}_${Timestamp}.csv"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

Write-Host "`n[BITLOCKER] Enumerating volumes..." -ForegroundColor Cyan

try {
    $Volumes = Get-BitLockerVolume -ErrorAction Stop
    $Report  = $Volumes | Select-Object `
        MountPoint,
        VolumeType,
        VolumeStatus,
        EncryptionPercentage,
        EncryptionMethod,
        ProtectionStatus,
        @{N='Protectors';E={($_.KeyProtector | Select-Object -ExpandProperty KeyProtectorType) -join ', '}},
        @{N='Pass';E={$_.ProtectionStatus -eq 'On'}},
        @{N='Hostname';E={$env:COMPUTERNAME}},
        @{N='Collected';E={Get-Date -Format 'o'}}

    $Report | Format-Table MountPoint, VolumeType, VolumeStatus, EncryptionPercentage, ProtectionStatus, Pass -AutoSize
    $Report | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8

    $Unprotected = $Report | Where-Object { -not $_.Pass }
    if ($Unprotected) {
        Write-Host "`nFAIL: Unprotected volumes:" -ForegroundColor Red
        $Unprotected | ForEach-Object { Write-Host "  $($_.MountPoint) - $($_.VolumeStatus)" -ForegroundColor Red }
    } else {
        Write-Host "`nPASS: All volumes have BitLocker protection ON." -ForegroundColor Green
    }
} catch {
    Write-Warning "BitLocker query failed (requires elevation or BitLocker feature): $_"
}

Write-Host "[DONE] Written to: $OutFile" -ForegroundColor Green
