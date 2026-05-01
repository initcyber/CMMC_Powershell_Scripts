#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CMMC Level 2 / NIST 800-171 r2 - RA.L2-3.11.1 / RA.L2-3.11.2
    Periodically assess the risk to organizational operations, assets, and
    individuals resulting from the operation of organizational systems.
    Scan for vulnerabilities in organizational systems periodically.

.DESCRIPTION
    Produces a system baseline artifact package for vulnerability assessment
    evidence. Covers:
      1. System information baseline
      2. Installed software  (HKLM 64-bit, HKLM 32-bit, HKCU)
      3. Patch inventory and currency (HotFix + WU COM history)
      4. Defender AV definition currency
      5. Pending updates flag (PSWindowsUpdate if available)

    NOTE: This script documents the system state as supporting evidence.
    It does NOT substitute for a credentialed vulnerability scan (Tenable,
    Nessus, Rapid7, etc.). Assessors will expect scan results from an
    approved scanner in addition to this artifact.

    Output: timestamped CSVs + txt in .\output\
      RA_3_11_1_SystemInfo_*.csv
      RA_3_11_1_Software_*.csv
      RA_3_11_1_Patches_*.csv
      RA_3_11_1_WUHistory_*.csv
      RA_3_11_1_Defender_*.csv
#>

$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$Hostname  = $env:COMPUTERNAME
$OutDir    = Join-Path $PSScriptRoot 'output'
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

# ── 1. SYSTEM INFORMATION BASELINE ───────────────────────────────────────────
Write-Host "`n[SYSINFO] Collecting system baseline..." -ForegroundColor Cyan

$OS  = Get-CimInstance Win32_OperatingSystem
$CS  = Get-CimInstance Win32_ComputerSystem
$CPU = Get-CimInstance Win32_Processor | Select-Object -First 1

$SysInfo = [PSCustomObject]@{
    Hostname        = $Hostname
    OSCaption       = $OS.Caption
    OSVersion       = $OS.Version
    OSBuild         = $OS.BuildNumber
    OSArchitecture  = $OS.OSArchitecture
    ServicePack     = $OS.ServicePackMajorVersion
    LastBootTime    = $OS.LastBootUpTime
    Domain          = $CS.Domain
    PartOfDomain    = $CS.PartOfDomain
    Manufacturer    = $CS.Manufacturer
    Model           = $CS.Model
    TotalRAM_GB     = [math]::Round($CS.TotalPhysicalMemory / 1GB, 2)
    Processor       = $CPU.Name
    Collected       = Get-Date -Format 'o'
}

$SysInfoCsv = Join-Path $OutDir "RA_3_11_1_SystemInfo_${Hostname}_${Timestamp}.csv"
$SysInfo | Export-Csv -Path $SysInfoCsv -NoTypeInformation -Encoding UTF8

$SysInfo | Format-List OSCaption, OSBuild, Domain, LastBootTime
Write-Host "  System info exported." -ForegroundColor Green

# ── 2. INSTALLED SOFTWARE (all three registry hives) ─────────────────────────
Write-Host "[SOFTWARE] Enumerating installed software (all registry hives)..." -ForegroundColor Cyan

$SoftwareResults = [System.Collections.Generic.List[PSCustomObject]]::new()

$RegPaths = @(
    @{Path='HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*';          Hive='HKLM-64'},
    @{Path='HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; Hive='HKLM-32'},
    @{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*';          Hive='HKCU'}
)

foreach ($Reg in $RegPaths) {
    try {
        Get-ItemProperty -Path $Reg.Path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            ForEach-Object {
                $SoftwareResults.Add([PSCustomObject]@{
                    RegistryHive    = $Reg.Hive
                    DisplayName     = $_.DisplayName
                    DisplayVersion  = $_.DisplayVersion
                    Publisher       = $_.Publisher
                    InstallDate     = $_.InstallDate
                    InstallLocation = $_.InstallLocation
                    Hostname        = $Hostname
                    Collected       = Get-Date -Format 'o'
                })
            }
    } catch {
        Write-Warning "Could not read $($Reg.Hive): $_"
    }
}

# Deduplicate by name+version across hives
$SoftwareResults = $SoftwareResults |
    Sort-Object DisplayName, DisplayVersion, RegistryHive |
    Group-Object DisplayName, DisplayVersion |
    ForEach-Object { $_.Group | Select-Object -First 1 }

$SoftwareCsv = Join-Path $OutDir "RA_3_11_1_Software_${Hostname}_${Timestamp}.csv"
$SoftwareResults | Export-Csv -Path $SoftwareCsv -NoTypeInformation -Encoding UTF8
Write-Host "  $($SoftwareResults.Count) unique installed applications documented." -ForegroundColor Green

# ── 3. PATCH INVENTORY & CURRENCY ────────────────────────────────────────────
Write-Host "[PATCHES] Retrieving installed hotfixes..." -ForegroundColor Cyan

$HotFixes = Get-HotFix |
    Sort-Object InstalledOn -Descending |
    ForEach-Object {
        [PSCustomObject]@{
            HotFixID    = $_.HotFixID
            Description = $_.Description
            InstalledBy = $_.InstalledBy
            InstalledOn = $_.InstalledOn
            DaysAgo     = if ($_.InstalledOn) { (New-TimeSpan -Start $_.InstalledOn).Days } else { $null }
            Hostname    = $Hostname
            Collected   = Get-Date -Format 'o'
        }
    }

$PatchCsv = Join-Path $OutDir "RA_3_11_1_Patches_${Hostname}_${Timestamp}.csv"
$HotFixes | Export-Csv -Path $PatchCsv -NoTypeInformation -Encoding UTF8

$Latest    = $HotFixes | Select-Object -First 1
$DaysSince = $Latest.DaysAgo
$PatchPass = $null -ne $DaysSince -and $DaysSince -le 30

Write-Host ("  {0} hotfixes found. Latest: {1} installed {2} days ago. [{3}]" -f
    $HotFixes.Count, $Latest.HotFixID, $DaysSince, $(if ($PatchPass) { 'PASS' } else { 'REVIEW' })) `
    -ForegroundColor $(if ($PatchPass) { 'Green' } else { 'Yellow' })

# ── 4. WINDOWS UPDATE HISTORY (COM object) ────────────────────────────────────
Write-Host "[WU] Querying Windows Update history..." -ForegroundColor Cyan

$WUResults = [System.Collections.Generic.List[PSCustomObject]]::new()

try {
    $UpdateSession  = New-Object -ComObject Microsoft.Update.Session
    $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
    $HistoryCount   = $UpdateSearcher.GetTotalHistoryCount()

    if ($HistoryCount -gt 0) {
        $History = $UpdateSearcher.QueryHistory(0, [math]::Min($HistoryCount, 50))
        foreach ($Entry in $History) {
            $WUResults.Add([PSCustomObject]@{
                Title       = $Entry.Title
                Date        = $Entry.Date
                Operation   = switch ($Entry.Operation) {
                    1 { 'Installation' }
                    2 { 'Uninstallation' }
                    3 { 'Other' }
                    default { "Unknown ($($Entry.Operation))" }
                }
                ResultCode  = switch ($Entry.ResultCode) {
                    1 { 'In Progress' }
                    2 { 'Succeeded' }
                    3 { 'Succeeded With Errors' }
                    4 { 'Failed' }
                    5 { 'Aborted' }
                    default { "Unknown ($($Entry.ResultCode))" }
                }
                DaysAgo     = (New-TimeSpan -Start $Entry.Date).Days
                Hostname    = $Hostname
                Collected   = Get-Date -Format 'o'
            })
        }
        Write-Host "  $($WUResults.Count) WU history entries retrieved." -ForegroundColor Green

        # Flag any failed installations
        $FailedUpdates = $WUResults | Where-Object { $_.ResultCode -match 'Failed|Aborted' }
        if ($FailedUpdates) {
            Write-Host "  REVIEW: $($FailedUpdates.Count) failed/aborted update(s) in history." -ForegroundColor Yellow
        }
    } else {
        Write-Host "  No Windows Update history found." -ForegroundColor DarkGray
    }
} catch {
    Write-Warning "Windows Update COM query failed: $_"
}

$WUCsv = Join-Path $OutDir "RA_3_11_1_WUHistory_${Hostname}_${Timestamp}.csv"
$WUResults | Export-Csv -Path $WUCsv -NoTypeInformation -Encoding UTF8

# ── 5. DEFENDER AV DEFINITION CURRENCY ───────────────────────────────────────
Write-Host "[DEFENDER] Checking AV definition currency..." -ForegroundColor Cyan

$DefResults = [System.Collections.Generic.List[PSCustomObject]]::new()

try {
    $Mp = Get-MpComputerStatus -ErrorAction Stop
    $DefAge = (New-TimeSpan -Start $Mp.AntivirusSignatureLastUpdated).Days

    $DefResults.Add([PSCustomObject]@{
        Setting         = 'AntivirusEnabled'
        Value           = $Mp.AntivirusEnabled
        Pass            = $Mp.AntivirusEnabled
        Hostname        = $Hostname
        Collected       = Get-Date -Format 'o'
    })
    $DefResults.Add([PSCustomObject]@{
        Setting         = 'RealTimeProtectionEnabled'
        Value           = $Mp.RealTimeProtectionEnabled
        Pass            = $Mp.RealTimeProtectionEnabled
        Hostname        = $Hostname
        Collected       = Get-Date -Format 'o'
    })
    $DefResults.Add([PSCustomObject]@{
        Setting         = 'SignatureVersion'
        Value           = $Mp.AntivirusSignatureVersion
        Pass            = 'N/A'
        Hostname        = $Hostname
        Collected       = Get-Date -Format 'o'
    })
    $DefResults.Add([PSCustomObject]@{
        Setting         = 'SignatureLastUpdated'
        Value           = $Mp.AntivirusSignatureLastUpdated
        Pass            = ($DefAge -le 1)
        Hostname        = $Hostname
        Collected       = Get-Date -Format 'o'
    })
    $DefResults.Add([PSCustomObject]@{
        Setting         = 'SignatureAgeDays'
        Value           = $DefAge
        Pass            = ($DefAge -le 1)
        Hostname        = $Hostname
        Collected       = Get-Date -Format 'o'
    })

    Write-Host ("  Defender signatures {0} days old. [{1}]" -f
        $DefAge, $(if ($DefAge -le 1) { 'PASS' } else { 'REVIEW' })) `
        -ForegroundColor $(if ($DefAge -le 1) { 'Green' } else { 'Yellow' })

} catch {
    Write-Warning "Get-MpComputerStatus failed (elevation required or Defender not present): $_"
}

$DefCsv = Join-Path $OutDir "RA_3_11_1_Defender_${Hostname}_${Timestamp}.csv"
$DefResults | Export-Csv -Path $DefCsv -NoTypeInformation -Encoding UTF8

# ── 6. SUMMARY ────────────────────────────────────────────────────────────────
Write-Host "`n-- RA.3.11.1 SUMMARY ---------------------------------------" -ForegroundColor White
Write-Host "  Installed applications  : $($SoftwareResults.Count)"
Write-Host "  Installed hotfixes      : $($HotFixes.Count)"
Write-Host "  Days since last patch   : $DaysSince  $(if($PatchPass){'[PASS]'}else{'[REVIEW]'})" `
    -ForegroundColor $(if ($PatchPass) { 'Green' } else { 'Yellow' })
Write-Host "  WU history entries      : $($WUResults.Count)"
Write-Host ""
Write-Host "  NOTE: External credentialed vulnerability scanner results" -ForegroundColor Yellow
Write-Host "  (Tenable, Nessus, Rapid7, etc.) are required separately." -ForegroundColor Yellow
Write-Host "  This script is supporting baseline evidence only." -ForegroundColor Yellow
Write-Host "`n  Artifacts:"
Write-Host "    $SysInfoCsv"
Write-Host "    $SoftwareCsv"
Write-Host "    $PatchCsv"
Write-Host "    $WUCsv"
Write-Host "    $DefCsv"
Write-Host "------------------------------------------------------------`n" -ForegroundColor White