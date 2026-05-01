#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CMMC Level 2 / NIST 800-171 r2 - AC.L2-3.1.3
    Control the flow of CUI in accordance with approved authorizations.

.DESCRIPTION
    Audits SMB shares and permissions as a technical indicator of CUI flow
    control — identifying who can access what over the network, and whether
    admin shares are exposed unnecessarily.

    Checks:
      1. All non-hidden SMB shares — SMB permissions + NTFS ACLs
      2. Hidden/admin shares (C$, ADMIN$, IPC$) — existence and access
      3. AutoShareWks / AutoShareServer registry settings
      4. Any share accessible by Everyone, Authenticated Users, or Domain Users
         (broad access = potential uncontrolled CUI flow)

    Output: two timestamped CSVs in .\output\
      1. AC_3_1_3_Shares_*.csv       -- all share + permission details
      2. AC_3_1_3_Findings_*.csv     -- flagged broad-access entries only
#>

$Timestamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
$Hostname    = $env:COMPUTERNAME
$OutDir      = Join-Path $PSScriptRoot 'output'
$ShareCsv    = Join-Path $OutDir "AC_3_1_3_Shares_${Hostname}_${Timestamp}.csv"
$FindingsCsv = Join-Path $OutDir "AC_3_1_3_Findings_${Hostname}_${Timestamp}.csv"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$ShareResults   = [System.Collections.Generic.List[PSCustomObject]]::new()
$FindingResults = [System.Collections.Generic.List[PSCustomObject]]::new()

# Identities that represent broad/uncontrolled access — flag these
$BroadAccessIdentities = @(
    'Everyone',
    'Authenticated Users',
    'NT AUTHORITY\Authenticated Users',
    'Domain Users',
    'BUILTIN\Users'
)

function Get-NtfsAcl {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path $Path -ErrorAction SilentlyContinue)) { return 'Path not accessible' }
    try {
        $Acl = Get-Acl -Path $Path -ErrorAction Stop
        ($Acl.Access | Where-Object { $_.AccessControlType -eq 'Allow' } |
            ForEach-Object { "$($_.IdentityReference):$($_.FileSystemRights)" }) -join ' | '
    } catch { "ACL query failed: $_" }
}

# ── 1. NON-HIDDEN SHARES ──────────────────────────────────────────────────────
Write-Host "`n[SMB] Enumerating non-hidden shares..." -ForegroundColor Cyan

$VisibleShares = Get-SmbShare | Where-Object { $_.Name -notlike '*$' }
Write-Host "  Found $($VisibleShares.Count) non-hidden share(s)." -ForegroundColor Green

foreach ($Share in $VisibleShares) {
    $NtfsAcl = Get-NtfsAcl -Path $Share.Path

    try {
        $AccessEntries = Get-SmbShareAccess -Name $Share.Name -ErrorAction Stop
    } catch {
        $AccessEntries = @([PSCustomObject]@{
            AccountName       = 'ERROR'
            AccessControlType = 'N/A'
            AccessRight       = "Query failed: $_"
        })
    }

    foreach ($Ace in $AccessEntries) {
        $IsBroad  = $BroadAccessIdentities | Where-Object { $Ace.AccountName -match [regex]::Escape($_) }
        $Finding  = if ($IsBroad -and $Ace.AccessControlType -eq 'Allow') {
                        "REVIEW: broad identity '$($Ace.AccountName)' has $($Ace.AccessRight)"
                    } else { 'OK' }

        $Row = [PSCustomObject]@{
            ShareType         = 'Visible'
            ShareName         = $Share.Name
            SharePath         = $Share.Path
            Description       = $Share.Description
            AccountName       = $Ace.AccountName
            AccessControlType = $Ace.AccessControlType
            AccessRight       = $Ace.AccessRight
            NtfsAcl           = $NtfsAcl
            Finding           = $Finding
            Hostname          = $Hostname
            Collected         = Get-Date -Format 'o'
        }
        $ShareResults.Add($Row)
        if ($Finding -ne 'OK') { $FindingResults.Add($Row) }
    }
}

# ── 2. HIDDEN / ADMIN SHARES ──────────────────────────────────────────────────
Write-Host "[SMB] Enumerating hidden/admin shares..." -ForegroundColor Cyan

$HiddenShares = Get-SmbShare | Where-Object { $_.Name -like '*$' }
Write-Host "  Found $($HiddenShares.Count) hidden share(s)." -ForegroundColor Green

foreach ($Share in $HiddenShares) {
    $NtfsAcl = Get-NtfsAcl -Path $Share.Path

    try {
        $AccessEntries = Get-SmbShareAccess -Name $Share.Name -ErrorAction Stop
    } catch {
        $AccessEntries = @([PSCustomObject]@{
            AccountName       = 'ERROR'
            AccessControlType = 'N/A'
            AccessRight       = "Query failed: $_"
        })
    }

    foreach ($Ace in $AccessEntries) {
        $IsBroad = $BroadAccessIdentities | Where-Object { $Ace.AccountName -match [regex]::Escape($_) }
        $Finding = if ($IsBroad -and $Ace.AccessControlType -eq 'Allow') {
                       "REVIEW: broad identity on admin share '$($Share.Name)'"
                   } else { 'OK - admin share, verify necessity' }

        $Row = [PSCustomObject]@{
            ShareType         = 'Hidden/Admin'
            ShareName         = $Share.Name
            SharePath         = $Share.Path
            Description       = $Share.Description
            AccountName       = $Ace.AccountName
            AccessControlType = $Ace.AccessControlType
            AccessRight       = $Ace.AccessRight
            NtfsAcl           = $NtfsAcl
            Finding           = $Finding
            Hostname          = $Hostname
            Collected         = Get-Date -Format 'o'
        }
        $ShareResults.Add($Row)
        if ($Finding -notmatch '^OK') { $FindingResults.Add($Row) }
    }
}

# ── 3. AUTOSHARE REGISTRY SETTINGS ────────────────────────────────────────────
Write-Host "[REGISTRY] Checking AutoShare settings..." -ForegroundColor Cyan

$LanmanPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
try {
    $LanmanParams = Get-ItemProperty -Path $LanmanPath -ErrorAction Stop
    $AutoShareWks    = $LanmanParams.AutoShareWks
    $AutoShareServer = $LanmanParams.AutoShareServer

    # 0 = disabled (admin shares suppressed), 1 or absent = enabled (default)
    foreach ($Setting in @(
        @{Name='AutoShareWks';    Value=$AutoShareWks;    Context='Workstation admin shares (C$, ADMIN$)'},
        @{Name='AutoShareServer'; Value=$AutoShareServer; Context='Server admin shares'}
    )) {
        $Val     = if ($null -eq $Setting.Value) { 'Not set (default: enabled)' } else { $Setting.Value }
        $Finding = if ($Setting.Value -eq 0) { 'OK - admin shares disabled' } else { 'REVIEW: admin shares enabled (default)' }

        $Row = [PSCustomObject]@{
            ShareType         = 'RegistryPolicy'
            ShareName         = $Setting.Name
            SharePath         = $LanmanPath
            Description       = $Setting.Context
            AccountName       = 'N/A'
            AccessControlType = 'N/A'
            AccessRight       = $Val
            NtfsAcl           = 'N/A'
            Finding           = $Finding
            Hostname          = $Hostname
            Collected         = Get-Date -Format 'o'
        }
        $ShareResults.Add($Row)
        if ($Finding -notmatch '^OK') { $FindingResults.Add($Row) }
    }
} catch {
    Write-Warning "Could not query LanmanServer parameters: $_"
}

# ── 4. OUTPUT & SUMMARY ───────────────────────────────────────────────────────
$ShareResults   | Export-Csv -Path $ShareCsv    -NoTypeInformation -Encoding UTF8
$FindingResults | Export-Csv -Path $FindingsCsv -NoTypeInformation -Encoding UTF8

Write-Host "`n-- AC.3.1.3 SUMMARY ----------------------------------------" -ForegroundColor White
Write-Host "  Total share ACEs documented : $($ShareResults.Count)"
Write-Host "  Findings (REVIEW)           : $($FindingResults.Count)" `
    -ForegroundColor $(if ($FindingResults.Count) { 'Red' } else { 'Green' })

if ($FindingResults) {
    Write-Host "`n  Flagged entries:" -ForegroundColor Red
    $FindingResults | ForEach-Object {
        Write-Host "    [$($_.ShareType)] $($_.ShareName) -- $($_.AccountName) -- $($_.Finding)" -ForegroundColor Red
    }
}

Write-Host "`n  Artifacts:"
Write-Host "    $ShareCsv"
Write-Host "    $FindingsCsv"
Write-Host "------------------------------------------------------------`n" -ForegroundColor White