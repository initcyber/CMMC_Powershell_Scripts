#Requires -Version 5.1
<#
.SYNOPSIS
    CMMC Level 2 / NIST 800-171 r2 - AC.3.1.1
    Limit system access to authorized users, processes acting on behalf of authorized users,
    and devices (including other systems).
.NOTES
    Scope  : Local machine + Active Directory (if available) + Entra ID (if available)
    Output : Console + timestamped CSV artifact
#>

$Timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$Hostname   = $env:COMPUTERNAME
$OutDir     = "$PSScriptRoot\output"
$OutFile    = "$OutDir\AC_3_1_1_${Hostname}_${Timestamp}.csv"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$Results = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Result {
    param($Source, $Identity, $Enabled, $LastLogon, $Notes)
    $Results.Add([PSCustomObject]@{
        Source    = $Source
        Identity  = $Identity
        Enabled   = $Enabled
        LastLogon = $LastLogon
        Notes     = $Notes
        Hostname  = $Hostname
        Collected = (Get-Date -Format 'o')
    })
}

# ── 1. LOCAL USERS ────────────────────────────────────────────────────────────
Write-Host "`n[LOCAL] Enumerating local user accounts..." -ForegroundColor Cyan
try {
    Get-LocalUser | ForEach-Object {
        Add-Result `
            -Source    'Local' `
            -Identity  $_.Name `
            -Enabled   $_.Enabled `
            -LastLogon ($_.LastLogon -as [string]) `
            -Notes     $(if (-not $_.PasswordRequired) { 'WARN: No password required' } else { '' })
    }
    Write-Host "  Found $((Get-LocalUser).Count) local accounts." -ForegroundColor Green
} catch {
    Write-Warning "Local user enumeration failed: $_"
}

# ── 2. LOCAL GROUP MEMBERSHIPS (Administrators + Remote Desktop Users) ────────
Write-Host "[LOCAL] Checking privileged group memberships..." -ForegroundColor Cyan
foreach ($Group in @('Administrators','Remote Desktop Users','Backup Operators')) {
    try {
        Get-LocalGroupMember -Group $Group -ErrorAction Stop | ForEach-Object {
            Add-Result `
                -Source    "LocalGroup:$Group" `
                -Identity  $_.Name `
                -Enabled   'N/A' `
                -LastLogon 'N/A' `
                -Notes     "Member of local $Group"
        }
    } catch {
        Write-Warning "Could not enumerate $Group : $_"
    }
}

# ── 3. ACTIVE DIRECTORY ───────────────────────────────────────────────────────
Write-Host "[AD] Checking for Active Directory module..." -ForegroundColor Cyan
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    try {
        $ADUsers = Get-ADUser -Filter * -Properties LastLogonDate, Enabled, DistinguishedName |
            Select-Object SamAccountName, Enabled, LastLogonDate, DistinguishedName
        $ADUsers | ForEach-Object {
            Add-Result `
                -Source    'ActiveDirectory' `
                -Identity  $_.SamAccountName `
                -Enabled   $_.Enabled `
                -LastLogon ($_.LastLogonDate -as [string]) `
                -Notes     $_.DistinguishedName
        }
        Write-Host "  Found $($ADUsers.Count) AD user accounts." -ForegroundColor Green

        # Stale accounts (no logon > 90 days) flagged
        $Stale = $ADUsers | Where-Object {
            $_.Enabled -and $_.LastLogonDate -and ((New-TimeSpan -Start $_.LastLogonDate).Days -gt 90)
        }
        if ($Stale) {
            Write-Warning "  $($Stale.Count) enabled AD accounts have not logged on in >90 days."
        }
    } catch {
        Write-Warning "AD query failed: $_"
    }
} else {
    Write-Host "  ActiveDirectory module not available — skipping AD check." -ForegroundColor Yellow
}

# ── 4. ENTRA ID (Microsoft Graph) ─────────────────────────────────────────────
Write-Host "[ENTRA] Checking for Microsoft.Graph module..." -ForegroundColor Cyan
if (Get-Module -ListAvailable -Name Microsoft.Graph.Users) {
    try {
        Connect-MgGraph -Scopes 'User.Read.All' -ErrorAction Stop | Out-Null
        $EntraUsers = Get-MgUser -All -Property DisplayName, UserPrincipalName, AccountEnabled, SignInActivity |
            Select-Object DisplayName, UserPrincipalName, AccountEnabled,
                          @{N='LastSignIn';E={$_.SignInActivity.LastSignInDateTime}}
        $EntraUsers | ForEach-Object {
            Add-Result `
                -Source    'EntraID' `
                -Identity  $_.UserPrincipalName `
                -Enabled   $_.AccountEnabled `
                -LastLogon ($_.LastSignIn -as [string]) `
                -Notes     $_.DisplayName
        }
        Write-Host "  Found $($EntraUsers.Count) Entra ID accounts." -ForegroundColor Green
    } catch {
        Write-Warning "Entra ID query failed (check permissions/auth): $_"
    }
} else {
    Write-Host "  Microsoft.Graph.Users module not available — skipping Entra check." -ForegroundColor Yellow
    Write-Host "  Install with: Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Yellow
}

# ── 5. OUTPUT ─────────────────────────────────────────────────────────────────
$Results | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
Write-Host "`n[DONE] $($Results.Count) total records written to:`n  $OutFile" -ForegroundColor Green

# Summary to console
Write-Host "`n── SUMMARY ──────────────────────────────────────────" -ForegroundColor White
$Results | Group-Object Source | ForEach-Object {
    Write-Host ("  {0,-30} {1} accounts" -f $_.Name, $_.Count)
}

$DisabledCount = ($Results | Where-Object { $_.Enabled -eq $false }).Count
$WarnCount     = ($Results | Where-Object { $_.Notes -like 'WARN*' }).Count
Write-Host "`n  Disabled accounts : $DisabledCount"
Write-Host "  Warnings flagged  : $WarnCount"
Write-Host "─────────────────────────────────────────────────────`n" -ForegroundColor White
