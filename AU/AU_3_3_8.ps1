#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CMMC Level 2 / NIST 800-171 r2 - AU.L2-3.3.8
    Protect audit information and audit tools from unauthorized access,
    modification, and deletion.

.DESCRIPTION
    Checks ACLs on:
      1. All .evtx log files in winevt\Logs
      2. Key audit tools: auditpol.exe, wevtutil.exe, eventvwr.exe
    Flags any non-admin identity with Write, Modify, or FullControl rights.

    Output: timestamped CSV in .\output\
#>

$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$Hostname  = $env:COMPUTERNAME
$OutDir    = Join-Path $PSScriptRoot 'output'
$OutFile   = Join-Path $OutDir "AU_3_3_8_${Hostname}_${Timestamp}.csv"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$Results = [System.Collections.Generic.List[PSCustomObject]]::new()

# Identities considered authorized for write/modify on audit resources
$AuthorizedWriters = @(
    'NT AUTHORITY\SYSTEM',
    'BUILTIN\Administrators',
    'NT SERVICE\EventLog'
)

function Test-AclForFindings {
    param(
        [string]$TargetPath,
        [string]$Category
    )

    if (-not (Test-Path $TargetPath)) {
        $Results.Add([PSCustomObject]@{
            Category   = $Category
            Target     = $TargetPath
            Identity   = 'N/A'
            Rights     = 'N/A'
            AccessType = 'N/A'
            Owner      = 'N/A'
            Finding    = 'PATH NOT FOUND'
            Hostname   = $Hostname
            Collected  = Get-Date -Format 'o'
        })
        return
    }

    try {
        $Acl = Get-Acl -Path $TargetPath -ErrorAction Stop

        # Check each ACE for write-capable rights granted to non-authorized identities
        $Acl.Access | Where-Object {
            $_.FileSystemRights -match 'Write|Modify|FullControl|TakeOwnership|ChangePermissions' -and
            $_.AccessControlType -eq 'Allow'
        } | ForEach-Object {
            $Identity  = $_.IdentityReference.ToString()
            $IsAuth    = $AuthorizedWriters | Where-Object { $Identity -match [regex]::Escape($_) }
            $Finding   = if ($IsAuth) { 'OK - authorized identity' } else { "REVIEW: non-admin write access" }

            $Results.Add([PSCustomObject]@{
                Category   = $Category
                Target     = Split-Path $TargetPath -Leaf
                Identity   = $Identity
                Rights     = $_.FileSystemRights.ToString()
                AccessType = $_.AccessControlType.ToString()
                Owner      = $Acl.Owner
                Finding    = $Finding
                Hostname   = $Hostname
                Collected  = Get-Date -Format 'o'
            })
        }

        # If no write-capable ACEs found at all, record that as a clean result
        $WriteAces = $Acl.Access | Where-Object {
            $_.FileSystemRights -match 'Write|Modify|FullControl' -and
            $_.AccessControlType -eq 'Allow'
        }
        if (-not $WriteAces) {
            $Results.Add([PSCustomObject]@{
                Category   = $Category
                Target     = Split-Path $TargetPath -Leaf
                Identity   = 'None with write rights'
                Rights     = 'N/A'
                AccessType = 'N/A'
                Owner      = $Acl.Owner
                Finding    = 'OK - no write-capable ACEs found'
                Hostname   = $Hostname
                Collected  = Get-Date -Format 'o'
            })
        }
    } catch {
        $Results.Add([PSCustomObject]@{
            Category   = $Category
            Target     = Split-Path $TargetPath -Leaf
            Identity   = 'ERROR'
            Rights     = 'N/A'
            AccessType = 'N/A'
            Owner      = 'N/A'
            Finding    = "ACL query failed: $_"
            Hostname   = $Hostname
            Collected  = Get-Date -Format 'o'
        })
    }
}

# ── 1. EVTX LOG FILES ─────────────────────────────────────────────────────────
Write-Host "`n[EVTX] Checking ACLs on Event Log files..." -ForegroundColor Cyan
$LogPath = "$env:SystemRoot\System32\winevt\Logs"

Get-ChildItem -Path $LogPath -Filter *.evtx -ErrorAction SilentlyContinue |
    ForEach-Object { Test-AclForFindings -TargetPath $_.FullName -Category 'EventLogFile' }

Write-Host "  $((Get-ChildItem $LogPath -Filter *.evtx).Count) .evtx files checked." -ForegroundColor Green

# ── 2. AUDIT TOOLS ────────────────────────────────────────────────────────────
Write-Host "[TOOLS] Checking ACLs on audit tool executables..." -ForegroundColor Cyan
$AuditTools = @(
    "$env:SystemRoot\System32\auditpol.exe",   # Primary audit policy tool
    "$env:SystemRoot\System32\wevtutil.exe",   # Can clear logs -- highest risk
    "$env:SystemRoot\System32\eventvwr.exe"    # Event viewer
)

foreach ($Tool in $AuditTools) {
    Test-AclForFindings -TargetPath $Tool -Category 'AuditTool'
}

# ── 3. OUTPUT & SUMMARY ───────────────────────────────────────────────────────
$Results | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8

$Findings = $Results | Where-Object { $_.Finding -like 'REVIEW*' }
$Errors   = $Results | Where-Object { $_.Finding -like '*failed*' -or $_.Finding -eq 'PATH NOT FOUND' }

Write-Host "`n-- AU.3.3.8 SUMMARY ----------------------------------------" -ForegroundColor White
Write-Host "  Total ACEs evaluated : $($Results.Count)"
Write-Host "  Findings (REVIEW)    : $($Findings.Count)" -ForegroundColor $(if($Findings.Count){'Red'}else{'Green'})
Write-Host "  Errors               : $($Errors.Count)"   -ForegroundColor $(if($Errors.Count){'Yellow'}else{'Green'})

if ($Findings) {
    Write-Host "`n  Non-admin write access found:" -ForegroundColor Red
    $Findings | ForEach-Object {
        Write-Host "    [$($_.Category)] $($_.Target) -- $($_.Identity) -- $($_.Rights)" -ForegroundColor Red
    }
}

Write-Host "`n  Artifact: $OutFile"
Write-Host "------------------------------------------------------------`n" -ForegroundColor White