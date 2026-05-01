#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CMMC Level 2 / NIST 800-171 r2 - IA.L2-3.5.7 and 3.5.8
    Enforce a minimum password complexity and change requirements when
    passwords are used.

.DESCRIPTION
    Three-tier password policy check:
      1. Local security policy (secedit) -- all systems
      2. Domain default password policy  -- domain-joined systems
      3. Fine-grained password policies  -- with AppliesTo groups

    Pass/fail evaluated against these thresholds (common assessor expectations):
      MinPasswordLength    >= 12
      ComplexityEnabled    = True
      MaxPasswordAge       <= 60 days  (and > 0)
      MinPasswordAge       >= 1 day
      PasswordHistoryCount >= 10       (3.5.8)
      ReversibleEncryption = Disabled

    Output: two timestamped CSVs in .\output\
      IA_3_5_7_Policy_*.csv    -- all policy settings with pass/fail
      IA_3_5_7_FGPP_*.csv     -- fine-grained policies (if present)
#>

$Timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$Hostname   = $env:COMPUTERNAME
$OutDir     = Join-Path $PSScriptRoot 'output'
$PolicyCsv  = Join-Path $OutDir "IA_3_5_7_Policy_${Hostname}_${Timestamp}.csv"
$FgppCsv    = Join-Path $OutDir "IA_3_5_7_FGPP_${Hostname}_${Timestamp}.csv"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$PolicyResults = [System.Collections.Generic.List[PSCustomObject]]::new()
$FgppResults   = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Policy {
    param($Source, $Setting, $Value, $Expected, [bool]$Pass, $Notes)
    $PolicyResults.Add([PSCustomObject]@{
        Source   = $Source
        Setting  = $Setting
        Value    = $Value
        Expected = $Expected
        Pass     = $Pass
        Notes    = $Notes
        Hostname = $Hostname
        Collected = Get-Date -Format 'o'
    })
}

# ── 1. LOCAL POLICY (secedit) ─────────────────────────────────────────────────
Write-Host "`n[LOCAL] Exporting local security policy via secedit..." -ForegroundColor Cyan

$SecCfg = Join-Path $env:TEMP "secpol_${Timestamp}.cfg"
secedit /export /cfg $SecCfg /quiet 2>&1 | Out-Null

if (Test-Path $SecCfg) {
    $Content = Get-Content $SecCfg

    # Helper to pull a value from the exported .cfg
    function Get-SecValue { param($Key)
        $Line = $Content | Select-String "^\s*$Key\s*=" | Select-Object -First 1
        if ($Line) { ($Line -replace ".*=\s*",'').Trim() } else { $null }
    }

    $MinLen  = Get-SecValue 'MinimumPasswordLength'
    $MaxAge  = Get-SecValue 'MaximumPasswordAge'
    $MinAge  = Get-SecValue 'MinimumPasswordAge'
    $History = Get-SecValue 'PasswordHistorySize'
    $Complex = Get-SecValue 'PasswordComplexity'
    $RevEnc  = Get-SecValue 'ClearTextPassword'

    Add-Policy 'LocalPolicy' 'MinimumPasswordLength'  $MinLen  '>= 12'  ([int]$MinLen -ge 12)                                          ''
    Add-Policy 'LocalPolicy' 'PasswordComplexity'     $Complex '1'      ($Complex -eq '1')                                             '1 = enabled'
    Add-Policy 'LocalPolicy' 'MaximumPasswordAge'     $MaxAge  '<= 60'  ([int]$MaxAge -le 60 -and [int]$MaxAge -gt 0)                  'Days; 0 = never expires (finding)'
    Add-Policy 'LocalPolicy' 'MinimumPasswordAge'     $MinAge  '>= 1'   ([int]$MinAge -ge 1)                                           'Prevents immediate re-use bypass'
    Add-Policy 'LocalPolicy' 'PasswordHistorySize'    $History '>= 10'  ([int]$History -ge 10)                                         'Covered by 3.5.8'
    Add-Policy 'LocalPolicy' 'ClearTextPassword'      $RevEnc  '0'      ($RevEnc -eq '0')                                             'Reversible encryption -- must be disabled'

    Remove-Item $SecCfg -Force -ErrorAction SilentlyContinue
    Write-Host "  Local policy exported and parsed." -ForegroundColor Green
} else {
    Write-Warning "secedit export failed -- verify elevation."
}

# ── 2. DOMAIN POLICY ──────────────────────────────────────────────────────────
$IsDomain = (Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain

if ($IsDomain) {
    Write-Host "[DOMAIN] Checking default domain password policy..." -ForegroundColor Cyan

    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        try {
            $DP = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop

            Add-Policy 'DomainPolicy' 'MinPasswordLength'        $DP.MinPasswordLength        '>= 12'  ($DP.MinPasswordLength -ge 12)                                          ''
            Add-Policy 'DomainPolicy' 'ComplexityEnabled'        $DP.ComplexityEnabled        'True'   ($DP.ComplexityEnabled)                                                 ''
            Add-Policy 'DomainPolicy' 'MaxPasswordAge (days)'    $DP.MaxPasswordAge.TotalDays '<= 60'  ($DP.MaxPasswordAge.TotalDays -le 60 -and $DP.MaxPasswordAge.TotalDays -gt 0) ''
            Add-Policy 'DomainPolicy' 'MinPasswordAge (days)'    $DP.MinPasswordAge.TotalDays '>= 1'   ($DP.MinPasswordAge.TotalDays -ge 1)                                    ''
            Add-Policy 'DomainPolicy' 'PasswordHistoryCount'     $DP.PasswordHistoryCount     '>= 10'  ($DP.PasswordHistoryCount -ge 10)                                       '3.5.8'
            Add-Policy 'DomainPolicy' 'ReversibleEncryption'     $DP.ReversibleEncryptionEnabled 'False' (-not $DP.ReversibleEncryptionEnabled)                               'Must be False'

            Write-Host "  Domain policy retrieved." -ForegroundColor Green
        } catch {
            Write-Warning "Get-ADDefaultDomainPasswordPolicy failed: $_"
        }

        # ── 3. FINE-GRAINED PASSWORD POLICIES ─────────────────────────────────
        Write-Host "[FGPP] Checking fine-grained password policies..." -ForegroundColor Cyan
        try {
            $FGPPs = Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction Stop

            if ($FGPPs) {
                foreach ($FGPP in $FGPPs) {
                    # Resolve AppliesTo DNs to readable names
                    $AppliesToNames = ($FGPP.AppliesTo | ForEach-Object {
                        try { (Get-ADObject $_ -ErrorAction Stop).Name } catch { $_ }
                    }) -join '; '

                    $FgppResults.Add([PSCustomObject]@{
                        Name                     = $FGPP.Name
                        Precedence               = $FGPP.Precedence
                        AppliesTo                = $AppliesToNames
                        MinPasswordLength        = $FGPP.MinPasswordLength
                        ComplexityEnabled        = $FGPP.ComplexityEnabled
                        MaxPasswordAge           = $FGPP.MaxPasswordAge.TotalDays
                        MinPasswordAge           = $FGPP.MinPasswordAge.TotalDays
                        PasswordHistoryCount     = $FGPP.PasswordHistoryCount
                        ReversibleEncryption     = $FGPP.ReversibleEncryptionEnabled
                        LockoutThreshold         = $FGPP.LockoutThreshold
                        LockoutDuration          = $FGPP.LockoutDuration.TotalMinutes
                        LockoutObservationWindow = $FGPP.LockoutObservationWindow.TotalMinutes
                        MinLenPass               = $FGPP.MinPasswordLength -ge 12
                        ComplexPass              = $FGPP.ComplexityEnabled
                        MaxAgePass               = $FGPP.MaxPasswordAge.TotalDays -le 60 -and $FGPP.MaxPasswordAge.TotalDays -gt 0
                        HistoryPass              = $FGPP.PasswordHistoryCount -ge 10
                        RevEncPass               = -not $FGPP.ReversibleEncryptionEnabled
                        Hostname                 = $Hostname
                        Collected                = Get-Date -Format 'o'
                    })
                }
                Write-Host "  $($FGPPs.Count) fine-grained policy/policies found." -ForegroundColor Green
            } else {
                Write-Host "  No fine-grained password policies configured." -ForegroundColor DarkGray
            }
        } catch {
            Write-Warning "FGPP query failed (may need Domain Admin or insufficient rights): $_"
        }
    } else {
        Write-Host "  ActiveDirectory module not available -- install RSAT." -ForegroundColor Yellow
    }
} else {
    Write-Host "[DOMAIN] System is not domain-joined -- skipping AD checks." -ForegroundColor DarkGray
}

# ── 4. OUTPUT & SUMMARY ───────────────────────────────────────────────────────
$PolicyResults | Export-Csv -Path $PolicyCsv -NoTypeInformation -Encoding UTF8
$FgppResults   | Export-Csv -Path $FgppCsv   -NoTypeInformation -Encoding UTF8

$Fails = $PolicyResults | Where-Object { $_.Pass -eq $false }

Write-Host "`n-- IA.3.5.7 SUMMARY ----------------------------------------" -ForegroundColor White
Write-Host "  Policy settings evaluated : $($PolicyResults.Count)"
Write-Host "  FAIL                      : $($Fails.Count)" `
    -ForegroundColor $(if ($Fails.Count) { 'Red' } else { 'Green' })
Write-Host "  FGPP policies documented  : $($FgppResults.Count)"

if ($Fails) {
    Write-Host "`n  Failing settings:" -ForegroundColor Red
    $Fails | ForEach-Object {
        Write-Host "    [$($_.Source)] $($_.Setting) = $($_.Value)  (expected $($_.Expected))" -ForegroundColor Red
    }
}

Write-Host "`n  Artifacts:"
Write-Host "    $PolicyCsv"
if ($FgppResults.Count) { Write-Host "    $FgppCsv" }
Write-Host "------------------------------------------------------------`n" -ForegroundColor White