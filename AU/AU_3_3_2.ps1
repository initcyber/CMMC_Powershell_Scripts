#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CMMC Level 2 / NIST 800-171 r2 - AU.L2-3.3.2
    Ensure that the actions of individual users can be uniquely traced to
    those users so they can be held accountable for their actions.

.DESCRIPTION
    Samples recent Security log events across key audit subcategories and
    evaluates whether individual user actions are uniquely traceable.

    Event IDs covered:
      4624  -- Successful logon
      4625  -- Failed logon
      4634  -- Logoff
      4647  -- User-initiated logoff
      4648  -- Logon with explicit credentials (runas)
      4720  -- User account created
      4722  -- User account enabled
      4725  -- User account disabled
      4726  -- User account deleted
      4728  -- Member added to security-enabled global group
      4732  -- Member added to security-enabled local group
      4756  -- Member added to security-enabled universal group
      4768  -- Kerberos TGT requested
      4769  -- Kerberos service ticket requested
      4776  -- NTLM credential validation

    Traceability flags:
      - Events where Subject/Target username is empty, SYSTEM, or anonymous
      - Network logons (Type 3) and service logons (Type 5) -- mask user identity
      - Events with no workstation or source IP

    Output: two timestamped CSVs in .\output\
      AU_3_3_2_Events_*.csv     -- sampled events with parsed fields
      AU_3_3_2_Gaps_*.csv       -- traceability gap findings only

.PARAMETER HoursBack
    How many hours of Security log history to sample. Default: 24.

.PARAMETER MaxEvents
    Maximum events to pull per event ID. Default: 50.
#>

param(
    [int]$HoursBack  = 24,
    [int]$MaxEvents  = 50
)

$Timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$Hostname   = $env:COMPUTERNAME
$OutDir     = Join-Path $PSScriptRoot 'output'
$EventCsv   = Join-Path $OutDir "AU_3_3_2_Events_${Hostname}_${Timestamp}.csv"
$GapCsv     = Join-Path $OutDir "AU_3_3_2_Gaps_${Hostname}_${Timestamp}.csv"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$StartTime = (Get-Date).AddHours(-$HoursBack)

$EventResults = [System.Collections.Generic.List[PSCustomObject]]::new()
$GapResults   = [System.Collections.Generic.List[PSCustomObject]]::new()

# Logon type descriptions -- Type 3 and 5 mask individual identity
$LogonTypes = @{
    2  = 'Interactive'
    3  = 'Network'          # REVIEW -- may mask individual user
    4  = 'Batch'
    5  = 'Service'          # REVIEW -- runs as service account
    7  = 'Unlock'
    8  = 'NetworkCleartext'
    9  = 'NewCredentials'
    10 = 'RemoteInteractive'
    11 = 'CachedInteractive'
}

# Per-event property maps -- index positions vary by event ID
# Format: EventID = @{ FieldName = PropertyIndex }
$PropertyMap = @{
    4624 = @{ SubjectUser=1;  SubjectDomain=2;  TargetUser=5;  TargetDomain=6;  LogonType=8;  WorkstationName=11; IPAddress=18 }
    4625 = @{ SubjectUser=1;  SubjectDomain=2;  TargetUser=5;  TargetDomain=6;  LogonType=10; WorkstationName=13; IPAddress=19 }
    4634 = @{ SubjectUser=1;  SubjectDomain=2;  TargetUser=$null; TargetDomain=$null; LogonType=4; WorkstationName=$null; IPAddress=$null }
    4647 = @{ SubjectUser=1;  SubjectDomain=2;  TargetUser=$null; TargetDomain=$null; LogonType=$null; WorkstationName=$null; IPAddress=$null }
    4648 = @{ SubjectUser=1;  SubjectDomain=2;  TargetUser=5;  TargetDomain=6;  LogonType=$null; WorkstationName=12; IPAddress=13 }
    4720 = @{ SubjectUser=4;  SubjectDomain=5;  TargetUser=0;  TargetDomain=1;  LogonType=$null; WorkstationName=$null; IPAddress=$null }
    4722 = @{ SubjectUser=4;  SubjectDomain=5;  TargetUser=0;  TargetDomain=1;  LogonType=$null; WorkstationName=$null; IPAddress=$null }
    4725 = @{ SubjectUser=4;  SubjectDomain=5;  TargetUser=0;  TargetDomain=1;  LogonType=$null; WorkstationName=$null; IPAddress=$null }
    4726 = @{ SubjectUser=4;  SubjectDomain=5;  TargetUser=0;  TargetDomain=1;  LogonType=$null; WorkstationName=$null; IPAddress=$null }
    4728 = @{ SubjectUser=4;  SubjectDomain=5;  TargetUser=0;  TargetDomain=1;  LogonType=$null; WorkstationName=$null; IPAddress=$null }
    4732 = @{ SubjectUser=4;  SubjectDomain=5;  TargetUser=0;  TargetDomain=1;  LogonType=$null; WorkstationName=$null; IPAddress=$null }
    4756 = @{ SubjectUser=4;  SubjectDomain=5;  TargetUser=0;  TargetDomain=1;  LogonType=$null; WorkstationName=$null; IPAddress=$null }
    4768 = @{ SubjectUser=$null; SubjectDomain=$null; TargetUser=0; TargetDomain=1; LogonType=$null; WorkstationName=$null; IPAddress=9 }
    4769 = @{ SubjectUser=$null; SubjectDomain=$null; TargetUser=0; TargetDomain=1; LogonType=$null; WorkstationName=$null; IPAddress=9 }
    4776 = @{ SubjectUser=$null; SubjectDomain=$null; TargetUser=1; TargetDomain=$null; LogonType=$null; WorkstationName=2; IPAddress=$null }
}

function Get-PropSafe {
    param($Event, $Index)
    if ($null -eq $Index) { return '' }
    try { $Event.Properties[$Index].Value } catch { '' }
}

# ── EVENT COLLECTION ──────────────────────────────────────────────────────────
$EventIDs = $PropertyMap.Keys
Write-Host "`n[EVENTS] Sampling Security log -- last ${HoursBack}h, up to $MaxEvents per event ID..." -ForegroundColor Cyan
Write-Host "  Event IDs: $($EventIDs -join ', ')" -ForegroundColor DarkGray

foreach ($ID in $EventIDs) {
    Write-Host "  Querying event $ID..." -ForegroundColor DarkGray -NoNewline
    try {
        $Raw = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = $ID
            StartTime = $StartTime
        } -MaxEvents $MaxEvents -ErrorAction Stop

        $Map = $PropertyMap[$ID]

        foreach ($Evt in $Raw) {
            $SubjectUser     = Get-PropSafe $Evt $Map.SubjectUser
            $SubjectDomain   = Get-PropSafe $Evt $Map.SubjectDomain
            $TargetUser      = Get-PropSafe $Evt $Map.TargetUser
            $TargetDomain    = Get-PropSafe $Evt $Map.TargetDomain
            $LogonTypeRaw    = Get-PropSafe $Evt $Map.LogonType
            $WorkstationName = Get-PropSafe $Evt $Map.WorkstationName
            $IPAddress       = Get-PropSafe $Evt $Map.IPAddress

            $LogonTypeDesc = if ($LogonTypeRaw -and $LogonTypes.ContainsKey([int]$LogonTypeRaw)) {
                "$LogonTypeRaw - $($LogonTypes[[int]$LogonTypeRaw])"
            } elseif ($LogonTypeRaw) { $LogonTypeRaw } else { '' }

            # Determine primary actor for traceability evaluation
            $Actor = if ($TargetUser -and $TargetUser -notmatch '^\$|^-$|^$') {
                "$TargetDomain\$TargetUser".Trim('\')
            } elseif ($SubjectUser -and $SubjectUser -notmatch '^\$|^-$|^$') {
                "$SubjectDomain\$SubjectUser".Trim('\')
            } else { '' }

            # Traceability gap flags
            $Gaps = [System.Collections.Generic.List[string]]::new()

            if ([string]::IsNullOrWhiteSpace($Actor) -or $Actor -match '^\\?-$') {
                $Gaps.Add('No identifiable user')
            }
            if ($Actor -match 'ANONYMOUS LOGON') {
                $Gaps.Add('Anonymous logon -- untraceable')
            }
            if ($LogonTypeRaw -eq 3) {
                $Gaps.Add('Network logon (Type 3) -- verify user identity in context')
            }
            if ($LogonTypeRaw -eq 5) {
                $Gaps.Add('Service logon (Type 5) -- service account, not individual user')
            }
            if ($ID -in @(4624,4625) -and [string]::IsNullOrWhiteSpace($IPAddress)) {
                $Gaps.Add('No source IP recorded')
            }

            $GapString  = if ($Gaps.Count) { $Gaps -join ' | ' } else { '' }
            $Traceable  = $Gaps.Count -eq 0

            $Row = [PSCustomObject]@{
                EventID          = $ID
                TimeCreated      = $Evt.TimeCreated
                Actor            = $Actor
                SubjectUser      = "$SubjectDomain\$SubjectUser".Trim('\')
                TargetUser       = "$TargetDomain\$TargetUser".Trim('\')
                LogonType        = $LogonTypeDesc
                WorkstationName  = $WorkstationName
                IPAddress        = $IPAddress
                Traceable        = $Traceable
                GapFlags         = $GapString
                Hostname         = $Hostname
                Collected        = Get-Date -Format 'o'
            }

            $EventResults.Add($Row)
            if (-not $Traceable) { $GapResults.Add($Row) }
        }

        Write-Host " $($Raw.Count) events" -ForegroundColor DarkGray
    } catch [System.Exception] {
        if ($_.Exception.Message -match 'No events were found') {
            Write-Host " 0 events in window" -ForegroundColor DarkGray
        } else {
            Write-Host " ERROR: $_" -ForegroundColor Yellow
        }
    }
}

# ── OUTPUT & SUMMARY ──────────────────────────────────────────────────────────
$EventResults | Sort-Object TimeCreated -Descending |
    Export-Csv -Path $EventCsv -NoTypeInformation -Encoding UTF8

$GapResults | Sort-Object TimeCreated -Descending |
    Export-Csv -Path $GapCsv -NoTypeInformation -Encoding UTF8

$TraceableCount    = ($EventResults | Where-Object { $_.Traceable }).Count
$NonTraceableCount = $GapResults.Count

Write-Host "`n-- AU.3.3.2 SUMMARY ----------------------------------------" -ForegroundColor White
Write-Host "  Sample window          : Last ${HoursBack} hours"
Write-Host "  Total events sampled   : $($EventResults.Count)"
Write-Host "  Traceable              : $TraceableCount" -ForegroundColor Green
Write-Host "  Traceability gaps      : $NonTraceableCount" `
    -ForegroundColor $(if ($NonTraceableCount) { 'Yellow' } else { 'Green' })

if ($GapResults.Count) {
    Write-Host "`n  Gap categories found:" -ForegroundColor Yellow
    $GapResults | ForEach-Object { $_.GapFlags } |
        ForEach-Object { $_ -split ' \| ' } |
        Group-Object | Sort-Object Count -Descending |
        ForEach-Object { Write-Host "    $($_.Count)x  $($_.Name)" -ForegroundColor Yellow }
}

Write-Host "`n  Artifacts:"
Write-Host "    $EventCsv"
if ($GapResults.Count) { Write-Host "    $GapCsv" }
Write-Host "------------------------------------------------------------`n" -ForegroundColor White