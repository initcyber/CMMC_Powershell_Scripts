#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CMMC Level 2 / NIST 800-171 r2 - CM.L2-3.4.7
    Restrict, disable, or prevent the use of nonessential programs, functions,
    ports, protocols, and services.

.DESCRIPTION
    Documents the running attack surface of the system across four areas:
      1. Running services         -- flagged against known-unnecessary list
      2. Listening ports (TCP+UDP)-- with owning process identified
      3. Enabled OS features      -- server and workstation OS aware
      4. Enabled scheduled tasks  -- non-Microsoft tasks flagged for review

    Output: four timestamped CSVs in .\output\
      CM_3_4_7_Services_*.csv
      CM_3_4_7_Ports_*.csv
      CM_3_4_7_Features_*.csv
      CM_3_4_7_Tasks_*.csv
#>

$Timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$Hostname   = $env:COMPUTERNAME
$OutDir     = Join-Path $PSScriptRoot 'output'
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

# Detect server vs workstation OS
$OSInfo    = Get-CimInstance Win32_OperatingSystem
$IsServer  = $OSInfo.ProductType -ne 1   # 1 = Workstation, 2 = DC, 3 = Server
Write-Host "`n[OS] $($OSInfo.Caption) detected -- $(if($IsServer){'Server'}else{'Workstation'}) mode" -ForegroundColor Cyan

# Services that are commonly unnecessary and worth flagging for review
# Not a definitive block list -- assessor should review flagged items in context
$UnnecessaryServices = @(
    'Fax',              # Fax service
    'TapiSrv',          # Telephony (if not needed)
    'RemoteRegistry',   # Remote registry access
    'SNMP',             # SNMP (unless monitored)
    'SNMPTrap',
    'XblAuthManager',   # Xbox services on enterprise endpoints
    'XblGameSave',
    'XboxNetApiSvc',
    'WMPNetworkSvc',    # Windows Media Player sharing
    'icssvc',           # Internet Connection Sharing
    'SharedAccess',
    'upnphost',         # UPnP host
    'SSDPSRV',          # SSDP Discovery (UPnP dependency)
    'lltdsvc',          # Link-Layer Topology Discovery
    'MapsBroker',       # Downloaded Maps Manager
    'RetailDemo',       # Retail demo service
    'DiagTrack',        # Connected User Experiences / telemetry
    'dmwappushservice'  # WAP push
)

# ── 1. RUNNING SERVICES ───────────────────────────────────────────────────────
Write-Host "[SERVICES] Enumerating running services..." -ForegroundColor Cyan

$ServiceResults = Get-Service |
    Where-Object { $_.Status -eq 'Running' } |
    Sort-Object DisplayName |
    ForEach-Object {
        $Flag = if ($UnnecessaryServices -contains $_.Name) { 'REVIEW: commonly unnecessary' } else { 'OK' }
        [PSCustomObject]@{
            Name        = $_.Name
            DisplayName = $_.DisplayName
            StartType   = $_.StartType
            Status      = $_.Status
            Finding     = $Flag
            Hostname    = $Hostname
            Collected   = Get-Date -Format 'o'
        }
    }

$ServiceCsv = Join-Path $OutDir "CM_3_4_7_Services_${Hostname}_${Timestamp}.csv"
$ServiceResults | Export-Csv -Path $ServiceCsv -NoTypeInformation -Encoding UTF8

$SvcFindings = $ServiceResults | Where-Object { $_.Finding -ne 'OK' }
Write-Host "  $($ServiceResults.Count) running services -- $($SvcFindings.Count) flagged for review" `
    -ForegroundColor $(if ($SvcFindings.Count) { 'Yellow' } else { 'Green' })

# ── 2. LISTENING PORTS (TCP + UDP) ────────────────────────────────────────────
Write-Host "[PORTS] Enumerating listening TCP and UDP ports..." -ForegroundColor Cyan

$PortResults = [System.Collections.Generic.List[PSCustomObject]]::new()

# TCP listeners
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Sort-Object LocalPort |
    ForEach-Object {
        $ProcName = try {
            (Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName
        } catch { "PID $($_.OwningProcess) (access denied)" }

        $PortResults.Add([PSCustomObject]@{
            Protocol    = 'TCP'
            LocalAddress = $_.LocalAddress
            LocalPort   = $_.LocalPort
            State       = $_.State
            PID         = $_.OwningProcess
            ProcessName = $ProcName
            Finding     = 'Review against approved port list'
            Hostname    = $Hostname
            Collected   = Get-Date -Format 'o'
        })
    }

# UDP listeners
Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
    Sort-Object LocalPort |
    ForEach-Object {
        $ProcName = try {
            (Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName
        } catch { "PID $($_.OwningProcess) (access denied)" }

        $PortResults.Add([PSCustomObject]@{
            Protocol     = 'UDP'
            LocalAddress = $_.LocalAddress
            LocalPort    = $_.LocalPort
            State        = 'Listen'
            PID          = $_.OwningProcess
            ProcessName  = $ProcName
            Finding      = 'Review against approved port list'
            Hostname     = $Hostname
            Collected    = Get-Date -Format 'o'
        })
    }

$PortCsv = Join-Path $OutDir "CM_3_4_7_Ports_${Hostname}_${Timestamp}.csv"
$PortResults | Export-Csv -Path $PortCsv -NoTypeInformation -Encoding UTF8
Write-Host "  $($PortResults.Count) listening endpoints (TCP + UDP)" -ForegroundColor Green

# ── 3. ENABLED OS FEATURES ────────────────────────────────────────────────────
Write-Host "[FEATURES] Enumerating enabled OS features..." -ForegroundColor Cyan

$FeatureResults = [System.Collections.Generic.List[PSCustomObject]]::new()

# Features worth flagging regardless of OS type
$UnnecessaryFeatures = @(
    'Telnet',
    'TFTP',
    'SMB1Protocol',
    'MicrosoftWindowsPowerShellV2',
    'MicrosoftWindowsPowerShellV2Root',
    'IIS-WebServer',            # if not an intentional web server
    'IIS-FTPServer',
    'SimpleTCP',                # includes echo, chargen, daytime -- legacy
    'MediaPlayback',
    'WindowsMediaPlayer'
)

if ($IsServer) {
    # Server OS -- use Get-WindowsFeature (requires ServerManager module)
    try {
        Import-Module ServerManager -ErrorAction Stop
        Get-WindowsFeature | Where-Object { $_.InstallState -eq 'Installed' } |
            ForEach-Object {
                $Flag = if ($UnnecessaryFeatures | Where-Object { $_.Name -match $_ }) {
                    'REVIEW: potentially unnecessary'
                } else { 'OK' }
                $FeatureResults.Add([PSCustomObject]@{
                    FeatureName = $_.Name
                    DisplayName = $_.DisplayName
                    State       = $_.InstallState
                    Finding     = $Flag
                    Hostname    = $Hostname
                    Collected   = Get-Date -Format 'o'
                })
            }
    } catch {
        Write-Warning "Get-WindowsFeature failed -- ServerManager module unavailable: $_"
    }
} else {
    # Workstation OS -- use Get-WindowsOptionalFeature
    Get-WindowsOptionalFeature -Online -ErrorAction SilentlyContinue |
        Where-Object { $_.State -eq 'Enabled' } |
        ForEach-Object {
            $FName = $_.FeatureName
            $Flag  = if ($UnnecessaryFeatures | Where-Object { $FName -match $_ }) {
                'REVIEW: potentially unnecessary'
            } else { 'OK' }
            $FeatureResults.Add([PSCustomObject]@{
                FeatureName = $FName
                DisplayName = $FName
                State       = $_.State
                Finding     = $Flag
                Hostname    = $Hostname
                Collected   = Get-Date -Format 'o'
            })
        }
}

$FeatureCsv = Join-Path $OutDir "CM_3_4_7_Features_${Hostname}_${Timestamp}.csv"
$FeatureResults | Export-Csv -Path $FeatureCsv -NoTypeInformation -Encoding UTF8

$FeatFindings = $FeatureResults | Where-Object { $_.Finding -ne 'OK' }
Write-Host "  $($FeatureResults.Count) enabled features -- $($FeatFindings.Count) flagged for review" `
    -ForegroundColor $(if ($FeatFindings.Count) { 'Yellow' } else { 'Green' })

# ── 4. SCHEDULED TASKS ────────────────────────────────────────────────────────
Write-Host "[TASKS] Enumerating non-system scheduled tasks..." -ForegroundColor Cyan

$TaskResults = Get-ScheduledTask |
    Where-Object {
        $_.State -ne 'Disabled' -and
        $_.TaskPath -notmatch '^\\Microsoft\\'
    } |
    ForEach-Object {
        $Action = ($_.Actions | ForEach-Object {
            if ($_.Execute) { "$($_.Execute) $($_.Arguments)".Trim() }
        }) -join ' | '

        [PSCustomObject]@{
            TaskName  = $_.TaskName
            TaskPath  = $_.TaskPath
            State     = $_.State
            Author    = $_.Author
            Action    = $Action
            Finding   = 'REVIEW: non-Microsoft task -- verify necessity'
            Hostname  = $Hostname
            Collected = Get-Date -Format 'o'
        }
    }

$TaskCsv = Join-Path $OutDir "CM_3_4_7_Tasks_${Hostname}_${Timestamp}.csv"
$TaskResults | Export-Csv -Path $TaskCsv -NoTypeInformation -Encoding UTF8
Write-Host "  $($TaskResults.Count) non-Microsoft scheduled tasks found" `
    -ForegroundColor $(if ($TaskResults.Count) { 'Yellow' } else { 'Green' })

# ── 5. SUMMARY ────────────────────────────────────────────────────────────────
Write-Host "`n-- CM.3.4.7 SUMMARY ----------------------------------------" -ForegroundColor White
Write-Host "  Running services      : $($ServiceResults.Count)  ($($SvcFindings.Count) flagged)"
Write-Host "  Listening endpoints   : $($PortResults.Count)  (all require review against approved list)"
Write-Host "  Enabled OS features   : $($FeatureResults.Count)  ($($FeatFindings.Count) flagged)"
Write-Host "  Non-system tasks      : $($TaskResults.Count)  (all flagged for review)"
Write-Host "`n  Artifacts:"
Write-Host "    $ServiceCsv"
Write-Host "    $PortCsv"
Write-Host "    $FeatureCsv"
Write-Host "    $TaskCsv"
Write-Host "------------------------------------------------------------`n" -ForegroundColor White