#Requires -Version 5.1
<#
.SYNOPSIS
    CMMC Level 2 / NIST 800-171 r2 - CM.3.4.5 / CM.3.4.6
    Employ the principle of least functionality — configure the system to
    provide only essential capabilities.
#>
$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$Hostname  = $env:COMPUTERNAME
$OutDir    = "$PSScriptRoot\output"
$OutFile   = "$OutDir\CM_3_4_5_${Hostname}_${Timestamp}.csv"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$Results = [System.Collections.Generic.List[PSCustomObject]]::new()
function Add-Result { param($Category,$Item,$Value,$Notes)
    $Results.Add([PSCustomObject]@{Category=$Category;Item=$Item;Value=$Value;Notes=$Notes
    Hostname=$Hostname;Collected=(Get-Date -Format 'o')}) }

# Running services
Write-Host "`n[SERVICES] Enumerating running services..." -ForegroundColor Cyan
Get-Service | Where-Object Status -eq Running | ForEach-Object {
    Add-Result 'RunningService' $_.Name $_.DisplayName $_.StartType
}

# Scheduled tasks (non-Microsoft)
Write-Host "[TASKS] Enumerating non-system scheduled tasks..." -ForegroundColor Cyan
Get-ScheduledTask | Where-Object {
    $_.TaskPath -notmatch '\\Microsoft\\' -and $_.State -ne 'Disabled'
} | ForEach-Object {
    Add-Result 'ScheduledTask' $_.TaskName $_.TaskPath $_.State
}

# Listening ports
Write-Host "[PORTS] Enumerating listening ports..." -ForegroundColor Cyan
Get-NetTCPConnection -State Listen | ForEach-Object {
    $Proc = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
    Add-Result 'ListeningPort' "Port $($_.LocalPort)" "PID $($_.OwningProcess)" $Proc
}

$Results | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
Write-Host "[DONE] $($Results.Count) records -> $OutFile" -ForegroundColor Green
