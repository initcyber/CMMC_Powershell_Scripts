#Requires -Version 5.1
<#
.SYNOPSIS
    CMMC Level 2 / NIST 800-171 r2 - SI.3.14.1
    Identify, report, and correct information and information system flaws in a timely manner.
    (Patch management / Windows Update status)
#>
$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$Hostname  = $env:COMPUTERNAME
$OutDir    = "$PSScriptRoot\output"
$OutFile   = "$OutDir\SI_3_14_1_${Hostname}_${Timestamp}.csv"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$Results = [System.Collections.Generic.List[PSCustomObject]]::new()
function Add-Result { param($Category,$Item,$Value,$Pass,$Notes)
    $Results.Add([PSCustomObject]@{Category=$Category;Item=$Item;Value=$Value;Pass=$Pass;Notes=$Notes
    Hostname=$Hostname;Collected=(Get-Date -Format 'o')}) }

# Installed hotfixes
Write-Host "`n[HOTFIX] Last 30 installed updates..." -ForegroundColor Cyan
$HotFixes = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 30
$HotFixes | ForEach-Object { Add-Result 'InstalledHotfix' $_.HotFixID $_.InstalledOn 'N/A' $_.Description }

$Latest = $HotFixes | Select-Object -First 1
$DaysSince = if ($Latest.InstalledOn) { (New-TimeSpan -Start $Latest.InstalledOn).Days } else { 9999 }
Add-Result 'PatchCurrency' 'DaysSinceLastPatch' $DaysSince ($DaysSince -le 30) "Latest KB: $($Latest.HotFixID)"

# PSWindowsUpdate (if available)
Write-Host "[WINDOWS UPDATE] Checking for pending updates (requires PSWindowsUpdate module)..." -ForegroundColor Cyan
if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
    Import-Module PSWindowsUpdate
    try {
        $Pending = Get-WindowsUpdate -MicrosoftUpdate -ErrorAction Stop
        $Pending | ForEach-Object { Add-Result 'PendingUpdate' $_.KBArticleID $_.Title ($false) 'PENDING — not yet installed' }
        if (-not $Pending) { Add-Result 'PendingUpdate' 'Status' 'No pending updates' $true '' }
    } catch { Write-Warning "Get-WindowsUpdate failed: $_" }
} else {
    Add-Result 'PendingUpdate' 'PSWindowsUpdate' 'Module not installed' 'N/A' 'Install: Install-Module PSWindowsUpdate -Force'
}

$Results | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
Write-Host "[DONE] $($Results.Count) records -> $OutFile" -ForegroundColor Green
$Fails = $Results | Where-Object { $_.Pass -eq $false -and $_.Category -ne 'InstalledHotfix' }
if ($Fails) { $Fails | ForEach-Object { Write-Host "FAIL: $($_.Category) / $($_.Item) = $($_.Value)" -ForegroundColor Red } }
