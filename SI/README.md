# CMMC PowerShell Scripts - System and Information Integrity (SI)

A set of PowerShell scripts CMMC assessors can use to assess compliance for select System and Information Integrity (SI.L2-3.14) controls.

## Scripts

| Script | CMMC Control | Description |
|--------|--------------|-------------|
| SI_3_14_1.ps1 | SI.L2-3.14.1 | Lists the last 30 installed hotfixes with install dates and checks patch currency (days since last patch). Queries Windows Update for any pending updates if the PSWindowsUpdate module is available. Outputs a CSV with installed patch history and pending update status. |
| SI_3_14_2.ps1 | SI.L2-3.14.2 | Checks Windows Defender status including antivirus, antispyware, behavior monitor, and Network Inspection Service (NIS). Verifies real-time protection and scheduled scan configuration, and checks definition currency (age in days). Outputs a CSV with Defender protection status and definition age. |

## Output

All scripts export timestamped CSV files to `.\output\` for use as audit evidence. Console output uses color-coded indicators: green (pass), yellow (review needed), red (fail).
