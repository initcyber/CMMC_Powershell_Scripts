# CMMC PowerShell Scripts - Media Protection (MP)

A set of PowerShell scripts CMMC assessors can use to assess compliance for select Media Protection (MP.L2-3.8) controls.

## Scripts

| Script | CMMC Control | Description |
|--------|--------------|-------------|
| MP_3_8_7.ps1 | MP.L2-3.8.7 | Checks removable storage device policies for USB disks and WPD/MTP devices. Queries USB device connection history from the registry and reviews USB insertion events from driver framework logs (past 7 days). Outputs a CSV with policy status and USB connection history. |

## Output

All scripts export timestamped CSV files to `.\output\` for use as audit evidence. Console output uses color-coded indicators: green (pass), yellow (review needed), red (fail).
