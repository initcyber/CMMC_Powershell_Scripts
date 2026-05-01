# CMMC PowerShell Scripts - Risk Assessment (RA)

A set of PowerShell scripts CMMC assessors can use to assess compliance for select Risk Assessment (RA.L2-3.11) controls.

## Scripts

| Script | CMMC Control | Description |
|--------|--------------|-------------|
| RA_3_11_1 | RA.L2-3.11.1 | Collects a system information baseline (OS, CPU, RAM, domain membership, uptime). Enumerates installed software from 64-bit, 32-bit, and user-hive registry paths. Documents patch inventory and currency, queries Windows Update history (last 50 updates), and checks Windows Defender AV definition currency. Outputs five CSVs (system info, installed software, patch list, Windows Update history, and Defender status). |

## Output

All scripts export timestamped CSV files to `.\output\` for use as audit evidence. Console output uses color-coded indicators: green (pass), yellow (review needed), red (fail).
