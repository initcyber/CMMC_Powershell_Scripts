# CMMC PowerShell Scripts - Audit and Accountability (AU)

A set of PowerShell scripts CMMC assessors can use to assess compliance for select Audit and Accountability (AU.L2-3.3) controls.

## Scripts

| Script | CMMC Control | Description |
|--------|--------------|-------------|
| AU_3_3_1 | AU.L2-3.3.1 | Documents all enabled Windows Event Logs including mode, max size, and record count. Lists all audit subcategories and their configured settings. Flags circular logs and undersized logs. Outputs CSVs for log configuration and audit policy. |
| AU_3_3_2 | AU.L2-3.3.2 | Queries the Security event log for critical security events (Event IDs 4624, 4625, 4634, 4648, 4720, 4726, 4728, 4732, 4756). Extracts user, source, and message information. Outputs a CSV with sampled security events. |
| AU_3_3_7.ps1 | AU.L2-3.3.7 | Queries the w32tm service for time source and NTP configuration. Checks W32Time service status and verifies NTP synchronization with authoritative time servers. Outputs a CSV with time sync status and NTP configuration. |
| AU_3_3_8 | AU.L2-3.3.8 | Checks ACLs on .evtx log files and audit tools. Flags non-admin identities with write or modify rights. Verifies ownership by SYSTEM, Administrators, or the EventLog service. Outputs a CSV with ACL findings. |

## Output

All scripts export timestamped CSV files to `.\output\` for use as audit evidence. Console output uses color-coded indicators: green (pass), yellow (review needed), red (fail).
