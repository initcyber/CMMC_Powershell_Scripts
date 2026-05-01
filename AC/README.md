# CMMC PowerShell Scripts - Access Control (AC)

A set of PowerShell scripts CMMC assessors can use to assess compliance for select Access Control (AC.L2-3.1) controls.

## Scripts

| Script | CMMC Control | Description |
|--------|--------------|-------------|
| AC_3_1_1.ps1 | AC.L2-3.1.1 | Enumerates local users, local groups (Administrators, Remote Desktop Users, Backup Operators), AD users, and Entra ID cloud users. Flags stale accounts with no logon activity in the past 90 days. Outputs a CSV with account status, enabled/disabled state, and last logon times. |
| AC_3_1_3.ps1 | AC.L2-3.1.3 | Checks all SMB shares and their permissions, including hidden/admin shares (C$, ADMIN$, IPC$). Verifies AutoShare registry settings and flags broad-access identities (Everyone, Authenticated Users, Domain Users). Outputs two CSVs — all shares and a findings report for overly permissive access. |
| AC_3_1_8.ps1 | AC.L2-3.1.8 | Exports local security policy lockout settings (threshold, duration), checks audit policy for failed logon auditing, and queries the Security event log for failed logon events (Event ID 4625) in the past 24 hours. Retrieves domain lockout policy if domain-joined. Outputs a CSV with policy settings and pass/fail status. |
| AC_3_1_10.ps1 | AC.L2-3.1.10 | Checks screen saver and session lock policy (timeout, password-on-resume) from both machine policy (HKLM) and user registry (HKCU). Verifies the DisableLockWorkstation policy. Outputs a CSV with screen saver configuration and compliance status. |
| AC_3_1_19.ps1 | AC.L2-3.1.19 | Enumerates BitLocker status on all volumes, including encryption percentage, protection status, and key protectors. Outputs a CSV with volume encryption details and protection status. |
| AC_3_1_21.ps1 | AC.L2-3.1.21 | Checks GPO and registry controls for USB disks and removable storage devices, including Deny_Write, Deny_Read, and Deny_All policies. Verifies AutoPlay is disabled. Outputs a CSV with removable storage policy status. |

## Output

All scripts export timestamped CSV files to `.\output\` for use as audit evidence. Console output uses color-coded indicators: green (pass), yellow (review needed), red (fail).
