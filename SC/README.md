# CMMC PowerShell Scripts - System and Communications Protection (SC)

A set of PowerShell scripts CMMC assessors can use to assess compliance for select System and Communications Protection (SC.L2-3.13) controls.

## Scripts

| Script | CMMC Control | Description |
|--------|--------------|-------------|
| SC_3_13_1.ps1 | SC.L2-3.13.1 | Checks Windows Firewall profile status (enabled state, default actions) and logging configuration. Enumerates active firewall rules and lists all services listening on open ports. Outputs a CSV with firewall configuration and listening port inventory. |
| SC_3_13_6.ps1 | SC.L2-3.13.6 | Verifies that all Windows Firewall profiles block inbound connections by default (DefaultInboundAction = Block). Outputs a CSV with the default inbound action status per profile. |
| SC_3_13_11.ps1 | SC.L2-3.13.11 | Checks whether the FIPS algorithm policy is enabled via registry. Reviews TLS cipher suites and flags non-FIPS algorithms (RC4, DES, MD5, etc.). Checks that legacy protocols (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1) are disabled. Outputs a CSV with FIPS and TLS compliance status. |
| SC_3_13_16.ps1 | SC.L2-3.13.16 | Enumerates BitLocker status on all volumes, verifying that encryption protection is enabled. Lists key protectors and encryption methods in use. Outputs a CSV with BitLocker encryption status per volume. |

## Output

All scripts export timestamped CSV files to `.\output\` for use as audit evidence. Console output uses color-coded indicators: green (pass), yellow (review needed), red (fail).
