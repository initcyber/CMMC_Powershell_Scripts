# CMMC PowerShell Scripts - Configuration Management (CM)

A set of PowerShell scripts CMMC assessors can use to assess compliance for select Configuration Management (CM.L2-3.4) controls.

## Scripts

| Script | CMMC Control | Description |
|--------|--------------|-------------|
| CM_3_4_2 | CM.L2-3.4.2 | Exports applied GPO report (gpresult /X) and security configuration baseline (secedit). Lists installed Windows features and running services for baseline documentation. Outputs an XML GPO report, a .cfg security baseline, and CSVs for installed features and services. |
| CM_3_4_5 | CM.L2-3.4.5 | Enumerates running services, non-system scheduled tasks, and listening ports to document system functionality. Outputs a CSV with a system functionality inventory for least-functionality review. |
| CM_3_4_7 | CM.L2-3.4.7 | Documents running services against a list of known unnecessary services. Maps listening TCP/UDP ports to their associated processes. Enumerates enabled OS features (server and workstation aware) and lists non-Microsoft scheduled tasks. Outputs four CSVs (services, ports, features, tasks) with flags for items needing review. |

## Output

All scripts export timestamped CSV files to `.\output\` for use as audit evidence. Console output uses color-coded indicators: green (pass), yellow (review needed), red (fail).
