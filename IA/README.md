# CMMC PowerShell Scripts - Identification and Authentication (IA)

A set of PowerShell scripts CMMC assessors can use to assess compliance for select Identification and Authentication (IA.L2-3.5) controls.

## Scripts

| Script | CMMC Control | Description |
|--------|--------------|-------------|
| IA_3_5_7-IA_3_5_8 | IA.L2-3.5.7 / IA.L2-3.5.8 | Exports local security policy for password settings (minimum length >= 12, complexity enabled, etc.) and queries the domain default password policy. Enumerates fine-grained password policies (FGPP) and the groups they apply to. Outputs two CSVs (policy settings and FGPP details) with pass/fail evaluation. |
| IA_3_5_10 | IA.L2-3.5.10 | Checks that LM hash storage is disabled (NoLMHash = 1) and NTLMv2 minimum is enforced (LmCompatibilityLevel >= 3). Verifies Credential Guard via VBS settings, checks that WDigest plaintext credential caching is disabled, and confirms reversible encryption is not in use. Outputs a CSV with password protection settings and compliance status. |

## Output

All scripts export timestamped CSV files to `.\output\` for use as audit evidence. Console output uses color-coded indicators: green (pass), yellow (review needed), red (fail).
