# CMMC Level 2 / NIST 800-171 PowerShell Evidence Collection

A collection of PowerShell scripts for technically validating and collecting evidence against NIST SP 800-171 Rev 2 controls required for CMMC Level 2 certification. Each script targets a specific control, outputs timestamped CSV artifacts, and includes pass/fail logic where technically deterministic.

> **Use at your own risk.** These scripts are provided as-is for informational and evidence-collection purposes. They are not a substitute for a formal CMMC assessment, C3PAO review, or credentialed vulnerability scan. Results should be reviewed by a qualified assessor in context. See [Disclaimer](#disclaimer) below.

---

## Requirements

| Requirement | Detail |
|---|---|
| PowerShell | 5.1 minimum; 7.x recommended |
| Execution | Most scripts require **Run as Administrator** |
| AD scripts | Require RSAT / ActiveDirectory module (`Install-Module RSAT`) |
| Entra ID scripts | Require Microsoft.Graph module (`Install-Module Microsoft.Graph`) |
| OS | Windows 10/11, Windows Server 2016+ |

---

## Repository Structure

```
├── AC/          Access Control
├── AU/          Audit & Accountability
├── CM/          Configuration Management
├── IA/          Identification & Authentication
├── MP/          Media Protection
├── RA/          Risk Assessment
├── SC/          System & Communications Protection
├── SI/          System & Information Integrity
└── README.md
```

Each script drops a timestamped CSV artifact into an `output\` subdirectory relative to where the script is run. Filenames follow the pattern:

```
{CONTROL}_{HOSTNAME}_{YYYYMMDD_HHMMSS}.csv
```

---

## Script Inventory

### AC — Access Control

| Script | Control | Description | Coverage |
|---|---|---|---|
| `AC_3_1_1.ps1` | AC.L2-3.1.1 | Enumerate authorized users — local, AD, and Entra ID | ✅ Full |
| `AC_3_1_3.ps1` | AC.L2-3.1.3 | SMB share permissions + NTFS ACLs, broad-access flagging | 🔶 Partial |
| `AC_3_1_8.ps1` | AC.L2-3.1.8 | Account lockout policy — local and domain | ✅ Full |
| `AC_3_1_10.ps1` | AC.L2-3.1.10 | Screen saver / session lock timeout and password-on-resume | ✅ Full |
| `AC_3_1_19.ps1` | AC.L2-3.1.19 | BitLocker encryption status on all volumes | ✅ Full |
| `AC_3_1_21.ps1` | AC.L2-3.1.21 | Removable storage device policy (registry GPO keys) | ✅ Full |

> **AC.L2-3.1.3 note:** Technical evidence of share permissions supports CUI flow control review but policy and data classification decisions require manual assessor review.

---

### AU — Audit & Accountability

| Script | Control | Description | Coverage |
|---|---|---|---|
| `AU_3_3_1.ps1` | AU.L2-3.3.1 | Event log configuration (size, mode, retention) + full auditpol subcategory dump | ✅ Full |
| `AU_3_3_2.ps1` | AU.L2-3.3.2 | Security event sampling with per-event property parsing; traceability gap flagging | 🔶 Partial |
| `AU_3_3_7.ps1` | AU.L2-3.3.7 | W32Time service status, NTP source, sync health | ✅ Full |
| `AU_3_3_8.ps1` | AU.L2-3.3.8 | ACLs on .evtx log files and audit tools (auditpol, wevtutil, eventvwr) | 🔶 Partial |

> **AU.L2-3.3.2 note:** Traceability gaps (anonymous logons, missing source IPs, service account logons) are flagged automatically. Assessor judgment is required to determine whether gaps represent findings in context.
>
> **AU.L2-3.3.8 note:** ACL checks confirm technical permissions. Policy controls (who is authorized to manage audit logs) require supplemental documentation.

---

### CM — Configuration Management

| Script | Control | Description | Coverage |
|---|---|---|---|
| `CM_3_4_2.ps1` | CM.L2-3.4.2 | GPO report, secedit baseline export, installed features, running services | 🔶 Partial |
| `CM_3_4_5.ps1` | CM.L2-3.4.5 | Least functionality — running services, listening ports, non-system scheduled tasks | 🔶 Partial |
| `CM_3_4_7.ps1` | CM.L2-3.4.7 | Nonessential programs — services, TCP+UDP ports, OS features (server/workstation aware), scheduled tasks | 🔶 Partial |

> **CM domain note:** Configuration management controls are inherently partial via PowerShell. Scripts document the current system state as baseline evidence. Deviation from an approved baseline requires a documented baseline to compare against, which is an organizational artifact.

---

### IA — Identification & Authentication

| Script | Control | Description | Coverage |
|---|---|---|---|
| `IA_3_5_7.ps1` | IA.L2-3.5.7 | Password complexity and age — local (secedit), domain, and FGPP with AppliesTo resolution | ✅ Full |
| `IA_3_5_8.ps1` | IA.L2-3.5.8 | **See note** | — |
| `IA_3_5_10.ps1` | IA.L2-3.5.10 | LM hash disabled, NTLMv2 enforcement, WDigest off, reversible encryption, Credential Guard | ✅ Full |

> **IA.L2-3.5.8 note:** Password history count (`PasswordHistoryCount`) is captured within `IA_3_5_7.ps1` at all three tiers (local, domain, FGPP). A separate 3.5.8 script is not required — reference the 3.5.7 artifact and annotate accordingly.

---

### MP — Media Protection

| Script | Control | Description | Coverage |
|---|---|---|---|
| `MP_3_8_7.ps1` | MP.L2-3.8.7 | Removable storage policy, USB device connection history, USB insertion event log | 🔶 Partial |

> **MP.L2-3.8.7 note:** Registry policy and event log checks confirm technical controls. An authorized device list (organizational artifact) is required to complete the evidence package.

---

### RA — Risk Assessment

| Script | Control | Description | Coverage |
|---|---|---|---|
| `RA_3_11_1.ps1` | RA.L2-3.11.1 / 3.11.2 | System baseline, installed software (all registry hives), patch inventory + currency, WU COM history, Defender AV currency | 🔶 Partial |

> **RA domain note:** PowerShell output is **supporting baseline evidence only.** A credentialed vulnerability scan from an approved scanner (Tenable, Nessus, Rapid7, etc.) is required separately. Assessors will not accept script output as a substitute for scanner results.

---

### SC — System & Communications Protection

| Script | Control | Description | Coverage |
|---|---|---|---|
| `SC_3_13_1.ps1` | SC.L2-3.13.1 | Firewall profile config, default inbound/outbound actions, log settings, listening ports | ✅ Full |
| `SC_3_13_6.ps1` | SC.L2-3.13.6 | Default deny posture — all firewall profiles checked for inbound Block | ✅ Full |
| `SC_3_13_11.ps1` | SC.L2-3.13.11 | FIPS mode registry key, TLS cipher suite audit, legacy SCHANNEL protocol status | ✅ Full |
| `SC_3_13_16.ps1` | SC.L2-3.13.16 | BitLocker encryption at rest — all volumes | ✅ Full |

---

### SI — System & Information Integrity

| Script | Control | Description | Coverage |
|---|---|---|---|
| `SI_3_14_1.ps1` | SI.L2-3.14.1 | Patch currency — HotFix inventory, patch age flag, PSWindowsUpdate pending check | ✅ Full |
| `SI_3_14_2.ps1` | SI.L2-3.14.2 / 3.14.4 / 3.14.5 | Defender AV enabled, real-time protection, definition currency, scan schedule | ✅ Full |

---

## Coverage Key

| Symbol | Meaning |
|---|---|
| ✅ Full | PowerShell output can technically confirm compliance or non-compliance. Pass/fail is deterministic against the control requirement. |
| 🔶 Partial | Script produces valid supporting evidence but the control also requires policy, process, or out-of-band artifacts that no script can validate. Assessor judgment required. |

---

## Usage

### Run a single script

```powershell
# From an elevated PowerShell session
cd .\AC
.\AC_3_1_1.ps1
```

Output drops to `.\AC\output\AC_3_1_1_{hostname}_{timestamp}.csv`.

### Run all scripts in a domain

```powershell
Get-ChildItem -Path .\AU -Filter *.ps1 | ForEach-Object {
    Write-Host "Running $($_.Name)..." -ForegroundColor Cyan
    & $_.FullName
}
```

### Adjust time window (AU_3_3_2)

```powershell
.\AU_3_3_2.ps1 -HoursBack 168 -MaxEvents 100
```

### Collect all output for evidence package

```powershell
# After running all scripts, collect all CSVs into one folder
Get-ChildItem -Path . -Recurse -Filter *.csv | Copy-Item -Destination .\evidence-package\
```

---

## Scope Notes

### Local vs. AD vs. Entra ID

Scripts that check user accounts and group memberships operate across three tiers:

- **Local** — always runs via `Get-LocalUser` / `Get-LocalGroupMember`
- **Active Directory** — runs if the `ActiveDirectory` module is present (RSAT required)
- **Entra ID** — runs if `Microsoft.Graph.Users` is present and authenticated

Each tier is attempted independently. Missing a module skips that tier gracefully with a warning — it does not fail the script.

### Server vs. Workstation OS

`CM_3_4_7.ps1` detects OS type via `Win32_OperatingSystem.ProductType` and calls `Get-WindowsFeature` (Server) or `Get-WindowsOptionalFeature` (Workstation) accordingly.

### Elevation

All scripts include `#Requires -RunAsAdministrator`. Scripts requiring elevation that are run without it will fail immediately with a clear error rather than silently returning partial results.

---

## What These Scripts Do Not Cover

The following require organizational artifacts, external tools, or assessor judgment and cannot be technically validated via PowerShell alone:

- **Approved baseline documentation** (CM.3.4.1) — PowerShell can document current state; comparison to an approved baseline requires the baseline document
- **Credentialed vulnerability scan results** (RA.3.11.2) — output from an approved scanner required (Tenable, Nessus, Rapid7, Microsoft Defender Vulnerability Management, or equivalent)
- **Incident response plan** (IR.3.6.1/3.6.2) — policy document, not a technical check
- **System Security Plan** (CA.3.12.4) — organizational artifact
- **Personnel screening** (PS.3.9.1/3.9.2) — HR process, not technically checkable
- **Physical access controls** (PE domain) — physical inspection required

---

## Disclaimer

These scripts are provided **as-is** for informational and evidence-support purposes under the following terms:

- **No warranty.** Scripts are provided without warranty of any kind, express or implied.
- **Not legal or compliance advice.** Output does not constitute a CMMC assessment, legal opinion, or guarantee of compliance.
- **Test before production.** Review and test each script in a non-production environment before running in your environment.
- **Your environment, your responsibility.** Results depend on your system configuration, OS version, and module availability. Always review output before submitting as evidence.
- **Not a C3PAO substitute.** A formal CMMC Level 2 assessment must be conducted by an accredited C3PAO. These scripts support preparation and self-assessment only.

Scripts may be freely used, modified, and redistributed. Attribution appreciated but not required.

---

## Contributing

Pull requests welcome. If you find a control gap, incorrect property index, or deprecated cmdlet, open an issue or submit a fix. Please maintain the existing output structure (timestamped CSV to `.\output\`) so artifacts remain consistent across the collection.

---

*Built to support CMMC Level 2 assessment preparation. Aligned to NIST SP 800-171 Rev 2 and the CMMC Assessment Guide v2.13.*
