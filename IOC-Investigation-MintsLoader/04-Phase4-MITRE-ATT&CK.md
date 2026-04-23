---
title: "Phase 4 — TTP Analysis: MITRE ATT&CK Mapping"
tags:
  - phase-4
  - mitre-attck
  - ttp
  - defense-evasion
  - c2
created: 2025-04-22
---

# Phase 4 — TTP Analysis: MITRE ATT&CK Mapping

**Previous:** [[Phase 3-Infrastructure-WHOIS](https://github.com/Kazu010101/Threat-Intelligence/blob/main/IOC-Investigation-MintsLoader/03-Phase3-Infrastructure-WHOIS.md)] | **Next:** [[Phase 5-Threat-Attribution](https://github.com/Kazu010101/Threat-Intelligence/blob/main/IOC-Investigation-MintsLoader/05-Phase5-Threat-Attribution.md)]

---

## Objective

Formally codify the observed attacker behaviours into MITRE ATT&CK tactics and techniques, tying each technique directly to the IOC evidence that supports it.

---

## 4.1 ATT&CK Mapping Table

| Tactic | Technique ID | Technique Name | IOC Evidence | Confidence |
|---|---|---|---|---|
| **Initial Access** (TA0001) | T1566 | Phishing | `invoice.ps1.exe` filename — social engineering lure | ✅ Confirmed |
| **Initial Access** (TA0001) | T1566.001 | Spearphishing Attachment | Invoice-themed file delivered as email attachment | ✅ Confirmed |
| **Initial Access** (TA0001) | T1566.002 | Spearphishing Link | Alternate delivery via malicious URL / ClickFix page | ✅ Confirmed |
| **Execution** (TA0002) | T1059 | Command & Scripting Interpreter | PowerShell and JavaScript execution chain | ✅ Confirmed |
| **Execution** (TA0002) | T1059.001 | PowerShell | `.ps1.exe` filename; Stage 2 is entirely PowerShell | ✅ Confirmed |
| **Execution** (TA0002) | T1059.007 | JavaScript | Stage 1 is heavily obfuscated JavaScript dropper | ✅ Confirmed |
| **Defense Evasion** (TA0005) | T1027 | Obfuscated Files or Information | Double extension `.ps1.exe`; multi-layer obfuscated JS/PS scripts | ✅ Confirmed |
| **Defense Evasion** (TA0005) | T1562 | Impair Defenses | AMSI bypass in Stage 2 PowerShell script | ✅ Confirmed |
| **Defense Evasion** (TA0005) | T1562.001 | Disable or Modify Tools | AMSI explicitly disabled before payload execution | ✅ Confirmed |
| **Defense Evasion** (TA0005) | T1497 | Virtualization/Sandbox Evasion | VM/sandbox detection via WMI; `key=` parameter is proof of execution | ✅ Confirmed |
| **Defense Evasion** (TA0005) | T1497.001 | System Checks | WMI checks: `IsVirtualMachine`, `AdapterDACType`, cache memory | ✅ Confirmed |
| **Defense Evasion** (TA0005) | T1568.002 | Dynamic Resolution: DGA | `abgnmlahkdfnfhn[.]top` — 15-char seeded DGA domain | ✅ Confirmed |
| **Discovery** (TA0007) | T1082 | System Information Discovery | `id=DESKTOP-ET51AJO` — hostname exfiltrated via `$env:computername` | ✅ Confirmed |
| **C2** (TA0011) | T1071.001 | Web Protocols | HTTP GET beacon to `abgnmlahkdfnfhn[.]top` over port 80 | ✅ Confirmed |
| **C2** (TA0011) | T1568.002 | Dynamic Resolution | Daily-rotating DGA domains — static blocklists are ineffective | ✅ Confirmed |
| **C2** (TA0011) | T1105 | Ingress Tool Transfer | Final payload delivered from `206.188.196.37` → SHA-256 hash | ✅ Confirmed |


---

## 4.2 Technique Deep-Dives

### T1566.001 — Spearphishing Attachment (`invoice.ps1.exe`)

The filename `invoice.ps1.exe` is a textbook spearphishing attachment:
- **`invoice`** — business document lure, designed to bypass suspicion in a professional context
- **`.ps1`** — visible extension if file extensions are shown; creates ambiguity about file type
- **`.exe`** — true executable extension, hidden by default in Windows Explorer

This technique is documented as TAG-124's primary delivery method for MintsLoader in targeted phishing campaigns against industrial, legal, and energy sector organisations.

---

### T1027 — Obfuscated Files or Information (`invoice.ps1.exe`)

Three layers of obfuscation are present:

1. **File obfuscation** — double extension hides the executable nature of the file
2. **Stage 1 JS obfuscation** — JavaScript uses junk comments, non-readable variable names, character replacement, and string encoding
3. **Stage 2 PS obfuscation** — PowerShell payload is Base64-encoded, XOR-decoded, and GZIP-compressed

---

### T1497 / T1497.001 — Sandbox Evasion (`key=63772388458`)

The `key=` parameter is the most technically sophisticated evasion in the chain. Stage 2 performs multiple environment checks via WMI before generating the key:

```powershell
# Check 1: Is the machine virtual?
Get-MpComputerStatus | Select IsVirtualMachine

# Check 2: Video adapter DAC type (physical hardware indicator)
Get-WmiObject Win32_VideoController | Select AdapterDACType

# Check 3: Cache memory presence
# (sandboxes often lack realistic cache configurations)
```

The resulting numeric key `63772388458` is sent to the C2 server. The server validates it against expected ranges for real hardware. If it fails validation, a decoy payload (such as AsyncRAT) is delivered instead of the real payload.

**For detection:** The presence of `key=` with a purely numeric value in a `.php` C2 URL, combined with WMI-based system checks in process telemetry, is a reliable behavioural indicator.

---

### T1568.002 — DGA (`abgnmlahkdfnfhn.top`)

The DGA seed combines:
- `[int](Get-Date).DayOfYear` — day number within the current year (1–365)
- `+ 1995584850` — hardcoded constant salt

This produces a deterministic but date-varying domain from a fixed 14-character alphabet. The operator can pre-generate all valid domains for any time period, while defenders must regenerate the full DGA pool to anticipate future C2 addresses.

**Detection approach:** Rather than blocklisting individual domains, defenders should detect the DGA *behaviour pattern*:
- DNS queries for 15-character lowercase `.top` domains with no prior history
- PowerShell invoking `New-Object System.Random` with a date-arithmetic seed
- Outbound HTTP GET requests matching `*htr.php?id=*&key=*&s=mints*`

---

### T1082 — System Information Discovery (`id=DESKTOP-ET51AJO`)

The victim's hostname is exfiltrated in the very first C2 beacon — before any payload is delivered. This gives the operator immediate triage capability:

```
DESKTOP-*  → Non-domain-joined home/SMB user
PC-* / WS-* → Likely workstation in small office
LAPTOP-*   → Mobile worker
AZURE-PC   → Cloud VM or developer machine (lower value target)
```

Multiple victim hostnames visible in VirusTotal (`AZURE-PC`, `DESKTOP-ET51AJO`, `DESKTOP-B0T93D6`) confirm the operator receives this data across all infections and uses it for targeting decisions.

---

## 4.3 Defense Evasion — Highest Technique Density

The Defense Evasion tactic has the highest concentration of confirmed techniques in this IOC set — four independent sub-techniques all confirmed by direct IOC evidence:

```
Defense Evasion techniques confirmed:
  T1027     ← invoice.ps1.exe double extension + JS/PS obfuscation
  T1562.001 ← AMSI explicitly disabled in Stage 2
  T1497.001 ← WMI-based VM/sandbox checks
  T1568.002 ← DGA domain rotation

This density of evasion techniques is NOT consistent with
commodity malware or script kiddie operations.
It points to a technically proficient, organised threat actor.
```

---

## 4.4 ATT&CK Navigator Coverage Summary

| Tactic | Confirmed Techniques | Inferred Techniques |
|---|---|---|
| Initial Access | 2 | 0 |
| Execution | 3 | 0 |
| Defense Evasion | 5 | 0 |
| Discovery | 2 | 0 |
| Command & Control | 3 | 0 |
| **Total** | **15** | **0** |

All 15 confirmed techniques are directly evidenced by one or more of the five original IOCs.

---

## References

- [MITRE ATT&CK — Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [MITRE T1566 — Phishing](https://attack.mitre.org/techniques/T1566/)
- [MITRE T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE T1562.001 — Disable AMSI](https://attack.mitre.org/techniques/T1562/001/)
- [MITRE T1497 — Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497/)
- [MITRE T1568.002 — DGA](https://attack.mitre.org/techniques/T1568/002/)
- [MITRE T1082 — System Information Discovery](https://attack.mitre.org/techniques/T1082/)
