# IOC Investigation — MintsLoader / TAG-124 Attribution

> **Cybersecurity Portfolio Project** | Practical Security Analyst Training (PCSA) - Cylynk Acitivty
> **Domain:** Threat Intelligence / IOC Analysis

---

## Project Summary

This project documents a complete threat intelligence investigation — starting from five raw Indicators of Compromise (IOCs) found in a log file and culminating in a documented, confidence-rated attribution to a known threat actor group.

The investigation follows a structured five-phase methodology aligned with professional threat intelligence practices, with all findings mapped to the MITRE ATT&CK framework. 

---

## Identified IOCs

| Type | Indicator |
|---|---|
| IP Address | `206.188.196.37` |
| Domain | `hxxp://abgnmlahkdfnfhn[.]top` *(defanged)* |
| URL | `hxxp://abgnmlahkdfnfhn[.]top/m9ve2kqf0rhtr.php?id=DESKTOP-ET51AJO&key=63772388458&s=mints13` *(defanged)* |
| File Name | `invoice.ps1.exe` |
| File Hash (SHA-256) | `02d072b70efe0c6c7840e65eba05e580604ae7958cea1d39082ba120d4c4ac93` |

---

## Investigation Phases

<img width="1340" height="252" alt="image" src="https://github.com/user-attachments/assets/7613ba99-a970-45bc-b82a-d482f0fdc65e" />


| Phase | Focus | Key Finding |
|---|---|---|
| [Phase 1](IOC-Investigation-MintsLoader/01-Phase1-Malware-Family.md) | Hash & File Analysis | MintsLoader malware family confirmed via VirusTotal (30/63 detections) |
| [Phase 2](IOC-Investigation-MintsLoader/02-Phase2-C2-URL-Analysis.md) | C2 URL Pattern Analysis | `htr.php` hardcoded suffix + DGA domain confirmed via PowerShell source code |
| [Phase 3](IOC-Investigation-MintsLoader/03-Phase3-Infrastructure-WHOIS.md) | Infrastructure + WHOIS | ARIN confirms `206.188.196.37` belongs to BLNWX — MintsLoader's original C2 host |
| [Phase 4](IOC-Investigation-MintsLoader/04-Phase4-MITRE-ATT&CK.md) | MITRE ATT&CK Mapping | 15 confirmed TTPs across 5 tactics; 5 Defense Evasion techniques in a single sample |
| [Phase 5](IOC-Investigation-MintsLoader/05-Phase5-Threat-Attribution.md) | Threat Group Attribution | **TAG-124 (LandUpdate808)** — high confidence |

---

## Final Attribution

> **Threat Group:** TAG-124 (LandUpdate808)  
> **Malware:** MintsLoader (campaign `mints13`)  
> **Confidence:** High  
> **Delivery:** Invoice-themed phishing → PowerShell loader → GhostWeaver RAT / StealC / Vidar Stealer  
> **Infrastructure:** BLNWX (ARIN) → SCALAXY-AS → Inferno Solutions (Russian bulletproof hosting)

---

## Tools Used

| Tool | Purpose |
|---|---|
| [VirusTotal](https://www.virustotal.com) | Hash analysis, behaviour tags, contacted URLs |
| [ARIN WHOIS](https://search.arin.net) | IP registration and ownership lookup |
| [Recorded Future](https://www.recordedfuture.com) | Threat intelligence correlation |
| [ThreatFox (abuse.ch)](https://threatfox.abuse.ch) | IOC community database |
| [ANY.RUN](https://any.run) | Sandbox behaviour analysis |
| [MITRE ATT&CK](https://attack.mitre.org) | TTP framework mapping |
| [BGP.he.net](https://bgp.he.net) | ASN and routing infrastructure lookup |

---

## Skills Demonstrated

- IOC triage and defanging
- SHA-256 hash algorithm identification
- Malware family identification via OSINT (VirusTotal, ThreatFox, ANY.RUN)
- C2 URL dissection and pattern matching against published malware source code
- WHOIS / RDAP lookups across ARIN and RIPE registries
- Bulletproof hosting infrastructure tracing
- MITRE ATT&CK technique mapping with direct IOC-to-technique evidence
- Multi-source threat actor attribution with confidence scoring
- Intelligence gap analysis and competing hypothesis evaluation

---

## Key References

- [Recorded Future — Uncovering MintsLoader](https://www.recordedfuture.com/research/uncovering-mintsloader-with-recorded-future-malware-intelligence-hunting)
- [Recorded Future — TAG-124 TDS Infrastructure](https://www.recordedfuture.com/research/tag-124-multi-layered-tds-infrastructure-extensive-user-base)
- [The Hacker News — MintsLoader drops GhostWeaver](https://thehackernews.com/2025/05/mintsloader-drops-ghostweaver-via.html)
- [Broadcom — MintsLoader powering TAG-124 campaigns](https://www.broadcom.com/support/security-center/protection-bulletin/mintsloader-the-loader-powering-tag-124-s-targeted-campaigns)
- [Orange Cyberdefense — MintsLoader IOC Repository](https://github.com/cert-orangecyberdefense/mintsloader)

---

*All IOCs in this repository are defanged. This project is for educational and portfolio purposes only.*
