---
title: "IOC Investigation — MintsLoader / TAG-124"
tags:
  - threat-intelligence
  - ioc-analysis
  - mintsloader
  - tag-124
  - portfolio
created: 2025-04-22
status: complete
difficulty: intermediate
---

# IOC Investigation — MintsLoader / TAG-124 Attribution

## Overview

This project documents a complete threat intelligence investigation starting from raw Indicators of Compromise (IOCs) and culminating in threat group attribution. It was completed as part of a SOC analyst training activity and is intended as a portfolio demonstration of structured threat intelligence methodology.

## Learning Objectives

- Analyse log artefacts to identify and categorise IOCs
- Conduct OSINT research to enrich each indicator
- Correlate technical evidence across multiple intelligence sources
- Map observed behaviour to the MITRE ATT&CK framework
- Attribute the IOC set to a known threat group with documented confidence reasoning

## Identified IOCs

| Type | Indicator |
|---|---|
| IP Address | `206.188.196.37` |
| Domain | `hxxp://abgnmlahkdfnfhn[.]top` |
| URL | `hxxp://abgnmlahkdfnfhn[.]top/m9ve2kqf0rhtr.php?id=DESKTOP-ET51AJO&key=63772388458&s=mints13` |
| File Name | `invoice.ps1.exe` |
| File Hash (SHA-256) | `02d072b70efe0c6c7840e65eba05e580604ae7958cea1d39082ba120d4c4ac93` |

> ⚠️ **Safety Note:** All IOCs above are defanged. When working with live indicators, always work in an isolated lab environment and use defanged notation (replacing `http` with `hxxp` and `.` with `[.]`).

## Investigation Phases

| Phase | Focus | Note |
|---|---|---|
| [[01-Phase1-Malware-Family\|Phase 1]] | Hash & File Analysis — Malware Family Identification | MintsLoader confirmed |
| [[02-Phase2-C2-URL-Analysis\|Phase 2]] | C2 URL Pattern Analysis — Confirming Malware Family | `htr.php` suffix match |
| [[03-Phase3-Infrastructure-WHOIS\|Phase 3]] | Domain & IP Infrastructure + WHOIS | BLNWX / BL Networks confirmed |
| [[04-Phase4-MITRE-ATT&CK\|Phase 4]] | TTP Mapping to MITRE ATT&CK | 10 confirmed techniques |
| [[05-Phase5-Threat-Attribution\|Phase 5]] | Threat Group Attribution | TAG-124 / LandUpdate808 |

## Final Verdict

> **Attribution:** TAG-124 (LandUpdate808), operating MintsLoader campaign `mints13`
> **Confidence:** High
> **Malware Family:** MintsLoader → GhostWeaver RAT / StealC / BOINC

## Key References

- [Recorded Future — Uncovering MintsLoader](https://www.recordedfuture.com/research/uncovering-mintsloader-with-recorded-future-malware-intelligence-hunting)
- [The Hacker News — MintsLoader drops GhostWeaver](https://thehackernews.com/2025/05/mintsloader-drops-ghostweaver-via.html)
- [Broadcom — MintsLoader powering TAG-124 campaigns](https://www.broadcom.com/support/security-center/protection-bulletin/mintsloader-the-loader-powering-tag-124-s-targeted-campaigns)
- [Orange Cyberdefense — MintsLoader IOC Repository (GitHub)](https://github.com/cert-orangecyberdefense/mintsloader)
- [ThreatFox — win.mintstealer](https://threatfox.abuse.ch/browse/malware/win.mintstealer/)
- [VirusTotal — File Hash](https://www.virustotal.com/gui/file/02d072b70efe0c6c7840e65eba05e580604ae7958cea1d39082ba120d4c4ac93/relations)
