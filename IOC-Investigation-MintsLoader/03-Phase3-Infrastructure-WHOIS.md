---
title: "Phase 3 — Domain & IP Infrastructure Analysis + WHOIS"
tags:
  - phase-3
  - infrastructure
  - whois
  - blnwx
  - bulletproof-hosting
  - dga
created: 2025-04-22
---

# Phase 3 — Domain & IP Infrastructure Analysis + WHOIS

**Previous:** [[Phase 2-C2-URL-Analysis](https://github.com/Kazu010101/Threat-Intelligence/blob/main/IOC-Investigation-MintsLoader/02-Phase2-C2-URL-Analysis.md)] | **Next:** [[Phase 4-MITRE-ATT&CK](https://github.com/Kazu010101/Threat-Intelligence/blob/main/IOC-Investigation-MintsLoader/04-Phase4-MITRE-ATT&CK.md)]

---

## Objective

Map the hosting infrastructure behind the IOC IP and domain, trace the ownership chain through registry records, and assess what the infrastructure choices reveal about the threat actor's operational maturity and intent.

---

## 3.1 Domain Analysis — `abgnmlahkdfnfhn[.]top`

### DGA Pattern Verification

The domain was already confirmed as a MintsLoader DGA output in [[Phase2-C2-URL-Analysis](https://github.com/Kazu010101/Threat-Intelligence/blob/main/IOC-Investigation-MintsLoader/02-Phase2-C2-URL-Analysis.md)]. Key registration characteristics are:

| Property | Expected for DGA domains | Significance |
|---|---|---|
| Domain length | Exactly 15 characters | MintsLoader DGA constant loop count |
| Character set | Lowercase `[a-n]` only | Matches `"abcdefghijklmn"` PowerShell charset |
| TLD | `.top` | MintsLoader-exclusive TLD, costs ~$1–2/year |
| Registration timing | Day-of or 1 day before use | Just-in-time registration per DGA seed |
| Registrant | Redacted / privacy-protected | Threat actors routinely use WHOIS privacy |
| DNSSEC | Not signed | Malicious domains rarely implement DNSSEC |

### Why `.top` Domains Are Preferred by Threat Actors

The `.top` TLD is a deliberate operational choice:
- At ~$1–2 USD per domain, the cost to register a daily rotating pool of 10–15 domains is negligible
- The `.top` registry has historically lower abuse-report enforcement responsiveness than `.com`/`.net`
- Combined with DGA rotation, blocking a `.top` domain provides zero lasting defence — the next day's domain is already being generated

### WHOIS Lookup Outcome for the Domain

Due to the short-lived, privacy-protected nature of DGA domains, a WHOIS lookup on `abgnmlahkdfnfhn[.]top` is likely to return one of three outcomes:

1. **Not found / expired**: the domain's registration lapsed after its single-day use
2. **Privacy-protected**: only registrar name and dates visible, no registrant identity
3. **Registry suspended**:  domain placed on `serverHold` following abuse report

For this reason, the **IP WHOIS is the primary forensic value** in Phase 3.

---

## 3.2 IP Analysis — `206.188.196.37`

### ARIN WHOIS Record (Primary Source)

WHOIS lookup via ARIN (American Registry for Internet Numbers), the authoritative registry for this IP block, returns the following record. **Note:** This data was captured 4 days prior to analysis and reflects the most current available registration data.

<img width="1171" height="563" alt="image" src="https://github.com/user-attachments/assets/6da53ec7-6126-46a5-a2c0-c1d9fb3f795a" />

*Screenshot: ARIN WHOIS for 206.188.196.37 — Updated 4 days ago. NetName: BLNETWORKS-01, Organisation: BL Networks (BNL-77), Geofeed: geoip.blnwx.com/csv, RegDate: 2021-05-07.*

```
NetRange:     206.188.196.0 - 206.188.197.255
CIDR:         206.188.196.0/23
NetName:      BLNETWORKS-01
NetHandle:    NET-206-188-196-0-1
Parent:       NET206 (NET-206-0-0-0-0)
NetType:      Direct Allocation
OriginAS:     [EMPTY]
Organization: BL Networks (BNL-77)
RegDate:      2021-05-07
Updated:      2024-02-18
Comment:      Geofeed https://geoip.blnwx.com/csv
```

### Organisation Record — BL Networks

<img width="799" height="613" alt="image" src="https://github.com/user-attachments/assets/17311a4b-c130-4934-bbea-6b8d52916674" />

*Screenshot: whois.com ARIN query — BL Networks (BNL-77), Address: 30 N Gould St, Ste R, Sheridan, WY 82801, Country: US, RegDate: 2019-11-01, Updated: 2024-11-25.*

```
OrgName:      BL Networks
OrgId:        BNL-77
Address:      30 N Gould St, Ste R
City:         Sheridan
StateProv:    WY
PostalCode:   82801
Country:      US
RegDate:      2019-11-01
Updated:      2024-11-25
```

---

## 3.3 Critical Finding: BL Networks = BLNWX

The `Comment` field in the ARIN record contains:

```
Geofeed https://geoip.blnwx.com/csv
```

The `blnwx.com` domain directly identifies **BL Networks as BLNWX** which is the same infrastructure provider named in Recorded Future's Insikt Group MintsLoader research as the *original, primary hosting provider* for MintsLoader C2 servers.

<img width="995" height="377" alt="image" src="https://github.com/user-attachments/assets/9070bb31-aeac-4585-80ae-745340353b0d" />

*Screenshot: Recorded Future — MintsLoader Infrastructure section. "Insikt Group initially found MintsLoader C2 servers hosted solely on BLNWX but later observed its growing use of other ISPs such as Stark Industries Solutions Ltd (AS44477), GWY IT Pty Ltd (AS199959), or SCALAXY-AS (58061), among others. MintsLoader C2 IP addresses announced via SCALAXY-AS are operated by hosting providers 3NT Solutions LLP and IROKO Networks Corporation, both of which are part of the Russian-language bulletproof hosting provider Inferno Solutions."*

This finding confirms that `206.188.196.37` is operating within MintsLoader's documented primary hosting infrastructure.

---

## 3.4 The Empty `OriginAS` Field — Infrastructure Intelligence

<img width="659" height="626" alt="image" src="https://github.com/user-attachments/assets/0341853f-d7b1-42ea-98d9-c3c21060ad1f" />

*Screenshot: ARIN WHOIS for 206.188.196.37 — OriginAS field is highlighted and empty. All other fields (NetRange, CIDR, NetName, Organisation) are populated, but OriginAS has no value.*

In a standard ARIN WHOIS record, `OriginAS` declares which Autonomous System (ASN) is BGP-announcing the IP block. An empty field means the block was registered with ARIN but the BGP routing responsibility has been sub-allocated to another provider without updating the ARIN record.

```
ARIN Record (Legal Registration Layer):
  206.188.196.0/23 → BL Networks / BLNWX
  OriginAS: [empty — not updated]
        │
        ▼  sub-allocation without ARIN update
BGP Routing Layer (Operational Layer):
  AS58061 — SCALAXY-AS (Scalaxy B.V., Riga, Latvia)
        │
        ▼  operated under SCALAXY-AS by:
Physical Host Layer:
  3NT Solutions LLP + IROKO Networks Corporation
  ← Part of Inferno Solutions (Russian-language BPH)
```

This deliberate separation between the legal ARIN registrant and the actual BGP routing operator is a documented OPSEC technique used by bulletproof hosting providers. It creates a layered takedown resistance: even if ARIN acts on an abuse report against BLNWX, the BGP routing through SCALAXY-AS continues to operate independently.

---

## 3.5 Wyoming Shell Company Pattern

The registration address `30 N Gould St, Ste R, Sheridan, WY 82801` is a registered agent address; a commercial mail forwarding service, not a physical operations office. Wyoming is a preferred jurisdiction for threat-actor-linked shell companies for the following reasons:

| Factor | Detail |
|---|---|
| No beneficial owner disclosure | Wyoming LLCs are not required to publicly name their actual owners |
| No state corporate income tax | Zero tax liability regardless of revenue |
| Low formation cost | ~$100 USD to establish an LLC |
| US-based appearance | American address lends false legitimacy to ARIN registration applications |
| Minimal compliance requirements | Minimal ongoing filing obligations |

> **Reference:** [Reuters — How cybercriminals are using Wyoming shell companies for global hacks (2023)](https://www.reuters.com/technology/cybersecurity/how-cybercriminals-are-using-wyoming-shell-companies-global-hacks-2023-12-12/)

The use of a Wyoming shell company to obtain a US-based ARIN IP allocation, while the actual infrastructure is operated by a Russian-language bulletproof hosting provider via European ASNs, is a well-documented evasion pattern in cybercrime hosting operations.

---

## 3.6 Full Infrastructure Ownership Chain

```
ARIN ALLOCATION (Registry Layer)
  NetRange: 206.188.196.0/23
  Registered: BL Networks (BLNWX)
  Address: 30 N Gould St Ste R, Sheridan WY
  (Wyoming shell company — registered agent address)
  RegDate: 2021-05-07
        │
        ▼ sub-allocation (OriginAS empty in ARIN)
BGP ROUTING (AS58061)
  SCALAXY-AS — Scalaxy B.V.
  Address: Dudayeva 2-16, Riga, Latvia
  RADB mnt-by: MAINT-3NT (noc@3nt.com)
        │
        ▼ operated by sub-allocators:
OPERATIONAL HOSTS
  3NT Solutions LLP (London registered, Inferno Solutions brand)
  IROKO Networks Corporation (Panama / London)
  Both part of: Inferno Solutions (inferno[.]name)
  ← Russian-language bulletproof hosting provider
        │
        ▼
206.188.196.37 ← Our IOC IP
MintsLoader C2 Server
```

---

## 3.7 Phase 3 Summary

The IP `206.188.196.37` was **likely already in use for MintsLoader C2 during the BLNWX-primary phase**, and continued to be used after the operator migrated BGP routing to SCALAXY-AS without updating the underlying ARIN record. This is strong evidence of **long-term, stable C2 infrastructure** designed to complicate takedown efforts, not a one-time or opportunistic deployment.

| Finding | Confidence | Significance |
|---|---|---|
| IP registered to BLNWX (BL Networks) | ✅ Confirmed | BLNWX is MintsLoader's documented original C2 host |
| Empty `OriginAS` | ✅ Confirmed | Sub-allocation OPSEC — separation of legal and operational layers |
| Wyoming shell company address | ✅ Confirmed | Documented pattern for bulletproof hosting ARIN registrations |
| BGP routing via SCALAXY-AS | ✅ Confirmed | Matches Phase 2 infrastructure migration documented by Insikt Group |
| Overall infrastructure maturity | High | This is organised, persistent threat actor infrastructure, not a script kiddie setup |

> **Note:** BLNWX and Inferno Solutions have documented histories of slow or non-responsive abuse handling which is consistent with bulletproof hosting operations. Parallel escalation through all channels simultaneously is recommended.

---

## References

- [Recorded Future — MintsLoader Infrastructure Analysis](https://www.recordedfuture.com/research/uncovering-mintsloader-with-recorded-future-malware-intelligence-hunting)
- [ARIN RDAP — 206.188.196.0/23](https://rdap.arin.net/registry/ip/206.188.196.0)
- [BGP.he.net — AS58061 SCALAXY-AS](https://bgp.he.net/AS58061)
- [Reuters — Wyoming Shell Companies in Cybercrime](https://www.reuters.com/technology/cybersecurity/how-cybercriminals-are-using-wyoming-shell-companies-global-hacks-2023-12-12/)
- [Wyoming LLC Pros and Cons](https://www.companiesinc.com/start-a-business/wyoming-llc-pros-and-cons/)
