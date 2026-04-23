# Assets — Screenshots

Place your screenshots in this folder and name them as follows so the wiki-links in each note resolve correctly.

| File Name | Content | Used In |
|---|---|---|
| `vt-detection-score.png` | VirusTotal — 30/63 detections, SHA-256 confirmed, community score −68, behaviour tags | Phase 1 |
| `vt-community-report.png` | NeikiAnalytics community report — Score 100/100, File Type PowerShell, `#ta582 #apt` tags | Phase 1 |
| `vt-relations-contacted-urls.png` | VirusTotal Relations tab — 5 contacted URLs, all `s=mints13`, multiple victim hostnames | Phase 1 |
| `mintsloader-attack-chain.png` | Recorded Future — MintsLoader Attack Chain diagram (Initial Access → Stage 1 JS → Stage 2 PS → Payload) | Phase 1 |
| `vt-htr-highlighted.png` | VirusTotal Contacted URLs — `htr.php` suffix highlighted in all 4 malicious URLs | Phase 2 |
| `vt-hostnames-highlighted.png` | VirusTotal Contacted URLs — `DESKTOP-*` and `AZURE-PC` victim hostnames highlighted | Phase 2 |
| `powershell-stage2-full.png` | Recorded Future Figure 21 — Full Stage 2 PowerShell source code | Phase 2 |
| `powershell-htr-zoomed.png` | PowerShell source — `htr` hardcoded in `$basename` construction, highlighted | Phase 2 |
| `powershell-dga-highlighted.png` | PowerShell source — `System.Random`, 15-char loop, `"abcdefghijklmn"` charset highlighted | Phase 2 |
| `arin-whois-blnetworks.png` | ARIN WHOIS for 206.188.196.37 — BL Networks, geofeed blnwx.com, "Updated 4 days ago" | Phase 3 |
| `recordedfuture-mintsloader-infra.png` | Recorded Future — MintsLoader Infrastructure text (BLNWX → SCALAXY-AS chain) | Phase 3 |
| `arin-whois-blnetworks-org.png` | whois.com — BL Networks org record, 30 N Gould St Sheridan WY | Phase 3 |
| `arin-originas-empty.png` | ARIN WHOIS — empty `OriginAS` field highlighted | Phase 3 |

## Your Original File Names (from Word doc)

Your images were extracted as `image1.png` through `image13.png` in this order:

| Original | Maps to |
|---|---|
| `image1.png` | `vt-detection-score.png` |
| `image2.png` | `vt-community-report.png` |
| `image3.png` | `vt-relations-contacted-urls.png` |
| `image4.png` | `mintsloader-attack-chain.png` |
| `image5.png` | `vt-htr-highlighted.png` |
| `image6.png` | `vt-hostnames-highlighted.png` |
| `image7.png` | `powershell-stage2-full.png` |
| `image8.png` | `powershell-htr-zoomed.png` |
| `image9.png` | `powershell-dga-highlighted.png` |
| `image10.png` | `arin-whois-blnetworks.png` |
| `image11.png` | `recordedfuture-mintsloader-infra.png` |
| `image12.png` | `arin-whois-blnetworks-org.png` |
| `image13.png` | `arin-originas-empty.png` |

Simply rename each file using the table above, place them in this `assets/` folder, and all `![[filename.png]]` links in the notes will resolve automatically in Obsidian.
