# CVE Lookup Panel

The CVE panel surfaces recent CVEs from the **NVD API v2**, enriched with the
**CISA KEV** catalog and the **MITRE cveawg** record for each CVE.

## Key Behaviors

- **Lazy loading**: 10 entries per page so large NVD windows stay responsive.
- **Severity filtering**: pick from `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `Common`, `ALL`, or a custom `Select` set.
- **Common-app detection**: vendor/product matching against a curated keyword list (Cisco, Fortinet, Palo Alto, VMware, Microsoft, Chrome, Zoom, Slack, WhatsApp Desktop, Telegram Desktop, Check Point, CyberArk, BeyondTrust, SentinelOne, Bitdefender, Trend Micro, Aruba, Ruckus, Sangfor, Hillstone, Imperva, Riverbed, Nagios, Veeam, Tenable, WordPress, HSM nShield, Atmos Agent, Device42, XFusion, SecIron, etc.) so SOC-relevant CVEs surface first. Short/ambiguous tokens (`hp`, `edge`, `aws`, `azure`, `f5`, `linux`, `oracle`, `php`, `mysql`) are matched against vendor+product fields only to avoid false positives on unrelated CVE descriptions.
- **MITRE enrichment**: pulls vendor / product / affected version range from `affected[]` and a short CAPEC attack-pattern label from `impacts[]`, plus the **CWE-N** id from the NVD weaknesses list. Records are fetched in parallel (12 workers) and cached for 24 hours.
- **KEV expansion**: when a CVE is in the CISA KEV catalog, the card carries the KEV `shortDescription`, `requiredAction`, `knownRansomwareCampaignUse`, and `vulnerabilityName` fields alongside the standard NVD data.
- **NVD-aware caching**: 1-hour TTL on NVD + KEV responses keeps the rolling window reasonably fresh while easing rate-limit pressure; MITRE responses use a separate 24h TTL. Optional `CVE_NVD_KEY` env variable injects an NVD API key for higher rate limits (50 req/30s vs 5).
- **Copy formatter**: one-click copy formatted for WhatsApp/SOC handoff, with bold styling, raw CVE URLs, and grouped severity output.

## Source

- Rendering: [`ui/components/cve_panel.py`](../ui/components/cve_panel.py)
- NVD / KEV / MITRE client and parsing: [`providers/nvd.py`](../providers/nvd.py)
- Tests: [`tests/test_cve_panel_copy.py`](../tests/test_cve_panel_copy.py), [`tests/test_nvd_provider.py`](../tests/test_nvd_provider.py)
