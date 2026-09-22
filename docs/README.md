# IOC Router Documentation

Reference documentation for IOC Router. See the [project README](../README.md) for
features, setup, and usage.

## Module Documentation

| Document | Covers |
|---|---|
| [Process & Filepath Analysis](process_analyzer.md) | Parent/child process pairing, filepath suspicion, masquerading |
| [Command Line Analysis](cmdline_analyzer.md) | Structural parsing, deobfuscation, LOLBAS, Sigma CommandLine rules |
| [WAF Payload Analysis](waf_payload_analyzer.md) | SQLi / XSS / RCE / LFI / SSRF detection, OWASP CRS matching |
| [Threat State, Level, and Verdict](threat_state_level_verdict.md) | How the three assessments are derived |
| [CVE Lookup Panel](cve_panel.md) | NVD / CISA KEV / MITRE enrichment, filtering, caching, copy formatter |

## Provider Documentation

| Provider | Document |
|---|---|
| VirusTotal | [virustotal.md](virustotal.md) |
| URLScan | [urlscan.md](urlscan.md) |
| AbuseIPDB | [abuseipdb.md](abuseipdb.md) |
| Shodan | [shodan.md](shodan.md) |
| ThreatFox | [threatfox.md](threatfox.md) |
| MalwareBazaar | [malwarebazaar.md](malwarebazaar.md) |
| DNSDumpster | [dnsdumpster.md](dnsdumpster.md) |
| Hybrid Analysis | [hybrid_analysis.md](hybrid_analysis.md) |
| MxToolBox | [mxtoolbox.md](mxtoolbox.md) |
| Whoxy | [whoxy.md](whoxy.md) |
| Ransomware.live | [ransomware_live.md](ransomware_live.md) |
| Gemini (AI) | [gemini.md](gemini.md) |
| Groq (AI) | [groq.md](groq.md) |

---

## Project Structure

```
ioc-router/
├── app.py                        # Streamlit entry point (fixed header + tab/dialog JS shim)
├── config.py                     # API key config & environment loading
├── requirements.txt
├── .streamlit/
│   └── config.toml               # ForwardMsg cache tuning + WS compression for Cloud stability
│
├── core/                         # Orchestration, local analysis & shared utilities
│   ├── orchestrator.py           # Async provider dispatch & result aggregation
│   ├── pipeline.py               # Enrichment run assembly (extracted from app.py)
│   ├── cache.py                  # In-memory result caching
│   ├── http.py                   # Pooled requests.Session + bounded parallel fan-out
│   ├── geo.py                    # IP geolocation resolution
│   ├── infra_classifier.py       # ASN-based infra classification (BP / FP / HIGH_RISK)
│   ├── process_analyzer.py       # Process/filepath identity, LOLBAS, Sigma pairing
│   ├── lolbas_lookup.py          # LOLBAS dual-use lookup + abuse-command patterns
│   ├── cmdline_parser.py         # cmd.exe + PowerShell tokenizer, interpreter detection
│   ├── cmdline_deobfuscator.py   # Command-line decode (pure transforms, never executes)
│   ├── decode_common.py          # Encoding primitives shared across analysis modules
│   ├── cmdline_analyzer.py       # Keywords, entropy, Sigma/LOLBAS matching, verdict
│   ├── waf_payload_parser.py     # WAF payload field parsing (line split + validation)
│   ├── waf_payload_analyzer.py   # CRS + CVE-fingerprint matching, verdict, rows
│   ├── crs_matcher.py            # OWASP CRS rule matching against decoded payloads
│   ├── crs_transforms.py         # ModSecurity-equivalent transformation chain
│   ├── cve_fingerprint.py        # Curated known-exploited CVE signature matching
│   │
│   ├── data/                     # Offline-generated datasets (no runtime fetches)
│   │   ├── known_system_processes.json    # Path-baseline whitelist (66)
│   │   ├── lolbas_binaries.json           # Dual-use binaries (240)
│   │   ├── lolbas_commands.json           # Documented abuse patterns (105 / 165)
│   │   ├── sigma_parent_child_pairs.json  # Parent→child blocklist (1,874)
│   │   ├── sigma_cmdline_patterns.json    # CommandLine rule patterns (1,409)
│   │   ├── suspicious_cmdline_keywords.json  # Curated switch table (34)
│   │   ├── cmd_internal_commands.json     # cmd.exe builtins (45)
│   │   ├── crs_patterns.json              # Extracted OWASP CRS rule subset (183)
│   │   └── cve_fingerprints.json          # Curated known-exploited CVE signatures
│   │
│   └── scripts/                  # Offline dataset regeneration & manual harnesses
│       ├── extract_lolbas.py                  # LOLBAS → binaries + abuse commands
│       ├── extract_sigma_pairs.py             # SigmaHQ → parent/child pairs
│       ├── extract_sigma_cmdline_patterns.py  # SigmaHQ → CommandLine patterns
│       ├── extract_crs_patterns.py            # OWASP CRS → crs_patterns.json
│       ├── try_process_analyzer.py            # Ad-hoc process/filepath analysis
│       └── try_cmdline_analyzer.py            # Ad-hoc analysis + `--calibrate`
│
├── ioc/                          # IOC processing pipeline
│   ├── parser.py                 # Type detection, normalization, deduplication
│   ├── verdict.py                # Multi-source verdict aggregation engine
│   ├── confidence_scorer.py      # 0–100 numeric confidence score + session aggregation
│   ├── threat_analysis.py        # Threat state, threat level, asset criticality
│   └── flags/                    # Per-provider threat flag extractors
│       ├── virustotal.py
│       ├── urlscan.py
│       ├── abuseipdb.py
│       ├── shodan.py
│       ├── threatfox.py
│       ├── malwarebazaar.py
│       ├── hybrid_analysis.py
│       ├── dnsdumpster.py
│       ├── multisource.py        # Cross-provider correlation flags
│       ├── ransomware_live.py    # Ransomware.live victim flags
│       └── base.py               # Shared flag builder helpers
│
├── providers/                    # Provider API clients
│   ├── virustotal.py
│   ├── urlscan.py
│   ├── abuseipdb.py
│   ├── shodan.py
│   ├── threatfox.py
│   ├── malwarebazaar.py
│   ├── hybrid_analysis.py
│   ├── dnsdumpster.py
│   ├── mxtoolbox.py              # MxToolBox DNS/blacklist/mail lookups
│   ├── whoxy.py                  # Whoxy WHOIS + reverse WHOIS
│   ├── ransomware_live.py        # Ransomware.live victim search
│   ├── path_prober.py            # Path Probe HTTP scanner (parallel via ThreadPoolExecutor)
│   ├── nvd.py                    # NVD / CISA KEV / MITRE cveawg client (CVE panel data layer)
│   ├── gemini.py                 # Google Gemini AI client
│   └── groq.py                   # Groq AI client
│
├── ui/                           # Streamlit UI components
│   ├── styles.py                 # Global CSS & theme
│   └── components/
│       ├── drawer.py             # API key drawer sidebar
│       ├── ioc_card.py           # Per-IOC result card
│       ├── ai_panel.py           # AI ticket generation panel
│       ├── cve_panel.py          # CVE details panel (NVD + CISA KEV, lazy-loaded)
│       ├── path_probe_panel.py   # Path Probe UI (domain + bulk paths + cleaner checkbox)
│       ├── bug_report.py         # Bug report / feature request dialog → Telegram
│       ├── note_popup.py         # ⓘ Notes dialog (landing-page notes from header)
│       ├── timing_popup.py       # ⏱ Timing dialog (per-provider + AI breakdown)
│       ├── tab_switcher.py       # Hidden Streamlit buttons for header tab switching
│       ├── popup_state.py        # Shared dialog/popup session-state helpers
│       ├── map.py                # Interactive OSM map builder
│       └── output_renderer.py    # Notes / Table / JSON / Shareable output
│
├── docs/                         # Provider integration & module design documentation
│   ├── virustotal.md
│   ├── urlscan.md
│   ├── abuseipdb.md
│   ├── shodan.md
│   ├── threatfox.md
│   ├── malwarebazaar.md
│   ├── hybrid_analysis.md
│   ├── dnsdumpster.md
│   ├── mxtoolbox.md
│   ├── whoxy.md
│   ├── ransomware_live.md
│   ├── gemini.md
│   ├── groq.md
│   ├── threat_state_level_verdict.md      # Threat state / level / verdict reference
│   ├── process_analyzer.md                # How the process/filepath module works
│   ├── cmdline_analyzer.md                # How the command-line module works
│   └── waf_payload_analyzer.md            # WAF payload module design record - shipped
│
├── image/                        # Screenshots for README documentation
│   ├── Homepage.jpeg
│   ├── Providers.jpeg
│   ├── Options.jpeg
│   ├── Ticket note ready output.jpeg
│   ├── AI Description result.jpeg
│   ├── Threat Analysis 1.jpeg
│   ├── Threat Analysis 2.jpeg
│   ├── Threat Analysis 3.jpeg
│   ├── Threat Analysis 4.jpeg
│   ├── Multiple diffrent IOC with Auto IOC detector and Auto Provider choose.jpeg
│   ├── multiple IOC results.jpeg
│   └── multiple provider output.jpeg
│
└── tests/                        # 900+ tests - `python -m pytest`
    ├── fixtures/
    │   ├── cmdline_corpus.json   # Calibration corpus: 30 known-bad / 32 known-good
    │   ├── process_corpus.json   # Calibration corpus: 14 known-bad / 28 known-good
    │   └── waf_corpus.json       # Calibration corpus: 28 known-bad / 20 known-good
    ├── test_abuseipdb_processing.py
    ├── test_ai_panel.py
    ├── test_cache_wrappers.py
    ├── test_cmdline_analyzer.py
    ├── test_cmdline_calibration.py      # False-positive regression gate
    ├── test_cmdline_deobfuscator.py
    ├── test_cmdline_integration.py
    ├── test_cmdline_lolbas_layer4.py
    ├── test_cmdline_parser.py
    ├── test_cmdline_sigma_layer5.py
    ├── test_crs_matching.py
    ├── test_crs_patterns.py
    ├── test_cve_fingerprints.py
    ├── test_cve_panel_copy.py
    ├── test_decode_common.py
    ├── test_defang_display.py
    ├── test_dnsdumpster_processing.py
    ├── test_http_helpers.py
    ├── test_hybrid_analysis_provider.py
    ├── test_infra_classifier.py
    ├── test_ioc_card.py
    ├── test_lolbas_lookup.py
    ├── test_malwarebazaar_provider.py
    ├── test_nvd_provider.py
    ├── test_orchestrator.py
    ├── test_parser_schemeless_url.py
    ├── test_path_prober.py
    ├── test_pipeline.py
    ├── test_process_analyzer.py
    ├── test_process_calibration.py      # False-positive regression gate
    ├── test_process_integration.py
    ├── test_shodan_internetdb.py
    ├── test_sigma_pairs.py
    ├── test_threat_analysis.py
    ├── test_urlscan_processing.py
    ├── test_verdict_authority.py
    ├── test_virustotal_batch.py
    ├── test_virustotal_url_scheme.py
    ├── test_waf_calibration.py          # False-positive regression gate
    ├── test_waf_consistency.py          # Verdict/flag agreement cross-checks
    ├── test_waf_payload_analyzer.py
    ├── test_waf_payload_integration.py
    └── test_waf_payload_parser.py
```
