# IOC Router

![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=flat&logo=streamlit&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![Threat Intelligence](https://img.shields.io/badge/Threat_Intelligence-multi--source-red)
![AI Powered](https://img.shields.io/badge/AI_Powered-Gemini_%2B_Groq-blue)
[![Live Demo](https://img.shields.io/badge/Live_Demo-ioc--router-FF4B4B?style=flat&logo=streamlit&logoColor=white)](https://ioc-router.streamlit.app)

IOC Router is a multi-source threat intelligence platform built for SOC analysts. Paste one or more suspicious indicators - IPs, domains, URLs, file hashes, emails, or bare keywords - and get an enriched verdict aggregated from up to 11 threat intel providers, complete with severity-rated flags, MITRE ATT&CK mappings, geolocation, and an AI-generated incident ticket.

Access from: [https://ioc-router.streamlit.app](https://ioc-router.streamlit.app)

---

## Features

### 1. Multi-source Enrichment

Queries up to 11 threat intelligence providers simultaneously - VirusTotal, URLScan, AbuseIPDB, Shodan, ThreatFox, MalwareBazaar, DNSDumpster, Hybrid Analysis, MxToolBox, Whoxy, and Ransomware.live. Each provider can be toggled individually, and results are displayed in a per-provider tabbed view showing detection scores, reputation data, and raw details from each source.

<p align="center">
  <img src="image/Providers.jpeg" width="40%">
  &nbsp;&nbsp;
  <img src="image/multiple provider output.jpeg" width="40%">
</p>

---

### 2. IOC Type Auto-detection

Automatically identifies and routes each indicator to the relevant providers - supports IPv4/IPv6, domain, URL, file hash (MD5/SHA1/SHA256), email, and keywords. When **Auto-detect** and **Auto Provider** are enabled, mixed IOC types can be submitted together in one batch and the system handles classification and routing without manual configuration.

<p align="center">
  <img src="image/Multiple diffrent IOC with Auto IOC detector and Auto Provider choose.jpeg" width="55%">
</p>

<p align="center">
  <img src="image/multiple IOC results.jpeg" width="55%">
</p>

---

### 3a. Analysis Modes: Triage, Lookup & Path Probe

Three analysis modes are available from the toolbar to match different SOC workflows:

- **Triage** *(default)*: incident-focused analysis using the full threat-intel provider set (VirusTotal, URLScan, AbuseIPDB, Shodan, ThreatFox, MalwareBazaar, DNSDumpster, Hybrid Analysis, Ransomware.live). MxToolBox and the Keyword group are excluded to keep the output focused on verdict-relevant signals.
- **Lookup**: lightweight reputation/infrastructure check using a minimal provider subset: IP → VirusTotal + AbuseIPDB + MxToolBox, Domain/URL → Shodan + MxToolBox, Email → MxToolBox. Useful when you only need a quick sanity check without the full ticket-grade analysis.
- **Path Probe**: active WAF / path-existence scanner. Replaces the IOC card with a domain + bulk-paths input that fires parallel HTTP requests and classifies each response by status code (see [§3b](#3b-path-probe-waf--exists-scanner)).

#### Triage Speed (Fast / Detailed)

When **Triage** mode is active together with **Auto detect IOC & Provider**, an additional **Speed** selector becomes available:

- **Detailed** *(default)*: runs the full Triage provider set for each IOC type.
- **Fast**: runs only the highest-signal providers per type for quicker verdicts:
  - IP → VirusTotal, AbuseIPDB
  - Domain / URL → VirusTotal, URLScan, Shodan
  - Hash → VirusTotal, Hybrid Analysis

Both **Mode** and **Speed** are exposed as compact popovers in the input toolbar (and in the post-result toolbar), so analysts can switch between deep-dive and fast-triage workflows without leaving the page.

---

### 3b. Path Probe: WAF / Exists Scanner

Selectable as a third option (`Path Probe`) in the Mode popover. Switches the Input tab from passive threat-intel enrichment to **active path probing** against a single domain - useful for confirming exposed admin panels, leaked config files, or quickly mapping which routes a WAF lets through versus blocks.

**Inputs:**

- **Domain**: single target (`https://` is prepended if no scheme is given).
- **URL Paths**: bulk text area. Accepts messy formats - `["/admin"]`, `'/login'`, `"/api"`, comma-separated, newline-separated, mixed.
- **🧹 Clean input** checkbox *(directly below the paths input)*: when enabled, strips `"`, `'`, `[`, `]` and splits on both newlines and commas before scanning. Disable to preserve paths exactly as typed (newline-split only).
- **Advanced settings**: timeout (3–30 s) and concurrency (1–50 parallel workers).

**Classification rule** (per HTTP status of each path):

| Status | Class | Notes |
|---|---|---|
| 200–399 | ✅ **Confirmed** | Endpoint reachable (incl. redirects) |
| 400–403 | ✅ **Confirmed** | Endpoint exists but malformed / auth-required / forbidden - often a WAF block |
| 404–599 | ❌ **Not Confirmed** | Not found, method not allowed, rate-limited, server error |
| (network) | ⚠️ **Error** | Timeout / connection refused: reported separately, not conflated with a real 404 |

**Output:**

- Live progress bar + streaming results table during the scan.
- Full-width classification filter (`st.multiselect`) so the `confirmed` / `not_confirmed` / `error` pills stay on a single row.
- Results table with per-path Status, Class badge, Reason, response time, size, and final URL.

Source: [providers/path_prober.py](providers/path_prober.py) · UI: [ui/components/path_probe_panel.py](ui/components/path_probe_panel.py) · Tests: [tests/test_path_prober.py](tests/test_path_prober.py)

---

### 4a. Threat Flag Extraction

Extracts 100+ granular threat flags from provider responses, each labeled with a severity level (CRITICAL, HIGH, MEDIUM, LOW) and mapped to MITRE ATT&CK technique IDs. Flags are grouped by severity in collapsible sections, making it easy to triage the most critical indicators first.

Each MITRE technique id on a flag is a direct link to its ATT&CK page, and the indicator badge links to the reporting provider's page for that IOC. **Indicators are rendered defanged** (`hxxp://198[.]51[.]100[.]7/a.ps1`) - a live link to attacker infrastructure sitting in a triage UI is one stray click away from a request nobody authorised.

<p align="center">
  <img src="image/Threat Analysis 2.jpeg" width="60%">
</p>

---

### 4b. Infrastructure Classification (Shodan & VirusTotal)

Every IP enriched via **Shodan** or **VirusTotal** is auto-classified by its hosting infrastructure (ASN + AS-owner). The classification is exposed as an `infra_classification` field on each provider result and is also surfaced as a Threat Indicator flag so it factors into the overall verdict.

| Category | Trigger | Threat Indicator | Examples |
|---|---|---|---|
| 🟢 **BP** (Benign Positive) | Anycast / CDN / public DNS: by-design always legitimate | **MEDIUM** | Cloudflare (AS13335), Google DNS (AS15169 @ 8.8.8.8), Quad9 (AS19281), Akamai (AS20940), Fastly (AS54113), AWS CloudFront |
| 🟡 **FP** (False Positive prone) | Shared hosting / hyperscaler compute: confidence discount | **LOW** | DigitalOcean (AS14061), Vultr (AS20473), Hetzner (AS24940), OVH (AS16276), Contabo (AS51167), AWS EC2, GCE, Azure VM |
| 🔴 **HIGH_RISK** | Bulletproof / abuse-friendly hosting: confidence boost | **HIGH** | Proton66 / PROSPERO, Chang Way, Media Land, PQ Hosting / Selectel, AEZA Group, Flyservers, SmartApe |

**Hyperscaler refinement**: AWS / GCP / Azure share one ASN between CDN and compute services. AWS IPs are refined against the published [`ip-ranges.json`](https://ip-ranges.amazonaws.com/ip-ranges.json) feed (cached for 24h) - addresses in CloudFront subnets are classified as **BP**, everything else on AS16509 falls to **FP** (EC2). Known Google Public DNS IPs (`8.8.8.8` / `8.8.4.4`) are pinned to **BP**; other AS15169 / AS8075 addresses default to **FP** (compute).

Source: [core/infra_classifier.py](core/infra_classifier.py) · Tests: [tests/test_infra_classifier.py](tests/test_infra_classifier.py)

---

### 4c. Endpoint Context Analysis: Process, Filepath & Command Line

Alerts rarely arrive as a bare indicator. The **Context** panel accepts the
endpoint fields an EDR alert actually carries - Device Action, Command Line,
File Path, Parent Process, Child Process - and two local modules analyse them
against datasets shipped in the repo. **Neither performs any network I/O**:
they are pure functions of their input plus `core/data/`, so they cost no API
budget and work with every provider key absent.

Every field is independent and optional. A run can proceed on endpoint context
alone, with the IOC box empty.

| Layer | Question answered | Dataset |
|---|---|---|
| **Identity** | Is this binary really what its name claims? Path-baseline whitelist plus Levenshtein typosquat detection (`scvhost.exe` vs `svchost.exe`), including extension swaps | `known_system_processes.json` (66) |
| **Dual-use** | Is the binary documented as abusable? | `lolbas_binaries.json` (240) |
| **Pairing** | Is this parent→child combination known-suspicious? Sigma-derived | `sigma_parent_child_pairs.json` (1,874) |
| **Command structure** | What does this command line actually *do*? Tokenizer for both cmd.exe and PowerShell | `cmd_internal_commands.json` (45) |
| **Deobfuscation** | What does it decode to? | - |
| **Suspicious switches** | Does it use known evasion switches? | `suspicious_cmdline_keywords.json` (34) |
| **Argument confirmation** | Do the arguments match a *documented* LOLBAS abuse pattern, not just a dual-use binary? | `lolbas_commands.json` (105 binaries / 165 patterns) |
| **Detection rules** | Does it match a Sigma CommandLine rule? | `sigma_cmdline_patterns.json` (1,409) |
| **Entropy** | Unrecognised encoding nothing else caught? | - |

The command line breakdown, deobfuscation, verdict and corroboration rules, and
calibration results are documented in
[docs/cmdline_analyzer.md](docs/cmdline_analyzer.md) and
[docs/process_analyzer.md](docs/process_analyzer.md).

Source: [core/process_analyzer.py](core/process_analyzer.py) ·
[core/cmdline_analyzer.py](core/cmdline_analyzer.py) ·
[core/cmdline_parser.py](core/cmdline_parser.py) ·
[core/cmdline_deobfuscator.py](core/cmdline_deobfuscator.py) ·
Plans: [docs/process_analyzer.md](docs/process_analyzer.md) ·
[docs/cmdline_analyzer.md](docs/cmdline_analyzer.md)

---

### 4d. WAF Payload Analysis: SQLi / XSS / RCE / LFI / SSRF Detection

A dedicated **WAF Payload** field sits in the Context panel beside Command
Line - one payload per line, optionally prefixed with a request path
(`/login | ' OR '1'='1`). Like the process and command-line modules, this is
**pure local analysis with no network I/O and nothing ever submitted to any
provider**.

| Layer | What it does | Dataset |
|---|---|---|
| **Decode** | Shared decoder (percent-encoding, HTML entities, `\uXXXX`/`\xNN`, base64), reused from the command-line module via `core/decode_common.py` with web-specific parameters | - |
| **CRS matching** | Payload matched against an extracted OWASP CRS rule subset - SQLi, XSS, RCE, LFI, RFI, SSRF, protocol-anomaly categories - after replaying each rule's own transformation chain | `crs_patterns.json` (183 rules) |
| **CVE fingerprinting** | Curated, hand-picked signatures for mass-exploited CVEs (Log4Shell, Spring4Shell, ProxyShell, ...) that have no benign reason to appear in traffic, cross-referenced against NVD + CISA KEV | `cve_fingerprints.json` |
| **Recon path probe** | Request path matched against paths scanners probe for (`/.env`, `/.git/config`, `/wp-admin`, `/actuator`, backup files, ...). Moves the Threat State to Reconnaissance; never changes the verdict | `recon_paths.json` |

In the Threat Analysis panel, a recon probe lands on **Reconnaissance** (Low), and any exploit payload lands on **Exploitation** (Medium), blocked or not. A WAF finding alone never reaches Execution. See [Threat State, Level, and Verdict](docs/threat_state_level_verdict.md).

The verdict ladder, integration points, and calibration results are documented
in [docs/waf_payload_analyzer.md](docs/waf_payload_analyzer.md).

Source: [core/waf_payload_analyzer.py](core/waf_payload_analyzer.py) ·
[core/waf_payload_parser.py](core/waf_payload_parser.py) ·
[core/crs_matcher.py](core/crs_matcher.py) ·
[core/crs_transforms.py](core/crs_transforms.py) ·
[core/cve_fingerprint.py](core/cve_fingerprint.py) ·
Design record: [docs/waf_payload_analyzer.md](docs/waf_payload_analyzer.md)

---

### 5a. Verdict Aggregation

Produces a final verdict per IOC - **Malicious**, **Suspicious**, **Unknown**, or **Benign** - based on consensus across all queried providers. The ticket notes output includes a session-level summary (total IOCs, count per verdict) followed by a per-IOC breakdown listing each provider's finding and a plain-language conclusion.

<p align="center">
  <img src="image/Ticket note ready output.jpeg" width="60%">
</p>

---

### 5b. Numeric Confidence Scoring (0–100)

In addition to the qualitative verdict, each IOC is assigned a numeric **Confidence Score** on a 0.0–100.0 scale, computed from a weighted blend of provider signals:

| Provider | Weight | Signal Normalized From |
|---|---|---|
| VirusTotal | 0.30 | engine ratio (60%) + reputation (20%) + community votes (20%) |
| AbuseIPDB | 0.20 | `abuseConfidenceScore` + report volume |
| ThreatFox | 0.20 | `confidence_level` (High / Medium / Low) |
| Shodan | 0.15 | malicious tags, open-port risk, CVE presence |
| Hybrid Analysis | 0.10 | sandbox threat score / verdict |
| MalwareBazaar | 0.05 | known-sample match |

Providers that return no data are excluded and the remaining weights are renormalized so the score never penalizes a missing source. The result is then nudged by [infra classification](#4b-infrastructure-classification-shodan--virustotal): **HIGH_RISK** ASNs add a confidence boost, **FP**-prone hyperscalers apply a discount, and **BP** anycast/CDN ranges enforce a soft ceiling.

**Session-level aggregation** - the highest-scoring IOC drives a session-wide threat panel rendered above the result cards (with verdict distribution pills), and each IOC card carries its own score badge, per-provider bar chart, and infra note. Numeric scores are also written to the JSON output as `ConfidenceScore`, `ConfidenceLabel`, `ProviderScores`, `ActiveProviders`, `InfraNote`, and `VerdictFromScore` fields per row.

Source: [ioc/confidence_scorer.py](ioc/confidence_scorer.py)

---

### 6. Threat State, Level, and Verdict

Determines the threat lifecycle state and assigns a threat level (Low → Very High), adjusted for asset criticality when the **Critical** flag is set. State names follow the [Unified Kill Chain](https://www.unifiedkillchain.com/) phases:

| Threat State | Meaning | Base Level |
|---|---|---|
| Exposure | No attack activity; asset posture only (outside UKC) | Low |
| Reconnaissance | Scanning or probing for sensitive paths | Low |
| Delivery | Phishing, exploit reputation, or an attack blocked by controls | Low |
| Exploitation | Web exploit payload (SQLi, XSS, LFI, ...), blocked or not | Medium |
| Execution | Malware executed or C2 communication | Medium |
| Privilege Escalation | Attacker gained higher privileges | High |
| Lateral Movement | Attacker spreading to other systems | High |
| Persistence | Attacker established a survival mechanism | High |
| Impact | Data exfiltration or service disruption/encryption | Very High |

The threat analysis also surfaces a human-readable risk label, a list of reasons driving the assessment, all relevant MITRE ATT&CK tactics observed across providers, key evidence per IOC (malware family, domain age, open ports, first seen), and direct source links back to each provider's result page.

See [Threat State, Level, and Verdict](docs/threat_state_level_verdict.md) for a full breakdown of each state, level, and verdict.

<p align="center">
  <img src="image/Threat Analysis 1.jpeg" width="42%">
  &nbsp;&nbsp;
  <img src="image/Threat Analysis 2.jpeg" width="42%">
</p>

<p align="center">
  <img src="image/Threat Analysis 3.jpeg" width="42%">
  &nbsp;&nbsp;
  <img src="image/Threat Analysis 4.jpeg" width="42%">
</p>

---

### 7. Geolocation & Mapping

Resolves IP addresses to country, city, ISP, and ASN, and plots them on an interactive OpenStreetMap map embedded in the result card. Geolocation context is also surfaced in the key evidence and ticket note outputs alongside other per-IOC metadata.

---

### 8. AI Ticket Generation

Auto-generates a human-readable incident narrative using Google Gemini or Groq, grounded in the extracted flags, raw provider logs, and analyst-supplied context (alert name, host, host IP, detection time, device action, command line, file path, parent/child process, and free-text context). The AI provider and model can be selected via the Options panel before running the analysis.

The prompt carries the [endpoint analysis](#4c-endpoint-context-analysis-process-filepath--command-line) findings verbatim - including the decoded command line and the transform chain that produced it - alongside an explicit **"checks NOT performed"** list, so the narrative never implies a field was cleared when the analyst simply left it blank.

Additional AI panel capabilities:

- **Tone control**: pick between *High level language* (for IT professionals without a security background), *SOC L1 concise*, or *More formal* narrative styles.
- **Ransomware.live correlation** - victim/leak-site hits are fed into the prompt so the ticket calls out known ransomware exposure alongside other provider findings.
- **Analyst override**: adjust the final State / Level / Verdict directly in the panel; the change can optionally be pushed to Telegram for audit (requires `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`).
- **Bug report / feature request dialog**: built-in form (see [ui/components/bug_report.py](ui/components/bug_report.py)) sends feedback to the same Telegram channel.

<p align="center">
  <img src="image/Options.jpeg" width="40%">
  &nbsp;&nbsp;
  <img src="image/AI Description result.jpeg" width="40%">
</p>

---

### 9. Multiple Output Formats

Results can be exported in four formats selectable from the Options panel - **Ticket Notes** (structured plain text per IOC, paste-ready for SIEM tickets), **Table** (tabular view with verdict, confidence, evidence, and sources), **JSON** (raw structured output for downstream processing), and **Shareable Text** (Base64-encoded summary, copy-to-clipboard ready).

<p align="center">
  <img src="image/Homepage.jpeg" width="80%">
</p>

---

### 10. CVE Lookup Panel

A dedicated panel surfaces recent CVEs from the **NVD API v2**, enriched with the **CISA KEV** catalog and the **MITRE cveawg** record for each CVE. Filtering, common-app detection, enrichment, caching, and
the copy formatter are documented in [docs/cve_panel.md](docs/cve_panel.md).

Source: [ui/components/cve_panel.py](ui/components/cve_panel.py) (rendering) · [providers/nvd.py](providers/nvd.py) (NVD/KEV/MITRE client & parsing) · Tests: [tests/test_cve_panel_copy.py](tests/test_cve_panel_copy.py), [tests/test_nvd_provider.py](tests/test_nvd_provider.py)

---

## Supported IOC Types

| Type | Examples |
|------|---------|
| IPv4 / IPv6 | `192.168.1.1`, `2001:db8::1` |
| Domain | `malicious-site.com` |
| URL | `http://phishing.example.com/login` |
| File Hash | MD5, SHA1, SHA256 |
| Email | `attacker@domain.com` |
| Keyword | `evilcorp`: triggers Whoxy reverse WHOIS by keyword |

---

## Threat Intelligence Providers

| Provider | Supported IOCs | Key Data |
|----------|---------------|----------|
| [**VirusTotal**](docs/virustotal.md) | IP, Domain, URL, Hash | 70+ AV engine results, YARA/SIGMA hits, sandbox behavior, reputation |
| [**URLScan.io**](docs/urlscan.md) | URL, Domain | Screenshot, redirect chain, credential form detection, obfuscation |
| [**AbuseIPDB**](docs/abuseipdb.md) | IP, Domain, URL | Abuse confidence score, report categories (DDoS, SSH brute force, phishing, etc.) |
| [**Shodan**](docs/shodan.md) | IP | Open ports, CVEs, service tags (tor, vpn, honeypot, etc.) |
| [**ThreatFox**](docs/threatfox.md) | IP, Domain, URL, Hash | Malware family, C2 infrastructure, confidence level |
| [**MalwareBazaar**](docs/malwarebazaar.md) | Hash | File signature, type, YARA rules, known sample metadata |
| [**DNSDumpster**](docs/dnsdumpster.md) | Domain, URL | Subdomains, A/MX/NS records, SPF configuration |
| [**Hybrid Analysis**](docs/hybrid_analysis.md) | IP, Domain, URL, Hash | Sandbox verdict, threat score, malware family, network IOCs, MITRE behavior |
| [**MxToolBox**](docs/mxtoolbox.md) | IP, Domain, URL, Email | Blacklist checks, PTR/MX/DNS/SPF/DMARC lookups, HTTP reachability, mail security posture |
| [**Whoxy**](docs/whoxy.md) | Domain, URL, Keyword | WHOIS registration data, registrant email/company, reverse WHOIS by registrant or keyword |
| [**Ransomware.live**](docs/ransomware_live.md) | Domain, URL, Keyword | Victim database search - ransomware group, incident date, breach records from dark-web leak sites |

---

## Analysis Pipeline

```
Input IOCs  +  Endpoint context (command line, filepath, parent/child process, WAF payload)
    ↓
[Parser]          - type detection, normalization, deduplication
    ↓
[Local Analysis]  - process/filepath identity + command-line decode & matching
                    + WAF payload CRS/CVE-fingerprint matching
                    (no network; emits flags and new IOC candidates)
    ↓
[Mode Filter]     - Triage (full) / Lookup (minimal) + Triage Speed (Fast/Detailed)
    ↓
[Provider Router] - each IOC is sent only to relevant providers
                    (including indicators recovered from a decoded payload)
    ↓
[Flag Extraction] - 100+ threat flags extracted, severity-rated, MITRE-mapped
    ↓
[Verdict Engine]  - multi-source aggregation → Malicious / Suspicious / Unknown / Benign
    ↓
[Threat Analysis] - threat state + level, asset criticality adjustment
    ↓
[Geolocation]     - IP → geo coordinates → interactive map
    ↓
[AI Generation]   - Gemini / Groq generates an incident ticket narrative
    ↓
Output (Notes / Table / JSON / Shareable Text)
```

---

## Output Formats

| Format | Description |
|--------|-------------|
| **Ticket Notes** | Structured human-readable text per IOC: suitable for copy-paste into SIEM tickets |
| **Table** | Tabular view with artifact, type, verdict, confidence, evidence, and sources |
| **JSON** | Raw structured output for downstream processing or logging |
| **Shareable Text** | Base64-encoded summary, copy-to-clipboard ready |

---

## Documentation

Module and provider references, plus the full project structure, live in
[docs/README.md](docs/README.md).

---

## Requirements

- Python 3.10 or higher
- pip
- API keys for the providers you want to use (at minimum `VT_KEY` is recommended)

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/your-username/ioc-router.git
cd ioc-router
```

### 2. Configure API keys

Create a `.env` file in the project root:

```env
VT_KEY=your_virustotal_key
URLSCAN_KEY=your_urlscan_key
ABUSEIPDB_KEY=your_abuseipdb_key
SHODAN_KEY=your_shodan_key
THREATFOX_KEY=your_threatfox_key
MALWAREBAZAAR_KEY=your_malwarebazaar_key
DNSDUMPSTER_KEY=your_dnsdumpster_key
HYBRID_ANALYSIS_KEY=your_hybrid_analysis_key
MXTOOLBOX_KEY=your_mxtoolbox_key
WHOXY_KEY=your_whoxy_key
RANSOMWARE_LIVE_KEY=your_ransomware_live_key
GEMINI_KEY=your_gemini_key
GEMINI_KEY_BACKUP=your_gemini_backup_key          # optional
GEMINI_MODEL=gemini-2.5-flash                     # optional, this is the default
GEMINI_API_VERSION=v1                             # optional, this is the default
GROQ_KEY=your_groq_key
CVE_NVD_KEY=your_nvd_api_key                      # optional, raises NVD rate limit
```

> API keys can also be entered directly in the app UI via the key drawer - they are stored in session only and never written to disk.

### 3. Run the app

```bash
streamlit run app.py
```

The app will be available at:

```
http://localhost:8501
```
