# IOC Router

![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=flat&logo=streamlit&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![Threat Intelligence](https://img.shields.io/badge/Threat_Intelligence-multi--source-red)
![AI Powered](https://img.shields.io/badge/AI_Powered-Gemini_%2B_Groq-blue)
[![Live Demo](https://img.shields.io/badge/Live_Demo-ioc--router-FF4B4B?style=flat&logo=streamlit&logoColor=white)](https://ioc-router.streamlit.app)

IOC Router is a multi-source threat intelligence platform built for SOC analysts. Paste one or more suspicious indicators — IPs, domains, URLs, file hashes, emails, or bare keywords — and get an enriched verdict aggregated from up to 11 threat intel providers, complete with severity-rated flags, MITRE ATT&CK mappings, geolocation, and an AI-generated incident ticket.

Access from: [https://ioc-router.streamlit.app](https://ioc-router.streamlit.app)

---

## Features

### 1. Multi-source Enrichment

Queries up to 11 threat intelligence providers simultaneously — VirusTotal, URLScan, AbuseIPDB, Shodan, ThreatFox, MalwareBazaar, DNSDumpster, Hybrid Analysis, MxToolBox, Whoxy, and Ransomware.live. Each provider can be toggled individually, and results are displayed in a per-provider tabbed view showing detection scores, reputation data, and raw details from each source.

<p align="center">
  <img src="image/Providers.jpeg" width="40%">
  &nbsp;&nbsp;
  <img src="image/multiple provider output.jpeg" width="40%">
</p>

---

### 2. IOC Type Auto-detection

Automatically identifies and routes each indicator to the relevant providers — supports IPv4/IPv6, domain, URL, file hash (MD5/SHA1/SHA256), email, and keywords. When **Auto-detect** and **Auto Provider** are enabled, mixed IOC types can be submitted together in one batch and the system handles classification and routing without manual configuration.

<p align="center">
  <img src="image/Multiple diffrent IOC with Auto IOC detector and Auto Provider choose.jpeg" width="55%">
</p>

<p align="center">
  <img src="image/multiple IOC results.jpeg" width="55%">
</p>

---

### 3. Analysis Modes — Triage, Lookup & Path Probe

Three analysis modes are available from the toolbar to match different SOC workflows:

- **Triage** *(default)* — incident-focused analysis using the full threat-intel provider set (VirusTotal, URLScan, AbuseIPDB, Shodan, ThreatFox, MalwareBazaar, DNSDumpster, Hybrid Analysis, Ransomware.live). MxToolBox and the Keyword group are excluded to keep the output focused on verdict-relevant signals.
- **Lookup** — lightweight reputation/infrastructure check using a minimal provider subset: IP → VirusTotal + AbuseIPDB + MxToolBox, Domain/URL → Shodan + MxToolBox, Email → MxToolBox. Useful when you only need a quick sanity check without the full ticket-grade analysis.
- **Path Probe** — active WAF / path-existence scanner. Replaces the IOC card with a domain + bulk-paths input that fires parallel HTTP requests and classifies each response by status code (see [§3b](#3b-path-probe--waf--exists-scanner)).

#### Triage Speed (Fast / Detailed)

When **Triage** mode is active together with **Auto detect IOC & Provider**, an additional **Speed** selector becomes available:

- **Detailed** *(default)* — runs the full Triage provider set for each IOC type.
- **Fast** — runs only the highest-signal providers per type for quicker verdicts:
  - IP → VirusTotal, AbuseIPDB
  - Domain / URL → VirusTotal, URLScan, Shodan
  - Hash → VirusTotal, Hybrid Analysis

Both **Mode** and **Speed** are exposed as compact popovers in the input toolbar (and in the post-result toolbar), so analysts can switch between deep-dive and fast-triage workflows without leaving the page.

---

### 3b. Path Probe — WAF / Exists Scanner

Selectable as a third option (`Path Probe`) in the Mode popover. Switches the Input tab from passive threat-intel enrichment to **active path probing** against a single domain — useful for confirming exposed admin panels, leaked config files, or quickly mapping which routes a WAF lets through versus blocks.

**Inputs:**

- **Domain** — single target (`https://` is prepended if no scheme is given).
- **URL Paths** — bulk text area. Accepts messy formats — `["/admin"]`, `'/login'`, `"/api"`, comma-separated, newline-separated, mixed.
- **🧹 Clean input** checkbox *(directly below the paths input)* — when enabled, strips `"`, `'`, `[`, `]` and splits on both newlines and commas before scanning. Disable to preserve paths exactly as typed (newline-split only).
- **Advanced settings** — timeout (3–30 s) and concurrency (1–50 parallel workers).

**Classification rule** (per HTTP status of each path):

| Status | Class | Notes |
|---|---|---|
| 200–399 | ✅ **Confirmed** | Endpoint reachable (incl. redirects) |
| 400–403 | ✅ **Confirmed** | Endpoint exists but malformed / auth-required / forbidden — often a WAF block |
| 404–599 | ❌ **Not Confirmed** | Not found, method not allowed, rate-limited, server error |
| (network) | ⚠️ **Error** | Timeout / connection refused — reported separately, not conflated with a real 404 |

**Output:**

- Live progress bar + streaming results table during the scan.
- Full-width classification filter (`st.multiselect`) so the `confirmed` / `not_confirmed` / `error` pills stay on a single row.
- Results table with per-path Status, Class badge, Reason, response time, size, and final URL.

Source: [providers/path_prober.py](providers/path_prober.py) · UI: [ui/components/path_probe_panel.py](ui/components/path_probe_panel.py) · Tests: [tests/test_path_prober.py](tests/test_path_prober.py)

---

### 4. Threat Flag Extraction

Extracts 100+ granular threat flags from provider responses, each labeled with a severity level (CRITICAL, HIGH, MEDIUM, LOW) and mapped to MITRE ATT&CK technique IDs. Flags are grouped by severity in collapsible sections, making it easy to triage the most critical indicators first.

<p align="center">
  <img src="image/Threat Analysis 2.jpeg" width="60%">
</p>

---

### 4b. Infrastructure Classification (Shodan & VirusTotal)

Every IP enriched via **Shodan** or **VirusTotal** is auto-classified by its hosting infrastructure (ASN + AS-owner). The classification is exposed as an `infra_classification` field on each provider result and is also surfaced as a Threat Indicator flag so it factors into the overall verdict.

| Category | Trigger | Threat Indicator | Examples |
|---|---|---|---|
| 🟢 **BP** (Benign Positive) | Anycast / CDN / public DNS — by-design always legitimate | **MEDIUM** | Cloudflare (AS13335), Google DNS (AS15169 @ 8.8.8.8), Quad9 (AS19281), Akamai (AS20940), Fastly (AS54113), AWS CloudFront |
| 🟡 **FP** (False Positive prone) | Shared hosting / hyperscaler compute — confidence discount | **LOW** | DigitalOcean (AS14061), Vultr (AS20473), Hetzner (AS24940), OVH (AS16276), Contabo (AS51167), AWS EC2, GCE, Azure VM |
| 🔴 **HIGH_RISK** | Bulletproof / abuse-friendly hosting — confidence boost | **HIGH** | Proton66 / PROSPERO, Chang Way, Media Land, PQ Hosting / Selectel, AEZA Group, Flyservers, SmartApe |

**Hyperscaler refinement**: AWS / GCP / Azure share one ASN between CDN and compute services. AWS IPs are refined against the published [`ip-ranges.json`](https://ip-ranges.amazonaws.com/ip-ranges.json) feed (cached for 24h) — addresses in CloudFront subnets are classified as **BP**, everything else on AS16509 falls to **FP** (EC2). Known Google Public DNS IPs (`8.8.8.8` / `8.8.4.4`) are pinned to **BP**; other AS15169 / AS8075 addresses default to **FP** (compute).

Source: [core/infra_classifier.py](core/infra_classifier.py) · Tests: [tests/test_infra_classifier.py](tests/test_infra_classifier.py)

---

### 5. Verdict Aggregation

Produces a final verdict per IOC — **Malicious**, **Suspicious**, **Unknown**, or **Benign** — based on consensus across all queried providers. The ticket notes output includes a session-level summary (total IOCs, count per verdict) followed by a per-IOC breakdown listing each provider's finding and a plain-language conclusion.

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

**Session-level aggregation** — the highest-scoring IOC drives a session-wide threat panel rendered above the result cards (with verdict distribution pills), and each IOC card carries its own score badge, per-provider bar chart, and infra note. Numeric scores are also written to the JSON output as `ConfidenceScore`, `ConfidenceLabel`, `ProviderScores`, `ActiveProviders`, `InfraNote`, and `VerdictFromScore` fields per row.

Source: [ioc/confidence_scorer.py](ioc/confidence_scorer.py)

---

### 6. Threat State & Level

Determines the threat lifecycle state (e.g. Reconnaissance, Persistence, Impact) and assigns a threat level (Low → Very High), adjusted for asset criticality when the **Critical** flag is set. Also surfaces a human-readable risk label, a list of reasons driving the assessment, all relevant MITRE ATT&CK tactics observed across providers, key evidence per IOC (malware family, domain age, open ports, first seen), and direct source links back to each provider's result page.

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

Auto-generates a human-readable incident narrative using Google Gemini or Groq, grounded in the extracted flags, raw provider logs, and analyst-supplied context (alert name, host, host IP, detection time, device action, parent/child process, and free-text context). The AI provider and model can be selected via the Options panel before running the analysis.

Additional AI panel capabilities:

- **Tone control** — pick between *High level language* (for IT professionals without a security background), *SOC L1 concise*, or *More formal* narrative styles.
- **Ransomware.live correlation** — victim/leak-site hits are fed into the prompt so the ticket calls out known ransomware exposure alongside other provider findings.
- **Analyst override** — adjust the final State / Level / Verdict directly in the panel; the change can optionally be pushed to Telegram for audit (requires `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`).
- **Bug report / feature request dialog** — built-in form (see [ui/components/bug_report.py](ui/components/bug_report.py)) sends feedback to the same Telegram channel.

<p align="center">
  <img src="image/Options.jpeg" width="40%">
  &nbsp;&nbsp;
  <img src="image/AI Description result.jpeg" width="40%">
</p>

---

### 9. Multiple Output Formats

Results can be exported in four formats selectable from the Options panel — **Ticket Notes** (structured plain text per IOC, paste-ready for SIEM tickets), **Table** (tabular view with verdict, confidence, evidence, and sources), **JSON** (raw structured output for downstream processing), and **Shareable Text** (Base64-encoded summary, copy-to-clipboard ready).

<p align="center">
  <img src="image/Homepage.jpeg" width="80%">
</p>

---

### 10. CVE Lookup Panel

A dedicated panel surfaces recent CVEs from the **NVD API v2**, enriched with the **CISA KEV** catalog and the **MITRE cveawg** record for each CVE. Key behaviors:

- **Lazy loading** — 10 entries per page so large NVD windows stay responsive.
- **Severity filtering** — pick from `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `Common`, `ALL`, or a custom `Select` set.
- **Common-app detection** — vendor/product matching against a curated keyword list (Cisco, Fortinet, Palo Alto, VMware, Microsoft, Chrome, Zoom, Slack, WhatsApp Desktop, Telegram Desktop, etc.) so SOC-relevant CVEs surface first.
- **MITRE enrichment** — pulls vendor / product / affected version range from `affected[]` and a short CAPEC attack-pattern label from `impacts[]`, plus the **CWE-N** id from the NVD weaknesses list. Records are fetched in parallel (12 workers) and cached for 24 hours.
- **KEV expansion** — when a CVE is in the CISA KEV catalog, the card carries the KEV `shortDescription`, `requiredAction`, `knownRansomwareCampaignUse`, and `vulnerabilityName` fields alongside the standard NVD data.
- **NVD-aware caching** — 1-hour TTL on NVD + KEV responses keeps the rolling window reasonably fresh while easing rate-limit pressure; MITRE responses use a separate 24h TTL. Optional `CVE_NVD_KEY` env variable injects an NVD API key for higher rate limits (50 req/30s vs 5).
- **Copy formatter** — one-click copy formatted for WhatsApp/SOC handoff: bold styling, raw CVE URLs, and grouped severity output.

Source: [ui/components/cve_panel.py](ui/components/cve_panel.py) · Tests: [tests/test_cve_panel_copy.py](tests/test_cve_panel_copy.py)

---

### 11. Run Timing & Performance Tracking

Every enrichment run records per-provider latency and total wall time, and the AI ticket call tracks its own elapsed duration (`ai_timing`). These timings are surfaced in the JSON output under the `timings` key (`providers`, `providers_total`) — useful for spotting slow providers and tracking AI cost/performance over time.

---

## Supported IOC Types

| Type | Examples |
|------|---------|
| IPv4 / IPv6 | `192.168.1.1`, `2001:db8::1` |
| Domain | `malicious-site.com` |
| URL | `http://phishing.example.com/login` |
| File Hash | MD5, SHA1, SHA256 |
| Email | `attacker@domain.com` |
| Keyword | `evilcorp` — triggers Whoxy reverse WHOIS by keyword |

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
| [**Ransomware.live**](docs/ransomware_live.md) | Domain, URL, Keyword | Victim database search — ransomware group, incident date, breach records from dark-web leak sites |

---

## Analysis Pipeline

```
Input IOCs
    ↓
[Parser]          — type detection, normalization, deduplication
    ↓
[Mode Filter]     — Triage (full) / Lookup (minimal) + Triage Speed (Fast/Detailed)
    ↓
[Provider Router] — each IOC is sent only to relevant providers
    ↓
[Flag Extraction] — 100+ threat flags extracted, severity-rated, MITRE-mapped
    ↓
[Verdict Engine]  — multi-source aggregation → Malicious / Suspicious / Unknown / Benign
    ↓
[Threat Analysis] — threat state + level, asset criticality adjustment
    ↓
[Geolocation]     — IP → geo coordinates → interactive map
    ↓
[AI Generation]   — Gemini / Groq generates an incident ticket narrative
    ↓
Output (Notes / Table / JSON / Shareable Text)
```

---

## Output Formats

| Format | Description |
|--------|-------------|
| **Ticket Notes** | Structured human-readable text per IOC — suitable for copy-paste into SIEM tickets |
| **Table** | Tabular view with artifact, type, verdict, confidence, evidence, and sources |
| **JSON** | Raw structured output for downstream processing or logging |
| **Shareable Text** | Base64-encoded summary, copy-to-clipboard ready |

---

## Project Structure

```
ioc-router/
├── app.py                        # Streamlit entry point
├── config.py                     # API key config & environment loading
├── requirements.txt
│
├── core/                         # Orchestration & shared utilities
│   ├── orchestrator.py           # Async provider dispatch & result aggregation
│   ├── cache.py                  # In-memory result caching
│   ├── geo.py                    # IP geolocation resolution
│   └── infra_classifier.py       # ASN-based infra classification (BP / FP / HIGH_RISK)
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
│       ├── map.py                # Interactive OSM map builder
│       └── output_renderer.py    # Notes / Table / JSON / Shareable output
│
├── docs/                         # Provider integration documentation
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
│   └── groq.md
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
└── tests/
    ├── test_abuseipdb_processing.py
    ├── test_cve_panel_copy.py
    ├── test_dnsdumpster_processing.py
    ├── test_hybrid_analysis_provider.py
    ├── test_infra_classifier.py
    ├── test_malwarebazaar_provider.py
    ├── test_path_prober.py
    ├── test_shodan_internetdb.py
    ├── test_threat_analysis.py
    └── test_urlscan_processing.py
```

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

> API keys can also be entered directly in the app UI via the key drawer — they are stored in session only and never written to disk.

### 3. Run the app

```bash
streamlit run app.py
```

The app will be available at:

```
http://localhost:8501
```
