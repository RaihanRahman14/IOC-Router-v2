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

Each MITRE technique id on a flag is a direct link to its ATT&CK page, and the indicator badge links to the reporting provider's page for that IOC. **Indicators are rendered defanged** (`hxxp://198[.]51[.]100[.]7/a.ps1`) — a live link to attacker infrastructure sitting in a triage UI is one stray click away from a request nobody authorised.

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

### 4c. Endpoint Context Analysis — Process, Filepath & Command Line

Alerts rarely arrive as a bare indicator. The **Context** panel accepts the
endpoint fields an EDR alert actually carries — Device Action, Command Line,
File Path, Parent Process, Child Process — and two local modules analyse them
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
| **Deobfuscation** | What does it decode to? | — |
| **Suspicious switches** | Does it use known evasion switches? | `suspicious_cmdline_keywords.json` (34) |
| **Argument confirmation** | Do the arguments match a *documented* LOLBAS abuse pattern, not just a dual-use binary? | `lolbas_commands.json` (105 binaries / 165 patterns) |
| **Detection rules** | Does it match a Sigma CommandLine rule? | `sigma_cmdline_patterns.json` (1,409) |
| **Entropy** | Unrecognised encoding nothing else caught? | — |

#### Command line breakdown

Rendered between the ticket-note output and the per-IOC cards: the submitted
line verbatim, the detected interpreter, the decoded form with the exact
transform chain that produced it, and the parsed base command / flags /
arguments.

Deobfuscation is **pure string rewriting — nothing is ever executed**. It folds
base64 (`-EncodedCommand`, decoded UTF-16LE first), quoted-string concatenation
`('c'+'a'+'l'+'c')`, `[char]` codes, the `-f` format operator, intra-word
backticks, percent-encoding, HTML entities and `\uXXXX` escapes — iterating to a
fixed point under hard round and size caps. Every applied step is recorded, so a
decoded string can always be traced back to its source.

Indicators recovered from a decoded payload (URLs, IPs, hashes) **join the normal
enrichment pipeline automatically** — pasting one encoded one-liner yields a
fully enriched URL row with no second analyst action. URLs found this way are
withheld from URLScan submission: publishing an attacker's URL is an outbound
disclosure the analyst did not ask for.

#### Verdicts and the corroboration rule

Both modules emit `_flag()`-shaped findings that feed the existing 100+ flag
system, Threat Analysis evidence, and the ticket narrative. Neither ever returns
**Benign** — absence of evidence is `Unknown`.

`Malicious` requires **two independent sources**, per the project's aggregation
rule. Suspicious switches and obfuscation together count as one; the second must
be a Sigma rule match or a confirmed LOLBAS abuse pattern. A Sigma rule whose
*full* original condition is satisfied across both modules in one session — the
process half supplying `Image`/`ParentImage`, the command-line half supplying
`CommandLine` — is treated as exact rather than approximate.

#### Calibration

Both modules ship a corpus and a regression gate, because a detection module
tuned only for recall looks excellent until analysts start ignoring it.

```bash
python core/scripts/try_cmdline_analyzer.py --calibrate
python core/scripts/try_cmdline_analyzer.py "powershell -nop -w hidden -enc SQBFAFgA..."
```

| Corpus | Known-bad | Known-good | Current result |
|---|---|---|---|
| `tests/fixtures/cmdline_corpus.json` | 30 | 32 | 30/30 detected, 0 unexpected flags |
| `tests/fixtures/process_corpus.json` | 14 | 28 | 14/14 as recorded, 2 documented defects |

> The known-good halves are hand-written from ordinary Windows administration,
> packaging and CI activity — **not** from any particular estate. Local habits
> differ, so the meaningful validation step is adding real command lines from
> your own closed-as-false-positive alerts to the corpus and re-running the gate.
> Four benign samples (SCCM and Intune wrappers, an administrator's
> `schtasks /create`, a `Compress-Archive` backup) legitimately reach
> `Suspicious`; they are declared in the corpus rather than suppressed.

Source: [core/process_analyzer.py](core/process_analyzer.py) ·
[core/cmdline_analyzer.py](core/cmdline_analyzer.py) ·
[core/cmdline_parser.py](core/cmdline_parser.py) ·
[core/cmdline_deobfuscator.py](core/cmdline_deobfuscator.py) ·
Plans: [docs/process_analyzer.md](docs/process_analyzer.md) ·
[docs/cmdline_analyzer.md](docs/cmdline_analyzer.md)

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

### 6. Threat State, Level, and Verdict

Determines the threat lifecycle state (e.g. Reconnaissance, Persistence, Impact) and assigns a threat level (Low → Very High), adjusted for asset criticality when the **Critical** flag is set. Also surfaces a human-readable risk label, a list of reasons driving the assessment, all relevant MITRE ATT&CK tactics observed across providers, key evidence per IOC (malware family, domain age, open ports, first seen), and direct source links back to each provider's result page.

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

The prompt carries the [endpoint analysis](#4c-endpoint-context-analysis--process-filepath--command-line) findings verbatim — including the decoded command line and the transform chain that produced it — alongside an explicit **"checks NOT performed"** list, so the narrative never implies a field was cleared when the analyst simply left it blank.

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
- **Common-app detection** — vendor/product matching against a curated keyword list (Cisco, Fortinet, Palo Alto, VMware, Microsoft, Chrome, Zoom, Slack, WhatsApp Desktop, Telegram Desktop, Check Point, CyberArk, BeyondTrust, SentinelOne, Bitdefender, Trend Micro, Aruba, Ruckus, Sangfor, Hillstone, Imperva, Riverbed, Nagios, Veeam, Tenable, WordPress, HSM nShield, Atmos Agent, Device42, XFusion, SecIron, etc.) so SOC-relevant CVEs surface first. Short/ambiguous tokens (`hp`, `edge`, `aws`, `azure`, `f5`, `linux`, `oracle`, `php`, `mysql`) are matched against vendor+product fields only to avoid false positives on unrelated CVE descriptions.
- **MITRE enrichment** — pulls vendor / product / affected version range from `affected[]` and a short CAPEC attack-pattern label from `impacts[]`, plus the **CWE-N** id from the NVD weaknesses list. Records are fetched in parallel (12 workers) and cached for 24 hours.
- **KEV expansion** — when a CVE is in the CISA KEV catalog, the card carries the KEV `shortDescription`, `requiredAction`, `knownRansomwareCampaignUse`, and `vulnerabilityName` fields alongside the standard NVD data.
- **NVD-aware caching** — 1-hour TTL on NVD + KEV responses keeps the rolling window reasonably fresh while easing rate-limit pressure; MITRE responses use a separate 24h TTL. Optional `CVE_NVD_KEY` env variable injects an NVD API key for higher rate limits (50 req/30s vs 5).
- **Copy formatter** — one-click copy formatted for WhatsApp/SOC handoff: bold styling, raw CVE URLs, and grouped severity output.

Source: [ui/components/cve_panel.py](ui/components/cve_panel.py) · Tests: [tests/test_cve_panel_copy.py](tests/test_cve_panel_copy.py)

---

### 11. Run Timing & Performance Tracking

Every enrichment run records per-provider latency and total wall time, and the AI ticket call tracks its own elapsed duration (`ai_timing`). These timings are surfaced in the JSON output under the `timings` key (`providers`, `providers_total`) — useful for spotting slow providers and tracking AI cost/performance over time.

The fixed header also exposes a **⏱ Timing** button that opens a dedicated dialog with a per-provider breakdown (elapsed seconds + IOC count), a providers subtotal, the AI (Threat Analysis) elapsed time, and the grand total — no need to open the JSON to see where a slow run went.

Source: [ui/components/timing_popup.py](ui/components/timing_popup.py)

---

### 12. Header Notes & Tab Switcher

- **ⓘ Notes popup** — a header button opens a small dialog with landing-page notes (API key requirements, provider availability, refresh tips, and dev status). Source: [ui/components/note_popup.py](ui/components/note_popup.py).
- **Header tab switcher** — the fixed header carries `Input` / `Result` / `CVE` tab buttons that forward clicks to hidden Streamlit buttons so switching stays instant even while a run is in progress. Source: [ui/components/tab_switcher.py](ui/components/tab_switcher.py).
- **Contextual help** — provider checkboxes and the Auto / Group / Speed toggles in the input toolbar now carry `help=` tooltips explaining what each option does and when to enable it.

---

### 13. Streamlit Runtime Reliability

The app ships a tuned `.streamlit/config.toml` and a small JS shim to keep long-running SOC sessions stable on Streamlit Community Cloud:

- **Aggressive ForwardMsg caching** — `minCachedMessageSize = 0` and `maxCachedMessageAge = 200` so that reconnects after Cloud sleep/wake or a transient network blip do not surface the `Cached ForwardMsg MISS` warning.
- **WebSocket compression + static serving** — `enableWebsocketCompression` and `enableStaticServing` shrink and offload large provider result payloads.
- **Fast reruns** — `runner.fastReruns = true` cancels stale script runs on rapid widget toggles so the client never holds a hash for a run that will never finish.
- **Auto-dismiss connection modal** — a MutationObserver in [app.py](app.py) detects and auto-closes any residual `Cached ForwardMsg MISS` modal, keeping the app interactive without a hard refresh.

Config: [.streamlit/config.toml](.streamlit/config.toml)

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
Input IOCs  +  Endpoint context (command line, filepath, parent/child process)
    ↓
[Parser]          — type detection, normalization, deduplication
    ↓
[Local Analysis]  — process/filepath identity + command-line decode & matching
                    (no network; emits flags and new IOC candidates)
    ↓
[Mode Filter]     — Triage (full) / Lookup (minimal) + Triage Speed (Fast/Detailed)
    ↓
[Provider Router] — each IOC is sent only to relevant providers
                    (including indicators recovered from a decoded payload)
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
├── app.py                        # Streamlit entry point (fixed header + tab/dialog JS shim)
├── config.py                     # API key config & environment loading
├── requirements.txt
├── .streamlit/
│   └── config.toml               # ForwardMsg cache tuning + WS compression for Cloud stability
│
├── core/                         # Orchestration, local analysis & shared utilities
│   ├── orchestrator.py           # Async provider dispatch & result aggregation
│   ├── cache.py                  # In-memory result caching
│   ├── geo.py                    # IP geolocation resolution
│   ├── infra_classifier.py       # ASN-based infra classification (BP / FP / HIGH_RISK)
│   ├── process_analyzer.py       # Process/filepath identity, LOLBAS, Sigma pairing
│   ├── lolbas_lookup.py          # LOLBAS dual-use lookup + abuse-command patterns
│   ├── cmdline_parser.py         # cmd.exe + PowerShell tokenizer, interpreter detection
│   ├── cmdline_deobfuscator.py   # Command-line decode (pure transforms, never executes)
│   ├── decode_common.py          # Encoding primitives shared across analysis modules
│   ├── cmdline_analyzer.py       # Keywords, entropy, Sigma/LOLBAS matching, verdict
│   │
│   ├── data/                     # Offline-generated datasets (no runtime fetches)
│   │   ├── known_system_processes.json    # Path-baseline whitelist (66)
│   │   ├── lolbas_binaries.json           # Dual-use binaries (240)
│   │   ├── lolbas_commands.json           # Documented abuse patterns (105 / 165)
│   │   ├── sigma_parent_child_pairs.json  # Parent→child blocklist (1,874)
│   │   ├── sigma_cmdline_patterns.json    # CommandLine rule patterns (1,409)
│   │   ├── suspicious_cmdline_keywords.json  # Curated switch table (34)
│   │   └── cmd_internal_commands.json     # cmd.exe builtins (45)
│   │
│   └── scripts/                  # Offline dataset regeneration & manual harnesses
│       ├── extract_lolbas.py                  # LOLBAS → binaries + abuse commands
│       ├── extract_sigma_pairs.py             # SigmaHQ → parent/child pairs
│       ├── extract_sigma_cmdline_patterns.py  # SigmaHQ → CommandLine patterns
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
│   └── waf_payload_analyzer_plan.md       # In progress — parser landed, not yet wired in
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
└── tests/                        # 533 tests — `python -m pytest`
    ├── fixtures/
    │   ├── cmdline_corpus.json   # Calibration corpus: 30 known-bad / 32 known-good
    │   └── process_corpus.json   # Calibration corpus: 14 known-bad / 28 known-good
    ├── test_abuseipdb_processing.py
    ├── test_cmdline_analyzer.py
    ├── test_cmdline_calibration.py      # False-positive regression gate
    ├── test_cmdline_deobfuscator.py
    ├── test_cmdline_integration.py
    ├── test_cmdline_lolbas_layer4.py
    ├── test_cmdline_parser.py
    ├── test_cmdline_sigma_layer5.py
    ├── test_cve_panel_copy.py
    ├── test_decode_common.py
    ├── test_defang_display.py
    ├── test_dnsdumpster_processing.py
    ├── test_hybrid_analysis_provider.py
    ├── test_infra_classifier.py
    ├── test_lolbas_lookup.py
    ├── test_malwarebazaar_provider.py
    ├── test_parser_schemeless_url.py
    ├── test_path_prober.py
    ├── test_process_analyzer.py
    ├── test_process_calibration.py      # False-positive regression gate
    ├── test_process_integration.py
    ├── test_shodan_internetdb.py
    ├── test_sigma_pairs.py
    ├── test_threat_analysis.py
    ├── test_urlscan_processing.py
    └── test_virustotal_url_scheme.py
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

---

## Development

### Tests

```bash
python -m pytest
```

Two of these are calibration gates rather than unit tests — they assert that the
endpoint-analysis modules do not fire on ordinary administrative activity. They
are the ones to watch when tuning any detection threshold.

### Regenerating the local datasets

The datasets under `core/data/` are generated **offline** and committed; the app
never fetches them at runtime. Re-run these quarterly, or whenever the upstream
projects publish notable additions, and commit the result.

```bash
pip install pyyaml          # script-only — deliberately NOT in requirements.txt

python core/scripts/extract_lolbas.py                            # → lolbas_binaries + lolbas_commands
python core/scripts/extract_sigma_pairs.py --download            # → sigma_parent_child_pairs
python core/scripts/extract_sigma_cmdline_patterns.py --download # → sigma_cmdline_patterns
```

Add `--dry-run` to any of them to report counts without writing. Sigma is never
evaluated at runtime — no `pySigma`, no rule engine; the app only reads the
generated JSON.

**Upstream sources and licences:** [SigmaHQ](https://github.com/SigmaHQ/sigma)
(Detection Rule License 1.1) · [LOLBAS](https://github.com/LOLBAS-Project/LOLBAS)
(CC BY 4.0).

> Both Sigma extractions are partial by design: each keeps the conditions it can
> evaluate and drops the rest, recording what was dropped on every record. A
> pattern that no longer discriminates once its siblings are removed is not
> shipped at all — the reasoning, and the measurements behind it, are in
> [docs/cmdline_analyzer.md](docs/cmdline_analyzer.md).
