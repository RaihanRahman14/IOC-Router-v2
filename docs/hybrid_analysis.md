# Hybrid Analysis

Hybrid Analysis (powered by CrowdStrike Falcon Sandbox) executes suspicious files and URLs in an isolated virtual machine and records all runtime behaviour - process trees, network connections, dropped files, registry changes, and MITRE ATT&CK technique mappings. IOC Router uses it for deep sandbox-based analysis of hashes and quick URL scans.

---

## How It Works (Technical)

### Endpoints Used

[`providers/hybrid_analysis.py`](../providers/hybrid_analysis.py) uses four endpoints depending on IOC type:

| Action | Method | Endpoint |
|--------|--------|----------|
| Hash lookup | `GET` | `/api/v2/search/hash` |
| Full sandbox report | `GET` | `/api/v2/report/{job_id}/summary` |
| Submit URL for quick scan | `POST` | `/api/v2/quick-scan/url` |
| Poll quick scan result | `GET` | `/api/v2/quick-scan/{scan_id}` |
| Search by domain/IP | `POST` | `/api/v2/search/terms` |

### Authentication

API key sent via the `api-key` HTTP header:

```
api-key: <HYBRID_ANALYSIS_KEY>
```

### Hash Analysis Flow

1. `GET /api/v2/search/hash?hash={hash}` returns a list of past analyses for that hash.
2. The most recent analysis `job_id` is selected.
3. `GET /api/v2/report/{job_id}/summary` retrieves the full sandbox report.

### URL Analysis Flow

1. `POST /api/v2/quick-scan/url` submits the URL for a lightweight scan.
2. The response contains a `scan_id` and a `finished` flag.
3. If not finished, the provider polls `GET /api/v2/quick-scan/{scan_id}` until the result is ready.

### Response Fields Used (Hash/File)

| Field | Description |
|-------|-------------|
| `verdict` | `malicious`, `benign`, or `unknown` |
| `threat_score` | Numeric risk score (0–100) |
| `vx_family` / `family` | Malware family name |
| `domains[]` | Network domains contacted during execution |
| `hosts[]` | IP addresses contacted during execution |
| `processes[]` | Process activity tree |
| `mutex[]` | Mutex names created (common persistence indicator) |
| `dropped_files[]` | Files written to disk during execution |
| `mitre_attack[]` | MITRE ATT&CK technique IDs and tactic names |
| `av_detect` | Number of AV engines detecting the sample |
| `analysis_start_time` | Sandbox execution timestamp |
| `analysis_environment` | OS environment used (e.g. Windows 10 64-bit) |

### Domain/IP Search

For domain and IP inputs, `POST /api/v2/search/terms` is used to find related hashes and malware families without triggering a full sandbox run.

### Flag Extraction

[`ioc/flags/hybrid_analysis.py`](../ioc/flags/hybrid_analysis.py) derives flags including:

- Sandbox verdict: malicious / suspicious
- High threat score: score ≥ 70
- Known malware family identified
- MITRE technique matched (e.g. T1055 Process Injection, T1071 C2 via HTTP)
- Network IOCs extracted: contacted domains/IPs listed
- Dropped executable files
- Mutex persistence indicator

### Timeout & Batching

- Timeout: **20 seconds** per request (extended to account for sandbox latency)
- Entry point: `hybrid_analysis_lookup_batch()` in [`providers/hybrid_analysis.py`](../providers/hybrid_analysis.py)

---

## Getting an API Key

1. Register at [https://www.hybrid-analysis.com/signup](https://www.hybrid-analysis.com/signup).
2. After email verification and login, go to **Profile → API key** (or [https://www.hybrid-analysis.com/my-account?tab=api-key](https://www.hybrid-analysis.com/my-account?tab=api-key)).
3. Generate a new key and copy it.
4. Add it to `.env`:
   ```env
   HYBRID_ANALYSIS_KEY=your_api_key_here
   ```

**Free tier:** Community accounts get access to hash lookups, URL quick scans, and search endpoints. Full sandbox submission with private results requires a paid CrowdStrike Falcon Sandbox licence.
