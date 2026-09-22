# VirusTotal

VirusTotal aggregates results from 70+ antivirus engines, URL scanners, and sandboxes into a single REST API. IOC Router uses it as the primary detection signal for IPs, domains, URLs, and file hashes.

---

## How It Works (Technical)

### IOC Type Routing

[`providers/virustotal.py`](../providers/virustotal.py) dispatches each IOC to a different v3 endpoint:

| IOC Type | Endpoint |
|----------|----------|
| IP | `GET /api/v3/ip_addresses/{ip}` |
| Domain | `GET /api/v3/domains/{domain}` |
| URL | `GET /api/v3/urls/{base64_url}` |
| Hash | `GET /api/v3/files/{hash}` |

URLs are submitted as a URL-safe base64 encoding of the raw URL string before being passed to the endpoint.

### Authentication

All requests include the API key in the `x-apikey` HTTP header ([`providers/virustotal.py:16`](../providers/virustotal.py#L16)):

```
x-apikey: <VT_KEY>
```

### Enrichment Calls

After the primary lookup, additional relationship endpoints are queried for richer context:

| Relationship | Endpoint Suffix | Limit |
|--------------|----------------|-------|
| Public comments | `/{id}/comments` | 5 |
| Community votes | `/{id}/votes` | 5 |
| DNS resolutions | `/{id}/resolutions` | 10 |
| Sandbox behavior | `/files/{id}/behaviour_summary` | - |

### Response Fields Used

| Field | Purpose |
|-------|---------|
| `last_analysis_stats` | Counts of malicious / suspicious / harmless / undetected engines |
| `last_analysis_results` | Per-engine name, category, and detection label |
| `attributes.categories` | Community-assigned categories (botnet, phishing, malware, etc.) |
| `attributes.reputation` | Community reputation score (-100 to +100) |

### Flag Extraction

[`ioc/flags/virustotal.py`](../ioc/flags/virustotal.py) converts raw stats into structured threat flags:

- `VT_HIGH_MALICIOUS_DETECTION`: 10+ engines flagged as malicious (CRITICAL)
- `VT_ENGINE_LABEL_PHISH / TROJAN / RANSOMWARE`: specific engine label categories (HIGH)
- `VT_CATEGORY_COMMAND_AND_CONTROL / BOTNET`: community category hits (HIGH)
- Thresholds: CRITICAL ≥ 10, HIGH ≥ 3, MEDIUM ≥ 1

### Verdict Logic

Defined in [`ioc/verdict.py`](../ioc/verdict.py):

- **Malicious**: `malicious >= 3` engines
- **Suspicious**: `suspicious >= 1` engine or 1–2 malicious
- **Unknown**: data returned but no detections

### Timeout & Batching

- Timeout: **15 seconds** per request
- Entry point: `vt_lookup_batch()` in [`providers/virustotal.py`](../providers/virustotal.py) - processes a list of IOCs and returns a dict keyed by IOC value

---

## Getting an API Key

1. Go to [https://www.virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) and create a free account.
2. After logging in, open the user menu (top-right avatar) and select **API key**.
3. Copy the key shown under **Your API key**.
4. Paste it into `.env` as:
   ```env
   VT_KEY=your_api_key_here
   ```

**Free tier limits:** 4 requests/minute, 500 requests/day, 15 500 requests/month. Upgrade to a premium plan for higher quotas and access to the behaviour summary endpoint.
