# ThreatFox

ThreatFox (by abuse.ch) is a free threat intelligence database focused on malware indicators - C2 infrastructure, malware families, and IOC confidence scores. IOC Router uses it to identify known malware C2 addresses, domains, and associated file hashes.

---

## How It Works (Technical)

### Endpoint Used

[`providers/threatfox.py`](../providers/threatfox.py) calls a single unified JSON API:

```
POST https://threatfox-api.abuse.ch/api/v1/
```

### Authentication

API key sent in the `Auth-Key` HTTP header:

```
Auth-Key: <THREATFOX_KEY>
```

### Query Methods

The request body selects the lookup type via the `query` field:

| IOC Type | `query` Value | Extra Body Field |
|----------|--------------|-----------------|
| Hash (MD5/SHA256) | `search_hash` | `hash` |
| IP address | `search_ip` | `ip` |
| Domain | `search_domain` | `domain` |
| Generic / URL | `search_ioc` | `search_term`, `exact_match: true/false` |

### Multi-Variant Strategy

For domains, the provider automatically expands the query to include `http://` and `https://` variants to maximise match coverage ([`providers/threatfox.py`](../providers/threatfox.py)). For IPs with known ports, port-suffixed variants (e.g. `1.2.3.4:8080`) are also tried.

### Response Fields Used

| Field | Description |
|-------|-------------|
| `query_status` | `ok`, `no_result`, or `error` |
| `data[]` | Array of matched threat entries |
| `data[].malware` | Malware family name |
| `data[].malware_printable` | Human-readable malware name |
| `data[].confidence_level` | Confidence score (0–100) |
| `data[].threat_type` | `botnet_cc`, `payload_delivery`, `c2`, etc. |
| `data[].ioc_type` | Type of the matched IOC |
| `data[].first_seen`, `last_seen` | Observation timestamps |
| `data[].tags[]` | Analyst-assigned tags |

### Flag Extraction

[`ioc/flags/threatfox.py`](../ioc/flags/threatfox.py) produces flags such as:

- Known C2 server: threat type is `botnet_cc` or `c2`
- High-confidence malware match: confidence ≥ 75
- Payload delivery infrastructure: threat type `payload_delivery`
- Known malware hash: hash matched in the database

### Verdict Contribution

A ThreatFox hit with any confidence level pushes the multi-source verdict to at least **SUSPICIOUS** in [`ioc/verdict.py`](../ioc/verdict.py).

### Timeout & Batching

- Timeout: **15 seconds** per request
- Entry point: `threatfox_lookup_batch()` in [`providers/threatfox.py`](../providers/threatfox.py)

---

## Getting an API Key

1. Go to [https://threatfox.abuse.ch/api/](https://threatfox.abuse.ch/api/) and scroll to **Authentication**.
2. Register / log in at [https://auth.abuse.ch/](https://auth.abuse.ch/).
3. Navigate to your profile and copy the **API key** shown there.
4. Add it to `.env`:
   ```env
   THREATFOX_KEY=your_api_key_here
   ```

**Free tier:** The ThreatFox API is completely free for non-commercial use with no strict rate limits documented. Bulk downloads are also available via [https://threatfox.abuse.ch/export/](https://threatfox.abuse.ch/export/).
