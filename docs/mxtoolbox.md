# MxToolBox

MxToolBox is a suite of network diagnostic tools that checks DNS records, email security configuration (SPF, DKIM, DMARC), blacklist status, and HTTP reachability. IOC Router uses it to assess the mail security posture and blacklist standing of IPs, domains, URLs, and email addresses.

---

## How It Works (Technical)

### Endpoint Used

[`providers/mxtoolbox.py`](../providers/mxtoolbox.py) calls:

```
GET https://api.mxtoolbox.com/api/v1/Lookup/{command}
```

A separate request is made for each command relevant to the IOC type.

### Authentication

API key sent via the `Authorization` HTTP header:

```
Authorization: <MXTOOLBOX_KEY>
```

### Commands by IOC Type

| IOC Type | Commands Executed |
|----------|-----------------|
| IP | `blacklist`, `ptr`, `ping` |
| Domain | `mx`, `dns`, `spf`, `dmarc`, `blacklist`, `http` |
| URL | `mx`, `dns`, `spf`, `dmarc`, `blacklist`, `http` |
| Email | `mx`, `spf`, `dmarc` |

Each command targets the IOC value as the lookup argument, e.g. `GET /api/v1/Lookup/blacklist?argument={ip}`.

### Response Structure

Each command returns a result object with four arrays:

| Array | Description |
|-------|-------------|
| `Failed[]` | Checks that definitively failed (e.g. listed on a blacklist) |
| `Warnings[]` | Checks with non-critical issues |
| `Passed[]` | Checks that passed |
| `Timeouts[]` | Checks that timed out during the lookup |
| `Information[]` | Informational data without a pass/fail verdict |

### Verdict Aggregation

[`providers/mxtoolbox.py`](../providers/mxtoolbox.py) aggregates results across all commands:

| Condition | Overall Verdict |
|-----------|----------------|
| Any `Failed` items present | FAIL |
| Only `Warnings` (no failures) | WARN |
| All checks passed | PASS |
| No usable data returned | UNKNOWN |

### Error Handling

| HTTP Status | Meaning |
|------------|---------|
| `401` | Invalid or expired API key |
| `429` | Monthly quota exceeded |

### Flag Extraction

Flags are derived from the aggregated Failed/Warning items:

- Blacklisted IP: IP found on one or more DNS-based blacklists (DNSBLs)
- Missing SPF record: SPF check returned no `v=spf1` TXT record
- Missing DMARC policy: no `v=DMARC1` record found
- No PTR record: reverse DNS not configured (common for spam sources)
- MX record misconfiguration: MX lookup failed or returned invalid data
- HTTP unreachable: HTTP check timed out or returned an error

### Timeout & Batching

- Timeout: **20 seconds** per request (multi-command lookups can be slow)
- Entry point: `mxtoolbox_lookup_batch()` in [`providers/mxtoolbox.py`](../providers/mxtoolbox.py)

---

## Getting an API Key

1. Register at [https://mxtoolbox.com/signup](https://mxtoolbox.com/signup).
2. After logging in, navigate to **Account → API** (or [https://mxtoolbox.com/user/api-key](https://mxtoolbox.com/user/api-key)).
3. Your API key is shown on that page - copy it.
4. Add it to `.env`:
   ```env
   MXTOOLBOX_KEY=your_api_key_here
   ```

**Free tier:** The free plan provides a limited number of API calls per month. Paid plans offer higher quotas, webhook alerts, and monitoring features.
