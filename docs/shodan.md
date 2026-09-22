# Shodan

Shodan continuously scans the public internet and indexes open ports, running services, CVEs, and service tags for every reachable IP. IOC Router uses the lightweight **InternetDB** endpoint - no API key required - to fetch port, vulnerability, and tag data.

---

## How It Works (Technical)

### Endpoint Used

[`providers/shodan.py`](../providers/shodan.py) calls:

```
GET https://internetdb.shodan.io/{ip}
```

This is a free, public read-only endpoint that returns a compact JSON summary of any IP's internet-facing posture. No authentication header is needed.

### IP Resolution

Domains and URLs are resolved to an IP address before the API call. If resolution fails, the lookup is skipped.

### Response Fields Used

| Field | Description |
|-------|-------------|
| `ports[]` | List of open TCP/UDP port numbers |
| `vulns[]` | CVE identifiers tied to detected services |
| `tags[]` | Semantic tags: `malware`, `compromised`, `tor`, `vpn`, `honeypot`, `scanner` |
| `cpes[]` | Common Platform Enumerations (software fingerprints) |
| `hostnames[]` | Reverse-DNS hostnames associated with the IP |

### Risk Scoring Logic

Defined in [`providers/shodan.py`](../providers/shodan.py):

| Condition | Risk Level |
|-----------|-----------|
| CVE present **AND** high-risk port open | HIGH |
| Strong tag present (`malware`, `compromised`) | HIGH |
| High-risk port open without CVE | MEDIUM |
| 10+ open ports without CVE | MEDIUM |
| Only common web ports (80, 443) and no CVE | LOW |
| No InternetDB data found | UNKNOWN |

High-risk ports: `22, 23, 3389, 445, 5900, 3306, 5432, 27017, 6379, 9200`

### Retry Logic

The provider implements automatic retry on HTTP `429` (rate-limited) and timeout responses, with a **1-second delay** between retries ([`providers/shodan.py`](../providers/shodan.py)).

### Flag Extraction

[`ioc/flags/shodan.py`](../ioc/flags/shodan.py) generates flags such as:

- Critical CVE exposure: CVE present on a critical service port
- RDP/SMB/SSH exposed: high-risk ports open to the internet
- Tor exit node / VPN relay: from `tags[]`
- Honeypot detected: from `tags[]`
- High port exposure: 10+ open ports

### Timeout & Batching

- Timeout: **10 seconds** per request (shorter than other providers due to the lightweight endpoint)
- Entry point: `shodan_lookup_batch()` in [`providers/shodan.py`](../providers/shodan.py)

---

## Getting an API Key

The **InternetDB** endpoint used by IOC Router is **completely free and requires no API key**. You can call it directly in a browser:

```
https://internetdb.shodan.io/8.8.8.8
```

If you want access to the full Shodan search API (not used by this project), create an account at [https://account.shodan.io/register](https://account.shodan.io/register). A free account gives you a personal API key with limited credits.

For this project the `SHODAN_KEY` field in `.env` is reserved for future use and is not currently required.
