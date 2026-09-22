# DNSDumpster

DNSDumpster is a domain research tool that enumerates DNS records (A, CNAME, MX, NS, TXT) and enriches each discovered host with ASN, geolocation, owner, and HTTP/HTTPS banner data. IOC Router uses it for passive DNS reconnaissance and red-flag detection on domains and URLs.

---

## How It Works (Technical)

### Endpoint Used

[`providers/dnsdumpster.py`](../providers/dnsdumpster.py) calls:

```
GET https://api.dnsdumpster.com/domain/{domain}
```

For URL inputs, the domain is extracted before the call is made.

### Authentication

API key sent via the `X-API-Key` HTTP header:

```
X-API-Key: <DNSDUMPSTER_KEY>
```

### Response Structure

| Field | Description |
|-------|-------------|
| `a[]` | A records: each entry includes IP, ASN, owner, country, PTR, HTTP/HTTPS banners |
| `cname[]` | CNAME records with target hostname |
| `mx[]` | MX records with priority and IP enrichment |
| `ns[]` | Nameserver records |
| `txt[]` | TXT records (SPF, DKIM, DMARC, etc.) |
| `total_a_recs` | Total count of A records found |

### Banner Extraction

For each A record, the provider extracts HTTP/HTTPS server headers and page titles from the embedded banner data. This reveals what software is running on subdomains without active probing ([`providers/dnsdumpster.py`](../providers/dnsdumpster.py)).

### Red Flag Detection

[`providers/dnsdumpster.py`](../providers/dnsdumpster.py) and [`ioc/flags/dnsdumpster.py`](../ioc/flags/dnsdumpster.py) scan the DNS records for:

| Red Flag | Detection Method |
|----------|----------------|
| Sensitive subdomain exposed | Hostname matches: `vpn`, `mail`, `remote`, `admin`, `staging`, `dev`, `test`, `old` |
| Residential/ISP host | Owner matches known ISP names (Comcast, Verizon, AT&T, Vodafone, etc.) |
| Random/generated hostname | Hostname ≥ 16 characters with mixed digits |
| CNAME takeover risk | CNAME target points to a CDN/cloud provider (e.g. `amazonaws.com`, `azurewebsites.net`) |
| Missing SPF/DMARC | TXT records scanned; absence of `v=spf1` or `v=DMARC1` flagged |

### Output Structure

The provider normalises the raw API response into a SOC-friendly dict containing:
- `a_records`: enriched list of A record entries
- `cname_map`: CNAME → target mappings
- `mail_dns_infra`: MX records with mail server details
- `network_enrichment`: NS and ASN data
- `red_flags`: list of detected anomalies

### Timeout & Batching

- Timeout: **15 seconds** per request
- Entry point: `dnsdumpster_lookup_batch()` in [`providers/dnsdumpster.py`](../providers/dnsdumpster.py) - only processes `domain` and `url` IOC types

---

## Getting an API Key

1. Go to [https://dnsdumpster.com/](https://dnsdumpster.com/) and create an account.
2. After logging in, navigate to the **API** section of your profile (or [https://api.dnsdumpster.com/](https://api.dnsdumpster.com/)).
3. Generate an API key and copy it.
4. Add it to `.env`:
   ```env
   DNSDUMPSTER_KEY=your_api_key_here
   ```

**Free tier:** The API offers a limited number of free requests per month. Paid plans provide higher quotas and bulk lookup support.
