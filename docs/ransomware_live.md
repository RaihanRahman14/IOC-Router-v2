# Ransomware.live

## What it is

[Ransomware.live](https://www.ransomware.live) is a community-maintained threat intelligence feed that continuously tracks ransomware gang activity - victim posts, attack disclosures, and infrastructure data published on dark-web leak sites. The **API-Pro** tier exposes a victim search endpoint (`/victims/search`) that lets you query whether a domain or organization name appears in the victim database.

IOC Router uses Ransomware.live to check whether a submitted domain or keyword is associated with a known ransomware incident. A match is treated as a high-severity indicator and surfaced in:

- **Threat Analysis**: flags `RL_VICTIM_MATCH`, `RL_RECENT_ATTACK`, `RL_KNOWN_GROUP`, `RL_MULTIPLE_VICTIMS`
- **AI Description**: victim count, group name, and most-recent discovery date are injected into the AI evidence bundle
- **Key Evidence**: the ransomware group name appears as a metric card

---

## Supported IOC Types

| IOC Type | How it is queried |
|----------|------------------|
| Domain   | Full domain + SLD (second-level domain): two queries, results merged |
| URL      | Hostname extracted from URL, then full host + SLD queries |
| Keyword  | Raw keyword passed directly to the search endpoint |

IP addresses and file hashes are not supported - the Ransomware.live victim search is text-based.

---

## How it works in the pipeline

For each domain or URL IOC, IOC Router sends two search queries:

1. **Full domain** - e.g. `subdomain.company.com`
2. **SLD** - e.g. `company` (the second-level label, without TLD)

Results from both queries are merged and deduplicated by victim ID. This two-pass approach catches victims recorded under the bare company name as well as their full domain.

```
Domain IOC: "billing.acmecorp.com"
    → query 1: "billing.acmecorp.com"  → 0 hits
    → query 2: "acmecorp"              → 2 hits
    → merged: 2 victims, deduplicated
```

---

## Flags extracted

| Flag ID | Label | Severity | MITRE |
|---------|-------|----------|-------|
| `RL_VICTIM_MATCH` | Domain/org found in ransomware victim database | CRITICAL | TA0040, T1486 |
| `RL_RECENT_ATTACK` | Recent ransomware incident within 90 days | CRITICAL | TA0040, T1486 |
| `RL_KNOWN_GROUP` | Ransomware group identified | HIGH | TA0042, TA0040 |
| `RL_MULTIPLE_VICTIMS` | Multiple victim records (≥3): repeated targeting | HIGH | TA0040 |

`RL_VICTIM_MATCH` and `RL_RECENT_ATTACK` set the **service_disruption_or_encryption** evidence key, which pushes the Threat State toward **Impact** and Threat Level toward **High / Very High**.

---

## How to get an API key

Ransomware.live offers both a free community portal and a paid **API-Pro** subscription.

### 1. Create an account

Go to [https://www.ransomware.live](https://www.ransomware.live) and register for an account using your email address.

### 2. Subscribe to API-Pro

From your account dashboard, navigate to **API / Subscriptions** and select the **API-Pro** plan. API-Pro provides access to the `/victims/search` endpoint used by IOC Router.

> The free tier does not expose the search endpoint - an API-Pro key is required.

### 3. Copy your API key

After subscribing, your key is displayed in the **API Keys** section of your dashboard. It is a long alphanumeric string.

### 4. Add it to IOC Router

**Via `.env` file:**

```env
RANSOMWARE_LIVE_KEY=your_api_key_here
```

**Via the UI key drawer:**

Open the key drawer (hamburger icon, top-left), scroll to **Ransomware Live**, paste your key, and press Enter. The key is stored in session only - it is never written to disk.

---

## Rate limits and caching

- Results are cached for **24 hours** per IOC per session to avoid redundant API calls.
- The provider only runs for `domain`, `url`, and `whois` (keyword) IOC types.
- When **Auto Provider** is enabled, Ransomware.live activates automatically if a valid key is set and the IOC type is supported.
- A 404 response from the API is treated as "no results" (count 0), not an error.

---

## Base URL

```
https://api-pro.ransomware.live
```

Endpoint used: `GET /victims/search?q=<query>&order=discovered`
