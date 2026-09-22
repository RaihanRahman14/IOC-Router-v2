# Whoxy

Whoxy provides WHOIS registration data and reverse WHOIS lookup - the ability to find all domains registered by a given email address, company name, or keyword. IOC Router uses it to surface domain registrant identity, registration history, and related infrastructure.

---

## How It Works (Technical)

### Endpoint Used

[`providers/whoxy.py`](../providers/whoxy.py) calls a single unified endpoint with different query parameters:

```
GET https://api.whoxy.com/
```

### Authentication

The API key is passed as a URL query parameter:

```
?key=<WHOXY_KEY>
```

### Query Modes

| Mode | URL Parameters | IOC Types |
|------|---------------|-----------|
| WHOIS lookup | `?whois={domain}&key=...` | Domain, URL |
| Reverse WHOIS by email | `?reverse=whois&email={email}&key=...` | Email |
| Reverse WHOIS by company | `?reverse=whois&company={company}&key=...` | - |
| Reverse WHOIS by keyword | `?reverse=whois&keyword={term}&key=...` | WHOIS keyword |

For URL inputs, the domain is extracted before the query is made. For bare WHOIS keyword IOCs (detected by [`ioc/parser.py`](../ioc/parser.py)), a keyword reverse lookup is performed to find all domains matching that registrant keyword.

### Response Fields Used (WHOIS)

| Field | Description |
|-------|-------------|
| `domain_registrar.registrar_name` | Registrar organisation name |
| `create_date` | Domain first registered (YYYY-MM-DD) |
| `update_date` | Last WHOIS record update |
| `expiry_date` | Registration expiry date |
| `domain_status[]` | Domain status flags (clientTransferProhibited, etc.) |
| `name_servers[]` | Authoritative nameservers |
| `registrant_contact.email` | Registrant email address |
| `registrant_contact.full_name` | Registrant name |
| `registrant_contact.company_name` | Registrant organisation |

### Response Fields Used (Reverse WHOIS)

| Field | Description |
|-------|-------------|
| `total_results` | Total domains matching the query |
| `whois_records[]` | List of related domain records |
| `whois_records[].domain_name` | Domain name |
| `whois_records[].create_date` | Registration date |
| `whois_records[].registrant_contact` | Registrant details |

### Flag Extraction

[`ioc/flags/` base flags](../ioc/flags/base.py) and the Whoxy provider output generate flags such as:

- Newly registered domain: `create_date` within the last 30 days
- Domain expiring soon: `expiry_date` within the next 14 days
- Privacy-protected registrant: registrant email/name redacted via proxy service
- Multiple domains, same registrant: reverse WHOIS returns 10+ related domains
- Suspicious registrar: known bullet-proof or low-reputation registrar

### Timeout & Batching

- Timeout: **15 seconds** per request
- Entry point: `whoxy_lookup_batch()` in [`providers/whoxy.py`](../providers/whoxy.py)

---

## Getting an API Key

1. Register at [https://www.whoxy.com/signup.php](https://www.whoxy.com/signup.php).
2. After logging in, go to **Account → API Access** (or [https://www.whoxy.com/my-account.php](https://www.whoxy.com/my-account.php)).
3. Your API key is displayed in the API section - copy it.
4. Add it to `.env`:
   ```env
   WHOXY_KEY=your_api_key_here
   ```

**Free tier:** Whoxy is a paid-only API. Plans start from a small per-query credit model. Check current pricing at [https://www.whoxy.com/pricing.php](https://www.whoxy.com/pricing.php).
