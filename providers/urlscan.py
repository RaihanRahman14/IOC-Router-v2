"""urlscan.io client (search-only)."""
from __future__ import annotations

import re
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import requests

from config import Settings
from ioc.parser import IOC


URLSCAN_BASE = "https://urlscan.io/api/v1"
SUSPICIOUS_POST_HINTS = ("/login", "/auth", "/verify", "/submit", "/signin", "/password")
KNOWN_TRACKERS = ("google-analytics", "doubleclick", "googletagmanager", "facebook", "hotjar", "segment")


def _search(query: str, key: str) -> dict:
    try:
        r = requests.get(
            f"{URLSCAN_BASE}/search/",
            headers={"API-Key": key},
            params={"q": query, "size": 1},
            timeout=15,
        )
    except requests.RequestException:
        return {}
    if r.status_code != 200:
        return {}
    return r.json()

def _search_first(queries: list[str], key: str) -> dict:
    for q in queries:
        data = _search(q, key)
        results = data.get("results", []) if data else []
        if results:
            return results[0]
    return {}

def _url_variants(url: str) -> list[str]:
    variants = []
    if url:
        variants.append(url)
        if url.endswith("/"):
            variants.append(url.rstrip("/"))
        else:
            variants.append(url + "/")
        if url.startswith("https://"):
            variants.append("http://" + url[len("https://"):])
        elif url.startswith("http://"):
            variants.append("https://" + url[len("http://"):])
    # Preserve order, remove duplicates
    seen = set()
    out = []
    for v in variants:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out

def _domain_url_variants(domain: str) -> list[str]:
    if not domain:
        return []
    base = domain.strip().lower()
    return [
        f"https://{base}",
        f"http://{base}",
        f"https://{base}/",
        f"http://{base}/",
    ]

def _submit(url: str, key: str) -> dict:
    try:
        r = requests.post(
            f"{URLSCAN_BASE}/scan/",
            headers={"API-Key": key, "Content-Type": "application/json"},
            json={"url": url, "visibility": "private"},
            timeout=15,
        )
    except requests.RequestException:
        return {}
    if r.status_code not in (200, 201):
        return {}
    return r.json()


def _result(uuid: str, key: str) -> dict:
    try:
        r = requests.get(
            f"{URLSCAN_BASE}/result/{uuid}/",
            headers={"API-Key": key},
            timeout=15,
        )
    except requests.RequestException:
        return {}
    if r.status_code != 200:
        return {}
    return r.json()


def urlscan_lookup_batch(
    items: list[IOC],
    settings: Settings,
    allow_submit: bool = True,
) -> dict[str, dict]:
    out: dict[str, dict] = {}
    if not settings.urlscan_key:
        return out
    for ioc in items:
        if ioc.type not in ("url", "domain"):
            continue

        first = {}
        if ioc.type == "url":
            queries = []
            for v in _url_variants(ioc.value):
                queries.append(f'page.url:"{v}"')
                queries.append(f'task.url:"{v}"')
            first = _search_first(queries, settings.urlscan_key)
        else:
            domain = ioc.value.lower()
            queries = [
                f'page.domain:"{domain}"',
                f'task.domain:"{domain}"',
                f'domain:"{domain}"',
            ]
            first = _search_first(queries, settings.urlscan_key)

        if first:
            uuid = first.get("_id")
            result_data = _result(uuid, settings.urlscan_key) if uuid else {}
            data = result_data or first
            verdicts = data.get("verdicts", {})
            out[ioc.value] = {
                "uuid": uuid,
                "verdicts": verdicts,
                "page": data.get("page", {}),
                "task": data.get("task", {}),
                "screenshot": data.get("screenshot") or data.get("screenshotURL"),
                "result": result_data or {},
            }
            continue

        if ioc.type == "domain" and allow_submit:
            submitted = {}
            for u in _domain_url_variants(ioc.value):
                submitted = _submit(u, settings.urlscan_key)
                if submitted.get("uuid"):
                    break
            uuid = submitted.get("uuid")
            if not uuid:
                out[ioc.value] = {}
                continue

            result_data = {}
            for _ in range(3):
                time.sleep(2)
                result_data = _result(uuid, settings.urlscan_key)
                if result_data:
                    break

            if not result_data:
                out[ioc.value] = {"uuid": uuid}
                continue

            verdicts = result_data.get("verdicts", {})
            out[ioc.value] = {
                "uuid": uuid,
                "verdicts": verdicts,
                "page": result_data.get("page", {}),
                "task": result_data.get("task", {}),
                "screenshot": result_data.get("screenshot") or result_data.get("screenshotURL"),
                "result": result_data,
            }
            continue

        if ioc.type != "url" or not allow_submit:
            out[ioc.value] = {}
            continue

        submitted = _submit(ioc.value, settings.urlscan_key)
        uuid = submitted.get("uuid")
        if not uuid:
            out[ioc.value] = {}
            continue

        # Poll a few times for result readiness
        result_data = {}
        for _ in range(3):
            time.sleep(2)
            result_data = _result(uuid, settings.urlscan_key)
            if result_data:
                break

        if not result_data:
            out[ioc.value] = {"uuid": uuid}
            continue

        verdicts = result_data.get("verdicts", {})
        out[ioc.value] = {
            "uuid": uuid,
            "verdicts": verdicts,
            "page": result_data.get("page", {}),
            "task": result_data.get("task", {}),
            "screenshot": result_data.get("screenshot") or result_data.get("screenshotURL"),
            "result": result_data,
        }
    return out


def extractMainDomain(url: str | None) -> str:
    if not url or not isinstance(url, str):
        return ""
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""
    if not host:
        return ""
    labels = [p for p in host.split(".") if p]
    if len(labels) < 2:
        return host
    return ".".join(labels[-2:])


def detectBase64Blob(text: str | None) -> bool:
    if not text or not isinstance(text, str):
        return False
    # Long base64-like chunks are a common obfuscation marker.
    return bool(re.search(r"(?:[A-Za-z0-9+/]{80,}={0,2})", text))


def isObfuscatedScript(text: str | None) -> bool:
    if not text or not isinstance(text, str):
        return False
    lowered = text.lower()
    if any(token in lowered for token in ("eval(", "function(", "atob(", "unescape(", "string.fromcharcode")):
        return True
    if detectBase64Blob(text):
        return True
    if re.search(r"(?:\\x[0-9a-fA-F]{2}){10,}", text):
        return True
    lines = text.splitlines()
    if len(lines) == 1 and len(text) > 1200:
        return True
    return False


def buildRedirectChain(transactions: list[dict] | None) -> list[str]:
    if not transactions or not isinstance(transactions, list):
        return []
    chain: list[str] = []
    seen = set()
    for tx in transactions:
        if not isinstance(tx, dict):
            continue
        req = tx.get("request", {}) if isinstance(tx.get("request"), dict) else {}
        res = tx.get("response", {}) if isinstance(tx.get("response"), dict) else {}
        req_url = req.get("url")
        if isinstance(req_url, str) and req_url and req_url not in seen:
            seen.add(req_url)
            chain.append(req_url)
        location = res.get("location") or res.get("redirect") or res.get("redirectURL")
        if isinstance(location, str) and location and location not in seen:
            seen.add(location)
            chain.append(location)
    return chain


def isRecentlyIssued(cert: dict | None, days: int = 14, now_utc: datetime | None = None) -> bool:
    if not cert or not isinstance(cert, dict):
        return False
    valid_from = cert.get("valid_from") or cert.get("notBefore")
    if not isinstance(valid_from, str):
        return False
    stamp = _parse_iso_datetime(valid_from)
    if stamp is None:
        return False
    now_value = now_utc.astimezone(timezone.utc) if now_utc else datetime.now(timezone.utc)
    age = now_value - stamp
    return timedelta(0) <= age <= timedelta(days=days)


def isDomainMismatch(urlDomain: str, certCN: str | None, certSAN: list[str] | None) -> bool:
    if not urlDomain:
        return False
    target = urlDomain.lower()
    names: list[str] = []
    if isinstance(certCN, str) and certCN.strip():
        names.append(certCN.strip().lower())
    if isinstance(certSAN, list):
        for item in certSAN:
            if isinstance(item, str) and item.strip():
                names.append(item.strip().lower())
    if not names:
        return False
    for name in names:
        cleaned = name[2:] if name.startswith("*.") else name
        if cleaned == target or target.endswith("." + cleaned):
            return False
    return True


def _parse_iso_datetime(value: str | None) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _coerce_transactions(result: dict) -> list[dict]:
    tx = result.get("http")
    if isinstance(tx, list):
        return tx
    data = result.get("data") if isinstance(result.get("data"), dict) else {}
    reqs = data.get("requests")
    if isinstance(reqs, list):
        return reqs
    return []


def _extract_domains_ips(result: dict) -> tuple[list[str], list[str], list[str]]:
    lists = result.get("lists", {}) if isinstance(result.get("lists"), dict) else {}
    domains = lists.get("domains") if isinstance(lists.get("domains"), list) else []
    ips = lists.get("ips") if isinstance(lists.get("ips"), list) else []
    urls = lists.get("urls") if isinstance(lists.get("urls"), list) else []
    if not domains:
        for u in urls:
            if not isinstance(u, str):
                continue
            host = extractMainDomain(u)
            if host and host not in domains:
                domains.append(host)
    return domains, ips, urls


def _is_weird_domain(domain: str) -> bool:
    host = (domain or "").lower()
    label = host.split(".")[0] if "." in host else host
    if len(label) >= 14 and re.search(r"\d", label):
        return True
    if re.search(r"[a-z]{5,}\d{4,}", label):
        return True
    return False


def _collect_form_posts(transactions: list[dict]) -> list[str]:
    out: list[str] = []
    for tx in transactions:
        if not isinstance(tx, dict):
            continue
        req = tx.get("request", {}) if isinstance(tx.get("request"), dict) else {}
        method = (req.get("method") or "").upper()
        url = req.get("url")
        if method == "POST" and isinstance(url, str):
            if any(h in url.lower() for h in SUSPICIOUS_POST_HINTS):
                if url not in out:
                    out.append(url)
    return out


def _collect_downloaded_files(transactions: list[dict]) -> list[str]:
    out: list[str] = []
    for tx in transactions:
        if not isinstance(tx, dict):
            continue
        req = tx.get("request", {}) if isinstance(tx.get("request"), dict) else {}
        res = tx.get("response", {}) if isinstance(tx.get("response"), dict) else {}
        req_url = req.get("url")
        ctype = (res.get("contentType") or res.get("mimeType") or "").lower()
        disp = (res.get("contentDisposition") or "").lower()
        if any(k in ctype for k in ("application/x-msdownload", "application/octet-stream", "application/x-dosexec", "application/pdf", "application/zip")):
            if isinstance(req_url, str) and req_url not in out:
                out.append(req_url)
        elif "attachment" in disp and isinstance(req_url, str) and req_url not in out:
            out.append(req_url)
    return out


def process_urlscan_response(urlscan_json: dict, now_utc: datetime | None = None) -> dict:
    task = urlscan_json.get("task", {}) if isinstance(urlscan_json.get("task"), dict) else {}
    page = urlscan_json.get("page", {}) if isinstance(urlscan_json.get("page"), dict) else {}
    result = urlscan_json.get("result", {}) if isinstance(urlscan_json.get("result"), dict) else {}
    verdicts = urlscan_json.get("verdicts", {}) if isinstance(urlscan_json.get("verdicts"), dict) else {}
    if not result and (urlscan_json.get("data") or urlscan_json.get("lists")):
        result = urlscan_json

    url = task.get("url") or page.get("url") or ""
    scan_id = urlscan_json.get("uuid") or task.get("uuid") or urlscan_json.get("_id")
    task_time = task.get("time") if isinstance(task.get("time"), str) else None
    screenshot_url = urlscan_json.get("screenshot") or result.get("screenshot") or task.get("screenshotURL")
    main_domain = extractMainDomain(url)

    screenshot_evidence: list[str] = []
    screenshot_risk_notes: list[str] = []
    title = (page.get("title") or "").lower() if isinstance(page.get("title"), str) else ""
    if screenshot_url:
        if any(k in title for k in ("login", "sign in", "verify", "password")):
            screenshot_evidence.append("Page title indicates possible credential collection flow")
        if any(k in title for k in ("bank", "microsoft", "google", "office", "paypal")) and main_domain and not any(k in main_domain for k in ("microsoft", "google", "paypal")):
            screenshot_evidence.append("Potential brand impersonation based on title/domain mismatch")
        screenshot_risk_notes.append("Phishing pages mimicking legitimate sites")

    dom_obj = result.get("dom") or (result.get("data", {}) if isinstance(result.get("data"), dict) else {}).get("dom") or {}
    dom_text = ""
    if isinstance(dom_obj, str):
        dom_text = dom_obj
    elif isinstance(dom_obj, dict):
        dom_text = " ".join(str(v) for v in dom_obj.values() if isinstance(v, (str, int, float)))
    findings: list[str] = []
    indicators: list[str] = []
    suspicious_count = 0

    if isObfuscatedScript(dom_text):
        findings.append("Obfuscated or packed JavaScript pattern detected")
        indicators.append("obfuscation")
        suspicious_count += 1
    if "password" in dom_text.lower() or "type=\"password\"" in dom_text.lower():
        findings.append("Password input field detected")
        indicators.append("credential-harvest")
        suspicious_count += 1
    if detectBase64Blob(dom_text):
        findings.append("Inline base64-like blob detected in DOM/script")
        indicators.append("encoded-payload")
        suspicious_count += 1
    if "action=" in dom_text.lower() and main_domain and re.search(r"action=[\"']https?://", dom_text.lower()):
        action_domains = re.findall(r"action=[\"']https?://([^/\"']+)", dom_text.lower())
        for ad in action_domains:
            ad_main = extractMainDomain("https://" + ad)
            if ad_main and ad_main != main_domain:
                findings.append("Form action posts to a different domain")
                indicators.append("credential-harvest")
                suspicious_count += 1
                break

    domains_contacted, ips_contacted, urls_contacted = _extract_domains_ips(result)
    suspicious_connections: list[str] = []
    network_notes: list[str] = []
    for d in domains_contacted:
        if _is_weird_domain(d):
            suspicious_connections.append(d)
        d_main = extractMainDomain("https://" + d)
        if main_domain and d_main and d_main != main_domain and not d_main.endswith(main_domain):
            if d not in suspicious_connections:
                suspicious_connections.append(d)
    tracker_hits = [d for d in domains_contacted if any(t in d.lower() for t in KNOWN_TRACKERS)]
    if len(tracker_hits) >= 5:
        network_notes.append("Many third-party tracking domains observed")
        suspicious_connections.extend([d for d in tracker_hits if d not in suspicious_connections])
    if verdicts.get("malicious") or verdicts.get("phishing"):
        network_notes.append("urlscan verdict contains malicious/phishing indicator")

    transactions = _coerce_transactions(result)
    redirect_chain = buildRedirectChain(transactions)
    num_redirects = max(len(redirect_chain) - 1, 0)

    encoded_payloads: list[str] = []
    for tx in transactions:
        if not isinstance(tx, dict):
            continue
        serialized = str(tx)
        if detectBase64Blob(serialized):
            encoded_payloads.append("base64-like blob in HTTP transaction")
            break
        if any(k in serialized.lower() for k in ("eval(", "atob(", "unescape(", "\\x")):
            encoded_payloads.append("encoded or obfuscated JavaScript pattern in transaction")
            break

    form_posts = _collect_form_posts(transactions)
    downloaded_files = _collect_downloaded_files(transactions)

    cert_obj = result.get("tls") or result.get("certificate") or {}
    if not isinstance(cert_obj, dict):
        cert_obj = {}
    https_flag = str(url).lower().startswith("https://")
    issuer = cert_obj.get("issuer") if isinstance(cert_obj.get("issuer"), str) else None
    subject_cn = cert_obj.get("subject_cn") or cert_obj.get("subjectCN") or cert_obj.get("cn")
    if not isinstance(subject_cn, str):
        subject_cn = None
    san = cert_obj.get("san") or cert_obj.get("subjectAltName") or []
    if isinstance(san, str):
        san = [san]
    if not isinstance(san, list):
        san = []
    valid_from = cert_obj.get("valid_from") or cert_obj.get("notBefore")
    valid_to = cert_obj.get("valid_to") or cert_obj.get("notAfter")
    valid_from = valid_from if isinstance(valid_from, str) else None
    valid_to = valid_to if isinstance(valid_to, str) else None
    self_signed = bool(issuer and subject_cn and issuer.strip().lower() == subject_cn.strip().lower()) or bool(cert_obj.get("selfSigned"))
    recently_issued = isRecentlyIssued(cert_obj, days=14, now_utc=now_utc)
    domain_mismatch = isDomainMismatch(main_domain, subject_cn, san)

    ssl_notes: list[str] = []
    if self_signed:
        ssl_notes.append("Self-signed certificate")
    if recently_issued:
        ssl_notes.append("Certificate recently issued")
    if domain_mismatch:
        ssl_notes.append("Certificate domain mismatch with scanned URL")
    if not ssl_notes:
        ssl_notes.append("No major certificate anomalies detected")

    reasons: list[str] = []
    flag_count = 0
    has_credential_harvest = "credential-harvest" in indicators or bool(form_posts)
    has_obfuscated = "obfuscation" in indicators or bool(encoded_payloads)
    has_aggressive_redirects = num_redirects >= 3
    has_suspicious_connections = len(suspicious_connections) > 0
    has_file_download = len(downloaded_files) > 0
    exfil_like = any(main_domain and extractMainDomain("https://" + d) != main_domain for d in suspicious_connections)

    for check, reason in [
        (has_obfuscated, "Obfuscation/encoded payload detected"),
        (num_redirects >= 2, "Multiple redirects observed"),
        (recently_issued, "Recently issued certificate"),
        (domain_mismatch, "Certificate domain mismatch"),
        (has_suspicious_connections, "Suspicious external connections detected"),
        (has_credential_harvest, "Credential-harvest signal detected"),
    ]:
        if check:
            flag_count += 1
            reasons.append(reason)

    if has_credential_harvest and exfil_like:
        classification = "MALICIOUS"
    elif has_obfuscated and has_file_download:
        classification = "MALICIOUS"
    elif has_aggressive_redirects and domain_mismatch and recently_issued:
        classification = "MALICIOUS"
    elif flag_count >= 2:
        classification = "SUSPICIOUS"
    else:
        has_data = bool(url or domains_contacted or transactions or dom_text or cert_obj)
        classification = "CLEAN" if has_data else "UNKNOWN"

    if classification == "MALICIOUS":
        confidence = min(95, 80 + flag_count * 3)
        recommended_action = "Block domain/URL jika sesuai policy, isolate host jika ada eksekusi, kumpulkan evidence urlscan (screenshot + requests), eskalasi ke L2/IR"
    elif classification == "SUSPICIOUS":
        confidence = min(79, 55 + flag_count * 4)
        recommended_action = "Korelasi dengan SIEM/EDR/DNS logs, cek user/process, pertimbangkan block sementara, monitor"
    elif classification == "CLEAN":
        confidence = 40 if (domains_contacted or transactions) else 25
        recommended_action = "Dokumentasi dan close dengan catatan"
    else:
        confidence = 25
        recommended_action = "Kumpulkan data tambahan (VT/WHOIS/DNS), rerun scan bila perlu"

    if not reasons:
        reasons.append("No strong malicious indicators found")

    return {
        "url": url,
        "scan_id": scan_id,
        "task_time": task_time,
        "screenshot": {
            "available": bool(screenshot_url),
            "evidence": screenshot_evidence,
            "risk_notes": screenshot_risk_notes,
        },
        "dom_analysis": {
            "suspicious_count": suspicious_count,
            "findings": findings,
            "indicators": sorted(set(indicators)),
        },
        "network_connections": {
            "total_requests": len(transactions),
            "domains_contacted": domains_contacted,
            "ips_contacted": ips_contacted,
            "suspicious_connections": sorted(set(suspicious_connections)),
            "notes": network_notes,
        },
        "ssl_tls_certificate": {
            "https": https_flag,
            "issuer": issuer,
            "subject_cn": subject_cn,
            "san": san,
            "valid_from": valid_from,
            "valid_to": valid_to,
            "flags": {
                "self_signed": self_signed,
                "recently_issued": recently_issued,
                "domain_mismatch": domain_mismatch,
            },
            "notes": ssl_notes,
        },
        "http_transactions": {
            "redirect_chain": redirect_chain,
            "num_redirects": num_redirects,
            "encoded_payloads": encoded_payloads,
            "form_posts": form_posts,
            "downloaded_files": downloaded_files,
            "notes": ["Redirects, encoded payloads"] if (num_redirects > 0 or encoded_payloads) else [],
        },
        "verdict": {
            "classification": classification,
            "confidence": confidence,
            "reasons": reasons,
        },
        "recommended_action": recommended_action,
    }
