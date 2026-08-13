"""Hybrid Analysis (Falcon Sandbox) enrichment helpers."""
from __future__ import annotations

from typing import Any

import requests

from config import Settings
from core.http import get_session
from ioc.parser import IOC


HA_BASE = "https://hybrid-analysis.com/api/v2"
DEFAULT_TIMEOUT = 20


def _headers(api_key: str) -> dict[str, str]:
    return {
        "api-key": api_key,
        "accept": "application/json",
        "user-agent": "Falcon",
    }


def _request(method: str, path: str, api_key: str, **kwargs: Any) -> Any:
    try:
        response = get_session().request(
            method,
            f"{HA_BASE}{path}",
            headers=_headers(api_key),
            timeout=DEFAULT_TIMEOUT,
            **kwargs,
        )
    except requests.RequestException as exc:
        return {"error": str(exc)}
    if response.status_code >= 400:
        body = response.text[:300] if isinstance(response.text, str) else ""
        return {"error": f"HTTP {response.status_code}: {body}"}
    try:
        return response.json()
    except ValueError:
        return {}


def _base_output(ioc_type: str, ioc_value: str) -> dict[str, Any]:
    return {
        "source": "Hybrid Analysis",
        "ioc_type": ioc_type,
        "ioc_value": ioc_value,
        "verdict": "",
        "threat_score": "",
        "malware_family": "",
        "file_information": {
            "file_name": "",
            "file_type": "",
            "file_size": "",
        },
        "analysis_environment": "",
        "analysis_time": "",
        "network_ioc": {
            "domains": [],
            "ips": [],
        },
        "behavior": {
            "process_activity": [],
            "persistence": [],
            "dropped_files": [],
            "mutex": [],
        },
        "mitre_attack": [],
    }


def _ensure_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value in (None, "", {}):
        return []
    return [value]


def _string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _first_present(obj: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in obj and obj.get(key) not in (None, ""):
            return obj.get(key)
    return None


def _flatten_texts(value: Any) -> list[str]:
    out: list[str] = []
    if isinstance(value, str):
        text = value.strip()
        if text:
            out.append(text)
    elif isinstance(value, dict):
        parts = []
        for key in ("name", "value", "command_line", "commandline", "path", "process_name", "description"):
            item = value.get(key)
            if isinstance(item, str) and item.strip():
                parts.append(item.strip())
        if parts:
            out.append(" | ".join(parts))
    elif isinstance(value, list):
        for item in value:
            out.extend(_flatten_texts(item))
    return out


def _uniq(values: list[str]) -> list[str]:
    out: list[str] = []
    seen = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _coerce_summary_rows(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [row for row in data if isinstance(row, dict)]
    if isinstance(data, dict):
        if isinstance(data.get("data"), list):
            return [row for row in data["data"] if isinstance(row, dict)]
        if isinstance(data.get("result"), list):
            return [row for row in data["result"] if isinstance(row, dict)]
    return []


def _extract_domains(value: Any) -> list[str]:
    out: list[str] = []
    for item in _ensure_list(value):
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            candidate = _first_present(item, "domain", "host", "hostname", "name")
            if candidate:
                out.append(_string(candidate))
    return _uniq(out)


def _extract_ips(value: Any) -> list[str]:
    out: list[str] = []
    for item in _ensure_list(value):
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            candidate = _first_present(item, "ip", "ip_address", "host")
            if candidate:
                out.append(_string(candidate))
    return _uniq(out)


def _extract_dropped_files(value: Any) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for item in _ensure_list(value):
        if not isinstance(item, dict):
            continue
        out.append(
            {
                "name": _string(_first_present(item, "filename", "name")),
                "sha256": _string(_first_present(item, "sha256", "file_sha256")),
                "type": _string(_first_present(item, "type", "file_type")),
            }
        )
    return [row for row in out if any(row.values())]


def _extract_mitre(report: dict[str, Any]) -> list[str]:
    hits: list[str] = []
    for key in ("mitre_attcks", "mitre_attck", "mitre_attack", "mitre", "attcks"):
        value = report.get(key)
        for item in _ensure_list(value):
            if isinstance(item, str):
                hits.append(item)
            elif isinstance(item, dict):
                technique = _first_present(item, "technique", "id", "name", "attck_id")
                if technique:
                    hits.append(_string(technique))
    return _uniq(hits)


def _extract_persistence(process_entries: list[str]) -> list[str]:
    keywords = ("run", "startup", "autorun", "registry", "schtasks", "service", "persistence")
    return [entry for entry in process_entries if any(word in entry.lower() for word in keywords)]


def _find_first_nested(report: dict[str, Any], keys: tuple[str, ...]) -> Any:
    stack: list[Any] = [report]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            for key, value in current.items():
                if key in keys and value not in (None, "", [], {}):
                    return value
                stack.append(value)
        elif isinstance(current, list):
            stack.extend(current)
    return None


def _report_domains(report: dict[str, Any]) -> list[str]:
    value = _find_first_nested(report, ("contacted_domains", "domains", "hosts"))
    return _extract_domains(value)


def _report_ips(report: dict[str, Any]) -> list[str]:
    value = _find_first_nested(report, ("contacted_hosts", "contacted_ips", "hosts", "ips"))
    return _extract_ips(value)


def _report_processes(report: dict[str, Any]) -> list[str]:
    value = _find_first_nested(report, ("process_tree", "processes", "process_list"))
    return _uniq(_flatten_texts(value))


def _report_mutex(report: dict[str, Any]) -> list[str]:
    value = _find_first_nested(report, ("mutex", "mutexes", "mutants"))
    return _uniq(_flatten_texts(value))


def _report_dropped_files(report: dict[str, Any]) -> list[dict[str, str]]:
    value = _find_first_nested(report, ("dropped_files", "extracted_files", "dropped"))
    return _extract_dropped_files(value)


def _hash_lookup(hash_value: str, api_key: str) -> dict[str, Any]:
    output = _base_output("hash", hash_value)

    # Step 1: Search/hash to get job_id.
    # Response format: {"sha256s": [...], "reports": [{"id": "...", "verdict": "...", ...}]}
    job_id = ""
    search_resp = _request("GET", "/search/hash", api_key, params={"hash": hash_value})
    if isinstance(search_resp, dict):
        report_list = search_resp.get("reports") or []
        if report_list and isinstance(report_list, list) and isinstance(report_list[0], dict):
            job_id = _string(_first_present(report_list[0], "id", "job_id"))
    elif isinstance(search_resp, list) and search_resp:
        job_id = _string(_first_present(search_resp[0], "id", "job_id"))

    if not job_id:
        output["message"] = "No results found"
        return output

    # Step 2: Full report summary — contains verdict, threat_score, vx_family,
    # domains, hosts, processes, mitre_attcks, file info, etc.
    report = _request("GET", f"/report/{job_id}/summary", api_key)
    if not isinstance(report, dict) or report.get("error"):
        output["report_error"] = report.get("error") if isinstance(report, dict) else "Unable to retrieve report"
        return output

    # Basic fields
    output["verdict"] = _string(report.get("verdict"))
    output["threat_score"] = _string(report.get("threat_score"))
    output["malware_family"] = _string(_first_present(report, "vx_family", "family"))
    file_type = _first_present(report, "type_short", "type")
    if isinstance(file_type, list):
        file_type = ", ".join(str(x) for x in file_type)
    output["file_information"] = {
        "file_name": _string(_first_present(report, "submit_name", "file_name")),
        "file_type": _string(file_type),
        "file_size": _string(report.get("size")),
    }
    output["analysis_environment"] = _string(report.get("environment_description"))
    output["analysis_time"] = _string(report.get("analysis_start_time"))
    output["sha256"] = _string(report.get("sha256"))
    output["av_detect"] = _string(report.get("av_detect"))

    # Network IOC — report summary exposes flat "domains" and "hosts" lists at top level
    domains_raw = report.get("domains") or []
    hosts_raw = report.get("hosts") or []
    output["network_ioc"]["domains"] = _extract_domains(domains_raw) if domains_raw else _report_domains(report)
    output["network_ioc"]["ips"] = _extract_ips(hosts_raw) if hosts_raw else _report_ips(report)

    # Behavioral data
    process_activity = _report_processes(report)
    output["behavior"]["process_activity"] = process_activity
    output["behavior"]["persistence"] = _extract_persistence(process_activity)
    output["behavior"]["dropped_files"] = _report_dropped_files(report)
    output["behavior"]["mutex"] = _report_mutex(report)
    output["mitre_attack"] = _extract_mitre(report)

    return output


def _quick_scan_url(url: str, api_key: str) -> dict[str, Any]:
    submitted = _request("POST", "/quick-scan/url", api_key, data={"url": url, "scan_type": "all"})
    if not isinstance(submitted, dict):
        return {"error": "Invalid quick scan response"}
    if submitted.get("error"):
        return submitted

    scan_id = _string(_first_present(submitted, "id", "quick_scan_id", "job_id"))
    details = submitted
    if scan_id:
        fetched = _request("GET", f"/quick-scan/{scan_id}", api_key)
        if isinstance(fetched, dict) and not fetched.get("error"):
            details = fetched
    return details


def _url_lookup(url: str, api_key: str) -> dict[str, Any]:
    output = _base_output("url", url)
    details = _quick_scan_url(url, api_key)
    if not isinstance(details, dict) or details.get("error"):
        output["message"] = details.get("error") if isinstance(details, dict) else "Quick scan failed"
        return output

    verdict = _first_present(details, "verdict", "status", "classification")
    threat_score = _first_present(details, "threat_score", "score", "threatlevel")
    redirects = _ensure_list(_first_present(details, "redirect_chain", "redirects"))
    downloaded = _ensure_list(_first_present(details, "downloaded_files", "downloads"))
    domains = _extract_domains(_first_present(details, "contacted_domains", "domains", "hosts"))
    ips = _extract_ips(_first_present(details, "contacted_ips", "ips", "resolved_ips"))

    output["verdict"] = _string(verdict)
    output["threat_score"] = _string(threat_score)
    output["network_ioc"]["domains"] = domains
    output["network_ioc"]["ips"] = ips
    output["behavior"]["dropped_files"] = _extract_dropped_files(downloaded)
    output["redirect_chain"] = [item for item in redirects if isinstance(item, str)]
    return output


def _search_terms(value: str, api_key: str, candidates: list[str]) -> list[dict[str, Any]]:
    for field in candidates:
        rows = _coerce_summary_rows(_request("POST", "/search/terms", api_key, data={field: value}))
        if rows:
            return rows
    return []


def _domain_lookup(domain: str, api_key: str) -> dict[str, Any]:
    output = _base_output("domain", domain)
    output["message"] = "Not supported by Hybrid Analysis API"

    rows = _search_terms(domain, api_key, ["domain", "hostname", "host"])
    output["related_hashes"] = _uniq([_string(_first_present(row, "sha256", "sha1", "md5")) for row in rows if _first_present(row, "sha256", "sha1", "md5")])
    output["malware_family"] = _string(_first_present(rows[0], "vx_family")) if rows else ""
    output["first_seen"] = _string(_first_present(rows[0], "analysis_start_time", "submit_time", "created_at")) if rows else ""
    output["network_activity_context"] = _uniq(
        [
            _string(_first_present(row, "environment_description", "verdict", "threat_score"))
            for row in rows
            if _first_present(row, "environment_description", "verdict", "threat_score")
        ]
    )
    return output


def _ip_lookup(ip_value: str, api_key: str) -> dict[str, Any]:
    output = _base_output("ip", ip_value)
    output["message"] = "Not supported by Hybrid Analysis API"

    rows = _search_terms(ip_value, api_key, ["host", "ip", "domain"])
    output["seen_in_samples"] = _uniq([_string(_first_present(row, "sha256", "sha1", "md5")) for row in rows if _first_present(row, "sha256", "sha1", "md5")])
    output["related_domains"] = _uniq(
        [
            _string(_first_present(row, "host", "domain", "submit_name"))
            for row in rows
            if _first_present(row, "host", "domain", "submit_name")
        ]
    )
    output["related_malware_family"] = _uniq(
        [_string(row.get("vx_family")) for row in rows if row.get("vx_family")]
    )
    return output


def hybrid_analysis_enrich(
    ioc_type: str, ioc_value: str, settings: Settings | None = None
) -> dict[str, Any]:
    """Enrich a single IOC via Hybrid Analysis.

    Args:
        ioc_type: IOC type — ``hash``, ``url``, ``domain``, ``ip``, or ``email``.
        ioc_value: The indicator to look up.
        settings: Settings carrying ``hybrid_analysis_key``. Falls back to the
            environment when omitted, which is what the standalone scripts and
            tests rely on; the app always passes the resolved Settings so a key
            entered in the API drawer takes precedence over ``.env``.

    Returns:
        The provider's result dict — always populated, carrying ``message`` when
        the lookup could not run.
    """
    ioc_type_normalized = _string(ioc_type).strip().lower()
    value = _string(ioc_value).strip()
    key = (settings or Settings.from_env()).hybrid_analysis_key

    if ioc_type_normalized == "email":
        output = _base_output("email", value)
        output["message"] = "Hybrid Analysis does not analyze email indicators."
        return output

    if not key:
        output = _base_output(ioc_type_normalized, value)
        output["message"] = "HYBRID_ANALYSIS_KEY is missing"
        return output

    if ioc_type_normalized == "hash":
        return _hash_lookup(value, key)
    if ioc_type_normalized == "url":
        return _url_lookup(value, key)
    if ioc_type_normalized == "domain":
        return _domain_lookup(value, key)
    if ioc_type_normalized == "ip":
        return _ip_lookup(value, key)

    output = _base_output(ioc_type_normalized, value)
    output["message"] = "Not supported by Hybrid Analysis API"
    return output


def hybrid_analysis_lookup_batch(
    items: list[IOC], settings: Settings | None = None
) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for ioc in items:
        out[ioc.value] = hybrid_analysis_enrich(ioc.type, ioc.value, settings)
    return out
