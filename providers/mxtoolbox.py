"""MxToolBox client — DNS, blacklist, and mail security lookups."""
from __future__ import annotations

import ipaddress
import logging
from urllib.parse import urlparse

import requests

from config import Settings
from core.http import get_session
from ioc.parser import IOC

logger = logging.getLogger(__name__)

MXTOOLBOX_BASE = "https://api.mxtoolbox.com/api/v1/Lookup"

# Commands we run per IOC type
_IP_COMMANDS = ["blacklist", "ptr", "ping"]
_DOMAIN_COMMANDS = ["mx", "dns", "spf", "dmarc", "blacklist", "http"]
_EMAIL_COMMANDS = ["mx", "spf", "dmarc"]
_URL_COMMANDS = ["mx", "dns", "spf", "dmarc", "blacklist", "http"]


def _host_from_url(value: str) -> str:
    try:
        parsed = urlparse(value)
        return (parsed.hostname or "").strip().lower()
    except ValueError:
        return ""


def _argument_for_ioc(ioc: IOC) -> str | None:
    if ioc.type == "ip":
        return ioc.value
    if ioc.type == "domain":
        return ioc.value
    if ioc.type == "url":
        return _host_from_url(ioc.value) or None
    if ioc.type == "email":
        parts = ioc.value.split("@")
        return parts[-1] if len(parts) == 2 else None
    return None


def _commands_for_ioc(ioc: IOC) -> list[str]:
    if ioc.type == "ip":
        return _IP_COMMANDS
    if ioc.type == "domain":
        return _DOMAIN_COMMANDS
    if ioc.type == "email":
        return _EMAIL_COMMANDS
    if ioc.type == "url":
        return _URL_COMMANDS
    return []


def _run_lookup(command: str, argument: str, api_key: str, timeout: int = 20) -> dict:
    """Call a single MxToolBox lookup command."""
    try:
        r = get_session().get(
            f"{MXTOOLBOX_BASE}/{command}/",
            headers={"Authorization": api_key},
            params={"argument": argument},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        return {"error": str(exc)}
    if r.status_code == 401:
        return {"error": "MXTOOLBOX_KEY is invalid or unauthorized"}
    if r.status_code == 429:
        return {"error": "MxToolBox quota exceeded"}
    if r.status_code != 200:
        body = (r.text or "").strip().replace("\n", " ")
        return {"error": f"HTTP {r.status_code}: {body[:200]}"}
    try:
        return r.json()
    except ValueError:
        return {"error": "Invalid JSON response"}


def _summarize_lookup(command: str, data: dict) -> dict:
    """Extract a normalized summary from a single lookup result."""
    failed = data.get("Failed") or []
    warnings = data.get("Warnings") or []
    passed = data.get("Passed") or []
    timeouts = data.get("Timeouts") or []
    information = data.get("Information") or []

    def _extract_items(items: list) -> list[str]:
        out = []
        for item in items:
            if isinstance(item, dict):
                name = item.get("Name") or item.get("Info") or item.get("Description") or ""
                info = item.get("Info") or item.get("Result") or item.get("Value") or ""
                text = f"{name}: {info}".strip(": ").strip()
                if text:
                    out.append(text)
            elif isinstance(item, str):
                out.append(item)
        return out

    return {
        "command": command,
        "failed": _extract_items(failed),
        "warnings": _extract_items(warnings),
        "passed": _extract_items(passed),
        "timeouts": _extract_items(timeouts),
        "information": _extract_items(information),
        "raw_failed_count": len(failed),
        "raw_warning_count": len(warnings),
        "raw_passed_count": len(passed),
    }


def mxtoolbox_lookup_batch(items: list[IOC], settings: Settings) -> dict[str, dict]:
    """Run MxToolBox lookups for a list of IOCs and return aggregated results."""
    out: dict[str, dict] = {}

    if not settings.mxtoolbox_key:
        for ioc in items:
            out[ioc.value] = {"error": "MXTOOLBOX_KEY is missing"}
        return out

    for ioc in items:
        argument = _argument_for_ioc(ioc)
        commands = _commands_for_ioc(ioc)

        if not argument or not commands:
            out[ioc.value] = {"error": f"No supported lookup for IOC type '{ioc.type}'"}
            continue

        lookups: dict[str, dict] = {}
        total_failed = 0
        total_warnings = 0
        total_passed = 0

        for cmd in commands:
            raw = _run_lookup(cmd, argument, settings.mxtoolbox_key)
            if raw.get("error"):
                lookups[cmd] = {"error": raw["error"]}
                continue
            summary = _summarize_lookup(cmd, raw)
            lookups[cmd] = summary
            total_failed += summary["raw_failed_count"]
            total_warnings += summary["raw_warning_count"]
            total_passed += summary["raw_passed_count"]

        # Derive overall verdict
        if total_failed > 0:
            verdict = "FAIL"
        elif total_warnings > 0:
            verdict = "WARN"
        elif total_passed > 0:
            verdict = "PASS"
        else:
            verdict = "UNKNOWN"

        out[ioc.value] = {
            "argument": argument,
            "lookups": lookups,
            "total_failed": total_failed,
            "total_warnings": total_warnings,
            "total_passed": total_passed,
            "verdict": verdict,
        }

    return out
