"""Shared helpers and flag builder for all per-provider flag extractors."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _flag(
    id: str,
    label: str,
    threat_type: str,
    severity: str,
    mitre: list[str],
    detail: str,
    source: str,
) -> dict:
    return {
        "id": id,
        "label": label,
        "threat_type": threat_type,
        "severity": severity,          # CRITICAL / HIGH / MEDIUM / LOW / INFO
        "mitre": mitre,
        "detail": detail,
        "source": source,
    }


MITRE_TECHNIQUE_BASE_URL = "https://attack.mitre.org/techniques"


def mitre_url(technique: str) -> str:
    """Build the ATT&CK page URL for a technique id.

    Canonical home for a helper that `core.process_analyzer` and
    `core.cmdline_analyzer` each carry a byte-identical private copy of. New
    call sites use this one; folding those two into it is a separate cleanup,
    kept out of the change that introduced this so the shipped modules stay
    untouched.

    Args:
        technique: e.g. ``"T1036.005"`` or ``"T1105"``.

    Returns:
        The technique's ATT&CK URL, or ``""`` for an unrecognised id.
    """
    value = str(technique or "").strip().upper()
    if not value.startswith("T"):
        return ""
    return f"{MITRE_TECHNIQUE_BASE_URL}/{value.replace('.', '/')}/"


def _days_since(ts: Any) -> int | None:
    """Convert unix timestamp or ISO string to age in days. None if unparseable."""
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        try:
            dt = datetime.fromtimestamp(int(ts), tz=timezone.utc)
            return (datetime.now(tz=timezone.utc) - dt).days
        except Exception:
            return None
    if isinstance(ts, str):
        raw = ts.strip().rstrip("Z")
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(raw[:len(fmt)+2], fmt).replace(tzinfo=timezone.utc)
                return (datetime.now(tz=timezone.utc) - dt).days
            except Exception:
                continue
    return None


def _safe_int(val: Any, default: int = 0) -> int:
    try:
        return int(val)
    except Exception:
        return default


# Map infra-classifier category to threat-flag id label and threat-type wording.
_INFRA_LABELS = {
    "BP":        ("INFRA_BENIGN",       "Benign infra (anycast/CDN/public DNS)",  "Hard whitelist — legitimate shared anycast infra"),
    "FP":        ("INFRA_FP_PRONE",     "FP-prone shared hosting",                "Shared hosting / hyperscaler compute — confidence discount"),
    "HIGH_RISK": ("INFRA_HIGH_RISK",    "Bulletproof / high-risk hosting",        "Known abuse-friendly / bulletproof hosting provider"),
}


def _flag_from_infra(infra: dict | None, source: str) -> dict | None:
    """Build a threat-indicator flag from an infra classification dict.

    Args:
        infra: Dict returned by ``core.infra_classifier.classify`` (with keys
            ``category``, ``severity``, ``provider``, ``reason``, ``asn``).
            Pass ``None`` to short-circuit and return ``None``.
        source: Provider name to attribute the flag to (e.g. ``"Shodan"``).

    Returns:
        A flag dict suitable for ``flags`` lists, or ``None`` if ``infra`` is
        falsy or its category is unknown.
    """
    if not isinstance(infra, dict):
        return None
    category = infra.get("category")
    if category not in _INFRA_LABELS:
        return None
    base_id, label, threat_type = _INFRA_LABELS[category]
    severity = infra.get("severity") or "LOW"
    provider = infra.get("provider") or "unknown"
    asn = infra.get("asn")
    reason = infra.get("reason") or ""
    detail = f"Provider: {provider}"
    if asn is not None:
        detail += f" (AS{asn})"
    if reason:
        detail += f" — {reason}"
    return _flag(
        f"{base_id}_{source.upper()}",
        f"{label}: {provider}",
        threat_type,
        severity,
        [],
        detail,
        source,
    )
