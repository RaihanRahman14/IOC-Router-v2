"""Layer 4 — match a payload against curated known-exploited CVE signatures.

Reads ``core/data/cve_fingerprints.json``. This is a **deliberately small,
hand-curated set**, not a classifier: the goal is not to name every CVE a payload
might relate to, but to recognise a handful of mass-exploited ones from a byte
sequence that has no benign reason to exist.

That narrowness is what pays for the module's one exception to its own
corroboration rule. Per ``docs/waf_payload_analyzer.md`` D10, a fingerprint match
returns ``Malicious`` on its own, where every other path needs two independent
layers. The exception holds only while every pattern is impossible in ordinary
traffic — which is why each entry carries a mandatory ``why_specific`` and why
the data file records the candidates that were **rejected** for being too broad.

Independent of Layer 3 by design: a payload can fingerprint-match without
tripping a single CRS rule. ``${jndi:ldap://…}`` is neither SQLi- nor XSS-shaped,
and CRS's own coverage of it arrived after the fact.

No network I/O. Matching is local and offline; enriching a matched CVE with NVD
and KEV data is the caller's job, and a verdict must never depend on that call
succeeding.
"""
from __future__ import annotations

import functools
import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

_DATA_FILE = Path(__file__).parent / "data" / "cve_fingerprints.json"

# Longest payload this layer scans. Far more generous than the CRS bound: these
# are a handful of anchored patterns, not 183 backtracking ones.
MAX_SCAN_LEN = 50_000


@dataclass
class CveFingerprintMatch:
    """One curated CVE signature that fired against a payload.

    Attributes:
        cve: CVE identifier, e.g. ``"CVE-2021-44228"``.
        name: Common name, e.g. ``"Log4Shell"``.
        category: Attack category, aligned with the CRS category names.
        matched: The substring that fired, truncated for display.
        matched_on: ``"raw"`` or ``"decoded"``.
        why_specific: Why this pattern cannot occur in legitimate traffic. Sent
            to the UI and the narrative — the claim being made is strong enough
            that its justification should travel with it.
        reference: Authoritative URL for the CVE.
    """

    cve: str
    name: str
    category: str
    matched: str
    matched_on: str
    why_specific: str
    reference: str


_MATCH_MAX_LEN = 120


@functools.lru_cache(maxsize=1)
def load_fingerprints() -> tuple[dict, ...]:
    """Load and compile the curated fingerprint set.

    Returns:
        Prepared fingerprint dicts. Empty when the file is missing or unreadable,
        which degrades this layer to "found nothing" rather than breaking a run.
    """
    try:
        document = json.loads(_DATA_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("CVE fingerprint file unreadable: %s", exc)
        return ()

    prepared: list[dict] = []
    for entry in document.get("fingerprints", []):
        pattern = entry.get("pattern")
        if not pattern or not entry.get("why_specific"):
            # An entry without a justification cannot be admitted: it is the
            # only record of why this layer is allowed to skip corroboration.
            logger.warning("fingerprint %s rejected: incomplete", entry.get("cve"))
            continue
        flags = re.IGNORECASE if entry.get("case_insensitive", True) else 0
        try:
            compiled = re.compile(pattern, flags)
        except re.error as exc:
            logger.warning("fingerprint %s rejected: %s", entry.get("cve"), exc)
            continue
        prepared.append({**entry, "regex": compiled})

    logger.info("loaded %d CVE fingerprints", len(prepared))
    return tuple(prepared)


def match(raw_payload: str, decoded_payload: str | None = None) -> CveFingerprintMatch | None:
    """Match a payload against the curated fingerprint set.

    Args:
        raw_payload: The payload exactly as submitted.
        decoded_payload: The Layer 1 decoded form. Defaults to ``raw_payload``.

    Returns:
        The first fingerprint that fires, in file order, or None. First rather
        than best: the set is curated so that two entries should not both match
        one payload, and picking a "winner" would imply a ranking the file does
        not have.
    """
    if not raw_payload or not raw_payload.strip():
        return None

    fingerprints = load_fingerprints()
    if not fingerprints:
        return None

    forms: dict[str, str] = {}
    for label, value in (("raw", raw_payload), ("decoded", decoded_payload or raw_payload)):
        forms.setdefault(value[:MAX_SCAN_LEN], label)

    for entry in fingerprints:
        for text, label in forms.items():
            found = entry["regex"].search(text)
            if found is None:
                continue
            matched = found.group(0)
            if len(matched) > _MATCH_MAX_LEN:
                matched = matched[: _MATCH_MAX_LEN - 1] + "…"
            return CveFingerprintMatch(
                cve=entry["cve"],
                name=entry["name"],
                category=entry.get("category", ""),
                matched=matched,
                matched_on=label,
                why_specific=entry["why_specific"],
                reference=entry.get("reference", ""),
            )

    return None
