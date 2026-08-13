"""Layer 3 — match a payload against the extracted OWASP CRS rule set.

Reads ``core/data/crs_patterns.json`` and nothing else. There is no rule engine
here and none is wanted: ``docs/waf_payload_analyzer.md`` §10 rules out running
ModSecurity or Coraza, so this module reproduces only the two things a rule needs
to be evaluated — its transformation chain (:mod:`core.crs_transforms`) and its
pattern.

**Scoring, not deciding.** Each matched rule contributes its CRS severity weight
to an anomaly score, and the caller decides what a score means. No single match
is conclusive at any severity; that is the whole reason CRS scores rather than
blocks on first hit, and D10 makes it a hard rule for this module.

**Matched against two forms, deliberately.** In a live ModSecurity the ``ARGS``
collection is already URL-decoded before rules see it, and 163 of the 197
extracted rules target ``ARGS`` while 47 declare no transformation at all. Those
47 would be blind to every encoded payload if matching ran only on the raw text.
So every rule is evaluated against both the raw payload and the Layer 1 decoded
payload, and each match records which form produced it — provenance the
Milestone C calibration needs in order to decide whether the decoded form is
pulling its weight or just adding noise.
"""
from __future__ import annotations

import functools
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.crs_transforms import apply_chain

logger = logging.getLogger(__name__)

_DATA_FILE = Path(__file__).parent / "data" / "crs_patterns.json"

# Most matched rules a result will carry. The score sums every match; this caps
# only what is stored for display, so one payload tripping fifty rules cannot
# produce an unreadable card or a bloated JSON export.
MAX_STORED_MATCHES = 20

# Longest payload this layer will scan, per form.
#
# **This is a denial-of-service bound, not a tidiness one, and it was measured.**
# Match cost grows roughly quadratically with payload length: 1 kB scans in
# ~78 ms, 4 kB in ~514 ms, 20 kB in ~13 s. A first draft set this to 100 kB and
# a single pasted payload froze the test run outright — in the app that is a
# frozen Streamlit rerun with no way for the analyst to cancel it.
#
# The cost is not spread evenly. Profiling at 8 kB put **88% of the total in
# three rules** — 932390, 941140 and 932290 — whose patterns backtrack badly on
# long low-entropy input. Python's ``re`` has no per-match timeout, so a length
# bound is the only mitigation available without threads or a different engine.
#
# 2 kB keeps a 20-line batch of worst-case payloads near 3.6 s while covering
# real WAF payloads comfortably: a JNDI string is ~50 characters, an obfuscated
# XSS vector rarely passes 1 kB. Truncation is recorded on the result rather
# than being silent, because a scan of the first 2 kB is not a scan of the
# payload.
MAX_SCAN_LEN = 2_000


@dataclass
class CrsMatch:
    """One CRS rule that fired against a payload.

    Attributes:
        rule_id: CRS rule id, e.g. ``"942100"``.
        category: Attack category the rule's file contributes.
        severity: CRS severity name.
        severity_weight: CRS anomaly weight for that severity.
        paranoia_level: CRS paranoia level. Higher levels are progressively more
            false-positive prone by CRS's own account.
        message: The rule's ``msg:`` text.
        matched_on: ``"raw"`` or ``"decoded"`` — which form of the payload
            produced the match.
        dropped_conditions: What the offline extraction could not carry over.
        unsupported_transforms: Transformations the rule asked for that were not
            performed, so the pattern saw text the rule did not expect.
    """

    rule_id: str
    category: str
    severity: str
    severity_weight: float
    paranoia_level: int
    message: str
    matched_on: str
    dropped_conditions: list[str] = field(default_factory=list)
    unsupported_transforms: list[str] = field(default_factory=list)


@dataclass
class CrsScanResult:
    """Outcome of scanning one payload against the whole rule set.

    Attributes:
        matches: Matched rules, highest severity first, capped at
            :data:`MAX_STORED_MATCHES`.
        anomaly_score: Sum of severity weights across **all** matches, including
            any beyond the storage cap.
        anomaly_score_pl12: The sum restricted to paranoia levels 1 and 2.
            **This is the figure decisions are made on.** CRS's PL3 and PL4
            rules are largely punctuation counters — "more than N special
            characters in this argument" — and they fire on ordinary JSON, CSV
            and source code. Measured against the corpus they put benign text at
            up to 45 while adding little to real payloads, so counting them
            would mean calibrating a threshold against noise.
        anomaly_score_pl1: The same sum restricted to paranoia level 1. CRS
            itself ships PL1 enabled and treats higher levels as opt-in because
            they trade precision for reach, so this is the figure comparable to
            what a default CRS deployment would score. Carried separately
            because ``matches`` is capped and cannot be re-summed downstream.
        match_count: True number of matched rules.
        categories: Distinct categories that fired, at any paranoia level.
        category_stats: Per-category totals computed over **every** match, not
            over the display-capped ``matches`` list, and split by paranoia
            level: ``{category: {count, weight, count_pl12, weight_pl12}}``.
            Consumers that report or escalate on a category must read this —
            deriving counts from ``matches`` silently under-reports any category
            whose matches fell past the cap, and deriving them from all paranoia
            levels re-admits the punctuation noise that verdicts exclude.
        truncated: True when the payload was longer than :data:`MAX_SCAN_LEN`
            and only its head was scanned.
    """

    matches: list[CrsMatch] = field(default_factory=list)
    anomaly_score: float = 0.0
    anomaly_score_pl12: float = 0.0
    anomaly_score_pl1: float = 0.0
    match_count: int = 0
    categories: list[str] = field(default_factory=list)
    category_stats: dict[str, dict[str, float]] = field(default_factory=dict)
    truncated: bool = False


@functools.lru_cache(maxsize=1)
def load_rules() -> tuple[dict[str, Any], ...]:
    """Load and compile the extracted CRS rule set.

    Compilation happens once per process. A rule whose pattern fails to compile
    is skipped with a warning rather than taking the module down — the extractor
    compile-verifies before emitting, so reaching that branch means the shipped
    file is stale or hand-edited.

    Returns:
        Prepared rule dicts. Empty when the data file is missing or unreadable,
        which degrades this layer to "found nothing" rather than breaking a run.
    """
    try:
        document = json.loads(_DATA_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("CRS pattern file unreadable: %s", exc)
        return ()

    phrase_lists = document.get("phrase_lists", {})
    prepared: list[dict[str, Any]] = []

    for rule in document.get("rules", []):
        entry: dict[str, Any] = {
            "rule_id": rule.get("rule_id", ""),
            "category": rule.get("category", ""),
            "severity": rule.get("severity", ""),
            "severity_weight": float(rule.get("severity_weight", 1.0)),
            "paranoia_level": int(rule.get("paranoia_level", 1)),
            "message": rule.get("message", ""),
            "chain": tuple(rule.get("transformations", ())),
            "dropped_conditions": list(rule.get("dropped_conditions", ())),
        }

        if rule.get("match") == "regex":
            try:
                entry["regex"] = re.compile(rule["pattern"])
            except (re.error, KeyError) as exc:
                logger.warning("CRS rule %s skipped: %s", entry["rule_id"], exc)
                continue
        else:
            phrases = rule.get("phrases")
            if phrases is None:
                phrases = phrase_lists.get(rule.get("phrase_list", ""), [])
            if not phrases:
                logger.warning("CRS rule %s has no phrases", entry["rule_id"])
                continue
            # @pm / @pmFromFile match case-insensitively as substrings.
            entry["phrases"] = tuple(p.lower() for p in phrases if p)

        prepared.append(entry)

    logger.info("loaded %d CRS rules", len(prepared))
    return tuple(prepared)


def _fires(rule: dict[str, Any], text: str) -> bool:
    """Report whether one prepared rule matches already-transformed text."""
    regex = rule.get("regex")
    if regex is not None:
        try:
            return bool(regex.search(text))
        except (re.error, RecursionError):
            logger.warning("CRS rule %s failed at match time", rule["rule_id"])
            return False
    lowered = text.lower()
    return any(phrase in lowered for phrase in rule["phrases"])


def scan(raw_payload: str, decoded_payload: str | None = None) -> CrsScanResult:
    """Match a payload against every extracted CRS rule.

    Args:
        raw_payload: The payload exactly as submitted.
        decoded_payload: The Layer 1 decoded form. Defaults to ``raw_payload``,
            in which case only one form is scanned.

    Returns:
        A :class:`CrsScanResult`. Empty with a zero score when nothing matched —
        which is a statement about this rule subset, never a clean bill of
        health for the payload.
    """
    if not raw_payload or not raw_payload.strip():
        return CrsScanResult()

    rules = load_rules()
    if not rules:
        return CrsScanResult()

    truncated = False
    forms: dict[str, str] = {}
    for label, value in (("raw", raw_payload), ("decoded", decoded_payload or raw_payload)):
        if len(value) > MAX_SCAN_LEN:
            value = value[:MAX_SCAN_LEN]
            truncated = True
        forms.setdefault(value, label)
    # forms is keyed by text so an unencoded payload, whose raw and decoded
    # forms are identical, is scanned once rather than twice.
    bases = [(label, text) for text, label in forms.items()]

    # Chains repeat heavily across the rule set — 61 rules share one — so each
    # (base, chain) pair is transformed once per scan rather than once per rule.
    cache: dict[tuple[str, tuple[str, ...]], tuple[str, list[str]]] = {}

    matches: list[CrsMatch] = []
    stats: dict[str, dict[str, float]] = {}
    score = 0.0
    score_pl12 = 0.0
    score_pl1 = 0.0

    for rule in rules:
        for label, base in bases:
            key = (label, rule["chain"])
            if key not in cache:
                cache[key] = apply_chain(base, rule["chain"])
            transformed, unsupported = cache[key]

            if not _fires(rule, transformed):
                continue

            matches.append(CrsMatch(
                rule_id=rule["rule_id"],
                category=rule["category"],
                severity=rule["severity"],
                severity_weight=rule["severity_weight"],
                paranoia_level=rule["paranoia_level"],
                message=rule["message"],
                matched_on=label,
                dropped_conditions=list(rule["dropped_conditions"]),
                unsupported_transforms=unsupported,
            ))
            bucket = stats.setdefault(
                rule["category"],
                {"count": 0, "weight": 0.0, "count_pl12": 0, "weight_pl12": 0.0},
            )
            bucket["count"] += 1
            bucket["weight"] += rule["severity_weight"]
            if rule["paranoia_level"] <= 2:
                bucket["count_pl12"] += 1
                bucket["weight_pl12"] += rule["severity_weight"]

            score += rule["severity_weight"]
            if rule["paranoia_level"] <= 2:
                score_pl12 += rule["severity_weight"]
            if rule["paranoia_level"] <= 1:
                score_pl1 += rule["severity_weight"]
            # One rule contributes once, even when both forms would fire.
            break

    # Heaviest first, then lowest paranoia level: a PL1 critical is the finding
    # an analyst should read before a PL4 one of the same weight.
    matches.sort(key=lambda m: (-m.severity_weight, m.paranoia_level, m.rule_id))

    return CrsScanResult(
        matches=matches[:MAX_STORED_MATCHES],
        anomaly_score=round(score, 2),
        anomaly_score_pl12=round(score_pl12, 2),
        anomaly_score_pl1=round(score_pl1, 2),
        match_count=len(matches),
        categories=sorted(stats),
        category_stats={
            cat: {k: round(v, 2) for k, v in vals.items()}
            for cat, vals in sorted(stats.items())
        },
        truncated=truncated,
    )
