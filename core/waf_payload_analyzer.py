"""WAF payload analysis — decode, verdict, flags and rows.

Implements ``docs/waf_payload_analyzer.md``. All three layers now run: decode
(Layer 1), OWASP CRS matching (Layer 3) and curated CVE fingerprints (Layer 4).

**Verdicts are deliberately hard to escalate.** A single rule match is never
``Malicious`` at any severity, and the anomaly score alone never reaches it
either — see :func:`aggregate_verdict`, whose ordering is the module's main
defence against becoming another source of alert fatigue. The one exception is a
CVE fingerprint match, and the admission bar in ``core/data/cve_fingerprints.json``
is what keeps that exception defensible.

The verdict floor is `Unknown`, never `Benign` (plan D9). These lines reach the
tool *because a WAF already flagged them* — "our local rules did not match" is a
statement about our rules, not about the request.

Nothing here performs network I/O, and no payload is ever forwarded anywhere.
The partition in ``app.py`` (plan D6) keeps this type out of provider dispatch;
this module has no provider call to make in the first place.
"""
from __future__ import annotations

import functools
import logging

from dataclasses import asdict, dataclass, field

from core.decode_common import (
    LABEL_BASE64,
    LABEL_ESCAPES,
    LABEL_HTML_ENTITIES,
    LABEL_PERCENT,
    DecodeProfile,
    Transform,
    decode_base64_inline,
    decode_escapes,
    decode_html_entities,
    decode_percent,
    run_pipeline,
)
from core.crs_matcher import MAX_SCAN_LEN as CRS_MAX_SCAN_LEN
from core.crs_matcher import scan as crs_scan
from core.cve_fingerprint import match as cve_match
from core.waf_payload_parser import WafPayloadInput
from ioc.flags.base import _flag, mitre_url

logger = logging.getLogger(__name__)

FLAG_SOURCE = "WAF Payload"

WAF_ENCODED_PAYLOAD = "WAF_ENCODED_PAYLOAD"
WAF_CVE_FINGERPRINT = "WAF_CVE_FINGERPRINT"

# One flag id per CRS category. Ids are prefixed WAF_ and mapped to evidence
# keys explicitly in ioc/flags/__init__.py rather than by the substring matching
# that would otherwise give SQLi an evidence key and XSS none (plan D8).
_CATEGORY_FLAGS = {
    "sqli": "WAF_SQLI_MATCH",
    "xss": "WAF_XSS_MATCH",
    "rce": "WAF_RCE_MATCH",
    "lfi": "WAF_LFI_MATCH",
    "rfi": "WAF_RFI_MATCH",
    "php": "WAF_PHP_INJECTION_MATCH",
    "ssrf": "WAF_SSRF_MATCH",
    "protocol": "WAF_PROTOCOL_ANOMALY",
}
_CATEGORY_LABELS = {
    "sqli": "SQL injection",
    "xss": "cross-site scripting",
    "rce": "command injection",
    "lfi": "local file inclusion",
    "rfi": "remote file inclusion",
    "php": "PHP injection",
    "ssrf": "server-side request forgery",
    "protocol": "HTTP protocol anomaly",
}

# Decode calibration for web payloads. Every field differs deliberately from the
# command-line profile — see :class:`core.decode_common.DecodeProfile`.
#
# ``min_b64_inline`` is **provisional**. It is the one value here without a
# principled derivation: too high and short base64 in a query parameter never
# decodes, too low and ordinary words decode to noise. 20 is a starting point to
# be measured against the Milestone C corpus, and it is safe to be wrong about
# in Milestone A because nothing escalates a verdict yet — a bad decode shows the
# analyst noise with its provenance attached, it cannot manufacture a verdict.
WEB_PROFILE = DecodeProfile(
    # A payload routinely carries exactly one encoded character: %27 for a
    # quote, ..%2f for traversal.
    min_encoding_hits=1,
    min_b64_inline=20,
    # A web payload has no command shape to find.
    b64_require_command_shape=False,
    # Web payloads are UTF-8; UTF-16LE-first is PowerShell's concern.
    b64_utf16_first=False,
    max_rounds=5,
    max_bytes=1_000_000,
)

# Transform order, composed explicitly rather than imported as a bundle so the
# ordering is visible in the module that depends on it. Percent-encoding wraps
# entities wraps escapes in practice, and base64 runs last so it sees an
# already-decoded blob.
_TRANSFORMS: tuple[tuple[str, Transform], ...] = (
    (LABEL_PERCENT, functools.partial(decode_percent, profile=WEB_PROFILE)),
    (LABEL_HTML_ENTITIES, functools.partial(decode_html_entities, profile=WEB_PROFILE)),
    (LABEL_ESCAPES, functools.partial(decode_escapes, profile=WEB_PROFILE)),
    (LABEL_BASE64, functools.partial(decode_base64_inline, profile=WEB_PROFILE)),
)

_MITRE_ENCODED = ["T1027", "T1140"]
_MITRE_EXPLOIT = ["T1190"]

VERDICT_LADDER = ("Unknown", "Suspicious", "Malicious")

# CRS categories treated as high-severity for §4 rule 2. These are the ones
# where a match describes an attack technique rather than an anomaly.
HIGH_SEVERITY_CATEGORIES = frozenset({"sqli", "xss", "rce", "lfi", "rfi", "php"})

# Minimum PL1/PL2 anomaly score for a payload to be worth reporting at all.
#
# **Decisions use the PL1+PL2 score, never the full one.** Measured against
# tests/fixtures/waf_corpus.json, CRS's PL3 and PL4 rules are largely
# punctuation counters: they put an ordinary JSON body at 45 and a shared code
# snippet at 32, higher than several real attacks. Restricting to PL1+PL2 drops
# four benign lines to exactly zero while barely touching the attacks.
#
# 5.0 is one PL1/PL2 rule at CRS's own CRITICAL weight — the smallest signal
# that is not pure punctuation noise.
CRS_SCORE_THRESHOLD = 5.0

# §4 rule 1 is the module's only single-source Malicious. Everything else needs
# two independent layers agreeing — see D10, and the admission bar in
# core/data/cve_fingerprints.json that keeps the exception defensible.
MALICIOUS_REQUIRES_CORROBORATION = True

# Longest artifact string a row may carry, so one pasted payload cannot break
# the table layout.
_ARTIFACT_MAX_LEN = 120


@dataclass
class WafPayloadAnalysisResult:
    """Outcome of analysing one WAF-flagged request line.

    ``checks_skipped`` records anything that did not run for this payload — a
    truncated scan, for instance. Without it, an empty result reads as a clean
    bill of health rather than as an incomplete one.

    Attributes:
        raw_line: The submitted line, verbatim.
        path: Left of the delimiter, or None.
        raw_payload: The payload as submitted.
        decoded_payload: Folded payload; equals ``raw_payload`` when nothing
            fired.
        was_encoded: True when any decode transform applied.
        decode_chain: Applied transforms in order — the provenance that makes
            ``decoded_payload`` trustworthy.
        markers: Which payload-characteristic markers admitted this line.
        parse_ok: False when the payload was empty after splitting.
        decode_ok: False when decoding was truncated by the byte cap or raised.
        crs_matches: Matched CRS rules, heaviest first, capped for display.
        crs_anomaly_score: Sum of matched severity weights across all matches.
        crs_anomaly_score_pl12: The same sum restricted to CRS paranoia levels
            1 and 2. **Verdicts are decided on this**, not on the full score:
            PL3 and PL4 rules count punctuation and fire on ordinary JSON and
            source code.
        crs_anomaly_score_pl1: The same sum restricted to CRS paranoia level
            1, which is what a default CRS deployment would score.
        crs_match_count: True number of matches, including any beyond the cap.
        crs_categories: Distinct attack categories that fired.
        cve_fingerprint_match: The curated CVE signature that fired, or None.
            ``nvd`` and ``kev`` enrichment is attached by the caller.
        checks_skipped: Human-readable list of checks that did not run.
        aggregated_verdict: Malicious | Suspicious | Unknown. Never Benign (D9).
        flags: ``_flag()``-shaped findings, feeding the existing flag system.
    """

    raw_line: str = ""
    path: str | None = None
    raw_payload: str = ""
    decoded_payload: str = ""
    was_encoded: bool = False
    decode_chain: list[str] = field(default_factory=list)
    markers: list[str] = field(default_factory=list)
    parse_ok: bool = True
    decode_ok: bool = True
    crs_matches: list[dict] = field(default_factory=list)
    crs_anomaly_score: float = 0.0
    crs_anomaly_score_pl12: float = 0.0
    crs_anomaly_score_pl1: float = 0.0
    crs_match_count: int = 0
    crs_categories: list[str] = field(default_factory=list)
    cve_fingerprint_match: dict | None = None
    checks_skipped: list[str] = field(default_factory=list)
    aggregated_verdict: str = "Unknown"
    flags: list[dict] = field(default_factory=list)


def decode_payload(payload: str) -> tuple[str, list[str], bool]:
    """Fold a payload to its plain form under the web profile.

    Args:
        payload: Raw payload text, already split from any path.

    Returns:
        Tuple of (decoded text, decode chain, decode_ok). ``decode_ok`` is False
        when the byte cap clipped the output or the pipeline raised — in both
        cases the returned text is not the whole payload, and saying so is the
        difference between a partial decode and a wrong one.
    """
    if not payload:
        return "", [], True

    try:
        run = run_pipeline(payload, _TRANSFORMS, WEB_PROFILE)
    except (ValueError, OverflowError, MemoryError, RecursionError) as exc:
        # run_pipeline already swallows per-transform failures; reaching here
        # means the driver itself failed, which is not something to report as a
        # clean "nothing was encoded".
        logger.warning("payload decode failed: %s", exc)
        return payload, [], False

    return run.text, run.chain, not run.truncated


def _with_link(flag: dict, mitre: list[str], preferred: str = "") -> dict:
    """Attach a source link so the flag's label becomes clickable.

    Args:
        flag: A ``_flag()``-shaped dict.
        mitre: Technique ids; the first usable one supplies a fallback link.
        preferred: A more specific URL, used ahead of the ATT&CK page. A CVE
            fingerprint should link to the CVE, not to T1190.

    Returns:
        The flag, with ``source_url`` set when a link was available.
    """
    url = preferred or next((u for u in (mitre_url(t) for t in mitre) if u), "")
    return {**flag, "source_url": url} if url else flag


def build_flags(result: WafPayloadAnalysisResult) -> list[dict]:
    """Emit ``_flag()``-shaped findings for the existing flag system.

    Milestone A has exactly one flag to raise. It is INFO severity and maps to
    **no** evidence key (plan D8): encoding is an evasion signal, not proof of an
    attack, and forcing it into one would overstate what it shows. The category
    flags that do carry evidence arrive with rule matching in Milestone B.

    Args:
        result: A populated analysis result.

    Returns:
        Flag dicts, empty when nothing was found.
    """
    flags: list[dict] = []

    fingerprint = result.cve_fingerprint_match
    if fingerprint:
        # The CVE id lives in ``detail``, not in the flag id. A per-CVE id could
        # not be placed in the frozenset evidence map and would defeat the
        # deduplication in extract_ioc_flags (plan D8).
        flags.append(_with_link(_flag(
            WAF_CVE_FINGERPRINT,
            f"Known-exploited CVE signature: {fingerprint['name']}",
            "Exploitation",
            "CRITICAL",
            _MITRE_EXPLOIT,
            f"{fingerprint['cve']} ({fingerprint['name']}) — matched "
            f"{fingerprint['matched']!r} in the {fingerprint['matched_on']} payload. "
            f"{fingerprint['why_specific']}",
            FLAG_SOURCE,
        ), _MITRE_EXPLOIT, fingerprint.get("reference", "")))

    for category in result.crs_categories:
        flag_id = _CATEGORY_FLAGS.get(category)
        if flag_id is None:
            continue
        hits = [m for m in result.crs_matches if m.get("category") == category]
        weight = sum(m.get("severity_weight", 0) for m in hits)
        # Severity follows the weight this category contributed, never the count
        # of rules. Counting matches is what turns one noisy rule set into a
        # stream of CRITICALs.
        severity = "HIGH" if weight >= CRS_SCORE_THRESHOLD else "MEDIUM"
        example = hits[0] if hits else {}
        flags.append(_with_link(_flag(
            flag_id,
            f"OWASP CRS {_CATEGORY_LABELS.get(category, category)} pattern match",
            "Exploitation",
            severity,
            _MITRE_EXPLOIT,
            f"{len(hits)} rule(s) matched, weight {weight:g} of a total anomaly "
            f"score of {result.crs_anomaly_score:g}. "
            f"Example: {example.get('rule_id', '?')} — {example.get('message', '')}",
            FLAG_SOURCE,
        ), _MITRE_EXPLOIT, ""))

    if result.was_encoded:
        chain = " -> ".join(result.decode_chain) or "unspecified"
        flags.append(_with_link(_flag(
            WAF_ENCODED_PAYLOAD,
            "WAF payload was encoded",
            "Defense evasion",
            "INFO",
            _MITRE_ENCODED,
            f"Decoded via: {chain}. Legitimate traffic is less likely to arrive "
            "pre-encoded, but encoding alone is not evidence of an attack.",
            FLAG_SOURCE,
        ), _MITRE_ENCODED, ""))

    return flags


def aggregate_verdict(result: WafPayloadAnalysisResult) -> str:
    """Decide the verdict for one analysed payload.

    Implements ``docs/waf_payload_analyzer.md`` §4, whose ordering exists to stop
    this module becoming another source of alert fatigue. Two rules carry most of
    that weight and neither is negotiable:

    * **A single rule match is never Malicious.** Not at any severity, not in any
      category. Briefing §5 names this as the most common cause of WAF alert
      fatigue in real SOC work, and building it in would undercut the tool's
      stated purpose.
    * **CRS can never corroborate itself.** Briefing §4 rule 2 escalates a
      lexical match when "the anomaly score also crosses a threshold", which was
      written on the assumption that libinjection (Layer 2) and CRS (Layer 3)
      were separate engines. D1 merged them, so that condition collapsed into
      *CRS agreeing with CRS* — one layer voting twice. Implemented literally it
      called an ordinary JSON body ``Malicious`` at a score of 45. The only
      corroboration this module has left is genuinely independent: Layer 1 saw
      the payload arrive encoded, or Layer 4 recognised a CVE.

    Decisions use ``crs_anomaly_score_pl12``, never the full score — see
    :data:`CRS_SCORE_THRESHOLD` for the measurement behind that.

    Args:
        result: A populated analysis result, with layers 1, 3 and 4 already run.

    Returns:
        ``Malicious``, ``Suspicious`` or ``Unknown``. Never ``Benign`` (D9): a
        line reached this tool because a WAF flagged it, so "our local rules did
        not match" is a statement about our rules, not about the request.
    """
    # §4 rule 6 — nothing to judge.
    if not result.parse_ok:
        return "Unknown"

    # §4 rule 1 — the one declared exception to corroboration (D10).
    if result.cve_fingerprint_match:
        return "Malicious"

    score = result.crs_anomaly_score_pl12
    if score < CRS_SCORE_THRESHOLD:
        # §4 rule 4 — punctuation noise from CRS's high-paranoia rules. An
        # ordinary query string is not a finding.
        return "Unknown"

    high_severity = bool(
        {m.get("category") for m in result.crs_matches} & HIGH_SEVERITY_CATEGORIES
    )

    # §4 rule 2 — an attack-technique category match, corroborated only by a
    # layer that is not CRS.
    if high_severity and result.was_encoded:
        return "Malicious"

    # §4 rules 2 and 3 — a real signal that nothing independent confirms.
    # Suspicious means unresolved, and for this module it is the common answer
    # rather than a consolation prize.
    return "Suspicious"


def _truncate(value: str) -> str:
    """Shorten an artifact string so one pasted payload cannot break the table."""
    text = " ".join(str(value).split())
    return text if len(text) <= _ARTIFACT_MAX_LEN else text[: _ARTIFACT_MAX_LEN - 1] + "…"


def _row(artifact: str, verdict: str, confidence: str, evidence: str, sources: str) -> dict:
    """Build one table row matching :func:`ioc.verdict.summarize_results`'s schema.

    Every key the IOC rows carry is set explicitly, including the
    ``ConfidenceScore`` family. ``ConfidenceScore`` is ``None`` rather than
    ``""`` for the reason the two sibling modules record: real rows put a number
    there, and an empty string beside it makes a column pyarrow cannot convert,
    which breaks the Table render for the whole run.

    Args:
        artifact: Value shown in the Artifact column.
        verdict: Malicious / Suspicious / Unknown.
        confidence: High / Med / Low.
        evidence: Primary Evidence text.
        sources: Sources text.

    Returns:
        A row dict.
    """
    return {
        "Artifact": artifact,
        "Type": "waf_payload",
        "Verdict": verdict,
        "Confidence": confidence,
        "Primary Evidence": evidence,
        "Next Action": "Review",
        "Sources": sources,
        "ConfidenceScore": None,
        "ConfidenceLabel": "",
        "ProviderScores": {},
        "ActiveProviders": [],
        "InfraNote": "",
        "VerdictFromScore": "",
    }


def to_rows(result: WafPayloadAnalysisResult) -> list[dict]:
    """Render an analysis result as table rows — one per submitted line.

    Uses the identical column schema to :func:`core.cmdline_analyzer.to_rows`,
    so the renderer does not care which module produced a row. Unlike the
    process module, a WAF payload maps 1:1 to a row, so this returns at most one.

    Args:
        result: A populated analysis result.

    Returns:
        Row dicts, empty when no line was submitted.
    """
    if not result.raw_line:
        return []

    fingerprint = result.cve_fingerprint_match
    if not result.parse_ok:
        evidence = "No payload after the delimiter — nothing to analyse"
    elif fingerprint:
        evidence = (
            f"{fingerprint['cve']} ({fingerprint['name']}) signature matched"
        )
    elif not result.decode_ok:
        evidence = "Decoding did not complete; the payload shown is partial"
    elif result.crs_match_count:
        # The score leads, because a single rule id says far less than the
        # weighted total does — and reading one match as decisive is the alert
        # fatigue this module is written to avoid.
        categories = "/".join(result.crs_categories)
        evidence = (
            f"CRS {categories}: {result.crs_match_count} rule(s), "
            f"anomaly score {result.crs_anomaly_score:g}"
        )
    elif result.was_encoded:
        evidence = f"Decoded via: {' -> '.join(result.decode_chain)}; no rule matched"
    else:
        evidence = "No CRS rule or CVE signature matched"

    # Confidence tracks how much agreed, not how loudly. A curated CVE
    # signature is the only single source this module trusts on its own; two
    # layers agreeing is Med; anything less stays Low.
    if result.cve_fingerprint_match:
        confidence = "High"
        sources = "Local (CVE fingerprint)"
    elif result.crs_match_count and result.crs_anomaly_score >= CRS_SCORE_THRESHOLD:
        confidence = "Med"
        sources = "Local (OWASP CRS)"
    elif result.crs_match_count:
        confidence = "Low"
        sources = "Local (OWASP CRS)"
    else:
        confidence = "Low"
        sources = "Local (decode only)"

    return [_row(
        _truncate(result.raw_line),
        result.aggregated_verdict,
        confidence,
        evidence,
        sources,
    )]


def analyze_waf_payload(data: WafPayloadInput) -> WafPayloadAnalysisResult:
    """Analyse one WAF-flagged request line.

    Args:
        data: The split line, as produced by
            :func:`core.waf_payload_parser.parse_waf_line`.

    Returns:
        A populated :class:`WafPayloadAnalysisResult`.
    """
    result = WafPayloadAnalysisResult(
        raw_line=data.raw_line,
        path=data.path,
        raw_payload=data.payload,
        decoded_payload=data.payload,
        markers=list(data.markers),
    )

    if not data.payload.strip():
        # Plan §4 rule 6. parse_ok is what keeps this distinguishable from a
        # payload that simply matched nothing.
        result.parse_ok = False
        return result

    decoded, chain, decode_ok = decode_payload(data.payload)
    result.decoded_payload = decoded
    result.decode_chain = chain
    result.was_encoded = bool(chain)
    result.decode_ok = decode_ok

    # Layer 3. Scored, displayed, and deliberately not allowed to move the
    # verdict — see below.
    scan = crs_scan(data.payload, decoded)
    result.crs_matches = [asdict(m) for m in scan.matches]
    result.crs_anomaly_score = scan.anomaly_score
    result.crs_anomaly_score_pl12 = scan.anomaly_score_pl12
    result.crs_anomaly_score_pl1 = scan.anomaly_score_pl1
    result.crs_match_count = scan.match_count
    result.crs_categories = list(scan.categories)
    if scan.truncated:
        # A scan of the first 2 kB is not a scan of the payload, and the
        # difference has to reach the analyst rather than sitting in a field.
        result.checks_skipped.append(
            f"CRS matching saw only the first {CRS_MAX_SCAN_LEN} characters of "
            "this payload — anything beyond that was not examined"
        )
    # Layer 4. Independent of Layer 3 — a JNDI string trips no CRS category.
    fingerprint = cve_match(data.payload, decoded)
    if fingerprint is not None:
        result.cve_fingerprint_match = asdict(fingerprint)

    result.flags = build_flags(result)
    result.aggregated_verdict = aggregate_verdict(result)

    return result
