"""Command-line analysis — Layers 3 and 6, flag emission and verdict aggregation.

Implements ``docs/cmdline_analyzer.md``. The pipeline is:

1. :mod:`core.cmdline_deobfuscator` folds the line (Layer 2);
2. :mod:`core.cmdline_parser` tokenizes the *folded* text (Layer 1) — matching
   against a still-encoded string finds nothing;
3. Layer 3 matches the curated keyword table;
4. Layer 6 scores token entropy as a weak fallback;
5. indicators found in the decoded text are returned as candidates for the
   caller to enrich.

This module performs **no network I/O**. Like :mod:`core.process_analyzer`, it
returns ``ioc_candidates`` and lets ``app.py`` feed them into the existing
enrichment pipeline, so a decoded download cradle produces a fully enriched URL
row without a second analyst action and without a second lookup path here.

**Corroboration rule.** Per the project's "aggregate from a minimum of two
sources before a final verdict" rule, :data:`MALICIOUS_REQUIRES_CORROBORATION`
holds a verdict at ``Suspicious`` unless a second, independent source agrees —
a Sigma CommandLine rule (Layer 5) or a confirmed LOLBAS abuse pattern
(Layer 4, still unbuilt). Keyword hits and obfuscation, however many, are one
source between them.

**Layer 5 matches only rules it can fully evaluate.** See
:func:`match_sigma_patterns` — the shipped dataset is mostly *fragments* of
rules whose remaining conditions this module cannot see, and matching those
standalone flagged every benign sample in the calibration corpus. Fragments are
consulted only through the D6 rule-id join.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import math
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path, PureWindowsPath

from core import cmdline_deobfuscator as deob
from core import lolbas_lookup
from core import cmdline_parser as parser
from core.process_analyzer import ProcessAnalysisResult
from ioc.flags.base import _flag, mitre_url

logger = logging.getLogger(__name__)

_KEYWORDS_FILE = Path(__file__).parent / "data" / "suspicious_cmdline_keywords.json"
_SIGMA_PATTERNS_FILE = Path(__file__).parent / "data" / "sigma_cmdline_patterns.json"

FLAG_SOURCE = "Command Line"

# Emitted flag ids. Prefixed CMDLINE_ and checked against the substrings
# ioc.flags.flags_summary_for_evidence reserves, so every evidence mapping is
# explicit rather than inherited by accident — the same call the process module
# made with SUSPICIOUS_PARENT_CHILD_PAIR.
CMDLINE_ENCODED_PAYLOAD = "CMDLINE_ENCODED_PAYLOAD"
CMDLINE_DECODED_SUSPICIOUS = "CMDLINE_DECODED_SUSPICIOUS"
CMDLINE_SWITCH_COMBINATION = "CMDLINE_SWITCH_COMBINATION"
CMDLINE_HIGH_ENTROPY_TOKEN = "CMDLINE_HIGH_ENTROPY_TOKEN"
# Deliberately omits the substring "SIGMA", which flags_summary_for_evidence
# maps straight to malware_executed — the mapping for this flag is declared
# explicitly instead, as the process module did for its pairing flag.
CMDLINE_DETECTION_RULE_MATCH = "CMDLINE_DETECTION_RULE_MATCH"
CMDLINE_LOLBAS_ABUSE_PATTERN = "CMDLINE_LOLBAS_ABUSE_PATTERN"
_KEYWORD_FLAG_PREFIX = "CMDLINE_"

# Layer 4's two authorities, deliberately separated — the corpus supports one
# and not the other. See the calibration section of docs/cmdline_analyzer.md.
#
# Measured over the calibration corpus: 4 of 30 known-bad samples confirmed, and
# **0 of 32 known-good** falsely confirmed. Perfect precision, low recall — which
# is the right shape for a confirmation layer, and enough to let it raise a
# verdict off the floor. It is also the only layer covering the LOLBAS long tail:
# 105 binaries carry skeletons, while the curated keyword table names ~15.
LOLBAS_SETS_SUSPICIOUS_FLOOR = True

# Not granted. Corroboration unlocks `Malicious`, and 32 benign samples is a thin
# basis for that. Revisit when the corpus is substantially larger, or when a real
# alert shows a confirmed abuse pattern that no other layer caught.
LOLBAS_COUNTS_AS_CORROBORATION = False

# Sigma levels strong enough to escalate a verdict on their own.
_ESCALATING_SIGMA_LEVELS = frozenset({"high", "critical"})
# Levels that count as an independent second source. See the corroboration
# rule in docs/cmdline_analyzer.md.
_CORROBORATING_SIGMA_LEVELS = frozenset({"medium", "high", "critical"})
_SIGMA_LEVEL_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_SIGMA_LEVEL_TO_SEVERITY = {
    "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
    "low": "LOW", "informational": "INFO",
}
# The AI prompt and the UI both read these; an unbounded list drowns both.
MAX_RULE_MATCHES = 8

# Verdict ladder, weakest first. This module never returns "Benign":
# "nothing matched our local datasets" is absence of evidence, and ioc.verdict
# hardcodes the benign count to 0.
VERDICT_LADDER = ("Unknown", "Suspicious", "Malicious")

# Project rule: a single source cannot reach the top of the ladder. Layer 5
# (Sigma) and Layer 4 (LOLBAS) are the only qualifying second sources.
MALICIOUS_REQUIRES_CORROBORATION = True

# Independent switch hits reinforce each other rather than merely
# accumulating as list entries.
COMPOUNDING_THRESHOLD = 3

# ── Layer 6 tuning ───────────────────────────────────────────────────────────
# Measured against real command lines, entropy alone does not separate blobs
# from ordinary text — it inverts the answer:
#
#   C:\Program Files\Common Files\vendor\setup.exe        4.27
#   http://cdn.vendor.example.com/updates/agent-x64.msi   4.46
#   SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA (real -enc)  3.70
#
# A UTF-16LE base64 payload is *low* entropy, because every NUL byte encodes to
# a repeated 'A'. Paths and URLs are high-diversity strings in their own right.
# So shape is the discriminator and entropy is only the second test: a candidate
# must first look like an opaque blob (no path separators, no scheme, restricted
# alphabet, mixed case with digits — which excludes GUIDs and CamelCase names).
ENTROPY_MIN_TOKEN_LEN = 20
ENTROPY_THRESHOLD = 3.2
_BLOB_ALPHABET_RE = re.compile(r"^[A-Za-z0-9+/=_.\-]+$")
_BLOB_MIN_ALPHABET_RATIO = 0.95

_SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_SEVERITY_TO_CONFIDENCE = {
    "CRITICAL": "High", "HIGH": "High", "MEDIUM": "Med", "LOW": "Low", "INFO": "Low",
}

# Indicator extraction from decoded payloads. Bare domains are deliberately
# excluded: ``Net.WebClient``, ``System.IO`` and ``kernel32.dll`` all satisfy a
# generic domain pattern, and ``System.IO`` even ends in a real TLD — so a
# domain sweep would push .NET type names into the provider pipeline.
_URL_RE = re.compile(r"https?://[^\s\"'<>()\\]+", re.IGNORECASE)
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_HASH_RE = re.compile(r"\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b")
_URL_TRAILING_PUNCT = ".,;:!?\"'"

_ARTIFACT_MAX_LEN = 120


@dataclass
class CommandLineInput:
    """The analyst-supplied command line plus its optional session context.

    Attributes:
        command_line: Raw command line. Required for this module to run at all.
        context: The sibling Context field (``raw_log`` in session state),
            carried unparsed and only ever forwarded to the AI step.
        linked_process: The process module's *result* for the same session, when
            the analyst also filled Parent/Child Process. Takes the process
            *result* rather than its input, because
            the cross-reference keys on findings — ``MASQUERADING_*`` and
            ``SUSPICIOUS_PARENT_CHILD_PAIR`` — which the raw input cannot supply
            without re-running the sibling module's layers here.
    """

    command_line: str | None = None
    context: str | None = None
    linked_process: ProcessAnalysisResult | None = None

    def submitted_fields(self) -> list[str]:
        """Return the names of the fields the analyst actually filled.

        Returns:
            Field names in declaration order. Whitespace-only counts as absent.
        """
        names = ("command_line", "context")
        return [n for n in names if (getattr(self, n) or "").strip()]


@dataclass
class CommandLineAnalysisResult:
    """Everything the analyzer can determine about one command line.

    Attributes:
        parse_ok: False for empty input or a malformed line. Both route to
            ``Unknown``; this keeps them distinguishable downstream.
        interpreter_detected: ``powershell`` / ``cmd`` / ``unknown``.
        commands: One :class:`~core.cmdline_parser.ParsedCommand` per statement.
        was_obfuscated: True if any decode transform applied.
        decoded_command: Folded text, or None when nothing fired.
        decode_chain: Applied transforms, in order.
        keyword_flags: Layer 3 matches against the curated table.
        revealed_keywords: Keyword ids that matched only *after* decoding — the
            evidence that the encoding was hiding something.
        entropy_flag: True if Layer 6 fired.
        entropy_tokens: The tokens that tripped it.
        ioc_candidates: URLs / IPs / hashes recovered from the decoded text, for
            the caller to enrich. This module never resolves them.
        rule_matches: Layer 5 Sigma CommandLine matches, most severe first.
        joined_rule_count: How many matches the D6 rule-id join upgraded to an
            exact multi-field match using the process module's findings.
        lolbas_cross_check: Layer 4 output — a confirmed LOLBAS abuse pattern,
            a dual-use annotation, or None.
        cross_reference: What the ``linked_process`` comparison contributed.
        checks_skipped: Layers that did not run, and why — so the AI narrative
            never implies certainty about a check that never happened.
        aggregated_verdict: Malicious / Suspicious / Unknown.
        flags: ``_flag()``-shaped, feeding the existing flag system.
    """

    original_command: str | None = None
    parse_ok: bool = False
    interpreter_detected: str = parser.INTERPRETER_UNKNOWN
    commands: list = field(default_factory=list)
    was_obfuscated: bool = False
    decoded_command: str | None = None
    decode_chain: list[str] = field(default_factory=list)
    keyword_flags: list[dict] = field(default_factory=list)
    revealed_keywords: list[str] = field(default_factory=list)
    entropy_flag: bool = False
    entropy_tokens: list[str] = field(default_factory=list)
    ioc_candidates: list[str] = field(default_factory=list)
    rule_matches: list[dict] = field(default_factory=list)
    joined_rule_count: int = 0
    lolbas_cross_check: dict | None = None
    cross_reference: dict | None = None
    checks_skipped: list[str] = field(default_factory=list)
    context_passthrough: str | None = None
    aggregated_verdict: str = "Unknown"
    flags: list[dict] = field(default_factory=list)

    def has_findings(self) -> bool:
        """Report whether any layer produced something beyond "nothing matched"."""
        return bool(
            self.keyword_flags or self.was_obfuscated or self.entropy_flag
            or self.rule_matches or self.lolbas_cross_check
        )


@lru_cache(maxsize=1)
def load_suspicious_keywords() -> list[dict]:
    """Load the Layer 3 keyword table.

    Cached for the process lifetime.

    Returns:
        Keyword records, or an empty list if the data file is missing or
        malformed — which degrades Layer 3 to "no matches" rather than raising
        inside a Streamlit rerun.
    """
    try:
        raw = json.loads(_KEYWORDS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("suspicious_cmdline_keywords.json unreadable (%s) — Layer 3 disabled", exc)
        return []

    keywords = raw.get("keywords")
    if not isinstance(keywords, list):
        logger.error("suspicious_cmdline_keywords.json has no 'keywords' list — Layer 3 disabled")
        return []

    return [k for k in keywords if isinstance(k, dict) and k.get("id") and k.get("patterns")]


def _match_flag(record: dict, commands: list) -> str | None:
    """Match a keyword record against parsed switch tokens."""
    patterns = {str(p).lower() for p in record["patterns"]}
    for command in commands:
        for flag in command.flags:
            if flag.lower() in patterns:
                return flag
    return None


def _match_flag_value(record: dict, commands: list) -> str | None:
    """Match a keyword record against an adjacent switch/value token pair.

    Matching ``-w hidden`` as an adjacent pair rather than as a substring is what
    stops it firing on any command line that merely contains that text inside a
    path or a URL.
    """
    pairs = {tuple(str(p).lower().split()) for p in record["patterns"]}
    pairs = {p for p in pairs if len(p) == 2}
    for command in commands:
        tokens = [t.lower() for t in command.tokens]
        for first, second in zip(tokens, tokens[1:]):
            if (first, second) in pairs:
                return f"{first} {second}"
    return None


def _match_token(record: dict, commands: list) -> str | None:
    """Match a keyword record against any whole token."""
    patterns = {str(p).lower() for p in record["patterns"]}
    for command in commands:
        for token in command.tokens:
            if token.lower() in patterns:
                return token
    return None


def _match_substring(record: dict, text: str) -> str | None:
    """Match a keyword record against the raw command text.

    A pattern is either a string (one substring must appear) or a list of
    strings (**all** must appear, in any order or spacing). The list form exists
    because a bare binary name is not a technique: matching ``schtasks`` alone
    labelled a read-only ``schtasks /query`` as "Scheduled task created", which
    is simply a false statement. Requiring the verb as well survives quoting and
    spacing variations that a single glued substring would miss.
    """
    lowered = text.lower()
    for pattern in record["patterns"]:
        if isinstance(pattern, (list, tuple)):
            parts = [str(p).lower() for p in pattern if str(p).strip()]
            if parts and all(p in lowered for p in parts):
                return " + ".join(parts)
            continue
        needle = str(pattern).lower()
        if needle and needle in lowered:
            return needle
    return None


def match_keywords(commands: list, text: str) -> list[dict]:
    """Run the Layer 3 keyword table over parsed commands and their source text.

    Args:
        commands: Parsed commands from :func:`core.cmdline_parser.parse_command_line`.
        text: The command text the commands were parsed from.

    Returns:
        One record per matched keyword, carrying the table entry plus the
        ``matched`` fragment that triggered it. At most one hit per keyword id —
        a keyword repeated across statements is one finding, not several.
    """
    matches: list[dict] = []
    for record in load_suspicious_keywords():
        mode = str(record.get("match_mode") or "substring")
        if mode == "flag":
            hit = _match_flag(record, commands)
        elif mode == "flag_value":
            hit = _match_flag_value(record, commands)
        elif mode == "token":
            hit = _match_token(record, commands)
        else:
            hit = _match_substring(record, text)

        if hit is None:
            continue
        matches.append({
            "id": record["id"],
            "label": record.get("label") or record["id"],
            "severity": str(record.get("severity") or "LOW").upper(),
            "mitre": list(record.get("mitre") or []),
            "why": record.get("why") or "",
            "matched": hit,
            "match_mode": mode,
        })

    return matches


@lru_cache(maxsize=1)
def load_sigma_cmdline_patterns() -> list[dict]:
    """Load the Layer 5 Sigma CommandLine pattern set.

    Cached for the process lifetime.

    Returns:
        Pattern records, or an empty list if the data file is missing or
        malformed — which degrades Layer 5 to "no matches" rather than raising.
    """
    try:
        raw = json.loads(_SIGMA_PATTERNS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("sigma_cmdline_patterns.json unreadable (%s) — Layer 5 disabled", exc)
        return []

    patterns = raw.get("patterns")
    if not isinstance(patterns, list):
        logger.error("sigma_cmdline_patterns.json has no 'patterns' list — Layer 5 disabled")
        return []

    return [p for p in patterns if isinstance(p, dict) and p.get("patterns")]


def _dropped_conditions(record: dict) -> list[str]:
    """List the source-rule conditions Layer 5 could not evaluate.

    Args:
        record: A Sigma pattern record.

    Returns:
        Human-readable condition names; empty when the extraction reproduced the
        original rule exactly.
    """
    dropped: list[str] = []
    if record.get("image_constrained"):
        dropped.append("an Image constraint")
    if record.get("parentimage_constrained"):
        dropped.append("a ParentImage constraint")
    return dropped


def _linked_rule_ids(linked: ProcessAnalysisResult | None) -> set[str]:
    """Collect Sigma rule ids the process module matched in this session."""
    if linked is None:
        return set()
    pairing = linked.pairing_flag or {}
    rule_id = pairing.get("sigma_rule_id")
    return {str(rule_id)} if rule_id else set()


def match_sigma_patterns(text: str, linked: ProcessAnalysisResult | None = None) -> list[dict]:
    """Match the Sigma-derived CommandLine patterns against command text — Layer 5.

    **A record whose source rule also constrained Image or ParentImage never
    matches on its own.** This is a correction forced by measurement:
    Option A is not symmetric between the two fields. A parent→child pair is
    inherently specific (``winword.exe`` → ``cmd.exe``), but a CommandLine
    fragment often carries no specificity at all once its Image condition is
    removed — the shipped dataset contains rules whose whole CommandLine
    condition is ``.exe`` or ``copy``, which is meaningful only alongside the
    binary the rule pinned. Matching those standalone flagged **every single**
    benign sample in the calibration corpus.

    Such records are therefore corroboration-only: they are consulted just when
    the process module matched the same ``sigma_rule_id`` in this session, at
    which point the rule's missing half is supplied and the match is exact
    rather than approximate. That turns the D6 join from a bonus into the sole
    route by which two thirds of the dataset can ever contribute.

    Args:
        text: The effective (decoded where applicable) command line.
        linked: The process module's result, used to unlock constrained records.

    Returns:
        At most :data:`MAX_RULE_MATCHES` records, most severe first, one per
        source rule.
    """
    lowered = (text or "").lower()
    if not lowered:
        return []

    joinable = _linked_rule_ids(linked)
    by_rule: dict[str, dict] = {}
    for record in load_sigma_cmdline_patterns():
        if not record.get("complete_condition"):
            if str(record.get("sigma_rule_id")) not in joinable:
                continue
        patterns = [str(p).lower() for p in record["patterns"]]
        if record.get("match_all"):
            if not all(p in lowered for p in patterns):
                continue
            hit = " + ".join(patterns)
        else:
            found = next((p for p in patterns if p in lowered), None)
            if found is None:
                continue
            hit = found

        dropped = _dropped_conditions(record)
        match = {
            **record,
            "matched": hit,
            "approximate": bool(dropped),
            "approximate_note": (
                f"approximate — Sigma rule {record.get('sigma_rule_id')} also matches on "
                + " and ".join(dropped)
                if dropped else ""
            ),
        }
        rule_id = str(record.get("sigma_rule_id") or hit)
        current = by_rule.get(rule_id)
        if current is None or _rule_rank(match) > _rule_rank(current):
            by_rule[rule_id] = match

    ranked = sorted(by_rule.values(), key=_rule_rank, reverse=True)
    return ranked[:MAX_RULE_MATCHES]


def _rule_rank(record: dict) -> tuple[int, int, int]:
    """Rank a rule match: severity, then faithfulness, then pattern specificity.

    At equal severity a rule whose whole condition survived extraction beats one
    that also pinned an Image — the first reproduces its source exactly, the
    second is being applied more broadly than its author intended.
    """
    level = _SIGMA_LEVEL_ORDER.get(str(record.get("sigma_level") or "").lower(), 2)
    faithful = 0 if record.get("approximate") else 1
    specificity = sum(len(str(p)) for p in record.get("patterns") or [])
    return (level, faithful, specificity)


def apply_rule_id_join(rule_matches: list[dict], linked: ProcessAnalysisResult | None) -> int:
    """Reconstruct full multi-field Sigma conditions across the two modules — D6.

    The two Option-A extractions are complementary halves of the same rules. A
    rule requiring ``ParentImage: winword.exe`` *and* ``CommandLine: *-enc*``
    produces a record in the pairs table (flagged ``commandline_constrained``)
    **and** one here (flagged ``parentimage_constrained``), both carrying the
    same ``sigma_rule_id``. When both modules match that id in one session, the
    original condition has in fact been satisfied — no approximation left.

    This is what recovers Option B for the overlapping case without building a
    rule engine, and it is why both extractors must keep ``sigma_rule_id``.

    Args:
        rule_matches: Layer 5 matches, mutated in place.
        linked: The process module's result, or None.

    Returns:
        How many matches were upgraded to ``faithful_multifield``.
    """
    if linked is None:
        return 0

    pairing = linked.pairing_flag or {}
    linked_ids = {str(pairing.get("sigma_rule_id"))} if pairing.get("sigma_rule_id") else set()
    if not linked_ids:
        return 0

    upgraded = 0
    for match in rule_matches:
        if str(match.get("sigma_rule_id")) in linked_ids:
            match["faithful_multifield"] = True
            match["approximate"] = False
            match["approximate_note"] = (
                "exact — the process/filepath analysis matched the same Sigma rule in this "
                "session, so the rule's full multi-field condition is satisfied, not approximated."
            )
            upgraded += 1
    return upgraded


def match_lolbas_arguments(commands: list) -> dict | None:
    """Confirm a dual-use binary's arguments against its documented abuse — Layer 4.

    Stronger than the process module's Layer 2, which can only say "this binary
    is dual-use". Here the arguments are available, so a match against a LOLBAS
    skeleton says the *documented abuse pattern itself* is present.

    Every token of a skeleton must appear: the skeletons are derived from LOLBAS'
    own placeholder markup rather than guessed, so requiring all of them is
    precise rather than merely strict. Skeletons that reduced to nothing
    discriminating were dropped at extraction — the same rule the Sigma work
    arrived at twice, since a pattern matching anything lends false specificity
    to whatever it is attached to.

    Args:
        commands: Parsed commands.

    Returns:
        ``{"binary", "match_strength", "category", "usecase", "matched", "mitre"}``
        or None. ``match_strength`` is ``CONFIRMED_ABUSE_PATTERN`` when a
        skeleton matched, ``DUAL_USE_PRESENT`` when the binary is documented but
        its arguments do not correspond to any abuse pattern.
    """
    best: dict | None = None

    for command in commands:
        records = lolbas_lookup.lookup_commands(command.base_command)
        if not records:
            continue

        binary = PureWindowsPath(str(command.base_command).strip('"')).name
        haystack = " ".join(command.tokens).lower()

        for record in records:
            skeleton = [str(t).lower() for t in record["skeleton"]]
            if not all(token in haystack for token in skeleton):
                continue
            return {
                "binary": binary,
                "match_strength": "CONFIRMED_ABUSE_PATTERN",
                "category": record.get("category") or "",
                "usecase": record.get("usecase") or "",
                "description": record.get("description") or "",
                "matched": " ".join(skeleton),
                "mitre": [record["mitre"]] if record.get("mitre") else [],
                "reference": record.get("command") or "",
            }

        if best is None:
            best = {
                "binary": binary,
                "match_strength": "DUAL_USE_PRESENT",
                "category": "",
                "usecase": "",
                "description": "",
                "matched": "",
                "mitre": [],
                "reference": "",
            }

    return best


def shannon_entropy(value: str) -> float:
    """Compute Shannon entropy in bits per character.

    Args:
        value: Token to score.

    Returns:
        Entropy in bits per character; 0.0 for an empty string.
    """
    if not value:
        return 0.0
    length = len(value)
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _is_blob_shaped(token: str) -> bool:
    """Report whether a token looks like an opaque encoded blob.

    This is the gate that makes Layer 6 usable at all. Ordinary Windows paths
    and URLs score *higher* entropy than a real base64 payload does, so entropy
    can only be applied once structure has ruled those out.

    Args:
        token: A parsed token.

    Returns:
        True if the token is blob-shaped: no path separators, whitespace or URL
        scheme; a restricted alphabet; and mixed case with digits, which
        excludes single-case GUIDs and CamelCase product names.
    """
    if len(token) < ENTROPY_MIN_TOKEN_LEN:
        return False
    if "\\" in token or "://" in token or any(c.isspace() for c in token):
        return False

    # A switch is not a payload. `-Dfile.encoding=UTF-8` clears every other
    # test here — mixed case, digits, restricted alphabet — and is a Java
    # system property, not an encoded blob.
    if token[0] in "-/":
        return False
    # Base64 and hex blobs contain no dots, and use `=` only as trailing
    # padding. Both rules exclude configuration values of the form key.sub=val.
    if "." in token or "=" in token.rstrip("="):
        return False

    allowed = sum(1 for c in token if _BLOB_ALPHABET_RE.match(c))
    if allowed / len(token) < _BLOB_MIN_ALPHABET_RATIO:
        return False

    return (
        any(c.isupper() for c in token)
        and any(c.islower() for c in token)
        and any(c.isdigit() for c in token)
    )


def find_high_entropy_tokens(commands: list) -> list[str]:
    """Find blob-shaped, high-entropy tokens — Layer 6's fallback signal.

    This is the weakest signal in the stack and never escalates a verdict on its
    own (it is the weakest signal in the stack): long base64 in a scheduled-task command line is
    entirely normal. It exists to justify routing to manual review when an
    unfamiliar encoding defeated every other layer.

    Args:
        commands: Parsed commands.

    Returns:
        Tokens that are blob-shaped and clear the entropy threshold.
    """
    hits: list[str] = []
    for command in commands:
        for token in command.tokens:
            if _is_blob_shaped(token) and shannon_entropy(token) >= ENTROPY_THRESHOLD:
                hits.append(token)
    return hits


def extract_ioc_candidates(*texts: str | None) -> list[str]:
    """Pull URLs, IPv4 addresses and hashes out of command text.

    Bare domains are deliberately not extracted — see :data:`_URL_RE` — because
    .NET type names and DLL names satisfy any generic domain pattern.

    Args:
        *texts: Raw and/or decoded command text.

    Returns:
        Deduplicated candidate strings, in discovery order. The caller runs them
        through :func:`ioc.parser.parse_iocs` for typing and enrichment; this
        module never resolves anything itself.
    """
    found: list[str] = []
    seen: set[str] = set()

    for text in texts:
        if not text:
            continue
        for match in _URL_RE.findall(text):
            value = match.rstrip(_URL_TRAILING_PUNCT)
            if value and value.lower() not in seen:
                seen.add(value.lower())
                found.append(value)
        for match in _IPV4_RE.findall(text):
            try:
                ipaddress.ip_address(match)
            except ValueError:
                continue
            if match not in seen:
                seen.add(match)
                found.append(match)
        for match in _HASH_RE.findall(text):
            value = match.lower()
            if value not in seen:
                seen.add(value)
                found.append(match)

    return found


def _detail_with_mitre(why: str, mitre: list[str]) -> str:
    """Return the flag detail unchanged.

    Kept as a seam so call sites read the same, but it no longer appends ATT&CK
    URLs. The renderer links the technique ids themselves and reads a flag's own
    link from ``source_url`` — the convention the process module already
    follows. Inlining raw URLs here duplicated those links and pushed the
    readable part of the detail off the card.

    Args:
        why: The human-readable reason for the flag.
        mitre: Technique ids, now rendered as links by the UI rather than here.

    Returns:
        ``why``, unmodified.
    """
    return why


def _with_source(flag: dict, mitre: list[str]) -> dict:
    """Attach an ATT&CK link so the flag's label and badge become clickable.

    Args:
        flag: A ``_flag()``-shaped dict.
        mitre: Technique ids; the first usable one supplies the link.

    Returns:
        The flag, with ``source_url`` set when a technique id was available.
    """
    url = next((u for u in (mitre_url(t) for t in mitre) if u), "")
    return {**flag, "source_url": url} if url else flag


def build_flags(result: CommandLineAnalysisResult) -> list[dict]:
    """Emit ``_flag()``-shaped findings for the existing flag system.

    Args:
        result: A populated analysis result.

    Returns:
        Flags, strongest first.
    """
    flags: list[dict] = []

    for match in result.keyword_flags:
        flags.append(_with_source(_flag(
            f"{_KEYWORD_FLAG_PREFIX}{match['id']}",
            match["label"],
            "Suspicious command line",
            match["severity"],
            match["mitre"],
            _detail_with_mitre(f"Matched {match['matched']!r}. {match['why']}", match["mitre"]),
            FLAG_SOURCE,
        ), match["mitre"]))

    for match in result.rule_matches:
        level = str(match.get("sigma_level") or "medium").lower()
        title = match.get("title") or "Sigma detection rule"
        note = match.get("approximate_note") or ""
        detail = f"Matched {match['matched']!r} against rule \"{title}\" [{level}]."
        if match.get("faithful_multifield"):
            detail += " " + note
        elif note:
            detail += " " + note
        flags.append(_with_source(_flag(
            CMDLINE_DETECTION_RULE_MATCH,
            f"Detection rule match: {title}",
            "Known-malicious command line",
            _SIGMA_LEVEL_TO_SEVERITY.get(level, "MEDIUM"),
            list(match.get("mitre_techniques") or []),
            _detail_with_mitre(detail, list(match.get("mitre_techniques") or [])),
            FLAG_SOURCE,
        ), list(match.get("mitre_techniques") or [])))

    cross = result.lolbas_cross_check or {}
    if cross.get("match_strength") == "CONFIRMED_ABUSE_PATTERN":
        flags.append(_with_source(_flag(
            CMDLINE_LOLBAS_ABUSE_PATTERN,
            f"Documented LOLBAS abuse pattern: {cross['binary']}",
            "Living-off-the-land abuse",
            "HIGH",
            list(cross.get("mitre") or []),
            _detail_with_mitre(
                f"Arguments {cross['matched']!r} correspond to LOLBAS' documented "
                f"{cross.get('category') or 'abuse'} pattern for {cross['binary']} "
                f"({cross.get('usecase') or 'no stated use case'}). Reference invocation: "
                f"{cross.get('reference') or 'n/a'}.",
                list(cross.get("mitre") or []),
            ),
            FLAG_SOURCE,
        ), list(cross.get("mitre") or [])))
    elif cross.get("match_strength") == "DUAL_USE_PRESENT":
        flags.append(_flag(
            lolbas_lookup.DUAL_USE_BINARY,
            f"Dual-use binary: {cross['binary']}",
            "Living-off-the-land abuse",
            "INFO",
            [],
            f"{cross['binary']} is documented in LOLBAS as dual-use, but its arguments "
            "do not correspond to any documented abuse pattern. Not suspicious by itself.",
            FLAG_SOURCE,
        ))

    if result.was_obfuscated:
        chain = " -> ".join(result.decode_chain) or "unspecified"
        flags.append(_flag(
            CMDLINE_ENCODED_PAYLOAD,
            "Command line was obfuscated or encoded",
            "Defense evasion",
            "MEDIUM",
            ["T1027", "T1140"],
            _detail_with_mitre(
                f"Decoded via: {chain}. Encoding alone is not proof of intent, but it is "
                "a deliberate act worth recording.",
                ["T1027", "T1140"],
            ),
            FLAG_SOURCE,
        ))

    if result.revealed_keywords:
        revealed = ", ".join(result.revealed_keywords)
        flags.append(_flag(
            CMDLINE_DECODED_SUSPICIOUS,
            "Decoding revealed suspicious content",
            "Defense evasion",
            "HIGH",
            ["T1027", "T1140"],
            _detail_with_mitre(
                f"These findings were invisible before decoding: {revealed}. The encoding "
                "was concealing them, not merely compressing the command.",
                ["T1027", "T1140"],
            ),
            FLAG_SOURCE,
        ))

    distinct = {m["id"] for m in result.keyword_flags}
    if len(distinct) >= COMPOUNDING_THRESHOLD:
        flags.append(_flag(
            CMDLINE_SWITCH_COMBINATION,
            f"{len(distinct)} independent suspicious indicators on one command line",
            "Suspicious command line",
            "HIGH",
            [],
            "Each indicator is weak alone; together they describe a deliberately "
            f"constructed invocation ({', '.join(sorted(distinct))}).",
            FLAG_SOURCE,
        ))

    if result.entropy_flag:
        sample = result.entropy_tokens[0][:60] if result.entropy_tokens else ""
        flags.append(_flag(
            CMDLINE_HIGH_ENTROPY_TOKEN,
            "High-entropy token (unrecognised encoding)",
            "Defense evasion",
            "INFO",
            ["T1027"],
            f"No known decode applied, but a long high-diversity token is present "
            f"(e.g. {sample!r}). Weak on its own — long base64 is common in "
            f"legitimate automation. Offered as a reason to look, not as evidence.",
            FLAG_SOURCE,
        ))

    flags.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 0), reverse=True)
    return flags


def _has_corroboration(result: CommandLineAnalysisResult) -> bool:
    """Report whether a second, independent detection source agrees.

    Layers 4 and 5 are the only sources that qualify, and neither exists in
    only sources that qualify.
    """
    for match in result.rule_matches:
        if str(match.get("sigma_level") or "").lower() in _CORROBORATING_SIGMA_LEVELS:
            return True
    if not LOLBAS_COUNTS_AS_CORROBORATION:
        return False
    cross = result.lolbas_cross_check or {}
    return cross.get("match_strength") == "CONFIRMED_ABUSE_PATTERN"


def aggregate_verdict(result: CommandLineAnalysisResult) -> str:
    """Reduce the layer findings to one qualitative verdict.

    Implements the verdict table in ``docs/cmdline_analyzer.md``.

    Args:
        result: A populated analysis result.

    Returns:
        One of :data:`VERDICT_LADDER`. Never ``"Benign"`` — a command
        line with no matches is ``Unknown``, and ``parse_ok`` distinguishes that
        from a parse failure.
    """
    if not result.commands:
        return "Unknown"

    corroborated = _has_corroboration(result)
    escalating = [
        m for m in result.rule_matches
        if str(m.get("sigma_level") or "").lower() in _ESCALATING_SIGMA_LEVELS
    ]

    # §4 rule 2 — a rule-id join means the source rule's full multi-field
    # condition was satisfied in this session. Nothing was approximated, so
    # this is the one path that reaches Malicious without needing obfuscation.
    if any(m.get("faithful_multifield") for m in escalating):
        return "Malicious"

    # §4 rule 1 — a high/critical rule match, escalated by obfuscation or a
    # confirmed LOLBAS abuse pattern.
    if escalating:
        cross = result.lolbas_cross_check or {}
        confirmed = (
            LOLBAS_COUNTS_AS_CORROBORATION
            and cross.get("match_strength") == "CONFIRMED_ABUSE_PATTERN"
        )
        if result.was_obfuscated or confirmed:
            return "Malicious"
        return "Suspicious"

    # §4 rule 4 — obfuscation whose decoded content is itself suspicious.
    if result.was_obfuscated and result.revealed_keywords:
        if corroborated or not MALICIOUS_REQUIRES_CORROBORATION:
            return "Malicious"
        return "Suspicious"

    # §4 rule 3 — a confirmed LOLBAS abuse pattern floors at Suspicious. This is
    # the layer's whole point: it reaches binaries the keyword table never names.
    lolbas_confirmed = (
        LOLBAS_SETS_SUSPICIOUS_FLOOR
        and (result.lolbas_cross_check or {}).get("match_strength")
        == "CONFIRMED_ABUSE_PATTERN"
    )

    # §4 rules 3-7 — each tops out at Suspicious.
    if (result.was_obfuscated or result.keyword_flags or result.entropy_flag
            or result.rule_matches or lolbas_confirmed):
        return "Suspicious"

    # §4 rule 8 — nothing matched, or the line would not parse.
    return "Unknown"


def _row(artifact: str, row_type: str, verdict: str, confidence: str,
         evidence: str, sources: str) -> dict:
    """Build one table row matching the schema from :func:`ioc.verdict.summarize_results`.

    Every key the IOC rows carry is set explicitly, including the
    ``ConfidenceScore`` family, so ``pd.DataFrame`` does not produce ragged NaN
    columns when these rows are concatenated with real ones.

    ``ConfidenceScore`` is ``None``, not ``""`` — see the same note on
    :func:`core.process_analyzer._row`. Real rows put a number there, and an
    empty string beside it makes a column pyarrow cannot convert, which breaks
    the Table render for the whole run.

    Args:
        artifact: Value shown in the Artifact column.
        row_type: Artifact type label.
        verdict: Malicious / Suspicious / Unknown.
        confidence: High / Med / Low.
        evidence: Primary Evidence text.
        sources: Sources text.

    Returns:
        A row dict.
    """
    return {
        "Artifact": artifact,
        "Type": row_type,
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


def _truncate(value: str) -> str:
    """Shorten an artifact string so one pasted payload cannot break the table."""
    text = " ".join(str(value).split())
    return text if len(text) <= _ARTIFACT_MAX_LEN else text[: _ARTIFACT_MAX_LEN - 1] + "…"


def to_rows(result: CommandLineAnalysisResult) -> list[dict]:
    """Render an analysis result as table rows — one per parsed statement.

    Uses the identical column schema to :func:`core.process_analyzer.to_rows`,
    so ``app.py`` can concatenate both lists into ``process_rows`` without the
    renderer caring which module produced a row.

    Args:
        result: A populated analysis result.

    Returns:
        Row dicts, empty when no command line was submitted.
    """
    if not result.commands:
        return []

    top = result.flags[0] if result.flags else None
    verdict = result.aggregated_verdict
    confidence = _SEVERITY_TO_CONFIDENCE.get(top["severity"], "Low") if top else "Low"

    if top:
        evidence = top["label"]
    elif result.parse_ok:
        evidence = "Parsed cleanly; no known-suspicious pattern matched"
    else:
        evidence = "Command line could not be fully parsed"

    rows: list[dict] = []
    for command in result.commands:
        rows.append(_row(
            _truncate(command.raw),
            "command_line",
            verdict,
            confidence,
            evidence,
            "Local (keyword table)",
        ))

    return rows


def _cross_reference(result: CommandLineAnalysisResult,
                     linked: ProcessAnalysisResult | None) -> dict | None:
    """Compare against the process module's findings for the same session.

    This is capped deliberately: the cross-reference may raise ``Unknown`` to
    ``Suspicious``, but it can never carry a verdict to ``Malicious`` on its own.
    The sibling module already reaches ``Malicious`` readily from name-only data
    (see its documentation's known-limits section), and stacking a second automatic escalation on top of that
    would compound a known over-eager rule.

    Args:
        result: This module's result, already aggregated.
        linked: The process module's result, or None.

    Returns:
        A description of what the comparison contributed, or None when there was
        nothing to compare.
    """
    if linked is None:
        return None

    linked_ids = {f.get("id", "") for f in (linked.flags or [])}
    corroborating = sorted(
        fid for fid in linked_ids
        if fid.startswith("MASQUERADING")
        or fid in ("PARENT_CHAIN_CONTAMINATION", "SUSPICIOUS_PARENT_CHILD_PAIR")
    )
    if not corroborating:
        return None

    return {
        "process_flags": corroborating,
        "applied": result.has_findings(),
        "note": (
            "The process/filepath analysis flagged the same event. Escalation is "
            "capped at Suspicious here — see docs/cmdline_analyzer.md."
        ),
    }


def analyze_command_line(data: CommandLineInput) -> CommandLineAnalysisResult:
    """Run every layer over one submitted command line.

    Layers are skipped independently when their input is absent, and
    ``checks_skipped`` records what did not run so downstream ticket generation
    never implies certainty about a check that never happened.

    Args:
        data: The command line plus its optional session context.

    Returns:
        A populated :class:`CommandLineAnalysisResult`. With no command line
        submitted the result is empty with an ``Unknown`` verdict — that case is
        form validation, handled at the UI layer, not an analysis outcome.
    """
    result = CommandLineAnalysisResult(context_passthrough=data.context)

    raw = (data.command_line or "").strip()
    if not raw:
        result.checks_skipped.append("all command-line checks — no command line submitted")
        return result

    # Kept verbatim so the UI can show the analyst exactly what was submitted,
    # beside whatever the decoder turned it into.
    result.original_command = raw

    decoded = deob.deobfuscate(raw)
    result.was_obfuscated = decoded.was_obfuscated
    result.decoded_command = decoded.decoded_command
    result.decode_chain = list(decoded.decode_chain)

    effective = decoded.decoded_command or raw
    parsed = parser.parse_command_line(effective)
    result.parse_ok = parsed.parse_ok
    result.interpreter_detected = parsed.interpreter
    result.commands = parsed.commands

    result.keyword_flags = match_keywords(parsed.commands, effective)

    if decoded.was_obfuscated:
        # Anything the raw form already exposed was not being hidden. Diffing
        # the two passes is what separates "encoded a suspicious command" from
        # "encoded something mundane".
        raw_parsed = parser.parse_command_line(raw)
        before = {m["id"] for m in match_keywords(raw_parsed.commands, raw)}
        result.revealed_keywords = sorted(
            m["id"] for m in result.keyword_flags if m["id"] not in before
        )

    result.rule_matches = match_sigma_patterns(effective, data.linked_process)
    result.lolbas_cross_check = match_lolbas_arguments(parsed.commands)
    result.joined_rule_count = apply_rule_id_join(result.rule_matches, data.linked_process)

    result.entropy_tokens = find_high_entropy_tokens(parsed.commands)
    result.entropy_flag = bool(result.entropy_tokens)

    result.ioc_candidates = extract_ioc_candidates(effective, raw)

    if data.linked_process is None:
        result.checks_skipped.append(
            "Sigma multi-field reconstruction — no Parent/Child Process was submitted, so "
            "rule matches that also constrain Image/ParentImage stay approximate"
        )
    if not data.context:
        result.checks_skipped.append("context passthrough — no Context text submitted")

    result.aggregated_verdict = aggregate_verdict(result)
    result.cross_reference = _cross_reference(result, data.linked_process)
    if result.cross_reference and result.cross_reference["applied"]:
        if result.aggregated_verdict == "Unknown":
            result.aggregated_verdict = "Suspicious"

    result.flags = build_flags(result)
    return result
