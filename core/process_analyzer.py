"""Parent/child process and filepath analysis — Layers 1, 3 (partial) and 4.

Implements ``docs/process_analyzer.md``:

* **Layer 1** — path-baseline whitelist + Levenshtein typosquat detection.
* **Layer 2** — delegated to :mod:`core.lolbas_lookup`.
* **Layer 3** — *opportunistic only*: pull hash-shaped substrings out of the
  freeform Context field. This module never resolves them; it returns
  candidates for the caller to feed into the existing enrichment pipeline.
* **Layer 4** — Sigma-derived suspicious parent→child pairing, plus chain
  contamination propagation from a masquerading parent.

The four analyst-supplied fields (File Path, Parent Process, Child Process,
Context) are fully independent — each layer only runs on the fields it needs and
is skippable. This module performs **no network I/O**; it is a pure function of
its input plus the local datasets under ``core/data/``.

Verdict aggregation here is deliberately **qualitative only** — it is not wired
into :mod:`ioc.confidence_scorer`, per the briefing's explicit deferral.
"""
from __future__ import annotations

import fnmatch
import json
import logging
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path, PureWindowsPath
from typing import Any

from core import lolbas_lookup
# Reuse the shared flag shape (and the ATT&CK URL builder) so process findings
# are indistinguishable from provider findings downstream. ioc.flags.base
# imports nothing from core, so this direction is cycle-free
# (core.orchestrator already imports from ioc).
from ioc.flags.base import _flag, mitre_url

logger = logging.getLogger(__name__)

_DATA_FILE = Path(__file__).parent / "data" / "known_system_processes.json"
_PAIRS_FILE = Path(__file__).parent / "data" / "sigma_parent_child_pairs.json"

# ── Identity flags ───────────────────────────────────────────────────────────
LEGITIMATE_SYSTEM_PROCESS = "LEGITIMATE_SYSTEM_PROCESS"
MASQUERADING_WRONG_PATH = "MASQUERADING_WRONG_PATH"
MASQUERADING_TYPOSQUAT = "MASQUERADING_TYPOSQUAT"
UNRESOLVED_THIRD_PARTY = "UNRESOLVED_THIRD_PARTY"

# Emitted flag ids. These feed the existing 100+ flag system, whose evidence
# mapper matches on **substrings of the id** — so these must avoid colliding
# with reserved tokens like "SIGMA" (-> malware_executed) and
# "PROCESS_INJECTION" (-> privilege_escalation). See docs/process_analyzer.md.
SUSPICIOUS_PARENT_CHILD_PAIR = "SUSPICIOUS_PARENT_CHILD_PAIR"
PARENT_CHAIN_CONTAMINATION = "PARENT_CHAIN_CONTAMINATION"
DUAL_USE_BINARY = lolbas_lookup.DUAL_USE_BINARY

# T1036.005 — Masquerading: Match Legitimate Resource Name or Location.
_MASQUERADE_MITRE = ["T1036.005"]

# Verdict ladder, weakest first. This module never returns "Benign": absence of
# data is "Unknown", consistent with ioc.verdict hardcoding benign to 0.
VERDICT_LADDER = ("Unknown", "Suspicious", "Malicious")

_SIGMA_LEVEL_TO_SEVERITY = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "informational": "INFO",
}

# Sigma levels that escalate the verdict on their own (briefing §5.3).
_ESCALATING_SIGMA_LEVELS = {"high", "critical"}

_SIGMA_LEVEL_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Unanchored twin of ioc.parser.HASH_RE — that one is ``^...$`` anchored for
# whole-line parsing and cannot scan freeform prose.
_CONTEXT_HASH_RE = re.compile(
    r"\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b"
)

# Which form fields carry a process name, and their human labels.
_PROCESS_FIELDS = (
    ("file_path", "File Path"),
    ("parent_process", "Parent Process"),
    ("child_process", "Child Process"),
)

# ── Fuzzy-match tuning (see the known-limits section — these are starting values, not validated) ──
# Levenshtein distance is computed over the *stem* (filename minus extension).
# Short stems collide by chance far more easily than long ones, so they get a
# stricter threshold instead of being skipped outright — a 1-edit typosquat of
# ``cmd.exe`` is still worth catching.
LEVENSHTEIN_MAX_DISTANCE = 2
SHORT_STEM_LENGTH = 6
SHORT_STEM_MAX_DISTANCE = 1

# Native / NT path prefixes seen in Sysmon and EDR telemetry.
_NATIVE_PREFIXES = ("\\??\\", "\\\\?\\")

# Tokens that resolve to the Windows directory.
_WINDIR_TOKENS = ("%systemroot%", "%windir%", "\\systemroot")
_WINDIR = "c:\\windows"


@dataclass
class ProcessFilepathInput:
    """The four independent, optional fields submitted by the analyst.

    Mirrors the UI form in ``app.py``. Note the Context field is stored under the
    ``raw_log`` session key in Streamlit; it is carried here unparsed and is only
    ever forwarded to the AI step.
    """

    file_path: str | None = None
    parent_process: str | None = None
    child_process: str | None = None
    context: str | None = None

    def submitted_fields(self) -> list[str]:
        """Return the names of the fields the analyst actually filled.

        Returns:
            Field names in declaration order, e.g. ``["file_path", "child_process"]``.
            Whitespace-only values count as not submitted.
        """
        names = ("file_path", "parent_process", "child_process", "context")
        return [n for n in names if (getattr(self, n) or "").strip()]


@dataclass
class FieldAnalysis:
    """Per-field identity result. One of these per submitted process-bearing field."""

    value: str
    identity_flag: str | None = None
    identity_detail: str = ""
    matched_process: str | None = None
    lolbas_match: dict | None = None
    impersonated_lolbas: dict | None = None
    expected_paths: list[str] = field(default_factory=list)

    def is_masquerading(self) -> bool:
        """Return True if this field was flagged as impersonating a system binary."""
        return bool(self.identity_flag and self.identity_flag.startswith("MASQUERADING"))


@dataclass
class ProcessAnalysisResult:
    """Aggregate result for one process-creation event.

    Tracks a result **per submitted field** rather than assuming a single
    unified process object — the four form fields have no guaranteed
    relationship to one another.
    """

    file_path_analysis: FieldAnalysis | None = None
    parent_process_analysis: FieldAnalysis | None = None
    child_process_analysis: FieldAnalysis | None = None
    hash_candidates: list[str] = field(default_factory=list)
    hash_verdict: dict | None = None
    pairing_flag: dict | None = None
    chain_contamination: bool = False
    context_passthrough: str | None = None
    aggregated_verdict: str = "Unknown"
    fields_submitted: list[str] = field(default_factory=list)
    checks_skipped: list[str] = field(default_factory=list)
    flags: list[dict] = field(default_factory=list)

    def field_analyses(self) -> list[tuple[str, str, FieldAnalysis]]:
        """Return ``(field_name, label, analysis)`` for every analyzed field.

        Returns:
            Only fields the analyst actually submitted, in form order.
        """
        pairs = (
            ("file_path", "File Path", self.file_path_analysis),
            ("parent_process", "Parent Process", self.parent_process_analysis),
            ("child_process", "Child Process", self.child_process_analysis),
        )
        return [(name, label, fa) for name, label, fa in pairs if fa is not None]

    def has_masquerading(self) -> bool:
        """Return True if any submitted field was flagged as masquerading."""
        return any(fa.is_masquerading() for _, _, fa in self.field_analyses())


# ── Whitelist loading ────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def load_known_system_processes() -> dict[str, list[str]]:
    """Load and normalize the Layer 1 path-baseline whitelist.

    Directories are normalized once at load time so lookups are plain string
    comparisons. Result is cached for the process lifetime.

    Returns:
        Mapping of lowercased process filename to its list of normalized
        expected directories. Empty dict if the data file is missing or invalid,
        in which case every name resolves to ``UNRESOLVED_THIRD_PARTY``.
    """
    try:
        raw = json.loads(_DATA_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("known_system_processes.json unreadable (%s) — Layer 1 disabled", exc)
        return {}

    processes = raw.get("processes")
    if not isinstance(processes, dict):
        logger.error("known_system_processes.json has no 'processes' object — Layer 1 disabled")
        return {}

    table: dict[str, list[str]] = {}
    for name, dirs in processes.items():
        if not isinstance(dirs, list):
            logger.warning("whitelist entry %r is not a list — skipped", name)
            continue
        table[str(name).strip().lower()] = [_normalize_dir(d) for d in dirs if str(d).strip()]
    return table


# ── Path / name helpers ──────────────────────────────────────────────────────

def _normalize_dir(raw: str) -> str:
    """Normalize a Windows directory string for case-insensitive comparison.

    Handles forward slashes, surrounding quotes, NT/native prefixes
    (``\\??\\``, ``\\\\?\\``), ``%SystemRoot%`` / ``%windir%`` / ``\\SystemRoot``
    expansion, duplicate separators, and trailing separators.

    Args:
        raw: A directory path in any of the above forms.

    Returns:
        Lowercased, backslash-separated path with no trailing separator.
    """
    value = str(raw or "").strip().strip('"').strip("'")
    value = value.replace("/", "\\")
    for prefix in _NATIVE_PREFIXES:
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    value = value.lower()
    for token in _WINDIR_TOKENS:
        if value.startswith(token):
            value = _WINDIR + value[len(token):]
            break
    while "\\\\" in value:
        value = value.replace("\\\\", "\\")
    return value.rstrip("\\")


def split_process_path(raw: str) -> tuple[str, str | None]:
    """Split an analyst-supplied value into (filename, directory).

    Accepts both a bare process name (``explorer.exe``) and a full path
    (``C:\\Windows\\explorer.exe``). Whether a directory is present is detected
    from the value itself rather than assumed from which form field it came —
    a full path pasted into the Parent Process field is still path-checkable.

    Args:
        raw: Free-text value from File Path / Parent Process / Child Process.

    Returns:
        Tuple of (lowercased filename, normalized directory or ``None`` when the
        value carries no directory component).
    """
    value = str(raw or "").strip().strip('"').strip("'").replace("/", "\\")
    for prefix in _NATIVE_PREFIXES:
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    if not value:
        return "", None

    pure = PureWindowsPath(value)
    name = pure.name.lower()
    parent = str(pure.parent)
    # PureWindowsPath("explorer.exe").parent renders as "." — no real directory.
    if parent in (".", "", name):
        return name, None
    return name, _normalize_dir(parent)


def _levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein edit distance between two strings.

    Pure-Python row-wise dynamic programming. The whitelist is ~50 short keys, so
    this is comfortably fast enough and avoids a compiled dependency.

    Args:
        a: First string.
        b: Second string.

    Returns:
        Minimum number of single-character insertions, deletions, or
        substitutions needed to turn ``a`` into ``b``.
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(min(
                previous[j] + 1,          # deletion
                current[j - 1] + 1,       # insertion
                previous[j - 1] + (ca != cb),  # substitution
            ))
        previous = current
    return previous[-1]


def _max_distance_for(stem: str) -> int:
    """Return the allowed typosquat distance for a stem of this length.

    Args:
        stem: Filename with the extension removed.

    Returns:
        ``SHORT_STEM_MAX_DISTANCE`` for stems shorter than ``SHORT_STEM_LENGTH``,
        otherwise ``LEVENSHTEIN_MAX_DISTANCE``.
    """
    return SHORT_STEM_MAX_DISTANCE if len(stem) < SHORT_STEM_LENGTH else LEVENSHTEIN_MAX_DISTANCE


def _stem(filename: str) -> str:
    """Return the filename with its final extension removed, lowercased."""
    return PureWindowsPath(filename).stem.lower()


# ── Layer 1 ──────────────────────────────────────────────────────────────────

def analyze_identity(raw_value: str) -> FieldAnalysis | None:
    """Run the Layer 1 identity check on one process name or file path.

    Resolution order:

    1. Exact filename match in the whitelist → verify the directory. Matching
       directory yields ``LEGITIMATE_SYSTEM_PROCESS``; a mismatch yields
       ``MASQUERADING_WRONG_PATH``. With no directory in the input the path check
       cannot run, so the result stays ``LEGITIMATE_SYSTEM_PROCESS`` with a
       detail noting the path was unverifiable.
    2. Exact stem match with a different extension (``svchost.com``) →
       ``MASQUERADING_TYPOSQUAT``.
    3. Fuzzy stem match within the length-scaled Levenshtein threshold →
       ``MASQUERADING_TYPOSQUAT``.
    4. No match → ``UNRESOLVED_THIRD_PARTY``. This is *not* suspicious; most
       legitimate third-party software lands here.

    Args:
        raw_value: Free-text value from one of the process-bearing form fields.

    Returns:
        A populated :class:`FieldAnalysis`, or ``None`` when ``raw_value`` is
        empty or carries no filename (field not submitted → layer skipped).
    """
    filename, directory = split_process_path(raw_value)
    if not filename:
        return None

    table = load_known_system_processes()
    result = FieldAnalysis(value=str(raw_value).strip())

    expected = table.get(filename)
    if expected is not None:
        result.matched_process = filename
        result.expected_paths = list(expected)
        if directory is None:
            result.identity_flag = LEGITIMATE_SYSTEM_PROCESS
            result.identity_detail = (
                f"{filename} is a known system binary; no path supplied, "
                "so its location could not be verified"
            )
        elif directory in expected:
            result.identity_flag = LEGITIMATE_SYSTEM_PROCESS
            result.identity_detail = f"{filename} running from expected location {directory}"
        else:
            result.identity_flag = MASQUERADING_WRONG_PATH
            result.identity_detail = (
                f"{filename} expected in {' or '.join(expected)}, observed in {directory}"
            )
        return result

    stem = _stem(filename)
    if not stem:
        result.identity_flag = UNRESOLVED_THIRD_PARTY
        result.identity_detail = "No filename stem to evaluate"
        return result

    # Same stem, different extension — e.g. svchost.com impersonating svchost.exe.
    for known in table:
        if _stem(known) == stem and known != filename:
            result.identity_flag = MASQUERADING_TYPOSQUAT
            result.matched_process = known
            result.expected_paths = list(table[known])
            result.identity_detail = (
                f"{filename} shares the name of system binary {known} "
                "but carries a different extension"
            )
            return result

    best_name: str | None = None
    best_distance = LEVENSHTEIN_MAX_DISTANCE + 1
    for known in table:
        distance = _levenshtein(stem, _stem(known))
        if distance < best_distance:
            best_distance, best_name = distance, known

    if best_name is not None and best_distance <= _max_distance_for(stem):
        result.identity_flag = MASQUERADING_TYPOSQUAT
        result.matched_process = best_name
        result.expected_paths = list(table[best_name])
        result.identity_detail = (
            f"{filename} is {best_distance} edit(s) from system binary {best_name}"
        )
        return result

    result.identity_flag = UNRESOLVED_THIRD_PARTY
    result.identity_detail = f"{filename} is not a known Windows system binary"
    return result


# ── Layer 3 — opportunistic hash extraction ──────────────────────────────────

def extract_hash_candidates(context: str | None) -> list[str]:
    """Scan the freeform Context field for hash-shaped substrings.

    This is a **best-effort bonus pass**, not a layer the module depends on.
    The form has no dedicated hash field; analysts wanting a definitive
    hash verdict should use the main IOC box, which already routes hashes
    through the 11-provider pipeline.

    No lookup happens here — this module stays network-free. The caller feeds
    the returned values into the existing enrichment pipeline.

    Args:
        context: Raw Context textarea contents, or ``None``.

    Returns:
        Lowercased MD5/SHA1/SHA256-shaped strings, de-duplicated, in first-seen
        order. Empty list when there is nothing to find — the expected default.
    """
    if not context:
        return []

    seen: list[str] = []
    for match in _CONTEXT_HASH_RE.findall(str(context)):
        value = match.lower()
        if value not in seen:
            seen.append(value)
    return seen


# ── Layer 4 — Sigma-derived parent/child pairing ─────────────────────────────

# Globs that match essentially every process of their kind. These arise when a
# source rule constrained a *path* ("a binary under \Users\...\*.exe") and Option
# A reduced it to a basename — the discriminating part was the directory, which
# this layer cannot evaluate, leaving a pattern that matches everything.
#
# Found by the calibration corpus: one such rule matched winword.exe -> winword.exe
# at HIGH severity (ordinary Office re-entry) and also outranked the real
# Office-spawns-a-shell rules for winword.exe -> cmd.exe, so it was both a false
# positive and a mislabel. Filtered at load so the shipped dataset needs no
# regeneration; the extractor now refuses to emit them either.
_INFORMATIONLESS_GLOB_CORES = frozenset({
    "", ".exe", ".dll", ".com", ".bat", ".cmd", ".ps1", ".scr", ".msi",
})


def _is_informationless_glob(glob: Any) -> bool:
    """Report whether a pairing glob matches essentially any process name.

    Args:
        glob: A ``parent_pattern`` or ``child_pattern`` value.

    Returns:
        True when the pattern carries no discriminating information.
    """
    if not isinstance(glob, str):
        return True
    core = glob.strip().lower().strip("*").lstrip("\\").strip("*")
    return core in _INFORMATIONLESS_GLOB_CORES

@lru_cache(maxsize=1)
def load_parent_child_pairs() -> list[dict]:
    """Load the extracted Sigma parent→child blocklist.

    Cached for the process lifetime.

    Returns:
        Pairing records, or an empty list if the data file is missing or
        malformed — which degrades Layer 4 to "no matches" rather than raising.
    """
    try:
        raw = json.loads(_PAIRS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("sigma_parent_child_pairs.json unreadable (%s) — Layer 4 disabled", exc)
        return []

    pairs = raw.get("pairs")
    if not isinstance(pairs, list):
        logger.error("sigma_parent_child_pairs.json has no 'pairs' list — Layer 4 disabled")
        return []

    kept = [
        p for p in pairs
        if isinstance(p, dict)
        and not _is_informationless_glob(p.get("parent_pattern"))
        and not _is_informationless_glob(p.get("child_pattern"))
    ]
    dropped = len([p for p in pairs if isinstance(p, dict)]) - len(kept)
    if dropped:
        logger.info("dropped %d pairing record(s) with an information-free glob", dropped)
    return kept


def _dropped_conditions(record: dict) -> list[str]:
    """List the source-rule conditions this layer could not evaluate.

    Args:
        record: A pairing record from the blocklist.

    Returns:
        Human-readable condition names, empty when the pairing check reproduces
        the original rule exactly.
    """
    dropped: list[str] = []
    if record.get("commandline_constrained"):
        dropped.append("a CommandLine pattern")
    if record.get("path_constrained"):
        dropped.append("a directory/path constraint")
    return dropped


def _pairing_sort_key(record: dict) -> tuple[int, int]:
    """Rank a pairing match: severity first, then faithfulness to the source rule.

    At equal severity, prefer a rule whose whole condition survived extraction.
    For that rule the pairing-only check reproduces the original exactly; a rule
    that also pinned a command line or a directory is being applied more broadly
    than its author intended.

    Args:
        record: A pairing record from the blocklist.

    Returns:
        Sort key; higher is a better match.
    """
    level = _SIGMA_LEVEL_ORDER.get(record.get("sigma_level"), 2)
    faithful = 0 if _dropped_conditions(record) else 1
    return (level, faithful)


def match_pairing(parent_process: str | None, child_process: str | None) -> dict | None:
    """Look up a parent→child pairing against the Sigma-derived blocklist.

    Runs **only when both** names are present. If only one side was submitted
    the layer is skipped entirely — the missing side is never guessed or
    defaulted.

    Args:
        parent_process: Parent process name or path.
        child_process: Child process name or path.

    Returns:
        The best-matching pairing record augmented with ``parent``, ``child``
        and ``approximate_note``, or ``None`` when either side is missing or no
        pairing matched.
    """
    if not (parent_process or "").strip() or not (child_process or "").strip():
        return None

    parent_name, _ = split_process_path(parent_process)
    child_name, _ = split_process_path(child_process)
    if not parent_name or not child_name:
        return None

    # Blocklist globs are lowercase and shaped like "*\name.exe"; prefixing a
    # separator lets one fnmatch handle endswith, contains and exact forms.
    parent_probe = f"\\{parent_name}"
    child_probe = f"\\{child_name}"

    matches = [
        record for record in load_parent_child_pairs()
        if fnmatch.fnmatchcase(parent_probe, str(record.get("parent_pattern", "")))
        and fnmatch.fnmatchcase(child_probe, str(record.get("child_pattern", "")))
    ]
    if not matches:
        return None

    best = max(matches, key=_pairing_sort_key)
    result = dict(best)
    result["parent"] = parent_name
    result["child"] = child_name
    result["match_count"] = len(matches)

    rule_id = best.get("sigma_rule_id") or "unknown"
    dropped = _dropped_conditions(best)
    result["approximate"] = bool(dropped)
    result["approximate_note"] = (
        f"approximate — Sigma rule {rule_id} also requires {' and '.join(dropped)}, "
        "which this layer does not evaluate"
    ) if dropped else ""
    return result


# ── Flag emission ────────────────────────────────────────────────────────────

SIGMA_RULE_BASE_URL = (
    "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation"
)


def _field_suffix(field_name: str) -> str:
    """Return the flag-id suffix for a form field (``file_path`` -> ``FILE_PATH``)."""
    return field_name.upper()


def _sigma_rule_url(pairing: dict) -> str:
    """Build the SigmaHQ source URL for a matched pairing.

    Lets an analyst read the full original condition — which matters most for
    the approximate matches, where this layer evaluated only part of the rule.

    Args:
        pairing: A pairing record carrying ``sigma_file``.

    Returns:
        The rule's GitHub URL, or ``""`` when the filename is missing.
    """
    filename = str(pairing.get("sigma_file") or "").strip().lstrip("/")
    return f"{SIGMA_RULE_BASE_URL}/{filename}" if filename else ""


def _impersonation_note(analysis: FieldAnalysis) -> str:
    """Describe the dual-use nature of the binary a masquerading field impersonates.

    Folded into the masquerading flag's detail rather than emitted as its own
    ``DUAL_USE_BINARY`` flag. A separate flag would read "not malicious by
    itself" on a field we just flagged as impersonating a system binary — a
    direct contradiction — and would attribute the real binary's abuse
    categories to a file that demonstrably is not it.

    Args:
        analysis: A field analysis, expected to be masquerading.

    Returns:
        A sentence to append to the flag detail, or ``""`` when the impersonated
        binary is not in LOLBAS.
    """
    record = analysis.impersonated_lolbas
    if not record:
        return ""
    categories = ", ".join(record.get("categories") or []) or "unspecified abuse"
    return (
        f"The binary it impersonates, {record.get('binary')}, is documented in LOLBAS "
        f"as dual-use ({categories}) — check what command line was used."
    )


def _masquerade_detail(analysis: FieldAnalysis) -> str:
    """Join the identity finding with its impersonation note as two sentences.

    Args:
        analysis: A masquerading field analysis.

    Returns:
        The full flag detail text.
    """
    note = _impersonation_note(analysis)
    if not note:
        return analysis.identity_detail
    return f"{analysis.identity_detail.rstrip('. ')}. {note}"


def build_flags(result: ProcessAnalysisResult) -> list[dict]:
    """Turn an analysis result into flags for the existing MITRE-mapped flag system.

    Only genuine indicators are emitted — a verified system binary or an
    unrecognised third-party binary produces no flag, since neither is a
    finding. Flag ids are suffixed with the source field so two fields flagged
    the same way stay distinct through the downstream de-duplication.

    A masquerading field yields exactly one flag: LOLBAS context is folded into
    its detail instead of a competing ``DUAL_USE_BINARY`` entry, per briefing §3
    Layer 2 ("only meaningful to run on processes that passed Layer 1").

    Args:
        result: A populated analysis result.

    Returns:
        Flag dicts in the shared :func:`ioc.flags.base._flag` shape, ordered
        most severe first.
    """
    flags: list[dict] = []

    for field_name, label, analysis in result.field_analyses():
        suffix = _field_suffix(field_name)
        if analysis.is_masquerading():
            threat_type = (
                "Binary running from an unexpected location"
                if analysis.identity_flag == MASQUERADING_WRONG_PATH
                else "Binary impersonating a system process name"
            )
            # MITRE stays T1036.005 only. The impersonated binary's techniques
            # describe what the real tool can do, not what this file did.
            flags.append({
                **_flag(
                    f"{analysis.identity_flag}_{suffix}",
                    f"{label}: {analysis.value}",
                    threat_type,
                    "HIGH",
                    list(_MASQUERADE_MITRE),
                    _masquerade_detail(analysis),
                    "Process Analysis",
                ),
                # Masquerading has no external record to cite, so point at the
                # technique. If it impersonates a LOLBAS binary, that page is
                # the more actionable read.
                "source_url": (
                    (analysis.impersonated_lolbas or {}).get("url")
                    or mitre_url(_MASQUERADE_MITRE[0])
                ),
            })
            continue

        if analysis.lolbas_match:
            flags.append({
                **_flag(
                    f"{DUAL_USE_BINARY}_{suffix}",
                    f"{label}: {analysis.value}",
                    "Dual-use binary documented as abusable",
                    "INFO",
                    lolbas_lookup.mitre_techniques(analysis.lolbas_match),
                    lolbas_lookup.abuse_summary(analysis.lolbas_match)
                    + " — not malicious by itself; review the command line",
                    "LOLBAS",
                ),
                "source_url": analysis.lolbas_match.get("url", ""),
            })

    pairing = result.pairing_flag
    if pairing:
        level = str(pairing.get("sigma_level") or "medium").lower()
        techniques = pairing.get("mitre_techniques") or []
        if not techniques and pairing.get("mitre_technique"):
            techniques = [pairing["mitre_technique"]]
        detail = f"{pairing['parent']} spawned {pairing['child']} — {pairing.get('title', '')}"
        if pairing.get("approximate_note"):
            detail += f" [{pairing['approximate_note']}]"
        flags.append({
            **_flag(
                SUSPICIOUS_PARENT_CHILD_PAIR,
                f"Suspicious parent-child pair: {pairing['parent']} -> {pairing['child']}",
                "Known-suspicious process lineage",
                _SIGMA_LEVEL_TO_SEVERITY.get(level, "MEDIUM"),
                [str(t) for t in techniques],
                detail,
                "Sigma (extracted)",
            ),
            "source_url": _sigma_rule_url(pairing),
        })

    if result.chain_contamination and result.parent_process_analysis is not None:
        parent = result.parent_process_analysis
        flags.append({
            **_flag(
                PARENT_CHAIN_CONTAMINATION,
                f"Parent process is not what it claims: {parent.value}",
                "Contaminated process lineage",
                "HIGH",
                list(_MASQUERADE_MITRE),
                f"Parent flagged {parent.identity_flag} — any child it spawned inherits "
                f"that doubt. {parent.identity_detail}",
                "Process Analysis",
            ),
            "source_url": mitre_url(_MASQUERADE_MITRE[0]),
        })

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    flags.sort(key=lambda f: order.get(f["severity"], 5))
    return flags


# ── Verdict aggregation ──────────────────────────────────────────────────────

def _escalate(verdict: str, steps: int = 1) -> str:
    """Move a verdict up the severity ladder, clamped at the top.

    Args:
        verdict: Current verdict.
        steps: How many levels to climb.

    Returns:
        The escalated verdict.
    """
    try:
        index = VERDICT_LADDER.index(verdict)
    except ValueError:
        index = 0
    return VERDICT_LADDER[min(index + steps, len(VERDICT_LADDER) - 1)]


def _at_least(current: str, floor: str) -> str:
    """Return whichever of two verdicts is more severe."""
    ladder = list(VERDICT_LADDER)
    try:
        return current if ladder.index(current) >= ladder.index(floor) else floor
    except ValueError:
        return floor


def aggregate_verdict(result: ProcessAnalysisResult) -> str:
    """Compute the qualitative verdict for an analysis result.

    Precedence (briefing §5); only layers that actually ran are considered:

    1. A hash verdict, if one was resolved, dominates everything.
    2. Any ``MASQUERADING_*`` identity flag floors the verdict at ``Suspicious``.
    3. A pairing match at Sigma level high/critical yields ``Suspicious``, and
       ``Malicious`` when combined with masquerading or chain contamination.
       Medium/low pairings annotate without escalating.
    4. A LOLBAS match alone never escalates — dual-use binaries are ubiquitous
       in benign activity.
    5. Chain contamination escalates one level above the standalone verdict.
    6. Anything else — including a single clean field — is ``Unknown``.

    ``Benign`` is never returned: a clean field is not evidence of benignity
    when the other fields were never checked.

    Args:
        result: A populated analysis result (flags not required).

    Returns:
        One of ``"Malicious"``, ``"Suspicious"``, ``"Unknown"``.
    """
    if result.hash_verdict:
        verdict = str(result.hash_verdict.get("verdict") or "").strip()
        if verdict in ("Malicious", "Suspicious", "Unknown", "Benign"):
            return verdict

    masquerading = result.has_masquerading()
    verdict = "Unknown"

    if masquerading:
        verdict = _at_least(verdict, "Suspicious")

    pairing = result.pairing_flag
    if pairing and str(pairing.get("sigma_level") or "").lower() in _ESCALATING_SIGMA_LEVELS:
        verdict = _at_least(verdict, "Suspicious")
        if masquerading or result.chain_contamination:
            verdict = "Malicious"

    if result.chain_contamination:
        verdict = _escalate(verdict)

    return verdict


# ── Table rows ───────────────────────────────────────────────────────────────

def _row(artifact: str, row_type: str, verdict: str, confidence: str,
         evidence: str, sources: str) -> dict:
    """Build one table row matching the schema from :func:`ioc.verdict.summarize_results`.

    Every key the IOC rows carry is set explicitly, including the
    ``ConfidenceScore`` family — left blank because wiring this module into the
    numeric scorer is deferred. Setting them keeps ``pd.DataFrame`` from
    producing ragged NaN columns when these rows are concatenated with real ones.

    ``ConfidenceScore`` is ``None`` rather than ``""`` deliberately. Real IOC
    rows put a **number** there (``ioc/verdict.py:160``); an empty string
    alongside it makes an object column that pyarrow refuses to convert
    ("Could not convert '' with type str: tried to convert to double"), which
    breaks the whole Table render whenever a run has both real and synthetic
    rows. ``None`` becomes a null in a double column instead. Setting every key
    prevents *missing* columns; it does not prevent mixed *types*.

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


def to_rows(result: ProcessAnalysisResult) -> list[dict]:
    """Render an analysis result as table rows — one per submitted field.

    The Table output is normally one row per atomic IOC. Representing each
    submitted field as its own row keeps that schema rather than special-casing
    the layout. These rows are kept in their own list rather than merged into
    ``run_results["rows"]``, because that list is indexed per-artifact by the
    IOC cards and counted by the session summary.

    Args:
        result: A populated analysis result.

    Returns:
        Row dicts, empty when no process-bearing field was submitted.
    """
    rows: list[dict] = []

    for field_name, label, analysis in result.field_analyses():
        if analysis.is_masquerading():
            verdict = "Suspicious"
            confidence = "High" if analysis.identity_flag == MASQUERADING_WRONG_PATH else "Med"
            evidence = analysis.identity_detail
        else:
            verdict = "Unknown"
            confidence = "Low"
            evidence = analysis.identity_detail
            if analysis.lolbas_match:
                evidence += f" | {lolbas_lookup.abuse_summary(analysis.lolbas_match)}"
        rows.append(_row(
            analysis.value,
            "file_path" if field_name == "file_path" else "process",
            verdict, confidence, evidence, "Local (whitelist / LOLBAS)",
        ))

    # Pair row: emitted whenever the layer actually ran, including on a clean
    # result — a check that ran and found nothing is information the analyst
    # needs, and silence would read as "not checked".
    if result.parent_process_analysis and result.child_process_analysis:
        pairing = result.pairing_flag
        artifact = (f"{result.parent_process_analysis.value}"
                    f" -> {result.child_process_analysis.value}")
        if pairing:
            level = str(pairing.get("sigma_level") or "").lower()
            escalates = level in _ESCALATING_SIGMA_LEVELS
            verdict = "Suspicious" if escalates else "Unknown"
            confidence = "Low" if pairing.get("approximate") else "Med"
            evidence = f"{pairing.get('title')} [{level}]"
            if pairing.get("approximate"):
                evidence += " — approximate, source rule has conditions not evaluated here"
        else:
            verdict, confidence = "Unknown", "Low"
            evidence = "No known-suspicious pairing matched"
        rows.append(_row(
            artifact, "parent_child_pair", verdict, confidence,
            evidence, "Local (Sigma-derived)",
        ))

    return rows


# ── Entry point ──────────────────────────────────────────────────────────────

def analyze_process_event(data: ProcessFilepathInput) -> ProcessAnalysisResult:
    """Run every applicable layer over one process-creation event.

    Each layer is skipped independently when its input is absent; nothing is
    inferred about a field the analyst did not fill. ``checks_skipped`` records
    what did not run so downstream ticket generation does not imply certainty
    about unchecked fields.

    Args:
        data: The four independent form fields.

    Returns:
        A populated :class:`ProcessAnalysisResult`. When nothing was submitted
        the result is empty with an ``Unknown`` verdict — that case is form
        validation, handled at the UI layer, not an analysis outcome.
    """
    result = ProcessAnalysisResult(
        context_passthrough=data.context,
        fields_submitted=data.submitted_fields(),
    )

    # Layers 1 + 2, per submitted process-bearing field.
    analyses: dict[str, FieldAnalysis | None] = {}
    for field_name, label in _PROCESS_FIELDS:
        raw_value = getattr(data, field_name)
        analysis = analyze_identity(raw_value) if (raw_value or "").strip() else None
        if analysis is not None:
            analysis.lolbas_match = lolbas_lookup.lookup(analysis.value)
            if analysis.is_masquerading() and analysis.matched_process:
                # Look up the binary being *impersonated*, not the file itself.
                # A typosquat like scvhost.exe is absent from LOLBAS; what the
                # analyst needs to know is whether svchost.exe is dual-use.
                analysis.impersonated_lolbas = lolbas_lookup.lookup(analysis.matched_process)
        else:
            result.checks_skipped.append(f"{label} — not provided")
        analyses[field_name] = analysis

    result.file_path_analysis = analyses["file_path"]
    result.parent_process_analysis = analyses["parent_process"]
    result.child_process_analysis = analyses["child_process"]

    # Layer 3 — opportunistic only.
    result.hash_candidates = extract_hash_candidates(data.context)
    if not result.hash_candidates:
        result.checks_skipped.append(
            "Hash lookup — no hash found in Context (expected; this form has no hash field)"
        )

    # Layer 4 — requires both sides.
    if result.parent_process_analysis and result.child_process_analysis:
        result.pairing_flag = match_pairing(data.parent_process, data.child_process)
    else:
        result.checks_skipped.append(
            "Parent-child pairing — requires both Parent Process and Child Process"
        )

    # Chain propagation. Capped at one level: the form has no grandparent field,
    # so ancestry deeper than parent→child cannot be expressed (briefing §9.3).
    result.chain_contamination = bool(
        result.parent_process_analysis
        and result.parent_process_analysis.is_masquerading()
        and result.child_process_analysis is not None
    )

    result.aggregated_verdict = aggregate_verdict(result)
    result.flags = build_flags(result)
    return result
