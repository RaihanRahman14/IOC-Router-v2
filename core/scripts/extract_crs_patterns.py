"""Offline extractor: OWASP CRS SecRule patterns -> crs_patterns.json.

Sibling of ``extract_sigma_cmdline_patterns.py`` and built on the same premise:
CRS is a **rule set, not a library**, so the app never runs a rule engine. This
script reads SecLang offline and emits plain JSON; ``core/waf_payload_analyzer``
only ever reads that file. No ModSecurity, no Coraza, no live evaluation —
``docs/waf_payload_analyzer.md`` D3 and §10.

Like the Sigma extractor this is **Option A — partial extraction with
provenance**. A CRS rule is a pattern *plus* a target list *plus* a
transformation chain, and this tool can only carry the first two faithfully. What
it had to drop is recorded per rule in ``dropped_conditions``, because a
partially-extracted rule that presents itself as complete produces confident
wrong answers.

Three SecLang complications, and what happens to each:

* **Operators that are not patterns.** ``@detectSQLi`` and ``@detectXSS`` *are*
  libinjection embedded in ModSecurity; they cannot be extracted as regex and are
  dropped and counted. Numeric operators (``@lt``, ``@gt``, ``@eq``) belong to
  CRS's paranoia-level control flow rather than to detection, and are skipped.
* **``@pmFromFile``.** These reference external ``.data`` word lists, which are
  read from the same archive and emitted as ``phrase_lists``. They are kept as
  phrases rather than converted to a regex alternation: ModSecurity matches them
  as case-insensitive substrings, and substring matching is what reproduces that
  faithfully.
* **PCRE constructs Python's ``re`` lacks.** Every pattern is compile-verified
  here; one that will not compile is dropped and counted, never emitted. Two
  PCRE-isms CRS actually uses are translated first — see
  :func:`pcre_to_python`, and read its warning before adding a third.

Requires no third-party package: SecLang is text, not YAML, so this script has
no PyYAML dependency and the app has no new one either.

Usage::

    python core/scripts/extract_crs_patterns.py --download
    python core/scripts/extract_crs_patterns.py --download --dry-run
    python core/scripts/extract_crs_patterns.py --crs-dir /path/to/coreruleset

Source: https://github.com/coreruleset/coreruleset (Apache License 2.0).
"""
from __future__ import annotations

import argparse
import io
import json
import logging
import re
import sys
import tarfile
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path
from typing import Any, Iterator

CRS_TARBALL_URL = "https://codeload.github.com/coreruleset/coreruleset/tar.gz/refs/heads/main"
DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / "data" / "crs_patterns.json"
REQUEST_TIMEOUT = 180

# Rule files to read, and the category each contributes.
#
# This is **wider than plan D3's list**, which named only 921/930/932/933. Two
# additions, both from briefing §3 Layer 3, which D3's shorter list dropped:
# 931 covers the RFI the briefing explicitly asked for, and 934 covers SSRF.
# 941 and 942 are here because of D1 — with libinjection rejected, CRS is the
# only source of SQLi and XSS patterns, so the ranges the briefing told us to
# skip become the ones we most need.
CATEGORY_BY_FILE: dict[str, str] = {
    "REQUEST-921-PROTOCOL-ATTACK.conf": "protocol",
    "REQUEST-930-APPLICATION-ATTACK-LFI.conf": "lfi",
    "REQUEST-931-APPLICATION-ATTACK-RFI.conf": "rfi",
    "REQUEST-932-APPLICATION-ATTACK-RCE.conf": "rce",
    "REQUEST-933-APPLICATION-ATTACK-PHP.conf": "php",
    "REQUEST-934-APPLICATION-ATTACK-GENERIC.conf": "ssrf",
    "REQUEST-941-APPLICATION-ATTACK-XSS.conf": "xss",
    "REQUEST-942-APPLICATION-ATTACK-SQLI.conf": "sqli",
}

# CRS's own anomaly-scoring weights. Taken from the rule set's scoring model
# rather than invented: this is what CRS itself adds to the anomaly score per
# matched rule at each severity.
SEVERITY_WEIGHTS: dict[str, float] = {
    "CRITICAL": 5.0,
    "ERROR": 4.0,
    "WARNING": 3.0,
    "NOTICE": 2.0,
}

# Operators that carry no extractable pattern, and why each is refused. The
# distinction matters: the first two are capability gaps this tool cannot close,
# the rest are control flow that was never detection in the first place.
UNEXTRACTABLE_OPERATORS: dict[str, str] = {
    "@detectSQLi": "libinjection operator — not a regex, cannot be extracted",
    "@detectXSS": "libinjection operator — not a regex, cannot be extracted",
    "@validateByteRange": "byte-range validation, not a pattern",
    "@validateUtf8Encoding": "encoding validation, not a pattern",
    "@validateUrlEncoding": "encoding validation, not a pattern",
    "@ipMatch": "matches client IP, not payload content",
    "@unconditionalMatch": "always true — a scoring hook, not a detection",
}

# Transformations this project's Layer 1 can reproduce. Anything else is
# recorded per rule so Milestone B knows the pattern is being matched against
# text the rule did not expect.
SUPPORTED_TRANSFORMS = frozenset({
    "none",
    "lowercase",
    "urldecode",
    "urldecodeuni",
    "htmlentitydecode",
    "base64decode",
    "removenulls",
    "compresswhitespace",
    "normalizepath",
    "normalizepathwin",
    "utf8tounicode",
})

# Targets whose content a submitted "path | payload" line can actually stand in
# for. A rule aimed only at headers or cookies is being applied to something its
# author never had in mind, and says so in dropped_conditions.
PAYLOAD_TARGETS = frozenset({
    "ARGS", "ARGS_NAMES", "ARGS_GET", "ARGS_GET_NAMES", "ARGS_POST",
    "ARGS_POST_NAMES", "REQUEST_URI", "REQUEST_URI_RAW", "REQUEST_FILENAME",
    "REQUEST_BODY", "QUERY_STRING", "REQUEST_LINE", "XML", "FILES",
    "FILES_NAMES", "MULTIPART_FILENAME", "MULTIPART_NAME", "PATH_INFO",
})

_CONTINUATION_RE = re.compile(r"\\\r?\n\s*")
_OPERATOR_RE = re.compile(r"\s*(!?)(@\w+)(?:\s+(.*))?$", re.DOTALL)
_ID_RE = re.compile(r"(?:^|,)\s*id:'?(\d+)'?")
_SEVERITY_RE = re.compile(r"(?:^|,)\s*severity:'?([A-Z]+)'?")
_MSG_RE = re.compile(r"(?:^|,)\s*msg:'((?:[^']|\\')*)'")
_TRANSFORM_RE = re.compile(r"(?:^|,)\s*t:'?(\w+)'?")
_PARANOIA_RE = re.compile(r"tag:'paranoia-level/(\d+)'")
_PM_FILE_RE = re.compile(r"^\s*(\S+\.data)\s*$")
# The ``chain`` action, as a standalone token in the comma-separated action list.
# Continuation folding leaves surrounding whitespace, so a plain
# ``"chain" in actions.split(",")`` misses every one of them.
_CHAIN_RE = re.compile(r"(?:^|,)\s*chain\s*(?:,|$)")

# PCRE-isms CRS actually uses. Deliberately a short, closed list.
_PCRE_HEX_BRACE_RE = re.compile(r"\\x\{([0-9A-Fa-f]{1,6})\}")
_PCRE_ABS_END_RE = re.compile(r"(?<!\\)\\z")

logger = logging.getLogger(__name__)


def pcre_to_python(pattern: str) -> str:
    """Translate the PCRE constructs CRS uses into Python ``re`` equivalents.

    Only two, both exact rewrites with no change of meaning:

    * ``\\x{hh}`` — PCRE's arbitrary-codepoint escape. Python spells the same
      thing ``\\xhh`` / ``\\uhhhh`` / ``\\Uhhhhhhhh`` depending on width.
    * ``\\z`` — PCRE's absolute end of subject. Python spells it ``\\Z``.

    **Do not add a rule here that merely makes a pattern compile.** The obvious
    "fix" for ``\\x{bc}`` is to pad the bare ``\\x`` to ``\\x00``, which compiles
    cleanly and silently turns the pattern into ``\\x00{bc}`` — it then fails to
    match the very payload the rule exists for. A translation that changes what a
    rule matches is worse than dropping the rule, because the drop is counted and
    the mistranslation is not.

    Args:
        pattern: The raw regex from a SecRule operand.

    Returns:
        An equivalent pattern in Python regex syntax.
    """
    def _hex(match: re.Match[str]) -> str:
        code = int(match.group(1), 16)
        if code <= 0xFF:
            return f"\\x{code:02x}"
        if code <= 0xFFFF:
            return f"\\u{code:04x}"
        return f"\\U{code:08x}"

    translated = _PCRE_HEX_BRACE_RE.sub(_hex, pattern)
    return _PCRE_ABS_END_RE.sub(r"\\Z", translated)


def quoted_blocks(statement: str) -> list[str]:
    """Split a SecRule statement into its double-quoted sections.

    Written as a scanner rather than a regex because the operand of a CRS rule is
    itself a regex full of brackets, quotes and escapes — the exact input that
    makes a quote-matching regex quietly wrong.

    Args:
        statement: One logical ``SecRule`` line, continuations already joined.

    Returns:
        The quoted sections in order. For a detection rule that is
        ``[operand, actions]``.
    """
    out: list[str] = []
    buf: list[str] = []
    inside = False
    escaped = False
    for char in statement:
        if escaped:
            buf.append(char)
            escaped = False
            continue
        if char == "\\":
            if inside:
                buf.append(char)
            escaped = True
            continue
        if char == '"':
            if inside:
                out.append("".join(buf))
                buf = []
            inside = not inside
            continue
        if inside:
            buf.append(char)
    return out


def iter_statements(text: str) -> Iterator[str]:
    """Yield logical ``SecRule`` statements from one .conf file.

    Args:
        text: Full file contents.

    Yields:
        One statement per rule, with backslash-newline continuations folded.
    """
    joined = _CONTINUATION_RE.sub(" ", text)
    for line in joined.splitlines():
        stripped = line.strip()
        if stripped.startswith("SecRule "):
            yield stripped


def iter_local_sources(crs_dir: Path) -> tuple[dict[str, str], dict[str, str]]:
    """Read rule files and .data word lists from a CRS checkout.

    Args:
        crs_dir: Path to a coreruleset checkout.

    Returns:
        Tuple of (conf files by basename, data files by basename).

    Raises:
        RuntimeError: If no rules directory is found.
    """
    rules_dir = crs_dir / "rules"
    if not rules_dir.is_dir():
        raise RuntimeError(f"no rules/ directory under {crs_dir}")
    confs = {p.name: p.read_text(encoding="utf-8") for p in rules_dir.glob("*.conf")}
    datas = {p.name: p.read_text(encoding="utf-8") for p in rules_dir.glob("*.data")}
    return confs, datas


def iter_downloaded_sources(url: str = CRS_TARBALL_URL) -> tuple[dict[str, str], dict[str, str]]:
    """Fetch rule files and .data word lists from the CRS source tarball.

    Args:
        url: Tarball URL for the coreruleset repository.

    Returns:
        Tuple of (conf files by basename, data files by basename).

    Raises:
        RuntimeError: If the download or archive read fails.
    """
    logger.info("downloading %s", url)
    try:
        with urllib.request.urlopen(url, timeout=REQUEST_TIMEOUT) as resp:  # noqa: S310
            payload = resp.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"CRS download failed: {exc}") from exc

    logger.info("downloaded %.1f MB", len(payload) / 1024 / 1024)
    confs: dict[str, str] = {}
    datas: dict[str, str] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            for member in archive.getmembers():
                if not member.isfile() or "/rules/" not in member.name:
                    continue
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                name = member.name.rsplit("/", 1)[-1]
                if name.endswith(".conf"):
                    confs[name] = handle.read().decode("utf-8")
                elif name.endswith(".data"):
                    datas[name] = handle.read().decode("utf-8")
    except (tarfile.TarError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"CRS archive unreadable: {exc}") from exc
    return confs, datas


def parse_phrase_list(text: str) -> list[str]:
    """Parse a CRS ``.data`` word list.

    Args:
        text: File contents.

    Returns:
        Phrases, comments and blank lines removed.
    """
    return [
        line.strip() for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _targets(statement: str) -> list[str]:
    """Extract the variable list a SecRule applies to.

    Args:
        statement: One logical SecRule statement.

    Returns:
        Target names, negations (``!REQUEST_HEADERS:Referer``) removed since they
        narrow a rule rather than defining it.
    """
    head = statement[len("SecRule "):].split('"', 1)[0].strip()
    out: list[str] = []
    for part in head.split("|"):
        part = part.strip()
        if not part or part.startswith("!"):
            continue
        out.append(part.split(":", 1)[0])
    return out


def _dropped_conditions(
    targets: list[str],
    transforms: list[str],
    negated: bool,
) -> list[str]:
    """Record what this extraction could not carry over from the source rule.

    Args:
        targets: The rule's variable list.
        transforms: The rule's transformation chain.
        negated: Whether the operator was negated (``!@rx``).

    Returns:
        Human-readable notes, empty when the rule was extracted whole.
    """
    dropped: list[str] = []

    if targets and not (set(targets) & PAYLOAD_TARGETS):
        dropped.append(
            "target mismatch: rule aims at " + "/".join(sorted(set(targets)))
            + ", none of which a path/payload line stands in for"
        )
    unsupported = [t for t in transforms if t.lower() not in SUPPORTED_TRANSFORMS]
    if unsupported:
        dropped.append(
            "unsupported transformations: " + ", ".join(sorted(set(unsupported)))
        )
    if negated:
        dropped.append("negated operator — rule fires when the pattern does NOT match")
    return dropped


def extract_from_file(
    filename: str,
    text: str,
    category: str,
    stats: dict[str, int],
) -> list[dict[str, Any]]:
    """Extract every usable detection rule from one CRS .conf file.

    Args:
        filename: Basename, recorded for provenance.
        text: File contents.
        category: Attack category this file contributes.
        stats: Mutable counter dict, updated with drop causes.

    Returns:
        Rule records.
    """
    records: list[dict[str, Any]] = []

    for statement in iter_statements(text):
        stats["statements_seen"] += 1
        blocks = quoted_blocks(statement)
        if len(blocks) < 2:
            stats["skipped_malformed"] += 1
            continue

        operand, actions = blocks[0], blocks[-1]
        rule_id_match = _ID_RE.search(actions)
        severity_match = _SEVERITY_RE.search(actions)

        # A chained rule's head pattern is a *precondition*, not the detection.
        # Rule 932205 is `@rx ^[^#]+` against the Referer header, which matches
        # essentially any string; what actually detects the attack lives in the
        # indented sub-rules that follow. Emitting the head alone produced a rule
        # that fired on "report q3", and one that fires on everything is exactly
        # the alert fatigue this module exists to avoid. Reconstructing the full
        # condition would mean modelling MATCHED_VARS and the chain's execution
        # order — a rule engine, which §10 rules out — so these are dropped and
        # counted, per D3's standing preference for a counted drop over a
        # confident mistranslation.
        if _CHAIN_RE.search(actions):
            stats["dropped_chained_rule"] += 1
            continue

        # The sub-rules of a chain carry neither an id nor a severity: they are
        # continuations of the rule above, already dropped. Counting them
        # separately keeps them out of the control-flow figure, which would
        # otherwise overstate how much of CRS is not detection.
        if rule_id_match is None and severity_match is None:
            stats["skipped_chain_continuation"] += 1
            continue

        # A CRS rule without a severity is control flow — paranoia-level gating,
        # skipAfter markers, score accumulation. Never a detection.
        if severity_match is None:
            stats["skipped_control_flow"] += 1
            continue
        if rule_id_match is None:
            stats["skipped_no_id"] += 1
            continue

        op_match = _OPERATOR_RE.match(operand)
        if op_match is None:
            # No explicit operator means an implicit @rx in SecLang.
            negated, operator, argument = "", "@rx", operand
        else:
            negated, operator, argument = op_match.groups()
            argument = argument or ""

        if operator in UNEXTRACTABLE_OPERATORS:
            stats["dropped_unextractable_operator"] += 1
            stats[f"dropped_operator_{operator}"] = (
                stats.get(f"dropped_operator_{operator}", 0) + 1
            )
            continue

        severity = severity_match.group(1)
        transforms = _TRANSFORM_RE.findall(actions)
        targets = _targets(statement)
        paranoia = _PARANOIA_RE.search(actions)
        msg = _MSG_RE.search(actions)

        record: dict[str, Any] = {
            "rule_id": rule_id_match.group(1),
            "category": category,
            "severity": severity,
            "severity_weight": SEVERITY_WEIGHTS.get(severity, 1.0),
            "paranoia_level": int(paranoia.group(1)) if paranoia else 1,
            "targets": targets,
            "transformations": transforms,
            "message": (msg.group(1) if msg else "").replace("\\'", "'"),
            "crs_file": filename,
            "dropped_conditions": _dropped_conditions(targets, transforms, bool(negated)),
        }

        if operator in ("@pmFromFile", "@pmf"):
            file_match = _PM_FILE_RE.match(argument)
            if file_match is None:
                stats["dropped_pm_inline"] += 1
                continue
            record["match"] = "phrases"
            record["phrase_list"] = file_match.group(1)
            records.append(record)
            stats["extracted_phrases"] += 1
            continue

        if operator == "@pm":
            record["match"] = "phrases"
            record["phrases"] = argument.split()
            records.append(record)
            stats["extracted_phrases"] += 1
            continue

        if operator != "@rx":
            stats["skipped_other_operator"] += 1
            stats[f"skipped_operator_{operator}"] = (
                stats.get(f"skipped_operator_{operator}", 0) + 1
            )
            continue

        translated = pcre_to_python(argument)
        if translated != argument:
            stats["pcre_translated"] += 1
        try:
            re.compile(translated)
        except re.error as exc:
            # Dropped, never emitted in a weakened form. Counted so the yield
            # figure in the plan stays honest.
            logger.warning("rule %s: uncompilable pattern (%s)", record["rule_id"], exc)
            stats["dropped_uncompilable"] += 1
            continue

        record["match"] = "regex"
        record["pattern"] = translated
        records.append(record)
        stats["extracted_regex"] += 1

    return records


def build_document(
    records: list[dict[str, Any]],
    phrase_lists: dict[str, list[str]],
    source: str,
    stats: dict[str, int],
) -> dict[str, Any]:
    """Wrap the rule list with provenance metadata.

    Args:
        records: Extracted rule records.
        phrase_lists: Word lists referenced by ``@pmFromFile`` rules.
        source: Where the rules came from (URL or directory).
        stats: Extraction counters.

    Returns:
        The full JSON document.
    """
    by_category: dict[str, int] = {}
    for record in records:
        by_category[record["category"]] = by_category.get(record["category"], 0) + 1
    partial = sum(1 for r in records if r["dropped_conditions"])

    return {
        "_meta": {
            "schema": (
                "list of {rule_id, category, match, pattern|phrases|phrase_list, "
                "severity, severity_weight, paranoia_level, targets, transformations, "
                "message, crs_file, dropped_conditions}"
            ),
            "purpose": "Layer 3 rule set for core.waf_payload_analyzer",
            "extraction_mode": (
                "Option A — pattern and targets only; transformation chains and "
                "non-regex operators are recorded, not reproduced"
            ),
            "source": source,
            "project": "https://github.com/coreruleset/coreruleset",
            "license": "Apache License 2.0",
            "generated_by": "core/scripts/extract_crs_patterns.py",
            "updated": date.today().isoformat(),
            "rule_count": len(records),
            "rules_by_category": dict(sorted(by_category.items())),
            "partial_extraction_count": partial,
            "counters": dict(sorted(stats.items())),
            "notes": [
                "Rules are never evaluated by a rule engine. The app reads this "
                "JSON and nothing else; there is no ModSecurity or Coraza in the "
                "loop, by design.",
                "A record with a non-empty dropped_conditions is applied MORE "
                "BROADLY than its source rule intended — usually because the rule "
                "targets headers or cookies that a pasted path/payload line does "
                "not stand in for, or because its transformation chain cannot be "
                "reproduced by this project's Layer 1.",
                "severity_weight follows CRS's own anomaly scoring: CRITICAL 5, "
                "ERROR 4, WARNING 3, NOTICE 2. Summing matched weights is what "
                "makes an anomaly score, and no single match is conclusive.",
                "paranoia_level is carried because CRS's own operational model "
                "treats higher levels as progressively more false-positive prone. "
                "A consumer that ignores it will inherit that noise.",
                "@detectSQLi and @detectXSS rules are dropped: they are "
                "libinjection inside ModSecurity, not regexes, and cannot be "
                "extracted. See docs/waf_payload_analyzer.md D1.",
                "Patterns are compile-verified before emission. PCRE's \\x{hh} "
                "and \\z are translated to Python equivalents; nothing else is "
                "rewritten, because a translation that changes what a rule "
                "matches is worse than a drop that gets counted.",
            ],
        },
        "phrase_lists": phrase_lists,
        "rules": records,
    }


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Args:
        argv: Command-line arguments (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code.
    """
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    ap = argparse.ArgumentParser(description="Extract OWASP CRS patterns to JSON.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--crs-dir", type=Path, help="path to a coreruleset checkout")
    src.add_argument("--download", action="store_true", help="fetch the CRS tarball")
    ap.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    ap.add_argument("--dry-run", action="store_true", help="report counts, write nothing")
    args = ap.parse_args(argv)

    try:
        if args.download:
            confs, datas = iter_downloaded_sources()
            source = CRS_TARBALL_URL
        else:
            confs, datas = iter_local_sources(args.crs_dir)
            source = str(args.crs_dir)
    except RuntimeError as exc:
        logger.error("%s", exc)
        return 2

    stats: dict[str, int] = {
        "statements_seen": 0,
        "extracted_regex": 0,
        "extracted_phrases": 0,
        "pcre_translated": 0,
        "dropped_uncompilable": 0,
        "dropped_unextractable_operator": 0,
        "dropped_pm_inline": 0,
        "dropped_chained_rule": 0,
        "skipped_chain_continuation": 0,
        "skipped_control_flow": 0,
        "skipped_other_operator": 0,
        "skipped_malformed": 0,
        "skipped_no_id": 0,
    }

    records: list[dict[str, Any]] = []
    missing_files: list[str] = []
    for filename, category in CATEGORY_BY_FILE.items():
        text = confs.get(filename)
        if text is None:
            missing_files.append(filename)
            logger.warning("rule file not found in source: %s", filename)
            continue
        records.extend(extract_from_file(filename, text, category, stats))

    # Only ship the word lists rules actually reference.
    wanted = {r["phrase_list"] for r in records if r.get("phrase_list")}
    phrase_lists: dict[str, list[str]] = {}
    for name in sorted(wanted):
        raw = datas.get(name)
        if raw is None:
            logger.warning("phrase list missing from source: %s", name)
            continue
        phrase_lists[name] = parse_phrase_list(raw)

    # A rule pointing at a list we could not read would match nothing while
    # claiming to be active. Drop it and say so.
    before = len(records)
    records = [
        r for r in records
        if not r.get("phrase_list") or r["phrase_list"] in phrase_lists
    ]
    stats["dropped_missing_phrase_list"] = before - len(records)
    if missing_files:
        stats["rule_files_missing"] = len(missing_files)

    records.sort(key=lambda r: r["rule_id"])
    document = build_document(records, phrase_lists, source, stats)

    meta = document["_meta"]
    logger.info("statements seen        : %d", stats["statements_seen"])
    logger.info("extracted (regex)      : %d", stats["extracted_regex"])
    logger.info("extracted (phrases)    : %d", stats["extracted_phrases"])
    logger.info("  of which partial     : %d", meta["partial_extraction_count"])
    logger.info("dropped (uncompilable) : %d", stats["dropped_uncompilable"])
    logger.info("dropped (operator)     : %d", stats["dropped_unextractable_operator"])
    logger.info("dropped (chained)      : %d", stats["dropped_chained_rule"])
    logger.info("skipped (control flow) : %d", stats["skipped_control_flow"])
    logger.info("skipped (chain cont.)  : %d", stats["skipped_chain_continuation"])
    logger.info("phrase lists           : %d", len(phrase_lists))
    logger.info("by category            : %s", meta["rules_by_category"])

    if args.dry_run:
        logger.info("dry run — nothing written")
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    logger.info("wrote %s (%.0f KB)", args.output, args.output.stat().st_size / 1024)
    return 0


if __name__ == "__main__":
    sys.exit(main())
