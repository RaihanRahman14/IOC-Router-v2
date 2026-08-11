"""Offline extractor: SigmaHQ CommandLine conditions -> sigma_cmdline_patterns.json.

Sibling of ``extract_sigma_pairs.py`` and its exact mirror image. That script
keeps ``ParentImage``/``Image`` and drops the ``CommandLine`` condition; this one
keeps ``CommandLine`` and drops the image constraints. Both are **Option A** —
partial extraction — and both record which conditions they had to drop, which is
what makes the rule-id join in ``docs/cmdline_analyzer_plan.md`` D6 possible: a
rule that appears in *both* datasets and matches in *both* modules during one
session has had its full original condition satisfied.

Sigma is never evaluated at runtime — no ``pySigma``, no rule engine. The app
only reads the generated JSON.

Requires PyYAML — a script-only dependency, deliberately kept out of
``requirements.txt`` since the app never imports it::

    pip install pyyaml

Usage::

    python core/scripts/extract_sigma_cmdline_patterns.py --download
    python core/scripts/extract_sigma_cmdline_patterns.py --download --dry-run
    python core/scripts/extract_sigma_cmdline_patterns.py --sigma-dir /path/to/sigma

Source: https://github.com/SigmaHQ/sigma (DRL 1.1), ``rules/windows/process_creation/``
and ``rules/windows/powershell/``.
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

try:
    import yaml
except ImportError:  # pragma: no cover — script-only dependency
    print("PyYAML is required: pip install pyyaml", file=sys.stderr)
    raise SystemExit(2) from None

SIGMA_TARBALL_URL = "https://codeload.github.com/SigmaHQ/sigma/tar.gz/refs/heads/master"
RULE_SUBPATHS = ("/rules/windows/process_creation/", "/rules/windows/powershell/")
DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / "data" / "sigma_cmdline_patterns.json"
REQUEST_TIMEOUT = 180

# Detection blocks that *exclude* rather than detect.
_EXCLUSION_PREFIXES = ("filter", "known", "reduction", "falsepositive")

_SKIPPED_STATUSES = {"deprecated", "unsupported"}

# Fields carrying command-line content. ScriptBlockText comes from the
# powershell logsource; its content is command-line shaped and directly
# applicable here, but the logsource difference is recorded per record so the
# broader application stays visible and measurable.
_CMDLINE_FIELDS = ("CommandLine", "ScriptBlockText")
_PARENT_CMDLINE_FIELDS = ("ParentCommandLine",)
_IMAGE_FIELDS = ("Image", "OriginalFileName")
_PARENT_IMAGE_FIELDS = ("ParentImage",)

# The most important guard in this script. A CommandLine pattern of "*-r*" is
# technically faithful to its rule and catastrophic in isolation — the rule that
# carried it also pinned an Image. Anything this short is dropped rather than
# shipped, and counted so the loss is visible.
MIN_PATTERN_LEN = 4

# Per-rule cap against a pathological enumeration.
_MAX_PATTERNS_PER_RULE = 200

_TECHNIQUE_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)

logger = logging.getLogger("extract_sigma_cmdline_patterns")


# ── Rule sourcing ────────────────────────────────────────────────────────────

def iter_local_rules(sigma_dir: Path) -> Iterator[tuple[str, str]]:
    """Yield rule files from a local SigmaHQ checkout.

    Args:
        sigma_dir: Path to a clone of github.com/SigmaHQ/sigma.

    Yields:
        Tuples of (display name, YAML text).

    Raises:
        RuntimeError: If no rule directory can be located.
    """
    roots = [
        sigma_dir / "rules" / "windows" / "process_creation",
        sigma_dir / "rules" / "windows" / "powershell",
    ]
    roots = [r for r in roots if r.is_dir()] or ([sigma_dir] if sigma_dir.is_dir() else [])
    if not roots:
        raise RuntimeError(f"no Sigma rule directories found under {sigma_dir}")

    for root in roots:
        logger.info("reading rules from %s", root)
        for path in sorted(root.rglob("*.yml")):
            try:
                yield path.name, path.read_text(encoding="utf-8")
            except OSError as exc:
                logger.warning("cannot read %s: %s", path, exc)


def iter_downloaded_rules(url: str = SIGMA_TARBALL_URL) -> Iterator[tuple[str, str]]:
    """Yield rule files from the SigmaHQ source tarball.

    Args:
        url: Tarball URL for the SigmaHQ repository.

    Yields:
        Tuples of (display name, YAML text).

    Raises:
        RuntimeError: If the download or archive read fails.
    """
    logger.info("downloading %s", url)
    try:
        with urllib.request.urlopen(url, timeout=REQUEST_TIMEOUT) as resp:  # noqa: S310
            payload = resp.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"Sigma download failed: {exc}") from exc

    logger.info("downloaded %.1f MB", len(payload) / 1024 / 1024)
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                subpath = next((s for s in RULE_SUBPATHS if s in member.name), None)
                if subpath is None or not member.name.endswith((".yml", ".yaml")):
                    continue
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                name = member.name.split(subpath, 1)[1]
                yield name, handle.read().decode("utf-8")
    except (tarfile.TarError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"Sigma archive unreadable: {exc}") from exc


# ── Detection parsing ────────────────────────────────────────────────────────

def _is_exclusion_block(name: str) -> bool:
    """Return True if a detection block name marks an exclusion, not a detection."""
    return name.lower().startswith(_EXCLUSION_PREFIXES)


def _negated_blocks(condition: Any, block_names: list[str]) -> set[str]:
    """Find detection blocks that the condition string negates.

    Args:
        condition: The rule's ``detection.condition`` value.
        block_names: All detection block names in the rule.

    Returns:
        The subset of ``block_names`` appearing under a negation.
    """
    text = " ".join(condition) if isinstance(condition, list) else str(condition or "")
    if "not" not in text:
        return set()

    negated: set[str] = set()
    for fragment in re.split(r"\bnot\b", text)[1:]:
        clause = re.split(r"\b(?:and|or)\b", fragment)[0]
        for token in re.findall(r"[A-Za-z0-9_*]+", clause):
            if token.endswith("*"):
                prefix = token[:-1]
                negated.update(b for b in block_names if b.startswith(prefix))
            elif token in block_names:
                negated.add(token)
    return negated


def _normalize_pattern(value: Any, modifier: str) -> str | None:
    """Convert one Sigma CommandLine value into a lowercase substring pattern.

    The analyzer matches substrings, not globs, so surrounding ``*`` markers are
    not emitted — position information is dropped and the match is a plain
    "appears anywhere". That widens ``startswith``/``endswith`` slightly, which
    is recorded via ``position_relaxed`` on the record.

    Args:
        value: The Sigma field value.
        modifier: The pipe modifier (``contains``, ``endswith``, ``re``...).

    Returns:
        A lowercase substring, or None when the value cannot be used.
    """
    if modifier == "re":
        # Regexes are not translated: shipping attacker-influenced regex into a
        # runtime matcher invites catastrophic backtracking, and translating
        # them by hand would misreport what the rule actually said.
        return None
    if isinstance(value, (int, float)):
        value = str(value)
    if not isinstance(value, str):
        return None

    text = value.strip().strip("*").lower()
    if not text or len(text) < MIN_PATTERN_LEN:
        return None
    if not any(c.isalnum() for c in text):
        return None
    return text


def _collect_cmdline_groups(node: Any, out: list[dict[str, Any]],
                            dropped: list[str] | None = None) -> None:
    """Recursively collect CommandLine constraint groups from a detection block.

    Sigma's ``|all`` modifier means every listed value must appear. That maps
    directly onto the analyzer's list-pattern form, so the semantics survive
    extraction instead of being flattened into a noisier any-of.

    Args:
        node: A detection block (dict, list or scalar).
        out: Accumulator of ``{"patterns": [...], "match_all": bool}`` groups.
        dropped: Optional accumulator recording values that could not be
            expressed — a regex, or a fragment below the length floor. A rule
            that lost any value is no longer a faithful reproduction of itself.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            if not isinstance(key, str):
                continue
            parts = key.split("|")
            if parts[0] in _CMDLINE_FIELDS + _PARENT_CMDLINE_FIELDS:
                modifiers = [p.lower() for p in parts[1:]]
                match_all = "all" in modifiers
                modifier = next((m for m in modifiers if m != "all"), "")
                values = value if isinstance(value, list) else [value]
                normalized = [(v, _normalize_pattern(v, modifier)) for v in values]
                patterns = [p for _, p in normalized if p]
                if dropped is not None:
                    dropped.extend(f"{key}: {v}" for v, p in normalized if not p)
                if patterns:
                    out.append({
                        "patterns": sorted(set(patterns)) if not match_all else patterns,
                        "match_all": match_all,
                        "position_relaxed": modifier in ("startswith", "endswith"),
                    })
            else:
                _collect_cmdline_groups(value, out, dropped)
    elif isinstance(node, list):
        for item in node:
            _collect_cmdline_groups(item, out, dropped)


def _field_present(detection: dict, fields: tuple[str, ...]) -> bool:
    """Return True if the detection block constrains any of the given fields."""
    blob = json.dumps(detection)
    return any(f'"{f}' in blob for f in fields)


def _techniques(tags: Any) -> list[str]:
    """Extract MITRE technique IDs from a rule's tags.

    Args:
        tags: The rule's ``tags`` list (may be absent or malformed).

    Returns:
        Uppercased technique IDs such as ``["T1059.001"]``.
    """
    found: list[str] = []
    for tag in tags or []:
        match = _TECHNIQUE_RE.match(str(tag).strip())
        if match:
            technique = match.group(1).upper()
            if technique not in found:
                found.append(technique)
    return found


def extract_from_rule(name: str, text: str) -> list[dict[str, Any]]:
    """Extract CommandLine pattern records from one Sigma rule.

    Args:
        name: Rule filename, kept for traceability.
        text: Raw YAML text of the rule.

    Returns:
        Zero or more records. Empty when the rule is deprecated, is not a
        Windows process_creation / powershell rule, or constrains no command
        line content.
    """
    try:
        rule = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        logger.warning("%s: YAML parse failed (%s)", name, exc)
        return []

    if not isinstance(rule, dict):
        return []
    if str(rule.get("status") or "").lower() in _SKIPPED_STATUSES:
        return []

    logsource = rule.get("logsource") or {}
    category = str(logsource.get("category") or "").lower()
    service = str(logsource.get("service") or "").lower()
    if category not in ("process_creation", "ps_script", "ps_module") and service != "powershell":
        return []

    detection = rule.get("detection") or {}
    if not isinstance(detection, dict):
        return []

    block_names = [k for k in detection if k != "condition"]
    skip = {b for b in block_names if _is_exclusion_block(b)}
    skip |= _negated_blocks(detection.get("condition"), block_names)

    active_blocks = [b for b in block_names if b not in skip]
    groups: list[dict[str, Any]] = []
    dropped: list[str] = []
    for block in active_blocks:
        _collect_cmdline_groups(detection[block], groups, dropped)

    if not groups:
        return []

    techniques = _techniques(rule.get("tags"))
    level = str(rule.get("level") or "medium").lower()
    image_constrained = _field_present(detection, _IMAGE_FIELDS)
    parentimage_constrained = _field_present(detection, _PARENT_IMAGE_FIELDS)

    # A record may only be trusted on its own when it reproduces the rule's
    # ENTIRE detection condition. Anything else is a fragment: an ANDed sibling
    # block, a dropped regex, or a value below the length floor all mean the
    # rule said more than this record can express. Measurement forced this —
    # matching fragments standalone flagged every benign sample in the
    # calibration corpus, because a rule whose CommandLine condition is
    # ".bat/.bin/.cmd" only makes sense beside the folder condition it was
    # ANDed with.
    complete_condition = (
        len(active_blocks) == 1
        and len(groups) == 1
        and not dropped
        and not image_constrained
        and not parentimage_constrained
    )

    records: list[dict[str, Any]] = []
    for group in groups[:_MAX_PATTERNS_PER_RULE]:
        records.append({
            "patterns": group["patterns"],
            "match_all": group["match_all"],
            "position_relaxed": group["position_relaxed"],
            "complete_condition": complete_condition,
            "dropped_value_count": len(dropped),
            "active_block_count": len(active_blocks),
            "mitre_technique": techniques[0] if techniques else None,
            "mitre_techniques": techniques,
            "sigma_rule_id": rule.get("id"),
            "sigma_level": level,
            "sigma_status": str(rule.get("status") or "").lower() or None,
            "sigma_file": name.replace("\\", "/"),
            "logsource": category or service,
            "title": rule.get("title") or name,
            "image_constrained": image_constrained,
            "parentimage_constrained": parentimage_constrained,
            "blocks_in_rule": len(block_names),
        })
    return records


# ── Assembly ─────────────────────────────────────────────────────────────────

_LEVEL_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _rank(record: dict[str, Any]) -> tuple[int, int]:
    """Rank a record: Sigma severity first, then faithfulness to the source rule.

    Args:
        record: A pattern record.

    Returns:
        Sort key; higher is better.
    """
    level = _LEVEL_ORDER.get(record.get("sigma_level"), 2)
    faithful = 0 if (record.get("image_constrained")
                     or record.get("parentimage_constrained")) else 1
    return (level, faithful)


def dedupe(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse duplicate pattern groups, keeping the most severe source rule.

    Args:
        records: All extracted records.

    Returns:
        One record per (patterns, match_all), sorted for stable diffs, each
        carrying ``duplicate_rule_count``.
    """
    best: dict[tuple[Any, ...], dict[str, Any]] = {}
    for record in records:
        key = (tuple(record["patterns"]), record["match_all"])
        current = best.get(key)
        if current is None:
            best[key] = {**record, "duplicate_rule_count": 1}
            continue
        current["duplicate_rule_count"] += 1
        if _rank(record) > _rank(current):
            count = current["duplicate_rule_count"]
            best[key] = {**record, "duplicate_rule_count": count}

    return sorted(best.values(), key=lambda r: (r["patterns"], r["match_all"]))


def build_document(records: list[dict[str, Any]], source: str, rules_seen: int) -> dict[str, Any]:
    """Wrap the pattern list with provenance metadata.

    Args:
        records: Deduplicated pattern records.
        source: Where the rules came from (URL or directory).
        rules_seen: How many rule files were inspected.

    Returns:
        The full JSON document.
    """
    image_constrained = sum(1 for r in records if r["image_constrained"])
    parent_constrained = sum(1 for r in records if r["parentimage_constrained"])
    faithful = sum(
        1 for r in records
        if not r["image_constrained"] and not r["parentimage_constrained"]
    )
    complete = sum(1 for r in records if r["complete_condition"])
    return {
        "_meta": {
            "schema": (
                "list of {patterns, match_all, position_relaxed, mitre_technique, "
                "mitre_techniques, sigma_rule_id, sigma_level, sigma_status, sigma_file, "
                "logsource, title, image_constrained, parentimage_constrained, "
                "blocks_in_rule, duplicate_rule_count}"
            ),
            "purpose": "Layer 5 CommandLine pattern set for core.cmdline_analyzer",
            "extraction_mode": "Option A — CommandLine only, Image/ParentImage conditions dropped",
            "source": source,
            "project": "https://github.com/SigmaHQ/sigma",
            "license": "Detection Rule License (DRL) 1.1",
            "generated_by": "core/scripts/extract_sigma_cmdline_patterns.py",
            "updated": date.today().isoformat(),
            "rules_inspected": rules_seen,
            "pattern_count": len(records),
            "image_constrained_count": image_constrained,
            "parentimage_constrained_count": parent_constrained,
            "fully_faithful_count": faithful,
            "complete_condition_count": complete,
            "min_pattern_len": MIN_PATTERN_LEN,
            "notes": [
                "Records where image_constrained or parentimage_constrained is true are "
                "applied MORE BROADLY than their source rule intended. The rule-id join "
                "(plan D6) narrows them back whenever the process module matches the same "
                "sigma_rule_id in the same session.",
                "Patterns shorter than min_pattern_len are dropped: a two-character "
                "CommandLine fragment is faithful to its rule and useless without the "
                "Image condition that accompanied it.",
                "Regex conditions (|re) are never translated — matching attacker-"
                "influenced regex at runtime is a denial-of-service risk and hand "
                "translation would misreport the rule.",
                "position_relaxed marks a startswith/endswith condition matched as a "
                "plain substring, which is slightly broader than the source rule.",
            ],
        },
        "patterns": records,
    }


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Args:
        argv: Command-line arguments (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code.
    """
    ap = argparse.ArgumentParser(description=__doc__)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--sigma-dir", type=Path, help="path to a SigmaHQ checkout")
    src.add_argument("--download", action="store_true", help="fetch the SigmaHQ tarball")
    ap.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    ap.add_argument("--dry-run", action="store_true", help="report counts, write nothing")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.download:
        source = SIGMA_TARBALL_URL
        rules = iter_downloaded_rules()
    else:
        source = str(args.sigma_dir)
        rules = iter_local_rules(args.sigma_dir)

    raw: list[dict[str, Any]] = []
    seen = 0
    for name, text in rules:
        seen += 1
        raw.extend(extract_from_rule(name, text))

    records = dedupe(raw)
    document = build_document(records, source, seen)
    meta = document["_meta"]

    logger.info(
        "inspected %d rules -> %d raw, %d deduped patterns "
        "(%d image-constrained, %d parentimage-constrained, %d fully faithful)",
        seen, len(raw), len(records), meta["image_constrained_count"],
        meta["parentimage_constrained_count"], meta["fully_faithful_count"],
    )

    if args.dry_run:
        logger.info("dry run — nothing written")
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    logger.info("wrote %s", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
