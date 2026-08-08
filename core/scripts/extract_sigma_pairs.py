"""Offline extractor: SigmaHQ process_creation rules -> sigma_parent_child_pairs.json.

Layer 4 of the process-analysis module needs a finite blocklist of suspicious
parent -> child process pairings. SigmaHQ documents these, but as full detection
rules; this script performs a **one-off / quarterly offline extraction** of just
the pairing data. Sigma is never evaluated at runtime — no ``pySigma``, no
``sigma-cli``, no rule engine. The app only reads the generated JSON.

**This is Option A** from the briefing: pairing-only extraction. Many source
rules additionally require a ``CommandLine`` pattern to match; dropping that
condition makes this table **broader and noisier than the original rules**.
Every emitted record therefore carries ``commandline_constrained`` and
``sigma_rule_id`` so an analyst can look up the precise original condition.

Requires PyYAML — a script-only dependency, deliberately kept out of
``requirements.txt`` since the app never imports it::

    pip install pyyaml

Usage::

    python core/scripts/extract_sigma_pairs.py --sigma-dir /path/to/sigma
    python core/scripts/extract_sigma_pairs.py --download
    python core/scripts/extract_sigma_pairs.py --download --dry-run

Source: https://github.com/SigmaHQ/sigma (DRL 1.1), ``rules/windows/process_creation/``
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
from pathlib import Path, PureWindowsPath
from typing import Any, Iterator

try:
    import yaml
except ImportError:  # pragma: no cover — script-only dependency
    print("PyYAML is required: pip install pyyaml", file=sys.stderr)
    raise SystemExit(2) from None

SIGMA_TARBALL_URL = "https://codeload.github.com/SigmaHQ/sigma/tar.gz/refs/heads/master"
RULE_SUBPATH = "/rules/windows/process_creation/"
DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / "data" / "sigma_parent_child_pairs.json"
REQUEST_TIMEOUT = 180

# Detection blocks that *exclude* rather than detect. Their Image/ParentImage
# values are known-good and must never become blocklist entries.
_EXCLUSION_PREFIXES = ("filter", "known", "reduction", "falsepositive")

# Rule statuses we refuse to ship.
_SKIPPED_STATUSES = {"deprecated", "unsupported"}

# Cross-product guard against a pathological rule. Deliberately loose: the
# genuinely valuable rules here (Office apps x shells, webserver x recon tools)
# legitimately enumerate ~600 pairs, so a tight cap silently drops exactly the
# data Layer 4 exists to carry.
_MAX_PAIRS_PER_RULE = 1000

_CHILD_FIELDS = ("Image", "OriginalFileName")
_PARENT_FIELDS = ("ParentImage",)

_TECHNIQUE_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)

logger = logging.getLogger("extract_sigma_pairs")


# ── Rule sourcing ────────────────────────────────────────────────────────────

def iter_local_rules(sigma_dir: Path) -> Iterator[tuple[str, str]]:
    """Yield process_creation rule files from a local SigmaHQ checkout.

    Args:
        sigma_dir: Path to a clone of github.com/SigmaHQ/sigma, or directly to
            its ``rules/windows/process_creation`` directory.

    Yields:
        Tuples of (display name, YAML text).

    Raises:
        RuntimeError: If no process_creation directory can be located.
    """
    candidates = [sigma_dir / "rules" / "windows" / "process_creation", sigma_dir]
    root = next((c for c in candidates if c.is_dir()), None)
    if root is None:
        raise RuntimeError(f"no process_creation rules found under {sigma_dir}")

    logger.info("reading rules from %s", root)
    for path in sorted(root.rglob("*.yml")):
        try:
            yield path.name, path.read_text(encoding="utf-8")
        except OSError as exc:
            logger.warning("cannot read %s: %s", path, exc)


def iter_downloaded_rules(url: str = SIGMA_TARBALL_URL) -> Iterator[tuple[str, str]]:
    """Yield process_creation rule files from the SigmaHQ source tarball.

    Downloads the default-branch archive once and streams the relevant members
    out of it — no clone is left on disk.

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
                if not member.isfile() or RULE_SUBPATH not in member.name:
                    continue
                if not member.name.endswith((".yml", ".yaml")):
                    continue
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                name = member.name.split(RULE_SUBPATH, 1)[1]
                yield name, handle.read().decode("utf-8")
    except (tarfile.TarError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"Sigma archive unreadable: {exc}") from exc


# ── Detection parsing ────────────────────────────────────────────────────────

def _is_exclusion_block(name: str) -> bool:
    """Return True if a detection block name marks an exclusion, not a detection."""
    return name.lower().startswith(_EXCLUSION_PREFIXES)


def _negated_blocks(condition: Any, block_names: list[str]) -> set[str]:
    """Find detection blocks that the condition string negates.

    Catches both ``not selection_x`` and ``not 1 of selection_x_*`` forms, which
    some rules use for blocks that are not named ``filter*``.

    Args:
        condition: The rule's ``detection.condition`` value.
        block_names: All detection block names in the rule.

    Returns:
        The subset of ``block_names`` that appears under a negation.
    """
    text = " ".join(condition) if isinstance(condition, list) else str(condition or "")
    if "not" not in text:
        return set()

    negated: set[str] = set()
    for fragment in re.split(r"\bnot\b", text)[1:]:
        # Only the clause immediately after `not` is negated; stop at the next
        # boolean joiner so `not filter_a and selection_b` does not over-capture.
        clause = re.split(r"\b(?:and|or)\b", fragment)[0]
        for token in re.findall(r"[A-Za-z0-9_*]+", clause):
            if token.endswith("*"):
                prefix = token[:-1]
                negated.update(b for b in block_names if b.startswith(prefix))
            elif token in block_names:
                negated.add(token)
    return negated


def _is_name_shaped(value: str) -> bool:
    """Return True if a Sigma value constrains a filename rather than a directory.

    Sigma uses the same ``contains``/``endswith`` modifiers for both, e.g.
    ``ParentImage|contains: '\\winword.exe'`` (a name) and
    ``ParentImage|contains: ':\\PerfLogs\\'`` (a directory). Only the former is
    evaluable against a name-only field; the latter would be a dead entry.

    A multi-segment value such as ``'\\wbem\\WmiPrvSE.exe'`` still names a file —
    it just also pins a directory we cannot check. Those are kept and reduced to
    their basename, which is the Option A approximation applied consistently.

    Args:
        value: The raw Sigma field value.

    Returns:
        True when the value names a file, False when it describes a location.
    """
    text = value.strip()
    if not text or text.endswith("\\"):  # pure directory
        return False
    return ":" not in text               # drive-qualified -> a location


def _to_name_glob(value: str, modifier: str) -> str | None:
    """Convert one Sigma field value into a filename glob.

    Our form supplies process **names only**, so directory-anchored constraints
    cannot be evaluated and are dropped rather than approximated.

    Args:
        value: The Sigma field value (e.g. ``"\\winword.exe"``).
        modifier: The pipe modifier (``"endswith"``, ``"contains"``, ``""``...).

    Returns:
        A glob such as ``"*\\winword.exe"``, or ``None`` when the constraint is
        not expressible as a name match.
    """
    text = str(value or "").strip()
    if not text:
        return None

    if modifier in ("startswith", "re", "all"):
        # Directory prefixes and regexes are path-shaped, not name-shaped.
        return None
    # Sigma matching is case-insensitive, but rule authors write names however
    # they like (``\WINWORD.EXE``, ``\Cmd.Exe``). Lowercase here so equivalent
    # patterns dedupe into one entry and Layer 4 never has to think about case.
    if modifier in ("endswith", "contains"):
        if not _is_name_shaped(text):
            return None
        # A bare token with no separator is a substring match on the name itself
        # (e.g. ``ParentImage|contains: 'tomcat'``).
        if "\\" not in text:
            return (f"*{text}" if modifier == "endswith" else f"*{text}*").lower()
        basename = PureWindowsPath(text).name
        # A UNC-shaped value like ``\\host\share`` has no basename — not a name.
        return f"*\\{basename}".lower() if basename else None

    # No modifier — an exact value. Reduce a full path to its basename.
    basename = PureWindowsPath(text.replace("/", "\\")).name or text
    if not basename or basename.endswith(":"):
        return None
    return f"*\\{basename}".lower()


def _collect_field_globs(
    node: Any, fields: tuple[str, ...], out: list[str], dropped: list[str] | None = None
) -> None:
    """Recursively collect name globs for the given Sigma fields.

    Args:
        node: A detection block (dict, list, or scalar).
        fields: Field names to collect (e.g. ``("ParentImage",)``).
        out: Accumulator, mutated in place; order preserved, duplicates skipped.
        dropped: Optional accumulator recording values that could **not** be
            expressed as a name match — directory or regex constraints the
            source rule relies on but this layer cannot evaluate.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            if not isinstance(key, str):
                continue
            parts = key.split("|")
            if parts[0] in fields:
                modifier = parts[1].lower() if len(parts) > 1 else ""
                if "all" in [p.lower() for p in parts[1:]]:
                    modifier = "all"
                values = value if isinstance(value, list) else [value]
                for item in values:
                    glob = _to_name_glob(item, modifier)
                    if glob is None:
                        if dropped is not None:
                            dropped.append(f"{key}: {item}")
                    elif glob not in out:
                        out.append(glob)
            else:
                _collect_field_globs(value, fields, out, dropped)
    elif isinstance(node, list):
        for item in node:
            _collect_field_globs(item, fields, out, dropped)


def _has_commandline_condition(detection: dict) -> bool:
    """Return True if the rule also constrains CommandLine or ParentCommandLine."""
    return "CommandLine" in json.dumps(detection)


def _techniques(tags: Any) -> list[str]:
    """Extract MITRE technique IDs from a rule's tags.

    Args:
        tags: The rule's ``tags`` list (may be absent or malformed).

    Returns:
        Uppercased technique IDs such as ``["T1059.005", "T1218.005"]``.
    """
    found: list[str] = []
    for tag in tags or []:
        match = _TECHNIQUE_RE.match(str(tag).strip())
        if match:
            technique = match.group(1).upper()
            if technique not in found:
                found.append(technique)
    return found


def extract_pairs_from_rule(name: str, text: str) -> list[dict[str, Any]]:
    """Extract parent -> child pairing records from one Sigma rule.

    Args:
        name: Rule filename, kept for traceability.
        text: Raw YAML text of the rule.

    Returns:
        Zero or more pairing records. Empty when the rule is not a windows
        process_creation rule, is deprecated, or does not constrain both a
        parent and a child process name.
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
    if str(logsource.get("category") or "").lower() != "process_creation":
        return []

    detection = rule.get("detection") or {}
    if not isinstance(detection, dict):
        return []

    block_names = [k for k in detection if k != "condition"]
    skip = {b for b in block_names if _is_exclusion_block(b)}
    skip |= _negated_blocks(detection.get("condition"), block_names)

    parent_globs: list[str] = []
    child_globs: list[str] = []
    dropped: list[str] = []
    for block in block_names:
        if block in skip:
            continue
        _collect_field_globs(detection[block], _PARENT_FIELDS, parent_globs, dropped)
        _collect_field_globs(detection[block], _CHILD_FIELDS, child_globs, dropped)

    if not parent_globs or not child_globs:
        return []

    techniques = _techniques(rule.get("tags"))
    level = str(rule.get("level") or "medium").lower()
    records: list[dict[str, Any]] = []

    for parent in parent_globs:
        for child in child_globs:
            if len(records) >= _MAX_PAIRS_PER_RULE:
                logger.warning("%s: pair cap %d reached — truncated", name, _MAX_PAIRS_PER_RULE)
                return records
            records.append({
                "parent_pattern": parent,
                "child_pattern": child,
                "mitre_technique": techniques[0] if techniques else None,
                "mitre_techniques": techniques,
                "sigma_rule_id": rule.get("id"),
                "sigma_level": level,
                "sigma_status": str(rule.get("status") or "").lower() or None,
                "sigma_file": name.replace("\\", "/"),
                "title": rule.get("title") or name,
                "commandline_constrained": _has_commandline_condition(detection),
                "path_constrained": bool(dropped),
            })
    return records


# ── Assembly ─────────────────────────────────────────────────────────────────

_LEVEL_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def dedupe(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse duplicate pairings, keeping the most severe source rule.

    Several rules often describe the same pairing. Keeping one record per
    (parent, child) keeps the table small and gives Layer 4 an unambiguous
    severity; the winning rule's id remains available for lookup.

    Args:
        records: All extracted records.

    Returns:
        One record per (parent_pattern, child_pattern), sorted for stable diffs.
        Each carries ``duplicate_rule_count`` — how many rules described it.
    """
    best: dict[tuple[str, str], dict[str, Any]] = {}
    for record in records:
        key = (record["parent_pattern"], record["child_pattern"])
        current = best.get(key)
        if current is None:
            best[key] = {**record, "duplicate_rule_count": 1}
            continue
        current["duplicate_rule_count"] += 1
        # Prefer higher severity; at equal severity prefer the rule whose whole
        # condition survived extraction, since for that one the pairing check
        # reproduces the original rule exactly rather than approximating it.
        if _rank(record) > _rank(current):
            count = current["duplicate_rule_count"]
            best[key] = {**record, "duplicate_rule_count": count}

    return sorted(best.values(), key=lambda r: (r["parent_pattern"], r["child_pattern"]))


def _rank(record: dict[str, Any]) -> tuple[int, int]:
    """Rank a record: Sigma severity first, then how faithful the extraction was.

    Args:
        record: A pairing record.

    Returns:
        Sort key; higher is better.
    """
    level = _LEVEL_ORDER.get(record.get("sigma_level"), 2)
    faithful = 0 if (record.get("commandline_constrained")
                     or record.get("path_constrained")) else 1
    return (level, faithful)


def build_document(pairs: list[dict[str, Any]], source: str, rules_seen: int) -> dict[str, Any]:
    """Wrap the pairing list with provenance metadata.

    Args:
        pairs: Deduplicated pairing records.
        source: Where the rules came from (URL or directory).
        rules_seen: How many rule files were inspected.

    Returns:
        The full document to serialize to disk.
    """
    approximate = sum(1 for p in pairs if p["commandline_constrained"])
    path_bound = sum(1 for p in pairs if p["path_constrained"])
    exact = sum(1 for p in pairs
                if not p["commandline_constrained"] and not p["path_constrained"])
    return {
        "_meta": {
            "schema": "list of {parent_pattern, child_pattern, mitre_technique, "
                      "sigma_rule_id, sigma_level, title, commandline_constrained, "
                      "path_constrained}",
            "purpose": "Layer 4 suspicious parent-child blocklist for core.process_analyzer",
            "extraction_mode": "Option A — pairing only, CommandLine conditions dropped",
            "source": source,
            "project": "https://github.com/SigmaHQ/sigma",
            "license": "Detection Rule License (DRL) 1.1",
            "generated_by": "core/scripts/extract_sigma_pairs.py",
            "updated": date.today().isoformat(),
            "rules_inspected": rules_seen,
            "pair_count": len(pairs),
            "commandline_constrained_count": approximate,
            "path_constrained_count": path_bound,
            "fully_faithful_count": exact,
            "notes": [
                f"Only {exact} of {len(pairs)} pairs reproduce their source rule exactly. "
                f"{approximate} come from rules that ALSO required a CommandLine match and "
                f"{path_bound} from rules that ALSO pinned a directory; both conditions are "
                "dropped here, so those entries are broader than the original rule and will "
                "over-fire — treat such a match as a lead, not a finding.",
                "Patterns are filename globs; match a bare process name by prefixing a "
                "backslash, e.g. fnmatch('\\\\cmd.exe', '*\\\\cmd.exe').",
                "Exclusion blocks (filter*/known*/reduction*) and condition-negated blocks "
                "are dropped, so known-good pairings do not leak into the blocklist.",
                "startswith / regex constraints are path-shaped and cannot be evaluated "
                "against a name-only field, so they are skipped rather than approximated.",
            ],
        },
        "pairs": pairs,
    }


def main(argv: list[str] | None = None) -> int:
    """Entry point.

    Args:
        argv: Command-line arguments (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code — 0 on success, 1 on failure.
    """
    parser = argparse.ArgumentParser(description="Extract Sigma parent-child pairings.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--sigma-dir", type=Path, help="Path to a local SigmaHQ clone.")
    group.add_argument("--download", action="store_true", help="Fetch the SigmaHQ tarball.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Destination JSON.")
    parser.add_argument("--dry-run", action="store_true", help="Report counts, write nothing.")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    try:
        if args.download:
            rules = list(iter_downloaded_rules())
            source = SIGMA_TARBALL_URL
        else:
            rules = list(iter_local_rules(args.sigma_dir))
            source = str(args.sigma_dir)
    except RuntimeError as exc:
        logger.error("%s", exc)
        return 1

    raw: list[dict[str, Any]] = []
    for name, text in rules:
        raw.extend(extract_pairs_from_rule(name, text))

    pairs = dedupe(raw)
    logger.info(
        "%d rule files -> %d raw pairs -> %d unique pairings", len(rules), len(raw), len(pairs)
    )

    if args.dry_run:
        logger.info("dry run — nothing written")
        return 0

    document = build_document(pairs, source, len(rules))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    logger.info("wrote %s", args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
