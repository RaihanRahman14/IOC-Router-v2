"""Offline extractor: LOLBAS corpus -> core/data/lolbas_binaries.json.

Layer 2 of the process-analysis module needs a flat "is this binary documented
as abusable, and how" lookup. The LOLBAS project already publishes its whole
corpus as one JSON document, so no YAML parsing or repo clone is needed.

This is a **periodic offline step**, not a runtime dependency — the app only
ever reads the generated JSON. Re-run it quarterly, or whenever LOLBAS
publishes notable additions, and commit the regenerated file.

Usage::

    python core/scripts/extract_lolbas.py                 # fetch live, write data file
    python core/scripts/extract_lolbas.py --input raw.json  # reuse a saved copy
    python core/scripts/extract_lolbas.py --dry-run       # report only, write nothing

Source: https://github.com/LOLBAS-Project/LOLBAS (CC BY 4.0)
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path
from typing import Any

LOLBAS_API_URL = "https://lolbas-project.github.io/api/lolbas.json"
_PLACEHOLDER_RE = re.compile(r"\{[^{}]*\}")

DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / "data" / "lolbas_binaries.json"
DEFAULT_COMMANDS_OUTPUT = (
    Path(__file__).resolve().parents[1] / "data" / "lolbas_commands.json"
)
REQUEST_TIMEOUT = 30

logger = logging.getLogger("extract_lolbas")


def fetch_corpus(url: str = LOLBAS_API_URL, timeout: int = REQUEST_TIMEOUT) -> list[dict]:
    """Download the LOLBAS corpus.

    Args:
        url: LOLBAS API endpoint returning the full corpus as a JSON array.
        timeout: Socket timeout in seconds.

    Returns:
        The decoded corpus, one dict per binary.

    Raises:
        RuntimeError: If the request fails or the payload is not a JSON array.
    """
    logger.info("fetching %s", url)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 — fixed https URL
            payload = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"LOLBAS fetch failed: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"LOLBAS response was not valid JSON: {exc}") from exc

    if not isinstance(payload, list):
        raise RuntimeError(f"expected a JSON array, got {type(payload).__name__}")
    return payload


def load_corpus(path: Path) -> list[dict]:
    """Read a previously saved copy of the corpus.

    Args:
        path: File containing the raw LOLBAS JSON array.

    Returns:
        The decoded corpus.

    Raises:
        RuntimeError: If the file cannot be read or is not a JSON array.
    """
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"cannot read {path}: {exc}") from exc
    if not isinstance(payload, list):
        raise RuntimeError(f"expected a JSON array in {path}")
    return payload


def flatten(corpus: list[dict]) -> dict[str, dict[str, Any]]:
    """Reduce the corpus to one lookup record per binary.

    Each LOLBAS entry carries a list of documented abuse commands; we keep only
    the distinct abuse categories and MITRE technique IDs across them. The
    command strings themselves are deliberately dropped — confirming LOLBAS
    abuse requires command-line analysis, which is a separate module.

    Args:
        corpus: Raw LOLBAS entries.

    Returns:
        Mapping of lowercased binary filename to its lookup record, sorted by key.
    """
    table: dict[str, dict[str, Any]] = {}

    for entry in corpus:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("Name") or "").strip()
        if not name:
            continue

        categories: list[str] = []
        mitre: list[str] = []
        for command in entry.get("Commands") or []:
            if not isinstance(command, dict):
                continue
            category = str(command.get("Category") or "").strip()
            if category and category not in categories:
                categories.append(category)
            technique = str(command.get("MitreID") or "").strip().upper()
            if technique.startswith("T") and technique not in mitre:
                mitre.append(technique)

        if not categories:
            logger.debug("%s has no abuse categories — skipped", name)
            continue

        table[name.lower()] = {
            "binary": name,
            "description": str(entry.get("Description") or "").strip(),
            "categories": sorted(categories),
            "mitre": sorted(mitre),
            "url": str(entry.get("url") or "").strip(),
        }

    return dict(sorted(table.items()))


def _is_switch(token: str) -> bool:
    """Report whether a token is switch-shaped (``-urlcache``, ``/transfer``)."""
    return len(token) >= 3 and token[0] in "-/" and any(c.isalpha() for c in token)


def _is_informative(token: str, binary_stem: str) -> bool:
    """Report whether a skeleton token can discriminate an abuse invocation.

    The same rule that the Sigma work arrived at twice: a token matching
    essentially anything is worse than no token, because it lends false
    specificity to a match. Dropped here are the binary's own name (already
    covered by the plain LOLBAS lookup), bare numbers and job ids, punctuation
    fragments left behind by inline script payloads (``)"))``, ``,entrypoint``),
    and stub words too short to mean anything.

    Args:
        token: A candidate skeleton token, already lowercased.
        binary_stem: The binary's name without extension, lowercased.

    Returns:
        True when the token carries discriminating information.
    """
    if not any(c.isalpha() for c in token):
        return False
    stripped = token.strip("-/").strip()
    if not stripped or stripped == binary_stem:
        return False
    if _is_switch(token):
        return True
    # A non-switch literal has to be a real word to count — "null", "1" and
    # stray syntax do not describe an abuse pattern.
    return len(stripped) >= 4 and stripped.isalnum()


def skeleton_tokens(command: str, binary: str = "") -> list[str]:
    """Reduce a documented abuse command to its invariant literal tokens.

    LOLBAS marks every variable part of a command with an explicit placeholder —
    ``{REMOTEURL:.exe}``, ``{PATH_ABSOLUTE}``, ``{PAYLOAD}``. Removing those
    leaves precisely the tokens an operator cannot change while still performing
    the documented abuse, so this is a derivation rather than a heuristic guess:

        ``certutil.exe -urlcache -f {REMOTEURL:.exe} {PATH:.exe}`` -> ``-urlcache -f``

    The binary name itself is dropped — matching that is what the plain LOLBAS
    lookup already does, and including it would let the skeleton "match" on
    nothing but the binary.

    Args:
        command: A documented abuse command string.
        binary: The binary this command belongs to, so its own name can be
            excluded — matching that is the plain LOLBAS lookup's job.

    Returns:
        Lowercased informative tokens, in order, duplicates removed. Empty when
        nothing discriminating survives, which is the signal to drop the command
        rather than ship a skeleton that matches everything.
    """
    stem = str(binary or "").rsplit(".", 1)[0].strip().lower()
    text = _PLACEHOLDER_RE.sub(" ", str(command or ""))
    tokens: list[str] = []
    for raw in text.split():
        token = raw.strip().strip('"').strip("'").strip(",").lower()
        if not token:
            continue
        # Paths and URLs vary per environment; the placeholders already cover
        # the variable parts, so anything still path-shaped is noise.
        if "\\" in token or "://" in token:
            continue
        if token.endswith((".exe", ".dll", ".com")):
            continue
        # A switch that carries an inline value keeps only the switch: LOLBAS
        # writes `/node:"192.168.0.1` as a worked example, and the address is
        # environment-specific, so retaining it would make the skeleton
        # unmatchable rather than specific.
        if _is_switch(token) and ":" in token:
            token = token.split(":", 1)[0] + ":"
        if not _is_informative(token, stem):
            continue
        if token not in tokens:
            tokens.append(token)
    return tokens


def flatten_commands(corpus: list[dict]) -> dict[str, list[dict[str, Any]]]:
    """Extract documented abuse commands and their skeletons, per binary.

    Kept in a **separate file** from :func:`flatten` so the shipped Layer 2
    lookup table and its module are untouched by this addition — the process
    module carries no regression risk from Layer 4 landing.

    Args:
        corpus: Raw LOLBAS entries.

    Returns:
        Mapping of lowercased binary filename to its abuse command records.
        Binaries whose commands all reduce to an empty skeleton are omitted:
        with no invariant token there is nothing to confirm, and claiming a
        match on the binary name alone is what the Layer 2 lookup already says.
    """
    table: dict[str, list[dict[str, Any]]] = {}

    for entry in corpus:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("Name") or "").strip()
        if not name:
            continue

        records: list[dict[str, Any]] = []
        seen: set[tuple[str, ...]] = set()
        for command in entry.get("Commands") or []:
            if not isinstance(command, dict):
                continue
            skeleton = skeleton_tokens(command.get("Command"), name)
            # A single non-switch word is not an abuse pattern. Require either a
            # switch, or two independent literals, before the skeleton is
            # allowed to claim a confirmed match.
            if not skeleton or tuple(skeleton) in seen:
                continue
            if len(skeleton) < 2 and not any(_is_switch(t) for t in skeleton):
                continue
            seen.add(tuple(skeleton))
            technique = str(command.get("MitreID") or "").strip().upper()
            records.append({
                "command": str(command.get("Command") or "").strip(),
                "skeleton": skeleton,
                "category": str(command.get("Category") or "").strip(),
                "usecase": str(command.get("Usecase") or "").strip(),
                "description": str(command.get("Description") or "").strip(),
                "mitre": technique if technique.startswith("T") else None,
            })

        if records:
            table[name.lower()] = records

    return dict(sorted(table.items()))


def build_commands_document(table: dict[str, list[dict[str, Any]]], source: str) -> dict[str, Any]:
    """Wrap the abuse-command table with provenance metadata.

    Args:
        table: Output of :func:`flatten_commands`.
        source: Where the corpus came from (URL or file path).

    Returns:
        The full document to serialize to disk.
    """
    total = sum(len(v) for v in table.values())
    return {
        "_meta": {
            "schema": "lowercased binary filename -> [{command, skeleton, category, "
                      "usecase, description, mitre}]",
            "purpose": "Layer 4 argument-pattern confirmation for core.cmdline_analyzer",
            "source": source,
            "project": "https://github.com/LOLBAS-Project/LOLBAS",
            "license": "CC BY 4.0",
            "generated_by": "core/scripts/extract_lolbas.py",
            "updated": date.today().isoformat(),
            "binary_count": len(table),
            "command_count": total,
            "notes": [
                "`skeleton` is the command with every LOLBAS placeholder ({REMOTEURL}, "
                "{PATH}, ...) and every path/URL-shaped token removed, leaving the tokens "
                "an operator cannot change while still performing the documented abuse.",
                "Commands whose skeleton is empty are dropped: with no invariant token "
                "there is nothing to confirm, and a match on the binary name alone is "
                "already what core/data/lolbas_binaries.json reports.",
                "Separate from lolbas_binaries.json on purpose — the Layer 2 lookup and "
                "the process module are unaffected by this file.",
            ],
        },
        "commands": table,
    }


def build_document(table: dict[str, dict[str, Any]], source: str) -> dict[str, Any]:
    """Wrap the lookup table with provenance metadata.

    Args:
        table: Flattened lookup table from :func:`flatten`.
        source: Where the corpus came from (URL or file path).

    Returns:
        The full document to serialize to disk.
    """
    return {
        "_meta": {
            "schema": "lowercased binary filename -> {binary, description, categories, mitre, url}",
            "purpose": "Layer 2 dual-use binary lookup for core.lolbas_lookup",
            "source": source,
            "project": "https://github.com/LOLBAS-Project/LOLBAS",
            "license": "CC BY 4.0",
            "generated_by": "core/scripts/extract_lolbas.py",
            "updated": date.today().isoformat(),
            "entry_count": len(table),
            "notes": [
                "Command strings are intentionally dropped — a LOLBAS match alone is not "
                "malicious, it only means the command line deserves review.",
                "Categories and MITRE IDs are the distinct union across every documented "
                "abuse command for that binary.",
            ],
        },
        "binaries": table,
    }


def main(argv: list[str] | None = None) -> int:
    """Entry point.

    Args:
        argv: Command-line arguments (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code — 0 on success, 1 on failure.
    """
    parser = argparse.ArgumentParser(description="Extract the LOLBAS lookup table.")
    parser.add_argument("--input", type=Path, help="Read raw corpus from a file instead of HTTP.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Destination JSON.")
    parser.add_argument("--url", default=LOLBAS_API_URL, help="LOLBAS API endpoint.")
    parser.add_argument("--dry-run", action="store_true", help="Report counts, write nothing.")
    parser.add_argument(
        "--commands-output", type=Path, default=DEFAULT_COMMANDS_OUTPUT,
        help="Destination for the Layer 4 abuse-command table.",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    try:
        if args.input:
            corpus = load_corpus(args.input)
            source = str(args.input)
        else:
            corpus = fetch_corpus(args.url)
            source = args.url
    except RuntimeError as exc:
        logger.error("%s", exc)
        return 1

    table = flatten(corpus)
    commands = flatten_commands(corpus)
    logger.info("%d corpus entries -> %d binaries with abuse categories", len(corpus), len(table))
    logger.info(
        "%d binaries carry %d distinct abuse-command skeletons",
        len(commands), sum(len(v) for v in commands.values()),
    )

    if args.dry_run:
        logger.info("dry run — nothing written")
        return 0

    document = build_document(table, source)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    logger.info("wrote %s", args.output)

    commands_document = build_commands_document(commands, source)
    args.commands_output.write_text(
        json.dumps(commands_document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    logger.info("wrote %s", args.commands_output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
