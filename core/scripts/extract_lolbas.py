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
import sys
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path
from typing import Any

LOLBAS_API_URL = "https://lolbas-project.github.io/api/lolbas.json"
DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / "data" / "lolbas_binaries.json"
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
    logger.info("%d corpus entries -> %d binaries with abuse categories", len(corpus), len(table))

    if args.dry_run:
        logger.info("dry run — nothing written")
        return 0

    document = build_document(table, source)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    logger.info("wrote %s", args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
