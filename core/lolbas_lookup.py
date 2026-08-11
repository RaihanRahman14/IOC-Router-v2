"""LOLBAS dual-use binary lookup — Layer 2 of the process-analysis module.

Answers one question: *is this Windows binary documented as abusable, and in
what way?* A match is *not* a maliciousness signal — LOLBAS binaries are
extremely common in benign activity. It means the binary's **command line**
deserves review, which is a separate module's job.

Dataset: ``core/data/lolbas_binaries.json``, regenerated offline by
``core/scripts/extract_lolbas.py``. This module performs no network I/O.

This module must not import :mod:`core.process_analyzer` — the dependency runs
the other way, since aggregation there calls into this lookup.
"""
from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path, PureWindowsPath
from typing import Any

logger = logging.getLogger(__name__)

_DATA_FILE = Path(__file__).parent / "data" / "lolbas_binaries.json"
# Layer 4's dataset, deliberately separate from the Layer 2 table above so this
# module's existing consumers are untouched by the argument-matching addition.
_COMMANDS_FILE = Path(__file__).parent / "data" / "lolbas_commands.json"

DUAL_USE_BINARY = "DUAL_USE_BINARY"


@lru_cache(maxsize=1)
def load_lolbas_table() -> dict[str, dict[str, Any]]:
    """Load the extracted LOLBAS lookup table.

    Cached for the process lifetime.

    Returns:
        Mapping of lowercased binary filename to its record
        (``binary``, ``description``, ``categories``, ``mitre``, ``url``).
        Empty dict if the data file is missing or malformed, which degrades
        Layer 2 to "no matches" rather than raising.
    """
    try:
        raw = json.loads(_DATA_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("lolbas_binaries.json unreadable (%s) — Layer 2 disabled", exc)
        return {}

    binaries = raw.get("binaries")
    if not isinstance(binaries, dict):
        logger.error("lolbas_binaries.json has no 'binaries' object — Layer 2 disabled")
        return {}

    return {str(k).strip().lower(): v for k, v in binaries.items() if isinstance(v, dict)}


def lookup(process_name: str) -> dict[str, Any] | None:
    """Look up one process against the LOLBAS dataset.

    Args:
        process_name: A bare process name (``certutil.exe``) or a full path —
            only the filename is used, matched case-insensitively.

    Returns:
        The LOLBAS record for the binary, or ``None`` when the name is empty or
        not documented as abusable. A ``None`` result is not evidence of
        benignity; LOLBAS only covers Windows-native binaries.
    """
    value = str(process_name or "").strip().strip('"').strip("'").replace("/", "\\")
    if not value:
        return None

    filename = PureWindowsPath(value).name.lower()
    if not filename:
        return None

    return load_lolbas_table().get(filename)


@lru_cache(maxsize=1)
def load_lolbas_commands() -> dict[str, list[dict[str, Any]]]:
    """Load the Layer 4 documented-abuse-command table.

    Cached for the process lifetime.

    Returns:
        Mapping of lowercased binary name to its abuse command records, or an
        empty mapping if the data file is missing or malformed — which degrades
        Layer 4 to "no confirmations" rather than raising.
    """
    try:
        raw = json.loads(_COMMANDS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("lolbas_commands.json unreadable (%s) — Layer 4 disabled", exc)
        return {}

    commands = raw.get("commands")
    if not isinstance(commands, dict):
        logger.error("lolbas_commands.json has no 'commands' mapping — Layer 4 disabled")
        return {}

    return {
        str(k).lower(): [r for r in v if isinstance(r, dict) and r.get("skeleton")]
        for k, v in commands.items()
        if isinstance(v, list)
    }


def lookup_commands(process_name: str) -> list[dict[str, Any]]:
    """Return the documented abuse commands for a binary.

    The name-only sibling of :func:`lookup`. Where that answers "is this binary
    dual-use", this supplies what an actual abuse invocation looks like, so the
    command line can be checked against it.

    Args:
        process_name: A binary name or full path.

    Returns:
        Abuse command records, or an empty list when the binary is absent from
        the dataset or documents no discriminating argument pattern.
    """
    if not process_name:
        return []
    name = PureWindowsPath(str(process_name).strip().strip('"')).name.lower()
    return load_lolbas_commands().get(name, [])


def abuse_summary(record: dict[str, Any] | None) -> str:
    """Render a LOLBAS record as one analyst-facing line.

    Args:
        record: A record from :func:`lookup`, or ``None``.

    Returns:
        A string such as
        ``"certutil.exe matched LOLBAS categories: ADS, Download (T1105)"``,
        or an empty string when ``record`` is ``None``.
    """
    if not record:
        return ""

    binary = record.get("binary") or "binary"
    categories = ", ".join(record.get("categories") or []) or "uncategorized"
    techniques = ", ".join(record.get("mitre") or [])
    line = f"{binary} matched LOLBAS categories: {categories}"
    if techniques:
        line += f" ({techniques})"
    return line


def mitre_techniques(record: dict[str, Any] | None) -> list[str]:
    """Extract the MITRE technique IDs from a LOLBAS record.

    Args:
        record: A record from :func:`lookup`, or ``None``.

    Returns:
        Technique IDs (e.g. ``["T1105", "T1218.005"]``), empty when unavailable.
    """
    if not record:
        return []
    return [str(t) for t in (record.get("mitre") or [])]
