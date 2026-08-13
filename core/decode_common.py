"""Interpreter-agnostic decode primitives. Pure transforms, never execution.

Implements ``docs/waf_payload_analyzer.md`` D2. Extracted from
:mod:`core.cmdline_deobfuscator`, which was the first consumer and remains the
owner of everything PowerShell-specific — backticks, ``[char]`` codes, the ``-f``
format operator, and the ``-EncodedCommand`` flag family all stay there. What
lives here is what a Windows command line and an HTTP request payload genuinely
share: percent-encoding, numeric HTML entities, ``\\uXXXX``/``\\xNN`` escapes,
base64, and the fixed-point iteration that folds layered combinations of them.

**The two consumers are calibrated differently, and that is the point.** A
command line and a web payload disagree on what counts as evidence of encoding:

* ``%SystemRoot%`` is not percent-encoding, so the command-line module requires
  two or more valid sequences before it believes one. A WAF payload routinely
  carries exactly one — ``%27`` for a quote, ``..%2f`` for traversal — so the
  same threshold would blind it.
* ``-EncodedCommand`` payloads are UTF-16LE, so the command-line module tries
  that encoding first. Web payloads are UTF-8.
* An opportunistic base64 run in a command line must also *look* like a command
  before it is believed. A base64 blob in a query parameter has no such shape.

Every one of those is a field on :class:`DecodeProfile` rather than a constant,
so neither consumer inherits the other's assumptions. No profile is exported for
the WAF module yet: its values are a calibration question, and guessing them
here is exactly what the plan's §7 warns against.

Decoding is iterative to a fixed point under two hard caps, so that a layered or
self-expanding payload cannot hang a Streamlit rerun. Every applied transform is
recorded: a decoded string an analyst cannot trace back to its source is worse
than no decode at all.
"""
from __future__ import annotations

import base64
import binascii
import functools
import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable

logger = logging.getLogger(__name__)

# A transform takes the current working text and reports the rewritten text plus
# whether it changed anything. Returning ``changed`` rather than comparing
# strings lets a transform that legitimately rewrites text to itself say so.
Transform = Callable[[str], "tuple[str, bool]"]

# Share of characters that must be printable for a decode to be believed.
_PRINTABLE_RATIO = 0.90

# Markers that distinguish a decoded *command* from a lucky-looking accident.
_COMMAND_MARKERS = (" ", ".", "\\", "/", ":", "(", "-")
_MIN_COMMAND_MARKERS = 2

_B64_CHARS_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_PERCENT_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_HTML_ENTITY_RE = re.compile(r"&#(?:x([0-9A-Fa-f]+)|(\d+));")
_UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9A-Fa-f]{4})")
_HEX_ESCAPE_RE = re.compile(r"\\x([0-9A-Fa-f]{2})")

# Chain labels. Shared so that a decode chain reads the same whichever module
# produced it, and so a consumer asserting on them is asserting on one source.
LABEL_PERCENT = "percent-encoding"
LABEL_HTML_ENTITIES = "HTML numeric entities"
LABEL_ESCAPES = "unicode/hex escapes"
LABEL_BASE64 = "base64 payload"


@dataclass(frozen=True)
class DecodeProfile:
    """Per-consumer calibration for the shared transforms.

    Attributes:
        min_encoding_hits: Valid sequences an encoding needs before it is
            believed. One ``%20`` in a URL is not percent-obfuscation; several
            in a row is. Web payloads legitimately use 1.
        min_b64_inline: Shortest run treated as an opportunistic base64 payload.
            Below this, ordinary words are valid base64 and decode to
            convincing-looking noise.
        b64_require_command_shape: Require a decoded blob to look like a command,
            not merely be printable. Correct for command lines, wrong for the
            web, where a decoded payload has no command shape to find.
        b64_utf16_first: Try UTF-16LE ahead of UTF-8 when the byte pattern
            suggests it. PowerShell's encoding; not the web's.
        max_rounds: Iteration cap. A layered payload legitimately needs a
            handful of passes; beyond that it is a decode bomb or a fixed-point
            bug.
        max_bytes: Output cap. Exceeding it truncates and stops the run.
    """

    min_encoding_hits: int = 2
    min_b64_inline: int = 24
    b64_require_command_shape: bool = True
    b64_utf16_first: bool = True
    max_rounds: int = 5
    max_bytes: int = 1_000_000


@dataclass
class DecodeRun:
    """Outcome of driving a transform list to a fixed point.

    Attributes:
        text: The folded text. Equals the input when nothing fired.
        chain: Applied transforms in order — the provenance a caller needs
            before it can present ``text`` as fact.
        rounds: Iterations that changed something.
        truncated: True if ``max_bytes`` clipped the output.
    """

    text: str
    chain: list[str] = field(default_factory=list)
    rounds: int = 0
    truncated: bool = False


@functools.lru_cache(maxsize=8)
def _b64_run_re(min_len: int) -> re.Pattern[str]:
    """Compile (and cache) the opportunistic base64 run pattern for a length."""
    return re.compile(r"[A-Za-z0-9+/]{%d,}={0,2}" % min_len)


def looks_like_text(decoded: str) -> bool:
    """Report whether decoded bytes plausibly represent human-readable text.

    Args:
        decoded: Candidate decoded string.

    Returns:
        True when the printable share clears the believability ratio.
    """
    if not decoded:
        return False
    printable = sum(1 for c in decoded if c.isprintable() or c in "\r\n\t")
    return printable / len(decoded) >= _PRINTABLE_RATIO


def b64_decode_text(
    blob: str,
    *,
    require_command_shape: bool,
    utf16_first: bool,
) -> str | None:
    """Decode a base64 blob to text, or return None if it is not text.

    PowerShell's ``-EncodedCommand`` payloads are UTF-16LE; decoding those as
    UTF-8 yields NUL-interleaved output that silently fails every downstream
    keyword and rule match, so UTF-16LE is tried first whenever the byte pattern
    suggests it *and* the caller's profile asks for it. Web payloads set
    ``utf16_first=False`` and get UTF-8 first.

    Args:
        blob: Candidate base64 string.
        require_command_shape: When True, the result must also look like a
            command rather than merely being printable.
        utf16_first: Allow the UTF-16LE-first ordering when NUL bytes and an
            even length suggest it.

    Returns:
        Decoded text, or None if the blob is not valid base64 or not text.
    """
    candidate = blob.strip()
    if not _B64_CHARS_RE.match(candidate):
        return None

    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not raw:
        return None

    utf16_shaped = utf16_first and b"\x00" in raw and len(raw) % 2 == 0
    orders = ["utf-16-le", "utf-8"] if utf16_shaped else ["utf-8", "utf-16-le"]
    for encoding in orders:
        try:
            decoded = raw.decode(encoding)
        except (UnicodeDecodeError, ValueError):
            continue
        if not looks_like_text(decoded):
            continue
        if require_command_shape:
            hits = sum(1 for marker in _COMMAND_MARKERS if marker in decoded)
            if hits < _MIN_COMMAND_MARKERS:
                continue
        return decoded

    return None


def decode_base64_inline(text: str, profile: DecodeProfile) -> tuple[str, bool]:
    """Decode base64-looking runs in place, keeping surrounding text intact.

    This is the opportunistic tier only — a long base64-shaped run anywhere in
    the text, which is a guess and therefore gated on ``min_b64_inline`` and
    optionally on command shape. A blob that is a payload *by declaration*
    (PowerShell's ``-enc`` argument) is the calling module's business, not this
    one's.

    Args:
        text: Current working text.
        profile: Calibration for the consuming module.

    Returns:
        Tuple of (text, changed).
    """
    changed = False

    def _replace(match: re.Match[str]) -> str:
        nonlocal changed
        blob = match.group(0)
        decoded = b64_decode_text(
            blob,
            require_command_shape=profile.b64_require_command_shape,
            utf16_first=profile.b64_utf16_first,
        )
        if decoded is None:
            return blob
        changed = True
        return decoded

    return _b64_run_re(profile.min_b64_inline).sub(_replace, text), changed


def decode_percent(text: str, profile: DecodeProfile) -> tuple[str, bool]:
    """Percent-decode, once the encoding is used more than incidentally.

    ``%SystemRoot%`` is not percent-encoding and a single ``%20`` in a URL is not
    obfuscation; ``min_encoding_hits`` is what keeps both out for a consumer that
    needs it kept out.

    Args:
        text: Current working text.
        profile: Calibration for the consuming module.

    Returns:
        Tuple of (text, changed).
    """
    if len(_PERCENT_RE.findall(text)) < profile.min_encoding_hits:
        return text, False
    decoded = urllib.parse.unquote(text)
    return decoded, decoded != text


def decode_html_entities(text: str, profile: DecodeProfile) -> tuple[str, bool]:
    """Decode numeric HTML entities only.

    Named entities are excluded on purpose: ``html.unescape`` would turn the
    ``&copy`` in ``dir&copy a b`` into a copyright sign.

    Args:
        text: Current working text.
        profile: Calibration for the consuming module.

    Returns:
        Tuple of (text, changed).
    """
    if len(_HTML_ENTITY_RE.findall(text)) < profile.min_encoding_hits:
        return text, False

    def _replace(match: re.Match[str]) -> str:
        raw_hex, raw_dec = match.group(1), match.group(2)
        try:
            return chr(int(raw_hex, 16) if raw_hex else int(raw_dec))
        except (ValueError, OverflowError):
            return match.group(0)

    decoded = _HTML_ENTITY_RE.sub(_replace, text)
    return decoded, decoded != text


def decode_escapes(text: str, profile: DecodeProfile) -> tuple[str, bool]:
    """Decode ``\\uXXXX`` and ``\\xNN`` escape sequences.

    Args:
        text: Current working text.
        profile: Calibration for the consuming module.

    Returns:
        Tuple of (text, changed).
    """
    decoded = text
    for pattern in (_UNICODE_ESCAPE_RE, _HEX_ESCAPE_RE):
        if len(pattern.findall(decoded)) < profile.min_encoding_hits:
            continue
        decoded = pattern.sub(lambda m: chr(int(m.group(1), 16)), decoded)
    return decoded, decoded != text


def run_pipeline(
    text: str,
    transforms: tuple[tuple[str, Transform], ...],
    profile: DecodeProfile,
) -> DecodeRun:
    """Apply transforms repeatedly until the text stops changing.

    A transform that raises is logged and skipped rather than sinking the run:
    one malformed construct in a long payload should cost that construct, not
    every other layer's decode.

    Args:
        text: Input text, never modified in place.
        transforms: (label, transform) pairs, applied in order within a round.
        profile: Supplies the round and byte caps.

    Returns:
        A :class:`DecodeRun`. ``chain`` is empty when nothing fired, which is how
        a caller distinguishes "already plain" from "decoded to something that
        happens to equal the input".
    """
    run = DecodeRun(text=text)
    working = text

    for round_index in range(profile.max_rounds):
        round_changed = False
        for label, transform in transforms:
            try:
                working, changed = transform(working)
            except (re.error, ValueError, OverflowError, MemoryError) as exc:
                logger.warning("decode step %r failed: %s", label, exc)
                continue
            if changed:
                round_changed = True
                run.chain.append(label)

        if len(working) > profile.max_bytes:
            working = working[: profile.max_bytes]
            run.truncated = True
            run.rounds = round_index + 1
            break

        if not round_changed:
            break
        run.rounds = round_index + 1

    run.text = working
    return run
