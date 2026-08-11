"""Command-line deobfuscation — Layer 2. Pure transforms, never execution.

Implements ``docs/cmdline_analyzer_plan.md`` D2. The briefing proposed
**PowerDecode** for the string-obfuscation cases; that tool recovers each stage
by *running* the sample, which is why its own documentation calls for an
isolated VM. Doing that here would execute attacker-supplied PowerShell on the
analyst's workstation the moment they paste into a triage form. Every transform
in this module is instead a pure string rewrite — no ``eval``, no subprocess, no
interpreter of any kind.

Coverage, all foldable without execution:

* base64 payloads (``-enc`` family and ``FromBase64String`` literals), decoded
  **UTF-16LE first** — PowerShell's encoding — falling back to UTF-8;
* quoted-string concatenation, ``('c'+'a'+'l'+'c')``;
* ``[char]`` codes and ``[char[]](…) -join ''`` arrays;
* the format operator, ``('{1}{0}' -f 'x','ie')``;
* intra-word backticks, ``i`e`x``;
* percent-encoding, numeric HTML entities, ``\\uXXXX`` and ``\\xNN`` escapes.

Deliberately **not** covered: anything needing variable state, such as
``$env:ComSpec[4,15]-join''``. Resolving that means modelling a variable store,
which is the first step toward writing an interpreter.

Decoding is iterative to a fixed point under two hard caps
(:data:`MAX_DECODE_ROUNDS`, :data:`MAX_DECODED_BYTES`) so that a layered or
self-expanding payload cannot hang a Streamlit rerun. Every applied transform is
recorded in ``decode_chain``: a decoded string an analyst cannot trace back to
its source is worse than no decode at all.
"""
from __future__ import annotations

import base64
import binascii
import logging
import re
import urllib.parse
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Iteration guards. A layered payload legitimately needs a handful of passes;
# anything beyond that is a decode bomb or a fixed-point bug.
MAX_DECODE_ROUNDS = 5
MAX_DECODED_BYTES = 1_000_000

# Shortest run treated as a base64 payload. Below this, ordinary words are valid
# base64 and decode to convincing-looking noise.
MIN_B64_FLAG_ARG = 20
MIN_B64_INLINE = 24

# Share of characters that must be printable for a decode to be believed.
_PRINTABLE_RATIO = 0.90

# Markers that distinguish a decoded *command* from a lucky-looking accident.
_COMMAND_MARKERS = (" ", ".", "\\", "/", ":", "(", "-")
_MIN_COMMAND_MARKERS = 2

# How many occurrences an encoding needs before it is believed. One "%20" in a
# URL is not percent-obfuscation; eight in a row is.
_MIN_ENCODING_HITS = 2

# PowerShell's -EncodedCommand and its accepted abbreviations.
_ENC_FLAG_RE = re.compile(
    r"(?:(?<=\s)|^)-(?:e|en|enc|ec|encoded|encodedcommand|encodedarguments)\s+([^\s\"']+)",
    re.IGNORECASE,
)
_B64_RUN_RE = re.compile(r"[A-Za-z0-9+/]{%d,}={0,2}" % MIN_B64_INLINE)
_B64_CHARS_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")

_BACKTICK_IN_WORD_RE = re.compile(r"(?<=\w)`(?=\w)")
_CHAR_CODE_RE = re.compile(r"\[char\]\s*(\d{1,7})", re.IGNORECASE)
_CHAR_ARRAY_RE = re.compile(r"\[char\[\]\]\s*\(\s*([0-9][0-9,\s]*)\)", re.IGNORECASE)
_JOIN_EMPTY_RE = re.compile(r"\s*-join\s*(['\"])\1", re.IGNORECASE)
_CONCAT_RE = re.compile(r"(['\"])([^'\"]*)\1\s*\+\s*(['\"])([^'\"]*)\3")
_FORMAT_OP_RE = re.compile(
    r"\(\s*(['\"])([^'\"]*)\1\s*-f\s*((?:['\"][^'\"]*['\"]\s*,\s*)*['\"][^'\"]*['\"])\s*\)",
    re.IGNORECASE,
)
_FORMAT_ARG_RE = re.compile(r"['\"]([^'\"]*)['\"]")
_FORMAT_SLOT_RE = re.compile(r"\{(\d+)\}")

_PERCENT_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_HTML_ENTITY_RE = re.compile(r"&#(?:x([0-9A-Fa-f]+)|(\d+));")
_UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9A-Fa-f]{4})")
_HEX_ESCAPE_RE = re.compile(r"\\x([0-9A-Fa-f]{2})")


@dataclass
class DeobfuscationResult:
    """Outcome of running the decode pipeline over one command line.

    Attributes:
        original: The input, always preserved unmodified.
        decoded_command: Fully folded text, or None when nothing fired.
        was_obfuscated: True if any transform applied.
        decode_chain: Applied transforms in order — the provenance an analyst
            needs to trust ``decoded_command``.
        rounds: Iterations run before reaching a fixed point.
        truncated: True if :data:`MAX_DECODED_BYTES` clipped the output.
    """

    original: str
    decoded_command: str | None = None
    was_obfuscated: bool = False
    decode_chain: list[str] = field(default_factory=list)
    rounds: int = 0
    truncated: bool = False


def _looks_like_text(decoded: str) -> bool:
    """Report whether decoded bytes plausibly represent human-readable text."""
    if not decoded:
        return False
    printable = sum(1 for c in decoded if c.isprintable() or c in "\r\n\t")
    return printable / len(decoded) >= _PRINTABLE_RATIO


def _b64_decode_text(blob: str, *, require_command_shape: bool) -> str | None:
    """Decode a base64 blob to text, or return None if it is not text.

    PowerShell's ``-EncodedCommand`` payloads are UTF-16LE; decoding those as
    UTF-8 yields NUL-interleaved output that silently fails every downstream
    keyword and Sigma match, so UTF-16LE is tried first whenever the byte
    pattern suggests it.

    Args:
        blob: Candidate base64 string.
        require_command_shape: When True (opportunistic inline scan), the result
            must also look like a command rather than merely being printable.

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

    utf16_first = b"\x00" in raw and len(raw) % 2 == 0
    orders = ["utf-16-le", "utf-8"] if utf16_first else ["utf-8", "utf-16-le"]
    for encoding in orders:
        try:
            decoded = raw.decode(encoding)
        except (UnicodeDecodeError, ValueError):
            continue
        if not _looks_like_text(decoded):
            continue
        if require_command_shape:
            hits = sum(1 for marker in _COMMAND_MARKERS if marker in decoded)
            if hits < _MIN_COMMAND_MARKERS:
                continue
        return decoded

    return None


def _decode_base64(text: str) -> tuple[str, bool]:
    """Decode base64 payloads in place, keeping the surrounding command intact.

    Two tiers, because confidence differs: an argument to an ``-enc``-family
    flag is a payload by declaration, while a long base64-looking run anywhere
    else is only a guess and has to clear a higher bar.

    Args:
        text: Current working text.

    Returns:
        Tuple of (text, changed).
    """
    changed = False

    def _replace_flag(match: re.Match[str]) -> str:
        nonlocal changed
        blob = match.group(1)
        if len(blob) < MIN_B64_FLAG_ARG:
            return match.group(0)
        decoded = _b64_decode_text(blob, require_command_shape=False)
        if decoded is None:
            return match.group(0)
        changed = True
        return match.group(0).replace(blob, decoded)

    text = _ENC_FLAG_RE.sub(_replace_flag, text)
    if changed:
        return text, True

    def _replace_inline(match: re.Match[str]) -> str:
        nonlocal changed
        blob = match.group(0)
        decoded = _b64_decode_text(blob, require_command_shape=True)
        if decoded is None:
            return blob
        changed = True
        return decoded

    return _B64_RUN_RE.sub(_replace_inline, text), changed


def _fold_backticks(text: str) -> tuple[str, bool]:
    """Remove backticks used to split a word, e.g. ``i`e`x`` -> ``iex``.

    Only backticks *between* two word characters are removed. A trailing
    backtick is PowerShell's line continuation, which is ordinary formatting
    rather than evasion, and folding it would raise a false obfuscation signal.
    """
    folded = _BACKTICK_IN_WORD_RE.sub("", text)
    return folded, folded != text


def _fold_char_arrays(text: str) -> tuple[str, bool]:
    """Fold ``[char[]](99,97,108,99)`` into a quoted literal."""

    def _replace(match: re.Match[str]) -> str:
        codes = [c.strip() for c in match.group(1).split(",") if c.strip()]
        try:
            chars = [chr(int(c)) for c in codes]
        except (ValueError, OverflowError):
            return match.group(0)
        return "'" + "".join(chars) + "'"

    folded = _CHAR_ARRAY_RE.sub(_replace, text)
    folded = _JOIN_EMPTY_RE.sub("", folded)
    return folded, folded != text


def _fold_char_codes(text: str) -> tuple[str, bool]:
    """Fold ``[char]99`` into ``'c'`` so concatenation folding can take over."""

    def _replace(match: re.Match[str]) -> str:
        try:
            return "'" + chr(int(match.group(1))) + "'"
        except (ValueError, OverflowError):
            return match.group(0)

    folded = _CHAR_CODE_RE.sub(_replace, text)
    return folded, folded != text


def _fold_concatenation(text: str) -> tuple[str, bool]:
    """Fold adjacent quoted literals joined by ``+`` into one literal."""
    def _join(match: re.Match[str]) -> str:
        quote = match.group(1)
        return f"{quote}{match.group(2)}{match.group(4)}{quote}"

    folded = text
    for _ in range(MAX_DECODE_ROUNDS * 10):
        next_text, count = _CONCAT_RE.subn(_join, folded)
        if not count:
            break
        folded = next_text
    return folded, folded != text


def _fold_format_operator(text: str) -> tuple[str, bool]:
    """Apply PowerShell's ``-f`` format operator to constant arguments."""

    def _replace(match: re.Match[str]) -> str:
        template = match.group(2)
        args = _FORMAT_ARG_RE.findall(match.group(3))

        def _slot(slot: re.Match[str]) -> str:
            index = int(slot.group(1))
            if index >= len(args):
                raise IndexError(index)
            return args[index]

        try:
            return "'" + _FORMAT_SLOT_RE.sub(_slot, template) + "'"
        except IndexError:
            # An out-of-range slot means we misread the construct. Leaving it
            # untouched is right: a wrong fold would be reported as fact.
            return match.group(0)

    folded = _FORMAT_OP_RE.sub(_replace, text)
    return folded, folded != text


def _decode_percent(text: str) -> tuple[str, bool]:
    """Percent-decode, but only when the encoding is used more than incidentally.

    ``%SystemRoot%`` is not percent-encoding and a single ``%20`` in a URL is not
    obfuscation; requiring several valid sequences keeps both out.
    """
    if len(_PERCENT_RE.findall(text)) < _MIN_ENCODING_HITS:
        return text, False
    decoded = urllib.parse.unquote(text)
    return decoded, decoded != text


def _decode_html_entities(text: str) -> tuple[str, bool]:
    """Decode numeric HTML entities only.

    Named entities are excluded on purpose: ``html.unescape`` would turn the
    ``&copy`` in ``dir&copy a b`` into a copyright sign.
    """
    if len(_HTML_ENTITY_RE.findall(text)) < _MIN_ENCODING_HITS:
        return text, False

    def _replace(match: re.Match[str]) -> str:
        raw_hex, raw_dec = match.group(1), match.group(2)
        try:
            return chr(int(raw_hex, 16) if raw_hex else int(raw_dec))
        except (ValueError, OverflowError):
            return match.group(0)

    decoded = _HTML_ENTITY_RE.sub(_replace, text)
    return decoded, decoded != text


def _decode_escapes(text: str) -> tuple[str, bool]:
    """Decode ``\\uXXXX`` and ``\\xNN`` escape sequences."""
    decoded = text
    for pattern, base in ((_UNICODE_ESCAPE_RE, 16), (_HEX_ESCAPE_RE, 16)):
        if len(pattern.findall(decoded)) < _MIN_ENCODING_HITS:
            continue
        decoded = pattern.sub(lambda m: chr(int(m.group(1), base)), decoded)
    return decoded, decoded != text


# Transform order within a round. Character-level folds run before
# concatenation so that ``[char]99+[char]97`` collapses in a single pass, and
# base64 runs last so it sees an already-deobfuscated blob.
_TRANSFORMS: tuple[tuple[str, object], ...] = (
    ("backtick-split token", _fold_backticks),
    ("[char[]] code array", _fold_char_arrays),
    ("[char] code", _fold_char_codes),
    ("quoted string concatenation", _fold_concatenation),
    ("format operator (-f)", _fold_format_operator),
    ("percent-encoding", _decode_percent),
    ("HTML numeric entities", _decode_html_entities),
    ("unicode/hex escapes", _decode_escapes),
    ("base64 payload", _decode_base64),
)


def deobfuscate(command_line: str | None) -> DeobfuscationResult:
    """Fold a command line to its plain form, iterating to a fixed point.

    Args:
        command_line: Raw command line as pasted by the analyst.

    Returns:
        A :class:`DeobfuscationResult`. ``decoded_command`` is None when nothing
        fired, so callers can distinguish "already plain" from "decoded to
        something that happens to equal the input".
    """
    if not command_line or not command_line.strip():
        return DeobfuscationResult(original=command_line or "")

    result = DeobfuscationResult(original=command_line)
    text = command_line

    for round_index in range(MAX_DECODE_ROUNDS):
        round_changed = False
        for label, transform in _TRANSFORMS:
            try:
                text, changed = transform(text)  # type: ignore[operator]
            except (re.error, ValueError, OverflowError, MemoryError) as exc:
                logger.warning("deobfuscation step %r failed: %s", label, exc)
                continue
            if changed:
                round_changed = True
                result.decode_chain.append(label)

        if len(text) > MAX_DECODED_BYTES:
            text = text[:MAX_DECODED_BYTES]
            result.truncated = True
            result.rounds = round_index + 1
            break

        if not round_changed:
            break
        result.rounds = round_index + 1

    if result.decode_chain:
        result.was_obfuscated = True
        result.decoded_command = text

    return result
