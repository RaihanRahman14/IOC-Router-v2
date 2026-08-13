"""Command-line deobfuscation — Layer 2. Pure transforms, never execution.

Implements ``docs/cmdline_analyzer.md`` D2. The briefing proposed
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

The last group above — the encodings any text can carry — now lives in
:mod:`core.decode_common`, shared with the WAF payload module
(``docs/waf_payload_analyzer.md`` D2). What stays here is what only a
PowerShell or cmd.exe command line can mean: the ``-EncodedCommand`` flag family
and the four string-folding tricks. :data:`_PROFILE` carries this module's
calibration of the shared transforms, and is the reason sharing them costs
nothing: the WAF module's payloads need looser thresholds, and it passes its own.

Decoding is iterative to a fixed point under two hard caps
(:data:`MAX_DECODE_ROUNDS`, :data:`MAX_DECODED_BYTES`) so that a layered or
self-expanding payload cannot hang a Streamlit rerun. Every applied transform is
recorded in ``decode_chain``: a decoded string an analyst cannot trace back to
its source is worse than no decode at all.
"""
from __future__ import annotations

import functools
import logging
import re
from dataclasses import dataclass, field

from core.decode_common import (
    LABEL_BASE64,
    LABEL_ESCAPES,
    LABEL_HTML_ENTITIES,
    LABEL_PERCENT,
    DecodeProfile,
    Transform,
    b64_decode_text,
    decode_base64_inline,
    decode_escapes,
    decode_html_entities,
    decode_percent,
    run_pipeline,
)

logger = logging.getLogger(__name__)

# How the shared transforms are calibrated for a Windows command line. Every
# value here is a deliberate difference from what a web payload would want —
# see :class:`core.decode_common.DecodeProfile` for the reasoning per field.
_PROFILE = DecodeProfile(
    min_encoding_hits=2,
    min_b64_inline=24,
    b64_require_command_shape=True,
    b64_utf16_first=True,
    max_rounds=5,
    max_bytes=1_000_000,
)

# Iteration guards. A layered payload legitimately needs a handful of passes;
# anything beyond that is a decode bomb or a fixed-point bug.
MAX_DECODE_ROUNDS = _PROFILE.max_rounds
MAX_DECODED_BYTES = _PROFILE.max_bytes

# Shortest run treated as a base64 payload. Below this, ordinary words are valid
# base64 and decode to convincing-looking noise. The flag tier can afford a lower
# bar than the inline tier: an ``-enc`` argument is a payload by declaration.
MIN_B64_FLAG_ARG = 20
MIN_B64_INLINE = _PROFILE.min_b64_inline

# PowerShell's -EncodedCommand and its accepted abbreviations.
_ENC_FLAG_RE = re.compile(
    r"(?:(?<=\s)|^)-(?:e|en|enc|ec|encoded|encodedcommand|encodedarguments)\s+([^\s\"']+)",
    re.IGNORECASE,
)

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


def _decode_base64(text: str) -> tuple[str, bool]:
    """Decode base64 payloads in place, keeping the surrounding command intact.

    Two tiers, because confidence differs: an argument to an ``-enc``-family
    flag is a payload by declaration and only this module can recognise one,
    while a long base64-looking run anywhere else is a guess and is handed to the
    shared opportunistic decoder under this module's profile.

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
        decoded = b64_decode_text(
            blob,
            require_command_shape=False,
            utf16_first=_PROFILE.b64_utf16_first,
        )
        if decoded is None:
            return match.group(0)
        changed = True
        return match.group(0).replace(blob, decoded)

    text = _ENC_FLAG_RE.sub(_replace_flag, text)
    if changed:
        return text, True

    return decode_base64_inline(text, _PROFILE)


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


# Transform order within a round. Character-level folds run before
# concatenation so that ``[char]99+[char]97`` collapses in a single pass, and
# base64 runs last so it sees an already-deobfuscated blob. The four shared
# transforms keep the labels :mod:`core.decode_common` defines, so a decode chain
# reads the same whichever module produced it.
_TRANSFORMS: tuple[tuple[str, Transform], ...] = (
    ("backtick-split token", _fold_backticks),
    ("[char[]] code array", _fold_char_arrays),
    ("[char] code", _fold_char_codes),
    ("quoted string concatenation", _fold_concatenation),
    ("format operator (-f)", _fold_format_operator),
    (LABEL_PERCENT, functools.partial(decode_percent, profile=_PROFILE)),
    (LABEL_HTML_ENTITIES, functools.partial(decode_html_entities, profile=_PROFILE)),
    (LABEL_ESCAPES, functools.partial(decode_escapes, profile=_PROFILE)),
    (LABEL_BASE64, _decode_base64),
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

    run = run_pipeline(command_line, _TRANSFORMS, _PROFILE)

    result = DeobfuscationResult(
        original=command_line,
        decode_chain=run.chain,
        rounds=run.rounds,
        truncated=run.truncated,
    )
    if run.chain:
        result.was_obfuscated = True
        result.decoded_command = run.text

    return result
