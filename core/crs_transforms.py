"""ModSecurity transformation functions, reproduced for offline CRS matching.

A CRS rule is a pattern *plus* a transformation chain. Matching the pattern
without running the chain is not a stricter version of the rule — it is a
different rule, and usually a blind one: rule 941110 expects JavaScript escapes
decoded before its pattern ever sees the payload.

``docs/waf_payload_analyzer.md`` B1 measured the cost of not having these: 61 of
197 extracted rules declared a transformation this project could not perform, and
they clustered in exactly the XSS and RCE categories D1 made CRS responsible for.
This module closes that gap.

**Deliberately not built on :mod:`core.decode_common`.** The two have opposite
obligations. ``decode_common`` is an analyst-facing heuristic: it refuses to
percent-decode a lone ``%27`` for the command-line module because ``%SystemRoot%``
would be corrupted, and it skips named HTML entities because ``dir&copy a b``
would be. ModSecurity has no such reservations — ``t:urlDecodeUni`` decodes
unconditionally, and ``t:htmlEntityDecode`` handles named entities. Reusing the
gated versions here would silently under-transform, which is the same failure the
missing transformations already caused. Fidelity to ModSecurity is the whole
point of this file; fidelity to the analyst's expectations is the point of the
other one.

Every function is a pure string rewrite. Nothing here executes, evaluates or
interprets its input.

Reference: ModSecurity Reference Manual, "Transformation functions".
"""
from __future__ import annotations

import base64
import binascii
import re
import urllib.parse

# %uXXXX — the IIS-style Unicode escape urlDecodeUni understands.
_PERCENT_U_RE = re.compile(r"%u([0-9A-Fa-f]{4})")
_HTML_NUMERIC_RE = re.compile(r"&#(?:[xX]([0-9A-Fa-f]{1,6})|(\d{1,7}));?")
_C_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_C_COMMENT_OPEN_RE = re.compile(r"/\*.*\Z", re.DOTALL)
_WHITESPACE_RUN_RE = re.compile(r"\s+")
_ALL_WHITESPACE_RE = re.compile(r"\s")
_ESCAPE_SEQ_RE = re.compile(r"\\(x[0-9A-Fa-f]{1,2}|[0-7]{1,3}|.)", re.DOTALL)
_JS_ESCAPE_RE = re.compile(r"\\(u[0-9A-Fa-f]{4}|x[0-9A-Fa-f]{1,2}|[0-7]{1,3}|.)", re.DOTALL)
_CSS_ESCAPE_RE = re.compile(r"\\([0-9A-Fa-f]{1,6})\s?|\\(.)", re.DOTALL)
_B64_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/=]{8,}")

# The named entities ModSecurity's htmlEntityDecode recognises. A short, closed
# list on purpose — it does not implement the full HTML entity table.
_NAMED_ENTITIES = {
    "quot": '"',
    "amp": "&",
    "lt": "<",
    "gt": ">",
    "nbsp": "\xa0",
}
_NAMED_ENTITY_RE = re.compile(
    r"&(" + "|".join(_NAMED_ENTITIES) + r");?", re.IGNORECASE
)

# Single-character C/JS escapes shared by escapeSeqDecode and jsDecode.
_SIMPLE_ESCAPES = {
    "a": "\a", "b": "\b", "f": "\f", "n": "\n",
    "r": "\r", "t": "\t", "v": "\v", "0": "\0",
}


def t_none(text: str) -> str:
    """Identity. ``t:none`` resets the chain; chains are applied from a fresh
    base here, so it has nothing to undo.

    Args:
        text: Input.

    Returns:
        The input unchanged.
    """
    return text


def t_lowercase(text: str) -> str:
    """Lowercase the whole string."""
    return text.lower()


def t_urldecode(text: str) -> str:
    """Percent-decode, unconditionally, mapping ``+`` to a space.

    Unlike :func:`core.decode_common.decode_percent` there is no occurrence
    threshold: ModSecurity decodes whatever is there, and a rule written against
    the decoded form must see it.

    **The ``+`` mapping is not cosmetic.** It is how query strings encode a
    space, so it is the form real payloads arrive in, and omitting it was
    measured to halve detection: ``1+union+all+select+1,2,3`` scored 10 while
    the space-separated form scored 25, because the rules expect whitespace
    between the keywords. ``unquote_plus`` is what ModSecurity's ``t:urlDecode``
    does.
    """
    return urllib.parse.unquote_plus(text, errors="replace")


def t_urldecodeuni(text: str) -> str:
    """Percent-decode including IIS-style ``%uXXXX`` escapes and ``+`` as space."""
    def _uni(match: re.Match[str]) -> str:
        try:
            return chr(int(match.group(1), 16))
        except (ValueError, OverflowError):
            return match.group(0)

    return t_urldecode(_PERCENT_U_RE.sub(_uni, text))


def t_htmlentitydecode(text: str) -> str:
    """Decode numeric and the handful of named entities ModSecurity handles."""
    def _numeric(match: re.Match[str]) -> str:
        raw_hex, raw_dec = match.group(1), match.group(2)
        try:
            return chr(int(raw_hex, 16) if raw_hex else int(raw_dec))
        except (ValueError, OverflowError):
            return match.group(0)

    decoded = _HTML_NUMERIC_RE.sub(_numeric, text)
    return _NAMED_ENTITY_RE.sub(
        lambda m: _NAMED_ENTITIES[m.group(1).lower()], decoded
    )


def t_base64decode(text: str) -> str:
    """Decode base64-looking runs in place.

    ModSecurity decodes the whole value forgivingly; applied to a payload that
    is only partly base64 that would destroy the rest, so the substitution is
    scoped to base64-shaped runs.
    """
    def _decode(match: re.Match[str]) -> str:
        blob = match.group(0)
        padded = blob + "=" * (-len(blob) % 4)
        try:
            raw = base64.b64decode(padded, validate=False)
            return raw.decode("utf-8", errors="replace")
        except (binascii.Error, ValueError):
            return blob

    return _B64_CANDIDATE_RE.sub(_decode, text)


def t_removenulls(text: str) -> str:
    """Remove NUL bytes."""
    return text.replace("\x00", "")


def t_compresswhitespace(text: str) -> str:
    """Collapse each run of whitespace into a single space."""
    return _WHITESPACE_RUN_RE.sub(" ", text)


def t_removewhitespace(text: str) -> str:
    """Remove all whitespace."""
    return _ALL_WHITESPACE_RE.sub("", text)


def t_replacecomments(text: str) -> str:
    """Replace C-style comments with a single space.

    An unterminated ``/*`` is replaced through to the end of the string, which
    is what stops ``un/*x*/ion`` and ``uni/*on`` both hiding a keyword.
    """
    replaced = _C_COMMENT_RE.sub(" ", text)
    return _C_COMMENT_OPEN_RE.sub(" ", replaced)


def t_removecommentschar(text: str) -> str:
    """Remove comment characters, leaving the content between them."""
    out = text
    for marker in ("/*", "*/", "--", "<!--", "-->", "#"):
        out = out.replace(marker, "")
    return out


def _decode_escape_body(body: str) -> str:
    """Resolve one escape body shared by escapeSeqDecode and jsDecode."""
    if body[0] in "xX" and len(body) > 1:
        try:
            return chr(int(body[1:], 16))
        except (ValueError, OverflowError):
            return "\\" + body
    if body[0] in "uU" and len(body) == 5:
        try:
            return chr(int(body[1:], 16))
        except (ValueError, OverflowError):
            return "\\" + body
    if body.isdigit() and all(c in "01234567" for c in body) and len(body) > 1:
        try:
            return chr(int(body, 8))
        except (ValueError, OverflowError):
            return "\\" + body
    if body in _SIMPLE_ESCAPES:
        return _SIMPLE_ESCAPES[body]
    # ModSecurity drops the backslash for any other escaped character, which is
    # what defeats \u\s\e\r-style splitting.
    return body


def t_escapeseqdecode(text: str) -> str:
    """Decode C-style escape sequences (``\\xHH``, octal, ``\\n`` and friends)."""
    return _ESCAPE_SEQ_RE.sub(lambda m: _decode_escape_body(m.group(1)), text)


def t_jsdecode(text: str) -> str:
    """Decode JavaScript escape sequences, including ``\\uHHHH``."""
    return _JS_ESCAPE_RE.sub(lambda m: _decode_escape_body(m.group(1)), text)


def t_cssdecode(text: str) -> str:
    """Decode CSS escapes: ``\\HH`` hex runs and ``\\<char>`` literals."""
    def _replace(match: re.Match[str]) -> str:
        hex_body, literal = match.group(1), match.group(2)
        if hex_body is not None:
            try:
                return chr(int(hex_body, 16))
            except (ValueError, OverflowError):
                return match.group(0)
        return literal

    return _CSS_ESCAPE_RE.sub(_replace, text)


def t_cmdline(text: str) -> str:
    """Normalise a command line the way ModSecurity's ``t:cmdLine`` does.

    Per the reference manual: delete backslashes, double quotes, single quotes
    and carets; delete spaces before ``/`` and ``(``; replace commas and
    semicolons with spaces; collapse whitespace; lowercase. This is what makes
    ``c^m^d /c`` and ``"cmd" /c`` reduce to the same text.
    """
    out = text
    for char in ("\\", '"', "'", "^"):
        out = out.replace(char, "")
    out = re.sub(r"\s+(?=[/(])", "", out)
    out = out.replace(",", " ").replace(";", " ")
    out = _WHITESPACE_RUN_RE.sub(" ", out)
    return out.lower()


def t_normalizepath(text: str) -> str:
    """Collapse ``//``, remove ``./`` and resolve ``../`` segments."""
    out = re.sub(r"/{2,}", "/", text)
    out = re.sub(r"(?<=/)\./", "", out)
    if out.startswith("./"):
        out = out[2:]
    previous = None
    while previous != out:
        previous = out
        out = re.sub(r"(?:[^/]+)/\.\./", "", out, count=1)
    return out


def t_normalizepathwin(text: str) -> str:
    """Convert backslashes to forward slashes, then normalise the path."""
    return t_normalizepath(text.replace("\\", "/"))


def t_utf8tounicode(text: str) -> str:
    """Render non-ASCII characters as ``%uXXXX``.

    ModSecurity converts UTF-8 byte sequences into this form so that rules can
    match the escape rather than the raw bytes.
    """
    return "".join(
        char if ord(char) < 0x80 else f"%u{ord(char):04x}"
        for char in text
    )


# Name as it appears in a SecRule ``t:`` action, lowercased, to implementation.
TRANSFORMS = {
    "none": t_none,
    "lowercase": t_lowercase,
    "urldecode": t_urldecode,
    "urldecodeuni": t_urldecodeuni,
    "htmlentitydecode": t_htmlentitydecode,
    "base64decode": t_base64decode,
    "removenulls": t_removenulls,
    "compresswhitespace": t_compresswhitespace,
    "removewhitespace": t_removewhitespace,
    "replacecomments": t_replacecomments,
    "removecommentschar": t_removecommentschar,
    "escapeseqdecode": t_escapeseqdecode,
    "jsdecode": t_jsdecode,
    "cssdecode": t_cssdecode,
    "cmdline": t_cmdline,
    "normalizepath": t_normalizepath,
    "normalizepathwin": t_normalizepathwin,
    "utf8tounicode": t_utf8tounicode,
}


def apply_chain(text: str, chain: tuple[str, ...]) -> tuple[str, list[str]]:
    """Run a rule's transformation chain over a payload.

    Args:
        text: The value to transform.
        chain: Transformation names in declaration order, as extracted from the
            rule's ``t:`` actions.

    Returns:
        Tuple of (transformed text, names of transformations this module does
        not implement). A caller that ignores the second element is claiming a
        fidelity it does not have.
    """
    out = text
    unknown: list[str] = []
    for name in chain:
        func = TRANSFORMS.get(name.lower())
        if func is None:
            unknown.append(name)
            continue
        try:
            out = func(out)
        except (ValueError, OverflowError, MemoryError, re.error):
            # One malformed construct must cost that transformation, not the
            # whole chain and not the rule.
            unknown.append(name)
    return out, unknown
