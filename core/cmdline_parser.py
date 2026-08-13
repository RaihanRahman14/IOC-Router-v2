"""Windows command-line tokenizer and interpreter detection — Layer 1.

Implements ``docs/cmdline_analyzer.md`` D1: a pure-Python tokenizer for both
cmd.exe and PowerShell, replacing the briefing's suggestion of shelling out to
``System.Management.Automation.Language.Parser``. That parser is not importable
from Python — using it means spawning ``powershell.exe`` per analysis, which
costs a process start inside every Streamlit rerun and makes the module
Windows-only in an otherwise pure-Python codebase.

What this module does **not** do:

* **Deobfuscate.** ``('c'+'a'+'l'+'c')`` tokenizes to the single token
  ``c+a+l+c``; folding it back to ``calc`` belongs to
  :mod:`core.cmdline_deobfuscator`, which runs *before* this module. Quote
  stripping is different — ``pow""ershell`` is one token that normalizes to
  ``powershell`` here, because that is ordinary lexical behaviour rather than a
  transformation of the string's meaning.
* **Recurse.** ``powershell -c "<payload>"`` yields ``<payload>`` as one
  argument. Re-parsing that payload is the analyzer's call to make, after it has
  been through the deobfuscator; doing it here would bury an unbounded recursion
  inside a tokenizer.
* **Execute or evaluate anything.** Every function here is a pure string
  transformation.

The tokenizer is deliberately faithful to the shells rather than to what an
analyst might have meant: ``curl http://x/a?b=1&c=2`` really is two statements to
cmd.exe, and showing that split is more useful than silently repairing it.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger(__name__)

_INTERNAL_COMMANDS_FILE = Path(__file__).parent / "data" / "cmd_internal_commands.json"

INTERPRETER_POWERSHELL = "powershell"
INTERPRETER_CMD = "cmd"
INTERPRETER_UNKNOWN = "unknown"

# PowerShell's stop-parsing token: everything after it is passed through
# verbatim, with no quoting, escaping or variable expansion applied.
STOP_PARSING = "--%"

_WHITESPACE = " \t\r\n"

# Statement separators per interpreter, longest first so "&&" is matched before
# "&". Bare "&" is absent from the PowerShell set on purpose — there it is the
# call operator (``& 'C:\tools\a.exe'``), and splitting on it would sever the
# operator from the command it invokes.
_SEPARATORS: dict[str, tuple[str, ...]] = {
    INTERPRETER_CMD: ("&&", "||", "&", "|"),
    INTERPRETER_POWERSHELL: ("&&", "||", ";", "|"),
}

# Approved PowerShell verbs common enough to identify cmdlet syntax on sight.
# Matching the full Verb-Noun shape (not a bare hyphen) keeps ordinary
# hyphenated filenames like ``sql-backup.exe`` out of the PowerShell branch.
_CMDLET_VERBS = (
    "Add", "Clear", "Compare", "ConvertFrom", "ConvertTo", "Copy", "Disable", "Enable",
    "Enter", "Exit", "Export", "ForEach", "Format", "Get", "Group", "Import", "Invoke",
    "Join", "Measure", "Move", "New", "Out", "Register", "Remove", "Rename", "Resolve",
    "Restart", "Select", "Set", "Show", "Sort", "Split", "Start", "Stop", "Test",
    "Unregister", "Update", "Where", "Write",
)
_CMDLET_RE = re.compile(r"\b(?:" + "|".join(_CMDLET_VERBS) + r")-[A-Za-z]{2,}\b", re.IGNORECASE)

# A PowerShell variable reference. cmd.exe uses %VAR% instead, so this does not
# collide.
_PS_VARIABLE_RE = re.compile(r"\$(?:env:)?[A-Za-z_][A-Za-z0-9_]*")

# Executable stems that mean "this line is PowerShell".
_PS_BINARY_STEMS = ("powershell", "pwsh", "powershell_ise")

# Characters stripped before interpreter detection only. An invocation written
# as ``p`o`w`e`r`s`h`e`l`l`` or ``pow""ershell`` must still be recognised, and
# detection has to happen before tokenizing decides which escape rules apply.
_DETECTION_NOISE_RE = re.compile(r"[`\"'^]")


@dataclass
class ParsedCommand:
    """One command within a possibly-chained command line.

    Attributes:
        interpreter: Interpreter this command was tokenized under.
        base_command: First token — the binary or builtin being invoked.
        flags: Tokens that look like switches (``-nop``, ``/c``, ``--config``).
        arguments: Every other non-base token, in order.
        tokens: The full ordered token list including ``base_command``. Layer 3
            matches flag/value pairs such as ``-w hidden``, which is only
            possible against adjacency information that ``flags`` and
            ``arguments`` have thrown away.
        raw: The untouched source text of this statement.
    """

    interpreter: str
    base_command: str
    raw: str
    tokens: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    arguments: list[str] = field(default_factory=list)


@dataclass
class ParseResult:
    """Outcome of parsing one submitted command line.

    Attributes:
        interpreter: Detected interpreter for the line as a whole.
        commands: One entry per statement; empty when nothing parseable was found.
        parse_ok: False for empty input or a malformed line. The plan (D10) maps
            both to the ``Unknown`` verdict, and this field is what keeps them
            distinguishable in the UI and the AI narrative.
        issues: Human-readable parse problems, e.g. an unterminated quote.
    """

    interpreter: str
    commands: list[ParsedCommand] = field(default_factory=list)
    parse_ok: bool = False
    issues: list[str] = field(default_factory=list)


@lru_cache(maxsize=1)
def load_cmd_internal_commands() -> frozenset[str]:
    """Load the cmd.exe builtin command table.

    Cached for the process lifetime.

    Returns:
        Lowercased builtin names, or an empty set if the data file is missing or
        malformed — which degrades the lookup to "nothing is a builtin" rather
        than raising inside a Streamlit rerun.
    """
    try:
        raw = json.loads(_INTERNAL_COMMANDS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("cmd_internal_commands.json unreadable (%s) — builtin lookup disabled", exc)
        return frozenset()

    commands = raw.get("commands")
    if not isinstance(commands, list):
        logger.error("cmd_internal_commands.json has no 'commands' list — lookup disabled")
        return frozenset()

    return frozenset(str(c).strip().lower() for c in commands if str(c).strip())


def is_internal_command(name: str | None) -> bool:
    """Report whether a base command is a cmd.exe builtin.

    Args:
        name: Base command token, with or without an extension.

    Returns:
        True if the name is a shell builtin. Builtins have no file on disk, so a
        False result is what makes a filepath or LOLBAS lookup meaningful.
    """
    if not name:
        return False
    return name.strip().lower() in load_cmd_internal_commands()


def detect_interpreter(command_line: str | None) -> str:
    """Identify which shell a command line is written for.

    Detection runs on a de-noised copy of the input (backticks, quotes and
    carets removed) so that a token-split invocation such as
    ``p`o`w`e`r`s`h`e`l`l`` is still recognised. Recognition has to precede
    tokenizing, since the interpreter decides which escape character applies.

    Args:
        command_line: Raw command line, possibly None or blank.

    Returns:
        One of :data:`INTERPRETER_POWERSHELL`, :data:`INTERPRETER_CMD` or
        :data:`INTERPRETER_UNKNOWN`. Anything non-blank that shows no PowerShell
        marker defaults to cmd.exe, per briefing §3 Layer 1.
    """
    if not command_line or not command_line.strip():
        return INTERPRETER_UNKNOWN

    cleaned = _DETECTION_NOISE_RE.sub("", command_line).strip()
    if not cleaned:
        return INTERPRETER_UNKNOWN

    first = cleaned.split(None, 1)[0]
    stem = re.split(r"[\\/]", first)[-1].lower()
    if stem.endswith(".exe"):
        stem = stem[: -len(".exe")]
    if stem in _PS_BINARY_STEMS:
        return INTERPRETER_POWERSHELL

    if _CMDLET_RE.search(cleaned) or _PS_VARIABLE_RE.search(cleaned):
        return INTERPRETER_POWERSHELL

    return INTERPRETER_CMD


def _escape_char(interpreter: str) -> str:
    """Return the interpreter's escape character."""
    return "`" if interpreter == INTERPRETER_POWERSHELL else "^"


def _quote_chars(interpreter: str) -> str:
    """Return the quote characters the interpreter honours.

    cmd.exe has no single-quote quoting; treating ``'`` as a quote there would
    merge tokens that the shell really does keep apart.
    """
    return "\"'" if interpreter == INTERPRETER_POWERSHELL else '"'


def _tokenize_with_state(text: str, interpreter: str) -> tuple[list[str], bool]:
    """Tokenize and report whether a quote was left open.

    Args:
        text: One statement's source text.
        interpreter: Interpreter whose quoting rules apply.

    Returns:
        Tuple of (tokens, unterminated) where ``unterminated`` is True if the
        text ended inside a quoted span. Tokens are still returned in that case —
        best effort beats discarding the analyst's input.
    """
    escape = _escape_char(interpreter)
    quotes = _quote_chars(interpreter)

    tokens: list[str] = []
    buf: list[str] = []
    started = False          # distinguishes an empty quoted token ("") from no token
    quote: str | None = None
    i = 0
    length = len(text)

    while i < length:
        ch = text[i]

        if quote is None:
            if ch in _WHITESPACE:
                if started:
                    tokens.append("".join(buf))
                    buf.clear()
                    started = False
                i += 1
            elif ch == escape and i + 1 < length:
                buf.append(text[i + 1])
                started = True
                i += 2
            elif ch in quotes:
                quote = ch
                started = True
                i += 1
            else:
                buf.append(ch)
                started = True
                i += 1
            continue

        # Inside a quoted span.
        if ch == quote:
            # A doubled quote is one literal quote and stays inside the span
            # (the MSVCRT argv rule, and PowerShell's rule for '' as well).
            if i + 1 < length and text[i + 1] == quote:
                buf.append(quote)
                i += 2
            else:
                quote = None
                i += 1
        elif (
            interpreter == INTERPRETER_POWERSHELL
            and quote == '"'
            and ch == "`"
            and i + 1 < length
        ):
            # Backtick still escapes inside double quotes, but not inside single
            # quotes, where PowerShell treats every character literally.
            buf.append(text[i + 1])
            i += 2
        else:
            buf.append(ch)
            i += 1

    if started:
        tokens.append("".join(buf))

    return tokens, quote is not None


def tokenize(text: str | None, interpreter: str) -> list[str]:
    """Split one statement into tokens under the given interpreter's rules.

    Handles quote grouping, doubled quotes as literals, intra-token quoting
    (``pow""ershell`` is one token) and the interpreter's escape character.

    Args:
        text: Statement source text.
        interpreter: One of the ``INTERPRETER_*`` constants.

    Returns:
        Tokens with quoting and escaping resolved. Empty for blank input.
    """
    if not text:
        return []
    tokens, _ = _tokenize_with_state(text, interpreter)
    return tokens


def split_statements(command_line: str | None, interpreter: str) -> list[str]:
    """Split a chained command line into its individual statements.

    Separator recognition respects quoting and escaping, so ``echo "a & b"`` and
    ``echo a^&b`` both stay single statements.

    Args:
        command_line: Raw command line.
        interpreter: Decides the separator set — see :data:`_SEPARATORS`.

    Returns:
        Statement source texts, stripped of surrounding whitespace, with empty
        segments dropped.
    """
    if not command_line:
        return []

    separators = _SEPARATORS.get(interpreter, _SEPARATORS[INTERPRETER_CMD])
    escape = _escape_char(interpreter)
    quotes = _quote_chars(interpreter)

    segments: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    i = 0
    length = len(command_line)

    while i < length:
        ch = command_line[i]

        if quote is not None:
            buf.append(ch)
            if ch == quote:
                if i + 1 < length and command_line[i + 1] == quote:
                    buf.append(quote)
                    i += 2
                    continue
                quote = None
            i += 1
            continue

        if ch == escape and i + 1 < length:
            buf.append(ch)
            buf.append(command_line[i + 1])
            i += 2
            continue

        if ch in quotes:
            quote = ch
            buf.append(ch)
            i += 1
            continue

        match = next((s for s in separators if command_line.startswith(s, i)), None)
        if match is not None:
            segments.append("".join(buf))
            buf.clear()
            i += len(match)
            continue

        buf.append(ch)
        i += 1

    segments.append("".join(buf))
    return [s.strip() for s in segments if s.strip()]


def _find_stop_parsing(statement: str) -> int:
    """Locate PowerShell's ``--%`` token outside any quoted span.

    Args:
        statement: One statement's source text.

    Returns:
        Index of the token, or -1 if absent. Only a standalone token counts;
        ``--%foo`` is an ordinary argument.
    """
    quote: str | None = None
    i = 0
    length = len(statement)

    while i < length:
        ch = statement[i]
        if quote is not None:
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "\"'":
            quote = ch
            i += 1
            continue
        if ch == "`" and i + 1 < length:
            i += 2
            continue
        if statement.startswith(STOP_PARSING, i):
            at_start = i == 0 or statement[i - 1] in _WHITESPACE
            end = i + len(STOP_PARSING)
            at_end = end >= length or statement[end] in _WHITESPACE
            if at_start and at_end:
                return i
        i += 1

    return -1


def _is_flag(token: str) -> bool:
    """Report whether a token reads as a switch rather than a value.

    Guards against the two common misreads: ``-1`` is a negative number, not a
    switch, and ``\\\\server\\share`` is a UNC path, not one either.
    """
    if not token:
        return False
    if token.startswith("/"):
        rest = token[1:]
        return bool(rest) and rest[0].isalnum()
    if token.startswith("-"):
        rest = token.lstrip("-")
        return bool(rest) and rest[0].isalpha()
    return False


def _build_command(statement: str, interpreter: str) -> tuple[ParsedCommand | None, bool]:
    """Parse one statement into a :class:`ParsedCommand`.

    Args:
        statement: Statement source text.
        interpreter: Interpreter whose rules apply.

    Returns:
        Tuple of (command or None when the statement holds no tokens,
        unterminated-quote flag).
    """
    verbatim: str | None = None
    body = statement

    if interpreter == INTERPRETER_POWERSHELL:
        stop = _find_stop_parsing(statement)
        if stop != -1:
            body = statement[:stop]
            remainder = statement[stop + len(STOP_PARSING):].strip()
            verbatim = remainder or None

    tokens, unterminated = _tokenize_with_state(body, interpreter)
    if not tokens and verbatim is None:
        return None, unterminated

    flags = [t for t in tokens[1:] if _is_flag(t)]
    arguments = [t for t in tokens[1:] if not _is_flag(t)]

    if verbatim is not None:
        # The stop-parsing remainder is one opaque value by definition. It must
        # skip _is_flag() entirely — a remainder like ``/c "a b" & whoami``
        # opens with something switch-shaped but is not a switch.
        tokens = tokens + [STOP_PARSING, verbatim]
        arguments = arguments + [STOP_PARSING, verbatim]

    return (
        ParsedCommand(
            interpreter=interpreter,
            base_command=tokens[0],
            raw=statement,
            tokens=tokens,
            flags=flags,
            arguments=arguments,
        ),
        unterminated,
    )


def parse_command_line(command_line: str | None) -> ParseResult:
    """Parse a submitted command line into structured commands.

    This is the module's entry point and the source of the analyst-facing
    structural breakdown (docs/cmdline_analyzer.md). It never raises on malformed input —
    a command line that cannot be parsed returns ``parse_ok=False`` with
    whatever tokens were recoverable, which the plan (D10) routes to ``Unknown``
    rather than to a silently clean result.

    Args:
        command_line: Raw command line as pasted by the analyst.

    Returns:
        A :class:`ParseResult`. ``commands`` holds one entry per chained
        statement, so ``powershell -enc … ; certutil …`` yields two.
    """
    interpreter = detect_interpreter(command_line)
    if interpreter == INTERPRETER_UNKNOWN:
        return ParseResult(interpreter=interpreter, issues=["empty command line"])

    commands: list[ParsedCommand] = []
    issues: list[str] = []

    for statement in split_statements(command_line, interpreter):
        command, unterminated = _build_command(statement, interpreter)
        if unterminated:
            issues.append(f"unterminated quote in: {statement}")
        if command is not None:
            commands.append(command)

    if not commands:
        issues.append("no parseable command found")

    return ParseResult(
        interpreter=interpreter,
        commands=commands,
        parse_ok=bool(commands) and not issues,
        issues=issues,
    )
