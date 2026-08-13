"""Manual harness and calibration runner for the command-line analyzer.

Two modes:

* **ad-hoc** — pass a command line and read back exactly what each layer decided;
* **calibration** — run the whole corpus in ``tests/fixtures/cmdline_corpus.json``
  and report detection on the known-bad half and, more importantly, the false
  positive rate on the known-good half.

The known-good half is the one that matters. A detection module tuned only for
recall looks excellent right up to the point analysts start ignoring it, and the
false-positive rate is invisible until something measures it.

Usage::

    python core/scripts/try_cmdline_analyzer.py "powershell -nop -w hidden -enc SQBF..."
    python core/scripts/try_cmdline_analyzer.py --calibrate
    python core/scripts/try_cmdline_analyzer.py --calibrate --verbose
    python core/scripts/try_cmdline_analyzer.py --calibrate --json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow running as a plain script from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.cmdline_analyzer import (  # noqa: E402
    CommandLineAnalysisResult,
    CommandLineInput,
    analyze_command_line,
)

CORPUS_PATH = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "cmdline_corpus.json"

_SEVERITY_MARK = {
    "CRITICAL": "!!", "HIGH": "!", "MEDIUM": "~", "LOW": "-", "INFO": "i",
}

# DUAL_USE_BINARY states a fact about the binary — "msiexec.exe is documented in
# LOLBAS, and these arguments do not match any abuse pattern". It is INFO, it can
# never escalate a verdict, and reporting that the check ran and came back clean
# is information the analyst needs; silence would read as "not checked". It is
# therefore not counted as a false positive on any sample. A test asserts
# separately that it cannot escalate, so this exemption cannot hide a regression.
_ALWAYS_TOLERATED = frozenset({"DUAL_USE_BINARY"})


def load_corpus(path: Path = CORPUS_PATH) -> dict:
    """Load the calibration corpus.

    Args:
        path: Corpus JSON location.

    Returns:
        The parsed corpus.

    Raises:
        SystemExit: If the corpus is missing or malformed — a calibration run
            with no corpus is meaningless, so it fails loudly.
    """
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read corpus at {path}: {exc}") from exc


def render(result: CommandLineAnalysisResult) -> str:
    """Render an analysis result as readable console text.

    Args:
        result: A populated analysis result.

    Returns:
        Multi-line console text.
    """
    out: list[str] = []
    out.append(f"  interpreter : {result.interpreter_detected}")
    out.append(f"  parse_ok    : {result.parse_ok}")
    out.append(f"  verdict     : {result.aggregated_verdict}")

    if result.was_obfuscated:
        out.append(f"  decoded via : {' -> '.join(result.decode_chain)}")
        out.append(f"  decoded     : {result.decoded_command}")
        if result.revealed_keywords:
            out.append(f"  revealed    : {', '.join(result.revealed_keywords)}")

    for index, command in enumerate(result.commands, 1):
        prefix = f"  [{index}] " if len(result.commands) > 1 else "  "
        out.append(f"{prefix}base    : {command.base_command}")
        if command.flags:
            out.append(f"{prefix}flags   : {' '.join(command.flags)}")
        if command.arguments:
            out.append(f"{prefix}args    : {' '.join(command.arguments)}")

    if result.entropy_flag:
        out.append(f"  entropy     : {', '.join(t[:40] for t in result.entropy_tokens)}")
    if result.ioc_candidates:
        out.append(f"  indicators  : {', '.join(result.ioc_candidates)}")

    if result.flags:
        out.append("  flags:")
        for flag in result.flags:
            mark = _SEVERITY_MARK.get(flag["severity"], "?")
            out.append(f"    {mark} {flag['id']} — {flag['label']}")
    else:
        out.append("  flags       : none")

    return "\n".join(out)


def _analyze(command_line: str) -> CommandLineAnalysisResult:
    """Run the analyzer over one command line."""
    return analyze_command_line(CommandLineInput(command_line=command_line))


def calibrate(corpus: dict, verbose: bool = False) -> dict:
    """Run the corpus and measure detection and false positives.

    Args:
        corpus: Parsed corpus.
        verbose: Print per-entry detail rather than only the offenders.

    Returns:
        A summary dict: counts, rates, and the offending entry ids.
    """
    bad = corpus.get("known_bad") or []
    good = corpus.get("known_good") or []

    missed: list[str] = []
    for entry in bad:
        result = _analyze(entry["command_line"])
        expected = entry.get("expect_verdict", "Suspicious")
        hit = result.aggregated_verdict == expected
        if not hit:
            missed.append(entry["id"])
        if verbose or not hit:
            status = "OK  " if hit else "MISS"
            print(f"[{status}] known_bad/{entry['id']} -> {result.aggregated_verdict}")
            if verbose:
                print(render(result))

    false_positives: list[dict] = []
    for entry in good:
        result = _analyze(entry["command_line"])
        tolerated = set(entry.get("tolerated_flags") or []) | _ALWAYS_TOLERATED
        fired = {
            f["id"].removeprefix("CMDLINE_") for f in result.flags
        }
        unexpected = sorted(fired - tolerated)
        if unexpected:
            false_positives.append({"id": entry["id"], "flags": unexpected})
        if verbose or unexpected:
            status = "OK  " if not unexpected else "FP  "
            extra = f" -> unexpected: {', '.join(unexpected)}" if unexpected else ""
            print(f"[{status}] known_good/{entry['id']}{extra}")
            if verbose:
                print(render(result))

    summary = {
        "known_bad_total": len(bad),
        "known_bad_detected": len(bad) - len(missed),
        "known_bad_missed": missed,
        "detection_rate": round((len(bad) - len(missed)) / len(bad), 3) if bad else 0.0,
        "known_good_total": len(good),
        "known_good_clean": len(good) - len(false_positives),
        "false_positives": false_positives,
        "false_positive_rate": round(len(false_positives) / len(good), 3) if good else 0.0,
    }
    return summary


def print_summary(summary: dict) -> None:
    """Print the calibration summary as a short report."""
    print()
    print("── calibration ──────────────────────────────────────────────")
    print(f"  known-bad detected : {summary['known_bad_detected']}/{summary['known_bad_total']}"
          f"  ({summary['detection_rate']:.0%})")
    if summary["known_bad_missed"]:
        print(f"    missed           : {', '.join(summary['known_bad_missed'])}")
    print(f"  known-good clean   : {summary['known_good_clean']}/{summary['known_good_total']}"
          f"  (FP rate {summary['false_positive_rate']:.0%})")
    for entry in summary["false_positives"]:
        print(f"    FP {entry['id']}: {', '.join(entry['flags'])}")
    print()


def _force_utf8_output() -> None:
    """Switch stdout/stderr to UTF-8 so the report survives a cp1252 console.

    A Windows console defaults to cp1252, which has no mapping for the U+2500
    box-drawing rule in :func:`print_summary`. The whole corpus would run, the
    numbers would be computed, and the process would then die with
    ``UnicodeEncodeError`` at the first line of output — the one failure mode
    that costs the entire result.

    ``errors="replace"`` is the belt to that braces: on a stream that cannot be
    reconfigured at all, a future non-ASCII character degrades to ``?`` instead
    of becoming fatal again.
    """
    for stream in (sys.stdout, sys.stderr):
        if not hasattr(stream, "reconfigure"):
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            # Detached or non-reconfigurable stream (a pytest capture, a pipe
            # wrapper). Printing is still worth attempting.
            pass


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Args:
        argv: Command-line arguments (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code — non-zero when calibration finds a false positive.
    """
    _force_utf8_output()

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("command_line", nargs="?", help="a command line to analyze")
    ap.add_argument("--calibrate", action="store_true", help="run the calibration corpus")
    ap.add_argument("--verbose", action="store_true", help="per-entry detail")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    if args.calibrate:
        summary = calibrate(load_corpus(), verbose=args.verbose)
        if args.json:
            print(json.dumps(summary, indent=2))
        else:
            print_summary(summary)
        return 1 if summary["false_positives"] else 0

    if not args.command_line:
        ap.error("pass a command line, or --calibrate")

    result = _analyze(args.command_line)
    if args.json:
        import dataclasses
        print(json.dumps(dataclasses.asdict(result), indent=2, default=str))
    else:
        print(render(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
