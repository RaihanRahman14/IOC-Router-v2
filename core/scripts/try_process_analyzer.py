"""Manual harness for the process/filepath analyzer.

This harness exercises the analyzer directly, so
script is how you exercise it by hand: pass any subset of the four form fields
and read back exactly what each layer decided.

Usage::

    python core/scripts/try_process_analyzer.py --parent winword.exe --child cmd.exe
    python core/scripts/try_process_analyzer.py --file-path "C:\\Temp\\scvhost.exe"
    python core/scripts/try_process_analyzer.py --child certutil.exe --context "hash 44d886..."
    python core/scripts/try_process_analyzer.py --demo      # run a spread of examples
    python core/scripts/try_process_analyzer.py --parent winword.exe --child cmd.exe --json

Every field is optional, exactly as in the real form.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path

# Allow running as a plain script from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.process_analyzer import (  # noqa: E402
    ProcessAnalysisResult,
    ProcessFilepathInput,
    analyze_process_event,
)

_SEVERITY_MARK = {
    "CRITICAL": "!!", "HIGH": "!", "MEDIUM": "~", "LOW": "-", "INFO": "i",
}

DEMO_CASES: list[tuple[str, ProcessFilepathInput]] = [
    ("Office macro spawning a shell",
     ProcessFilepathInput(parent_process="winword.exe", child_process="cmd.exe")),
    ("Masquerading parent, ordinary child",
     ProcessFilepathInput(parent_process=r"C:\Users\Public\svchost.exe",
                          child_process="notepad.exe")),
    ("Typosquatted binary, file path only",
     ProcessFilepathInput(file_path=r"C:\Temp\scvhost.exe")),
    ("System binary in the right place",
     ProcessFilepathInput(file_path=r"C:\Windows\System32\svchost.exe")),
    ("Dual-use binary on its own",
     ProcessFilepathInput(child_process="certutil.exe")),
    ("Ordinary desktop activity",
     ProcessFilepathInput(parent_process="explorer.exe", child_process="chrome.exe")),
    ("Hash pasted into Context",
     ProcessFilepathInput(child_process="cmd.exe",
                          context="EDR log: sample 44d88612fea8a8f36de82e1278abb02f blocked")),
]


def render(result: ProcessAnalysisResult) -> str:
    """Render an analysis result as readable console text.

    Args:
        result: The result to render.

    Returns:
        A multi-line report string.
    """
    out: list[str] = [f"VERDICT: {result.aggregated_verdict}"]

    if result.fields_submitted:
        out.append(f"Fields submitted: {', '.join(result.fields_submitted)}")
    else:
        out.append("Fields submitted: none — in the real app this is a form-validation case")

    for _, label, analysis in result.field_analyses():
        out.append(f"\n  [{label}] {analysis.value}")
        out.append(f"    identity : {analysis.identity_flag}")
        out.append(f"               {analysis.identity_detail}")
        if analysis.impersonated_lolbas:
            record = analysis.impersonated_lolbas
            categories = ", ".join(record.get("categories") or [])
            out.append(f"    LOLBAS   : impersonates {record.get('binary')} — dual-use "
                       f"({categories})")
        elif analysis.lolbas_match and not analysis.is_masquerading():
            categories = ", ".join(analysis.lolbas_match.get("categories") or [])
            out.append(f"    LOLBAS   : {categories}")

    if result.pairing_flag:
        pairing = result.pairing_flag
        out.append(f"\n  [Parent-Child Pair] {pairing['parent']} -> {pairing['child']}")
        out.append(f"    rule     : {pairing.get('title')} [{pairing.get('sigma_level')}]")
        out.append(f"    sigma id : {pairing.get('sigma_rule_id')}")
        out.append(f"    fidelity : {pairing.get('approximate_note') or 'exact match to the rule'}")

    if result.chain_contamination:
        out.append("\n  [Chain] parent is masquerading — contamination propagated to the child")

    if result.hash_candidates:
        out.append(f"\n  [Hash candidates from Context] {', '.join(result.hash_candidates)}")
        out.append("    (not resolved here — the app feeds these to the existing providers)")

    if result.flags:
        out.append("\n  Flags:")
        for flag in result.flags:
            mark = _SEVERITY_MARK.get(flag["severity"], "?")
            mitre = ", ".join(flag["mitre"]) or "—"
            out.append(f"    {mark} [{flag['severity']:<8}] {flag['id']}  ({mitre})")
            out.append(f"        {flag['detail']}")
    else:
        out.append("\n  Flags: none")

    if result.checks_skipped:
        out.append("\n  Checks skipped:")
        out.extend(f"    - {item}" for item in result.checks_skipped)

    return "\n".join(out)


def _force_utf8_output() -> None:
    """Switch stdout/stderr to UTF-8 so the report survives a cp1252 console.

    Same defect as the sibling harness, caught one step earlier: this script's
    non-ASCII is currently limited to the em dash, which cp1252 happens to map,
    so it garbles rather than crashes. The moment a flag label or a box-drawing
    rule introduces a character cp1252 lacks, it becomes fatal — the failure the
    command-line harness actually hit.

    ``errors="replace"`` keeps that degradation cosmetic on a stream that cannot
    be reconfigured.
    """
    for stream in (sys.stdout, sys.stderr):
        if not hasattr(stream, "reconfigure"):
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            # Detached or non-reconfigurable stream. Printing is still worth
            # attempting.
            pass


def main(argv: list[str] | None = None) -> int:
    """Entry point.

    Args:
        argv: Command-line arguments (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code.
    """
    _force_utf8_output()

    parser = argparse.ArgumentParser(
        description="Run the process/filepath analyzer against ad-hoc input.",
    )
    parser.add_argument("--file-path", help="e.g. C:\\Users\\user\\Downloads\\malware.exe")
    parser.add_argument("--parent", help="Parent process name, e.g. explorer.exe")
    parser.add_argument("--child", help="Child process name, e.g. cmd.exe")
    parser.add_argument("--context", help="Freeform context / raw log excerpt")
    parser.add_argument("--json", action="store_true", help="Emit the raw result as JSON.")
    parser.add_argument("--demo", action="store_true", help="Run a spread of worked examples.")
    args = parser.parse_args(argv)

    if args.demo:
        for title, data in DEMO_CASES:
            print("=" * 78)
            print(title)
            print("=" * 78)
            print(render(analyze_process_event(data)))
            print()
        return 0

    data = ProcessFilepathInput(
        file_path=args.file_path,
        parent_process=args.parent,
        child_process=args.child,
        context=args.context,
    )
    if not data.submitted_fields():
        parser.error("give at least one of --file-path / --parent / --child / --context "
                     "(or use --demo)")

    result = analyze_process_event(data)
    if args.json:
        print(json.dumps(dataclasses.asdict(result), indent=2, ensure_ascii=False))
    else:
        print(render(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
