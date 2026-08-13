"""One enrichment run, start to finish — the analysis half of a Run click.

This is what used to be a 190-line block inside ``app.py``'s ``if
run_requested:``. Living there, it could only be exercised by driving Streamlit:
the ordering rules that make it correct — process analysis before provider
selection so a hash found in Context gets enriched, URLs recovered from a
decoded payload never reaching URLScan's public queue, the hash verdict fed back
into the process aggregate afterwards — had no way to be tested directly.

Nothing here touches Streamlit. The two places that genuinely need the app's
state are passed in as callables (``allowed_for``, ``cve_lookup``), and the
provider fan-out is injectable so a test can run the whole pipeline without a
network or a cache. ``app.py`` keeps what is actually its job: reading widgets,
showing the spinner, and storing the result.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Callable, Protocol

from config import Settings
from core.cmdline_analyzer import (
    CommandLineInput,
    analyze_command_line,
    to_rows as cmdline_analysis_rows,
)
from core.orchestrator import PROVIDER_KEYS, run_provider_lookups
from core.process_analyzer import (
    ProcessFilepathInput,
    aggregate_verdict as aggregate_process_verdict,
    analyze_process_event,
    to_rows as process_analysis_rows,
)
from core.waf_payload_analyzer import analyze_waf_payload, to_rows as waf_analysis_rows
from core.waf_payload_parser import WafPayloadInput
from ioc.parser import IOC, parse_iocs
from ioc.verdict import summarize_results

# (value, type, scheme_inferred) — one IOC as handed to a provider lookup.
Payload = list[tuple[str, str, bool]]

# Which providers may run for each IOC type, e.g. {"ip": {"vt", "abuse"}}.
AllowedByType = dict[str, set[str]]


class ProviderLookup(Protocol):
    """The provider fan-out, as :func:`core.orchestrator.run_provider_lookups`."""

    def __call__(
        self,
        settings: Settings,
        provider_flags: dict[str, bool],
        payload_for: Callable[[str], Payload],
        allow_urlscan_submit: bool,
    ) -> tuple[dict[str, dict], dict]:
        ...


@dataclass
class EnrichmentInput:
    """Everything the analyst supplied for one Run.

    Attributes:
        items: IOCs parsed from the main textarea.
        waf_payloads: Payloads from the dedicated WAF field.
        file_path: Context "File Path" field.
        parent_process: Context "Parent Process" field.
        child_process: Context "Child Process" field.
        command_line: Context "Command Line" field.
        context: Free-form raw log / context field.
        allow_urlscan_submit: Whether URLScan may submit new scans.
    """

    items: list[IOC] = field(default_factory=list)
    waf_payloads: list[WafPayloadInput] = field(default_factory=list)
    file_path: str | None = None
    parent_process: str | None = None
    child_process: str | None = None
    command_line: str | None = None
    context: str | None = None
    allow_urlscan_submit: bool = True

    @property
    def has_local_input(self) -> bool:
        """True when a Run has process/command-line/WAF work even with no IOCs."""
        return bool(
            (self.file_path or "").strip()
            or (self.parent_process or "").strip()
            or (self.child_process or "").strip()
            or (self.command_line or "").strip()
            or self.waf_payloads
        )

    @property
    def is_empty(self) -> bool:
        """True when there is nothing at all to analyse."""
        return not self.items and not self.has_local_input


def _analyse_waf(
    payloads: list[WafPayloadInput],
    cve_lookup: Callable[[str], dict | None] | None,
) -> list:
    """Analyse WAF payloads and decorate any CVE fingerprint match.

    The NVD/KEV lookup happens here rather than inside the analyzer: that module
    performs no network I/O and its verdict must never depend on a lookup
    succeeding (docs/waf_payload_analyzer.md D4). A failed call leaves ``nvd`` /
    ``kev`` as None, which the UI renders as "not retrieved" — never as "not
    known-exploited".

    Args:
        payloads: Parsed payload inputs from the WAF field.
        cve_lookup: Resolves a CVE id to a record, or None. When omitted the
            fingerprint is left undecorated — the offline verdict still stands.

    Returns:
        The list of analysis results, fingerprints decorated in place.
    """
    results = [analyze_waf_payload(payload) for payload in payloads]
    if cve_lookup is None:
        return results

    seen: dict[str, dict | None] = {}
    for result in results:
        fingerprint = result.cve_fingerprint_match
        if not fingerprint:
            continue
        cve_id = fingerprint["cve"]
        if cve_id not in seen:
            seen[cve_id] = cve_lookup(cve_id)
        record = seen[cve_id]
        fingerprint["nvd"] = record
        fingerprint["kev"] = bool(record.get("isKev")) if record else None
    return results


def _feed_hash_verdict_back(proc_result, rows: list[dict], context_hashes: list[str]) -> None:
    """Push a Context-derived hash's provider verdict into the process aggregate.

    Layer 3 close-out: a hash lifted from Context has now been through the
    normal providers, so its verdict is the strongest signal available and
    overrides the name-based layers in aggregation.

    Args:
        proc_result: The process analysis result, mutated in place.
        rows: Per-IOC verdict rows from :func:`ioc.verdict.summarize_results`.
        context_hashes: Hashes that came from Context rather than the textarea.
    """
    if not context_hashes:
        return
    wanted = set(context_hashes)
    decisive = next(
        (
            row for row in rows
            if row.get("Artifact") in wanted
            and row.get("Verdict") in ("Malicious", "Suspicious")
        ),
        None,
    )
    if decisive is None:
        return
    proc_result.hash_verdict = {
        "verdict": decisive.get("Verdict"),
        "artifact": decisive.get("Artifact"),
        "evidence": decisive.get("Primary Evidence"),
        "sources": decisive.get("Sources"),
    }
    proc_result.aggregated_verdict = aggregate_process_verdict(proc_result)


def run_enrichment(
    inputs: EnrichmentInput,
    settings: Settings,
    allowed_for: Callable[[list[IOC]], AllowedByType],
    cve_lookup: Callable[[str], dict | None] | None = None,
    lookup: ProviderLookup = run_provider_lookups,
) -> dict:
    """Run one full enrichment and return the assembled ``run_results`` dict.

    Order matters and is load-bearing:

    1. WAF payloads are analysed on their own list. They never enter ``items``,
       so a payload cannot reach a provider or add a row to the verdict table.
    2. Process analysis runs *before* provider selection, so a hash found in
       Context joins the IOC list and is enriched by the normal pipeline rather
       than needing a second lookup path.
    3. Command-line analysis runs after it, so it can cross-reference the
       process findings, and still before provider selection so indicators
       recovered from a decoded payload join the same path.
    4. Providers run, then the hash verdict is fed back into the process
       aggregate — it needs the verdicts that only exist after step 4.

    Args:
        inputs: The analyst's input for this Run.
        settings: Resolved API keys / config.
        allowed_for: Given the *final* IOC list (originals plus anything the
            local analyzers recovered), returns which providers may run per IOC
            type. A callback rather than a value because the app derives it from
            widget state, and the list it applies to does not exist until the
            local analysis has run.
        cve_lookup: Resolves a CVE id for a WAF fingerprint match. Optional —
            omitting it skips the decoration, never the verdict.
        lookup: The provider fan-out. Injectable for tests.

    Returns:
        The ``run_results`` dict the Result tab renders.
    """
    items = list(inputs.items)
    waf_results = _analyse_waf(inputs.waf_payloads, cve_lookup)

    # ── Local analysis: process / filepath, then command line (no network) ────
    proc_result = analyze_process_event(ProcessFilepathInput(
        file_path=inputs.file_path or None,
        parent_process=inputs.parent_process or None,
        child_process=inputs.child_process or None,
        context=inputs.context or None,
    ))
    known = {ioc.value for ioc in items}
    context_hashes = [h for h in proc_result.hash_candidates if h not in known]
    items += [IOC(value=h, type="hash") for h in context_hashes]

    cmd_result = analyze_command_line(CommandLineInput(
        command_line=inputs.command_line or None,
        context=inputs.context or None,
        linked_process=proc_result,
    ))
    known = {ioc.value for ioc in items}
    derived = [
        ioc for ioc in parse_iocs("\n".join(cmd_result.ioc_candidates))
        if ioc.value not in known
    ]
    # URLs recovered from a decoded payload are looked up, never submitted.
    # Submitting an attacker's URL to URLScan's public queue is an outbound
    # disclosure the analyst did not ask for and cannot take back.
    submit_blocked = {ioc.value for ioc in derived if ioc.type == "url"}
    items += derived

    # ── Provider dispatch ────────────────────────────────────────────────────
    allowed_by_type = allowed_for(items)

    def payload_for(provider: str) -> Payload:
        return [
            (ioc.value, ioc.type, ioc.scheme_inferred)
            for ioc in items
            if provider in allowed_by_type.get(ioc.type, set())
            # URLScan takes one submit/lookup-only flag for the whole call, so a
            # URL recovered from a decoded payload is held back from that
            # provider entirely rather than risking a public submission. Every
            # other provider still enriches it.
            and not (provider == "urlscan" and ioc.value in submit_blocked)
        ]

    provider_flags = {p: bool(payload_for(p)) for p in PROVIDER_KEYS}
    results, timings = lookup(
        settings=settings,
        provider_flags=provider_flags,
        payload_for=payload_for,
        allow_urlscan_submit=inputs.allow_urlscan_submit,
    )

    summary, rows = summarize_results(
        items,
        results["vt"],
        results["urlscan"],
        results["abuse"],
        results["tf"],
        results["mb"],
        shodan_results=results["shodan"],
        hybrid_results=results["ha"],
    )
    _feed_hash_verdict_back(proc_result, rows, context_hashes)

    return {
        "items": items,
        "summary": summary,
        "rows": rows,
        **{key: results[key] for key in results},
        "provider_flags": provider_flags,
        # Kept out of "rows": that list is indexed per-artifact by the IOC cards
        # and counted by the session summary, both of which assume one entry per
        # atomic IOC. The local analyzers' rows are kept separate for the same
        # reason.
        "waf_analysis": [dataclasses.asdict(r) for r in waf_results],
        "waf_flags": [f for r in waf_results for f in r.flags],
        "waf_rows": [row for r in waf_results for row in waf_analysis_rows(r)],
        "process_analysis": dataclasses.asdict(proc_result),
        "process_flags": proc_result.flags,
        # Command-line rows share the process rows' column schema exactly
        # (asserted by a test), so the renderer concatenates the two without
        # caring which module produced a row.
        "process_rows": process_analysis_rows(proc_result) + cmdline_analysis_rows(cmd_result),
        "cmdline_analysis": dataclasses.asdict(cmd_result),
        "cmdline_flags": cmd_result.flags,
        "allowed_by_type": {t: sorted(ps) for t, ps in allowed_by_type.items()},
        "timings": timings,
    }
