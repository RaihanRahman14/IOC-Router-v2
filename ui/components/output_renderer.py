"""Results output format rendering — metrics, table, JSON, shareable text, ticket notes."""
from __future__ import annotations

import base64

import streamlit as st
import streamlit.components.v1 as components

try:
    import pandas as pd
except Exception:
    pd = None


# CRS category codes rendered for an analyst rather than for a rule author.
# Module-level because both the ticket notes and the WAF breakdown below spell
# out the same categories, and two copies would drift.
_WAF_CATEGORY_LABELS = {
    "sqli": "SQL injection",
    "xss": "cross-site scripting",
    "rce": "command injection",
    "lfi": "local file inclusion",
    "rfi": "remote file inclusion",
    "php": "PHP injection",
    "ssrf": "server-side request forgery",
    "protocol": "HTTP protocol anomaly",
}


def _truncate_note(text: str, limit: int = 300) -> str:
    """Shorten a value for a ticket-note line, marking that it was cut.

    Ticket notes are pasted into SIEM fields, so a decoded one-liner running to
    several kilobytes has to be bounded. The marker matters as much as the
    bound: a silently cut command line reads as a complete one.

    Args:
        text: The value to shorten.
        limit: Maximum characters to keep before the marker.

    Returns:
        The value unchanged when short enough, otherwise a truncated copy with
        a trailing ``… [truncated]``.
    """
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "… [truncated]"


def _score_color(score: float) -> tuple[str, str]:
    """Pick (background, accent) hex colors for a 0–100 confidence score.

    Args:
        score: Confidence score on the 0–100 scale.

    Returns:
        Tuple of (background_hex, accent_hex).
    """
    if score >= 70:
        return "#3a1414", "#f87171"
    if score >= 40:
        return "#3a2a14", "#fbbf24"
    if score >= 10:
        return "#1e2236", "#60a5fa"
    return "#14321a", "#4ade80"


_COUNT_CARD_COLORS: dict[str, tuple[str, str]] = {
    "Total":      ("#1a2030", "#60a5fa"),  # neutral blue
    "Malicious":  ("#3a1414", "#f87171"),  # red
    "Suspicious": ("#3a2a14", "#fbbf24"),  # amber
    "Unknown":    ("#1f1f24", "#9ca3af"),  # gray
    "Benign":     ("#14321a", "#4ade80"),  # green
}


_HERO_RESPONSIVE_CSS = (
    "<style>"
    ".iocr-hero-grid{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(0,1fr);"
    "gap:20px;align-items:center;}"
    ".iocr-counts-grid{display:grid;grid-template-columns:repeat(5, minmax(0,1fr));gap:8px;}"
    ".iocr-count-card{background:var(--iocr-cbg);border:1px solid var(--iocr-cacc);"
    "border-radius:10px;padding:12px 6px;text-align:center;min-width:0;"
    "display:flex;flex-direction:column;align-items:center;justify-content:center;}"
    ".iocr-count-value{font-size:1.7rem;font-weight:700;color:var(--iocr-cacc);line-height:1;}"
    ".iocr-count-label{font-size:0.72rem;letter-spacing:0.05em;text-transform:uppercase;"
    "color:#cfd3dc;margin-top:6px;}"
    "@media (max-width: 640px){"
    ".iocr-hero-grid{grid-template-columns:1fr;gap:12px;}"
    ".iocr-counts-grid{grid-template-columns:1fr;gap:6px;}"
    ".iocr-count-card{flex-direction:row;justify-content:space-between;"
    "padding:6px 10px;gap:8px;}"
    ".iocr-count-value{font-size:1.05rem;}"
    ".iocr-count-label{font-size:0.65rem;margin-top:0;}"
    "}"
    "</style>"
)


def _count_card(label_name: str, value: int) -> str:
    """Return HTML for one count card used in the session hero block.

    Args:
        label_name: One of Total/Malicious/Suspicious/Unknown/Benign.
        value: Integer count to display.

    Returns:
        HTML string for the card.
    """
    cbg, cacc = _COUNT_CARD_COLORS.get(label_name, ("#1f1f24", "#9ca3af"))
    return (
        f"<div class='iocr-count-card' style='--iocr-cbg:{cbg};--iocr-cacc:{cacc};'>"
        f"<div class='iocr-count-value'>{value}</div>"
        f"<div class='iocr-count-label'>{label_name}</div>"
        f"</div>"
    )


def render_session_hero(summary: dict) -> None:
    """Render the full-width session hero block: evidence panel + count cards.

    Combines the session-level evidence-strength score (left) with the
    authoritative verdict counts (right) into a single block intended to span
    the full Result-tab width, sitting above the split columns. Falls back to a
    counts-only block when no session summary is present (older runs).

    The two halves answer different questions on purpose: the cards say what the
    verdicts are, the panel says how well corroborated the evidence behind them
    was. Only the cards are a verdict.

    Args:
        summary: The aggregated summary dict returned by `summarize_results`.
    """
    sess = summary.get("session_summary") or {}

    total_count: int = int(summary.get("total", 0))
    mal_count: int = int(summary.get("malicious", 0))
    susp_count: int = int(summary.get("suspicious", 0))
    unk_count: int = int(summary.get("unknown", 0))
    ben_count: int = int(summary.get("benign", 0))

    cards_html = (
        "<div class='iocr-counts-grid'>"
        f"{_count_card('Total', total_count)}"
        f"{_count_card('Malicious', mal_count)}"
        f"{_count_card('Suspicious', susp_count)}"
        f"{_count_card('Unknown', unk_count)}"
        f"{_count_card('Benign', ben_count)}"
        "</div>"
    )

    if not sess:
        # No session summary — show counts only, no score panel.
        html = (
            f"{_HERO_RESPONSIVE_CSS}"
            "<div style='background:#14181f;border:1px solid #2a2f3a;border-radius:12px;"
            "padding:16px 20px;margin:6px 0 16px 0;'>"
            f"{cards_html}"
            "</div>"
        )
        st.markdown(html, unsafe_allow_html=True)
        return

    highest = float(sess.get("highest_score") or 0.0)
    label = sess.get("session_label") or "Minimal"
    highest_ioc = sess.get("highest_ioc") or "—"

    bg, accent = _score_color(highest)
    fill_pct = max(0.0, min(100.0, highest))

    # The score's own verdict distribution used to be rendered here as pills,
    # directly beside the count cards on the right — two different tallies of
    # the same batch, disagreeing more often than not. The cards hold the
    # verdict of record (see `ioc.verdict`), so this panel now reports only
    # what the score can actually speak to: how strong the evidence was.
    left_html = (
        f"<div style='font-size:0.78rem;letter-spacing:0.08em;text-transform:uppercase;"
        f"color:#9ea8cf;'>Strongest Evidence In Session</div>"
        f"<div style='display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-top:4px;'>"
        f"  <div style='font-size:1.85rem;font-weight:700;color:{accent};line-height:1.1;'>"
        f"{highest:.1f}<span style='font-size:0.9rem;color:#9ea8cf;'> / 100</span></div>"
        f"  <span style='background:#0f1117;border:1px solid {accent};color:{accent};"
        f"border-radius:999px;padding:3px 12px;font-size:0.82rem;font-weight:600;'>"
        f"{label} corroboration</span>"
        f"</div>"
        f"<div style='font-size:0.82rem;color:#9ea8cf;margin-top:6px;'>"
        f"Highest IOC: <span style='font-family:monospace;color:#e8eaf0;"
        f"word-break:break-all;overflow-wrap:anywhere;'>{highest_ioc}</span>"
        f"</div>"
        f"<div style='background:#0f1117;border-radius:6px;height:8px;margin-top:10px;"
        f"overflow:hidden;'>"
        f"  <div style='background:{accent};width:{fill_pct:.1f}%;height:100%;"
        f"transition:width 0.3s;'></div>"
        f"</div>"
        f"<div style='font-size:0.75rem;color:#9ea8cf;margin-top:10px;'>"
        f"How much the providers corroborated each other. The verdict counts "
        f"alongside are decided by the verdict rules, not by this score.</div>"
    )

    html = (
        f"{_HERO_RESPONSIVE_CSS}"
        f"<div style='background:{bg};border:1px solid {accent};border-radius:12px;"
        f"padding:16px 20px;margin:6px 0 16px 0;'>"
        f"  <div class='iocr-hero-grid'>"
        f"    <div style='min-width:0;'>{left_html}</div>"
        f"    <div style='min-width:0;'>{cards_html}</div>"
        f"  </div>"
        f"</div>"
    )
    st.markdown(html, unsafe_allow_html=True)


def render_cmdline_breakdown(analysis: dict) -> None:
    """Render the command-line structural breakdown above the results table.

    This is the "explainshell" half of the command-line module and, per its
    docs/cmdline_analyzer.md, the part analysts read first — before any flag or verdict. It
    is rendered as its own block rather than squeezed into a table row, because
    a token list does not survive being flattened into one cell.

    Args:
        analysis: The ``cmdline_analysis`` dict from ``run_results``. Anything
            falsy or command-less renders nothing at all.
    """
    commands = analysis.get("commands") or []
    if not commands:
        return

    with st.expander("⌨️ Command line breakdown", expanded=True):
        # The submitted line comes first: everything below is a claim about it,
        # and the analyst needs to see what was actually analysed before reading
        # any of them — especially when decoding rewrote it.
        submitted = analysis.get("original_command")
        if submitted:
            st.caption("Command line submitted")
            st.code(submitted, language="powershell")

        interpreter = analysis.get("interpreter_detected", "unknown")
        st.caption(f"Interpreter detected: **{interpreter}**")

        if analysis.get("was_obfuscated"):
            chain = " → ".join(analysis.get("decode_chain") or []) or "unspecified"
            st.warning(f"Obfuscated — decoded via {chain}")
            st.caption("Decoded form")
            st.code(analysis.get("decoded_command") or "", language="powershell")
            revealed = analysis.get("revealed_keywords") or []
            if revealed:
                st.caption("Only visible after decoding: " + ", ".join(revealed))

        for index, command in enumerate(commands, 1):
            prefix = f"{index}. " if len(commands) > 1 else ""
            st.markdown(f"**{prefix}{command.get('base_command', '')}**")
            flags = command.get("flags") or []
            arguments = command.get("arguments") or []
            if flags:
                st.markdown("Flags: " + ", ".join(f"`{f}`" for f in flags))
            if arguments:
                st.markdown("Arguments: " + ", ".join(f"`{a}`" for a in arguments))
            if not flags and not arguments:
                st.caption("No flags or arguments.")

        cross = analysis.get("lolbas_cross_check") or {}
        if cross.get("match_strength") == "CONFIRMED_ABUSE_PATTERN":
            st.warning(
                f"LOLBAS: `{cross.get('binary')}` arguments match its documented "
                f"{cross.get('category') or 'abuse'} pattern — `{cross.get('matched')}`"
            )
        elif cross.get("match_strength") == "DUAL_USE_PRESENT":
            st.caption(
                f"LOLBAS: {cross.get('binary')} is a dual-use binary, but its arguments "
                "match no documented abuse pattern."
            )

        if not analysis.get("parse_ok"):
            st.caption(
                "Parsed on a best-effort basis — the line was malformed, so treat the "
                "breakdown above as incomplete."
            )


def render_waf_breakdown(analysis: list[dict]) -> None:
    """Render the WAF payload breakdown above the results table.

    The counterpart to :func:`render_cmdline_breakdown`, for the same reason it
    exists: the decode chain, the matched CRS rules and the paranoia-level split
    are the parts an analyst reads before trusting the verdict, and none of them
    survive being flattened into a single table cell.

    Unlike the command-line module there may be several payloads in one run, so
    each gets its own block inside the expander.

    Args:
        analysis: The ``waf_analysis`` list from ``run_results``. Anything falsy
            renders nothing at all.
    """
    if not analysis:
        return

    with st.expander("🛡️ WAF payload breakdown", expanded=True):
        for index, entry in enumerate(analysis, 1):
            if index > 1:
                st.divider()
            if len(analysis) > 1:
                st.markdown(f"**Payload {index} of {len(analysis)}**")

            path = entry.get("path")
            st.caption(f"Request path: **{path}**" if path else "Request path: *(none supplied)*")

            # The submitted payload comes first: everything below is a claim
            # about it, and decoding may have rewritten what the rules saw.
            st.caption("Payload submitted")
            st.code(entry.get("raw_payload") or "(empty)", language="text")

            if entry.get("was_encoded"):
                chain = " → ".join(entry.get("decode_chain") or []) or "unspecified"
                st.warning(f"Encoded — decoded via {chain}")
                st.caption("Decoded form")
                st.code(entry.get("decoded_payload") or "", language="text")

            markers = entry.get("markers") or []
            if markers:
                st.caption("Admitted by marker: " + ", ".join(f"`{m}`" for m in markers))

            # A curated fingerprint is the only single-source route to Malicious
            # (docs/waf_payload_analyzer.md D10), so it is stated before the CRS
            # detail rather than buried under it.
            fingerprint = entry.get("cve_fingerprint_match") or {}
            if fingerprint:
                st.error(
                    f"CVE fingerprint: **{fingerprint.get('name')}** "
                    f"({fingerprint.get('cve')})"
                )
                kev = fingerprint.get("kev")
                if kev is None:
                    st.caption(
                        "NVD/KEV enrichment not retrieved — the lookup did not complete. "
                        "This is not the same as 'not known-exploited'."
                    )
                elif kev:
                    st.caption("Listed in the CISA Known Exploited Vulnerabilities catalogue.")
                else:
                    st.caption("Not listed in the CISA KEV catalogue.")

            matches = entry.get("crs_matches") or []
            match_count = entry.get("crs_match_count", len(matches))
            if match_count:
                # PL1+PL2 is the deciding score (calibration C3): PL3/PL4 rules
                # count punctuation and fire on ordinary JSON and source code,
                # so showing the full score alone would misrepresent the verdict.
                st.markdown(
                    f"**OWASP CRS — {match_count} rule(s) matched.** "
                    f"Anomaly score {entry.get('crs_anomaly_score_pl12', 0):g} "
                    f"(PL1+PL2, decides the verdict) · "
                    f"{entry.get('crs_anomaly_score', 0):g} all levels · "
                    f"{entry.get('crs_anomaly_score_pl1', 0):g} PL1 only"
                )

                categories = entry.get("crs_categories") or []
                if categories:
                    st.markdown(
                        "Categories: "
                        + ", ".join(
                            _WAF_CATEGORY_LABELS.get(c, c) for c in sorted(categories)
                        )
                    )

                for match in matches:
                    label = _WAF_CATEGORY_LABELS.get(
                        match.get("category"), match.get("category", "")
                    )
                    st.markdown(
                        f"- `{match.get('rule_id')}` **{label}** "
                        f"[{match.get('severity')}, PL{match.get('paranoia_level')}, "
                        f"weight {match.get('severity_weight', 0):g}] — "
                        f"{match.get('message', '')} "
                        f"*(matched on {match.get('matched_on', 'raw')})*"
                    )
                    # Provenance, not decoration: a rule that was extracted
                    # without part of its logic will under-match, and an analyst
                    # reading the hit needs to know it was partial.
                    dropped = match.get("dropped_conditions") or []
                    if dropped:
                        st.caption("    Partial rule — " + "; ".join(dropped))

                if len(matches) < match_count:
                    st.caption(
                        f"Showing the {len(matches)} heaviest of {match_count} matches."
                    )
            elif entry.get("parse_ok", True):
                st.markdown("**OWASP CRS — no rule matched.**")

            # Every reason the result may be thinner than it looks, last, where
            # it qualifies everything above it.
            if not entry.get("parse_ok", True):
                st.caption("No payload followed the delimiter — there was nothing to analyse.")
            elif not entry.get("decode_ok", True):
                st.caption("Decoding did not complete; the decoded form above is partial.")
            if entry.get("crs_truncated"):
                st.caption("Payload exceeded the scan cap — only its head was matched.")

            skipped = entry.get("checks_skipped") or []
            if skipped:
                st.caption("Checks NOT performed: " + "; ".join(skipped))

            verdict = entry.get("aggregated_verdict", "Unknown")
            if verdict == "Unknown":
                st.caption(
                    "Verdict **Unknown** — nothing matched locally. This module never "
                    "returns Benign, so this is not a clean result."
                )
            else:
                st.caption(f"Verdict: **{verdict}** — local analysis, no provider lookup.")


def render_results_output(output_format: str, run_results: dict) -> None:
    """Render the results section: summary metrics + selected output format."""
    summary = run_results["summary"]
    rows = run_results["rows"]
    vt_results = run_results["vt"]
    urlscan_results = run_results["urlscan"]
    abuse_results = run_results["abuse"]
    tf_results = run_results["tf"]
    mb_results = run_results["mb"]
    ha_results = run_results.get("ha", {})
    shodan_results = run_results.get("shodan", {})
    dnsd_results = run_results.get("dnsd", {})
    mxtoolbox_results = run_results.get("mxtoolbox", {})
    whoxy_results = run_results.get("whoxy", {})
    ransomware_live_results = run_results.get("ransomware_live", {})

    # Process/filepath analysis contributes one row per submitted field, using
    # the same column schema so the table needs no special-casing. Kept separate
    # from `rows` upstream because that list is one-entry-per-atomic-IOC.
    process_rows = run_results.get("process_rows") or []
    # WAF payload rows share that same column schema (asserted by a test), and
    # are likewise kept out of `rows` upstream — see docs/waf_payload_analyzer.md
    # D6, where letting them into it would add evidence-free rows and inflate
    # the session counts.
    waf_rows = run_results.get("waf_rows") or []
    table_rows = rows + process_rows + waf_rows


    if output_format == "Table":
        if pd:
            df = pd.DataFrame(table_rows)

            if "ActiveProviders" in df.columns:
                df["ActiveProviders"] = df["ActiveProviders"].apply(
                    lambda v: ", ".join(v) if isinstance(v, (list, tuple)) else ("" if v is None else str(v))
                )

            def _style_row(row: "pd.Series") -> list[str]:
                """Apply white background to every cell, color only the Verdict cell.

                Args:
                    row: A row from the results DataFrame.

                Returns:
                    A list of CSS strings, one per column in the row.
                """
                verdict = row.get("Verdict", "")
                verdict_palette = {
                    "Malicious":  ("#fde2e2", "#b42318"),
                    "Suspicious": ("#fdecc8", "#8a5a00"),
                    "Benign":     ("#e4f5e7", "#1a7f37"),
                    "Unknown":    ("#eef0f3", "#3a3f47"),
                }
                styles = ["background-color: #ffffff; color: #1f2937"] * len(row)
                if verdict in verdict_palette:
                    bg, fg = verdict_palette[verdict]
                    try:
                        idx = list(row.index).index("Verdict")
                        styles[idx] = (
                            f"background-color: {bg}; color: {fg}; "
                            f"font-weight: 600"
                        )
                    except ValueError:
                        pass
                return styles

            styled = (
                df.style
                .apply(_style_row, axis=1)
                .set_table_styles(
                    [
                        {
                            "selector": "thead th",
                            "props": [
                                ("background-color", "#ffffff"),
                                ("color", "#1f2937"),
                                ("border-bottom", "1px solid #e5e7eb"),
                                ("font-weight", "600"),
                            ],
                        },
                        {
                            "selector": "tbody td",
                            "props": [("border-bottom", "1px solid #f1f3f5")],
                        },
                    ]
                )
            )
            st.dataframe(styled, use_container_width=True)
        else:
            st.dataframe(table_rows, use_container_width=True)

    elif output_format == "JSON":
        payload = {"summary": summary, "rows": rows}
        if run_results.get("process_analysis"):
            payload["process_analysis"] = run_results["process_analysis"]
        if run_results.get("cmdline_analysis"):
            payload["cmdline_analysis"] = run_results["cmdline_analysis"]
        if run_results.get("waf_analysis"):
            payload["waf_analysis"] = run_results["waf_analysis"]
        st.json(payload)

    elif output_format == "Shareable Text":
        _st_text = st.session_state.get("share_text", "")
        if _st_text:
            _st_b64 = base64.b64encode(_st_text.encode("utf-8")).decode("ascii")
            st.text_area("", value=_st_text, height=420, key="shareable_text_area", label_visibility="collapsed")
            _st_html = f"""
            <style>
              .copy-wrap{{display:flex;align-items:center;gap:8px;margin-top:4px}}
              .copy-btn{{padding:5px 12px;border:1px solid #555;border-radius:6px;background:#23272f;color:#f5f7fb;cursor:pointer;font-size:0.9rem}}
              .copy-msg{{color:#4ade80;font-size:0.82rem}}
            </style>
            <div class="copy-wrap">
              <button class="copy-btn" id="st_copy_btn">Copy Report</button>
              <span class="copy-msg" id="st_copy_msg"></span>
            </div>
            <script>
              (function(){{
                var btn=document.getElementById("st_copy_btn");
                var msg=document.getElementById("st_copy_msg");
                if(btn){{btn.addEventListener("click",function(){{
                  navigator.clipboard.writeText(atob("{_st_b64}")).then(function(){{msg.textContent="Copied!"}});
                }})}}
              }})();
            </script>
            """
            components.html(_st_html, height=50)
        else:
            st.info("Run analysis first to generate shareable text.")

    else:
        # ── Ticket notes ──────────────────────────────────────────────────────
        def _vt_line(val: str) -> str:
            vt = vt_results.get(val, {})
            stats = vt.get("stats", {})
            total = sum(stats.values()) if stats else 0
            mal = stats.get("malicious", 0)
            if total == 0:
                return "VirusTotal: No data"
            return f"VirusTotal: {mal}/{total} malicious"

        def _abuse_line(val: str) -> str:
            ab = abuse_results.get(val, {})
            if not ab or ab.get("error") or ab.get("abuseConfidenceScore") is None:
                return "AbuseIPDB: No data"
            return (
                f"AbuseIPDB: Confidence {ab.get('abuseConfidenceScore', 0)}%, "
                f"{ab.get('totalReports', 0)} reports, "
                f"last seen {ab.get('lastReportedAt') or 'unknown'}"
            )

        def _urlscan_line(val: str) -> str:
            us = urlscan_results.get(val, {})
            if not us:
                return "URLScan: No data"
            verdicts = us.get("verdicts", {}) or {}
            engines = 0
            if isinstance(verdicts, dict):
                for k, v in verdicts.items():
                    if v is None:
                        continue
                    if isinstance(v, dict):
                        if v.get("malicious") or v.get("suspicious") or v.get("score", 0) > 0:
                            engines += 1
                    elif isinstance(v, bool):
                        if v:
                            engines += 1
            if engines == 0:
                return "URLScan: No data"
            return f"URLScan: {engines} engine(s) detected"

        def _tf_line(val: str) -> str:
            tf = tf_results.get(val, {})
            if not tf:
                return "ThreatFox: No data"
            if tf.get("error"):
                return "ThreatFox: No data"
            if tf.get("query_status") and tf.get("query_status") != "ok":
                return "ThreatFox: No data"
            count = len(tf.get("data", []))
            return f"ThreatFox: {count} match(es)"

        def _mb_line(val: str) -> str:
            mb = mb_results.get(val, {})
            if not mb:
                return "MalwareBazaar: No data"
            if mb.get("error"):
                return "MalwareBazaar: No data"
            if mb.get("query_status") and mb.get("query_status") != "ok":
                return "MalwareBazaar: No data"
            count = len(mb.get("data", []))
            return f"MalwareBazaar: {count} match(es)"

        def _ha_line(val: str) -> str:
            ha = ha_results.get(val, {})
            if not ha:
                return "Hybrid Analysis: No data"
            message = str(ha.get("message") or "").strip()
            if message:
                return "Hybrid Analysis: No data"
            verdict = ha.get("verdict") or ""
            score = ha.get("threat_score") or ""
            family = ha.get("malware_family") or ""
            parts = []
            if verdict:
                parts.append(f"verdict={verdict}")
            if score:
                parts.append(f"threat_score={score}")
            if family:
                parts.append(f"family={family}")
            if not parts:
                return "Hybrid Analysis: No data"
            return f"Hybrid Analysis: {', '.join(parts)}"

        def _shodan_line(val: str) -> str:
            sh = shodan_results.get(val, {})
            if not sh or sh.get("error"):
                return "Shodan: No data"
            ports = sh.get("ports") or []
            vulns = sh.get("vulns") or []
            tags = sh.get("tags") or []
            risk = (sh.get("risk_summary") or {}).get("risk_level") or "UNKNOWN"
            if not ports and not vulns and not tags and risk == "UNKNOWN":
                return "Shodan: No data"
            parts = [risk, f"{len(ports)} port(s)"]
            if vulns:
                parts.append(f"{len(vulns)} CVE(s)")
            if tags:
                tag_str = ",".join(tags[:3]) + ("…" if len(tags) > 3 else "")
                parts.append(tag_str)
            queried_ip = sh.get("queriedIp") or ""
            if queried_ip:
                try:
                    from core.geo import fetch_geo_ip_api
                    geo = fetch_geo_ip_api(queried_ip) or {}
                    country = geo.get("country") or ""
                    if country:
                        parts.append(country)
                except Exception:
                    pass
            return "Shodan: " + ", ".join(parts)

        def _mx_line(val: str) -> str:
            mx = mxtoolbox_results.get(val, {})
            if not mx or mx.get("error"):
                return "MxToolBox: No data"
            verdict = mx.get("verdict") or "UNKNOWN"
            failed = mx.get("total_failed", 0)
            warnings = mx.get("total_warnings", 0)
            passed = mx.get("total_passed", 0)
            return f"MxToolBox: {verdict} — {failed} fail, {warnings} warn, {passed} pass"

        def _whoxy_line(val: str) -> str:
            wx = whoxy_results.get(val, {})
            if not wx or wx.get("error"):
                return "Whoxy: No data"
            rev = wx.get("reverse_whois") or {}
            total = rev.get("total_results", 0)
            if wx.get("mode") == "keyword":
                if total == 0:
                    return "Whoxy: No domains found for keyword"
                return f"Whoxy (keyword): {total} domain(s) found"
            whois = wx.get("whois") or {}
            registrar = whois.get("registrar") or ""
            reg_email = whois.get("registrant_email") or ""
            created = whois.get("created_date") or ""
            parts = []
            if registrar:
                parts.append(f"registrar={registrar}")
            if created:
                parts.append(f"created={created[:10]}")
            if reg_email:
                parts.append(f"email={reg_email}")
            if total:
                parts.append(f"{total} related domain(s)")
            if not parts:
                return "Whoxy: No data"
            return "Whoxy: " + ", ".join(parts)

        def _dd_line(val: str) -> str:
            dd = dnsd_results.get(val, {})
            if not dd or dd.get("error"):
                return "DNSDumpster: No data"
            summary_dd = dd.get("soc_summary") or {}
            a_recs = summary_dd.get("a_records") or []
            red_flags = summary_dd.get("red_flags") or []
            ip_count = len(a_recs)
            flag_str = f", {len(red_flags)} flag(s)" if red_flags else ""
            if ip_count == 0:
                return "DNSDumpster: No data"
            first_ip = a_recs[0].get("ip", "")
            country = a_recs[0].get("country", "")
            geo = f" ({country})" if country else ""
            return f"DNSDumpster: {ip_count} IP(s), e.g. {first_ip}{geo}{flag_str}"

        def _rl_line(val: str) -> str:
            rl = ransomware_live_results.get(val, {})
            if not rl or rl.get("error"):
                return "Ransomware Live: No data"
            count = rl.get("count", 0)
            if count == 0:
                return "Ransomware Live: No victims found"
            victims = rl.get("victims") or []
            groups = list({v.get("group_name") for v in victims if v.get("group_name")})
            group_str = ", ".join(groups[:3]) + ("…" if len(groups) > 3 else "")
            queries = rl.get("queries") or []
            q_str = " + ".join(f'"{q}"' for q in queries) if queries else val
            if groups:
                return f"Ransomware Live: {count} victim(s) matched [{q_str}] — group(s): {group_str}"
            return f"Ransomware Live: {count} victim(s) matched [{q_str}]"

        def _indicator_conclusion(verdict: str) -> str:
            if verdict == "Malicious":
                return "Confirmed phishing"
            if verdict in {"Unknown", "Benign"}:
                return "No malicious indicator was found"
            return f"{verdict} indicator"

        pf = run_results.get("provider_flags") or {}
        allowed_by_type_raw = run_results.get("allowed_by_type") or {}
        allowed_by_type: dict[str, set[str]] = {
            t: set(ps) for t, ps in allowed_by_type_raw.items()
        }

        def _add(notes_list: list, ioc_type: str, provider: str, line: str) -> None:
            allowed = allowed_by_type.get(ioc_type)
            if allowed is None:
                if not pf.get(provider, True):
                    return
            elif provider not in allowed:
                return
            notes_list.append(line)

        # Rows produced by the local analyzers rather than by a provider. They
        # carry the same column schema but no provider data, so they take a
        # single generic branch instead of a per-provider one.
        _LOCAL_ROW_HEADINGS = {
            "file_path": "#File Path",
            "process": "#Process",
            "parent_child_pair": "#Parent-Child Pair",
            "command_line": "#Command Line",
            "waf_payload": "#WAF Payload",
        }

        # Conclusions for the WAF rows, built from the structured analysis
        # rather than by parsing the Evidence string back apart. waf_rows and
        # waf_analysis are produced in the same order, one row per payload.
        def _waf_conclusion(entry: dict) -> str:
            verdict = entry.get("aggregated_verdict", "Unknown")
            fingerprint = entry.get("cve_fingerprint_match") or {}
            if fingerprint:
                return (
                    f"{verdict} — {fingerprint.get('name')} "
                    f"({fingerprint.get('cve')}) exploitation attempt"
                )
            stats = entry.get("crs_category_stats") or {}
            decided = sorted(
                c for c, s in stats.items() if s.get("weight_pl12", 0)
            )
            if decided:
                labels = ", ".join(_WAF_CATEGORY_LABELS.get(c, c) for c in decided)
                return f"{verdict} — {labels} pattern"
            if not entry.get("parse_ok", True):
                return "Unknown — no payload supplied"
            return "Unknown — no known attack pattern matched"

        _waf_conclusions = iter([
            _waf_conclusion(e) for e in (run_results.get("waf_analysis") or [])
        ])

        # Detail lines for the command-line rows. The row itself carries only
        # the parsed statement, a verdict and one evidence string — everything
        # the breakdown expander shows (what was actually submitted, the decode
        # chain that rewrote it, the parsed structure) was absent from the
        # ticket, which is the artefact that leaves the tool. Built from
        # ``cmdline_analysis`` rather than re-parsed out of the row.
        def _cmdline_details(analysis: dict) -> list[list[str]]:
            """Return the extra ticket lines for each command-line row.

            Args:
                analysis: The ``cmdline_analysis`` dict from ``run_results``.

            Returns:
                One list of lines per parsed statement, aligned with the order
                ``core.cmdline_analyzer.to_rows`` emits its rows in.
            """
            commands = analysis.get("commands") or []
            if not commands:
                return []

            # Run-wide context belongs on the first statement only; repeating it
            # per statement would pad a ticket with identical lines.
            shared: list[str] = []
            interpreter = analysis.get("interpreter_detected") or "unknown"
            shared.append(f"Interpreter: {interpreter}")

            submitted = analysis.get("original_command")
            if submitted and analysis.get("was_obfuscated"):
                # The Artifact line shows the decoded statement, so without this
                # the ticket never records what the analyst actually observed.
                shared.append(f"Submitted: {_truncate_note(submitted)}")
                chain = " -> ".join(analysis.get("decode_chain") or []) or "unspecified"
                shared.append(f"Obfuscated: decoded via {chain}")
                revealed = analysis.get("revealed_keywords") or []
                if revealed:
                    shared.append("Revealed only after decoding: " + ", ".join(revealed))

            if not analysis.get("parse_ok"):
                shared.append(
                    "Parsing: best-effort — the line was malformed, so the "
                    "structure below is incomplete"
                )

            cross = analysis.get("cross_reference") or {}
            if cross.get("applied") and cross.get("note"):
                shared.append(f"Cross-reference: {cross['note']}")

            lolbas = analysis.get("lolbas_cross_check") or {}
            if lolbas.get("match_strength") == "CONFIRMED_ABUSE_PATTERN":
                shared.append(
                    f"LOLBAS: {lolbas.get('binary')} arguments match its documented "
                    f"{lolbas.get('category') or 'abuse'} pattern — {lolbas.get('matched')}"
                )
            elif lolbas.get("match_strength") == "DUAL_USE_PRESENT":
                shared.append(
                    f"LOLBAS: {lolbas.get('binary')} is dual-use, but its arguments match "
                    "no documented abuse pattern"
                )

            out: list[list[str]] = []
            for index, command in enumerate(commands):
                lines = list(shared) if index == 0 else []
                structure = [f"base={command.get('base_command', '')}"]
                flags = command.get("flags") or []
                arguments = command.get("arguments") or []
                if flags:
                    structure.append("flags=" + ", ".join(flags))
                if arguments:
                    structure.append("arguments=" + ", ".join(arguments))
                lines.append("Structure: " + _truncate_note(" | ".join(structure)))
                out.append(lines)
            return out

        _cmdline_detail_lines = iter(
            _cmdline_details(run_results.get("cmdline_analysis") or {})
        )

        notes = []
        # Ticket notes previously iterated `rows` alone, which silently omitted
        # every finding from the process, command-line and WAF modules — all
        # three keep their rows outside `rows` on purpose (see
        # docs/waf_payload_analyzer.md D6). This is the app's *default* output
        # format, so an analyst pasting it into a ticket was handing over an
        # incomplete picture without any sign that something was missing.
        for row in list(rows) + list(process_rows) + list(waf_rows):
            t = row["Type"]
            val = row["Artifact"]
            verdict = row["Verdict"]
            if t in _LOCAL_ROW_HEADINGS:
                notes.append(_LOCAL_ROW_HEADINGS[t])
                notes.append(f"Artifact: {val}")
                if t == "command_line":
                    notes.extend(next(_cmdline_detail_lines, []))
                notes.append(f"Evidence: {row.get('Primary Evidence', '')}")
                # "Local (…)" already says no provider was consulted, so the
                # conclusion does not repeat it — it names what was found.
                notes.append(f"Source: {row.get('Sources', '')}")
                if t == "waf_payload":
                    conclusion = next(_waf_conclusions, verdict)
                elif verdict == "Unknown":
                    conclusion = "Unknown — nothing matched locally"
                else:
                    conclusion = verdict
                notes.append(f"Conclusion: {conclusion}")
                notes.append("")
                continue
            if t == "ip":
                notes.append("#IP")
                notes.append(f"IP: {val}")
                _add(notes, t, "abuse",     _abuse_line(val))
                _add(notes, t, "vt",        _vt_line(val))
                _add(notes, t, "tf",        _tf_line(val))
                _add(notes, t, "shodan",    _shodan_line(val))
                _add(notes, t, "ha",        _ha_line(val))
                _add(notes, t, "mxtoolbox", _mx_line(val))
                notes.append("Conclusion: " + ("Malicious IP, confirmed suspicious activity" if verdict == "Malicious" else f"{verdict} IP"))
            elif t == "hash":
                notes.append("#Hash")
                notes.append(f"Hash: {val}")
                _add(notes, t, "vt", _vt_line(val))
                _add(notes, t, "tf", _tf_line(val))
                _add(notes, t, "mb", _mb_line(val))
                _add(notes, t, "ha", _ha_line(val))
                notes.append("Conclusion: " + ("Confirmed malware" if verdict == "Malicious" else f"{verdict} file"))
            elif t == "domain":
                notes.append("#Domain")
                notes.append(f"Domain: {val}")
                _add(notes, t, "urlscan",        _urlscan_line(val))
                _add(notes, t, "vt",             _vt_line(val))
                _add(notes, t, "tf",             _tf_line(val))
                _add(notes, t, "shodan",         _shodan_line(val))
                _add(notes, t, "ha",             _ha_line(val))
                _add(notes, t, "dns",            _dd_line(val))
                _add(notes, t, "mxtoolbox",      _mx_line(val))
                notes.append("Conclusion: " + _indicator_conclusion(verdict))
            elif t == "url":
                notes.append("#URL")
                notes.append(f"URL: {val}")
                _add(notes, t, "urlscan",        _urlscan_line(val))
                _add(notes, t, "vt",             _vt_line(val))
                _add(notes, t, "tf",             _tf_line(val))
                _add(notes, t, "shodan",         _shodan_line(val))
                _add(notes, t, "ha",             _ha_line(val))
                _add(notes, t, "dns",            _dd_line(val))
                _add(notes, t, "mxtoolbox",      _mx_line(val))
                notes.append("Conclusion: " + _indicator_conclusion(verdict))
            elif t == "email":
                notes.append("#Email")
                notes.append(f"Email: {val}")
                _add(notes, t, "vt",        _vt_line(val))
                _add(notes, t, "tf",        _tf_line(val))
                _add(notes, t, "ha",        _ha_line(val))
                _add(notes, t, "mxtoolbox", _mx_line(val))
                notes.append("Conclusion: " + _indicator_conclusion(verdict))
            elif t == "whois":
                notes.append("#Whois Keyword")
                notes.append(f"Keyword: {val}")
                _add(notes, t, "whoxy",           _whoxy_line(val))
                _add(notes, t, "ransomware_live", _rl_line(val))
                notes.append("Conclusion: " + _indicator_conclusion(verdict))
            notes.append("")
        notes_text = "\n".join(notes)
        st.code(notes_text, language="text")
