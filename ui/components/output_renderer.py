"""Results output format rendering — metrics, table, JSON, shareable text, ticket notes."""
from __future__ import annotations

import base64

import streamlit as st
import streamlit.components.v1 as components

try:
    import pandas as pd
except Exception:
    pd = None


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
    """Render the full-width session hero block: score panel + count cards.

    Combines the session-level threat score (left) with the verdict counts
    (right) into a single block intended to span the full Result-tab width,
    sitting above the split columns. Falls back to a counts-only block when
    no session summary is present (older runs).

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
    label = sess.get("session_label") or "Unknown"
    highest_ioc = sess.get("highest_ioc") or "—"
    distribution = sess.get("verdict_distribution") or {}

    bg, accent = _score_color(highest)
    fill_pct = max(0.0, min(100.0, highest))

    dist_pills = "".join(
        f"<span style='background:#1e1e2e;border:1px solid #333;border-radius:999px;"
        f"padding:2px 10px;margin-right:6px;font-size:0.78rem;color:#cfd3dc;'>"
        f"{verd}: <b style='color:{accent};'>{cnt}</b></span>"
        for verd, cnt in distribution.items()
    )

    left_html = (
        f"<div style='font-size:0.78rem;letter-spacing:0.08em;text-transform:uppercase;"
        f"color:#9ea8cf;'>Session Threat Score</div>"
        f"<div style='display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-top:4px;'>"
        f"  <div style='font-size:1.85rem;font-weight:700;color:{accent};line-height:1.1;'>{label}</div>"
        f"  <span style='background:#0f1117;border:1px solid {accent};color:{accent};"
        f"border-radius:999px;padding:3px 12px;font-size:0.82rem;font-weight:600;'>"
        f"score {highest:.1f} / 100</span>"
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
        f"<div style='margin-top:10px;display:flex;flex-wrap:wrap;gap:6px;'>{dist_pills}</div>"
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
                notes.append(f"Evidence: {row.get('Primary Evidence', '')}")
                notes.append(f"Source: {row.get('Sources', '')} (no provider lookup)")
                notes.append(
                    "Conclusion: "
                    + (
                        f"{verdict} — local analysis only, not corroborated by a provider"
                        if verdict != "Unknown"
                        else "Unknown — nothing matched locally; this is not a clean result"
                    )
                )
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
