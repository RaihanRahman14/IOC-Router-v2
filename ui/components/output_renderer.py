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


def _render_session_threat_panel(summary: dict) -> None:
    """Render the session-level threat score panel above the metric strip.

    Reads `summary["session_summary"]` produced by
    `ioc.confidence_scorer.compute_session_summary`. Renders nothing if the
    summary is missing or empty (graceful fallback for older sessions).

    Args:
        summary: The aggregated summary dict returned by `summarize_results`.
    """
    sess = summary.get("session_summary") or {}
    if not sess:
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

    html = (
        f"<div style='background:{bg};border:1px solid {accent};border-radius:10px;"
        f"padding:14px 18px;margin:6px 0 14px 0;overflow:hidden;'>"
        f"  <div style='display:flex;justify-content:space-between;align-items:flex-start;"
        f"flex-wrap:wrap;gap:10px;'>"
        f"    <div style='min-width:0;flex:1 1 auto;'>"
        f"      <div style='font-size:0.78rem;letter-spacing:0.08em;text-transform:uppercase;"
        f"color:#9ea8cf;'>Session Threat Score</div>"
        f"      <div style='font-size:2.1rem;font-weight:700;color:{accent};line-height:1.1;'>"
        f"{highest:.1f}<span style='font-size:0.9rem;color:#9ea8cf;'> / 100</span></div>"
        f"      <div style='font-size:0.95rem;color:#e8eaf0;margin-top:2px;'>{label}</div>"
        f"    </div>"
        f"    <div style='text-align:right;min-width:0;flex:1 1 180px;max-width:100%;'>"
        f"      <div style='font-size:0.78rem;color:#9ea8cf;'>Highest IOC</div>"
        f"      <div style='font-family:monospace;color:#e8eaf0;font-size:0.85rem;"
        f"word-break:break-all;overflow-wrap:anywhere;'>"
        f"{highest_ioc}</div>"
        f"    </div>"
        f"  </div>"
        f"  <div style='background:#0f1117;border-radius:6px;height:8px;margin-top:10px;"
        f"overflow:hidden;'>"
        f"    <div style='background:{accent};width:{fill_pct:.1f}%;height:100%;"
        f"transition:width 0.3s;'></div>"
        f"  </div>"
        f"  <div style='margin-top:10px;display:flex;flex-wrap:wrap;gap:6px;'>{dist_pills}</div>"
        f"</div>"
    )
    st.markdown(html, unsafe_allow_html=True)


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

    col_sum = st.columns(5)
    col_sum[0].metric("Total", summary["total"])
    col_sum[1].metric("Malicious", summary["malicious"])
    col_sum[2].metric("Suspicious", summary["suspicious"])
    col_sum[3].metric("Unknown", summary["unknown"])
    col_sum[4].metric("Benign", summary["benign"])

    _render_session_threat_panel(summary)

    if output_format == "Table":
        if pd:
            df = pd.DataFrame(rows)

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
            st.dataframe(rows, use_container_width=True)

    elif output_format == "JSON":
        st.json({"summary": summary, "rows": rows})

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

        notes = []
        for row in rows:
            t = row["Type"]
            val = row["Artifact"]
            verdict = row["Verdict"]
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
