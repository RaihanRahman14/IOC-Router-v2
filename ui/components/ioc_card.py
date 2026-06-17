"""Per-IOC expandable detail cards — all 8 provider tabs."""
from __future__ import annotations

import re
from datetime import datetime

import streamlit as st
import streamlit.components.v1 as components

from core.geo import fetch_geo_ip_api, fetch_nominatim
from ui.components.map import build_osm_map_html

# Common port → (service name, short description)
_PORT_INFO: dict[int, tuple[str, str]] = {
    21:   ("FTP",           "File Transfer Protocol — upload/download files"),
    22:   ("SSH",           "Secure Shell — encrypted remote login & tunneling"),
    23:   ("Telnet",        "Unencrypted remote shell — legacy, highly insecure"),
    25:   ("SMTP",          "Mail Transfer — sending email between servers"),
    53:   ("DNS",           "Domain Name System — hostname ↔ IP resolution"),
    80:   ("HTTP",          "Web traffic — plain-text, no encryption"),
    110:  ("POP3",          "Post Office Protocol — mail retrieval (plain-text)"),
    137:  ("NetBIOS-NS",    "NetBIOS Name Service — Windows name resolution"),
    138:  ("NetBIOS-DGM",   "NetBIOS Datagram — Windows broadcast messaging"),
    139:  ("NetBIOS-SSN",   "NetBIOS Session / SMB — Windows file & print sharing"),
    143:  ("IMAP",          "Internet Message Access Protocol — mail access"),
    443:  ("HTTPS",         "Web traffic over TLS — encrypted HTTP"),
    445:  ("SMB",           "Server Message Block — Windows file sharing (direct TCP)"),
    548:  ("AFP",           "Apple Filing Protocol — macOS file sharing"),
    587:  ("SMTP/STARTTLS", "Mail submission — client-to-server, encrypted"),
    993:  ("IMAPS",         "IMAP over TLS — encrypted mail access"),
    995:  ("POP3S",         "POP3 over TLS — encrypted mail retrieval"),
    1433: ("MSSQL",         "Microsoft SQL Server database"),
    1701: ("L2TP",          "Layer 2 Tunneling Protocol — VPN tunneling"),
    1723: ("PPTP",          "Point-to-Point Tunneling Protocol — legacy VPN"),
    2052: ("Cloudflare",    "Cloudflare proxy port (HTTP alternative)"),
    2053: ("Cloudflare",    "Cloudflare proxy port (HTTPS alternative)"),
    2082: ("cPanel",        "cPanel web hosting control panel"),
    2083: ("cPanel TLS",    "cPanel control panel over TLS"),
    2086: ("WHM",           "Web Host Manager — server admin panel"),
    2087: ("WHM TLS",       "WHM admin panel over TLS"),
    2095: ("cPanel Webmail","cPanel webmail interface"),
    2096: ("cPanel Webmail","cPanel webmail over TLS"),
    3306: ("MySQL",         "MySQL / MariaDB database"),
    3389: ("RDP",           "Remote Desktop Protocol — Windows GUI remote access"),
    5432: ("PostgreSQL",    "PostgreSQL database"),
    5900: ("VNC",           "Virtual Network Computing — remote desktop"),
    6379: ("Redis",         "Redis in-memory data store / cache"),
    8008: ("HTTP-alt",      "HTTP alternative port — often used by proxies & IoT"),
    8080: ("HTTP-alt",      "HTTP alternative / reverse proxy / dev server"),
    8443: ("HTTPS-alt",     "HTTPS alternative — common for admin panels & APIs"),
    8880: ("HTTP-alt",      "HTTP alternative — used by Plesk control panel"),
    9200: ("Elasticsearch", "Elasticsearch REST API — search & analytics engine"),
    27017:("MongoDB",       "MongoDB NoSQL database"),
}


# Ports that should never be publicly exposed, mapped to their risk category
_RISKY_PORTS: dict[int, str] = {
    # Remote Management
    20:   "Remote Management",
    21:   "Remote Management",
    22:   "Remote Management",
    23:   "Remote Management",
    3389: "Remote Management",
    # Database
    1433: "Database",
    3306: "Database",
    5432: "Database",
    6379: "Database",
    # File Sharing & Internal Network
    137:  "File Sharing & Internal Network",
    138:  "File Sharing & Internal Network",
    139:  "File Sharing & Internal Network",
    161:  "File Sharing & Internal Network",
    162:  "File Sharing & Internal Network",
    445:  "File Sharing & Internal Network",
}


def _ports_table(ports: list[int]) -> None:
    """Render open ports as HTML table. Risky ports are red; safe open ports are green."""
    rows = []
    for p in sorted(ports):
        svc, desc = _PORT_INFO.get(p, ("Unknown", "—"))
        risky = p in _RISKY_PORTS
        rows.append((p, svc, desc, risky))

    header = (
        "<tr style='background:#1e1e2e;color:#9ea8cf;font-size:0.78rem;text-transform:uppercase;"
        "letter-spacing:0.05em;'>"
        "<th style='padding:6px 12px;text-align:right;width:70px;'>Port</th>"
        "<th style='padding:6px 12px;text-align:left;width:130px;'>Service</th>"
        "<th style='padding:6px 12px;text-align:left;'>Description</th>"
        "<th style='padding:6px 12px;text-align:center;width:90px;'>Risk</th>"
        "</tr>"
    )
    body_rows = []
    for port, svc, desc, risky in rows:
        if risky:
            row_bg   = "#2e1a1a"
            port_clr = "#f87171"
            desc_clr = "#d08080"
            risk_cell = "<td style='padding:5px 12px;text-align:center;color:#f87171;font-weight:700;'>⚠ High</td>"
        else:
            row_bg   = "#1a2e1a"
            port_clr = "#4ade80"
            desc_clr = "#a0d8a0"
            risk_cell = "<td style='padding:5px 12px;text-align:center;color:#4ade80;'>✓ Open</td>"
        body_rows.append(
            f"<tr style='background:{row_bg};'>"
            f"<td style='padding:5px 12px;text-align:right;font-family:monospace;"
            f"font-weight:700;color:{port_clr};'>{port}</td>"
            f"<td style='padding:5px 12px;font-weight:600;color:#e8eaf0;'>{svc}</td>"
            f"<td style='padding:5px 12px;color:{desc_clr};font-size:0.9em;'>{desc}</td>"
            f"{risk_cell}"
            f"</tr>"
        )
    html = (
        "<div style='overflow-x:auto;margin:6px 0 12px 0;'>"
        "<table style='border-collapse:collapse;width:100%;font-size:0.88rem;"
        "border:1px solid #333;border-radius:6px;overflow:hidden;'>"
        f"<thead>{header}</thead>"
        f"<tbody>{''.join(body_rows)}</tbody>"
        "</table></div>"
    )
    st.markdown(html, unsafe_allow_html=True)


def _vuln_warnings_for_ports(ports: list[int]) -> list[str]:
    """Return vulnerability warning strings for any risky ports found open."""
    warnings = []
    for p in sorted(ports):
        if p in _RISKY_PORTS:
            svc, _ = _PORT_INFO.get(p, ("Unknown", ""))
            category = _RISKY_PORTS[p]
            warnings.append(f"Vulnerable open port: {p} ({svc}) [{category}]")
    return warnings


def _confidence_score_color(score: float) -> tuple[str, str]:
    """Return (background, accent) hex colors for a 0–100 score, matching the panel above."""
    if score >= 70:
        return "#3a1414", "#f87171"
    if score >= 40:
        return "#3a2a14", "#fbbf24"
    if score >= 10:
        return "#1e2236", "#60a5fa"
    return "#14321a", "#4ade80"


def _render_confidence_score_card(row: dict) -> None:
    """Render the per-IOC confidence-score card inside an IOC expander.

    Reads the `ConfidenceScore` family of fields added by `summarize_results`.
    Renders nothing if those fields are missing (graceful fallback).

    Args:
        row: A single row dict from `run_results["rows"]`.
    """
    if not row or row.get("ConfidenceScore") is None:
        return

    score = float(row.get("ConfidenceScore") or 0.0)
    label = row.get("ConfidenceLabel") or "Unknown"
    verdict_score = row.get("VerdictFromScore") or "Unknown"
    provider_scores = row.get("ProviderScores") or {}
    active = row.get("ActiveProviders") or []
    infra_note = row.get("InfraNote")

    bg, accent = _confidence_score_color(score)
    fill_pct = max(0.0, min(100.0, score))

    provider_rows = "".join(
        f"<tr>"
        f"<td style='padding:3px 10px 3px 0;color:#cfd3dc;font-size:0.85rem;'>{p}</td>"
        f"<td style='padding:3px 0;width:100%;'>"
        f"  <div style='background:#0f1117;border-radius:4px;height:6px;overflow:hidden;'>"
        f"    <div style='background:{accent};"
        f"width:{min(100.0, float(provider_scores.get(p, 0))):.1f}%;height:100%;'></div>"
        f"  </div>"
        f"</td>"
        f"<td style='padding:3px 0 3px 10px;color:{accent};font-family:monospace;"
        f"font-size:0.85rem;text-align:right;min-width:55px;'>"
        f"{float(provider_scores.get(p, 0)):.1f}</td>"
        f"</tr>"
        for p in active
    )

    infra_block = (
        f"<div style='margin-top:8px;padding:6px 10px;background:#1e1e2e;"
        f"border-left:3px solid {accent};border-radius:4px;font-size:0.82rem;color:#cfd3dc;'>"
        f"<b style='color:{accent};'>Infra:</b> {infra_note}</div>"
        if infra_note else ""
    )

    table_block = (
        f"<table style='width:100%;border-collapse:collapse;margin-top:8px;'>"
        f"{provider_rows}</table>"
        if provider_rows
        else "<div style='color:#9ea8cf;font-size:0.85rem;margin-top:8px;'>"
             "No active providers.</div>"
    )

    html = (
        f"<div style='background:{bg};border:1px solid {accent};border-radius:8px;"
        f"padding:12px 14px;margin-bottom:12px;overflow:hidden;'>"
        f"  <div style='display:flex;justify-content:space-between;align-items:flex-start;"
        f"flex-wrap:wrap;gap:8px;'>"
        f"    <div style='min-width:0;'>"
        f"      <div style='font-size:0.72rem;letter-spacing:0.08em;text-transform:uppercase;"
        f"color:#9ea8cf;'>Confidence Score</div>"
        f"      <div style='font-size:1.6rem;font-weight:700;color:{accent};line-height:1.2;"
        f"word-break:break-word;'>"
        f"{score:.1f}<span style='font-size:0.8rem;color:#9ea8cf;'> / 100</span>"
        f"      <span style='font-size:0.8rem;color:#cfd3dc;margin-left:10px;"
        f"display:inline-block;'>"
        f"({label} · {verdict_score})</span></div>"
        f"    </div>"
        f"  </div>"
        f"  <div style='background:#0f1117;border-radius:6px;height:6px;margin-top:8px;"
        f"overflow:hidden;'>"
        f"    <div style='background:{accent};width:{fill_pct:.1f}%;height:100%;'></div>"
        f"  </div>"
        f"  {table_block}"
        f"  {infra_block}"
        f"</div>"
    )
    st.markdown(html, unsafe_allow_html=True)


def render_ioc_cards(run_results: dict) -> None:
    """Render one expandable detail card per IOC with per-provider tabs."""
    items = run_results["items"]
    vt_results = run_results["vt"]
    urlscan_results = run_results["urlscan"]
    abuse_results = run_results["abuse"]
    shodan_results = run_results.get("shodan", {})
    tf_results = run_results["tf"]
    mb_results = run_results["mb"]
    dnsd_results = run_results.get("dnsd", {})
    ha_results = run_results.get("ha", {})
    mxtoolbox_results = run_results.get("mxtoolbox", {})
    whoxy_results = run_results.get("whoxy", {})
    ransomware_live_results = run_results.get("ransomware_live", {})
    rows_by_value: dict[str, dict] = {
        r.get("Artifact"): r for r in (run_results.get("rows") or [])
    }

    def _urlscan_screenshot_url(us: dict) -> str:
        if not us:
            return ""
        if us.get("screenshotURL"):
            return us.get("screenshotURL", "")
        if us.get("screenshot"):
            return us.get("screenshot", "")
        task = us.get("task", {})
        if isinstance(task, dict):
            if task.get("screenshotURL"):
                return task.get("screenshotURL", "")
            if task.get("screenshot"):
                return task.get("screenshot", "")
        return ""

    def _verdict_badge(verdict: str) -> str:
        v = (verdict or "").lower()
        if v == "malicious":
            return f'<span style="background:#c0392b;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.85em">🔴 {verdict}</span>'
        if v == "suspicious":
            return f'<span style="background:#e67e22;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.85em">🟠 {verdict}</span>'
        if v in ("benign", "clean", "no threat"):
            return f'<span style="background:#27ae60;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.85em">🟢 {verdict}</span>'
        return f'<span style="background:#555;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.85em">⚪ {verdict or "Unknown"}</span>'

    for ioc in items:
        _row = rows_by_value.get(ioc.value, {}) or {}
        _score = _row.get("ConfidenceScore")
        _title_suffix = f" — Score: {_score:.1f}" if isinstance(_score, (int, float)) else ""
        with st.expander(
            f"Details: {ioc.value} ({ioc.type}){_title_suffix}", expanded=False
        ):
            _render_confidence_score_card(_row)
            vt = vt_results.get(ioc.value, {})
            us = urlscan_results.get(ioc.value, {})
            ab = abuse_results.get(ioc.value, {})
            sh = shodan_results.get(ioc.value, {})
            tf = tf_results.get(ioc.value, {})
            mb = mb_results.get(ioc.value, {})
            dd = dnsd_results.get(ioc.value, {})
            ha = ha_results.get(ioc.value, {})
            mx = mxtoolbox_results.get(ioc.value, {})
            wx = whoxy_results.get(ioc.value, {})
            rl = ransomware_live_results.get(ioc.value, {})

            # ── Geolocation: resolve target IP ─────────────────────────────
            _geo_target_ip: str | None = None
            if ioc.type == "ip":
                _geo_target_ip = ioc.value
            else:
                _sh_ips = sh.get("queriedIps") or []
                if _sh_ips:
                    _geo_target_ip = _sh_ips[0]
                elif sh.get("queriedIp"):
                    _geo_target_ip = sh.get("queriedIp")

            _geo_data: dict = fetch_geo_ip_api(_geo_target_ip) if _geo_target_ip else {}
            _geo_lat = _geo_data.get("lat")
            _geo_lon = _geo_data.get("lon")
            _has_coords = _geo_lat is not None and _geo_lon is not None
            _nom_data: dict = fetch_nominatim(_geo_lat, _geo_lon) if _has_coords else {}
            _vt_attrs: dict = (vt.get("attributes") or {}) if vt else {}

            # ── Screenshot + Map layout ────────────────────────────────────
            _shot_url = _urlscan_screenshot_url(us) if ioc.type in ("url", "domain") else ""
            if _shot_url:
                st.image(_shot_url, use_container_width=True)
            if _has_coords:
                components.html(
                    build_osm_map_html(_geo_lat, _geo_lon, _geo_data, _nom_data,
                                       ab, _vt_attrs, _geo_target_ip or ioc.value),
                    height=400,
                )

            _ha_msg = str(ha.get("message") or "").strip() if ha else ""
            _vt_has = bool(vt and (vt.get("stats") or vt.get("attributes") or vt.get("analysis_results")))
            _us_has = bool(us and (us.get("uuid") or us.get("result") or us.get("page") or us.get("task")))
            _ab_has = bool(ab and not ab.get("error") and (ab.get("abuseConfidenceScore") is not None or ab.get("totalReports") is not None))
            _tf_has = bool(tf and tf.get("query_status") == "ok" and tf.get("data"))
            _mb_has = bool(mb and mb.get("query_status") == "ok" and mb.get("data"))
            _sh_has = bool(sh and not sh.get("error") and (sh.get("summary") or sh.get("ports") or sh.get("queriedIp")))
            _dd_has = bool(dd and not dd.get("error") and (dd.get("soc_summary") or dd.get("dns_records") or dd.get("host_records")))
            _mx_has = bool(
                mx
                and not mx.get("error")
                and mx.get("lookups")
            )
            _wx_has = bool(
                wx
                and not wx.get("error")
                and (
                    (ioc.type in ("domain", "url") and wx.get("whois"))
                    or (ioc.type == "whois" and wx.get("reverse_whois"))
                )
            )

            _ha_has = bool(
                ha
                and _ha_msg not in {
                    "Not supported by Hybrid Analysis API",
                    "Hybrid Analysis does not analyze email indicators.",
                    "No results found",
                }
                and (
                    ha.get("verdict")
                    or ha.get("threat_score")
                    or ha.get("malware_family")
                    or any((ha.get("file_information") or {}).values())
                    or ha.get("analysis_environment")
                    or ha.get("analysis_time")
                    or (ha.get("network_ioc") or {}).get("domains")
                    or (ha.get("network_ioc") or {}).get("ips")
                    or any((ha.get("behavior") or {}).values())
                    or ha.get("mitre_attack")
                )
            )

            _rl_has = bool(
                rl
                and not rl.get("error")
                and rl.get("count", 0) > 0
            )

            _active_tabs = []
            if _vt_has: _active_tabs.append("VirusTotal")
            if _us_has: _active_tabs.append("urlscan")
            if _ab_has: _active_tabs.append("AbuseIPDB")
            if _tf_has: _active_tabs.append("ThreatFox")
            if _mb_has: _active_tabs.append("MalwareBazaar")
            if _sh_has: _active_tabs.append("Shodan")
            if _dd_has: _active_tabs.append("DNSDumpster")
            if _ha_has: _active_tabs.append("Hybrid Analysis")
            if _mx_has: _active_tabs.append("MxToolBox")
            if _wx_has: _active_tabs.append("Whoxy")
            if _rl_has: _active_tabs.append("Ransomware Live")

            _ti = {}
            if not _active_tabs:
                st.info("No data was found in any platform")
            else:
                _ti = dict(zip(_active_tabs, st.tabs(_active_tabs)))

            # ── VirusTotal tab ─────────────────────────────────────────────
            if "VirusTotal" in _ti:
                with _ti["VirusTotal"]:
                    def _fmt_ts(value):
                        try:
                            ts = int(value)
                        except Exception:
                            return value
                        try:
                            return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")
                        except Exception:
                            return value

                    attrs = vt.get("attributes", {}) or {}
                    stats = vt.get("stats", {}) or {}
                    analysis = vt.get("analysis_results", {}) or {}

                    st.markdown("**Detection**")
                    total = sum(stats.values()) if stats else 0
                    mal = stats.get("malicious", 0)
                    sus = stats.get("suspicious", 0)
                    undet = stats.get("undetected", 0)
                    harmless = stats.get("harmless", 0)
                    _dc1, _dc2, _dc3, _dc4, _dc5 = st.columns(5)
                    _dc1.metric("Malicious", mal)
                    _dc2.metric("Suspicious", sus)
                    _dc3.metric("Undetected", undet)
                    _dc4.metric("Harmless", harmless)
                    _dc5.metric("Total", total)
                    flagged = [(eng, res.get("result") or res.get("category")) for eng, res in analysis.items()
                               if isinstance(res, dict) and res.get("category") in ("malicious", "suspicious")]
                    if flagged:
                        with st.expander(f"Flagged engines ({len(flagged)})"):
                            for _eng, _lbl in flagged:
                                st.markdown(f"- **{_eng}**: {_lbl}")
                    else:
                        st.caption("No engines flagged this indicator.")

                    st.divider()
                    st.markdown("**Details**")

                    def _vt_kv_rows(pairs):
                        for _lbl, _val in pairs:
                            if _val is None or _val == "" or _val == [] or _val == {}:
                                continue
                            st.markdown(f"**{_lbl}:** {_val}")

                    _common = [
                        ("Reputation", attrs.get("reputation")),
                        ("Last Analysis", _fmt_ts(attrs.get("last_analysis_date")) if attrs.get("last_analysis_date") else None),
                        ("Last Modified", _fmt_ts(attrs.get("last_modification_date")) if attrs.get("last_modification_date") else None),
                        ("First Seen ITW", _fmt_ts(attrs.get("first_seen_itw_date")) if attrs.get("first_seen_itw_date") else None),
                        ("Last Seen ITW", _fmt_ts(attrs.get("last_seen_itw_date")) if attrs.get("last_seen_itw_date") else None),
                        ("Total Votes", ", ".join(f"{k}: {v}" for k, v in attrs["total_votes"].items()) if isinstance(attrs.get("total_votes"), dict) else attrs.get("total_votes")),
                    ]
                    _vt_kv_rows(_common)
                    _tags = attrs.get("tags") or []
                    if _tags:
                        st.markdown("**Tags:** " + " ".join(f"`{t}`" for t in _tags))
                    _cats = attrs.get("categories") or {}
                    if _cats and isinstance(_cats, dict):
                        _cat_vals = sorted(set(_cats.values()))
                        st.markdown("**Categories:** " + " · ".join(f"`{c}`" for c in _cat_vals[:10]))
                    _ctx = attrs.get("crowdsourced_context") or []
                    if _ctx and isinstance(_ctx, list):
                        with st.expander(f"Crowdsourced context ({len(_ctx)})"):
                            for _cx in _ctx[:10]:
                                if isinstance(_cx, dict):
                                    _cx_title = _cx.get("title") or _cx.get("details") or str(_cx)
                                    _cx_src = _cx.get("source") or ""
                                    st.markdown(f"- **{_cx_title}**" + (f" — {_cx_src}" if _cx_src else ""))

                    if ioc.type == "ip":
                        _vt_kv_rows([
                            ("Country", attrs.get("country")),
                            ("Continent", attrs.get("continent")),
                            ("ASN", attrs.get("asn")),
                            ("AS Owner", attrs.get("as_owner")),
                            ("Network", attrs.get("network")),
                            ("RIR", attrs.get("regional_internet_registry")),
                        ])
                        _cert_ip = attrs.get("last_https_certificate") or {}
                        if _cert_ip and isinstance(_cert_ip, dict):
                            with st.expander("SSL/TLS Certificate"):
                                for _ck, _clbl in [("issuer", "Issuer"), ("subject", "Subject"), ("validity", "Validity"), ("thumbprint", "Thumbprint"), ("serial_number", "Serial")]:
                                    _cv = _cert_ip.get(_ck)
                                    if _cv:
                                        if isinstance(_cv, dict):
                                            _cv = ", ".join(f"{k}: {v}" for k, v in _cv.items())
                                        st.markdown(f"**{_clbl}:** {_cv}")
                        _whois_ip = attrs.get("whois")
                        if _whois_ip:
                            with st.expander("Whois"):
                                st.text(_whois_ip[:3000])
                        _reso_ip = vt.get("resolutions") or []
                        if _reso_ip and isinstance(_reso_ip, list):
                            with st.expander(f"Resolutions — domains seen on this IP ({len(_reso_ip)})"):
                                for _r in _reso_ip[:15]:
                                    if not isinstance(_r, dict):
                                        continue
                                    _ra = _r.get("attributes", {}) if isinstance(_r.get("attributes"), dict) else {}
                                    _rhost = _ra.get("host_name") or str(_r)
                                    _rdate = _ra.get("date")
                                    st.markdown(f"- `{_rhost}`" + (f" — {_fmt_ts(_rdate)}" if _rdate else ""))

                    elif ioc.type == "domain":
                        _vt_kv_rows([
                            ("Registrar", attrs.get("registrar")),
                            ("Created", _fmt_ts(attrs.get("creation_date")) if attrs.get("creation_date") else None),
                            ("Expires", _fmt_ts(attrs.get("expiration_date")) if attrs.get("expiration_date") else None),
                            ("Last DNS Records", _fmt_ts(attrs.get("last_dns_records_date")) if attrs.get("last_dns_records_date") else None),
                            ("Last Cert", _fmt_ts(attrs.get("last_https_certificate_date")) if attrs.get("last_https_certificate_date") else None),
                            ("Whois Updated", _fmt_ts(attrs.get("whois_date")) if attrs.get("whois_date") else None),
                        ])
                        _pop = attrs.get("popularity_ranks") or {}
                        if _pop and isinstance(_pop, dict):
                            st.markdown("**Popularity rankings:**")
                            _pop_items = list(_pop.items())[:4]
                            _pop_cols = st.columns(len(_pop_items))
                            for _pi, (_src, _rank_obj) in enumerate(_pop_items):
                                _rank_val = _rank_obj.get("rank") if isinstance(_rank_obj, dict) else _rank_obj
                                _pop_cols[_pi].metric(_src, f"#{_rank_val}")
                        _dns = attrs.get("dns_records") or []
                        if _dns and isinstance(_dns, list):
                            with st.expander(f"DNS Records ({len(_dns)})"):
                                for _rec in _dns:
                                    if not isinstance(_rec, dict):
                                        continue
                                    _rtype = _rec.get("type") or "?"
                                    _rval = _rec.get("value") or ""
                                    _rttl = _rec.get("ttl")
                                    st.markdown(f"- `{_rtype}` → `{_rval}`" + (f"  TTL: {_rttl}" if _rttl else ""))
                        _cert_dom = attrs.get("last_https_certificate") or {}
                        if _cert_dom and isinstance(_cert_dom, dict):
                            with st.expander("SSL/TLS Certificate"):
                                for _ck, _clbl in [("issuer", "Issuer"), ("subject", "Subject"), ("validity", "Validity"), ("thumbprint", "Thumbprint"), ("serial_number", "Serial")]:
                                    _cv = _cert_dom.get(_ck)
                                    if _cv:
                                        if isinstance(_cv, dict):
                                            _cv = ", ".join(f"{k}: {v}" for k, v in _cv.items())
                                        st.markdown(f"**{_clbl}:** {_cv}")
                        _whois_dom = attrs.get("whois")
                        if _whois_dom:
                            with st.expander("Whois"):
                                st.text(_whois_dom[:3000])
                        _reso_dom = vt.get("resolutions") or []
                        if _reso_dom and isinstance(_reso_dom, list):
                            with st.expander(f"Resolutions — IPs seen for this domain ({len(_reso_dom)})"):
                                for _r in _reso_dom[:15]:
                                    if not isinstance(_r, dict):
                                        continue
                                    _ra = _r.get("attributes", {}) if isinstance(_r.get("attributes"), dict) else {}
                                    _rip = _ra.get("ip_address") or str(_r)
                                    _rdate = _ra.get("date")
                                    st.markdown(f"- `{_rip}`" + (f" — {_fmt_ts(_rdate)}" if _rdate else ""))

                    elif ioc.type == "url":
                        _vt_kv_rows([
                            ("Title", attrs.get("title")),
                            ("Final URL", attrs.get("final_url")),
                            ("HTTP Status", attrs.get("last_http_response_code")),
                            ("Content Length", attrs.get("last_http_response_content_length")),
                        ])
                        _cats_url = attrs.get("categories") or {}
                        if _cats_url and isinstance(_cats_url, dict):
                            st.markdown("**Categories:** " + " · ".join(f"`{c}`" for c in sorted(set(_cats_url.values()))[:10]))
                        _rchain = attrs.get("redirection_chain") or []
                        if _rchain and isinstance(_rchain, list):
                            with st.expander(f"Redirect chain ({len(_rchain)} hops)"):
                                for _i, _u in enumerate(_rchain):
                                    st.markdown(f"{_i+1}. `{_u}`")
                        _trackers = attrs.get("trackers") or {}
                        if _trackers and isinstance(_trackers, dict):
                            _tracker_list = [(n, e) for n, e in _trackers.items() if e]
                            if _tracker_list:
                                with st.expander(f"Trackers ({len(_tracker_list)})"):
                                    for _tname, _tentries in _tracker_list:
                                        _tid = ""
                                        _tdate = ""
                                        if isinstance(_tentries, list) and _tentries and isinstance(_tentries[0], dict):
                                            _tid = _tentries[0].get("id") or ""
                                            _tts = _tentries[0].get("timestamp")
                                            _tdate = f" — {_fmt_ts(_tts)}" if _tts else ""
                                        st.markdown(f"- **{_tname}**" + (f" `{_tid}`" if _tid else "") + _tdate)
                        _hdrs = attrs.get("last_http_response_headers") or {}
                        if _hdrs and isinstance(_hdrs, dict):
                            with st.expander(f"HTTP Response Headers ({len(_hdrs)})"):
                                for _hk, _hv in list(_hdrs.items())[:20]:
                                    st.markdown(f"- `{_hk}`: {_hv}")
                        _hmeta = attrs.get("html_meta") or {}
                        if _hmeta and isinstance(_hmeta, dict):
                            with st.expander(f"HTML Meta tags ({len(_hmeta)})"):
                                for _mk, _mv in list(_hmeta.items())[:15]:
                                    st.markdown(f"- **{_mk}:** {_mv}")
                        _links = attrs.get("outgoing_links") or []
                        if _links and isinstance(_links, list):
                            with st.expander(f"Outgoing links ({len(_links)})"):
                                for _lnk in _links[:30]:
                                    st.markdown(f"- `{_lnk}`")

                    elif ioc.type == "hash":
                        _vt_kv_rows([
                            ("Type", attrs.get("type_description")),
                            ("Type tag", attrs.get("type_tag")),
                            ("Magic", attrs.get("magic")),
                            ("Size", attrs.get("size")),
                            ("Meaningful name", attrs.get("meaningful_name")),
                            ("Submissions", attrs.get("times_submitted")),
                            ("First submitted", _fmt_ts(attrs.get("first_submission_date")) if attrs.get("first_submission_date") else None),
                            ("Last submitted", _fmt_ts(attrs.get("last_submission_date")) if attrs.get("last_submission_date") else None),
                        ])
                        _names = attrs.get("names") or []
                        if _names:
                            st.markdown("**Known names:** " + ", ".join(f"`{n}`" for n in _names[:10]))
                        st.divider()
                        st.markdown("**Hashes**")
                        for _hk, _hlbl in [("md5", "MD5"), ("sha1", "SHA-1"), ("sha256", "SHA-256"), ("ssdeep", "SSDeep"), ("tlsh", "TLSH"), ("vhash", "VHash")]:
                            _hv = attrs.get(_hk)
                            if _hv:
                                st.markdown(f"**{_hlbl}:** `{_hv}`")
                        _beh = vt.get("behavior") or {}
                        if _beh and isinstance(_beh, dict):
                            st.divider()
                            with st.expander("Sandbox Behavior"):
                                _beh_procs = _beh.get("processes_created") or _beh.get("processes_injected") or []
                                if _beh_procs:
                                    st.markdown("**Processes:**")
                                    for _p in _beh_procs[:10]:
                                        st.markdown(f"- `{_p}`")
                                _beh_files = _beh.get("files_dropped") or _beh.get("files_written") or []
                                if isinstance(_beh_files, list) and _beh_files:
                                    st.markdown("**Files dropped/written:**")
                                    for _f in _beh_files[:10]:
                                        _fn = (_f.get("path") or _f.get("name") or str(_f)) if isinstance(_f, dict) else str(_f)
                                        st.markdown(f"- `{_fn}`")
                                _beh_net = _beh.get("network_communications") or {}
                                if isinstance(_beh_net, dict):
                                    _beh_dns = _beh_net.get("dns_lookups") or []
                                    _beh_http = _beh_net.get("http_conversations") or []
                                    if _beh_dns:
                                        st.markdown("**DNS lookups:**")
                                        for _d in _beh_dns[:10]:
                                            _dh = (_d.get("hostname") or str(_d)) if isinstance(_d, dict) else str(_d)
                                            st.markdown(f"- `{_dh}`")
                                    if _beh_http:
                                        st.markdown("**HTTP conversations:**")
                                        for _h in _beh_http[:10]:
                                            _hu = (_h.get("url") or str(_h)) if isinstance(_h, dict) else str(_h)
                                            st.markdown(f"- `{_hu}`")
                                _beh_reg = _beh.get("registry_keys_set") or []
                                if _beh_reg:
                                    st.markdown("**Registry keys set:**")
                                    for _r in _beh_reg[:10]:
                                        _rk = (_r.get("key") or str(_r)) if isinstance(_r, dict) else str(_r)
                                        st.markdown(f"- `{_rk}`")
                                _beh_mutex = _beh.get("mutexes_created") or []
                                if _beh_mutex:
                                    st.markdown("**Mutexes:** " + ", ".join(f"`{m}`" for m in _beh_mutex[:10]))
                        _sigma = attrs.get("sigma_analysis_results") or []
                        if _sigma and isinstance(_sigma, list):
                            with st.expander(f"SIGMA Rules ({len(_sigma)})"):
                                for _s in _sigma[:10]:
                                    if not isinstance(_s, dict):
                                        continue
                                    _s_title = _s.get("rule_title") or _s.get("rule_id") or str(_s)
                                    _s_sev = _s.get("rule_level") or ""
                                    st.markdown(f"- **{_s_title}**" + (f" — `{_s_sev}`" if _s_sev else ""))
                        _yara = attrs.get("crowdsourced_yara_results") or []
                        if _yara and isinstance(_yara, list):
                            with st.expander(f"YARA Rules ({len(_yara)})"):
                                for _y in _yara[:10]:
                                    if not isinstance(_y, dict):
                                        continue
                                    _y_name = _y.get("rule_name") or str(_y)
                                    _y_src = _y.get("source") or _y.get("author") or ""
                                    st.markdown(f"- **{_y_name}**" + (f" — {_y_src}" if _y_src else ""))
                        _ids = attrs.get("crowdsourced_ids_results") or []
                        if _ids and isinstance(_ids, list):
                            with st.expander(f"IDS/IPS Rules ({len(_ids)})"):
                                for _id in _ids[:10]:
                                    if not isinstance(_id, dict):
                                        continue
                                    _id_name = _id.get("rule_msg") or _id.get("rule_id") or str(_id)
                                    _id_sev = _id.get("alert_severity") or ""
                                    st.markdown(f"- **{_id_name}**" + (f" — `{_id_sev}`" if _id_sev else ""))

                    rels = vt.get("relationships", []) or []
                    if rels:
                        st.divider()
                        st.markdown("**Relations**")
                        st.markdown(", ".join(f"`{r}`" for r in sorted(rels)))

                    st.divider()
                    st.markdown("**Community**")
                    comments = vt.get("comments", []) or []
                    votes = vt.get("votes", []) or []
                    if comments:
                        for c in comments[:5]:
                            attrs_c = c.get("attributes", {}) if isinstance(c, dict) else {}
                            text = attrs_c.get("text") or ""
                            date = attrs_c.get("date")
                            votes_c = attrs_c.get("votes")
                            line = f"{_fmt_ts(date)} — {text}" if date else text
                            if votes_c is not None:
                                line += f" *(votes: {votes_c})*"
                            if line.strip():
                                st.markdown(f"> {line}")
                    elif votes:
                        for v in votes[:5]:
                            attrs_v = v.get("attributes", {}) if isinstance(v, dict) else {}
                            verdict_v = attrs_v.get("verdict")
                            date_v = attrs_v.get("date")
                            if verdict_v or date_v:
                                st.markdown(f"- {_fmt_ts(date_v)} — {verdict_v}")
                    else:
                        st.caption("No community data.")

            # ── urlscan tab ────────────────────────────────────────────────
            if "urlscan" in _ti:
                with _ti["urlscan"]:
                    page = us.get("page", {}) or {}
                    task = us.get("task", {}) or {}
                    result = us.get("result", {}) or {}

                    meta_lines = []
                    if page.get("title"):
                        meta_lines.append(f"**Title:** {page['title']}")
                    if page.get("url"):
                        meta_lines.append(f"**URL:** [{page['url']}]({page['url']})")
                    if page.get("domain"):
                        meta_lines.append(f"**Domain:** {page['domain']}")
                    if page.get("ip"):
                        meta_lines.append(f"**Server IP:** `{page['ip']}`")
                    if page.get("server"):
                        meta_lines.append(f"**Server:** {page['server']}")
                    if page.get("mimeType"):
                        meta_lines.append(f"**MIME:** {page['mimeType']}")
                    if page.get("country"):
                        meta_lines.append(f"**Country:** {page['country']}")
                    if task.get("time"):
                        meta_lines.append(f"**Scan time:** {task['time']}")
                    if task.get("tags"):
                        tags_val = task["tags"]
                        meta_lines.append("**Tags:** " + " ".join(f"`{t}`" for t in tags_val))
                    for line in meta_lines:
                        st.markdown(line)

                    st.divider()
                    st.markdown("**Verdict**")
                    verdicts = us.get("verdicts", {}) or {}
                    overall = verdicts.get("overall", {}) or {}
                    score = overall.get("score", 0)
                    malicious = overall.get("malicious", False)
                    cats = overall.get("categories") or []
                    c1, c2 = st.columns(2)
                    c1.metric("Overall score", score)
                    c2.metric("Malicious", "Yes" if malicious else "No")
                    if cats:
                        st.markdown("**Categories:** " + ", ".join(f"`{c}`" for c in cats))
                    engine_verdicts = {k: v for k, v in verdicts.items() if k != "overall" and isinstance(v, dict)}
                    if engine_verdicts:
                        for eng, ev in engine_verdicts.items():
                            s = ev.get("score", 0)
                            m = ev.get("malicious", False)
                            st.markdown(f"- **{eng}**: score={s}, malicious={'Yes' if m else 'No'}")
                    _v_tags = overall.get("tags") or []
                    _v_brands = overall.get("brands") or []
                    _v_threats = overall.get("threatNames") or []
                    if _v_tags:
                        st.markdown("**Threat tags:** " + " ".join(f"`{t}`" for t in _v_tags))
                    if _v_brands:
                        st.markdown("**Brands targeted:** " + " ".join(f"`{b}`" for b in _v_brands))
                    if _v_threats:
                        st.markdown("**Threat names:** " + " ".join(f"`{t}`" for t in _v_threats))

                    _stats = result.get("stats", {}) if isinstance(result.get("stats"), dict) else {}
                    if _stats:
                        st.divider()
                        st.markdown("**Scan Stats**")
                        _sc1, _sc2, _sc3 = st.columns(3)
                        _data_obj_pre = result.get("data", {}) if isinstance(result.get("data"), dict) else {}
                        _requests_pre = _data_obj_pre.get("requests") or result.get("http") or []
                        _total_reqs = sum(
                            (s.get("count") or s.get("requests") or 0)
                            for s in (_stats.get("resourceStats") or [])
                            if isinstance(s, dict)
                        ) or _stats.get("totalRequests") or len(_requests_pre) or 0
                        _secure_pct = _stats.get("securePercentage")
                        _uniq_countries = _stats.get("uniqCountries")
                        if _total_reqs:
                            _sc1.metric("Total requests", _total_reqs)
                        if _secure_pct is not None:
                            _sc2.metric("Secure (HTTPS)", f"{_secure_pct}%")
                        if _uniq_countries is not None:
                            _sc3.metric("Countries", _uniq_countries)
                        _proto_stats = _stats.get("protocolStats") or []
                        if isinstance(_proto_stats, list) and _proto_stats:
                            _proto_lines = []
                            for _ps in _proto_stats:
                                if isinstance(_ps, dict) and _ps.get("protocol"):
                                    _proto_lines.append(f"`{_ps['protocol']}` ({_ps.get('count') or _ps.get('requests', '?')} req)")
                            if _proto_lines:
                                st.markdown("**Protocols:** " + " · ".join(_proto_lines))

                    lists = result.get("lists", {}) or {}
                    net_ips = lists.get("ips") or []
                    net_domains = lists.get("domains") or []
                    net_urls = lists.get("urls") or []
                    net_servers = lists.get("servers") or []
                    if net_ips or net_domains or net_urls or net_servers:
                        st.divider()
                        st.markdown("**Network connections**")
                        if net_ips:
                            st.markdown("**IPs:** " + ", ".join(f"`{x}`" for x in net_ips[:20]))
                        if net_domains:
                            st.markdown("**Domains:** " + ", ".join(f"`{x}`" for x in net_domains[:20]))
                        if net_servers:
                            st.markdown("**Servers:** " + ", ".join(f"`{x}`" for x in net_servers[:10]))
                        if net_urls:
                            with st.expander(f"URLs contacted ({len(net_urls)})"):
                                for u in net_urls[:50]:
                                    st.markdown(f"- `{u}`")
                                if len(net_urls) > 50:
                                    st.caption(f"... and {len(net_urls) - 50} more")

                    tls = result.get("tls") or result.get("certificate") or {}
                    if isinstance(tls, list) and tls:
                        tls = tls[0]
                    if tls and isinstance(tls, dict):
                        st.divider()
                        st.markdown("**SSL/TLS Certificate**")
                        for k in ["issuer", "subject", "validFrom", "validTo", "protocol", "keyExchange"]:
                            v = tls.get(k)
                            if v:
                                st.markdown(f"**{k}:** {v}")

                    _data_obj = result.get("data", {}) if isinstance(result.get("data"), dict) else {}
                    _requests = _data_obj.get("requests") or []
                    if not _requests:
                        _requests = result.get("http") or []
                    if _requests and isinstance(_requests, list):
                        st.divider()
                        st.markdown("**HTTP Transactions**")
                        st.markdown(f"**Total requests:** {len(_requests)}")
                        _redirect_chain: list[str] = []
                        _seen_redir: set[str] = set()
                        _form_posts: list[str] = []
                        _downloads: list[str] = []
                        _encoded_hits: list[str] = []
                        _suspicious_post_hints = ("/login", "/auth", "/verify", "/submit", "/signin", "/password")
                        for _tx in _requests:
                            if not isinstance(_tx, dict):
                                continue
                            _req = _tx.get("request", {}) if isinstance(_tx.get("request"), dict) else {}
                            _res = _tx.get("response", {}) if isinstance(_tx.get("response"), dict) else {}
                            _req_url = _req.get("url")
                            if isinstance(_req_url, str) and _req_url and _req_url not in _seen_redir:
                                _seen_redir.add(_req_url)
                                _redirect_chain.append(_req_url)
                            _loc = _res.get("location") or _res.get("redirect") or _res.get("redirectURL")
                            if isinstance(_loc, str) and _loc and _loc not in _seen_redir:
                                _seen_redir.add(_loc)
                                _redirect_chain.append(_loc)
                            _method = (_req.get("method") or "").upper()
                            if _method == "POST" and isinstance(_req_url, str):
                                if any(h in _req_url.lower() for h in _suspicious_post_hints):
                                    if _req_url not in _form_posts:
                                        _form_posts.append(_req_url)
                            _ctype = (_res.get("contentType") or _res.get("mimeType") or "").lower()
                            _disp = (_res.get("contentDisposition") or "").lower()
                            if any(k in _ctype for k in ("application/x-msdownload", "application/octet-stream", "application/x-dosexec", "application/pdf", "application/zip")):
                                if isinstance(_req_url, str) and _req_url not in _downloads:
                                    _downloads.append(_req_url)
                            elif "attachment" in _disp and isinstance(_req_url, str) and _req_url not in _downloads:
                                _downloads.append(_req_url)
                            _serialized = str(_tx)
                            import re as _re
                            if _re.search(r"(?:[A-Za-z0-9+/]{80,}={0,2})", _serialized):
                                if not _encoded_hits:
                                    _encoded_hits.append("Base64-like blob detected in HTTP transaction")
                            elif any(k in _serialized.lower() for k in ("eval(", "atob(", "unescape(", "\\x")):
                                if not _encoded_hits:
                                    _encoded_hits.append("Obfuscated/encoded JS pattern in transaction")
                        _num_redirects = max(len(_redirect_chain) - 1, 0)
                        if _num_redirects > 0:
                            st.markdown(f"**Redirects:** {_num_redirects}")
                            with st.expander(f"Redirect chain ({len(_redirect_chain)} hops)"):
                                for _i, _u in enumerate(_redirect_chain):
                                    st.markdown(f"{_i+1}. `{_u}`")
                        if _form_posts:
                            st.markdown("**Suspicious POST targets:**")
                            for _fp in _form_posts:
                                st.markdown(f"- `{_fp}`")
                        if _downloads:
                            st.markdown("**Files served for download:**")
                            for _dl in _downloads:
                                st.markdown(f"- `{_dl}`")
                        if _encoded_hits:
                            for _eh in _encoded_hits:
                                st.markdown(f"- `{_eh}`")

                    _meta = result.get("meta", {}) if isinstance(result.get("meta"), dict) else {}
                    _processors = _meta.get("processors", {}) if isinstance(_meta.get("processors"), dict) else {}
                    _wappa = _processors.get("wappa", {}) if isinstance(_processors.get("wappa"), dict) else {}
                    _wappa_data = _wappa.get("data") or []
                    _wappa_items = [_t for _t in _wappa_data[:20] if isinstance(_t, dict) and (_t.get("app") or _t.get("name"))]
                    _cookies = _data_obj.get("cookies") or []
                    _console = _data_obj.get("console") or []
                    if _wappa_items or _cookies or _console:
                        st.divider()
                        if _wappa_items:
                            with st.expander(f"Technology Detection ({len(_wappa_items)})"):
                                for _tech in _wappa_items:
                                    _tname = _tech.get("app") or _tech.get("name") or ""
                                    _tcat = _tech.get("categories") or []
                                    if isinstance(_tcat, list):
                                        _tcat_parts = [_c.get("name") if isinstance(_c, dict) else str(_c) for _c in _tcat]
                                        _tcat_str = ", ".join(_p for _p in _tcat_parts if _p)
                                    else:
                                        _tcat_str = str(_tcat)
                                    st.markdown(f"- **{_tname}**" + (f" — {_tcat_str}" if _tcat_str else ""))
                        if _cookies and isinstance(_cookies, list):
                            with st.expander(f"Cookies ({len(_cookies)})"):
                                for _ck in _cookies[:30]:
                                    if not isinstance(_ck, dict):
                                        continue
                                    _ck_name = _ck.get("name") or "?"
                                    _ck_domain = _ck.get("domain") or ""
                                    _ck_flags = []
                                    if _ck.get("secure"):
                                        _ck_flags.append("Secure")
                                    if _ck.get("httpOnly"):
                                        _ck_flags.append("HttpOnly")
                                    _ck_flag_str = " · ".join(_ck_flags) if _ck_flags else "—"
                                    st.markdown(f"- `{_ck_name}` — domain: `{_ck_domain}` — flags: {_ck_flag_str}")
                        if _console and isinstance(_console, list):
                            with st.expander(f"Console logs ({len(_console)})"):
                                for _cl in _console[:20]:
                                    if not isinstance(_cl, dict):
                                        continue
                                    _cl_type = (_cl.get("type") or "log").upper()
                                    _cl_text = _cl.get("text") or str(_cl)
                                    st.markdown(f"- `[{_cl_type}]` {_cl_text}")

            # ── AbuseIPDB tab ──────────────────────────────────────────────
            if "AbuseIPDB" in _ti:
                with _ti["AbuseIPDB"]:
                    queried = ab.get("queriedIp") or (", ".join(str(x) for x in ab.get("queriedIps", [])) if ab.get("queriedIps") else None)
                    if queried:
                        st.markdown(f"**Queried:** `{queried}`")

                    score_val = ab.get("abuseConfidenceScore", 0)
                    reports_val = ab.get("totalReports", 0)
                    c1, c2 = st.columns(2)
                    c1.metric("Abuse confidence", f"{score_val}%")
                    c2.metric("Total reports", reports_val)
                    last_rep = ab.get("lastReportedAt")
                    if last_rep:
                        st.markdown(f"**Last reported:** {last_rep}")

                    category_map = {
                        3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
                        6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
                        9: "Open Proxy", 10: "Web Spam", 11: "Email Spam",
                        12: "Blog Spam", 13: "VPN IP", 14: "Port Scan",
                        15: "Hacking", 16: "SQL Injection", 17: "Spoofing",
                        18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
                        21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
                    }
                    categories = ab.get("reportCategories") or {}
                    if categories:
                        st.divider()
                        st.markdown("**Report categories**")
                        lines_out = []
                        for code, count in sorted(categories.items(), key=lambda x: x[0]):
                            try:
                                code_int = int(code)
                            except Exception:
                                code_int = None
                            label = category_map.get(code_int, "Unknown")
                            lines_out.append(f"- {label} ({count}×)")
                        st.markdown("\n".join(lines_out))

                    report_items = ab.get("reports") or []
                    if report_items:
                        st.divider()
                        st.markdown("**Recent abuse reports**")
                        for idx, rep in enumerate(report_items[:10], start=1):
                            reporter = rep.get("reporter") or "Unknown"
                            ioa_ts = rep.get("ioaTimestamp") or "—"
                            comment = rep.get("comment") or "No comment"
                            rep_cats = rep.get("categories") or []
                            cat_labels = [category_map.get(int(c), "Unknown") for c in rep_cats if str(c).isdigit()]
                            cat_text = ", ".join(cat_labels) if cat_labels else "—"
                            with st.expander(f"#{idx} — {ioa_ts} — {cat_text}"):
                                st.markdown(f"**Reporter:** {reporter}")
                                st.markdown(f"**Comment:** {comment}")
                                st.markdown(f"**Categories:** {cat_text}")

            # ── ThreatFox tab ──────────────────────────────────────────────
            if "ThreatFox" in _ti:
                with _ti["ThreatFox"]:
                    data_list = tf.get("data", []) or []
                    primary = data_list[0] if isinstance(data_list, list) and data_list else {}
                    malware_family = primary.get("malware") or primary.get("malware_family") or primary.get("malware_name")
                    confidence = primary.get("confidence_level")
                    tags = primary.get("tags") or []
                    threat_type_raw = (primary.get("threat_type") or primary.get("threat_type_desc") or "").strip()
                    threat_type_lower = threat_type_raw.lower()
                    if "c2" in threat_type_lower or "cc" in threat_type_lower or "command" in threat_type_lower:
                        threat_type_view = "C2"
                    elif "payload" in threat_type_lower or "download" in threat_type_lower:
                        threat_type_view = "Payload delivery"
                    else:
                        threat_type_view = threat_type_raw or "—"
                    first_seen = primary.get("first_seen") or "—"
                    last_seen = primary.get("last_seen") or "—"

                    c1, c2 = st.columns(2)
                    c1.metric("Malware family", malware_family or "—")
                    c2.metric("Confidence", f"{confidence}%" if confidence is not None else "—")
                    st.markdown(f"**Threat type:** {threat_type_view}")
                    st.markdown(f"**First seen:** {first_seen}  |  **Last seen:** {last_seen}")

                    if tags:
                        st.markdown("**Tags:** " + " ".join(f"`{t}`" for t in (tags if isinstance(tags, list) else [str(tags)])))

                    related = []
                    if isinstance(data_list, list):
                        for entry in data_list:
                            val = str(entry.get("ioc") or "").strip()
                            ioc_type_val = str(entry.get("ioc_type") or "").strip().lower()
                            if not val or val == ioc.value:
                                continue
                            is_ip_port = bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}$", val))
                            if ioc_type_val in {"url", "domain", "ip:port"} or is_ip_port:
                                related.append(val)
                    related = list(dict.fromkeys(related))
                    if related:
                        st.divider()
                        st.markdown("**Related IOCs**")
                        st.markdown("\n".join(f"- `{r}`" for r in related[:10]))

                    extra_keys = ["reference", "reporter", "reporter_name", "malware_alias", "malware_printable"]
                    extras = {k: primary.get(k) for k in extra_keys if primary.get(k) not in (None, "", [], {})}
                    if extras:
                        st.divider()
                        st.markdown("**Additional info**")
                        for k, v in extras.items():
                            st.markdown(f"**{k.replace('_', ' ').title()}:** {v}")

            # ── MalwareBazaar tab ──────────────────────────────────────────
            if "MalwareBazaar" in _ti:
                with _ti["MalwareBazaar"]:
                    data_list = mb.get("data", []) or []
                    primary = data_list[0] if isinstance(data_list, list) and data_list else {}
                    primary_meta = mb.get("primary_metadata") or {}
                    src = primary_meta if primary_meta else primary

                    malware_family = src.get("signature") or src.get("family") or src.get("malware") or src.get("family_signature")
                    tags = src.get("tags") or []
                    file_type = src.get("file_type") or src.get("file_type_mime") or src.get("file_type_guess") or "—"
                    file_size = src.get("file_size")
                    first_seen = src.get("first_seen") or "—"
                    last_seen = src.get("last_seen") or "—"

                    c1, c2, c3 = st.columns(3)
                    c1.metric("Malware family", malware_family or "—")
                    c2.metric("File type", file_type)
                    c3.metric("File size", f"{file_size} B" if file_size else "—")

                    st.markdown(f"**First seen:** {first_seen}  |  **Last seen:** {last_seen}")
                    if tags:
                        st.markdown("**Tags:** " + " ".join(f"`{t}`" for t in (tags if isinstance(tags, list) else [str(tags)])))

                    hashes = src.get("hashes") or {}
                    md5_h = src.get("md5_hash") or hashes.get("md5") or primary.get("md5_hash")
                    sha1_h = src.get("sha1_hash") or hashes.get("sha1") or primary.get("sha1_hash")
                    sha256_h = src.get("sha256_hash") or hashes.get("sha256") or primary.get("sha256_hash")
                    if any([md5_h, sha1_h, sha256_h]):
                        st.divider()
                        st.markdown("**Hashes**")
                        if md5_h:
                            st.markdown(f"**MD5:** `{md5_h}`")
                        if sha1_h:
                            st.markdown(f"**SHA1:** `{sha1_h}`")
                        if sha256_h:
                            st.markdown(f"**SHA256:** `{sha256_h}`")

                    arch = src.get("architecture") or src.get("cpu_architecture") or src.get("arch")
                    imphash = src.get("imphash") or "—"
                    tlsh = src.get("tlsh") or "—"
                    ssdeep = src.get("ssdeep") or src.get("ssdeep_hash") or "—"
                    if any(x != "—" for x in [imphash, tlsh, ssdeep]) or arch:
                        st.divider()
                        st.markdown("**Fuzzy hashes & metadata**")
                        if arch:
                            st.markdown(f"**Architecture:** {arch}")
                        if imphash != "—":
                            st.markdown(f"**imphash:** `{imphash}`")
                        if tlsh != "—":
                            st.markdown(f"**TLSH:** `{tlsh}`")
                        if ssdeep != "—":
                            st.markdown(f"**ssdeep:** `{ssdeep}`")

                    reporter = src.get("reporter") or primary.get("reporter")
                    origin = src.get("origin_country") or primary.get("origin_country")
                    if reporter or origin:
                        st.divider()
                        if reporter:
                            st.markdown(f"**Reporter:** {reporter}")
                        if origin:
                            st.markdown(f"**Origin country:** {origin}")

            # ── Shodan tab ─────────────────────────────────────────────────
            if "Shodan" in _ti:
                with _ti["Shodan"]:
                    summary_sh = sh.get("summary") or {}
                    if summary_sh:
                        input_block = summary_sh.get("input", {}) or {}
                        resolved = input_block.get("resolved_ips") or []
                        if resolved:
                            st.markdown("**Resolved IPs:** " + ", ".join(f"`{x}`" for x in resolved))
                        results_block = (summary_sh.get("shodan", {}) or {}).get("results", []) or []
                        if results_block:
                            st.markdown("**Per-IP results**")
                            for r in results_block[:20]:
                                risk = r.get("risk_summary", {}) or {}
                                risk_level = risk.get("risk_level") or "—"
                                risk_conf = risk.get("confidence") or "—"
                                ports = ", ".join(str(p) for p in (r.get("ports") or [])) or "—"
                                vulns = ", ".join(r.get("vulns") or []) or "—"
                                hostnames = ", ".join(r.get("hostnames") or []) or "—"
                                tags_s = ", ".join(r.get("tags") or []) or "—"
                                reasons = ", ".join((risk.get("reasons") or [])[:3]) or "—"
                                with st.expander(f"`{r.get('ip')}` — Risk: {risk_level} ({risk_conf})"):
                                    _ip_ports = r.get("ports") or []
                                    if _ip_ports:
                                        st.markdown("**Open Ports**")
                                        _ports_table(_ip_ports)
                                    else:
                                        st.markdown("**Ports:** —")
                                    _port_vuln_warns = _vuln_warnings_for_ports(_ip_ports)
                                    _all_vulns = list(r.get("vulns") or []) + _port_vuln_warns
                                    st.markdown(f"**Vulnerabilities:** {', '.join(_all_vulns) if _all_vulns else '—'}")
                                    st.markdown(f"**Hostnames:** {hostnames}")
                                    st.markdown(f"**Tags:** {tags_s}")
                                    st.markdown(f"**Reasons:** {reasons}")
                        rollup = (summary_sh.get("shodan", {}) or {}).get("rollup", {}) or {}
                        if rollup:
                            st.divider()
                            st.markdown("**Rollup**")
                            _rollup_ports = rollup.get("unique_ports")
                            if _rollup_ports:
                                st.markdown("**Ports**")
                                _ports_table([int(p) for p in _rollup_ports])
                            for rk in ["unique_vulns", "unique_cpes", "unique_hostnames", "unique_tags"]:
                                rv = rollup.get(rk)
                                if rv:
                                    label = rk.replace("unique_", "").replace("_", " ").title()
                                    st.markdown(f"**{label}:** {', '.join(str(x) for x in rv) if isinstance(rv, list) else rv}")
                    else:
                        queried_ip = sh.get("queriedIp") or (", ".join(str(x) for x in sh.get("queriedIps", [])) if sh.get("queriedIps") else None)
                        if queried_ip:
                            st.markdown(f"**Queried:** `{queried_ip}`")
                        ports = sh.get("ports") or []
                        if ports:
                            st.markdown("**Open Ports**")
                            _ports_table(ports)
                            _idb_vuln_warns = _vuln_warnings_for_ports(ports)
                            if _idb_vuln_warns:
                                st.markdown("**Vulnerabilities:** " + ", ".join(_idb_vuln_warns))
                        hostnames = sh.get("hostnames") or []
                        if hostnames:
                            st.markdown("**Hostnames:** " + ", ".join(hostnames[:10]))

                    if _has_coords or _vt_attrs.get("country") or ab.get("countryCode"):
                        st.divider()
                        st.markdown("**📍 Geolocation**")

                        def _geo_row(label: str, value: object, source: str) -> None:
                            if value:
                                st.markdown(
                                    f"<div style='display:flex;gap:8px;align-items:baseline;"
                                    f"font-family:JetBrains Mono,Courier New,monospace;font-size:13px;'>"
                                    f"<span style='min-width:160px;color:#8b95a8;'>{label}</span>"
                                    f"<span style='color:#e8eaf0;'>{value}</span>"
                                    f"<span style='color:#555;font-size:11px;margin-left:4px;'>({source})</span>"
                                    f"</div>",
                                    unsafe_allow_html=True,
                                )

                        _c_geo = _geo_data.get("country")
                        _cc_geo = _geo_data.get("countryCode")
                        _cc_ab = ab.get("countryCode")
                        _c_vt = _vt_attrs.get("country")
                        _country_merged = " / ".join(
                            p for p in dict.fromkeys([_c_geo, _c_vt]) if p
                        ) or None
                        _cc_merged = " / ".join(
                            p for p in dict.fromkeys([_cc_geo, _cc_ab]) if p
                        ) or None
                        _country_disp = (
                            f"{_country_merged} ({_cc_merged})"
                            if _country_merged and _cc_merged
                            else _country_merged or _cc_merged
                        )
                        _geo_row("Country", _country_disp,
                                 " + ".join(s for s, v in [("Geo", _c_geo), ("AbuseIPDB", _cc_ab), ("VirusTotal", _c_vt)] if v))

                        _geo_row("City", _geo_data.get("city"), "Geo")
                        _geo_row("Region", f"{_geo_data.get('regionName')} ({_geo_data.get('region')})"
                                 if _geo_data.get("regionName") and _geo_data.get("region")
                                 else _geo_data.get("regionName") or _geo_data.get("region"),
                                 "Geo")
                        if _has_coords:
                            _geo_row("Coordinates", f"{_geo_lat}, {_geo_lon}", "Geo")
                        _geo_row("Postal Code", _geo_data.get("zip"), "Geo")

                        _nom_addr = _nom_data.get("address", {}) or {}
                        _street_parts = [p for p in [
                            _nom_addr.get("road"), _nom_addr.get("suburb"),
                            _nom_addr.get("city") or _nom_addr.get("town") or _nom_addr.get("village"),
                        ] if p]
                        _geo_row("Street area", ", ".join(_street_parts) if _street_parts else None, "Nominatim")
                        _geo_row("State / Province", _nom_addr.get("state"), "Nominatim")

                        _org_geo = _geo_data.get("org")
                        _isp_geo = _geo_data.get("isp")
                        _isp_ab = ab.get("isp")
                        _org_disp = _org_geo or None
                        _isp_disp = " / ".join(p for p in dict.fromkeys([_isp_geo, _isp_ab]) if p) or None
                        _geo_row("Org", _org_disp, "Geo")
                        _geo_row("ISP", _isp_disp,
                                 " + ".join(s for s, v in [("Geo", _isp_geo), ("AbuseIPDB", _isp_ab)] if v))

                        _geo_row("Usage Type", ab.get("usageType"), "AbuseIPDB")
                        _geo_row("Domain", ab.get("domain"), "AbuseIPDB")

                        _vt_asn = _vt_attrs.get("asn")
                        _vt_owner = _vt_attrs.get("as_owner")
                        _asn_disp = f"AS{_vt_asn} — {_vt_owner}" if _vt_asn and _vt_owner else (f"AS{_vt_asn}" if _vt_asn else None)
                        _geo_row("ASN", _asn_disp, "VirusTotal")
                        _geo_row("Continent", _vt_attrs.get("continent"), "VirusTotal")
                        _geo_row("RIR", _vt_attrs.get("regional_internet_registry"), "VirusTotal")

            # ── DNSDumpster tab ────────────────────────────────────────────
            if "DNSDumpster" in _ti:
                with _ti["DNSDumpster"]:
                    _dd_domain = dd.get("queriedDomain") or ""
                    if _dd_domain:
                        st.markdown(f"**Queried:** `{_dd_domain}`")
                    summary_dd = dd.get("soc_summary") or {}
                    _dd_a_records  = summary_dd.get("a_records") or []
                    _dd_cname_map  = summary_dd.get("cname_map") or {}
                    infra          = summary_dd.get("mail_dns_infra") or {}
                    _dd_open_svc   = summary_dd.get("open_services") or []
                    network        = summary_dd.get("network_enrichment") or []
                    red_flags      = summary_dd.get("red_flags") or []
                    _dd_mx         = infra.get("mx") or []
                    _dd_mx_details = infra.get("mx_details") or []
                    _dd_ns         = infra.get("ns") or []
                    _dd_txt        = infra.get("txt_highlights") or []
                    _dd_total      = summary_dd.get("total_a_recs") or len(_dd_a_records)

                    _dd_has_content = any([_dd_a_records, _dd_cname_map, _dd_mx, _dd_ns,
                                           _dd_txt, _dd_open_svc, network, red_flags])

                    if red_flags:
                        st.markdown(
                            "<div style='background:#2d1a1a;border-left:3px solid #f85149;"
                            "padding:8px 12px;border-radius:4px;margin-bottom:8px;'>"
                            "<span style='color:#f85149;font-weight:600;'>⚠ Red Flags</span></div>",
                            unsafe_allow_html=True,
                        )
                        for _rf in red_flags[:15]:
                            st.markdown(f"- {_rf}")
                        st.divider()

                    if _dd_a_records:
                        _dd_shown = _dd_a_records[:20]
                        _dd_label = f"**A Records** ({_dd_total} total)"
                        with st.expander(_dd_label, expanded=True):
                            st.markdown(
                                "<div style='display:grid;grid-template-columns:140px 130px 1fr 90px;"
                                "gap:6px;padding:3px 0 6px;border-bottom:1px solid #30363d;"
                                "font-size:11px;color:#6e7681;font-family:JetBrains Mono,monospace;'>"
                                "<span>IP</span><span>ASN</span><span>Owner / Netblock</span><span>Country</span>"
                                "</div>", unsafe_allow_html=True,
                            )
                            for _ar in _dd_shown:
                                _ar_ip  = _ar.get("ip") or "—"
                                _ar_asn = _ar.get("asn") or "—"
                                _ar_own = _ar.get("owner") or ""
                                _ar_net = _ar.get("netblock") or ""
                                _ar_cc  = _ar.get("country_code") or _ar.get("country") or "—"
                                _ar_ptr = _ar.get("ptr") or ""
                                _ar_own_disp = f"{_ar_own}<br><span style='color:#6e7681;font-size:10px;'>{_ar_net}</span>" if _ar_net else _ar_own or "—"
                                _ar_ptr_disp = f"<br><span style='color:#6e7681;font-size:10px;'>PTR: {_ar_ptr}</span>" if _ar_ptr else ""
                                st.markdown(
                                    f"<div style='display:grid;grid-template-columns:140px 130px 1fr 90px;"
                                    f"gap:6px;align-items:start;padding:5px 0;"
                                    f"border-bottom:1px solid #21262d;"
                                    f"font-family:JetBrains Mono,monospace;font-size:12px;'>"
                                    f"<span style='color:#e8eaf0;'>{_ar_ip}{_ar_ptr_disp}</span>"
                                    f"<span style='color:#79c0ff;'>{_ar_asn}</span>"
                                    f"<span style='color:#8b95a8;'>{_ar_own_disp}</span>"
                                    f"<span style='color:#8b95a8;'>{_ar_cc}</span>"
                                    f"</div>",
                                    unsafe_allow_html=True,
                                )
                            if _dd_total > 20:
                                st.caption(f"Showing 20 of {_dd_total} records.")

                    if _dd_cname_map:
                        st.divider()
                        st.markdown("**CNAME Records**")
                        for _ch, _ct in _dd_cname_map.items():
                            st.markdown(
                                f"<div style='font-family:JetBrains Mono,monospace;font-size:12px;"
                                f"padding:4px 0;border-bottom:1px solid #21262d;'>"
                                f"<span style='color:#79c0ff;'>{_ch}</span>"
                                f"<span style='color:#6e7681;'> → </span>"
                                f"<span style='color:#e8eaf0;'>{_ct}</span>"
                                f"</div>",
                                unsafe_allow_html=True,
                            )

                    if _dd_open_svc:
                        st.divider()
                        st.markdown(f"**Open Services** ({len(_dd_open_svc)})")
                        _seen_banners: set[str] = set()
                        for _svc in _dd_open_svc[:20]:
                            _svc_ip     = _svc.get("ip") or ""
                            _svc_banner = _svc.get("banner") or ""
                            _key = f"{_svc_ip}|{_svc_banner}"
                            if _key in _seen_banners:
                                continue
                            _seen_banners.add(_key)
                            st.markdown(
                                f"<div style='font-family:JetBrains Mono,monospace;"
                                f"font-size:12px;padding:4px 0;border-bottom:1px solid #21262d;'>"
                                f"<span style='color:#e8eaf0;'>{_svc_ip}</span>"
                                + (f"<span style='color:#56d364;margin-left:12px;'>{_svc_banner}</span>" if _svc_banner else "")
                                + "</div>",
                                unsafe_allow_html=True,
                            )

                    if _dd_mx or _dd_mx_details:
                        st.divider()
                        st.markdown("**MX Records**")
                        for _mx in (_dd_mx_details or [{"host": m} for m in _dd_mx])[:15]:
                            _mx_host = _mx.get("host") or "—"
                            _mx_prio = f" (pri {_mx['priority']})" if _mx.get("priority") else ""
                            _mx_meta = " | ".join(p for p in [
                                _mx.get("ip"), _mx.get("asn"), _mx.get("owner"), _mx.get("country")
                            ] if p)
                            st.markdown(
                                f"<div style='font-family:JetBrains Mono,monospace;"
                                f"font-size:12px;padding:4px 0;border-bottom:1px solid #21262d;'>"
                                f"<span style='color:#79c0ff;'>{_mx_host}</span>"
                                f"<span style='color:#6e7681;'>{_mx_prio}</span>"
                                + (f"<span style='color:#8b95a8;margin-left:12px;'>{_mx_meta}</span>" if _mx_meta else "")
                                + "</div>",
                                unsafe_allow_html=True,
                            )

                    if _dd_ns:
                        st.divider()
                        st.markdown("**NS Records**")
                        st.markdown(" &nbsp;·&nbsp; ".join(f"`{x}`" for x in _dd_ns))

                    if _dd_txt:
                        st.divider()
                        st.markdown("**TXT / SPF Records**")
                        for _tv in _dd_txt[:15]:
                            st.markdown(
                                f"<div style='font-family:JetBrains Mono,monospace;"
                                f"font-size:11px;color:#8b95a8;padding:3px 6px;"
                                f"background:#161b22;border-radius:3px;margin-bottom:4px;"
                                f"word-break:break-all;'>{_tv}</div>",
                                unsafe_allow_html=True,
                            )

                    if not _dd_has_content:
                        if dd.get("error"):
                            st.error(dd["error"])
                        else:
                            st.caption("No DNS records found.")

            # ── Hybrid Analysis tab ────────────────────────────────────────
            if "Hybrid Analysis" in _ti:
                with _ti["Hybrid Analysis"]:
                    verdict_ha = ha.get("verdict") or ""
                    score_ha = ha.get("threat_score") or ""
                    family_ha = ha.get("malware_family") or ""

                    c1, c2, c3 = st.columns(3)
                    if verdict_ha:
                        c1.markdown(_verdict_badge(verdict_ha), unsafe_allow_html=True)
                    else:
                        c1.metric("Verdict", "—")
                    c2.metric("Threat score", score_ha or "—")
                    c3.metric("Malware family", family_ha or "—")

                    file_info = ha.get("file_information") or {}
                    if file_info and any(file_info.values()):
                        st.divider()
                        st.markdown("**File information**")
                        for fk, fv in file_info.items():
                            if fv:
                                st.markdown(f"**{fk.replace('_', ' ').title()}:** {fv}")

                    env = ha.get("analysis_environment")
                    atime = ha.get("analysis_time")
                    if env or atime:
                        st.divider()
                        if env:
                            st.markdown(f"**Analysis environment:** {env}")
                        if atime:
                            st.markdown(f"**Analysis time:** {atime}")

                    network_ioc = ha.get("network_ioc") or {}
                    net_domains = network_ioc.get("domains") or []
                    net_ips = network_ioc.get("ips") or []
                    if net_domains or net_ips:
                        st.divider()
                        st.markdown("**Network IOCs**")
                        if net_domains:
                            st.markdown("Domains: " + ", ".join(f"`{d}`" for d in net_domains))
                        if net_ips:
                            st.markdown("IPs: " + ", ".join(f"`{ip}`" for ip in net_ips))

                    behavior = ha.get("behavior") or {}
                    proc = behavior.get("process_activity") or []
                    persist = behavior.get("persistence") or []
                    dropped = behavior.get("dropped_files") or []
                    mutex = behavior.get("mutex") or []
                    if any([proc, persist, dropped, mutex]):
                        st.divider()
                        st.markdown("**Behavior**")
                        if proc:
                            with st.expander(f"Process activity ({len(proc)})"):
                                for p in proc[:20]:
                                    st.markdown(f"- `{p}`")
                        if persist:
                            st.markdown("**Persistence:**")
                            for p in persist[:10]:
                                st.markdown(f"- `{p}`")
                        if dropped:
                            st.markdown("**Dropped files:**")
                            for df in dropped[:10]:
                                name = df.get("name") or "—"
                                sha = df.get("sha256") or "—"
                                ftype = df.get("type") or "—"
                                st.markdown(f"- `{name}` ({ftype}) sha256: `{sha}`")
                        if mutex:
                            st.markdown("**Mutex:** " + ", ".join(f"`{m}`" for m in mutex[:10]))

                    mitre_attack = ha.get("mitre_attack") or []
                    if mitre_attack:
                        st.divider()
                        st.markdown("**MITRE ATT&CK**")
                        st.markdown(" ".join(f"`{t}`" for t in mitre_attack))

                    extras = {}
                    for key in ["sha256", "av_detect", "redirect_chain", "related_hashes", "first_seen",
                                "network_activity_context", "seen_in_samples", "related_domains",
                                "related_malware_family", "report_error"]:
                        value = ha.get(key)
                        if value not in (None, "", [], {}):
                            extras[key] = value
                    if extras:
                        st.divider()
                        st.markdown("**Additional context**")
                        for k, v in extras.items():
                            label = k.replace("_", " ").title()
                            if isinstance(v, list):
                                st.markdown(f"**{label}:** " + ", ".join(f"`{x}`" for x in v[:10]))
                            else:
                                st.markdown(f"**{label}:** `{v}`")

            # ── MxToolBox tab ──────────────────────────────────────────────
            if "MxToolBox" in _ti:
                with _ti["MxToolBox"]:
                    _mx_argument = mx.get("argument") or ioc.value
                    _mx_verdict = mx.get("verdict") or "UNKNOWN"
                    _mx_failed = mx.get("total_failed", 0)
                    _mx_warnings = mx.get("total_warnings", 0)
                    _mx_passed = mx.get("total_passed", 0)

                    _verdict_color = {
                        "FAIL": "#c0392b",
                        "WARN": "#e67e22",
                        "PASS": "#27ae60",
                    }.get(_mx_verdict, "#555")
                    st.markdown(
                        f"<div style='margin-bottom:10px;'>"
                        f"<span style='background:{_verdict_color};color:#fff;"
                        f"padding:3px 10px;border-radius:4px;font-size:0.9em;"
                        f"font-weight:600;'>{_mx_verdict}</span>"
                        f"&nbsp;<span style='color:#8b95a8;font-size:0.85em;'>queried: "
                        f"<code>{_mx_argument}</code></span></div>",
                        unsafe_allow_html=True,
                    )

                    _mc1, _mc2, _mc3 = st.columns(3)
                    _mc1.metric("Failed checks", _mx_failed)
                    _mc2.metric("Warnings", _mx_warnings)
                    _mc3.metric("Passed checks", _mx_passed)

                    _mx_lookups: dict = mx.get("lookups") or {}
                    _cmd_labels = {
                        "blacklist": "Blacklist",
                        "ptr": "PTR / Reverse DNS",
                        "ping": "Ping",
                        "mx": "MX Records",
                        "dns": "DNS",
                        "spf": "SPF",
                        "dmarc": "DMARC",
                        "dkim": "DKIM",
                        "http": "HTTP Check",
                        "https": "HTTPS Check",
                    }

                    for cmd, result in _mx_lookups.items():
                        if not isinstance(result, dict):
                            continue
                        _label = _cmd_labels.get(cmd, cmd.upper())
                        if result.get("error"):
                            with st.expander(f"{_label} — ⚠ Error"):
                                st.error(result["error"])
                            continue

                        _f = result.get("failed") or []
                        _w = result.get("warnings") or []
                        _p = result.get("passed") or []
                        _i = result.get("information") or []

                        if not any([_f, _w, _p, _i]):
                            continue

                        _status_icon = "🔴" if _f else ("🟡" if _w else "🟢")
                        with st.expander(f"{_status_icon} {_label} — {result['raw_failed_count']} fail, {result['raw_warning_count']} warn, {result['raw_passed_count']} pass"):
                            if _f:
                                st.markdown("**Failed**")
                                for line in _f:
                                    st.markdown(
                                        f"<div style='font-family:JetBrains Mono,monospace;"
                                        f"font-size:12px;padding:3px 6px;"
                                        f"background:#2d1a1a;border-left:3px solid #f85149;"
                                        f"border-radius:3px;margin-bottom:3px;color:#f0837f;'>"
                                        f"{line}</div>",
                                        unsafe_allow_html=True,
                                    )
                            if _w:
                                st.markdown("**Warnings**")
                                for line in _w:
                                    st.markdown(
                                        f"<div style='font-family:JetBrains Mono,monospace;"
                                        f"font-size:12px;padding:3px 6px;"
                                        f"background:#2d2410;border-left:3px solid #e3b341;"
                                        f"border-radius:3px;margin-bottom:3px;color:#e3b341;'>"
                                        f"{line}</div>",
                                        unsafe_allow_html=True,
                                    )
                            if _p:
                                st.markdown("**Passed**")
                                for line in _p:
                                    st.markdown(
                                        f"<div style='font-family:JetBrains Mono,monospace;"
                                        f"font-size:12px;padding:3px 6px;"
                                        f"background:#0e2a1a;border-left:3px solid #56d364;"
                                        f"border-radius:3px;margin-bottom:3px;color:#56d364;'>"
                                        f"{line}</div>",
                                        unsafe_allow_html=True,
                                    )
                            if _i:
                                st.markdown("**Information**")
                                for line in _i:
                                    st.markdown(f"- {line}")

            # ── Whoxy tab ──────────────────────────────────────────────────
            if "Whoxy" in _ti:
                with _ti["Whoxy"]:
                    _wx_rev = wx.get("reverse_whois") or {}
                    _wx_label = wx.get("keyword") or wx.get("domain") or ioc.value

                    def _wx_render_domains(rev: dict, domain_color: str = "#90c8f8") -> None:
                        _total = rev.get("total_results", 0)
                        _doms = rev.get("related_domains") or []
                        _pages = rev.get("total_pages", 0)
                        if rev.get("error"):
                            st.error(f"Reverse WHOIS error: {rev['error']}")
                        elif _total == 0:
                            st.caption("No domains found.")
                        else:
                            st.markdown(
                                f"<span style='color:#8b95a8;font-size:0.82rem;'>"
                                f"Found <strong style='color:#e2e6f0;'>{_total}</strong> domain(s)"
                                f"{f' across {_pages} page(s)' if _pages > 1 else ''}."
                                f" Showing top {len(_doms)}.</span>",
                                unsafe_allow_html=True,
                            )
                            if _doms:
                                _rows_html = "".join(
                                    f"<tr><td style='padding:4px 12px;font-family:"
                                    f"JetBrains Mono,monospace;font-size:0.82rem;"
                                    f"color:{domain_color};'>{d}</td></tr>"
                                    for d in _doms
                                )
                                st.markdown(
                                    "<div style='overflow-x:auto;margin:6px 0 8px 0;'>"
                                    "<table style='border-collapse:collapse;width:100%;"
                                    "font-size:0.85rem;border:1px solid #21262d;"
                                    "border-radius:6px;overflow:hidden;'>"
                                    f"<tbody>{_rows_html}</tbody></table></div>",
                                    unsafe_allow_html=True,
                                )

                    if ioc.type == "whois":
                        # ── Keyword mode: bare word → reverse WHOIS by keyword ──
                        st.markdown(
                            f"<div style='margin-bottom:10px;'>"
                            f"<span style='background:#2d1f5e;color:#b39ddb;"
                            f"padding:3px 10px;border-radius:4px;font-size:0.9em;"
                            f"font-weight:600;'>REVERSE WHOIS — KEYWORD</span>"
                            f"&nbsp;<span style='color:#8b95a8;font-size:0.85em;'>keyword: "
                            f"<code>{_wx_label}</code></span></div>",
                            unsafe_allow_html=True,
                        )
                        _wx_render_domains(_wx_rev, domain_color="#b39ddb")

                    else:
                        # ── Domain/URL mode: WHOIS + reverse by registrant ──────
                        _wx_whois = wx.get("whois") or {}
                        st.markdown(
                            f"<div style='margin-bottom:10px;'>"
                            f"<span style='background:#1f3a5f;color:#90c8f8;"
                            f"padding:3px 10px;border-radius:4px;font-size:0.9em;"
                            f"font-weight:600;'>WHOIS</span>"
                            f"&nbsp;<span style='color:#8b95a8;font-size:0.85em;'>domain: "
                            f"<code>{_wx_label}</code></span></div>",
                            unsafe_allow_html=True,
                        )

                        _wx_fields = [
                            ("Registrar", _wx_whois.get("registrar")),
                            ("Created", _wx_whois.get("created_date")),
                            ("Updated", _wx_whois.get("updated_date")),
                            ("Expires", _wx_whois.get("expires_date")),
                            ("Registrant Name", _wx_whois.get("registrant_name")),
                            ("Registrant Company", _wx_whois.get("registrant_company")),
                            ("Registrant Email", _wx_whois.get("registrant_email")),
                        ]
                        _wx_rows_html = ""
                        for _lbl, _val in _wx_fields:
                            if not _val:
                                continue
                            _wx_rows_html += (
                                f"<tr>"
                                f"<td style='padding:5px 12px;color:#8b95a8;font-size:0.83rem;"
                                f"white-space:nowrap;font-weight:600;'>{_lbl}</td>"
                                f"<td style='padding:5px 12px;color:#e2e6f0;font-family:"
                                f"JetBrains Mono,monospace;font-size:0.83rem;'>{_val}</td>"
                                f"</tr>"
                            )

                        _wx_ns = _wx_whois.get("name_servers") or []
                        if _wx_ns:
                            _wx_rows_html += (
                                f"<tr><td style='padding:5px 12px;color:#8b95a8;font-size:0.83rem;"
                                f"white-space:nowrap;font-weight:600;'>Name Servers</td>"
                                f"<td style='padding:5px 12px;color:#e2e6f0;font-family:"
                                f"JetBrains Mono,monospace;font-size:0.83rem;'>"
                                f"{', '.join(_wx_ns[:6])}</td></tr>"
                            )

                        _wx_status = _wx_whois.get("domain_status") or []
                        if _wx_status:
                            _sv = ", ".join(str(s) for s in _wx_status[:4]) if isinstance(_wx_status, list) else str(_wx_status)
                            _wx_rows_html += (
                                f"<tr><td style='padding:5px 12px;color:#8b95a8;font-size:0.83rem;"
                                f"white-space:nowrap;font-weight:600;'>Domain Status</td>"
                                f"<td style='padding:5px 12px;color:#e2e6f0;font-family:"
                                f"JetBrains Mono,monospace;font-size:0.83rem;'>{_sv}</td></tr>"
                            )

                        if _wx_rows_html:
                            st.markdown(
                                "<div style='overflow-x:auto;margin:6px 0 14px 0;'>"
                                "<table style='border-collapse:collapse;width:100%;font-size:0.88rem;"
                                "border:1px solid #21262d;border-radius:6px;overflow:hidden;'>"
                                f"<tbody>{_wx_rows_html}</tbody></table></div>",
                                unsafe_allow_html=True,
                            )
                        else:
                            st.caption("No WHOIS details available.")

                        st.divider()
                        st.markdown("**Reverse WHOIS — Related Domains**")
                        _wx_render_domains(_wx_rev, domain_color="#90c8f8")

            # ── Ransomware Live tab ────────────────────────────────────────
            if "Ransomware Live" in _ti:
                with _ti["Ransomware Live"]:
                    _rl_full = rl.get("full_domain") or ioc.value
                    _rl_sld = rl.get("sld") or ""
                    _rl_queries = rl.get("queries") or [_rl_full]
                    _rl_count = rl.get("count", 0)
                    _rl_victims = rl.get("victims") or []

                    _rl_query_badges = " &nbsp;+&nbsp; ".join(
                        f"<code>{q}</code>" for q in _rl_queries
                    )
                    st.markdown(
                        f"<div style='margin-bottom:10px;'>"
                        f"<span style='background:#3b0f0f;color:#f87171;"
                        f"padding:3px 10px;border-radius:4px;font-size:0.9em;"
                        f"font-weight:600;'>RANSOMWARE LIVE</span>"
                        f"&nbsp;<span style='color:#8b95a8;font-size:0.85em;'>queries: "
                        f"{_rl_query_badges}</span></div>",
                        unsafe_allow_html=True,
                    )
                    st.markdown(
                        f"<span style='color:#8b95a8;font-size:0.82rem;'>"
                        f"Found <strong style='color:#f87171;'>{_rl_count}</strong> victim record(s)</span>",
                        unsafe_allow_html=True,
                    )

                    for _v in _rl_victims:
                        _v_title = _v.get("post_title") or "Unknown"
                        _v_group = _v.get("group_name") or "—"
                        _v_site = _v.get("website") or ""
                        _v_country = _v.get("country") or ""
                        _v_sector = _v.get("activity") or ""
                        _v_discovered = (_v.get("discovered") or "")[:10]
                        _v_published = (_v.get("published") or "")[:10]
                        _v_desc = _v.get("description") or ""
                        _v_permalink = _v.get("permalink") or ""
                        _v_screenshot = _v.get("screenshot") or ""
                        _v_post_url = _v.get("post_url") or ""
                        _v_ransom = _v.get("ransom")
                        _v_data_size = _v.get("data_size")

                        st.markdown("<hr style='border:none;border-top:1px solid #2d2d2d;margin:12px 0;'>", unsafe_allow_html=True)

                        _header_parts = [f"<strong style='color:#f5f7fb;font-size:0.95rem;'>{_v_title}</strong>"]
                        if _v_group:
                            _header_parts.append(
                                f"<span style='background:#4b0000;color:#fca5a5;"
                                f"padding:2px 8px;border-radius:4px;font-size:0.78rem;"
                                f"margin-left:8px;'>{_v_group}</span>"
                            )
                        if _v_country:
                            _header_parts.append(
                                f"<span style='background:#1e293b;color:#94a3b8;"
                                f"padding:2px 8px;border-radius:4px;font-size:0.78rem;"
                                f"margin-left:4px;'>{_v_country}</span>"
                            )
                        st.markdown("".join(_header_parts), unsafe_allow_html=True)

                        _meta_rows = []
                        if _v_site:
                            _meta_rows.append(("Website", _v_site))
                        if _v_sector and _v_sector != "Not Found":
                            _meta_rows.append(("Sector", _v_sector))
                        if _v_discovered:
                            _meta_rows.append(("Discovered", _v_discovered))
                        if _v_published:
                            _meta_rows.append(("Published", _v_published))
                        if _v_ransom is not None:
                            _meta_rows.append(("Ransom", f"${_v_ransom:,}" if isinstance(_v_ransom, (int, float)) else str(_v_ransom)))
                        if _v_data_size:
                            _meta_rows.append(("Data Size", str(_v_data_size)))

                        if _meta_rows:
                            _meta_html = "".join(
                                f"<tr>"
                                f"<td style='padding:4px 12px;color:#8b95a8;font-size:0.81rem;"
                                f"white-space:nowrap;font-weight:600;'>{_lbl}</td>"
                                f"<td style='padding:4px 12px;color:#e2e6f0;font-family:"
                                f"JetBrains Mono,monospace;font-size:0.81rem;'>{_val}</td>"
                                f"</tr>"
                                for _lbl, _val in _meta_rows
                            )
                            st.markdown(
                                "<div style='overflow-x:auto;margin:6px 0 8px 0;'>"
                                "<table style='border-collapse:collapse;width:100%;font-size:0.85rem;"
                                "border:1px solid #2d2d2d;border-radius:6px;overflow:hidden;'>"
                                f"<tbody>{_meta_html}</tbody></table></div>",
                                unsafe_allow_html=True,
                            )

                        if _v_desc:
                            _desc_clean = _v_desc.replace("[AI generated] ", "")
                            st.markdown(
                                f"<p style='color:#9ca3af;font-size:0.82rem;margin:4px 0 6px 0;"
                                f"line-height:1.5;'>{_desc_clean}</p>",
                                unsafe_allow_html=True,
                            )

                        _link_parts = []
                        if _v_permalink:
                            _link_parts.append(f"<a href='{_v_permalink}' target='_blank' style='color:#f87171;font-size:0.82rem;'>🔗 Ransomware.live</a>")
                        if _v_post_url:
                            _link_parts.append(f"<a href='{_v_post_url}' target='_blank' style='color:#8b95a8;font-size:0.82rem;'>📄 Original Post</a>")
                        if _link_parts:
                            st.markdown(" &nbsp;·&nbsp; ".join(_link_parts), unsafe_allow_html=True)

                        if _v_screenshot:
                            with st.expander("Screenshot"):
                                st.image(_v_screenshot, use_container_width=True)
