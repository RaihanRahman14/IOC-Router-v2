"""AI output panel — threat analysis, AI description, share text generation."""
from __future__ import annotations

import base64
import os
import re
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import quote_plus, urlsplit, urlunsplit

import requests

import streamlit as st
import streamlit.components.v1 as components

from ioc.flags import extract_ioc_flags, flags_to_ai_context, flags_summary_for_evidence
from ioc.threat_analysis import analyzeThreat
from providers.gemini import gemini_generate, gemini_list_models
from providers.groq import groq_generate
from core.geo import fetch_geo_ip_api, fetch_nominatim


# ── Help text for the Threat State / Level / Verdict override dropdowns ──────
# Rendered as the "?" tooltip next to each selectbox (Streamlit renders markdown).
# See docs/threat_state_level_verdict.md for the full breakdown.
_THREAT_STATE_HELP = (
    "**How far the attack has progressed (kill-chain stage):**\n\n"
    "- **Exposure** — asset merely exposed/visible; no attack activity.\n"
    "- **Intrusion Attempt** — recon, phishing, or exploit attempt, *or* a "
    "serious attack that was blocked by controls.\n"
    "- **Compromise** — foothold gained: malware executed or C2 communication.\n"
    "- **Privilege Escalation** — attacker gained higher privileges.\n"
    "- **Lateral Movement** — attacker spreading to other systems.\n"
    "- **Persistence** — attacker established a survival mechanism.\n"
    "- **Impact** — real damage: data exfiltration or service disruption/encryption."
)

_THREAT_LEVEL_HELP = (
    "**Severity / response priority:**\n\n"
    "- **Low** — minimal risk; exposure or attempts with no real progress.\n"
    "- **Medium** — confirmed compromise, limited scope; needs investigation.\n"
    "- **High** — serious progression (priv-esc, lateral, persistence) or "
    "critical-asset compromise; prompt response.\n"
    "- **Very High** — active impact (exfiltration/encryption) or critical "
    "assets under advanced attack; immediate escalation."
)

_VERDICT_HELP = (
    "**The analyst's final call on the alert:**\n\n"
    "- **True Positive** 🔴 — a genuine, meaningful threat; warrants action.\n"
    "- **Benign Positive** 🟠 — real activity detected, but low-impact or "
    "already contained (attempts, recon, blocked attacks).\n"
    "- **False Positive** 🟢 — no actual threat signal; the alert can be dismissed."
)


def defang_for_display(value: str) -> str:
    """Neutralise an indicator so it is safe to show and cannot be clicked.

    Serves two purposes at once, which is why it is applied to the badge text:

    * **Safety.** A live link to attacker infrastructure sitting in a triage UI
      is one stray click away from a request nobody authorised. Defanged text is
      the SOC convention for exactly this reason.
    * **Correctness.** Streamlit's markdown renderer auto-links any bare URL,
      even inside ``unsafe_allow_html`` markup. Inside the badge's own ``<a>``
      that produced a nested anchor — invalid HTML, which browsers repair by
      closing the outer tag early, leaving an empty coloured box with the URL
      spilled outside it. Defanging removes the pattern the linkifier matches,
      so the badge keeps its contents.

    Only the host is altered; the path is left readable.

    Args:
        value: An IOC — URL, domain, IP or hash.

    Returns:
        The display-safe form, e.g. ``hxxp://198.51.100[.]7/a.ps1``. Hashes and
        anything without a host come back unchanged.
    """
    text = str(value or "").strip()
    if not text:
        return ""

    if re.match(r"^https?://", text, re.IGNORECASE):
        try:
            parsed = urlsplit(text)
        except ValueError:
            return text
        if parsed.netloc:
            scheme = parsed.scheme.lower().replace("http", "hxxp", 1)
            rebuilt = urlunsplit((
                scheme, parsed.netloc.replace(".", "[.]"),
                parsed.path, parsed.query, parsed.fragment,
            ))
            return rebuilt
        return text

    # A bare IP or domain: no scheme to neutralise, so the dots do the work.
    if re.match(r"^[A-Za-z0-9.\-_]+$", text) and "." in text:
        return text.replace(".", "[.]")
    return text


def _get_effective_device_action() -> str:
    """Return the effective device action value, resolving 'Others' to the custom text input.

    Reads from the Result-tab snapshot (``result_*``) since this panel only
    renders inside the Result tab (after :func:`app._snapshot_input_context_to_result`
    has populated those keys).
    """
    action = (st.session_state.get("result_device_action") or "").strip()
    if action in ("", "None"):
        return ""
    if action == "Others":
        return (st.session_state.get("result_device_action_others") or "").strip()
    return action


def _clear_ai_outputs() -> None:
    """Clear all AI-generated session state outputs."""
    for _k in ("ai_desc", "ai_threat_analysis", "ai_ioc_links", "ai_timing"):
        if _k in st.session_state:
            del st.session_state[_k]


def render_ai_panel(run_results: dict, settings) -> None:
    """Render the AI output panel (left split) for threat analysis and AI description.

    Args:
        run_results: The full run_results dict from session state.
        settings: The Settings object with API keys and model config.
    """
    items = run_results["items"]
    vt_results = run_results["vt"]
    urlscan_results = run_results["urlscan"]
    abuse_results = run_results["abuse"]
    tf_results = run_results["tf"]
    mb_results = run_results["mb"]
    shodan_results = run_results["shodan"]
    dnsd_results = run_results.get("dnsd", {})
    ha_results = run_results.get("ha", {})
    mxtoolbox_results = run_results.get("mxtoolbox", {})
    ransomware_live_results = run_results.get("ransomware_live", {})

    # AI provider/tone/model selectors are rendered later, inline with the
    # AI Output text area — but we read defaults here so prompt builders below
    # work even before the user opens the inline settings expander.
    if "ai_provider" not in st.session_state:
        st.session_state["ai_provider"] = "Gemini"
    if "ai_tone" not in st.session_state:
        st.session_state["ai_tone"] = "High level language"
    if "ai_use_only_evidence" not in st.session_state:
        st.session_state["ai_use_only_evidence"] = True
    if "ai_sanitize" not in st.session_state:
        st.session_state["ai_sanitize"] = True
    ai_provider = st.session_state.get("ai_provider", "Gemini")
    tone = st.session_state.get("ai_tone", "High level language")
    use_only_evidence = st.session_state.get("ai_use_only_evidence", True)
    sanitize = st.session_state.get("ai_sanitize", True)
    selections = [ioc.value for ioc in items]
    selected = selections

    def _clip(value: object, limit: int = 600) -> str:
        text = str(value)
        if len(text) <= limit:
            return text
        return text[:limit] + "...(truncated)"

    def _vt_url_id(url: str) -> str:
        raw_bytes = str(url or "").encode("utf-8")
        return base64.urlsafe_b64encode(raw_bytes).decode("utf-8").rstrip("=")

    def _vt_gui_url(ioc_value: str, ioc_type: str) -> str:
        """Return the VirusTotal GUI URL that actually holds this IOC's report.

        VirusTotal keys URL reports by the exact string, so http:// and https://
        are separate entries. When the parser inferred the scheme, the report may
        sit under the other form than the canonical ``ioc_value``; the provider
        records whichever it matched as ``matched_url``. Preferring it keeps the
        link pointing at the same report the displayed stats came from.

        Args:
            ioc_value: The IOC value as shown in the UI.
            ioc_type: One of ip, domain, url, hash.

        Returns:
            The VirusTotal GUI URL, or an empty string for unsupported types.
        """
        if ioc_type == "url":
            matched = (vt_results.get(ioc_value, {}) or {}).get("matched_url")
            return f"https://www.virustotal.com/gui/url/{_vt_url_id(matched or ioc_value)}"
        if ioc_type == "ip":
            return f"https://www.virustotal.com/gui/ip-address/{ioc_value}"
        if ioc_type == "domain":
            return f"https://www.virustotal.com/gui/domain/{ioc_value}"
        if ioc_type == "hash":
            return f"https://www.virustotal.com/gui/file/{ioc_value}"
        return ""

    def _ha_text_payload(val: str) -> object:
        ha = ha_results.get(val, {})
        if not ha:
            return "No data"
        message = str(ha.get("message") or "").strip()
        if message in {
            "Not supported by Hybrid Analysis API",
            "Hybrid Analysis does not analyze email indicators.",
            "No results found",
        }:
            return "No data"
        return ha

    def _provider_has_data(provider_name: str, ioc) -> bool:
        value = ioc.value
        if provider_name == "virustotal":
            vt = vt_results.get(value, {}) or {}
            return bool(vt and (vt.get("attributes") or vt.get("stats") or vt.get("id")))
        if provider_name == "urlscan":
            us = urlscan_results.get(value, {}) or {}
            return bool(us and (us.get("uuid") or us.get("result") or us.get("page") or us.get("task")))
        if provider_name == "abuseipdb":
            ab = abuse_results.get(value, {}) or {}
            return bool(ab and not ab.get("error"))
        if provider_name == "threatfox":
            tf = tf_results.get(value, {}) or {}
            return bool(tf.get("query_status") == "ok" and tf.get("data"))
        if provider_name == "malwarebazaar":
            mb = mb_results.get(value, {}) or {}
            return bool(mb.get("query_status") == "ok" and mb.get("data"))
        if provider_name == "shodan":
            sh = shodan_results.get(value, {}) or {}
            return bool(sh and not sh.get("error") and (sh.get("summary") or sh.get("ports") or sh.get("queriedIp")))
        if provider_name == "dnsdumpster":
            dd = dnsd_results.get(value, {}) or {}
            return bool(dd and not dd.get("error") and (dd.get("soc_summary") or dd.get("dns_records") or dd.get("host_records")))
        if provider_name == "hybrid_analysis":
            ha = ha_results.get(value, {}) or {}
            if not ha:
                return False
            message = str(ha.get("message") or "").strip()
            if message in {
                "Not supported by Hybrid Analysis API",
                "Hybrid Analysis does not analyze email indicators.",
                "No results found",
            }:
                return False
            return bool(
                ha.get("verdict")
                or ha.get("threat_score")
                or ha.get("malware_family")
                or (ha.get("network_ioc") or {}).get("domains")
                or (ha.get("network_ioc") or {}).get("ips")
                or any((ha.get("behavior") or {}).values())
            )
        if provider_name == "ransomware_live":
            rl = ransomware_live_results.get(value, {}) or {}
            return bool(rl and not rl.get("error") and rl.get("count", 0) > 0)
        return False

    def _build_ioc_links(selected_values: list[str]) -> str:
        link_lines: list[str] = []
        for ioc in items:
            if ioc.value not in selected_values:
                continue

            links: list[str] = []
            value = ioc.value
            ioc_type = ioc.type

            if ioc_type in {"ip", "domain", "url", "hash"} and _provider_has_data("virustotal", ioc):
                _vt_link = _vt_gui_url(value, ioc_type)
                if _vt_link:
                    links.append(f"VirusTotal: {_vt_link}")

            if ioc_type in {"ip", "domain", "url", "hash"} and _provider_has_data("urlscan", ioc):
                if ioc_type == "ip":
                    links.append(f"urlscan: https://urlscan.io/ip/{value}")
                elif ioc_type == "domain":
                    links.append(f"urlscan: https://urlscan.io/domain/{value}")
                elif ioc_type == "url":
                    links.append(f"urlscan: https://urlscan.io/search/#q={quote_plus(value)}")
                elif ioc_type == "hash":
                    links.append(f"urlscan: https://urlscan.io/search/#q=hash:{quote_plus(value)}")

            if ioc_type == "ip" and _provider_has_data("abuseipdb", ioc):
                links.append(f"AbuseIPDB: https://www.abuseipdb.com/check/{value}")

            if ioc_type in {"ip", "domain", "url", "hash"} and _provider_has_data("threatfox", ioc):
                links.append(f"ThreatFox: https://threatfox.abuse.ch/browse.php?search={quote_plus(value)}")

            if ioc_type == "hash" and _provider_has_data("malwarebazaar", ioc):
                links.append(f"MalwareBazaar: https://bazaar.abuse.ch/sample/{value}/")

            if ioc_type in {"ip", "domain"} and _provider_has_data("shodan", ioc):
                if ioc_type == "ip":
                    links.append(f"Shodan: https://www.shodan.io/host/{value}")
                else:
                    links.append(f"Shodan: https://www.shodan.io/domain/{value}")

            if ioc_type in {"domain", "url"} and _provider_has_data("dnsdumpster", ioc):
                _dd_target = dnsd_results.get(value, {}).get("queriedDomain") or value
                links.append(f"DNSDumpster: https://dnsdumpster.com/?s={_dd_target}")

            if ioc_type in {"ip", "domain", "url", "hash"} and _provider_has_data("hybrid_analysis", ioc):
                if ioc_type == "hash":
                    links.append(f"Hybrid Analysis: https://hybrid-analysis.com/sample/{value}")
                else:
                    links.append(f"Hybrid Analysis: https://hybrid-analysis.com/search?query={quote_plus(value)}")

            if links:
                link_lines.append(f"Source: {value} ({ioc_type})")
                link_lines.extend(f"- {line}" for line in links)

        return "\n".join(link_lines)

    def _build_prompt(selected_values: list[str], section: str) -> str:
        lines = []
        lines.append(f"You are a SOC assistant. Generate ONLY the {section} section.")
        if section == "SHORT":
            lines.append("Output 2-4 sentences.")
        else:
            lines.append("Output a concise ticket description in 4-6 sentences.")
            lines.append("Write exactly one paragraph.")
            lines.append("Do not truncate output. Always finish with complete sentences.")
            lines.append("Include a concluding assessment sentence based on all evidence.")
            lines.append("Do not mention remediation or recommended actions.")
        lines.append("Return plain text only, no bullets.")
        lines.append("Use only the evidence provided. If evidence is insufficient, say 'inconclusive' and recommend next checks.")
        if tone == "High level language":
            lines.append("Tone: Write for an IT professional who understands systems and infrastructure but has no security background.")
            lines.append("Avoid all security jargon — do not use terms like 'IOC', 'C2', 'threat actor', 'lateral movement', 'TTPs', 'MITRE', 'CVE', or similar.")
            lines.append("Instead of naming tools or techniques, describe what they do in plain terms (e.g. instead of 'C2 beacon', say 'the affected machine was quietly sending data out to an external address').")
            lines.append("Tell it as a short story: what was observed, what it could mean for the organisation, and why it is a concern.")
            lines.append("Lead with impact — emphasise what could go wrong or what may already have happened, not how it was detected.")
            lines.append("Keep the language natural and direct, as if briefing a senior IT manager who needs to understand urgency without a security lecture.")
        else:
            lines.append(f"Tone: {tone}.")
        if sanitize:
            lines.append("Sanitize sensitive data where possible.")
        # Shared process/action context — always included when values are present
        _ctx_device_action = _get_effective_device_action()
        _ctx_parent = st.session_state.get("result_parent_process") or ""
        _ctx_child = st.session_state.get("result_child_process") or ""
        _ctx_file_path = st.session_state.get("result_file_path") or ""
        _ctx_cmdline = st.session_state.get("result_command_line") or ""
        _has_process_ctx = bool(
            _ctx_device_action or _ctx_parent or _ctx_child or _ctx_file_path or _ctx_cmdline
        )
        if _has_process_ctx:
            lines.append("Additional endpoint context (use if present, do not invent):")
            if _ctx_device_action:
                lines.append(f"  Device Action: {_ctx_device_action} — incorporate this to indicate whether the activity was blocked/prevented or allowed.")
            if _ctx_cmdline:
                lines.append(
                    f"  Command Line: {_ctx_cmdline} — the command line the process "
                    "was executed with."
                )
            if _ctx_file_path:
                lines.append(f"  File Path: {_ctx_file_path} — the file path involved in the activity.")
            if _ctx_parent:
                lines.append(f"  Parent Process: {_ctx_parent} — the process that spawned the suspicious activity.")
            if _ctx_child:
                lines.append(f"  Child Process: {_ctx_child} — the process spawned as a result of the activity.")

        # Structured findings from the process/filepath analyzer. Without the
        # skipped-checks list the model implies certainty about fields the
        # analyst never filled.
        _proc = run_results.get("process_analysis") or {}
        _proc_flags = run_results.get("process_flags") or []
        if _proc.get("fields_submitted"):
            lines.append("Process / filepath analysis (local datasets, no provider lookup):")
            lines.append(f"  Verdict: {_proc.get('aggregated_verdict', 'Unknown')}")
            if _proc_flags:
                lines.append(f"  Findings:\n{flags_to_ai_context(_proc_flags)}")
            else:
                lines.append("  Findings: none — no masquerading, pairing, or dual-use match.")
            if _proc.get("checks_skipped"):
                lines.append(
                    "  Checks NOT performed (field not provided — do not imply these were "
                    "cleared): " + "; ".join(_proc["checks_skipped"])
                )
            lines.append(
                "  Treat 'Unknown' as unverified, never as benign. Do not claim a field was "
                "checked unless it appears above."
            )

        # Structured findings from the command-line analyzer. The decoded form
        # and its decode chain go in verbatim: a decoded command the model
        # cannot trace back to its source is worse than no decode at all.
        _cmd = run_results.get("cmdline_analysis") or {}
        _cmd_flags = run_results.get("cmdline_flags") or []
        if _cmd.get("commands"):
            lines.append("Command line analysis (local datasets, no provider lookup):")
            lines.append(f"  Verdict: {_cmd.get('aggregated_verdict', 'Unknown')}")
            lines.append(f"  Interpreter: {_cmd.get('interpreter_detected', 'unknown')}")
            if _cmd.get("was_obfuscated"):
                lines.append(
                    f"  Obfuscated — decoded via {' -> '.join(_cmd.get('decode_chain') or [])}."
                )
                lines.append(f"  Decoded form: {_cmd.get('decoded_command') or ''}")
                if _cmd.get("revealed_keywords"):
                    lines.append(
                        "  Only visible after decoding: "
                        + ", ".join(_cmd["revealed_keywords"])
                    )
            if _cmd_flags:
                lines.append(f"  Findings:\n{flags_to_ai_context(_cmd_flags)}")
            else:
                lines.append("  Findings: none — no suspicious switch or keyword matched.")
            if _cmd.get("checks_skipped"):
                lines.append(
                    "  Checks NOT performed (do not imply these were cleared): "
                    + "; ".join(_cmd["checks_skipped"])
                )
            _lolbas = _cmd.get("lolbas_cross_check") or {}
            if _lolbas.get("match_strength") == "CONFIRMED_ABUSE_PATTERN":
                lines.append(
                    f"  LOLBAS: {_lolbas.get('binary')} arguments match its documented "
                    f"{_lolbas.get('category') or 'abuse'} pattern "
                    f"({_lolbas.get('matched')!r}) — not merely a dual-use binary."
                )
            elif _lolbas.get("match_strength") == "DUAL_USE_PRESENT":
                lines.append(
                    f"  LOLBAS: {_lolbas.get('binary')} is dual-use, but its arguments match "
                    "no documented abuse pattern. Do not treat this as incriminating."
                )
            if _cmd.get("rule_matches"):
                lines.append("  Detection rules matched:")
                for _rm in _cmd["rule_matches"][:5]:
                    _exact = "exact" if _rm.get("faithful_multifield") else "approximate"
                    lines.append(
                        f"    - [{_rm.get('sigma_level')}] {_rm.get('title')} "
                        f"(matched {_rm.get('matched')!r}, {_exact})"
                    )
                if _cmd.get("joined_rule_count"):
                    lines.append(
                        f"  {_cmd['joined_rule_count']} rule(s) were confirmed against the "
                        "process/filepath analysis, satisfying their full original condition."
                    )
            lines.append(
                "  A 'Suspicious' verdict here means no second independent source agreed — "
                "treat it as unresolved, never as reassurance."
            )

        # Structured findings from the WAF payload analyzer. The decoded payload
        # and its chain go in verbatim, same reasoning as the command line above.
        # The skipped-checks list matters more here than anywhere else: in
        # Milestone A only decoding has run, so every verdict is Unknown for lack
        # of a rule set rather than for lack of findings.
        _waf = run_results.get("waf_analysis") or []
        _waf_flags = run_results.get("waf_flags") or []
        if _waf:
            lines.append("WAF payload analysis (local, no provider lookup):")
            for _entry in _waf[:10]:
                _path = _entry.get("path") or "(no path)"
                lines.append(f"  - Path: {_path}")
                lines.append(f"    Payload: {_entry.get('raw_payload') or '(empty)'}")
                if _entry.get("was_encoded"):
                    lines.append(
                        "    Decoded via "
                        f"{' -> '.join(_entry.get('decode_chain') or [])}: "
                        f"{_entry.get('decoded_payload') or ''}"
                    )
                if not _entry.get("parse_ok"):
                    lines.append("    No payload followed the delimiter — nothing to analyse.")
                elif not _entry.get("decode_ok"):
                    lines.append("    Decoding did not complete; the payload above is partial.")
                lines.append(f"    Verdict: {_entry.get('aggregated_verdict', 'Unknown')}")
            if _waf_flags:
                lines.append(f"  Findings:\n{flags_to_ai_context(_waf_flags)}")
            # Every payload's warnings, not just the first one's. Reading
            # _waf[0] alone presented a second, truncated payload to the model
            # as though it had been fully assessed.
            _skipped = sorted({
                note for _entry in _waf for note in (_entry.get("checks_skipped") or [])
            })
            if _skipped:
                lines.append(
                    "  Checks NOT performed (do not imply these were cleared): "
                    + "; ".join(_skipped)
                )
            lines.append(
                "  These verdicts come from local rule sets only — OWASP CRS patterns and a "
                "curated CVE fingerprint list — with no external provider consulted. "
                "'Unknown' means no local rule matched; it is NOT a finding of benign, "
                "harmless, or checked-and-clear. 'Suspicious' means a pattern matched but "
                "nothing independent confirmed it."
            )

        if section == "DESCRIPTION":
            host_ip_value = st.session_state.get("result_host_ip") or st.session_state.get("source_ip") or "N/A"
            raw_log_value = (st.session_state.get("result_raw_log") or "").strip()
            lines.append("Use the available context fields below as part of the description narrative.")
            lines.append("Map them as follows: what/how=Alert Name, who=Host and Host IP (internal IP), when=Time Detected, where=Artifacts/IOCs.")
            lines.append("Treat Host IP as the affected internal IP. If an IOC is an IP, treat it as an external IP that may represent either the source or destination of the connection.")
            lines.append("Use Raw Log only as supporting context for the description. Do not invent fields that are not explicitly present.")
            lines.append("If a context field is present, incorporate it naturally into the paragraph.")
            lines.append(f"Context what/how: {st.session_state.get('result_alert_name') or 'N/A'}")
            lines.append(f"Context who host: {st.session_state.get('result_host') or 'N/A'}")
            lines.append(f"Context who host_ip (internal): {host_ip_value}")
            lines.append(f"Context when: {st.session_state.get('result_time_detected') or 'N/A'}")
            where_values = [f"{ioc.value} ({ioc.type})" for ioc in items if ioc.value in selected_values]
            lines.append(f"Context where artifacts: {', '.join(where_values) if where_values else 'N/A'}")
            lines.append(f"Context raw_log: {raw_log_value if raw_log_value else 'N/A'}")
        lines.append("Evidence bundle:")
        for ioc in items:
            if ioc.value not in selected_values:
                continue
            lines.append(f"- IOC: {ioc.value} ({ioc.type})")
            lines.append(f"  VT: {_clip(vt_results.get(ioc.value, {}))}")
            lines.append(f"  urlscan: {_clip(urlscan_results.get(ioc.value, {}))}")
            lines.append(f"  AbuseIPDB: {_clip(abuse_results.get(ioc.value, {}))}")
            lines.append(f"  ThreatFox: {_clip(tf_results.get(ioc.value, {}))}")
            lines.append(f"  MalwareBazaar: {_clip(mb_results.get(ioc.value, {}))}")
            lines.append(f"  Shodan: {_clip(shodan_results.get(ioc.value, {}))}")
            lines.append(f"  DNSDumpster: {_clip(dnsd_results.get(ioc.value, {}))}")
            lines.append(f"  Hybrid Analysis: {_clip(_ha_text_payload(ioc.value))}")
            _mx_entry = mxtoolbox_results.get(ioc.value, {})
            if _mx_entry and not _mx_entry.get("error"):
                _mx_clip = {"verdict": _mx_entry.get("verdict"), "total_failed": _mx_entry.get("total_failed"), "total_warnings": _mx_entry.get("total_warnings")}
                lines.append(f"  MxToolBox: {_clip(_mx_clip)}")
            _rl_entry = ransomware_live_results.get(ioc.value, {})
            if _rl_entry and not _rl_entry.get("error") and _rl_entry.get("count", 0) > 0:
                _rl_victims = (_rl_entry.get("victims") or [])[:2]
                _rl_groups = list(dict.fromkeys(str(v.get("group_name") or "") for v in _rl_victims if v.get("group_name")))
                _rl_clip = {
                    "count": _rl_entry.get("count"),
                    "groups": _rl_groups,
                    "recent": [{"title": v.get("post_title"), "discovered": v.get("discovered")} for v in _rl_victims],
                }
                lines.append(f"  Ransomware.live: {_clip(_rl_clip)}")
            # Inject structured threat flags as additional context
            _ioc_flags = extract_ioc_flags(
                ioc.value, ioc.type,
                vt_results.get(ioc.value, {}) or {},
                urlscan_results.get(ioc.value, {}) or {},
                abuse_results.get(ioc.value, {}) or {},
                tf_results.get(ioc.value, {}) or {},
                mb_results.get(ioc.value, {}) or {},
                shodan_results.get(ioc.value, {}) or {},
                dnsd_results.get(ioc.value, {}) or {},
                ha_results.get(ioc.value, {}) or {},
                mxtoolbox_results.get(ioc.value, {}) or {},
                ransomware_live_results.get(ioc.value, {}) or {},
            )
            if _ioc_flags:
                lines.append(f"  Threat Flags:\n{flags_to_ai_context(_ioc_flags)}")
        return "\n".join(lines)

    def _obfuscate_domains_and_urls(text: str) -> str:
        raw = str(text or "")

        def _obfuscate_host(host: str) -> str:
            return host.replace(".", "[.]")

        # Obfuscate host part in full URLs first.
        url_pattern = re.compile(r"\bhttps?://[^\s]+", re.IGNORECASE)

        def _url_repl(match: re.Match) -> str:
            token = match.group(0)
            trailing = ""
            while token and token[-1] in ".,;:!?)]}\"'":
                trailing = token[-1] + trailing
                token = token[:-1]
            try:
                parsed = urlsplit(token)
                if not parsed.netloc:
                    return match.group(0)
                obf_netloc = _obfuscate_host(parsed.netloc)
                rebuilt = urlunsplit((parsed.scheme, obf_netloc, parsed.path, parsed.query, parsed.fragment))
                return rebuilt + trailing
            except Exception:
                return match.group(0)

        out = url_pattern.sub(_url_repl, raw)

        # Obfuscate bare domains.
        domain_pattern = re.compile(
            r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
            re.IGNORECASE,
        )
        return domain_pattern.sub(lambda m: _obfuscate_host(m.group(0)), out)

    def _build_analysis_summary(selected_values: list[str]) -> dict:
        picked = set(selected_values or [])
        evidence = {
            "attack_prevented": False,
            "scanning_or_recon": False,
            "phishing_or_social_eng": False,
            "exploit_attempt": False,
            "malware_executed": False,
            "c2_connection": False,
            "privilege_escalation": False,
            "lateral_movement": False,
            "persistence_mechanism": False,
            "data_exfiltration": False,
            "service_disruption_or_encryption": False,
        }
        notes: list[str] = []
        tactics = set()

        def _add_note(text: str) -> None:
            if text and text not in notes and len(notes) < 12:
                notes.append(text)

        for ioc in items:
            if picked and ioc.value not in picked:
                continue
            _vt  = vt_results.get(ioc.value, {}) or {}
            us   = urlscan_results.get(ioc.value, {}) or {}
            ab   = abuse_results.get(ioc.value, {}) or {}
            tf   = tf_results.get(ioc.value, {}) or {}
            mb   = mb_results.get(ioc.value, {}) or {}
            sh   = shodan_results.get(ioc.value, {}) or {}
            dnsd = dnsd_results.get(ioc.value, {}) or {}
            ha   = ha_results.get(ioc.value, {}) or {}
            mx   = mxtoolbox_results.get(ioc.value, {}) or {}
            rl   = ransomware_live_results.get(ioc.value, {}) or {}

            # --- Derive evidence from flags ---
            ioc_flags = extract_ioc_flags(
                ioc.value, ioc.type, _vt, us, ab, tf, mb, sh, dnsd, ha, mx, rl
            )
            flag_summary = flags_summary_for_evidence(ioc_flags)
            for k, v in flag_summary["evidence"].items():
                if v:
                    evidence[k] = True
            for t in flag_summary["mitre_tactics"]:
                tactics.add(t)
            for n in flag_summary["notes"]:
                _add_note(n)

            # --- Keep original signals for backward compat ---
            verdicts = us.get("verdicts", {}) if isinstance(us.get("verdicts"), dict) else {}
            if verdicts.get("phishing"):
                evidence["phishing_or_social_eng"] = True
                tactics.add("TA0001")
            if verdicts.get("malicious"):
                evidence["attack_prevented"] = True

            tf_rows = tf.get("data", []) if isinstance(tf.get("data"), list) else []
            for row in tf_rows:
                if not isinstance(row, dict):
                    continue
                tt = str(row.get("threat_type") or "").lower()
                if "exploit" in tt:
                    evidence["exploit_attempt"] = True
                    tactics.add("TA0001")

            ha_behavior = ha.get("behavior", {}) if isinstance(ha.get("behavior"), dict) else {}
            ha_mitre = ha.get("mitre_attack", []) if isinstance(ha.get("mitre_attack"), list) else []
            if ha_behavior.get("persistence"):
                evidence["persistence_mechanism"] = True
                tactics.add("TA0003")
            for technique in ha_mitre:
                if isinstance(technique, str) and technique.strip():
                    tactics.add(technique.strip())

        # Process/filepath findings are event-level, not per-IOC, so they are
        # folded in once here rather than inside the per-IOC loop above. They go
        # through the same evidence mapper as provider flags.
        _event_flags = (
            (run_results.get("process_flags") or [])
            + (run_results.get("cmdline_flags") or [])
            + (run_results.get("waf_flags") or [])
        )
        if _event_flags:
            _proc_summary = flags_summary_for_evidence(_event_flags)
            for k, v in _proc_summary["evidence"].items():
                if v:
                    evidence[k] = True
            for t in _proc_summary["mitre_tactics"]:
                tactics.add(t)
            for n in _proc_summary["notes"]:
                _add_note(n)

        if evidence["phishing_or_social_eng"] or evidence["exploit_attempt"] or evidence["scanning_or_recon"]:
            evidence["attack_prevented"] = evidence["attack_prevented"] or not (evidence["malware_executed"] or evidence["c2_connection"])

        return {
            "evidence": evidence,
            "mitre_tactics": sorted(tactics),
            "risk_notes": notes[:8],
            "asset_criticality": "critical" if st.session_state.get("result_critical_asset_sel") == "Critical Asset" else "standard",
            "device_action": _get_effective_device_action(),
        }

    def _to_bold_unicode(text: str) -> str:
        out = []
        for ch in str(text):
            if "A" <= ch <= "Z":
                out.append(chr(ord(ch) - ord("A") + 0x1D400))
            elif "a" <= ch <= "z":
                out.append(chr(ord(ch) - ord("a") + 0x1D41A))
            elif "0" <= ch <= "9":
                out.append(chr(ord(ch) - ord("0") + 0x1D7CE))
            else:
                out.append(ch)
        return "".join(out)

    def _derive_threat_category(ev: dict) -> str:
        if ev.get("data_exfiltration") or ev.get("service_disruption_or_encryption"):
            return "Impact/Exfiltration"
        if ev.get("persistence_mechanism"):
            return "Persistence Mechanism"
        if ev.get("lateral_movement"):
            return "Lateral Movement Technique"
        if ev.get("privilege_escalation"):
            return "Privilege Escalation Technique"
        if ev.get("malware_executed") or ev.get("c2_connection"):
            return "Execution and C2"
        if ev.get("phishing_or_social_eng"):
            return "Phishing/Social Engineering"
        if ev.get("exploit_attempt"):
            return "Exploitation Attempt"
        if ev.get("scanning_or_recon"):
            return "Reconnaissance/Scanning"
        return "Exposure/Misconfiguration"

    def _derive_attack_status(ev: dict) -> str:
        has_active = any(
            [
                ev.get("malware_executed"),
                ev.get("c2_connection"),
                ev.get("privilege_escalation"),
                ev.get("lateral_movement"),
                ev.get("persistence_mechanism"),
                ev.get("data_exfiltration"),
                ev.get("service_disruption_or_encryption"),
            ]
        )
        has_attempt = any([ev.get("scanning_or_recon"), ev.get("phishing_or_social_eng"), ev.get("exploit_attempt")])
        if has_active:
            return "Active"
        if ev.get("attack_prevented") and has_attempt:
            return "Prevented/Blocked"
        if has_attempt:
            return "Attempted"
        return "No active attack evidence"

    def _build_reason_fallbacks(summary: dict, state: str, level: str) -> list[str]:
        ev = summary.get("evidence", {}) if isinstance(summary, dict) else {}
        if not isinstance(ev, dict):
            ev = {}
        category = _derive_threat_category(ev)
        status = _derive_attack_status(ev)
        criticality = str(summary.get("asset_criticality", "standard")).lower()

        state_reason_map = {
            "Impact": "attack progression has reached business impact",
            "Persistence": "attack progression indicates a sustained foothold",
            "Lateral Movement": "attack progression indicates movement between hosts",
            "Privilege Escalation": "attack progression indicates privilege elevation",
            "Compromise": "attack progression has moved beyond attempt to full compromise",
            "Intrusion Attempt": "attack progression is still at the attempt stage",
            "Exposure": "no active attack progression observed",
        }
        r1 = f"Threat State {state} selected because {state_reason_map.get(state, 'observed evidence progression')}."
        r2 = f"Threat Category {category} derived from techniques observed in the evidence."
        r3 = f"Attack Status {status} with asset criticality {criticality} yields Threat Level {level}."
        return [r1, r2, r3]

    def _format_threat_text_for_box(raw_text: str, summary: dict) -> str:
        lines = [ln.strip() for ln in str(raw_text or "").splitlines() if ln.strip()]
        state = ""
        level = ""
        risk_label = ""
        reasons: list[str] = []

        for ln in lines:
            low = ln.lower()
            if low.startswith("- threat state:") or low.startswith("threat state:"):
                state = ln.split(":", 1)[1].strip() if ":" in ln else state
            elif low.startswith("- threat level:") or low.startswith("threat level:"):
                level = ln.split(":", 1)[1].strip() if ":" in ln else level
            elif low.startswith("- risk label:") or low.startswith("risk label:"):
                risk_label = ln.split(":", 1)[1].strip() if ":" in ln else risk_label
            elif low.startswith("* ") or low.startswith("- ") or low.startswith("• "):
                candidate = ln.lstrip("-*• ").strip()
                if candidate and not candidate.lower().startswith("threat ") and not candidate.lower().startswith("risk label") and not candidate.lower().startswith("reasons"):
                    reasons.append(candidate)

        if not state:
            # Fallback if AI missed structured line.
            for s in ["Impact", "Persistence", "Lateral Movement", "Privilege Escalation", "Compromise", "Intrusion Attempt", "Exposure"]:
                if s.lower() in str(raw_text).lower():
                    state = s
                    break
        if not level:
            for lv in ["Very High", "High", "Medium", "Low"]:
                if lv.lower() in str(raw_text).lower():
                    level = lv
                    break
        reasons = _build_reason_fallbacks(summary, state or "-", level or "-")
        if not risk_label:
            risk_label = "-"

        emoji_map = {
            "Low": "🟢",
            "Medium": "🟡",
            "High": "🟠",
            "Very High": "🔴",
        }
        emoji = emoji_map.get(level, "")
        state_disp = _to_bold_unicode(state or "-")
        level_disp = _to_bold_unicode(level or "-")

        out = [
            f"- Threat State: {state_disp}",
            f"- Threat Level: {emoji} {level_disp}".rstrip(),
            f"- Risk Label: {risk_label}",
            "- Reasons:",
        ]
        for r in reasons[:3]:
            out.append(f"  * {r}")
        return "\n".join(out)

    current_ai_signature = (
        ai_provider,
        settings.gemini_model if ai_provider == "Gemini" else "llama-3.1-8b-instant",
    )
    last_ai_signature = st.session_state.get("ai_signature_last")
    if last_ai_signature and last_ai_signature != current_ai_signature:
        _clear_ai_outputs()
    st.session_state["ai_signature_last"] = current_ai_signature

    def _run_ai_description_generation() -> bool:
        """Execute the AI Description call — called when the inline Generate button is clicked.

        Returns:
            True when ``ai_desc`` was updated and a rerun is needed for the
            textarea to display it. False on validation failure or provider
            error — the caller MUST NOT call ``st.rerun()`` in that case, or
            the warning/error shown here will be wiped before the user sees it.
        """
        if not selected:
            st.warning("Select at least 1 IOC.")
            return False
        if ai_provider == "Gemini" and not settings.gemini_key:
            st.warning("GEMINI_KEY is not set.")
            return False
        if ai_provider == "Groq" and not settings.groq_key:
            st.warning("GROQ_KEY is not set.")
            return False
        st.session_state["auto_generate_ai"] = False
        desc_prompt = _build_prompt(selected, "DESCRIPTION")
        if use_only_evidence:
            desc_prompt = "STRICT: Do not invent data. " + desc_prompt
        _t_ai = time.perf_counter()
        if ai_provider == "Gemini":
            desc_out, desc_err = gemini_generate(desc_prompt, settings, use_backup=False)
        else:
            desc_out, desc_err = groq_generate(desc_prompt, settings)
        st.session_state["ai_timing"] = {
            "provider": ai_provider,
            "time": time.perf_counter() - _t_ai,
        }
        if not desc_out:
            if desc_err:
                st.error(f"AI Description failed — {desc_err}")
            else:
                st.error("AI Description failed.")
            return False
        desc_clean = desc_out.strip()
        if desc_clean.upper().startswith("DESCRIPTION:"):
            desc_clean = desc_clean.split(":", 1)[1].strip()
        desc_clean = re.sub(r"\s+", " ", desc_clean).strip()
        desc_clean = _obfuscate_domains_and_urls(desc_clean)
        st.session_state["ai_desc"] = f"#Description: {desc_clean}" if desc_clean else "#Description:"
        st.session_state["ai_ioc_links"] = _build_ioc_links(selected)
        return True

    # Auto-generate trigger fires once when enrichment Run completes with the
    # "Auto AI Description" checkbox enabled. Cleared inside the helper.
    if st.session_state.get("auto_generate_ai"):
        _run_ai_description_generation()

    def _build_share_text(selected_values: list[str]) -> str:
        lines: list[str] = []
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines.append("=== IOC Router — Analysis Report ===")
        lines.append(f"Generated : {now}")
        lines.append("")

        # ── Summary ──────────────────────────────────────────────────────
        run_summary = st.session_state["run_results"].get("summary", {})
        lines.append("--- SUMMARY ---")
        lines.append(
            f"Total: {run_summary.get('total', 0)}  |  "
            f"Malicious: {run_summary.get('malicious', 0)}  |  "
            f"Suspicious: {run_summary.get('suspicious', 0)}  |  "
            f"Unknown: {run_summary.get('unknown', 0)}"
        )
        lines.append("")

        # ── IOC Results ──────────────────────────────────────────────────
        lines.append("--- IOC RESULTS ---")
        run_rows = st.session_state["run_results"].get("rows", [])
        for idx, row in enumerate(run_rows, 1):
            artifact = row.get("Artifact", "")
            if artifact not in selected_values:
                continue
            lines.append(f"{idx}. {artifact} [{row.get('Type', '')}]")
            lines.append(f"   Verdict   : {row.get('Verdict', '')} ({row.get('Confidence', '')} confidence)")
            lines.append(f"   Evidence  : {row.get('Primary Evidence', '')}")
            lines.append(f"   Sources   : {row.get('Sources', '')}")
        lines.append("")

        # ── Event analysis (process / command line / WAF payload) ─────────
        # These rows live outside `rows` by design — they are per-event, not
        # per-atomic-IOC — and this report used to read `rows` alone, so every
        # local finding was dropped from the shared output. They are also not
        # filtered by `selected_values`: that list holds IOC values, and an
        # event finding has no IOC to be selected by.
        _event_rows = (
            list(st.session_state["run_results"].get("process_rows") or [])
            + list(st.session_state["run_results"].get("waf_rows") or [])
        )
        if _event_rows:
            lines.append("--- EVENT ANALYSIS (local, no provider lookup) ---")
            for idx, row in enumerate(_event_rows, 1):
                lines.append(f"{idx}. {row.get('Artifact', '')} [{row.get('Type', '')}]")
                lines.append(
                    f"   Verdict   : {row.get('Verdict', '')} "
                    f"({row.get('Confidence', '')} confidence)"
                )
                lines.append(f"   Evidence  : {row.get('Primary Evidence', '')}")
                lines.append(f"   Sources   : {row.get('Sources', '')}")
            lines.append(
                "NOTE: these findings come from local rule sets only. "
                "'Unknown' means nothing matched locally, not that the artifact is clean."
            )
            lines.append("")

        # ── Threat Analysis ───────────────────────────────────────────────
        _ta_sum    = _build_analysis_summary(selected_values)
        _ta_result = analyzeThreat(_ta_sum)
        _ta_state  = _ta_result.get("threat_state", "Exposure")
        _ta_level  = _ta_result.get("threat_level", "Low")
        _ta_verdict = _ta_result.get("verdict", "")
        _ta_mitre  = _ta_result.get("mitre_alignment", [])
        _ta_reasons = _ta_result.get("reasons", [])
        _emoji_map = {"Low": "🟢", "Medium": "🟡", "High": "🟠", "Very High": "🔴"}
        _verdict_emoji = {"False Positive": "🟢", "Benign Positive": "🟠", "True Positive": "🔴"}
        lines.append("--- THREAT ANALYSIS ---")
        _da = _get_effective_device_action()
        if _da:
            lines.append(f"Device Action : {_da}")
        lines.append(f"Threat State : {_ta_state}")
        lines.append(f"Threat Level : {_emoji_map.get(_ta_level, '')} {_ta_level}".rstrip())
        lines.append(f"Verdict      : {_verdict_emoji.get(_ta_verdict, '')} {_ta_verdict or '—'}".rstrip())
        if _ta_reasons:
            lines.append("Reasons:")
            for _r in _ta_reasons:
                lines.append(f"  * {_r}")
        _tactic_ids = [t for t in _ta_mitre if t.startswith("TA")]
        if _tactic_ids:
            lines.append(f"MITRE ATT&CK : {', '.join(_tactic_ids)}")
        lines.append("")

        # ── Infrastructure ───────────────────────────────────────────────
        _infra_blocks: list[str] = []
        for ioc in items:
            if ioc.value not in selected_values:
                continue
            if ioc.type not in ("ip", "domain"):
                continue

            _vt_a = (vt_results.get(ioc.value) or {}).get("attributes") or {}
            _ab   = abuse_results.get(ioc.value) or {}
            _sh   = shodan_results.get(ioc.value) or {}

            # Resolve target IP for geo lookup
            _geo_target: str | None = None
            if ioc.type == "ip":
                _geo_target = ioc.value
            else:
                _sh_ips = _sh.get("queriedIps") or []
                _geo_target = _sh_ips[0] if _sh_ips else _sh.get("queriedIp")

            # ip-api.com (cached — no extra network call if already fetched)
            _geo: dict = fetch_geo_ip_api(_geo_target) if _geo_target else {}

            # Nominatim reverse geocode (cached)
            _lat = _geo.get("lat")
            _lon = _geo.get("lon")
            _nom: dict = fetch_nominatim(_lat, _lon) if _lat is not None and _lon is not None else {}
            _nom_addr: dict = _nom.get("address") or {}

            # ── ASN (VT preferred)
            _asn_num   = _vt_a.get("asn")
            _asn_owner = _vt_a.get("as_owner")
            _asn_geo   = _geo.get("as")  # e.g. "AS150984 PT Fitrah Marina Sukses"
            if _asn_num and _asn_owner:
                _asn_str = f"AS{_asn_num} — {_asn_owner}"
            elif _asn_num:
                _asn_str = f"AS{_asn_num}"
            elif _asn_geo:
                _asn_str = _asn_geo
            else:
                _asn_str = None

            # ── Location: build richest possible string
            # City from ip-api or Nominatim
            _city = (
                _geo.get("city")
                or _nom_addr.get("city")
                or _nom_addr.get("town")
                or _nom_addr.get("village")
            )
            # Region/state
            _region = (
                _geo.get("regionName")
                or _nom_addr.get("state")
            )
            # Country
            _country = (
                _geo.get("country")
                or _nom_addr.get("country")
                or _vt_a.get("country")
            )
            _cc = (
                _geo.get("countryCode")
                or _ab.get("countryCode")
                or _vt_a.get("country")
            )
            # Postal code
            _postal = _geo.get("zip") or _nom_addr.get("postcode")
            # Continent (VT)
            _continent = _vt_a.get("continent")
            # RIR (VT)
            _rir = _vt_a.get("regional_internet_registry")
            # Coordinates
            _coords = f"{_lat}, {_lon}" if _lat is not None and _lon is not None else None

            # Compose location string: "City, Region, Country (CC)"
            _loc_parts = [p for p in [_city, _region, _country] if p]
            _loc_str = ", ".join(dict.fromkeys(_loc_parts)) or None
            if _loc_str and _cc and f"({_cc})" not in _loc_str:
                _loc_str = f"{_loc_str} ({_cc})"

            # ── ISP / Org
            _isp = _ab.get("isp") or _geo.get("isp")
            _org = _geo.get("org")
            _usage = _ab.get("usageType")

            block_lines = [f"  [{ioc.value}]"]
            if _asn_str:
                block_lines.append(f"    ASN         : {_asn_str}")
            if _rir:
                block_lines.append(f"    RIR         : {_rir}")
            if _loc_str:
                block_lines.append(f"    Location    : {_loc_str}")
            if _postal:
                block_lines.append(f"    Postal Code : {_postal}")
            if _continent:
                block_lines.append(f"    Continent   : {_continent}")
            if _coords:
                block_lines.append(f"    Coordinates : {_coords}")
            if _isp:
                block_lines.append(f"    ISP         : {_isp}")
            if _org and _org != _isp:
                block_lines.append(f"    Org         : {_org}")
            if _usage:
                block_lines.append(f"    Usage Type  : {_usage}")

            if len(block_lines) > 1:
                _infra_blocks.append("\n".join(block_lines))

        if _infra_blocks:
            lines.append("--- INFRASTRUCTURE ---")
            for blk in _infra_blocks:
                lines.append(blk)
            lines.append("")

        # ── AI Description ────────────────────────────────────────────────
        _desc = st.session_state.get("ai_desc", "").strip()
        if _desc:
            _desc_clean = re.sub(r"^#?Description:\s*", "", _desc, flags=re.IGNORECASE).strip()
            lines.append("--- DESCRIPTION ---")
            lines.append(_desc_clean)
            lines.append("")

        # ── Sources ───────────────────────────────────────────────────────
        _links_text = _build_ioc_links(selected_values)
        if _links_text:
            lines.append("--- SOURCES ---")
            for _ln in _links_text.splitlines():
                lines.append(_ln)
            lines.append("")

        lines.append("=== End of Report ===")
        return "\n".join(lines)

    desc_text = st.session_state.get("ai_desc", "")

    def _text_with_copy(label: str, text: str, height: int, key: str) -> None:
        st.text_area(label, value=text or "", height=height, key=key)
        data = base64.b64encode((text or "").encode("utf-8")).decode("ascii")
        html = f"""
        <style>
          .copy-wrap {{ display: flex; align-items: center; gap: 8px; margin-top: 6px; }}
          .copy-btn {{
            padding: 6px 10px;
            border: 1px solid #ccc;
            border-radius: 6px;
            background: #f7f7f7;
            cursor: pointer;
            font-size: 0.9rem;
          }}
          .copy-msg {{ color: #0a7b30; font-size: 0.85rem; }}
        </style>
        <div class="copy-wrap">
          <button class="copy-btn" id="{key}_btn">Copy</button>
          <span class="copy-msg" id="{key}_msg"></span>
        </div>
        <script>
          const btn = document.getElementById("{key}_btn");
          const msg = document.getElementById("{key}_msg");
          const data = "{data}";
          if (btn) {{
            btn.addEventListener("click", () => {{
              const text = atob(data);
              navigator.clipboard.writeText(text).then(() => {{
                msg.textContent = "copied!";
              }});
            }});
          }}
        </script>
        """
        components.html(html, height=60)

    if desc_text or selected:
        # ── Threat Analysis expander (always shown when IOCs selected) ──────
        _ta_summary = _build_analysis_summary(selected or [])
        _ta_result  = analyzeThreat(_ta_summary)
        _ta_state   = _ta_result.get("threat_state", "Exposure")
        _ta_level   = _ta_result.get("threat_level", "Low")
        _ta_verdict = _ta_result.get("verdict", "")
        _ta_verdict_color = _ta_result.get("verdict_color", "#aaa")
        _ta_mitre   = _ta_result.get("mitre_alignment", [])
        _ta_reasons = _ta_result.get("reasons", [])

        _level_color = {"Low": "#2ecc71", "Medium": "#f39c12", "High": "#e67e22", "Very High": "#e74c3c"}.get(_ta_level, "#aaa")
        _level_badge = f'<span style="background:{_level_color};color:#fff;padding:2px 10px;border-radius:12px;font-size:0.82rem;font-weight:600">{_ta_level}</span>'
        _state_color = {"Exposure":"#3498db","Intrusion Attempt":"#f39c12","Compromise":"#e67e22","Privilege Escalation":"#e74c3c","Lateral Movement":"#c0392b","Persistence":"#8e44ad","Impact":"#7b241c"}.get(_ta_state,"#555")
        _state_badge = f'<span style="background:{_state_color};color:#fff;padding:2px 10px;border-radius:12px;font-size:0.82rem;font-weight:600">{_ta_state}</span>'
        _verdict_badge = f'<span style="background:{_ta_verdict_color};color:#fff;padding:2px 10px;border-radius:12px;font-size:0.82rem;font-weight:600">{_ta_verdict or "—"}</span>'

        # ── Pre-compute data needed by both the override send and display rows ──
        _mitre_names = {
            "TA0001": "Initial Access", "TA0002": "Execution", "TA0003": "Persistence",
            "TA0004": "Privilege Escalation", "TA0005": "Defense Evasion",
            "TA0006": "Credential Access", "TA0007": "Discovery",
            "TA0008": "Lateral Movement", "TA0009": "Collection",
            "TA0010": "Exfiltration", "TA0011": "Command & Control",
            "TA0040": "Impact", "TA0042": "Resource Development",
            "TA0043": "Reconnaissance",
        }
        _tactic_ids = [t for t in _ta_mitre if t.startswith("TA")]

        def _flag_source_url(source: str, ioc_value: str, ioc_type: str) -> str:
            """Return the direct Threat Intel URL for a given flag source + IOC."""
            s = source.lower()
            if "virustotal" in s or s == "vt":
                _vt_link = _vt_gui_url(ioc_value, ioc_type)
                if _vt_link:
                    return _vt_link
            if "urlscan" in s:
                if ioc_type == "ip":
                    return f"https://urlscan.io/ip/{ioc_value}"
                if ioc_type == "domain":
                    return f"https://urlscan.io/domain/{ioc_value}"
                if ioc_type == "url":
                    return f"https://urlscan.io/search/#q={quote_plus(ioc_value)}"
                if ioc_type == "hash":
                    return f"https://urlscan.io/search/#q=hash:{quote_plus(ioc_value)}"
            if "abuse" in s:
                return f"https://www.abuseipdb.com/check/{ioc_value}"
            if "threatfox" in s:
                return f"https://threatfox.abuse.ch/browse.php?search={quote_plus(ioc_value)}"
            if "malwarebazaar" in s:
                return f"https://bazaar.abuse.ch/sample/{ioc_value}/"
            if "shodan" in s:
                if ioc_type == "ip":
                    return f"https://www.shodan.io/host/{ioc_value}"
                return f"https://www.shodan.io/domain/{ioc_value}"
            if "dnsdumpster" in s:
                _dd_target = dnsd_results.get(ioc_value, {}).get("queriedDomain") or ioc_value
                return f"https://dnsdumpster.com/?s={_dd_target}"
            if "hybrid" in s:
                if ioc_type == "hash":
                    return f"https://hybrid-analysis.com/sample/{ioc_value}"
                return f"https://hybrid-analysis.com/search?query={quote_plus(ioc_value)}"
            return ""

        _all_flags: list[dict] = []
        for _ioc in items:
            if selected and _ioc.value not in selected:
                continue
            _ioc_flags = extract_ioc_flags(
                _ioc.value, _ioc.type,
                vt_results.get(_ioc.value, {}) or {},
                urlscan_results.get(_ioc.value, {}) or {},
                abuse_results.get(_ioc.value, {}) or {},
                tf_results.get(_ioc.value, {}) or {},
                mb_results.get(_ioc.value, {}) or {},
                shodan_results.get(_ioc.value, {}) or {},
                dnsd_results.get(_ioc.value, {}) or {},
                ha_results.get(_ioc.value, {}) or {},
                mxtoolbox_results.get(_ioc.value, {}) or {},
                ransomware_live_results.get(_ioc.value, {}) or {},
            )
            for _f in _ioc_flags:
                _f["ioc_value"] = _ioc.value
                _f["ioc_type"] = _ioc.type
            _all_flags.extend(_ioc_flags)

        # Process findings attach to the event, not to any one IOC, so they are
        # appended with the source field as their artifact label.
        for _pf in (run_results.get("process_flags") or []):
            _all_flags.append({**_pf, "ioc_value": _pf.get("label", ""), "ioc_type": "process"})
        for _cf in (run_results.get("cmdline_flags") or []):
            _all_flags.append({**_cf, "ioc_value": _cf.get("label", ""), "ioc_type": "command_line"})
        for _wf in (run_results.get("waf_flags") or []):
            _all_flags.append({**_wf, "ioc_value": _wf.get("label", ""), "ioc_type": "waf_payload"})

        _seen_fids: set[str] = set()
        _deduped_flags: list[dict] = []
        for _f in _all_flags:
            if _f["id"] not in _seen_fids:
                _seen_fids.add(_f["id"])
                _deduped_flags.append(_f)

        _ke_rows: list[tuple[str, str, str]] = []  # (ioc, label, value)
        for _ioc in items:
            if selected and _ioc.value not in selected:
                continue
            _vt_i  = vt_results.get(_ioc.value, {}) or {}
            _us_i  = urlscan_results.get(_ioc.value, {}) or {}
            _tf_i  = tf_results.get(_ioc.value, {}) or {}
            _mb_i  = mb_results.get(_ioc.value, {}) or {}
            _sh_i  = shodan_results.get(_ioc.value, {}) or {}
            _ha_i  = ha_results.get(_ioc.value, {}) or {}
            _at_i  = (_vt_i.get("attributes") or {})

            _family = (
                str(_ha_i.get("malware_family") or "").strip()
                or str(((_tf_i.get("data") or [{}])[0]).get("malware") or "").strip()
                or str(_mb_i.get("data", [{}])[0].get("signature") if isinstance(_mb_i.get("data"), list) and _mb_i.get("data") else "").strip()
            )
            if _family:
                _ke_rows.append((_ioc.value, "Malware Family", _family))

            _fs = _at_i.get("first_seen_itw_date") or _at_i.get("first_submission_date")
            if _fs:
                try:
                    _fs_str = datetime.utcfromtimestamp(int(_fs)).strftime("%Y-%m-%d")
                except Exception:
                    _fs_str = str(_fs)[:10]
                _ke_rows.append((_ioc.value, "First Seen", _fs_str))

            _cd = _at_i.get("creation_date")
            if _cd:
                try:
                    _age = (datetime.utcnow() - datetime.utcfromtimestamp(int(_cd))).days
                    _ke_rows.append((_ioc.value, "Domain Age", f"{_age} days"))
                except Exception:
                    pass

            _us_result = _us_i.get("result", {}) or {}
            _us_data = _us_result.get("data", {}) if isinstance(_us_result.get("data"), dict) else {}
            _us_reqs = _us_data.get("requests") or _us_result.get("http") or []
            if isinstance(_us_reqs, list) and _us_reqs:
                _seen_r: set = set()
                _chain_r: list = []
                for _tx in _us_reqs:
                    if not isinstance(_tx, dict):
                        continue
                    _u = (_tx.get("request") or {}).get("url")
                    if isinstance(_u, str) and _u not in _seen_r:
                        _seen_r.add(_u)
                        _chain_r.append(_u)
                _nr = max(len(_chain_r) - 1, 0)
                if _nr > 0:
                    _ke_rows.append((_ioc.value, "Redirect Hops", str(_nr)))

            _sh_sum = _sh_i.get("summary", {}) if isinstance(_sh_i.get("summary"), dict) else {}
            _sh_roll = (_sh_sum.get("shodan", {}) or {}).get("rollup", {})
            _sh_cves = _sh_roll.get("cves") or _sh_i.get("vulns") or []
            if isinstance(_sh_cves, list) and _sh_cves:
                _ke_rows.append((_ioc.value, "CVEs (Shodan)", str(len(_sh_cves))))

            _sh_ports = _sh_roll.get("unique_ports") or _sh_i.get("ports") or []
            if isinstance(_sh_ports, list) and _sh_ports:
                _ke_rows.append((_ioc.value, "Open Ports", str(len(_sh_ports))))

            _us_brands = ((_us_i.get("verdicts", {}) or {}).get("overall", {}) or {}).get("brands") or []
            if _us_brands:
                _ke_rows.append((_ioc.value, "Brand Impersonation", ", ".join(str(b) for b in _us_brands[:3])))

            _ab_i = abuse_results.get(_ioc.value, {}) or {}
            _ab_score = _ab_i.get("abuseConfidenceScore")
            if _ab_score is not None and int(_ab_score) >= 25:
                _ke_rows.append((_ioc.value, "Abuse Confidence", f"{_ab_score}%"))

            _rl_i = ransomware_live_results.get(_ioc.value, {}) or {}
            _rl_count = _rl_i.get("count") or 0
            if _rl_count > 0:
                _rl_groups = list(dict.fromkeys(
                    str(v.get("group_name") or "") for v in (_rl_i.get("victims") or []) if v.get("group_name")
                ))
                _rl_label = _rl_groups[0] if _rl_groups else f"{_rl_count} record(s)"
                _ke_rows.append((_ioc.value, "Ransomware Group", _rl_label))

        # ── AI Description block (rendered ABOVE Threat Analysis) ──────────
        shown_desc = desc_text if desc_text else ""
        if st.session_state.get("ai_description") != shown_desc:
            st.session_state["ai_description"] = shown_desc

        # The ➤ Generate button floats inside the textarea, vertically
        # centered on the right edge. We wrap the textarea + button in a
        # keyed container so `.st-key-ai_desc_wrap` becomes a positioning
        # context for the absolutely-placed button (Streamlit 1.36+ adds
        # `st-key-<key>` to keyed containers and widgets).
        st.markdown(
            """
            <style>
            div.st-key-ai_desc_wrap { position: relative !important; }
            div.st-key-ai_desc_wrap [data-testid="stTextArea"] textarea {
                padding-right: 78px !important;
            }
            div.st-key-ai_desc_wrap div.st-key-generate_ai_desc_btn {
                position: absolute !important;
                top: 50% !important;
                right: 14px !important;
                transform: translateY(-50%) !important;
                width: auto !important;
                margin: 0 !important;
                z-index: 10 !important;
            }
            div.st-key-ai_desc_wrap div.st-key-generate_ai_desc_btn button {
                min-width: 50px !important;
                width: auto !important;
                padding: 10px 18px !important;
                font-size: 1.05rem !important;
                line-height: 1 !important;
            }
            </style>
            """,
            unsafe_allow_html=True,
        )

        with st.container(key="ai_desc_wrap"):
            st.text_area(
                "AI Description",
                height=180,
                key="ai_description",
                label_visibility="collapsed",
                placeholder="No description generated yet",
            )
            if st.button("➤", type="primary", key="generate_ai_desc_btn"):
                # Only rerun on success — a rerun after a warning/error wipes
                # the toast before the user can see it, leaving the textarea
                # apparently "reset to empty" with no feedback.
                if _run_ai_description_generation():
                    st.rerun()

            # Word-count caption shown at the bottom-right of the textarea box.
            # When empty, the textarea's placeholder shows "No description
            # generated yet" inside the box instead.
            if shown_desc:
                st.markdown(
                    f"<div style='text-align:right;color:#6c757d;"
                    f"font-size:0.82rem;margin-top:-6px;'>"
                    f"~{len(shown_desc.split())} words</div>",
                    unsafe_allow_html=True,
                )

        if shown_desc:
            _desc_b64 = base64.b64encode(shown_desc.encode("utf-8")).decode("ascii")
            _desc_html = f"""
            <style>
              .copy-wrap{{display:flex;align-items:center;gap:8px;margin-top:4px}}
              .copy-btn{{padding:5px 10px;border:1px solid #ccc;border-radius:6px;background:#f7f7f7;cursor:pointer;font-size:0.88rem}}
              .copy-msg{{color:#0a7b30;font-size:0.82rem}}
            </style>
            <div class="copy-wrap">
              <button class="copy-btn" id="desc_copy_btn">Copy</button>
              <span class="copy-msg" id="desc_copy_msg"></span>
            </div>
            <script>
              (function(){{
                var btn=document.getElementById("desc_copy_btn");
                var msg=document.getElementById("desc_copy_msg");
                if(btn){{btn.addEventListener("click",function(){{
                  navigator.clipboard.writeText(atob("{_desc_b64}")).then(function(){{msg.textContent="copied!"}});
                }})}}
              }})();
            </script>
            """
            components.html(_desc_html, height=50)

        with st.expander("**Threat Analysis**", expanded=False):
            # ── Row 1: State + Level + Verdict with analyst override dropdowns ──
            _state_options = [
                "Exposure", "Intrusion Attempt", "Compromise",
                "Privilege Escalation", "Lateral Movement", "Persistence", "Impact",
            ]
            _level_options = ["Low", "Medium", "High", "Very High"]
            _verdict_options = ["False Positive", "Benign Positive", "True Positive"]

            _h1, _h2, _h3 = st.columns([2, 2, 3])
            with _h1:
                _sel_state = st.selectbox(
                    "Threat State", _state_options,
                    index=_state_options.index(_ta_state) if _ta_state in _state_options else 0,
                    key="ta_override_state",
                    help=_THREAT_STATE_HELP,
                )
            with _h2:
                _sel_level = st.selectbox(
                    "Threat Level", _level_options,
                    index=_level_options.index(_ta_level) if _ta_level in _level_options else 0,
                    key="ta_override_level",
                    help=_THREAT_LEVEL_HELP,
                )
            with _h3:
                _sel_verdict = st.selectbox(
                    "Verdict", _verdict_options,
                    index=_verdict_options.index(_ta_verdict) if _ta_verdict in _verdict_options else 0,
                    key="ta_override_verdict",
                    help=_VERDICT_HELP,
                )

            # Color each selectbox background to match its value
            components.html("""
            <script>
            (function() {
              var colorMap = {
                "Exposure": "#3498db",
                "Intrusion Attempt": "#f39c12",
                "Compromise": "#e67e22",
                "Privilege Escalation": "#e74c3c",
                "Lateral Movement": "#c0392b",
                "Persistence": "#8e44ad",
                "Impact": "#7b241c",
                "Low": "#2ecc71",
                "Medium": "#f39c12",
                "High": "#e67e22",
                "Very High": "#e74c3c",
                "False Positive": "#2ecc71",
                "Benign Positive": "#f39c12",
                "True Positive": "#e74c3c"
              };
              function applyColors() {
                var doc = window.parent.document;
                doc.querySelectorAll('[data-baseweb="select"]').forEach(function(sel) {
                  var valEl = sel.querySelector('[class*="singleValue"]');
                  if (!valEl) return;
                  var text = valEl.textContent.trim();
                  var color = colorMap[text];
                  if (!color) return;
                  sel.style.backgroundColor = color;
                  sel.style.borderRadius = "8px";
                  sel.style.border = "none";
                  valEl.style.color = "#ffffff";
                  valEl.style.fontWeight = "600";
                  sel.querySelectorAll('[class*="indicatorContainer"] svg').forEach(function(svg) {
                    svg.style.fill = "#ffffff";
                  });
                });
              }
              applyColors();
              setTimeout(applyColors, 150);
              setTimeout(applyColors, 600);
            })();
            </script>
            """, height=0)

            # ── Analyst override: reason textarea + send (shown only on change) ──
            _changes: dict[str, tuple[str, str]] = {}
            if _sel_state != _ta_state:
                _changes["Threat State"] = (_ta_state, _sel_state)
            if _sel_level != _ta_level:
                _changes["Threat Level"] = (_ta_level, _sel_level)
            if _sel_verdict != _ta_verdict:
                _changes["Verdict"] = (_ta_verdict, _sel_verdict)

            if not _changes:
                st.caption("\\*Change Threat State to improve the app, thank you")

            if _changes:
                _analyst_reason = st.text_area(
                    "Reason for change (optional)",
                    placeholder="Enter your reasoning as analyst…",
                    key="ta_analyst_reason",
                    height=80,
                )
                if st.button("Send Feedback 📤", type="primary", key="ta_send_override"):
                    _ioc_list_str = "\n".join(f"  • {v}" for v in (selected or []))
                    _change_lines = "\n".join(
                        f"  {k}: {orig} → {new}" for k, (orig, new) in _changes.items()
                    )
                    _reason_block = (
                        f"\n📝 Analyst Reason:\n{(_analyst_reason or '').strip()}"
                        if (_analyst_reason or "").strip() else ""
                    )
                    _mitre_text = ", ".join(
                        f"{t} ({_mitre_names.get(t, t)})" for t in _tactic_ids
                    ) or "—"
                    _SEV_EXPORT_LABEL = {"INFO": "INFORMATIONAL"}
                    _ti_lines = [
                        f"  [{_SEV_EXPORT_LABEL.get(_f['severity'], _f['severity'])}] "
                        f"{_f['label']} ({_f['source']}): {_f['threat_type']}"
                        for _f in _deduped_flags[:20]
                    ]
                    _ti_text = "\n".join(_ti_lines) or "—"
                    _ke_text = "\n".join(
                        f"  {lbl}: {val}" for _, lbl, val in _ke_rows[:12]
                    ) or "—"
                    _reasons_text = "\n".join(f"  - {r}" for r in _ta_reasons) or "—"
                    _WIB = timezone(timedelta(hours=7))
                    _ts = datetime.now(_WIB).strftime("%Y-%m-%d %H:%M:%S")
                    _DIV = "━" * 26
                    _msg_parts = [
                        "🔍 IOC Router — Analyst Override",
                        _DIV,
                        f"🕐 {_ts} WIB",
                        "",
                        "📌 IOC Input:",
                        _ioc_list_str or "  (none)",
                        "",
                        "🔄 Changes Made:",
                        _change_lines,
                    ]
                    if _reason_block:
                        _msg_parts.append(_reason_block)
                    _msg_parts += [
                        "",
                        "📊 Threat Analysis:",
                        f"  State: {_sel_state}  |  Level: {_sel_level}  |  Verdict: {_sel_verdict}",
                        "",
                        "📋 Reasons:",
                        _reasons_text,
                        "",
                        "🎯 MITRE ATT&CK Tactics:",
                        f"  {_mitre_text}",
                        "",
                        "🚨 Threat Indicators:",
                        _ti_text,
                        "",
                        "🔑 Key Evidence:",
                        _ke_text,
                        "",
                        _DIV,
                        "📍 minzelo · IOC Router v1.0",
                    ]
                    _tg_msg = "\n".join(_msg_parts)
                    _bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
                    _chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
                    if not _bot_token or not _chat_id:
                        st.error(
                            "Telegram not configured. "
                            "Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in .env"
                        )
                    else:
                        try:
                            _tg_resp = requests.post(
                                f"https://api.telegram.org/bot{_bot_token}/sendMessage",
                                json={"chat_id": _chat_id, "text": _tg_msg},
                                timeout=10,
                            )
                            _tg_resp.raise_for_status()
                            st.toast("Analyst override sent to Telegram ✅")
                        except requests.RequestException as _tg_err:
                            st.error(f"Failed to send to Telegram: {_tg_err}")

            # ── Row 2: Reasons ────────────────────────────────────────────
            if _ta_reasons:
                st.divider()
                st.markdown("**Reasons**")
                for _r in _ta_reasons:
                    st.markdown(f"- {_r}")

            # ── Row 3: MITRE ATT&CK tactics ──────────────────────────────
            if _tactic_ids:
                st.divider()
                st.markdown("**MITRE ATT&CK Tactics**")
                _badge_html = " ".join(
                    f'<span style="background:#2c3e50;color:#ecf0f1;padding:3px 9px;border-radius:10px;font-size:0.78rem;margin:2px;display:inline-block">'
                    f'{t} · {_mitre_names.get(t, t)}</span>'
                    for t in _tactic_ids
                )
                st.markdown(_badge_html, unsafe_allow_html=True)

            # ── Row 4: IOC Flags ──────────────────────────────────────────
            if _deduped_flags:
                st.divider()
                st.markdown("**Threat Indicators**")
                # Display labels only — the stored severity value stays "INFO",
                # which the sort orders and every provider flag module rely on.
                _sev_cfg = {
                    "CRITICAL": ("#c0392b", "🔴", "CRITICAL"),
                    "HIGH":     ("#e67e22", "🟠", "HIGH"),
                    "MEDIUM":   ("#f39c12", "🟡", "MEDIUM"),
                    "LOW":      ("#27ae60", "🟢", "LOW"),
                    "INFO":     ("#7f8c8d", "ℹ️", "INFORMATIONAL"),
                }
                for _sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                    _grp = [_f for _f in _deduped_flags if _f["severity"] == _sev]
                    if not _grp:
                        continue
                    _sc, _se, _sev_label = _sev_cfg[_sev]
                    with st.expander(f"{_se} {_sev_label} — {len(_grp)} indicator(s)"):
                        for _f in _grp:
                            # Each technique id links to its ATT&CK page, the same
                            # way the source badge and label do. Printing bare
                            # ids forced the reader to copy them somewhere else,
                            # and printing the URLs inline made the detail text
                            # unreadable.
                            _mitre_str = " · ".join(
                                f'<a href="https://attack.mitre.org/techniques/'
                                f'{str(_t).strip().upper().replace(".", "/")}/" target="_blank" '
                                f'style="color:#79c0ff;text-decoration:none">{_t}</a>'
                                for _t in _f["mitre"]
                            ) if _f["mitre"] else "—"
                            _f_ioc_val  = _f.get("ioc_value", "")
                            _f_ioc_type = _f.get("ioc_type", "")
                            # Shown defanged: it keeps attacker infrastructure
                            # unclickable, and stops the markdown linkifier from
                            # nesting an anchor inside the badge's own anchor,
                            # which was emptying the badge. The href below still
                            # points at the provider's report page, not here.
                            _f_ioc_disp = defang_for_display(_f_ioc_val)
                            # A flag may carry its own source link (LOLBAS page,
                            # SigmaHQ rule, ATT&CK technique); otherwise derive
                            # one from the provider + IOC.
                            _f_src_url = (
                                _f.get("source_url")
                                or _flag_source_url(_f["source"], _f_ioc_val, _f_ioc_type)
                            )
                            _src_badge = (
                                f'<a href="{_f_src_url}" target="_blank" style="text-decoration:none">'
                                f'<span style="background:#34495e;color:#ecf0f1;padding:1px 7px;'
                                f'border-radius:8px;font-size:0.73rem;cursor:pointer">{_f["source"]}</span></a>'
                                if _f_src_url else
                                f'<span style="background:#34495e;color:#ecf0f1;padding:1px 7px;'
                                f'border-radius:8px;font-size:0.73rem">{_f["source"]}</span>'
                            )
                            _ioc_badge = (
                                f'<a href="{_f_src_url}" target="_blank" style="text-decoration:none">'
                                f'<span style="background:#1a3050;color:#79c0ff;padding:1px 7px;'
                                f'border-radius:8px;font-size:0.73rem;font-family:monospace;cursor:pointer">'
                                f'{_f_ioc_disp}</span></a>'
                                if _f_ioc_val and _f_src_url else
                                f'<span style="background:#1a3050;color:#79c0ff;padding:1px 7px;'
                                f'border-radius:8px;font-size:0.73rem;font-family:monospace">'
                                f'{_f_ioc_disp}</span>'
                                if _f_ioc_val else ""
                            )
                            _label_html = (
                                f'<a href="{_f_src_url}" target="_blank" '
                                f'style="color:inherit;text-decoration:none;font-weight:700">'
                                f'{_f["label"]}</a>'
                                if _f_src_url else
                                f'<strong>{_f["label"]}</strong>'
                            )
                            st.markdown(
                                f'{_label_html} {_src_badge} {_ioc_badge}<br>'
                                f'<span style="color:#aaa;font-size:0.82rem">Type: {_f["threat_type"]} &nbsp;|&nbsp; MITRE: {_mitre_str}</span>'
                                + (f'<br><span style="color:#888;font-size:0.78rem">{_f["detail"]}</span>' if _f.get("detail") else ""),
                                unsafe_allow_html=True,
                            )
                            st.markdown("---")

            # ── Row 5: Key Evidence per IOC ───────────────────────────────
            if _ke_rows:
                st.divider()
                st.markdown("**Key Evidence**")
                _ke_by_ioc: dict[str, list] = {}
                for _iv, _lbl, _val in _ke_rows:
                    _ke_by_ioc.setdefault(_iv, []).append((_lbl, _val))
                for _iv, _pairs in _ke_by_ioc.items():
                    if len(selected) > 1:
                        st.caption(f"`{_iv}`")
                    _ncols = min(len(_pairs), 4)
                    for _ci in range(0, len(_pairs), _ncols):
                        _chunk = _pairs[_ci:_ci + _ncols]
                        _cols = st.columns(len(_chunk))
                        for _col, (_lbl, _val) in zip(_cols, _chunk):
                            _col.metric(_lbl, _val)

            # ── Row 6: Source Links (grouped by IOC) ─────────────────────
            _ioc_links_text = st.session_state.get("ai_ioc_links") or _build_ioc_links(selected or [])
            if _ioc_links_text:
                st.divider()
                st.markdown("**Source Links**")
                _show_ioc_header = len(selected or []) > 1
                for _ll in _ioc_links_text.strip().splitlines():
                    _ll = _ll.strip()
                    if not _ll:
                        continue
                    if _ll.startswith("Source:"):
                        if _show_ioc_header:
                            _src_header = _ll[len("Source:"):].strip()
                            st.caption(f"`{_src_header}`")
                    elif _ll.startswith("- "):
                        _parts = _ll[2:].split(": ", 1)
                        if len(_parts) == 2:
                            _lname, _lurl = _parts
                            st.markdown(f"• [{_lname}]({_lurl}) — `{_lurl}`")
                        else:
                            st.markdown(f"• {_ll[2:]}")

        # ── Pre-compute share text into session_state for output format ──
        st.session_state["share_text"] = _build_share_text([ioc.value for ioc in items])
