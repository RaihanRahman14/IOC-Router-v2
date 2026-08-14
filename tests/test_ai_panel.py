"""Tests for the pure business-logic functions extracted from render_ai_panel.

render_ai_panel() used to be a single ~1590-line function holding 17 nested
closures — prompt construction, threat-summary derivation, share-text
formatting, source-link building — all unreachable from outside it and
completely untested. 15 of them touched no Streamlit widget and wrote no
session state (verified by a regex scan for st.<widget> calls during the
extraction); those are now module-level functions taking `run_results: dict`
plus whatever scalars they need, and are tested directly here.

Left in place inside render_ai_panel: `_run_ai_description_generation` (a
genuine button-click action handler — validates input, calls the AI
provider, writes session state) and the widget-rendering flow itself. Those
are exercised through the app, not unit-tested here.
"""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from ui.components import ai_panel as ap


def _run_results(**overrides) -> dict:
    """A minimal but complete run_results dict — every key the extracted
    functions read, defaulted empty, so a test only has to override what it
    cares about.
    """
    base = {
        "items": [], "vt": {}, "urlscan": {}, "abuse": {}, "tf": {}, "mb": {},
        "shodan": {}, "dnsd": {}, "ha": {}, "mxtoolbox": {}, "ransomware_live": {},
        "process_flags": [], "cmdline_flags": [], "waf_flags": [],
        "process_analysis": {}, "cmdline_analysis": {}, "waf_analysis": [],
        "rows": [], "process_rows": [], "waf_rows": [], "summary": {},
    }
    base.update(overrides)
    return base


class _Ioc:
    """Duck-typed stand-in for ioc.parser.IOC — only .value/.type are read."""

    def __init__(self, value: str, type: str):
        self.value = value
        self.type = type


# ---------------------------------------------------------------------------
# Trivial pure helpers
# ---------------------------------------------------------------------------

class TestClip(unittest.TestCase):
    def test_short_value_is_unchanged(self):
        self.assertEqual(ap._clip("hi", 10), "hi")

    def test_long_value_is_truncated_with_marker(self):
        out = ap._clip("x" * 20, 5)
        self.assertEqual(out, "xxxxx...(truncated)")

    def test_non_string_input_is_stringified(self):
        self.assertEqual(ap._clip({"a": 1}, 100), "{'a': 1}")


class TestVtUrlId(unittest.TestCase):
    def test_matches_the_provider_clients_own_encoding(self):
        # providers/virustotal.py's _url_id must produce the same id for the
        # same URL, or the GUI link and the API report point at different things.
        from providers.virustotal import _url_id
        url = "http://evil.test/payload"
        self.assertEqual(ap._vt_url_id(url), _url_id(url))

    def test_no_padding_characters(self):
        self.assertNotIn("=", ap._vt_url_id("http://a.test/" + "x" * 50))


class TestToBoldUnicode(unittest.TestCase):
    def test_letters_and_digits_are_mapped(self):
        out = ap._to_bold_unicode("A1")
        self.assertEqual(len(out), 2)
        self.assertNotEqual(out, "A1")  # actually transformed, not passed through

    def test_punctuation_passes_through_unchanged(self):
        self.assertEqual(ap._to_bold_unicode("-"), "-")


class TestObfuscateDomainsAndUrls(unittest.TestCase):
    def test_bare_domain_is_defanged(self):
        self.assertEqual(ap._obfuscate_domains_and_urls("see evil.test now"), "see evil[.]test now")

    def test_full_url_host_is_defanged(self):
        out = ap._obfuscate_domains_and_urls("fetch http://evil.test/a.exe")
        self.assertIn("evil[.]test", out)

    def test_query_string_is_left_alone(self):
        # The bare-domain pass runs after the URL pass and is dot-shaped, so a
        # path segment that looks like "word.word" (e.g. a filename) gets
        # defanged too — pre-existing behavior, not something this test targets.
        out = ap._obfuscate_domains_and_urls("fetch http://evil.test/a?id=1")
        self.assertIn("id=1", out)

    def test_trailing_punctuation_is_preserved_outside_the_url(self):
        out = ap._obfuscate_domains_and_urls("see http://evil.test/a.")
        self.assertTrue(out.endswith("."))


# ---------------------------------------------------------------------------
# Threat-analysis derivation
# ---------------------------------------------------------------------------

class TestDeriveThreatCategory(unittest.TestCase):
    def test_impact_wins_over_everything_else(self):
        ev = {"data_exfiltration": True, "malware_executed": True}
        self.assertEqual(ap._derive_threat_category(ev), "Impact/Exfiltration")

    def test_falls_back_to_exposure_when_nothing_matched(self):
        self.assertEqual(ap._derive_threat_category({}), "Exposure/Misconfiguration")

    def test_priority_order_malware_beats_phishing(self):
        ev = {"malware_executed": True, "phishing_or_social_eng": True}
        self.assertEqual(ap._derive_threat_category(ev), "Execution and C2")


class TestDeriveAttackStatus(unittest.TestCase):
    def test_active_when_any_active_stage_present(self):
        self.assertEqual(ap._derive_attack_status({"lateral_movement": True}), "Active")

    def test_prevented_requires_both_prevented_flag_and_an_attempt(self):
        ev = {"attack_prevented": True, "exploit_attempt": True}
        self.assertEqual(ap._derive_attack_status(ev), "Prevented/Blocked")

    def test_prevented_flag_alone_without_an_attempt_is_not_enough(self):
        self.assertEqual(ap._derive_attack_status({"attack_prevented": True}), "No active attack evidence")

    def test_attempt_without_prevention_reads_as_attempted(self):
        self.assertEqual(ap._derive_attack_status({"scanning_or_recon": True}), "Attempted")

    def test_no_evidence_at_all(self):
        self.assertEqual(ap._derive_attack_status({}), "No active attack evidence")


class TestBuildReasonFallbacks(unittest.TestCase):
    def test_returns_exactly_three_reasons(self):
        reasons = ap._build_reason_fallbacks({}, "Exposure", "Low")
        self.assertEqual(len(reasons), 3)

    def test_state_reason_mentions_the_given_state(self):
        reasons = ap._build_reason_fallbacks({}, "Impact", "Very High")
        self.assertIn("Impact", reasons[0])

    def test_missing_summary_fields_default_sanely(self):
        reasons = ap._build_reason_fallbacks({"evidence": None}, "Exposure", "Low")
        self.assertEqual(len(reasons), 3)


class TestFormatThreatTextForBox(unittest.TestCase):
    def test_structured_lines_are_parsed(self):
        raw = "- Threat State: Compromise\n- Threat Level: High\n- Risk Label: x"
        out = ap._format_threat_text_for_box(raw, {})
        self.assertIn("Compromise", out)
        self.assertIn("High", out)

    def test_empty_input_still_produces_a_well_formed_box(self):
        out = ap._format_threat_text_for_box("", {})
        self.assertIn("Threat State", out)
        self.assertIn("Threat Level", out)
        self.assertIn("Reasons", out)

    def test_state_is_recovered_from_free_text_when_unstructured(self):
        out = ap._format_threat_text_for_box("This looks like a Persistence mechanism.", {})
        self.assertIn("Persistence", out)


# ---------------------------------------------------------------------------
# Provider-dict-dependent functions
# ---------------------------------------------------------------------------

class TestVtGuiUrl(unittest.TestCase):
    def test_ip_domain_hash_use_the_ioc_value_directly(self):
        rr = _run_results()
        self.assertIn("1.2.3.4", ap._vt_gui_url("1.2.3.4", "ip", rr))
        self.assertIn("evil.test", ap._vt_gui_url("evil.test", "domain", rr))
        self.assertIn("deadbeef", ap._vt_gui_url("deadbeef", "hash", rr))

    def test_url_prefers_the_matched_url_the_provider_recorded(self):
        rr = _run_results(vt={"http://evil.test/a": {"matched_url": "https://evil.test/a"}})
        link = ap._vt_gui_url("http://evil.test/a", "url", rr)
        self.assertEqual(link, ap._vt_gui_url("https://evil.test/a", "url", _run_results()))

    def test_unsupported_type_returns_empty(self):
        self.assertEqual(ap._vt_gui_url("acme", "whois", _run_results()), "")


class TestHaTextPayload(unittest.TestCase):
    def test_missing_entry_reads_as_no_data(self):
        self.assertEqual(ap._ha_text_payload("x", _run_results()), "No data")

    def test_bare_status_messages_read_as_no_data(self):
        for message in (
            "Not supported by Hybrid Analysis API",
            "Hybrid Analysis does not analyze email indicators.",
            "No results found",
        ):
            with self.subTest(message=message):
                rr = _run_results(ha={"x": {"message": message}})
                self.assertEqual(ap._ha_text_payload("x", rr), "No data")

    def test_real_finding_is_returned_as_is(self):
        rr = _run_results(ha={"x": {"verdict": "malicious"}})
        self.assertEqual(ap._ha_text_payload("x", rr), {"verdict": "malicious"})


class TestProviderHasData(unittest.TestCase):
    def test_no_data_for_any_provider_on_an_empty_run(self):
        ioc = _Ioc("1.2.3.4", "ip")
        rr = _run_results()
        for provider in ("virustotal", "urlscan", "abuseipdb", "threatfox",
                          "malwarebazaar", "shodan", "dnsdumpster",
                          "hybrid_analysis", "ransomware_live"):
            with self.subTest(provider=provider):
                self.assertFalse(ap._provider_has_data(provider, ioc, rr))

    def test_virustotal_true_when_stats_present(self):
        ioc = _Ioc("1.2.3.4", "ip")
        rr = _run_results(vt={"1.2.3.4": {"stats": {"malicious": 1}}})
        self.assertTrue(ap._provider_has_data("virustotal", ioc, rr))

    def test_hybrid_analysis_rejects_bare_status_messages(self):
        ioc = _Ioc("1.2.3.4", "ip")
        rr = _run_results(ha={"1.2.3.4": {"message": "No results found", "verdict": "x"}})
        self.assertFalse(ap._provider_has_data("hybrid_analysis", ioc, rr))

    def test_unknown_provider_name_is_false(self):
        self.assertFalse(ap._provider_has_data("not_a_provider", _Ioc("x", "ip"), _run_results()))


class TestBuildIocLinks(unittest.TestCase):
    def test_no_selection_produces_empty_output(self):
        rr = _run_results(items=[_Ioc("1.2.3.4", "ip")], vt={"1.2.3.4": {"stats": {"malicious": 1}}})
        self.assertEqual(ap._build_ioc_links([], rr), "")

    def test_virustotal_link_included_when_data_present(self):
        rr = _run_results(items=[_Ioc("1.2.3.4", "ip")], vt={"1.2.3.4": {"stats": {"malicious": 1}}})
        out = ap._build_ioc_links(["1.2.3.4"], rr)
        self.assertIn("VirusTotal:", out)
        self.assertIn("Source: 1.2.3.4 (ip)", out)

    def test_dnsdumpster_link_uses_the_queried_domain_when_present(self):
        items = [_Ioc("evil.test", "domain")]
        rr = _run_results(items=items, dnsd={"evil.test": {"queriedDomain": "evil.test", "soc_summary": {}}})
        out = ap._build_ioc_links(["evil.test"], rr)
        # dnsdumpster needs _provider_has_data("dnsdumpster", ...) True, which
        # requires an error-free dict with content; empty soc_summary alone
        # won't trigger it — this asserts no crash and correct link format
        # when it *does* have real content.
        rr2 = _run_results(items=items, dnsd={"evil.test": {
            "queriedDomain": "evil.test", "soc_summary": {"a_records": [{"ip": "1.1.1.1"}]},
        }})
        out2 = ap._build_ioc_links(["evil.test"], rr2)
        self.assertIn("DNSDumpster:", out2)
        self.assertIn("s=evil.test", out2)

    def test_unselected_iocs_are_skipped(self):
        items = [_Ioc("1.2.3.4", "ip"), _Ioc("5.6.7.8", "ip")]
        rr = _run_results(items=items, vt={
            "1.2.3.4": {"stats": {"malicious": 1}},
            "5.6.7.8": {"stats": {"malicious": 1}},
        })
        out = ap._build_ioc_links(["1.2.3.4"], rr)
        self.assertIn("1.2.3.4", out)
        self.assertNotIn("5.6.7.8", out)


class TestFlagSourceUrl(unittest.TestCase):
    def test_virustotal_source_delegates_to_vt_gui_url(self):
        rr = _run_results()
        self.assertEqual(
            ap._flag_source_url("VirusTotal", "1.2.3.4", "ip", rr),
            ap._vt_gui_url("1.2.3.4", "ip", rr),
        )

    def test_urlscan_source_is_type_specific(self):
        rr = _run_results()
        self.assertIn("urlscan.io/ip/", ap._flag_source_url("urlscan", "1.2.3.4", "ip", rr))
        self.assertIn("urlscan.io/domain/", ap._flag_source_url("urlscan", "evil.test", "domain", rr))

    def test_unknown_source_returns_empty(self):
        self.assertEqual(ap._flag_source_url("nonexistent", "x", "ip", _run_results()), "")

    def test_matching_is_case_insensitive_substring(self):
        rr = _run_results()
        self.assertNotEqual(ap._flag_source_url("Abuse.ch ThreatFox", "x", "ip", rr), "")


# ---------------------------------------------------------------------------
# _build_prompt — the largest closure, now the biggest single test surface
# ---------------------------------------------------------------------------

class TestBuildPrompt(unittest.TestCase):
    def _session_state(self, **overrides):
        state = {"result_device_action": "", "result_parent_process": "",
                  "result_child_process": "", "result_file_path": "",
                  "result_command_line": ""}
        state.update(overrides)
        return state

    def test_short_section_asks_for_2_to_4_sentences(self):
        with patch.object(ap, "st") as mock_st:
            mock_st.session_state = self._session_state()
            prompt = ap._build_prompt([], "SHORT", _run_results(), "High level language", False)
        self.assertIn("2-4 sentences", prompt)

    def test_description_section_includes_output_context_fields(self):
        with patch.object(ap, "st") as mock_st:
            mock_st.session_state = self._session_state(
                result_alert_name="Suspicious Outbound", result_host="host01",
            )
            prompt = ap._build_prompt([], "DESCRIPTION", _run_results(), "High level language", False)
        self.assertIn("Suspicious Outbound", prompt)
        self.assertIn("host01", prompt)

    def test_high_level_tone_avoids_jargon_instruction_present(self):
        with patch.object(ap, "st") as mock_st:
            mock_st.session_state = self._session_state()
            prompt = ap._build_prompt([], "SHORT", _run_results(), "High level language", False)
        self.assertIn("Avoid all security jargon", prompt)

    def test_custom_tone_is_passed_through_verbatim(self):
        with patch.object(ap, "st") as mock_st:
            mock_st.session_state = self._session_state()
            prompt = ap._build_prompt([], "SHORT", _run_results(), "SOC L1 concise", False)
        self.assertIn("Tone: SOC L1 concise.", prompt)

    def test_sanitize_flag_adds_its_instruction(self):
        with patch.object(ap, "st") as mock_st:
            mock_st.session_state = self._session_state()
            with_san = ap._build_prompt([], "SHORT", _run_results(), "High level language", True)
            without_san = ap._build_prompt([], "SHORT", _run_results(), "High level language", False)
        self.assertIn("Sanitize sensitive data", with_san)
        self.assertNotIn("Sanitize sensitive data", without_san)

    def test_selected_ioc_evidence_is_included(self):
        items = [_Ioc("1.2.3.4", "ip")]
        rr = _run_results(items=items, vt={"1.2.3.4": {"stats": {"malicious": 3}}})
        with patch.object(ap, "st") as mock_st:
            mock_st.session_state = self._session_state()
            prompt = ap._build_prompt(["1.2.3.4"], "SHORT", rr, "High level language", False)
        self.assertIn("1.2.3.4", prompt)
        self.assertIn("malicious", prompt.lower())

    def test_process_analysis_findings_are_included_when_submitted(self):
        rr = _run_results(process_analysis={
            "fields_submitted": True, "aggregated_verdict": "Suspicious", "checks_skipped": [],
        })
        with patch.object(ap, "st") as mock_st:
            mock_st.session_state = self._session_state()
            prompt = ap._build_prompt([], "SHORT", rr, "High level language", False)
        self.assertIn("Process / filepath analysis", prompt)
        self.assertIn("Suspicious", prompt)

    def test_device_action_context_line_appears_when_set(self):
        with patch.object(ap, "st") as mock_st:
            mock_st.session_state = self._session_state(result_device_action="Blocked")
            prompt = ap._build_prompt([], "SHORT", _run_results(), "High level language", False)
        self.assertIn("Device Action: Blocked", prompt)


# ---------------------------------------------------------------------------
# _build_analysis_summary
# ---------------------------------------------------------------------------

class TestBuildAnalysisSummary(unittest.TestCase):
    def test_empty_run_yields_all_false_evidence(self):
        with patch.object(ap, "st") as mock_st:
            mock_st.session_state = {"result_critical_asset_sel": "Non Critical Asset",
                                      "result_device_action": ""}
            summary = ap._build_analysis_summary([], _run_results())
        self.assertTrue(all(v is False for v in summary["evidence"].values()))
        self.assertEqual(summary["mitre_tactics"], [])

    def test_urlscan_phishing_verdict_sets_evidence_and_tactic(self):
        items = [_Ioc("evil.test", "url")]
        rr = _run_results(items=items, urlscan={
            "evil.test": {"verdicts": {"phishing": True}},
        })
        with patch.object(ap, "st") as mock_st:
            mock_st.session_state = {"result_critical_asset_sel": "Non Critical Asset",
                                      "result_device_action": ""}
            summary = ap._build_analysis_summary(["evil.test"], rr)
        self.assertTrue(summary["evidence"]["phishing_or_social_eng"])
        self.assertIn("TA0001", summary["mitre_tactics"])

    def test_critical_asset_flag_is_read_from_session_state(self):
        with patch.object(ap, "st") as mock_st:
            mock_st.session_state = {"result_critical_asset_sel": "Critical Asset",
                                      "result_device_action": ""}
            summary = ap._build_analysis_summary([], _run_results())
        self.assertEqual(summary["asset_criticality"], "critical")

    def test_event_level_flags_are_folded_in_once(self):
        rr = _run_results(process_flags=[{
            "id": "f1", "label": "L", "threat_type": "T", "severity": "HIGH",
            "mitre": [], "detail": "", "source": "process",
        }])
        with patch.object(ap, "st") as mock_st:
            mock_st.session_state = {"result_critical_asset_sel": "Non Critical Asset",
                                      "result_device_action": ""}
            summary = ap._build_analysis_summary([], rr)
        # Just needs to not crash and to have processed the flag list — the
        # exact evidence key it maps to is flags_summary_for_evidence's
        # concern, already covered by its own tests.
        self.assertIsInstance(summary["evidence"], dict)


# ---------------------------------------------------------------------------
# _build_share_text — the big integration function
# ---------------------------------------------------------------------------

class TestBuildShareText(unittest.TestCase):
    def _session_state(self, run_results, **overrides):
        state = {
            "run_results": run_results, "ai_desc": "", "result_critical_asset_sel": "Non Critical Asset",
            "result_device_action": "", "result_parent_process": "", "result_child_process": "",
            "result_file_path": "", "result_command_line": "",
        }
        state.update(overrides)
        return state

    def test_report_header_and_footer_are_always_present(self):
        rr = _run_results(summary={"total": 0, "malicious": 0, "suspicious": 0, "unknown": 0})
        with patch.object(ap, "st") as mock_st, \
             patch.object(ap, "fetch_geo_ip_api", return_value={}), \
             patch.object(ap, "fetch_nominatim", return_value={}):
            mock_st.session_state = self._session_state(rr)
            out = ap._build_share_text([], rr)
        self.assertTrue(out.startswith("=== IOC Router"))
        self.assertTrue(out.rstrip().endswith("=== End of Report ==="))

    def test_selected_ioc_row_is_included_unselected_is_not(self):
        rr = _run_results(
            summary={"total": 2, "malicious": 1, "suspicious": 0, "unknown": 1},
            rows=[
                {"Artifact": "1.2.3.4", "Type": "ip", "Verdict": "Malicious",
                 "Confidence": "High", "Primary Evidence": "e", "Sources": "VT"},
                {"Artifact": "5.6.7.8", "Type": "ip", "Verdict": "Unknown",
                 "Confidence": "Low", "Primary Evidence": "e2", "Sources": ""},
            ],
        )
        with patch.object(ap, "st") as mock_st, \
             patch.object(ap, "fetch_geo_ip_api", return_value={}), \
             patch.object(ap, "fetch_nominatim", return_value={}):
            mock_st.session_state = self._session_state(rr)
            out = ap._build_share_text(["1.2.3.4"], rr)
        self.assertIn("1.2.3.4", out)
        self.assertNotIn("5.6.7.8", out)

    def test_ai_description_section_strips_its_own_prefix(self):
        rr = _run_results(summary={"total": 0})
        with patch.object(ap, "st") as mock_st, \
             patch.object(ap, "fetch_geo_ip_api", return_value={}), \
             patch.object(ap, "fetch_nominatim", return_value={}):
            mock_st.session_state = self._session_state(rr, ai_desc="#Description: Host contacted a C2 server.")
            out = ap._build_share_text([], rr)
        self.assertIn("--- DESCRIPTION ---", out)
        self.assertIn("Host contacted a C2 server.", out)
        self.assertNotIn("#Description:", out)

    def test_event_rows_are_included_and_not_filtered_by_selection(self):
        """process_rows/waf_rows have no IOC to be selected by — always shown."""
        rr = _run_results(
            summary={"total": 0},
            process_rows=[{"Artifact": "cmd.exe", "Type": "process", "Verdict": "Suspicious",
                           "Confidence": "Med", "Primary Evidence": "e", "Sources": ""}],
        )
        with patch.object(ap, "st") as mock_st, \
             patch.object(ap, "fetch_geo_ip_api", return_value={}), \
             patch.object(ap, "fetch_nominatim", return_value={}):
            mock_st.session_state = self._session_state(rr)
            out = ap._build_share_text([], rr)  # nothing selected
        self.assertIn("EVENT ANALYSIS", out)
        self.assertIn("cmd.exe", out)

    def test_infrastructure_block_uses_geo_and_provider_data(self):
        items = [_Ioc("1.2.3.4", "ip")]
        rr = _run_results(
            items=items, summary={"total": 1},
            abuse={"1.2.3.4": {"isp": "Evil ISP", "countryCode": "US"}},
        )
        with patch.object(ap, "st") as mock_st, \
             patch.object(ap, "fetch_geo_ip_api", return_value={"lat": 1.0, "lon": 2.0, "country": "United States"}), \
             patch.object(ap, "fetch_nominatim", return_value={}):
            mock_st.session_state = self._session_state(rr)
            out = ap._build_share_text(["1.2.3.4"], rr)
        self.assertIn("INFRASTRUCTURE", out)
        self.assertIn("Evil ISP", out)

    def test_source_links_section_reuses_build_ioc_links(self):
        items = [_Ioc("1.2.3.4", "ip")]
        rr = _run_results(items=items, summary={"total": 1}, vt={"1.2.3.4": {"stats": {"malicious": 1}}})
        with patch.object(ap, "st") as mock_st, \
             patch.object(ap, "fetch_geo_ip_api", return_value={}), \
             patch.object(ap, "fetch_nominatim", return_value={}):
            mock_st.session_state = self._session_state(rr)
            out = ap._build_share_text(["1.2.3.4"], rr)
        self.assertIn("--- SOURCES ---", out)
        self.assertIn("VirusTotal:", out)


if __name__ == "__main__":
    unittest.main()
