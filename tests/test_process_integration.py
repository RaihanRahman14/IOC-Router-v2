"""Integration tests for wiring the process analyzer into the existing pipeline.

Covers the seams introduced by plan steps 7-9 — the evidence mapping, the table
row schema, and the JSON payload — without needing a Streamlit runtime.
"""
from __future__ import annotations

import unittest

from core import process_analyzer as pa
from ioc.flags import flags_summary_for_evidence
from ioc.threat_analysis import analyzeThreat
from ioc.verdict import summarize_results


class TestEvidenceMapping(unittest.TestCase):
    """Step 7 — process flags must reach the evidence dict, or they are inert."""

    def test_masquerading_maps_to_malware_executed(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            file_path="C:\\Users\\Public\\svchost.exe"))
        evidence = flags_summary_for_evidence(result.flags)["evidence"]
        self.assertTrue(evidence["malware_executed"])

    def test_pairing_maps_to_malware_executed(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            parent_process="winword.exe", child_process="cmd.exe"))
        evidence = flags_summary_for_evidence(result.flags)["evidence"]
        self.assertTrue(evidence["malware_executed"])

    def test_chain_contamination_maps(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            parent_process="C:\\Users\\Public\\svchost.exe", child_process="notepad.exe"))
        evidence = flags_summary_for_evidence(result.flags)["evidence"]
        self.assertTrue(evidence["malware_executed"])

    def test_masquerading_does_not_claim_persistence(self) -> None:
        """Impersonating a binary says nothing about a persistence mechanism."""
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            file_path="C:\\Users\\Public\\svchost.exe"))
        evidence = flags_summary_for_evidence(result.flags)["evidence"]
        self.assertFalse(evidence["persistence_mechanism"])

    def test_dual_use_alone_sets_no_evidence(self) -> None:
        """A LOLBAS match must not move the Threat State on its own."""
        result = pa.analyze_process_event(pa.ProcessFilepathInput(child_process="certutil.exe"))
        evidence = flags_summary_for_evidence(result.flags)["evidence"]
        self.assertFalse(any(evidence.values()))

    def test_clean_input_sets_no_evidence(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            file_path="C:\\Windows\\System32\\lsass.exe"))
        self.assertFalse(any(flags_summary_for_evidence(result.flags)["evidence"].values()))

    def test_mitre_techniques_reach_the_summary(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            file_path="C:\\Users\\Public\\svchost.exe"))
        self.assertIn("T1036.005", flags_summary_for_evidence(result.flags)["mitre_tactics"])


class TestThreatAnalysisIntegration(unittest.TestCase):
    """The evidence must actually move analyzeThreat, end to end."""

    @staticmethod
    def _analyze(result: pa.ProcessAnalysisResult, device_action: str = "") -> dict:
        summary = flags_summary_for_evidence(result.flags)
        return analyzeThreat({
            "evidence": summary["evidence"],
            "mitre_tactics": summary["mitre_tactics"],
            "risk_notes": summary["notes"],
            "asset_criticality": "standard",
            "device_action": device_action,
        })

    def test_office_pairing_raises_threat_state(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            parent_process="winword.exe", child_process="cmd.exe"))
        self.assertEqual(self._analyze(result)["threat_state"], "Compromise")

    def test_prevented_action_caps_the_state(self) -> None:
        """A blocked detection must not read as a successful compromise."""
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            parent_process="winword.exe", child_process="cmd.exe"))
        self.assertEqual(
            self._analyze(result, device_action="Blocked")["threat_state"], "Intrusion Attempt"
        )

    def test_clean_input_stays_at_exposure(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            file_path="C:\\Windows\\System32\\lsass.exe"))
        self.assertEqual(self._analyze(result)["threat_state"], "Exposure")


class TestTableRowSchema(unittest.TestCase):
    """Step 9 — process rows share the IOC row schema so the table needs no fork."""

    @staticmethod
    def _ioc_row_keys() -> set[str]:
        from ioc.parser import IOC
        _, rows = summarize_results([IOC(value="8.8.8.8", type="ip")], {}, {}, {}, {}, {})
        return set(rows[0])

    def test_schema_matches_ioc_rows_exactly(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            file_path="C:\\Temp\\scvhost.exe",
            parent_process="winword.exe", child_process="cmd.exe"))
        rows = pa.to_rows(result)
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual(set(row), self._ioc_row_keys())

    def test_one_row_per_submitted_field_plus_pair(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            file_path="C:\\Temp\\scvhost.exe",
            parent_process="winword.exe", child_process="cmd.exe"))
        types = [r["Type"] for r in pa.to_rows(result)]
        self.assertEqual(types, ["file_path", "process", "process", "parent_child_pair"])

    def test_no_pair_row_when_one_side_missing(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(parent_process="winword.exe"))
        self.assertNotIn("parent_child_pair", [r["Type"] for r in pa.to_rows(result)])

    def test_pair_row_emitted_even_when_nothing_matched(self) -> None:
        """A check that ran and found nothing must be visible, not silent."""
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            parent_process="explorer.exe", child_process="chrome.exe"))
        pair = [r for r in pa.to_rows(result) if r["Type"] == "parent_child_pair"]
        self.assertEqual(len(pair), 1)
        self.assertEqual(pair[0]["Verdict"], "Unknown")
        self.assertIn("No known-suspicious pairing", pair[0]["Primary Evidence"])

    def test_verdicts_use_the_existing_vocabulary(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            file_path="C:\\Temp\\scvhost.exe",
            parent_process="winword.exe", child_process="cmd.exe"))
        for row in pa.to_rows(result):
            self.assertIn(row["Verdict"], ("Malicious", "Suspicious", "Unknown", "Benign"))
            self.assertIn(row["Confidence"], ("High", "Med", "Low"))

    def test_confidence_score_columns_blank_not_missing(self) -> None:
        """Blank, not absent — a missing key yields ragged NaN columns in pandas.

        ``ConfidenceScore`` is None rather than "": real IOC rows put a number
        in that column, and an empty string beside it makes an object column
        pyarrow cannot convert, which broke ``st.dataframe`` for the entire run.
        None becomes a null in a double column. The key is still present, which
        is what this test was written to guarantee.
        """
        rows = pa.to_rows(pa.analyze_process_event(
            pa.ProcessFilepathInput(file_path="C:\\Temp\\scvhost.exe")))
        self.assertIn("ConfidenceScore", rows[0])
        self.assertIsNone(rows[0]["ConfidenceScore"])
        self.assertEqual(rows[0]["ActiveProviders"], [])

    def test_no_rows_without_process_fields(self) -> None:
        self.assertEqual(pa.to_rows(pa.analyze_process_event(
            pa.ProcessFilepathInput(context="just prose"))), [])

    def test_concatenates_with_ioc_rows_cleanly(self) -> None:
        try:
            import pandas as pd
        except ImportError:  # pragma: no cover
            self.skipTest("pandas not installed")
        from ioc.parser import IOC
        _, ioc_rows = summarize_results([IOC(value="8.8.8.8", type="ip")], {}, {}, {}, {}, {})
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            parent_process="winword.exe", child_process="cmd.exe"))
        df = pd.DataFrame(ioc_rows + pa.to_rows(result))
        self.assertEqual(len(df), 1 + len(pa.to_rows(result)))
        self.assertFalse(df["Verdict"].isna().any())
        self.assertFalse(df["Artifact"].isna().any())


class TestFlagSourceLinks(unittest.TestCase):
    """Every process flag cites a source the analyst can open.

    The Threat Indicators panel makes the label and badges clickable only when
    a URL is present; without one these flags rendered as dead text while every
    provider flag was linked.
    """

    @staticmethod
    def _flags(**kwargs) -> list[dict]:
        return pa.analyze_process_event(pa.ProcessFilepathInput(**kwargs)).flags

    def test_every_flag_carries_a_source_url(self) -> None:
        cases = (
            {"parent_process": "outlook.exe", "child_process": "cmd.exe"},
            {"file_path": "C:\\Users\\Public\\certutil.exe"},
            {"file_path": "C:\\Temp\\scvhost.exe"},
            {"parent_process": "C:\\Users\\Public\\svchost.exe", "child_process": "notepad.exe"},
            {"child_process": "mshta.exe"},
        )
        for case in cases:
            for flag in self._flags(**case):
                with self.subTest(case=case, flag=flag["id"]):
                    self.assertTrue(flag.get("source_url"), f"{flag['id']} has no source_url")
                    self.assertTrue(flag["source_url"].startswith("https://"))

    def test_pairing_links_to_the_sigma_rule(self) -> None:
        flag = next(f for f in self._flags(parent_process="outlook.exe", child_process="cmd.exe")
                    if f["id"] == pa.SUSPICIOUS_PARENT_CHILD_PAIR)
        self.assertIn("github.com/SigmaHQ/sigma", flag["source_url"])
        self.assertTrue(flag["source_url"].endswith(".yml"))

    def test_dual_use_links_to_the_lolbas_page(self) -> None:
        flag = self._flags(child_process="certutil.exe")[0]
        self.assertIn("lolbas-project.github.io", flag["source_url"])

    def test_masquerading_prefers_the_impersonated_lolbas_page(self) -> None:
        flag = self._flags(file_path="C:\\Users\\Public\\certutil.exe")[0]
        self.assertIn("lolbas-project.github.io", flag["source_url"])

    def test_masquerading_falls_back_to_the_attack_technique(self) -> None:
        """svchost.exe is not a LOLBAS binary, so cite T1036.005 instead."""
        flag = self._flags(file_path="C:\\Temp\\scvhost.exe")[0]
        self.assertEqual(flag["source_url"], "https://attack.mitre.org/techniques/T1036/005/")

    def test_mitre_url_builder(self) -> None:
        self.assertEqual(pa._mitre_url("T1105"), "https://attack.mitre.org/techniques/T1105/")
        self.assertEqual(pa._mitre_url("T1218.005"),
                         "https://attack.mitre.org/techniques/T1218/005/")
        self.assertEqual(pa._mitre_url(""), "")
        self.assertEqual(pa._mitre_url("TA0002"), "https://attack.mitre.org/techniques/TA0002/")

    def test_sigma_url_builder_handles_missing_file(self) -> None:
        self.assertEqual(pa._sigma_rule_url({}), "")

    def test_source_url_does_not_break_the_shared_flag_shape(self) -> None:
        for flag in self._flags(parent_process="outlook.exe", child_process="cmd.exe"):
            for key in ("id", "label", "threat_type", "severity", "mitre", "detail", "source"):
                self.assertIn(key, flag)


class TestHashHandoff(unittest.TestCase):
    """Step 8 — a hash found in Context is enriched, then dominates aggregation."""

    def test_candidate_is_exposed_for_the_caller(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            file_path="C:\\Temp\\scvhost.exe",
            context="log line 44d88612fea8a8f36de82e1278abb02f"))
        self.assertEqual(result.hash_candidates, ["44d88612fea8a8f36de82e1278abb02f"])
        self.assertIsNone(result.hash_verdict)
        self.assertEqual(result.aggregated_verdict, "Suspicious")

    def test_written_back_verdict_overrides_name_based_layers(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            file_path="C:\\Temp\\scvhost.exe",
            context="log line 44d88612fea8a8f36de82e1278abb02f"))
        result.hash_verdict = {"verdict": "Malicious", "artifact": result.hash_candidates[0]}
        self.assertEqual(pa.aggregate_verdict(result), "Malicious")

    def test_analyzer_performs_no_lookup_itself(self) -> None:
        """The module must stay network-free; resolution belongs to the caller."""
        import inspect
        source = inspect.getsource(pa)
        for forbidden in ("requests", "urllib", "httpx", "vt_cached", "mb_cached"):
            self.assertNotIn(forbidden, source, f"{forbidden} leaked into the analyzer")


if __name__ == "__main__":
    unittest.main()
