"""Tests for Layer 5 (Sigma CommandLine matching) and the D6 rule-id join."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from core import cmdline_analyzer as ca
from core import process_analyzer as pa

_DATASET = Path(__file__).resolve().parents[1] / "core" / "data" / "sigma_cmdline_patterns.json"


class TestDataset(unittest.TestCase):
    def test_dataset_loads(self) -> None:
        patterns = ca.load_sigma_cmdline_patterns()
        self.assertGreater(len(patterns), 500)

    def test_every_record_carries_provenance(self) -> None:
        for record in ca.load_sigma_cmdline_patterns():
            for key in (
                "sigma_rule_id", "sigma_level", "sigma_file", "title",
                "image_constrained", "parentimage_constrained", "complete_condition",
            ):
                self.assertIn(key, record)

    def test_no_pattern_is_dangerously_short(self) -> None:
        meta = json.loads(_DATASET.read_text(encoding="utf-8"))["_meta"]
        floor = meta["min_pattern_len"]
        for record in ca.load_sigma_cmdline_patterns():
            for pattern in record["patterns"]:
                self.assertGreaterEqual(len(pattern), floor, f"{pattern!r} in {record['title']}")

    def test_high_value_techniques_survived_extraction(self) -> None:
        # Plan §6 B1 sanity check: a missing category means the detection-block
        # filter is wrong, not that Sigma lacks the rule.
        blob = " ".join(
            p for record in ca.load_sigma_cmdline_patterns() for p in record["patterns"]
        )
        for needle in (
            "encodedcommand", "downloadstring", "urlcache", "javascript:",
            "process call create", "delete shadows", "amsi",
        ):
            self.assertIn(needle, blob, f"{needle} missing from the dataset")

    def test_most_records_are_fragments(self) -> None:
        # The finding that reshaped Layer 5: only a minority of records
        # reproduce their rule's whole condition. If this ratio ever inverts,
        # the extractor changed and the gating below needs re-justifying.
        records = ca.load_sigma_cmdline_patterns()
        complete = [r for r in records if r["complete_condition"]]
        self.assertLess(len(complete), len(records) / 2)


class TestStandaloneMatching(unittest.TestCase):
    def test_fragment_records_never_match_alone(self) -> None:
        for record in ca.load_sigma_cmdline_patterns():
            if record["complete_condition"]:
                continue
            # Build text that contains every pattern this fragment asks for.
            text = " ".join(record["patterns"])
            matched = [m for m in ca.match_sigma_patterns(text)
                       if m["sigma_rule_id"] == record["sigma_rule_id"]
                       and not m["complete_condition"]]
            self.assertEqual(matched, [], f"fragment matched alone: {record['title']}")

    def test_complete_records_do_match_alone(self) -> None:
        complete = [r for r in ca.load_sigma_cmdline_patterns() if r["complete_condition"]]
        sample = next(r for r in complete if not r["match_all"])
        matches = ca.match_sigma_patterns(sample["patterns"][0])
        self.assertTrue(matches)

    def test_benign_line_matches_no_rule(self) -> None:
        for line in (
            r"ipconfig.exe /all",
            r"robocopy.exe D:\data E:\backup /MIR",
            r'msiexec.exe /i "C:\ProgramData\vendor\agent.msi" /qn',
        ):
            with self.subTest(line=line):
                self.assertEqual(ca.match_sigma_patterns(line), [])

    def test_matches_are_capped(self) -> None:
        noisy = "powershell -enc -nop -w hidden iex downloadstring certutil -urlcache mshta http"
        self.assertLessEqual(len(ca.match_sigma_patterns(noisy)), ca.MAX_RULE_MATCHES)

    def test_missing_dataset_degrades_to_no_matches(self) -> None:
        ca.load_sigma_cmdline_patterns.cache_clear()
        original = ca._SIGMA_PATTERNS_FILE
        try:
            ca._SIGMA_PATTERNS_FILE = original.with_name("absent.json")
            self.assertEqual(ca.load_sigma_cmdline_patterns(), [])
            self.assertEqual(ca.match_sigma_patterns("powershell -enc AAAA"), [])
        finally:
            ca._SIGMA_PATTERNS_FILE = original
            ca.load_sigma_cmdline_patterns.cache_clear()


class TestRuleIdJoin(unittest.TestCase):
    """D6 — the two Option-A datasets reconstruct their source rule together.

    ``apache-tomcat-9.exe -> adfind.exe`` and a command line containing ``-nop``
    are two halves of SigmaHQ rule 4ebc877f ("Webshell Hacking Activity
    Patterns"): the pairs table kept its ParentImage/Image condition and dropped
    the CommandLine one, this dataset did the reverse.
    """

    def _linked(self) -> pa.ProcessAnalysisResult:
        return pa.analyze_process_event(pa.ProcessFilepathInput(
            parent_process="apache-tomcat-9.exe", child_process="adfind.exe",
        ))

    def test_the_fixture_really_is_two_halves_of_one_rule(self) -> None:
        pairing = self._linked().pairing_flag or {}
        self.assertTrue(pairing.get("commandline_constrained"))
        rule_id = str(pairing["sigma_rule_id"])
        halves = [r for r in ca.load_sigma_cmdline_patterns()
                  if str(r["sigma_rule_id"]) == rule_id]
        self.assertTrue(halves, "fixture rule is absent from the CommandLine dataset")
        self.assertTrue(any(h["parentimage_constrained"] or h["image_constrained"]
                            for h in halves))

    def test_without_the_process_half_the_fragment_stays_suppressed(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line="powershell.exe -nop -c Get-Item C:\\Temp"))
        self.assertEqual(result.rule_matches, [])
        self.assertEqual(result.joined_rule_count, 0)

    def test_with_the_process_half_the_rule_is_reconstructed(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line="powershell.exe -nop -c Get-Item C:\\Temp",
            linked_process=self._linked(),
        ))
        self.assertEqual(result.joined_rule_count, 1)
        match = result.rule_matches[0]
        self.assertTrue(match["faithful_multifield"])
        self.assertFalse(match["approximate"])
        self.assertIn("exact", match["approximate_note"])

    def test_a_reconstructed_rule_reaches_malicious(self) -> None:
        # Plan §4 rule 2: nothing was approximated, so this is the one path to
        # Malicious that does not require obfuscation.
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line="powershell.exe -nop -c Get-Item C:\\Temp",
            linked_process=self._linked(),
        ))
        self.assertEqual(result.aggregated_verdict, "Malicious")

    def test_an_unrelated_process_result_unlocks_nothing(self) -> None:
        unrelated = pa.analyze_process_event(pa.ProcessFilepathInput(
            parent_process="explorer.exe", child_process="chrome.exe"))
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line="powershell.exe -nop -c Get-Item C:\\Temp",
            linked_process=unrelated,
        ))
        self.assertEqual(result.joined_rule_count, 0)
        self.assertEqual(result.rule_matches, [])


if __name__ == "__main__":
    unittest.main()
