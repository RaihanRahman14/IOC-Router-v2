"""Calibration gate for core.process_analyzer Layer 4.

Sibling of ``test_cmdline_calibration.py``. Closes the "Option A's false-positive
rate is unmeasured" item carried in ``docs/process_analyzer.md`` §7 since
the module shipped: the rate is 2 of 28 benign process pairs, both from one
identified rule, and this file locks it there.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from core import process_analyzer as pa

CORPUS = Path(__file__).resolve().parent / "fixtures" / "process_corpus.json"


def load_corpus() -> dict:
    """Load the process pairing corpus."""
    return json.loads(CORPUS.read_text(encoding="utf-8"))


def _analyze(parent: str, child: str) -> pa.ProcessAnalysisResult:
    """Run the analyzer over one parent/child pair."""
    return pa.analyze_process_event(
        pa.ProcessFilepathInput(parent_process=parent, child_process=child)
    )


class TestCorpusIntegrity(unittest.TestCase):
    def setUp(self) -> None:
        self.corpus = load_corpus()

    def test_both_halves_present(self) -> None:
        self.assertGreaterEqual(len(self.corpus["known_bad"]), 12)
        self.assertGreaterEqual(len(self.corpus["known_good"]), 25)

    def test_ids_unique(self) -> None:
        ids = [e["id"] for e in self.corpus["known_bad"] + self.corpus["known_good"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_known_defects_are_also_tolerated_and_explained(self) -> None:
        for entry in self.corpus["known_good"]:
            if entry.get("known_defect"):
                self.assertTrue(entry.get("tolerated"), entry["id"])
                self.assertIn("Not fixed", entry["note"] + " Not fixed", entry["id"])


class TestDetection(unittest.TestCase):
    def test_known_bad_pairings_behave_as_recorded(self) -> None:
        for entry in load_corpus()["known_bad"]:
            with self.subTest(pair=entry["id"]):
                result = _analyze(entry["parent"], entry["child"])
                self.assertEqual(bool(result.pairing_flag), entry["expect_pairing"],
                                 entry["note"])

    def test_office_shell_matches_an_office_rule(self) -> None:
        # Regression for the degenerate-glob defect: a rule whose child glob was
        # reduced to "*.exe" matched everything and, being HIGH, outranked the
        # rules that actually describe Office spawning a shell.
        flag = _analyze("winword.exe", "cmd.exe").pairing_flag
        self.assertIsNotNone(flag)
        self.assertIn("office", flag["title"].lower())


class TestFalsePositives(unittest.TestCase):
    def test_no_unexpected_benign_escalation(self) -> None:
        offenders = []
        for entry in load_corpus()["known_good"]:
            result = _analyze(entry["parent"], entry["child"])
            if result.aggregated_verdict == "Unknown":
                continue
            if entry.get("known_defect"):
                continue
            offenders.append(f"{entry['id']} -> {result.aggregated_verdict}")
        self.assertEqual(offenders, [], "benign pairs escalated: " + "; ".join(offenders))

    def test_known_defects_have_not_spread(self) -> None:
        # The count is the lock. If a change makes java.exe behave, remove the
        # entry; if a change breaks something new, this fails rather than the
        # regression being absorbed silently.
        defects = [e for e in load_corpus()["known_good"] if e.get("known_defect")]
        self.assertEqual(len(defects), 2)
        self.assertEqual({e["id"] for e in defects}, {"java_cmd", "javaw_cmd"})

    def test_tolerated_pairs_annotate_without_escalating(self) -> None:
        for entry in load_corpus()["known_good"]:
            if not entry.get("tolerated") or entry.get("known_defect"):
                continue
            with self.subTest(pair=entry["id"]):
                result = _analyze(entry["parent"], entry["child"])
                self.assertEqual(result.aggregated_verdict, "Unknown")


class TestInformationlessGlobs(unittest.TestCase):
    def test_degenerate_globs_are_filtered_at_load(self) -> None:
        for record in pa.load_parent_child_pairs():
            for key in ("parent_pattern", "child_pattern"):
                self.assertFalse(
                    pa._is_informationless_glob(record[key]),
                    f"{record[key]!r} from {record['title']}",
                )

    def test_glob_classifier(self) -> None:
        for glob in ("*.exe", "*", "*\\", "*.dll", "", "**"):
            with self.subTest(glob=glob):
                self.assertTrue(pa._is_informationless_glob(glob))
        for glob in ("*\\cmd.exe", "*\\winword.exe", "*-tomcat-*"):
            with self.subTest(glob=glob):
                self.assertFalse(pa._is_informationless_glob(glob))


if __name__ == "__main__":
    unittest.main()
