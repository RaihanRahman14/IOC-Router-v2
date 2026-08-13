"""Calibration gate for the command-line analyzer.

Turns the corpus in ``tests/fixtures/cmdline_corpus.json`` from a one-off
measurement into a regression lock. The false-positive assertion is the one that
matters: detection can be re-measured any time, but a module that starts firing
on ordinary administration gets ignored by analysts and never recovers.

Run the same corpus interactively with::

    python core/scripts/try_cmdline_analyzer.py --calibrate --verbose
"""
from __future__ import annotations

import unittest

from core.scripts.try_cmdline_analyzer import calibrate, load_corpus

# Detection is allowed to slip slightly below perfect so that adding a genuinely
# hard sample to the corpus documents a gap instead of breaking the build. False
# positives get no such allowance.
MIN_DETECTION_RATE = 0.90


class TestCorpusIntegrity(unittest.TestCase):
    def setUp(self) -> None:
        self.corpus = load_corpus()

    def test_corpus_has_both_halves(self) -> None:
        self.assertGreaterEqual(len(self.corpus["known_bad"]), 25)
        self.assertGreaterEqual(len(self.corpus["known_good"]), 25)

    def test_ids_are_unique(self) -> None:
        ids = [e["id"] for e in self.corpus["known_bad"] + self.corpus["known_good"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_entry_documents_itself(self) -> None:
        for entry in self.corpus["known_bad"] + self.corpus["known_good"]:
            self.assertTrue(entry.get("note"), f"{entry['id']} has no note")

    def test_tolerated_flags_are_declared_not_implied(self) -> None:
        # A tolerated flag is a reviewed exception. Requiring the key to exist
        # on every known-good entry stops "benign but noisy" becoming a silent
        # default that swallows real false positives.
        for entry in self.corpus["known_good"]:
            self.assertIn("tolerated_flags", entry, f"{entry['id']} omits tolerated_flags")

    def test_no_live_infrastructure_in_the_corpus(self) -> None:
        # Documentation ranges only (RFC 5737 / RFC 2606). The corpus is
        # committed to the repo and must not point anywhere real.
        import re
        allowed_host = re.compile(r"^(198\.51\.100\.|203\.0\.113\.|192\.0\.2\.)")
        host_re = re.compile(r"https?://([^/\s\"')]+)", re.IGNORECASE)
        for entry in self.corpus["known_bad"] + self.corpus["known_good"]:
            for host in host_re.findall(entry["command_line"]):
                ok = allowed_host.match(host) or host.endswith("example.com")
                self.assertTrue(ok, f"{entry['id']} references {host}")


class TestCalibrationGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.summary = calibrate(load_corpus())

    def test_no_false_positives_on_known_good(self) -> None:
        offenders = self.summary["false_positives"]
        self.assertEqual(
            offenders, [],
            "benign command lines fired unexpected flags: "
            + "; ".join(f"{o['id']} -> {', '.join(o['flags'])}" for o in offenders),
        )

    def test_detection_rate_holds(self) -> None:
        self.assertGreaterEqual(
            self.summary["detection_rate"], MIN_DETECTION_RATE,
            f"missed: {', '.join(self.summary['known_bad_missed'])}",
        )

    def test_malicious_verdicts_are_always_corroborated(self) -> None:
        # Layer 5 can lift the ceiling, but not the rule that guards it: every
        # Malicious verdict must rest on a second, independent source. Asserted
        # across the whole corpus rather than on a single crafted case.
        from core.cmdline_analyzer import (
            _CORROBORATING_SIGMA_LEVELS, CommandLineInput, analyze_command_line,
        )
        for entry in load_corpus()["known_bad"]:
            result = analyze_command_line(CommandLineInput(command_line=entry["command_line"]))
            if result.aggregated_verdict != "Malicious":
                continue
            corroborating = [
                m for m in result.rule_matches
                if str(m.get("sigma_level", "")).lower() in _CORROBORATING_SIGMA_LEVELS
            ]
            self.assertTrue(
                corroborating or result.lolbas_cross_check,
                f"{entry['id']} reached Malicious with no second source",
            )

    def test_rule_matches_reproduce_their_whole_condition(self) -> None:
        # A standalone match must come from a rule whose entire condition this
        # layer can evaluate. Fragment matching flagged 100% of the known-good
        # half when it was briefly allowed.
        from core.cmdline_analyzer import CommandLineInput, analyze_command_line
        for entry in load_corpus()["known_bad"] + load_corpus()["known_good"]:
            result = analyze_command_line(CommandLineInput(command_line=entry["command_line"]))
            for match in result.rule_matches:
                self.assertTrue(
                    match.get("complete_condition") or match.get("faithful_multifield"),
                    f"{entry['id']} matched a partial rule condition: {match.get('title')}",
                )


if __name__ == "__main__":
    unittest.main()
