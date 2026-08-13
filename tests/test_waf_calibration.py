"""Calibration of the WAF payload analyzer against a fixed corpus.

Per ``docs/waf_payload_analyzer.md`` Milestone C. The corpus lives in
``tests/fixtures/waf_corpus.json`` and has two halves that are **not** weighted
equally in importance:

* ``known_bad`` — real payloads. Each must reach at least ``Suspicious``.
* ``known_good`` — text a WAF might flag or an analyst might paste, none of
  which may reach ``Malicious``.

Briefing §5 names alert fatigue as the failure this module exists to avoid, so
the false-positive rate is the module's primary quality metric and the
detection rate is secondary. A module that scores 100% on the first half and
90% on the second is worse than one scoring 85% and 100%.

These tests are also where ``CRS_SCORE_THRESHOLD`` is justified. If they start
failing after a CRS regeneration, the threshold is re-derived here from the
measured distribution — not nudged in the module until the suite goes green.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from core.waf_payload_analyzer import CRS_SCORE_THRESHOLD, analyze_waf_payload
from core.waf_payload_parser import parse_waf_line

CORPUS = Path(__file__).resolve().parent / "fixtures" / "waf_corpus.json"


def _load() -> dict:
    return json.loads(CORPUS.read_text(encoding="utf-8"))


def _analyze(line: str):
    """Run one corpus line through the real parse-then-analyse path."""
    data = parse_waf_line(line)
    if data is None:
        return None
    return analyze_waf_payload(data)


class TestCorpusIntegrity(unittest.TestCase):
    def test_corpus_has_both_halves(self) -> None:
        corpus = _load()
        self.assertGreaterEqual(len(corpus["known_bad"]), 20)
        self.assertGreaterEqual(len(corpus["known_good"]), 15)

    def test_every_attack_is_classified_as_a_payload(self) -> None:
        # An attack the parser refuses is never analysed at all, so it would
        # pass every verdict test below by never reaching them. This is the
        # check that catches it — and it did: five corpus attacks, including
        # Spring4Shell, were being dropped by the validation gate.
        for entry in _load()["known_bad"]:
            with self.subTest(id=entry["id"]):
                self.assertIsNotNone(
                    parse_waf_line(entry["line"]),
                    f"{entry['id']} was refused by the validation gate",
                )

    def test_benign_lines_may_or_may_not_be_classified(self) -> None:
        # Deliberately not asserted either way. Ordinary text with no attack
        # markers is correctly refused; text that happens to carry one is
        # correctly analysed and comes out Unknown. Both are acceptable, and
        # requiring one would push the gate in a direction that costs
        # detections.
        classified = sum(
            1 for entry in _load()["known_good"]
            if parse_waf_line(entry["line"]) is not None
        )
        self.assertGreaterEqual(classified, 0)

    def test_ids_are_unique(self) -> None:
        corpus = _load()
        ids = [e["id"] for e in corpus["known_bad"] + corpus["known_good"]]
        self.assertEqual(len(ids), len(set(ids)))


class TestKnownBad(unittest.TestCase):
    def test_every_attack_reaches_suspicious_or_worse(self) -> None:
        misses = []
        for entry in _load()["known_bad"]:
            result = _analyze(entry["line"])
            if result is None or result.aggregated_verdict not in ("Suspicious", "Malicious"):
                verdict = result.aggregated_verdict if result else "not-a-payload"
                score = result.crs_anomaly_score if result else 0
                misses.append(f"{entry['id']} -> {verdict} (score {score:g})")
        self.assertEqual(misses, [], f"{len(misses)} known-bad missed: {misses}")

    def test_curated_cve_payloads_trip_their_fingerprint(self) -> None:
        # Layer 4 is the only layer allowed to reach Malicious unaided, so its
        # entries are asserted individually. An entry carrying
        # expect_fingerprint: false is a documented limitation, not a pass —
        # read its note before relaxing anything here.
        for entry in _load()["known_bad"]:
            if entry.get("category") != "cve":
                continue
            if entry.get("expect_fingerprint") is False:
                continue
            with self.subTest(id=entry["id"]):
                result = _analyze(entry["line"])
                self.assertIsNotNone(
                    result.cve_fingerprint_match,
                    f"{entry['id']} did not trip its fingerprint "
                    f"(score {result.crs_anomaly_score_pl12:g})",
                )
                self.assertEqual(result.aggregated_verdict, "Malicious")

    def test_documented_fingerprint_gaps_still_reach_suspicious(self) -> None:
        # A known limitation must still be caught by another layer, or it is
        # not a limitation but a hole.
        for entry in _load()["known_bad"]:
            if entry.get("expect_fingerprint") is not False:
                continue
            with self.subTest(id=entry["id"]):
                self.assertIn(
                    _analyze(entry["line"]).aggregated_verdict,
                    ("Suspicious", "Malicious"),
                )


class TestKnownGood(unittest.TestCase):
    """The half that decides whether analysts keep reading the output."""

    def test_no_benign_line_is_ever_malicious(self) -> None:
        # The hard requirement. A false Malicious is what trains an analyst to
        # stop reading this module's output.
        false_positives = []
        for entry in _load()["known_good"]:
            result = _analyze(entry["line"])
            if result is not None and result.aggregated_verdict == "Malicious":
                false_positives.append(
                    f"{entry['id']} (score {result.crs_anomaly_score:g}, "
                    f"{entry.get('note', '')})"
                )
        self.assertEqual(
            false_positives, [],
            f"{len(false_positives)} benign lines called Malicious: {false_positives}",
        )

    # Measured ceiling for benign lines reaching Suspicious, as of 2026-08-11.
    #
    # The rate is **not zero and cannot honestly be driven to zero** on this
    # corpus. Four lines clear the threshold: a shared C-like code snippet, a
    # JSON body, a CSV parameter list, and `../shared/reports` in a file
    # manager. A real WAF at PL2 flags all four — that is why they are in the
    # corpus — and the PL1+PL2 score cannot tell them from the weakest genuine
    # attacks, which sit at the same 5-20 range.
    #
    # Raising the threshold to 20 would clear three of them and simultaneously
    # drop `rce_backtick`, `xss_svg_onload` and `lfi_php_wrapper` to Unknown.
    # That trade was measured and rejected: this module never returns Benign, so
    # Suspicious and Unknown both mean "a human decides" and the only difference
    # is whether the line draws attention. Missing an attack outright is worse
    # than drawing attention to an ambiguous one.
    #
    # What must stay at zero is the false **Malicious** rate, asserted above.
    MAX_SUSPICIOUS_FP_RATE = 0.25

    def test_false_positive_rate_stays_under_its_measured_ceiling(self) -> None:
        corpus = _load()["known_good"]
        escalated = [
            entry["id"] for entry in corpus
            if (r := _analyze(entry["line"])) is not None
            and r.aggregated_verdict != "Unknown"
        ]
        rate = len(escalated) / len(corpus)
        self.assertLessEqual(
            rate, self.MAX_SUSPICIOUS_FP_RATE,
            f"FP rate {rate:.0%} exceeds the {self.MAX_SUSPICIOUS_FP_RATE:.0%} "
            f"ceiling — escalated: {escalated}",
        )

    def test_no_benign_line_reaches_suspicious_without_a_real_rule(self) -> None:
        # Whatever the rate, every escalation must be traceable to a PL1/PL2
        # rule. An escalation driven only by punctuation counters would be noise
        # wearing a finding's clothes.
        for entry in _load()["known_good"]:
            result = _analyze(entry["line"])
            if result is None or result.aggregated_verdict == "Unknown":
                continue
            with self.subTest(id=entry["id"]):
                self.assertGreaterEqual(
                    result.crs_anomaly_score_pl12, CRS_SCORE_THRESHOLD,
                )

    def test_punctuation_only_noise_is_filtered_out_by_the_pl12_score(self) -> None:
        # The four lines whose entire score comes from CRS's PL3/PL4 punctuation
        # counters. On the full score they reach 9; on the PL1+PL2 score they are
        # exactly zero, which is why verdicts are decided on the latter.
        noise_only = {"french_name", "discount_text", "math_expression",
                      "html_escaped_text"}
        for entry in _load()["known_good"]:
            if entry["id"] not in noise_only:
                continue
            with self.subTest(id=entry["id"]):
                result = _analyze(entry["line"])
                self.assertGreater(result.crs_anomaly_score, 0)
                self.assertEqual(result.crs_anomaly_score_pl12, 0.0)
                self.assertEqual(result.aggregated_verdict, "Unknown")

    def test_no_benign_line_trips_a_cve_fingerprint(self) -> None:
        # A fingerprint match is the only single-source Malicious in the module.
        # One false positive here invalidates that exception for every entry in
        # the file, not just the offending one.
        for entry in _load()["known_good"]:
            with self.subTest(id=entry["id"]):
                result = _analyze(entry["line"])
                if result is None:
                    continue
                self.assertIsNone(result.cve_fingerprint_match)


class TestThresholdIsJustified(unittest.TestCase):
    """The threshold has to sit in a gap that actually exists."""

    def test_the_full_score_would_not_separate_the_halves(self) -> None:
        # Why the PL1+PL2 score exists. On the full score the two halves overlap
        # badly — an ordinary JSON body outscores most real attacks — so no
        # threshold placed on it could work. Pinned so that anyone tempted to
        # simplify back to the full score sees the measurement first.
        corpus = _load()
        worst_benign = max(
            r.crs_anomaly_score for e in corpus["known_good"]
            if (r := _analyze(e["line"])) is not None
        )
        attacks_below = [
            e["id"] for e in corpus["known_bad"]
            if (r := _analyze(e["line"])) is not None
            and r.crs_anomaly_score < worst_benign
        ]
        self.assertTrue(
            attacks_below,
            "the full score now separates the halves — re-derive the threshold",
        )

    def test_pl12_threshold_sits_in_a_real_gap(self) -> None:
        corpus = _load()
        # Benign lines that clear the threshold are the module's Suspicious
        # false positives: acceptable, but they must stay a minority.
        benign_scores = [
            r.crs_anomaly_score_pl12 for e in corpus["known_good"]
            if (r := _analyze(e["line"])) is not None
        ]
        over = [s for s in benign_scores if s >= CRS_SCORE_THRESHOLD]
        self.assertLess(
            len(over), len(benign_scores) / 2,
            f"more than half of benign lines clear the threshold: {benign_scores}",
        )

    def test_threshold_is_one_real_rule_not_zero(self) -> None:
        # A threshold of zero would make any single PL3 punctuation match a
        # finding, which is the failure mode this module is written against.
        self.assertGreaterEqual(CRS_SCORE_THRESHOLD, 5.0)


if __name__ == "__main__":
    unittest.main()
