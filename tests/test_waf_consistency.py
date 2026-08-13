"""Consistency between a WAF payload's verdict and everything derived from it.

This file exists because of a specific failure. Milestone C moved verdicts onto
the PL1/PL2 anomaly score, after measuring that CRS's PL3/PL4 rules are largely
punctuation counters that fire on ordinary JSON and source code. Only
``aggregate_verdict`` was changed. The flag builder, the table row and the AI
prompt kept reading the full score and the display-capped match list, so a benign
line came out ``Unknown`` while simultaneously raising a **HIGH**
``WAF_SQLI_MATCH`` that set ``exploit_attempt=True`` in the Threat Analysis
narrative.

Every existing test passed throughout: they checked verdicts, and they checked
flags, but nothing checked that the two agreed. That is the gap these tests
close. They assert relationships between outputs rather than the value of any one
output, so a future change that moves one of them has to move the others.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from core.waf_payload_analyzer import (
    CATEGORY_HIGH_SEVERITY_WEIGHT,
    CRS_SCORE_THRESHOLD,
    analyze_waf_payload,
    decision_categories,
    to_rows,
)
from core.waf_payload_parser import parse_waf_line
from ioc.flags import flags_summary_for_evidence

CORPUS = Path(__file__).resolve().parent / "fixtures" / "waf_corpus.json"


def _analyze(line: str):
    data = parse_waf_line(line)
    return analyze_waf_payload(data) if data else None


def _corpus_lines() -> list[str]:
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    return [e["line"] for e in corpus["known_bad"] + corpus["known_good"]]


class TestVerdictAndFlagsAgree(unittest.TestCase):
    def test_unknown_verdict_never_claims_an_exploit_attempt(self) -> None:
        # The exact regression. `50% off -- limited time` scored 9 on the full
        # score and 0 on PL1/PL2, so the verdict was Unknown while the flag
        # builder still raised a HIGH SQLi flag from PL3/PL4 punctuation rules.
        for line in _corpus_lines():
            result = _analyze(line)
            if result is None or result.aggregated_verdict != "Unknown":
                continue
            with self.subTest(line=line[:48]):
                evidence = flags_summary_for_evidence(result.flags)["evidence"]
                self.assertFalse(
                    evidence["exploit_attempt"],
                    f"Unknown verdict but exploit_attempt=True, flags="
                    f"{[f['id'] for f in result.flags]}",
                )

    def test_punctuation_only_noise_raises_no_category_flag(self) -> None:
        result = _analyze("/promo?text= | 50% off -- limited time")
        self.assertGreater(result.crs_anomaly_score, 0)
        self.assertEqual(result.crs_anomaly_score_pl12, 0.0)
        self.assertEqual(result.aggregated_verdict, "Unknown")
        self.assertEqual(
            [f["id"] for f in result.flags], [],
            "a category flag survived on PL3/PL4 matches alone",
        )

    def test_category_flags_match_the_decision_categories(self) -> None:
        # Flags and the verdict must be computed from the same category set.
        for line in _corpus_lines():
            result = _analyze(line)
            if result is None:
                continue
            with self.subTest(line=line[:48]):
                flagged = {
                    f["id"] for f in result.flags if f["id"].startswith("WAF_")
                    and f["id"] not in ("WAF_ENCODED_PAYLOAD", "WAF_CVE_FINGERPRINT")
                }
                self.assertEqual(len(flagged), len(decision_categories(result)))

    def test_a_single_rule_is_never_a_high_flag(self) -> None:
        # D10 applied to flags, not just to verdicts: HIGH on one match tells
        # the analyst and the evidence mapper that one rule was conclusive.
        for line in _corpus_lines():
            result = _analyze(line)
            if result is None:
                continue
            for flag in result.flags:
                if flag["severity"] != "HIGH":
                    continue
                category = next(
                    (c for c, s in result.crs_category_stats.items()
                     if s.get("weight_pl12", 0) >= CATEGORY_HIGH_SEVERITY_WEIGHT),
                    None,
                )
                with self.subTest(line=line[:48], flag=flag["id"]):
                    self.assertIsNotNone(
                        category, f"{flag['id']} is HIGH on a sub-threshold weight",
                    )

    def test_flag_counts_are_not_truncated_by_the_display_cap(self) -> None:
        # crs_matches is capped at 20 for display; category totals must come
        # from the uncapped stats. A category whose matches all fell past the
        # cap previously rendered "0 rule(s) matched, weight 0. Example: ?".
        result = _analyze(
            "/x | ' OR 1=1 UNION ALL SELECT 1,2,3 <script>alert(1)</script> "
            ";cat /etc/passwd ../../etc/passwd"
        )
        self.assertIsNotNone(result)
        for flag in result.flags:
            if not flag["id"].endswith("_MATCH") or flag["id"] == "WAF_CVE_FINGERPRINT":
                continue
            with self.subTest(flag=flag["id"]):
                self.assertNotIn("0 rule(s)", flag["detail"])
                self.assertNotIn("Example: ?", flag["detail"])


class TestVerdictAndRowAgree(unittest.TestCase):
    def test_row_confidence_never_outruns_the_verdict(self) -> None:
        for line in _corpus_lines():
            result = _analyze(line)
            if result is None:
                continue
            row = to_rows(result)[0]
            with self.subTest(line=line[:48]):
                self.assertEqual(row["Verdict"], result.aggregated_verdict)
                if result.aggregated_verdict == "Unknown":
                    self.assertEqual(
                        row["Confidence"], "Low",
                        f"Unknown verdict rendered at {row['Confidence']} confidence",
                    )

    def test_crs_is_only_cited_as_a_source_when_it_decided_something(self) -> None:
        # A row citing "Local (OWASP CRS)" claims CRS found something that
        # mattered. PL3/PL4 punctuation matches do not qualify.
        for line in _corpus_lines():
            result = _analyze(line)
            if result is None:
                continue
            row = to_rows(result)[0]
            with self.subTest(line=line[:48]):
                if "OWASP CRS" in row["Sources"]:
                    self.assertGreaterEqual(
                        result.crs_anomaly_score_pl12, CRS_SCORE_THRESHOLD,
                    )

    def test_a_truncated_scan_is_never_rendered_as_a_clean_one(self) -> None:
        from core.crs_matcher import MAX_SCAN_LEN

        # SQLi placed past the scan bound: the row must not claim nothing
        # matched, because nothing was looked at down there.
        line = "/x | '" + ("a" * (MAX_SCAN_LEN + 50)) + " UNION ALL SELECT 1,2,3"
        result = _analyze(line)
        self.assertTrue(result.crs_truncated)
        row = to_rows(result)[0]
        self.assertIn("truncated", row["Primary Evidence"])


if __name__ == "__main__":
    unittest.main()
