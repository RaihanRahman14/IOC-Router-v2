"""Tests pinning which verdict is authoritative.

The rule cascade in `ioc.verdict` decides the verdict; the numeric score in
`ioc.confidence_scorer` only measures how well the providers corroborate each
other. The two disagree in most real cases, so these tests lock the split: the
cascade's answer must not follow the score, and no UI surface may present the
score's band as a second verdict.
"""
import unittest
from unittest.mock import patch

from ioc.confidence_scorer import compute_session_summary
from ioc.parser import IOC
from ioc.verdict import summarize_results
from ui.components import ioc_card, output_renderer


def _vt(malicious=0, suspicious=0, harmless=0, undetected=0) -> dict:
    return {"stats": {
        "malicious": malicious, "suspicious": suspicious,
        "harmless": harmless, "undetected": undetected,
    }}


def _row_for(vt=None, abuse=None, mb=None, tf=None) -> dict:
    value = "8.8.8.8"
    ioc = IOC(value=value, type="ip")
    _, rows = summarize_results(
        [ioc],
        {value: vt or {}}, {}, {value: abuse or {}},
        {value: tf or {}}, {value: mb or {}},
    )
    return rows[0]


class TestCascadeIsAuthoritative(unittest.TestCase):
    def test_thin_virustotal_hit_stays_malicious_though_score_says_benign(self):
        """One engine out of 90 scores near zero, but the cascade still calls it.

        This is the disagreement that matters most: letting the score decide
        would quietly reclassify a real detection as benign.
        """
        row = _row_for(vt=_vt(malicious=1, harmless=20, undetected=69))

        self.assertEqual(row["Verdict"], "Malicious")
        self.assertEqual(row["VerdictFromScore"], "Benign")
        self.assertLess(row["ConfidenceScore"], 10)

    def test_confirmed_sample_keeps_the_cascade_verdict_though_score_maxes_out(self):
        """Disagreement in the other direction — the score must not promote either."""
        row = _row_for(mb={"query_status": "ok", "data": [{"signature": "Emotet"}]})

        self.assertEqual(row["Verdict"], "Suspicious")
        self.assertEqual(row["VerdictFromScore"], "Malicious")
        self.assertEqual(row["ConfidenceScore"], 100.0)

    def test_abuse_score_threshold_is_the_cascades_call_not_the_scores(self):
        """AbuseIPDB >= 80 is a cascade rule; the score only reaches its middle band."""
        row = _row_for(abuse={"abuseConfidenceScore": 85})

        self.assertEqual(row["Verdict"], "Malicious")
        self.assertEqual(row["VerdictFromScore"], "Suspicious")

    def test_verdict_vocabulary_is_the_cascades(self):
        """The cascade never emits Benign — its floor is Unknown."""
        verdicts = {
            _row_for()["Verdict"],
            _row_for(vt=_vt(harmless=70, undetected=20))["Verdict"],
        }
        self.assertEqual(verdicts, {"Unknown"})

    def test_benign_count_is_structurally_zero(self):
        summary, _ = summarize_results(
            [IOC(value="8.8.8.8", type="ip")],
            {"8.8.8.8": _vt(harmless=90)}, {}, {}, {}, {},
        )
        self.assertEqual(summary["benign"], 0)


class TestSessionLabelVocabulary(unittest.TestCase):
    def test_labels_describe_evidence_strength_not_threat(self):
        bands = {
            100.0: "Strong", 70.0: "Strong",
            55.0: "Moderate", 40.0: "Moderate",
            25.0: "Weak", 10.0: "Weak",
            0.0: "Minimal",
        }
        for score, expected in bands.items():
            with self.subTest(score=score):
                summary = compute_session_summary([{"score": score, "ioc_value": "x"}])
                self.assertEqual(summary["session_label"], expected)

    def test_no_label_reads_as_a_verdict(self):
        forbidden = ("threat", "benign", "malicious", "suspicious")
        scores = [0.0, 5.0, 25.0, 55.0, 95.0]
        labels = [
            compute_session_summary([{"score": s, "ioc_value": "x"}])["session_label"]
            for s in scores
        ]
        labels.append(compute_session_summary([])["session_label"])
        for label in labels:
            with self.subTest(label=label):
                self.assertFalse(any(word in label.lower() for word in forbidden))


class TestUiShowsOneVerdict(unittest.TestCase):
    def _card_html(self, row: dict) -> str:
        with patch.object(ioc_card, "st") as fake_st:
            ioc_card._render_confidence_score_card(row)
        self.assertTrue(fake_st.markdown.called, "card rendered nothing")
        return fake_st.markdown.call_args[0][0]

    def test_card_shows_the_cascade_verdict_and_hides_the_scores(self):
        html = self._card_html({
            "Verdict": "Malicious", "Confidence": "Med",
            "Primary Evidence": "VT: 1 engines flagged",
            "ConfidenceScore": 0.7, "ConfidenceLabel": "Low",
            "VerdictFromScore": "Benign",
            "ProviderScores": {"virustotal": 0.7}, "ActiveProviders": ["virustotal"],
        })

        self.assertIn("Malicious", html)
        self.assertIn("VT: 1 engines flagged", html)
        # The score's own band must not appear as a competing judgement.
        self.assertNotIn("Benign", html)

    def test_card_labels_the_score_as_corroboration(self):
        html = self._card_html({
            "Verdict": "Unknown", "Confidence": "Low",
            "ConfidenceScore": 42.0, "ConfidenceLabel": "Medium",
            "VerdictFromScore": "Suspicious",
            "ProviderScores": {}, "ActiveProviders": [],
        })

        self.assertIn("Evidence Strength", html)
        self.assertIn("not a verdict", html)
        self.assertNotIn("Suspicious", html)

    def test_card_still_renders_nothing_without_a_score(self):
        with patch.object(ioc_card, "st") as fake_st:
            ioc_card._render_confidence_score_card({"Verdict": "Malicious"})
        fake_st.markdown.assert_not_called()

    def test_hero_drops_the_scores_verdict_distribution(self):
        summary = {
            "total": 3, "malicious": 2, "suspicious": 1, "unknown": 0, "benign": 0,
            "session_summary": {
                "highest_score": 12.5, "highest_ioc": "8.8.8.8",
                # Would have been rendered as pills beside the count cards.
                "verdict_distribution": {"Benign": 2, "Unknown": 1},
                "session_label": "Weak",
            },
        }
        with patch.object(output_renderer, "st") as fake_st:
            output_renderer.render_session_hero(summary)
        html = fake_st.markdown.call_args[0][0]

        self.assertNotIn("Benign: ", html)
        self.assertNotIn("Unknown: ", html)
        # The authoritative counts stay.
        self.assertIn("Malicious", html)
        self.assertIn("Weak corroboration", html)

    def test_hero_without_session_summary_still_renders_counts(self):
        with patch.object(output_renderer, "st") as fake_st:
            output_renderer.render_session_hero(
                {"total": 1, "malicious": 1, "suspicious": 0, "unknown": 0, "benign": 0}
            )
        self.assertIn("Malicious", fake_st.markdown.call_args[0][0])


if __name__ == "__main__":
    unittest.main()
