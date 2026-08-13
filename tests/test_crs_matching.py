"""Tests for Layer 3 — CRS transformations and payload matching.

Per ``docs/waf_payload_analyzer.md`` B2, the measure of this layer is not how
many rules it can make fire. It is whether ordinary traffic stays quiet while
real payloads score. Both halves are tested here, and the known-good half is the
one that matters: a matcher tuned only for recall looks excellent right up to the
point analysts start ignoring it.
"""
from __future__ import annotations

import unittest

from core import crs_transforms as tr
from core.crs_matcher import MAX_STORED_MATCHES, load_rules, scan


class TestTransformations(unittest.TestCase):
    """Faithfulness to ModSecurity, not to this project's other decoder."""

    def test_urldecode_has_no_occurrence_threshold(self) -> None:
        # The deliberate difference from decode_common, which refuses a lone
        # percent sequence so that %SystemRoot% survives. ModSecurity has no
        # such reservation and a rule written against the decoded form needs it.
        self.assertEqual(tr.t_urldecode("id=1%27"), "id=1'")

    def test_urldecodeuni_handles_iis_style_escapes(self) -> None:
        self.assertEqual(tr.t_urldecodeuni("%u003cscript%u003e"), "<script>")

    def test_htmlentitydecode_handles_named_entities(self) -> None:
        # The other deliberate difference: decode_common excludes named
        # entities so "dir&copy a b" survives. ModSecurity decodes them.
        self.assertEqual(tr.t_htmlentitydecode("&lt;script&gt;"), "<script>")
        self.assertEqual(tr.t_htmlentitydecode("&#60;a&#62;"), "<a>")

    def test_replacecomments_defeats_comment_splitting(self) -> None:
        self.assertEqual(tr.t_replacecomments("un/*x*/ion"), "un ion")

    def test_unterminated_comment_is_replaced_to_end_of_string(self) -> None:
        # uni/*on would otherwise keep hiding a keyword behind an open comment.
        self.assertEqual(tr.t_replacecomments("select/*rest"), "select ")

    def test_removewhitespace_and_compresswhitespace_differ(self) -> None:
        self.assertEqual(tr.t_removewhitespace("a \t b"), "ab")
        self.assertEqual(tr.t_compresswhitespace("a \t b"), "a b")

    def test_cmdline_normalises_caret_and_quote_evasion(self) -> None:
        # The evasion this transformation exists for: c^m^d and "cmd" must both
        # reduce to the same text as plain cmd.
        self.assertEqual(tr.t_cmdline("c^m^d /c whoami"), "cmd/c whoami")
        self.assertEqual(tr.t_cmdline('"cmd" /c'), "cmd/c")

    def test_cmdline_replaces_separators_with_spaces(self) -> None:
        self.assertEqual(tr.t_cmdline("a,b;c"), "a b c")

    def test_jsdecode_handles_unicode_and_hex_escapes(self) -> None:
        self.assertEqual(tr.t_jsdecode(r"alert"), "alert")
        self.assertEqual(tr.t_jsdecode(r"\x61lert"), "alert")

    def test_jsdecode_drops_the_backslash_only_from_non_escape_letters(self) -> None:
        # \l and \e are not escapes, so their backslashes go. \a, \r and \t are,
        # so they become BEL, CR and TAB. The consequence is worth pinning:
        # backslash-splitting "alert" does NOT round-trip back to "alert", here
        # or in ModSecurity. A reader assuming otherwise would think this
        # transformation defeats an evasion it does not.
        self.assertEqual(tr.t_jsdecode(r"\l\e"), "le")
        self.assertEqual(tr.t_jsdecode(r"\a\l\e\r\t"), "\x07le\r\t")

    def test_cssdecode_resolves_hex_escapes(self) -> None:
        self.assertEqual(tr.t_cssdecode(r"\61 lert"), "alert")

    def test_escapeseqdecode_handles_c_escapes(self) -> None:
        self.assertEqual(tr.t_escapeseqdecode(r"a\x62c"), "abc")
        self.assertEqual(tr.t_escapeseqdecode(r"a\tb"), "a\tb")

    def test_normalizepath_resolves_traversal(self) -> None:
        self.assertEqual(tr.t_normalizepath("a/b/../c"), "a/c")
        self.assertEqual(tr.t_normalizepath("a//b"), "a/b")

    def test_normalizepathwin_converts_separators_first(self) -> None:
        self.assertEqual(tr.t_normalizepathwin(r"a\b\..\c"), "a/c")

    def test_utf8tounicode_escapes_non_ascii(self) -> None:
        self.assertEqual(tr.t_utf8tounicode("aé"), "a%u00e9")
        self.assertEqual(tr.t_utf8tounicode("plain"), "plain")

    def test_removenulls_and_removecommentschar(self) -> None:
        self.assertEqual(tr.t_removenulls("a\x00b"), "ab")
        self.assertEqual(tr.t_removecommentschar("a--b"), "ab")


class TestApplyChain(unittest.TestCase):
    def test_chain_runs_in_declaration_order(self) -> None:
        text, unknown = tr.apply_chain("%3CSCRIPT%3E", ("none", "urlDecodeUni", "lowercase"))
        self.assertEqual(text, "<script>")
        self.assertEqual(unknown, [])

    def test_unknown_transformation_is_reported_not_silently_skipped(self) -> None:
        # A caller that ignores this is claiming a fidelity it does not have.
        text, unknown = tr.apply_chain("abc", ("none", "someFutureTransform"))
        self.assertEqual(text, "abc")
        self.assertEqual(unknown, ["someFutureTransform"])

    def test_names_are_matched_case_insensitively(self) -> None:
        text, unknown = tr.apply_chain("A", ("LOWERCASE",))
        self.assertEqual(text, "a")
        self.assertEqual(unknown, [])

    def test_empty_chain_returns_the_input(self) -> None:
        self.assertEqual(tr.apply_chain("abc", ())[0], "abc")


class TestRuleSetLoads(unittest.TestCase):
    def test_rules_load_and_compile(self) -> None:
        rules = load_rules()
        self.assertGreater(len(rules), 100)

    def test_every_rule_is_matchable(self) -> None:
        for rule in load_rules():
            with self.subTest(rule_id=rule["rule_id"]):
                self.assertTrue("regex" in rule or "phrases" in rule)

    def test_no_chained_rule_survived_extraction(self) -> None:
        # Regression for the defect that nearly shipped. CRS rule 932205 is the
        # head of a chain: its own pattern is "^[^#]+" against the Referer
        # header, which matches essentially any string, and the real detection
        # lives in the sub-rules that follow it. Emitted alone it fired on
        # "report q3" — a rule that matches everything is worse than no rule.
        ids = {rule["rule_id"] for rule in load_rules()}
        for chained in ("932205", "932206", "932200"):
            self.assertNotIn(chained, ids)


class TestMatchingKnownBad(unittest.TestCase):
    CASES = {
        "sqli quote": ("' OR '1'='1", "sqli"),
        "sqli union": ("id=1 UNION SELECT password FROM users--", "sqli"),
        "xss script tag": ("<script>alert(1)</script>", "xss"),
        "traversal": ("../../../../etc/passwd", "lfi"),
        "command injection": (";cat /etc/passwd", "rce"),
    }

    def test_each_payload_scores_and_names_its_category(self) -> None:
        for label, (payload, expected) in self.CASES.items():
            with self.subTest(case=label):
                result = scan(payload, payload)
                self.assertGreater(result.anomaly_score, 0, f"{label} scored nothing")
                self.assertIn(expected, result.categories)

    def test_encoded_payload_is_caught_via_the_decoded_form(self) -> None:
        # The reason both forms are scanned: 47 extracted rules declare no
        # transformation at all, and in a live ModSecurity they would see an
        # already-decoded ARGS value.
        raw = "%3Cscript%3Ealert(1)%3C/script%3E"
        decoded = "<script>alert(1)</script>"
        result = scan(raw, decoded)
        self.assertIn("xss", result.categories)

    def test_a_rule_contributes_once_even_if_both_forms_fire(self) -> None:
        payload = "' OR '1'='1"
        both = scan(payload, payload)
        ids = [m.rule_id for m in both.matches]
        self.assertEqual(len(ids), len(set(ids)))


class TestMatchingKnownGood(unittest.TestCase):
    """The half that decides whether analysts keep reading the output."""

    # Text that must never look like an attack.
    SILENT = (
        "SELECT * FROM menu",
        "how to use the < operator in python",
        "O'Brien",
        "report q3 2024",
    )

    # Ordinary text that does score a little, because CRS's high-paranoia rules
    # count punctuation. Kept as a separate group rather than being asserted to
    # zero: pretending these are silent would hide the noise floor a threshold
    # has to clear.
    NOISY_BUT_BENIGN = (
        "item=3&qty=2",
        "search for c++ tutorials",
        "50% off -- limited time",
    )

    NOISE_CEILING = 10.0

    def test_ordinary_text_does_not_score_at_all(self) -> None:
        for payload in self.SILENT:
            with self.subTest(payload=payload):
                result = scan(payload, payload)
                self.assertEqual(
                    result.anomaly_score, 0.0,
                    f"{payload!r} matched {[m.rule_id for m in result.matches]}",
                )

    def test_a_search_query_containing_select_stays_silent(self) -> None:
        # The briefing's own canonical false positive, called out in §5.
        self.assertEqual(scan("SELECT * FROM menu").match_count, 0)

    def test_punctuation_heavy_text_stays_under_the_noise_ceiling(self) -> None:
        for payload in self.NOISY_BUT_BENIGN:
            with self.subTest(payload=payload):
                score = scan(payload, payload).anomaly_score
                self.assertLessEqual(
                    score, self.NOISE_CEILING,
                    f"{payload!r} scored {score}, into attack territory",
                )

    def test_attacks_and_benign_text_are_cleanly_separated(self) -> None:
        # The property a Milestone C threshold needs in order to exist. Not a
        # threshold itself — this asserts there is room for one.
        attacks = [
            scan(p, p).anomaly_score for p in (
                "' OR '1'='1",
                "id=1 UNION SELECT password FROM users--",
                "<script>alert(1)</script>",
                "../../../../etc/passwd",
                ";cat /etc/passwd",
            )
        ]
        benign = [
            scan(p, p).anomaly_score
            for p in self.SILENT + self.NOISY_BUT_BENIGN
        ]
        self.assertGreater(
            min(attacks), max(benign) * 2,
            f"separation collapsed: attacks {attacks}, benign {benign}",
        )


class TestScanMechanics(unittest.TestCase):
    def test_empty_payload_scores_nothing(self) -> None:
        for payload in ("", "   "):
            with self.subTest(payload=repr(payload)):
                result = scan(payload, payload)
                self.assertEqual(result.match_count, 0)
                self.assertEqual(result.anomaly_score, 0.0)

    def test_matches_are_ordered_heaviest_first(self) -> None:
        result = scan("../../../../etc/passwd")
        weights = [m.severity_weight for m in result.matches]
        self.assertEqual(weights, sorted(weights, reverse=True))

    def test_stored_matches_are_capped_but_the_score_is_not(self) -> None:
        result = scan("../../../../etc/passwd' OR 1=1 <script>;cat /etc/passwd")
        self.assertLessEqual(len(result.matches), MAX_STORED_MATCHES)
        self.assertGreaterEqual(result.match_count, len(result.matches))

    def test_pl1_score_never_exceeds_the_total(self) -> None:
        for payload in ("' OR '1'='1", "<script>alert(1)</script>", "../../etc/passwd"):
            with self.subTest(payload=payload):
                result = scan(payload)
                self.assertLessEqual(result.anomaly_score_pl1, result.anomaly_score)

    def test_paranoia_level_1_alone_would_miss_basic_sqli(self) -> None:
        # The reason the headline score counts every paranoia level, against the
        # obvious instinct to follow CRS's own PL1 default. A live CRS sees the
        # whole HTTP request and has its chained rules; this module sees one
        # payload fragment and dropped the chains, so PL1 coverage is thinner
        # here than it is there.
        #
        # `' OR '1'='1` — the most canonical SQLi payload there is — scores
        # nothing at PL1 and 30+ across all levels. Anyone "fixing" this module
        # to respect the CRS default would silence it on the first payload an
        # analyst tests it with.
        result = scan("' OR '1'='1")
        self.assertEqual(result.anomaly_score_pl1, 0.0)
        self.assertGreater(result.anomaly_score, 30.0)

    def test_matches_record_where_they_came_from(self) -> None:
        result = scan("' OR '1'='1")
        for match in result.matches:
            with self.subTest(rule_id=match.rule_id):
                self.assertIn(match.matched_on, ("raw", "decoded"))

    def test_oversized_payload_is_truncated_not_refused(self) -> None:
        from core.crs_matcher import MAX_SCAN_LEN

        result = scan("a" * (MAX_SCAN_LEN + 100))
        self.assertTrue(result.truncated)

    def test_matches_carry_their_extraction_caveats(self) -> None:
        # A rule matched with an unperformed transformation saw text its author
        # did not expect. That has to travel with the match.
        result = scan("<script>alert(1)</script>")
        self.assertTrue(result.matches)
        for match in result.matches:
            self.assertIsInstance(match.dropped_conditions, list)
            self.assertIsInstance(match.unsupported_transforms, list)


if __name__ == "__main__":
    unittest.main()
