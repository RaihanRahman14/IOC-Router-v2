"""Unit tests for providers.path_prober."""
from __future__ import annotations

import unittest

from providers.path_prober import (
    classify_status,
    clean_paths,
    normalize_domain,
    split_paths,
)


class TestClassifyStatus(unittest.TestCase):
    """Verify the WAF/exists classification rule.

    Rule: 200-399 and 400-403 → confirmed; 404-599 → not_confirmed.
    """

    def test_2xx_all_confirmed(self):
        for code in (200, 201, 204, 226, 299):
            self.assertEqual(classify_status(code), "confirmed")

    def test_3xx_all_confirmed(self):
        for code in (300, 301, 302, 304, 307, 308, 399):
            self.assertEqual(classify_status(code), "confirmed")

    def test_400_through_403_confirmed(self):
        for code in (400, 401, 402, 403):
            self.assertEqual(classify_status(code), "confirmed")

    def test_404_and_above_not_confirmed(self):
        for code in (404, 405, 410, 418, 429, 451):
            self.assertEqual(classify_status(code), "not_confirmed")

    def test_5xx_not_confirmed(self):
        for code in (500, 502, 503, 504, 599):
            self.assertEqual(classify_status(code), "not_confirmed")


class TestCleanPaths(unittest.TestCase):
    """Aggressive cleaner — strips quotes, brackets, commas."""

    def test_strips_quotes_and_brackets(self):
        raw = '["/admin"], \'/login\''
        self.assertEqual(clean_paths(raw), ["/admin", "/login"])

    def test_prepends_leading_slash(self):
        self.assertEqual(clean_paths("admin\nlogin"), ["/admin", "/login"])

    def test_dedupes_preserves_order(self):
        raw = "/a\n/b\n/a\n/c\n/b"
        self.assertEqual(clean_paths(raw), ["/a", "/b", "/c"])

    def test_empty_input_returns_empty(self):
        self.assertEqual(clean_paths(""), [])
        self.assertEqual(clean_paths("   \n  \n"), [])

    def test_mixed_newline_and_comma(self):
        raw = '/x, /y\n"/z"'
        self.assertEqual(clean_paths(raw), ["/x", "/y", "/z"])

    def test_matches_original_tkinter_sample(self):
        raw = (
            '["/.env"]\n'
            '["/public/.env"]\n'
            '"/xampp/.env"\n'
            "'/www/.env'\n"
        )
        self.assertEqual(
            clean_paths(raw),
            ["/.env", "/public/.env", "/xampp/.env", "/www/.env"],
        )


class TestSplitPaths(unittest.TestCase):
    """Conservative splitter — newline only, no character stripping."""

    def test_newline_only_split(self):
        raw = "/a, b\n/c"
        self.assertEqual(split_paths(raw), ["/a, b", "/c"])

    def test_preserves_quotes(self):
        raw = '"/quoted"\n/plain'
        self.assertEqual(split_paths(raw), ['/"/quoted"', "/plain"])

    def test_dedupes(self):
        raw = "/a\n/a\n/b"
        self.assertEqual(split_paths(raw), ["/a", "/b"])


class TestNormalizeDomain(unittest.TestCase):
    """Domain normalization — scheme + trailing-slash handling."""

    def test_adds_https_when_missing(self):
        self.assertEqual(normalize_domain("example.com"), "https://example.com")

    def test_preserves_existing_scheme(self):
        self.assertEqual(
            normalize_domain("http://example.com"), "http://example.com"
        )
        self.assertEqual(
            normalize_domain("https://example.com"), "https://example.com"
        )

    def test_strips_trailing_slash(self):
        self.assertEqual(
            normalize_domain("https://example.com/"), "https://example.com"
        )

    def test_empty_input(self):
        self.assertEqual(normalize_domain(""), "")
        self.assertEqual(normalize_domain("   "), "")


if __name__ == "__main__":
    unittest.main()
