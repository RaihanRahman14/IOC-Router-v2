"""Tests for schemeless-URL detection and per-provider scheme variants."""
from __future__ import annotations

import unittest

from core.cache import _inflate
from ioc.parser import IOC, parse_iocs, scheme_variants


def _first(raw: str) -> IOC:
    items = parse_iocs(raw)
    assert items, f"no IOC parsed from {raw!r}"
    return items[0]


class TestSchemelessUrlDetection(unittest.TestCase):
    def test_host_with_path_becomes_url(self):
        ioc = _first("example.com/login")
        self.assertEqual(ioc.type, "url")
        self.assertEqual(ioc.value, "http://example.com/login")
        self.assertTrue(ioc.scheme_inferred)

    def test_host_with_port_and_path(self):
        ioc = _first("evil.net:8443/panel")
        self.assertEqual(ioc.type, "url")
        self.assertEqual(ioc.value, "http://evil.net:8443/panel")

    def test_ipv4_host_with_path(self):
        ioc = _first("192.168.1.1/admin")
        self.assertEqual(ioc.type, "url")
        self.assertEqual(ioc.value, "http://192.168.1.1/admin")

    def test_query_and_fragment_delimiters(self):
        self.assertEqual(_first("example.com?id=1").type, "url")
        self.assertEqual(_first("example.com#frag").type, "url")

    def test_host_case_normalised_but_path_preserved(self):
        ioc = _first("Example.COM/Payload.EXE")
        self.assertEqual(ioc.value, "http://example.com/Payload.EXE")

    def test_bare_domain_still_domain(self):
        ioc = _first("example.com")
        self.assertEqual(ioc.type, "domain")
        self.assertEqual(ioc.value, "example.com")
        self.assertFalse(ioc.scheme_inferred)

    def test_explicit_url_not_marked_inferred(self):
        ioc = _first("https://example.com/login")
        self.assertEqual(ioc.type, "url")
        self.assertEqual(ioc.value, "https://example.com/login")
        self.assertFalse(ioc.scheme_inferred)

    def test_ip_and_hash_precedence_unchanged(self):
        self.assertEqual(_first("8.8.8.8").type, "ip")
        self.assertEqual(_first("44d88612fea8a8f36de82e1278abb02f").type, "hash")

    def test_email_and_keyword_not_swallowed(self):
        self.assertEqual(_first("user@example.com").type, "email")
        self.assertEqual(_first("acmecorp").type, "whois")

    def test_still_rejected(self):
        for raw in ("ftp://example.com/file", "example.com.", "/just/a/path", "??"):
            self.assertEqual(parse_iocs(raw), [], f"{raw!r} should not parse")

    def test_allowed_types_filter_covers_schemeless(self):
        items = parse_iocs(
            "example.com/login", auto_detect=False, allowed_types={"ip"}
        )
        self.assertEqual(items, [])


class TestSchemeVariants(unittest.TestCase):
    def test_inferred_url_yields_both_schemes_http_first(self):
        ioc = _first("example.com/login")
        self.assertEqual(
            scheme_variants(ioc),
            ["http://example.com/login", "https://example.com/login"],
        )

    def test_https_first_ordering_for_submission(self):
        ioc = _first("example.com/login")
        self.assertEqual(
            scheme_variants(ioc, https_first=True),
            ["https://example.com/login", "http://example.com/login"],
        )

    def test_explicit_url_is_not_widened(self):
        ioc = _first("https://example.com/login")
        self.assertEqual(scheme_variants(ioc), ["https://example.com/login"])

    def test_non_url_types_return_raw_value(self):
        self.assertEqual(scheme_variants(_first("example.com")), ["example.com"])
        self.assertEqual(scheme_variants(IOC(value="", type="url")), [])


class TestCacheInflate(unittest.TestCase):
    def test_three_tuple_round_trip(self):
        payload = [(i.value, i.type, i.scheme_inferred) for i in parse_iocs("example.com/login")]
        self.assertEqual(_inflate(payload), parse_iocs("example.com/login"))

    def test_legacy_two_tuple_still_accepted(self):
        [ioc] = _inflate([("example.com", "domain")])
        self.assertEqual(
            (ioc.value, ioc.type, ioc.scheme_inferred),
            ("example.com", "domain", False),
        )


if __name__ == "__main__":
    unittest.main()
