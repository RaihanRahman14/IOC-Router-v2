"""Tests for VirusTotal URL lookup across inferred http:// / https:// schemes."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from config import Settings
from ioc.parser import parse_iocs
from providers.virustotal import _url_id, vt_lookup_batch


HTTP_URL = "http://example.com/login"
HTTPS_URL = "https://example.com/login"

_REPORT = {
    "data": {
        "id": "abc123",
        "type": "url",
        "attributes": {"last_analysis_stats": {"malicious": 8, "harmless": 86}},
    }
}


def _fake_vt_get(report_for: str | None):
    """Build a _vt_get stand-in that only holds a report for one URL form.

    Args:
        report_for: The URL whose /urls/<id> path returns a report, or None.

    Returns:
        A callable matching the _vt_get signature.
    """
    wanted = f"/urls/{_url_id(report_for)}" if report_for else None

    def _get(path: str, key: str, params: dict | None = None) -> dict:
        if wanted and path == wanted:
            return _REPORT
        return {}

    return _get


class TestVirusTotalUrlScheme(unittest.TestCase):
    def _lookup(self, raw: str, report_for: str | None) -> dict:
        items = parse_iocs(raw)
        with patch("providers.virustotal._vt_get", side_effect=_fake_vt_get(report_for)):
            out = vt_lookup_batch(items, Settings(vt_key="k"))
        return out[items[0].value]

    def test_falls_back_to_https_when_scheme_inferred(self):
        row = self._lookup("example.com/login", report_for=HTTPS_URL)
        self.assertEqual(row["stats"], {"malicious": 8, "harmless": 86})
        self.assertEqual(row["matched_url"], HTTPS_URL)

    def test_http_hit_wins_and_is_recorded(self):
        row = self._lookup("example.com/login", report_for=HTTP_URL)
        self.assertEqual(row["stats"], {"malicious": 8, "harmless": 86})
        self.assertEqual(row["matched_url"], HTTP_URL)

    def test_no_report_anywhere_yields_empty_stats_and_no_matched_url(self):
        row = self._lookup("example.com/login", report_for=None)
        self.assertEqual(row["stats"], {})
        self.assertNotIn("matched_url", row)

    def test_explicit_url_is_not_widened_to_other_scheme(self):
        # Analyst typed https://; a report existing only under http:// must not leak in.
        row = self._lookup(HTTPS_URL, report_for=HTTP_URL)
        self.assertEqual(row["stats"], {})
        self.assertNotIn("matched_url", row)

    def test_explicit_url_still_matches_its_own_scheme(self):
        row = self._lookup(HTTPS_URL, report_for=HTTPS_URL)
        self.assertEqual(row["matched_url"], HTTPS_URL)

    def test_domain_lookup_unaffected(self):
        items = parse_iocs("example.com")
        with patch("providers.virustotal._vt_get", side_effect=_fake_vt_get(None)) as m:
            vt_lookup_batch(items, Settings(vt_key="k"))
        self.assertTrue(
            any(call.args[0] == "/domains/example.com" for call in m.call_args_list)
        )


if __name__ == "__main__":
    unittest.main()
