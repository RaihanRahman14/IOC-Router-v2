"""Tests for the New CVE panel copy formatter and NVD item parser."""
from __future__ import annotations

import sys
import unittest
from unittest.mock import MagicMock


# Streamlit imports happen at module load time; stub the package and the
# `streamlit.components.v1` submodule so the panel module can be imported
# without a running Streamlit context.
sys.modules.setdefault("streamlit", MagicMock())
sys.modules.setdefault("streamlit.components", MagicMock())
sys.modules.setdefault("streamlit.components.v1", MagicMock())

from ui.components.cve_panel import (  # noqa: E402
    CVE_RECORD_URL,
    _format_selected_text,
    _parse_nvd_item,
)


def _sample_nvd_item(
    cve_id: str,
    description: str,
    published: str,
    score: float,
    severity: str,
) -> dict:
    """Build a minimal NVD-shaped item dict for tests."""
    return {
        "cve": {
            "id": cve_id,
            "published": published,
            "descriptions": [{"lang": "en", "value": description}],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "type": "Primary",
                        "cvssData": {"baseScore": score, "baseSeverity": severity},
                    }
                ]
            },
            "configurations": [],
        }
    }


# Three real-shaped NVD items (CVE IDs/descriptions adapted from public NVD data).
SAMPLE_ITEMS = [
    _sample_nvd_item(
        cve_id="CVE-2024-3094",
        description=(
            "Malicious code was discovered in the upstream tarballs of xz, starting "
            "with version 5.6.0. Through a series of complex obfuscations, the liblzma "
            "build process extracts a prebuilt object file from a disguised test file "
            "existing in the source code, which is then used to modify specific "
            "functions in the liblzma code."
        ),
        published="2024-03-29T17:15:21.150",
        score=10.0,
        severity="CRITICAL",
    ),
    _sample_nvd_item(
        cve_id="CVE-2021-44228",
        description=(
            "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases "
            "2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log "
            "messages, and parameters do not protect against attacker-controlled "
            "LDAP and other JNDI related endpoints."
        ),
        published="2021-12-10T10:15:09.143",
        score=10.0,
        severity="CRITICAL",
    ),
    _sample_nvd_item(
        cve_id="CVE-2023-23397",
        description="Microsoft Outlook Elevation of Privilege Vulnerability.",
        published="2023-03-14T17:15:14.000",
        score=9.8,
        severity="CRITICAL",
    ),
]


class TestParseNvdItem(unittest.TestCase):
    def test_keeps_full_description(self) -> None:
        parsed = _parse_nvd_item(SAMPLE_ITEMS[0], kev_data={})
        self.assertIn("descriptionFull", parsed)
        self.assertTrue(parsed["descriptionFull"].startswith("Malicious code was discovered"))
        # Truncated display description tops out around 120 chars.
        self.assertLessEqual(len(parsed["description"]), 120)

    def test_short_description_not_truncated(self) -> None:
        parsed = _parse_nvd_item(SAMPLE_ITEMS[2], kev_data={})
        self.assertEqual(
            parsed["descriptionFull"],
            "Microsoft Outlook Elevation of Privilege Vulnerability.",
        )
        self.assertEqual(parsed["description"], parsed["descriptionFull"])

    def test_score_and_severity_extracted(self) -> None:
        parsed = _parse_nvd_item(SAMPLE_ITEMS[1], kev_data={})
        self.assertEqual(parsed["score"], 10.0)
        self.assertEqual(parsed["severity"], "CRITICAL")


class TestFormatSelectedText(unittest.TestCase):
    def test_single_cve_format(self) -> None:
        parsed = _parse_nvd_item(SAMPLE_ITEMS[2], kev_data={})
        out = _format_selected_text([parsed])

        url = CVE_RECORD_URL.format(cve_id="CVE-2023-23397")
        self.assertIn(f"[CVE-2023-23397]({url})", out)
        self.assertIn("CVE Metrics: 9.8 (CRITICAL)", out)
        self.assertIn("Time published: ", out)
        self.assertIn("WIB", out)
        self.assertIn("Descriptions:\n", out)
        self.assertIn("Microsoft Outlook Elevation of Privilege Vulnerability.", out)

    def test_multiple_cves_separated_by_blank_line(self) -> None:
        parsed = [_parse_nvd_item(it, kev_data={}) for it in SAMPLE_ITEMS]
        out = _format_selected_text(parsed)

        # Each CVE appears in the output, in the order provided.
        idx_xz = out.index("CVE-2024-3094")
        idx_log4j = out.index("CVE-2021-44228")
        idx_outlook = out.index("CVE-2023-23397")
        self.assertLess(idx_xz, idx_log4j)
        self.assertLess(idx_log4j, idx_outlook)

        # Exactly one blank line (== "\n\n") between consecutive CVE blocks.
        self.assertEqual(out.count("\n\n"), len(SAMPLE_ITEMS) - 1)

    def test_empty_selection(self) -> None:
        self.assertEqual(_format_selected_text([]), "")

    def test_handles_missing_score(self) -> None:
        partial = {
            "cveID": "CVE-9999-0001",
            "score": None,
            "severity": "N/A",
            "datePublished": "2026-06-02",
            "timePublished": "10:00",
            "descriptionFull": "Reserved.",
        }
        out = _format_selected_text([partial])
        self.assertIn("CVE Metrics: N/A (N/A)", out)
        self.assertIn("Time published: 2026-06-02 10:00 WIB", out)


if __name__ == "__main__":
    unittest.main()
