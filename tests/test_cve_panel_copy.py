"""Tests for the New CVE panel copy formatter and NVD item parser."""
from __future__ import annotations

import sys
import unittest
from unittest.mock import MagicMock


from providers.nvd import parse_nvd_item

# Streamlit imports happen at module load time; stub the package and the
# `streamlit.components.v1` submodule so the *panel* module can be imported
# without a running Streamlit context. The parser above needs no stub — it
# lives in the provider layer, which is Streamlit-free by design.
sys.modules.setdefault("streamlit", MagicMock())
sys.modules.setdefault("streamlit.components", MagicMock())
sys.modules.setdefault("streamlit.components.v1", MagicMock())

from ui.components.cve_panel import (  # noqa: E402
    CVE_RECORD_URL,
    _format_selected_text,
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
        parsed = parse_nvd_item(SAMPLE_ITEMS[0], kev_data={}, mitre_data={})
        self.assertIn("descriptionFull", parsed)
        self.assertTrue(parsed["descriptionFull"].startswith("Malicious code was discovered"))
        # No char truncation: the card clamps visually via CSS, so the display
        # description is the same full text as descriptionFull.
        self.assertEqual(parsed["description"], parsed["descriptionFull"])

    def test_short_description_not_truncated(self) -> None:
        parsed = parse_nvd_item(SAMPLE_ITEMS[2], kev_data={}, mitre_data={})
        self.assertEqual(
            parsed["descriptionFull"],
            "Microsoft Outlook Elevation of Privilege Vulnerability.",
        )
        self.assertEqual(parsed["description"], parsed["descriptionFull"])

    def test_score_and_severity_extracted(self) -> None:
        parsed = parse_nvd_item(SAMPLE_ITEMS[1], kev_data={}, mitre_data={})
        self.assertEqual(parsed["score"], 10.0)
        self.assertEqual(parsed["severity"], "CRITICAL")

    def test_mitre_vendor_product_takes_precedence(self) -> None:
        """MITRE cveawg `affected[]` wins over the description keyword fallback."""
        mitre_data = {
            "containers": {
                "cna": {
                    "affected": [
                        {
                            "vendor": "Microsoft",
                            "product": "Outlook",
                            "versions": [
                                {"status": "affected", "lessThan": "16.0.16227.20280"}
                            ],
                        }
                    ],
                    "impacts": [
                        {
                            "capecId": "CAPEC-275",
                            "descriptions": [{"value": "DNS Rebinding"}],
                        }
                    ],
                }
            }
        }
        parsed = parse_nvd_item(SAMPLE_ITEMS[2], kev_data={}, mitre_data=mitre_data)
        self.assertEqual(parsed["vendorProject"], "Microsoft")
        self.assertEqual(parsed["product"], "Outlook")
        self.assertEqual(parsed["versionRange"], "< 16.0.16227.20280")
        self.assertEqual(parsed["attackPattern"], "DNS Rebinding (CAPEC-275)")

    def test_kev_short_description_preferred(self) -> None:
        """CISA KEV shortDescription replaces the longer NVD description."""
        kev_data = {
            "CVE-2021-44228": {
                "vendorProject": "Apache",
                "product": "Log4j2",
                "shortDescription": "Apache Log4j2 contains a JNDI injection vulnerability.",
                "requiredAction": "Apply updates per vendor instructions.",
                "knownRansomwareCampaignUse": "Known",
            }
        }
        parsed = parse_nvd_item(SAMPLE_ITEMS[1], kev_data=kev_data, mitre_data={})
        self.assertEqual(
            parsed["descriptionFull"],
            "Apache Log4j2 contains a JNDI injection vulnerability.",
        )
        self.assertTrue(parsed["isKev"])
        self.assertTrue(parsed["isRansomware"])
        self.assertEqual(parsed["requiredAction"], "Apply updates per vendor instructions.")


class TestFormatSelectedText(unittest.TestCase):
    def test_single_cve_format(self) -> None:
        parsed = parse_nvd_item(SAMPLE_ITEMS[2], kev_data={}, mitre_data={})
        out = _format_selected_text([parsed])

        url = CVE_RECORD_URL.format(cve_id="CVE-2023-23397")
        # WhatsApp-style bold header on its own line, followed by a blank line.
        self.assertIn("*CVE-2023-23397*\n\n", out)
        self.assertIn("*Severity*: 9.8 (CRITICAL)", out)
        self.assertIn("*Affected*: ", out)
        self.assertIn("*Time published*: ", out)
        self.assertIn("WIB", out)
        self.assertIn(f"*Reference*: {url}", out)
        self.assertIn("*Description*:\n", out)
        self.assertIn("Microsoft Outlook Elevation of Privilege Vulnerability.", out)
        # Must NOT contain markdown-style links or markdown-double-asterisk bold.
        self.assertNotIn("](", out)
        self.assertNotIn("**", out)

    def test_kev_tags_and_required_action_block(self) -> None:
        kev_entry = {
            "cveID": "CVE-2021-44228",
            "score": 10.0,
            "severity": "CRITICAL",
            "cwe": "CWE-917",
            "datePublished": "2021-12-10",
            "timePublished": "17:15",
            "descriptionFull": "Apache Log4j2 JNDI injection.",
            "requiredAction": "Apply updates per vendor instructions.",
            "isKev": True,
            "isRansomware": True,
        }
        out = _format_selected_text([kev_entry])
        self.assertIn("*CVE-2021-44228* ⚠️ KEV · RANSOMWARE\n", out)
        self.assertIn("*Severity*: 10.0 (CRITICAL) · CWE-917", out)
        self.assertIn("*Required Action*:\nApply updates per vendor instructions.", out)

    def test_multiple_cves_separated_by_blank_line(self) -> None:
        parsed = [
            parse_nvd_item(it, kev_data={}, mitre_data={}) for it in SAMPLE_ITEMS
        ]
        out = _format_selected_text(parsed)

        # Each CVE appears in the output, in the order provided.
        idx_xz = out.index("CVE-2024-3094")
        idx_log4j = out.index("CVE-2021-44228")
        idx_outlook = out.index("CVE-2023-23397")
        self.assertLess(idx_xz, idx_log4j)
        self.assertLess(idx_log4j, idx_outlook)

        # Each CVE block has three internal blank lines (after the bold header,
        # before *Description*, and before *Reference*) — the *Required Action*
        # block is absent here because no KEV data was supplied. Consecutive
        # blocks are joined by one more blank line each.
        blank_lines_per_block = 3
        self.assertEqual(
            out.count("\n\n"),
            len(SAMPLE_ITEMS) * blank_lines_per_block + (len(SAMPLE_ITEMS) - 1),
        )

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
        # Opsi B layout: fields without data render as "-".
        self.assertIn("*Severity*: -", out)
        self.assertIn("*Affected*: -", out)
        self.assertIn("*Time published*: 2026-06-02 10:00 WIB", out)
        self.assertIn(
            "*Reference*: https://www.cve.org/CVERecord?id=CVE-9999-0001", out
        )
        # No KEV requiredAction → the whole block is omitted, not left empty.
        self.assertNotIn("*Required Action*", out)


if __name__ == "__main__":
    unittest.main()
