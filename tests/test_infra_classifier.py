"""Tests for core.infra_classifier and the infra-derived threat flags."""
from __future__ import annotations

import ipaddress
import unittest
from unittest.mock import patch

from core import infra_classifier as ic
from ioc.flags.base import _flag_from_infra
from ioc.flags.shodan import _flags_shodan
from ioc.flags.virustotal import _flags_virustotal


class TestClassify(unittest.TestCase):
    def test_bp_cloudflare_dns(self) -> None:
        res = ic.classify(asn=13335, ip="1.1.1.1")
        self.assertIsNotNone(res)
        self.assertEqual(res["category"], "BP")
        self.assertEqual(res["severity"], "MEDIUM")

    def test_bp_quad9(self) -> None:
        res = ic.classify(asn="AS19281", ip="9.9.9.9")
        self.assertEqual(res["category"], "BP")

    def test_fp_digitalocean(self) -> None:
        res = ic.classify(asn=14061, ip="138.68.1.1")
        self.assertEqual(res["category"], "FP")
        self.assertEqual(res["severity"], "LOW")

    def test_fp_aws_ec2_default(self) -> None:
        # AS16509 with an IP not in CloudFront ranges should fall to FP (EC2).
        with patch.object(ic, "is_cloudfront_ip", return_value=False):
            res = ic.classify(asn=16509, ip="3.5.140.1")
        self.assertEqual(res["category"], "FP")
        self.assertIn("EC2", res["provider"])

    def test_bp_aws_cloudfront_refinement(self) -> None:
        with patch.object(ic, "is_cloudfront_ip", return_value=True):
            res = ic.classify(asn=16509, ip="13.32.0.1")
        self.assertEqual(res["category"], "BP")
        self.assertIn("CloudFront", res["provider"])

    def test_bp_google_public_dns_refinement(self) -> None:
        res = ic.classify(asn=15169, ip="8.8.8.8")
        self.assertEqual(res["category"], "BP")
        self.assertIn("Public DNS", res["provider"])

    def test_fp_google_compute_default(self) -> None:
        res = ic.classify(asn=15169, ip="35.190.1.1")
        self.assertEqual(res["category"], "FP")

    def test_high_risk_by_asn(self) -> None:
        res = ic.classify(asn=200593, ip="45.135.232.1")
        self.assertEqual(res["category"], "HIGH_RISK")
        self.assertEqual(res["severity"], "HIGH")

    def test_high_risk_by_org_hint(self) -> None:
        res = ic.classify(asn=999999, org="AEZA Group LLC")
        self.assertEqual(res["category"], "HIGH_RISK")
        self.assertIn("AEZA", res["provider"])

    def test_unknown_returns_none(self) -> None:
        res = ic.classify(asn=4242, org="Some Random ISP")
        self.assertIsNone(res)

    def test_normalize_asn_with_prefix(self) -> None:
        self.assertEqual(ic._normalize_asn("AS13335"), 13335)
        self.assertEqual(ic._normalize_asn("13335"), 13335)
        self.assertEqual(ic._normalize_asn(13335), 13335)
        self.assertIsNone(ic._normalize_asn("not-an-asn"))


class TestCloudFrontCache(unittest.TestCase):
    def test_is_cloudfront_ip_membership(self) -> None:
        # Inject a fake CloudFront prefix and verify membership check.
        with ic._aws_cache_lock:
            ic._aws_cache["fetched_at"] = 9e12  # far future so no refresh
            ic._aws_cache["cloudfront_v4"] = [ipaddress.ip_network("13.32.0.0/15")]
            ic._aws_cache["cloudfront_v6"] = []
        try:
            self.assertTrue(ic.is_cloudfront_ip("13.32.0.1"))
            self.assertFalse(ic.is_cloudfront_ip("3.5.140.1"))
            self.assertFalse(ic.is_cloudfront_ip("not-an-ip"))
        finally:
            with ic._aws_cache_lock:
                ic._aws_cache["fetched_at"] = 0.0
                ic._aws_cache["cloudfront_v4"] = []


class TestFlagFromInfra(unittest.TestCase):
    def test_bp_flag_is_medium(self) -> None:
        infra = {"category": "BP", "severity": "MEDIUM", "provider": "Cloudflare",
                 "reason": "Cloudflare DNS / CDN (anycast)", "asn": 13335}
        flag = _flag_from_infra(infra, "Shodan")
        self.assertIsNotNone(flag)
        self.assertEqual(flag["severity"], "MEDIUM")
        self.assertIn("Cloudflare", flag["label"])
        self.assertIn("AS13335", flag["detail"])

    def test_fp_flag_is_low(self) -> None:
        infra = {"category": "FP", "severity": "LOW", "provider": "DigitalOcean",
                 "reason": "Shared VPS", "asn": 14061}
        flag = _flag_from_infra(infra, "VirusTotal")
        self.assertEqual(flag["severity"], "LOW")

    def test_high_risk_flag_is_high(self) -> None:
        infra = {"category": "HIGH_RISK", "severity": "HIGH", "provider": "Proton66",
                 "reason": "BPH", "asn": 200593}
        flag = _flag_from_infra(infra, "Shodan")
        self.assertEqual(flag["severity"], "HIGH")
        self.assertEqual(flag["id"], "INFRA_HIGH_RISK_SHODAN")

    def test_none_returns_none(self) -> None:
        self.assertIsNone(_flag_from_infra(None, "Shodan"))
        self.assertIsNone(_flag_from_infra({"category": "?"}, "Shodan"))


class TestProviderFlagIntegration(unittest.TestCase):
    def test_shodan_flag_emitted_from_classification(self) -> None:
        sh = {
            "ports": [80],
            "vulns": [],
            "tags": [],
            "hostnames": [],
            "infra_classification": {
                "category": "BP", "severity": "MEDIUM",
                "provider": "Cloudflare", "reason": "anycast",
                "asn": 13335,
            },
        }
        flags = _flags_shodan(sh)
        ids = [f["id"] for f in flags]
        self.assertIn("INFRA_BENIGN_SHODAN", ids)

    def test_virustotal_flag_emitted_from_classification(self) -> None:
        vt = {
            "stats": {"malicious": 0, "harmless": 70},
            "attributes": {},
            "analysis_results": {},
            "infra_classification": {
                "category": "HIGH_RISK", "severity": "HIGH",
                "provider": "Proton66", "reason": "BPH",
                "asn": 200593,
            },
        }
        flags = _flags_virustotal(vt)
        ids = [f["id"] for f in flags]
        self.assertIn("INFRA_HIGH_RISK_VIRUSTOTAL", ids)


if __name__ == "__main__":
    unittest.main()
