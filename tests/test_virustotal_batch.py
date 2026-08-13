"""Tests for the two-phase VirusTotal batch lookup."""
import threading
import time
import unittest
from unittest.mock import patch

from config import Settings
from ioc.parser import IOC
from providers.virustotal import _url_id, vt_lookup_batch


KEY = Settings(vt_key="k")


def _object(**attrs) -> dict:
    """A VT response carrying a real object."""
    return {"data": {"id": "obj-1", "type": "x", "attributes": attrs}}


class _RecordingVtGet:
    """Stand-in for _vt_get that records paths and serves canned responses."""

    def __init__(self, responses: dict[str, dict] | None = None, delay: float = 0.0):
        self.responses = responses or {}
        self.delay = delay
        self.paths: list[str] = []
        self.threads: set[int] = set()
        self._lock = threading.Lock()

    def __call__(self, path: str, key: str, params: dict | None = None) -> dict:
        with self._lock:
            self.paths.append(path)
            self.threads.add(threading.get_ident())
        if self.delay:
            time.sleep(self.delay)
        return self.responses.get(path, {})

    def paths_ending(self, suffix: str) -> list[str]:
        return [p for p in self.paths if p.endswith(suffix)]


class TestEnrichmentGating(unittest.TestCase):
    def test_known_object_gets_its_enrichment_calls(self):
        fake = _RecordingVtGet({
            "/ip_addresses/8.8.8.8": _object(last_analysis_stats={"malicious": 2}),
            "/ip_addresses/8.8.8.8/comments": {"data": [{"c": 1}]},
            "/ip_addresses/8.8.8.8/votes": {"data": [{"v": 1}]},
            "/ip_addresses/8.8.8.8/resolutions": {"data": [{"r": 1}]},
        })
        with patch("providers.virustotal._vt_get", side_effect=fake):
            out = vt_lookup_batch([IOC(value="8.8.8.8", type="ip")], KEY)

        row = out["8.8.8.8"]
        self.assertEqual(row["stats"], {"malicious": 2})
        self.assertEqual(row["comments"], [{"c": 1}])
        self.assertEqual(row["votes"], [{"v": 1}])
        self.assertEqual(row["resolutions"], [{"r": 1}])

    def test_unknown_object_skips_enrichment_entirely(self):
        """VT holds nothing for this IP, so follow-up calls would burn quota.

        Their responses were discarded before this change, so skipping them
        leaves the result dict identical and only removes wasted requests.
        """
        fake = _RecordingVtGet()
        with patch("providers.virustotal._vt_get", side_effect=fake):
            out = vt_lookup_batch([IOC(value="1.2.3.4", type="ip")], KEY)

        self.assertEqual(fake.paths, ["/ip_addresses/1.2.3.4"])
        self.assertEqual(out["1.2.3.4"]["stats"], {})
        for absent in ("comments", "votes", "resolutions", "behavior"):
            with self.subTest(field=absent):
                self.assertNotIn(absent, out["1.2.3.4"])

    def test_hash_gets_behaviour_summary_not_resolutions(self):
        h = "44d88612fea8a8f36de82e1278abb02f"
        fake = _RecordingVtGet({
            f"/files/{h}": _object(last_analysis_stats={"malicious": 9}),
            f"/files/{h}/behaviour_summary": {"data": {"attributes": {"calls": 3}}},
        })
        with patch("providers.virustotal._vt_get", side_effect=fake):
            out = vt_lookup_batch([IOC(value=h, type="hash")], KEY)

        self.assertEqual(out[h]["behavior"], {"calls": 3})
        self.assertEqual(fake.paths_ending("/resolutions"), [])
        self.assertEqual(len(fake.paths_ending("/behaviour_summary")), 1)

    def test_empty_enrichment_response_adds_no_field(self):
        fake = _RecordingVtGet({
            "/domains/evil.test": _object(last_analysis_stats={"malicious": 1}),
            "/domains/evil.test/comments": {"data": []},
        })
        with patch("providers.virustotal._vt_get", side_effect=fake):
            out = vt_lookup_batch([IOC(value="evil.test", type="domain")], KEY)

        self.assertNotIn("comments", out["evil.test"])


class TestBatchShape(unittest.TestCase):
    def test_unsupported_types_yield_empty_results_without_calls(self):
        fake = _RecordingVtGet()
        items = [IOC(value="a@b.test", type="email"), IOC(value="acme", type="whois")]
        with patch("providers.virustotal._vt_get", side_effect=fake):
            out = vt_lookup_batch(items, KEY)

        self.assertEqual(fake.paths, [])
        self.assertEqual(out, {"a@b.test": {}, "acme": {}})

    def test_missing_key_short_circuits(self):
        fake = _RecordingVtGet()
        with patch("providers.virustotal._vt_get", side_effect=fake):
            out = vt_lookup_batch([IOC(value="8.8.8.8", type="ip")], Settings())

        self.assertEqual(fake.paths, [])
        self.assertEqual(out, {"8.8.8.8": {}})

    def test_every_input_value_is_present_in_the_output(self):
        items = [
            IOC(value="8.8.8.8", type="ip"),
            IOC(value="a@b.test", type="email"),
            IOC(value="evil.test", type="domain"),
        ]
        with patch("providers.virustotal._vt_get", side_effect=_RecordingVtGet()):
            out = vt_lookup_batch(items, KEY)

        self.assertEqual(set(out), {i.value for i in items})

    def test_url_scheme_fallback_still_records_the_matched_form(self):
        matched = "https://example.com/login"
        fake = _RecordingVtGet({f"/urls/{_url_id(matched)}": _object()})
        ioc = IOC(value="http://example.com/login", type="url", scheme_inferred=True)
        with patch("providers.virustotal._vt_get", side_effect=fake):
            out = vt_lookup_batch([ioc], KEY)

        self.assertEqual(out[ioc.value]["matched_url"], matched)


class TestFailureIsolation(unittest.TestCase):
    def test_one_exploding_lookup_leaves_the_others_intact(self):
        def _boom(path: str, key: str, params: dict | None = None) -> dict:
            if path == "/ip_addresses/1.1.1.1":
                raise RuntimeError("boom")
            return _object(last_analysis_stats={"malicious": 5})

        items = [IOC(value="1.1.1.1", type="ip"), IOC(value="8.8.8.8", type="ip")]
        with patch("providers.virustotal._vt_get", side_effect=_boom), \
             self.assertLogs("core.http", level="ERROR"):
            out = vt_lookup_batch(items, KEY)

        self.assertEqual(out["1.1.1.1"], {})
        self.assertEqual(out["8.8.8.8"]["stats"], {"malicious": 5})


class TestConcurrency(unittest.TestCase):
    def test_primary_lookups_overlap(self):
        """Four 120ms IOCs must finish well inside their 480ms serial cost."""
        delay = 0.12
        items = [IOC(value=f"10.0.0.{n}", type="ip") for n in range(4)]
        fake = _RecordingVtGet(delay=delay)

        with patch("providers.virustotal._vt_get", side_effect=fake):
            start = time.perf_counter()
            vt_lookup_batch(items, KEY)
            elapsed = time.perf_counter() - start

        self.assertLess(elapsed, delay * len(items))
        self.assertGreater(len(fake.threads), 1)

    def test_enrichment_calls_overlap_across_iocs(self):
        delay = 0.1
        responses = {
            f"/ip_addresses/10.0.0.{n}": _object(last_analysis_stats={"malicious": 1})
            for n in range(3)
        }
        fake = _RecordingVtGet(responses, delay=delay)
        items = [IOC(value=f"10.0.0.{n}", type="ip") for n in range(3)]

        with patch("providers.virustotal._vt_get", side_effect=fake):
            start = time.perf_counter()
            vt_lookup_batch(items, KEY)
            elapsed = time.perf_counter() - start

        # 3 primaries + 9 enrichment calls = 12 calls; serial would be 1.2s.
        self.assertEqual(len(fake.paths), 12)
        self.assertLess(elapsed, delay * 12)


if __name__ == "__main__":
    unittest.main()
