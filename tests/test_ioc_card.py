"""Tests for the per-provider units extracted from render_ioc_cards.

render_ioc_cards() used to be a single ~1500-line function with no tests at
all: 11 "has data" checks, 11 provider tab bodies, and two small closures were
private to it and unreachable from outside. They are now module-level
functions. These tests cover:

  - each `_x_has_data` predicate directly (fast, no Streamlit needed);
  - the two small HTML helpers directly;
  - the *dispatcher* in render_ioc_cards — that it activates the right tabs
    and calls each `_render_x_tab` with the right arguments. This is the
    exact class of bug the extraction risked (a tab wired to the wrong
    provider dict, or `ioc.type`/`ioc.value` not reaching the function that
    now takes them as plain parameters) — caught here by mocking each
    `_render_x_tab` and asserting on its call.

The tab bodies' own HTML output is not re-tested here: that content moved
verbatim (verified byte-for-byte against the pre-refactor output during the
extraction) and is exercised by hand when the cards are used in the app.
"""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock, call, patch

from ioc.parser import IOC
from ui.components import ioc_card


# ---------------------------------------------------------------------------
# Has-data predicates
# ---------------------------------------------------------------------------

class TestHasDataPredicates(unittest.TestCase):
    def test_virustotal(self):
        self.assertFalse(ioc_card._virustotal_has_data({}))
        self.assertFalse(ioc_card._virustotal_has_data(None))
        self.assertTrue(ioc_card._virustotal_has_data({"stats": {"malicious": 0}}))
        self.assertTrue(ioc_card._virustotal_has_data({"attributes": {"asn": 1}}))
        self.assertTrue(ioc_card._virustotal_has_data({"analysis_results": {"e": {}}}))

    def test_urlscan(self):
        self.assertFalse(ioc_card._urlscan_has_data({}))
        for key in ("uuid", "result", "page", "task"):
            with self.subTest(key=key):
                self.assertTrue(ioc_card._urlscan_has_data({key: {"x": 1}}))

    def test_abuseipdb(self):
        self.assertFalse(ioc_card._abuseipdb_has_data({}))
        self.assertFalse(ioc_card._abuseipdb_has_data({"error": "boom", "abuseConfidenceScore": 90}))
        self.assertTrue(ioc_card._abuseipdb_has_data({"abuseConfidenceScore": 0}))
        self.assertTrue(ioc_card._abuseipdb_has_data({"totalReports": 0}))

    def test_threatfox(self):
        self.assertFalse(ioc_card._threatfox_has_data({}))
        self.assertFalse(ioc_card._threatfox_has_data({"query_status": "ok", "data": []}))
        self.assertFalse(ioc_card._threatfox_has_data({"query_status": "no_result", "data": [1]}))
        self.assertTrue(ioc_card._threatfox_has_data({"query_status": "ok", "data": [1]}))

    def test_malwarebazaar(self):
        self.assertFalse(ioc_card._malwarebazaar_has_data({}))
        self.assertFalse(ioc_card._malwarebazaar_has_data({"query_status": "hash_not_found"}))
        self.assertTrue(ioc_card._malwarebazaar_has_data({"query_status": "ok", "data": [1]}))

    def test_shodan(self):
        self.assertFalse(ioc_card._shodan_has_data({}))
        self.assertFalse(ioc_card._shodan_has_data({"error": "x", "summary": {"a": 1}}))
        self.assertTrue(ioc_card._shodan_has_data({"summary": {"a": 1}}))
        self.assertTrue(ioc_card._shodan_has_data({"ports": [22]}))
        self.assertTrue(ioc_card._shodan_has_data({"queriedIp": "1.2.3.4"}))

    def test_dnsdumpster(self):
        self.assertFalse(ioc_card._dnsdumpster_has_data({}))
        self.assertFalse(ioc_card._dnsdumpster_has_data({"error": "x", "soc_summary": {"a": 1}}))
        self.assertTrue(ioc_card._dnsdumpster_has_data({"soc_summary": {"a": 1}}))

    def test_hybrid_analysis_rejects_bare_status_messages(self):
        """The three known 'nothing to show' messages must not count as data."""
        for message in (
            "Not supported by Hybrid Analysis API",
            "Hybrid Analysis does not analyze email indicators.",
            "No results found",
        ):
            with self.subTest(message=message):
                self.assertFalse(
                    ioc_card._hybrid_analysis_has_data({"message": message, "verdict": "malicious"})
                )

    def test_hybrid_analysis_accepts_any_real_finding(self):
        self.assertTrue(ioc_card._hybrid_analysis_has_data({"verdict": "malicious"}))
        self.assertTrue(ioc_card._hybrid_analysis_has_data({"threat_score": 10}))
        self.assertTrue(ioc_card._hybrid_analysis_has_data({"mitre_attack": ["T1059"]}))
        self.assertFalse(ioc_card._hybrid_analysis_has_data({}))

    def test_mxtoolbox(self):
        self.assertFalse(ioc_card._mxtoolbox_has_data({}))
        self.assertFalse(ioc_card._mxtoolbox_has_data({"error": "x", "lookups": {"a": 1}}))
        self.assertTrue(ioc_card._mxtoolbox_has_data({"lookups": {"spf": {}}}))

    def test_whoxy_is_gated_by_ioc_type(self):
        domain_data = {"whois": {"registrar": "x"}}
        keyword_data = {"reverse_whois": {"total_results": 1}}
        self.assertTrue(ioc_card._whoxy_has_data(domain_data, "domain"))
        self.assertTrue(ioc_card._whoxy_has_data(domain_data, "url"))
        self.assertFalse(ioc_card._whoxy_has_data(domain_data, "whois"))
        self.assertTrue(ioc_card._whoxy_has_data(keyword_data, "whois"))
        self.assertFalse(ioc_card._whoxy_has_data(keyword_data, "domain"))

    def test_ransomware_live(self):
        self.assertFalse(ioc_card._ransomware_live_has_data({}))
        self.assertFalse(ioc_card._ransomware_live_has_data({"count": 0}))
        self.assertFalse(ioc_card._ransomware_live_has_data({"error": "x", "count": 1}))
        self.assertTrue(ioc_card._ransomware_live_has_data({"count": 1}))


# ---------------------------------------------------------------------------
# Small HTML helpers
# ---------------------------------------------------------------------------

class TestUrlscanScreenshotUrl(unittest.TestCase):
    def test_empty_input(self):
        self.assertEqual(ioc_card._urlscan_screenshot_url({}), "")

    def test_top_level_screenshot_url_wins(self):
        us = {"screenshotURL": "https://a", "task": {"screenshotURL": "https://b"}}
        self.assertEqual(ioc_card._urlscan_screenshot_url(us), "https://a")

    def test_falls_back_to_top_level_screenshot(self):
        self.assertEqual(ioc_card._urlscan_screenshot_url({"screenshot": "https://s"}), "https://s")

    def test_falls_back_to_task_screenshot_url(self):
        us = {"task": {"screenshotURL": "https://t"}}
        self.assertEqual(ioc_card._urlscan_screenshot_url(us), "https://t")

    def test_falls_back_to_task_screenshot(self):
        us = {"task": {"screenshot": "https://t2"}}
        self.assertEqual(ioc_card._urlscan_screenshot_url(us), "https://t2")

    def test_no_screenshot_anywhere(self):
        self.assertEqual(ioc_card._urlscan_screenshot_url({"task": {}}), "")


class TestVerdictBadge(unittest.TestCase):
    def test_known_verdicts_get_their_color_and_text(self):
        # The badge echoes the caller's exact casing rather than normalizing it.
        self.assertIn("🔴", ioc_card._verdict_badge("Malicious"))
        self.assertIn("Malicious", ioc_card._verdict_badge("Malicious"))
        self.assertIn("🟠", ioc_card._verdict_badge("suspicious"))
        self.assertIn("🟢", ioc_card._verdict_badge("benign"))
        self.assertIn("🟢", ioc_card._verdict_badge("no threat"))

    def test_unknown_or_empty_falls_back_to_grey(self):
        self.assertIn("⚪", ioc_card._verdict_badge(""))
        self.assertIn("Unknown", ioc_card._verdict_badge(""))
        self.assertIn("⚪", ioc_card._verdict_badge("something else"))

    def test_matching_is_case_insensitive(self):
        self.assertIn("🔴", ioc_card._verdict_badge("MALICIOUS"))


# ---------------------------------------------------------------------------
# render_ioc_cards() dispatch — the seam the extraction actually risked
# ---------------------------------------------------------------------------

def _fake_st():
    """Just enough of the Streamlit surface for render_ioc_cards to run."""
    st = MagicMock()
    st.expander.return_value.__enter__ = MagicMock(return_value=None)
    st.expander.return_value.__exit__ = MagicMock(return_value=False)
    st.tabs.side_effect = lambda names: [MagicMock() for _ in names]
    return st


class TestRenderDispatch(unittest.TestCase):
    """Patches every _render_x_tab so only the dispatcher in
    render_ioc_cards is under test — not the 1000+ lines of tab bodies.
    """

    RENDER_FN_NAMES = (
        "_render_virustotal_tab", "_render_urlscan_tab", "_render_abuseipdb_tab",
        "_render_threatfox_tab", "_render_malwarebazaar_tab", "_render_shodan_tab",
        "_render_dnsdumpster_tab", "_render_hybrid_analysis_tab",
        "_render_mxtoolbox_tab", "_render_whoxy_tab", "_render_ransomware_live_tab",
    )

    def setUp(self):
        self._patches = [patch.object(ioc_card, "st", _fake_st())]
        self._patches += [patch.object(ioc_card, "components", MagicMock())]
        self._patches += [patch.object(ioc_card, "fetch_geo_ip_api", return_value={})]
        self._patches += [patch.object(ioc_card, "fetch_nominatim", return_value={})]
        self._patches += [patch.object(ioc_card, "build_osm_map_html", return_value="")]
        self._patches += [patch.object(ioc_card, name) for name in self.RENDER_FN_NAMES]
        self.mocks = {p.attribute if hasattr(p, "attribute") else None: p.start() for p in self._patches}
        self.addCleanup(lambda: [p.stop() for p in self._patches])
        # Re-fetch named mocks by attribute for readability in assertions.
        self.render = {name: getattr(ioc_card, name) for name in self.RENDER_FN_NAMES}

    def _run(self, run_results: dict) -> None:
        ioc_card.render_ioc_cards(run_results)

    def _base_results(self, items) -> dict:
        empty = {}
        return {
            "items": items, "vt": empty, "urlscan": empty, "abuse": empty,
            "tf": empty, "mb": empty, "shodan": empty, "dnsd": empty, "ha": empty,
            "mxtoolbox": empty, "whoxy": empty, "ransomware_live": empty, "rows": [],
        }

    def test_no_data_calls_no_render_function(self):
        self._run(self._base_results([IOC(value="1.2.3.4", type="ip")]))
        for name, mock in self.render.items():
            with self.subTest(fn=name):
                mock.assert_not_called()

    def test_virustotal_receives_the_dict_and_ioc_type(self):
        results = self._base_results([IOC(value="1.2.3.4", type="ip")])
        results["vt"] = {"1.2.3.4": {"stats": {"malicious": 1}}}
        self._run(results)

        self.render["_render_virustotal_tab"].assert_called_once_with(
            {"stats": {"malicious": 1}}, "ip"
        )

    def test_threatfox_receives_the_dict_and_ioc_value(self):
        results = self._base_results([IOC(value="evil.test", type="domain")])
        results["tf"] = {"evil.test": {"query_status": "ok", "data": [{}]}}
        self._run(results)

        self.render["_render_threatfox_tab"].assert_called_once_with(
            {"query_status": "ok", "data": [{}]}, "evil.test"
        )

    def test_mxtoolbox_receives_the_dict_and_ioc_value(self):
        results = self._base_results([IOC(value="1.2.3.4", type="ip")])
        results["mxtoolbox"] = {"1.2.3.4": {"lookups": {"spf": {}}}}
        self._run(results)

        self.render["_render_mxtoolbox_tab"].assert_called_once_with(
            {"lookups": {"spf": {}}}, "1.2.3.4"
        )

    def test_whoxy_receives_the_dict_ioc_type_and_ioc_value(self):
        results = self._base_results([IOC(value="acme", type="whois")])
        results["whoxy"] = {"acme": {"reverse_whois": {"total_results": 1}}}
        self._run(results)

        self.render["_render_whoxy_tab"].assert_called_once_with(
            {"reverse_whois": {"total_results": 1}}, "whois", "acme"
        )

    def test_ransomware_live_receives_the_dict_and_ioc_value(self):
        results = self._base_results([IOC(value="evil.test", type="domain")])
        results["ransomware_live"] = {"evil.test": {"count": 1}}
        self._run(results)

        self.render["_render_ransomware_live_tab"].assert_called_once_with(
            {"count": 1}, "evil.test"
        )

    def test_shodan_receives_provider_dicts_and_a_geo_context(self):
        results = self._base_results([IOC(value="1.2.3.4", type="ip")])
        results["shodan"] = {"1.2.3.4": {"ports": [22]}}
        results["abuse"] = {"1.2.3.4": {"abuseConfidenceScore": 10}}
        self._run(results)

        self.render["_render_shodan_tab"].assert_called_once()
        sh_arg, ab_arg, vt_attrs_arg, geo_arg = self.render["_render_shodan_tab"].call_args[0]
        self.assertEqual(sh_arg, {"ports": [22]})
        self.assertEqual(ab_arg, {"abuseConfidenceScore": 10})
        self.assertEqual(vt_attrs_arg, {})
        self.assertIsInstance(geo_arg, ioc_card._GeoContext)
        self.assertFalse(geo_arg.has_coords)

    def test_only_providers_with_data_are_dispatched(self):
        """A provider with an empty dict for this IOC must not be called."""
        results = self._base_results([IOC(value="1.2.3.4", type="ip")])
        results["vt"] = {"1.2.3.4": {"stats": {"malicious": 1}}}
        # abuse/tf/etc. stay empty.
        self._run(results)

        self.render["_render_virustotal_tab"].assert_called_once()
        for name in self.RENDER_FN_NAMES:
            if name != "_render_virustotal_tab":
                with self.subTest(fn=name):
                    self.render[name].assert_not_called()

    def test_multiple_iocs_each_get_their_own_dispatch(self):
        items = [IOC(value="1.1.1.1", type="ip"), IOC(value="2.2.2.2", type="ip")]
        results = self._base_results(items)
        results["vt"] = {
            "1.1.1.1": {"stats": {"malicious": 1}},
            "2.2.2.2": {"stats": {"malicious": 2}},
        }
        self._run(results)

        self.render["_render_virustotal_tab"].assert_has_calls([
            call({"stats": {"malicious": 1}}, "ip"),
            call({"stats": {"malicious": 2}}, "ip"),
        ])
        self.assertEqual(self.render["_render_virustotal_tab"].call_count, 2)

    def test_missing_optional_provider_keys_do_not_crash(self):
        """run_results.get(...) providers (shodan/dnsd/ha/...) may be absent."""
        minimal = {
            "items": [IOC(value="1.2.3.4", type="ip")],
            "vt": {}, "urlscan": {}, "abuse": {}, "tf": {}, "mb": {},
        }
        self._run(minimal)  # must not raise


if __name__ == "__main__":
    unittest.main()
