"""Tests for the NVD / CISA KEV / MITRE provider and the layering it restores."""
import re
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from config import Settings
from providers import nvd


def _response(payload, status=200):
    resp = Mock()
    resp.status_code = status
    resp.json.return_value = payload
    resp.raise_for_status.return_value = None
    return resp


def _nvd_item(cve_id="CVE-2021-44228", description="Apache Log4j2 flaw.") -> dict:
    return {"cve": {
        "id": cve_id,
        "published": "2021-12-10T10:15:09.143",
        "descriptions": [{"lang": "en", "value": description}],
        "metrics": {"cvssMetricV31": [
            {"type": "Primary", "cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}
        ]},
    }}


class TestProviderLayerIsStreamlitFree(unittest.TestCase):
    """The point of moving this module out of `ui/`: no UI dependency in the data layer."""

    def test_no_provider_imports_streamlit(self):
        offenders = []
        for path in Path("providers").glob("*.py"):
            source = path.read_text(encoding="utf-8")
            if re.search(r"^\s*(import streamlit|from streamlit)", source, re.M):
                offenders.append(path.name)
        self.assertEqual(offenders, [])

    def test_nvd_module_exposes_the_names_app_and_panel_need(self):
        for name in ("fetch_cve_by_id", "fetch_kev_catalog", "fetch_nvd_page",
                     "fetch_mitre_cve", "fetch_mitre_records", "parse_nvd_item",
                     "is_common_app", "time_window"):
            with self.subTest(name=name):
                self.assertTrue(callable(getattr(nvd, name)))


class TestFetchCveById(unittest.TestCase):
    def test_malformed_id_is_rejected_without_any_request(self):
        for bad in ("", "CVE-21-44228", "'; DROP TABLE--", "notacve", None):
            with self.subTest(cve_id=bad), patch.object(nvd, "get_session") as session:
                with self.assertLogs("providers.nvd", level="WARNING"):
                    self.assertIsNone(nvd.fetch_cve_by_id(bad))
                session.assert_not_called()

    def test_supplied_kev_catalog_is_used_and_not_refetched(self):
        """The caller holds a cached catalog; refetching it per lookup is the waste."""
        catalog = {"CVE-2021-44228": {
            "shortDescription": "Log4Shell.", "requiredAction": "Patch.",
            "knownRansomwareCampaignUse": "Known",
        }}
        with patch.object(nvd, "get_session") as session, \
             patch.object(nvd, "fetch_kev_catalog") as kev:
            session.return_value.get.return_value = _response(
                {"vulnerabilities": [_nvd_item()]}
            )
            result = nvd.fetch_cve_by_id("CVE-2021-44228", kev_catalog=catalog)

        kev.assert_not_called()
        self.assertEqual(result["description"], "Log4Shell.")
        self.assertTrue(result["isKev"])
        self.assertTrue(result["isRansomware"])

    def test_catalog_is_fetched_when_not_supplied(self):
        with patch.object(nvd, "get_session") as session, \
             patch.object(nvd, "fetch_kev_catalog", return_value={}) as kev:
            session.return_value.get.return_value = _response(
                {"vulnerabilities": [_nvd_item()]}
            )
            nvd.fetch_cve_by_id("CVE-2021-44228")

        kev.assert_called_once()

    def test_unknown_cve_returns_none(self):
        with patch.object(nvd, "get_session") as session:
            session.return_value.get.return_value = _response({"vulnerabilities": []})
            self.assertIsNone(nvd.fetch_cve_by_id("CVE-1999-0001", kev_catalog={}))

    def test_request_failure_returns_none_not_a_clean_record(self):
        """A failed lookup must read as 'not retrieved', never as 'not exploited'."""
        with patch.object(nvd, "get_session") as session:
            session.return_value.get.side_effect = nvd.requests.RequestException("down")
            with self.assertLogs("providers.nvd", level="ERROR"):
                self.assertIsNone(nvd.fetch_cve_by_id("CVE-2021-44228", kev_catalog={}))

    def test_identifier_is_normalised_before_the_request(self):
        with patch.object(nvd, "get_session") as session:
            session.return_value.get.return_value = _response({"vulnerabilities": []})
            nvd.fetch_cve_by_id("  cve-2021-44228  ", kev_catalog={})

        self.assertEqual(
            session.return_value.get.call_args[1]["params"]["cveId"], "CVE-2021-44228"
        )


class TestApiKeyHandling(unittest.TestCase):
    def test_api_key_is_sent_when_configured(self):
        with patch.object(nvd, "get_session") as session:
            session.return_value.get.return_value = _response({})
            nvd.fetch_nvd_page("s", "e", 0, Settings(cve_nvd_key="secret"))

        self.assertEqual(
            session.return_value.get.call_args[1]["headers"]["apiKey"], "secret"
        )

    def test_no_api_key_header_when_unset(self):
        with patch.object(nvd, "get_session") as session:
            session.return_value.get.return_value = _response({})
            nvd.fetch_nvd_page("s", "e", 0, Settings())

        self.assertNotIn("apiKey", session.return_value.get.call_args[1]["headers"])

    def test_page_failure_is_reported_as_an_error_not_an_empty_window(self):
        with patch.object(nvd, "get_session") as session:
            session.return_value.get.side_effect = nvd.requests.RequestException("429")
            with self.assertLogs("providers.nvd", level="ERROR"):
                page = nvd.fetch_nvd_page("s", "e", 0, Settings())

        self.assertTrue(page["error"])
        self.assertEqual(page["items"], [])


class TestKevCatalog(unittest.TestCase):
    def test_catalog_is_keyed_by_cve_id(self):
        with patch.object(nvd, "get_session") as session:
            session.return_value.get.return_value = _response({"vulnerabilities": [
                {"cveID": "CVE-2021-44228", "vendorProject": "Apache",
                 "knownRansomwareCampaignUse": "Known"},
            ]})
            catalog = nvd.fetch_kev_catalog()

        self.assertEqual(catalog["CVE-2021-44228"]["vendorProject"], "Apache")

    def test_failure_yields_an_empty_catalog(self):
        with patch.object(nvd, "get_session") as session:
            session.return_value.get.side_effect = nvd.requests.RequestException("down")
            with self.assertLogs("providers.nvd", level="WARNING"):
                self.assertEqual(nvd.fetch_kev_catalog(), {})


class TestMitreRecords(unittest.TestCase):
    def test_ids_are_deduplicated_and_blanks_dropped(self):
        seen = []

        def _fetch(cve_id):
            seen.append(cve_id)
            return {"id": cve_id}

        out = nvd.fetch_mitre_records(
            ["CVE-1", "CVE-1", "", "CVE-2", None], fetch=_fetch
        )

        self.assertEqual(sorted(seen), ["CVE-1", "CVE-2"])
        self.assertEqual(set(out), {"CVE-1", "CVE-2"})

    def test_empty_input_makes_no_calls(self):
        self.assertEqual(nvd.fetch_mitre_records([], fetch=Mock()), {})
        self.assertEqual(nvd.fetch_mitre_records(["", None], fetch=Mock()), {})

    def test_one_failing_record_does_not_lose_the_others(self):
        def _fetch(cve_id):
            if cve_id == "CVE-2":
                raise RuntimeError("boom")
            return {"id": cve_id}

        with self.assertLogs("core.http", level="ERROR"):
            out = nvd.fetch_mitre_records(["CVE-1", "CVE-2", "CVE-3"], fetch=_fetch)

        self.assertEqual(set(out), {"CVE-1", "CVE-3"})


class TestTimeWindow(unittest.TestCase):
    def test_window_is_ordered_and_nvd_formatted(self):
        start, end = nvd.time_window(3)
        pattern = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.000"
        self.assertRegex(start, pattern)
        self.assertRegex(end, pattern)
        self.assertLess(start, end)


if __name__ == "__main__":
    unittest.main()
