import unittest
from unittest.mock import Mock, patch

from providers.shodan import enrichWithInternetDB, scoreRisk, summarize_shodan_internetdb


class TestShodanInternetDB(unittest.TestCase):
    @patch("providers.shodan.get_session")
    def test_high_vulns_and_risky_port(self, mock_session):
        mock_get = mock_session.return_value.get
        response = Mock()
        response.status_code = 200
        response.json.return_value = {
            "ports": [22, 80],
            "vulns": ["CVE-2025-1234"],
            "cpes": ["cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*"],
            "hostnames": ["srv1.example.com"],
            "tags": [],
        }
        mock_get.return_value = response

        items = enrichWithInternetDB(["1.2.3.4"])
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["risk_summary"]["risk_level"], "HIGH")

    @patch("providers.shodan.get_session")
    def test_medium_risky_port_without_vulns(self, mock_session):
        mock_get = mock_session.return_value.get
        response = Mock()
        response.status_code = 200
        response.json.return_value = {
            "ports": [3389],
            "vulns": [],
            "cpes": [],
            "hostnames": [],
            "tags": [],
        }
        mock_get.return_value = response

        items = enrichWithInternetDB(["5.6.7.8"])
        self.assertEqual(items[0]["risk_summary"]["risk_level"], "MEDIUM")

    @patch("providers.shodan.get_session")
    def test_low_common_ports_without_vulns(self, mock_session):
        mock_get = mock_session.return_value.get
        response = Mock()
        response.status_code = 200
        response.json.return_value = {
            "ports": [80, 443],
            "vulns": [],
            "cpes": [],
            "hostnames": ["example.com"],
            "tags": [],
        }
        mock_get.return_value = response

        items = enrichWithInternetDB(["9.9.9.9"])
        self.assertEqual(items[0]["risk_summary"]["risk_level"], "LOW")

    @patch("providers.shodan.get_session")
    def test_unknown_for_404(self, mock_session):
        mock_get = mock_session.return_value.get
        response = Mock()
        response.status_code = 404
        mock_get.return_value = response

        items = enrichWithInternetDB(["10.10.10.10"])
        self.assertEqual(items[0]["risk_summary"]["risk_level"], "UNKNOWN")

    def test_score_risk_reasons_max_three(self):
        item = {
            "ports": [22, 23, 3389, 445, 5900, 3306, 5432, 27017, 6379, 9200],
            "vulns": ["CVE-1"],
            "tags": ["compromised", "malware"],
            "cpes": [],
            "hostnames": [],
        }
        risk = scoreRisk(item)
        self.assertLessEqual(len(risk.get("reasons", [])), 3)

    @patch("providers.shodan.get_session")
    def test_summary_output_shape(self, mock_session):
        mock_get = mock_session.return_value.get
        response = Mock()
        response.status_code = 200
        response.json.return_value = {
            "ports": [80, 443],
            "vulns": [],
            "cpes": ["cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*"],
            "hostnames": ["www.example.com"],
            "tags": [],
        }
        mock_get.return_value = response

        summary = summarize_shodan_internetdb(
            {"input_type": "domain", "value": "example.com", "resolved_ips": ["1.2.3.4"]}
        )
        self.assertIn("input", summary)
        self.assertIn("shodan", summary)
        self.assertIn("recommended_action", summary)
        self.assertEqual(summary["shodan"].get("source"), "internetdb")
        self.assertIn("results", summary["shodan"])
        self.assertIn("rollup", summary["shodan"])


if __name__ == "__main__":
    unittest.main()
