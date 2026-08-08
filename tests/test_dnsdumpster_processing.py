import unittest

from providers.dnsdumpster import _build_soc_summary


# Real DNSDumpster API response shape (see providers/dnsdumpster.py module
# docstring): per-record-type keys, each host carrying a nested "ips" list.
SAMPLE_RESPONSE = {
    "a": [
        {
            "host": "vpn.example.com",
            "ips": [
                {
                    "ip": "1.2.3.4",
                    "asn": "123",
                    "asn_name": "Example Telecom",
                    "asn_range": "1.2.3.0/24",
                    "country": "Indonesia",
                    "country_code": "ID",
                    "ptr": "vpn.example.com",
                    "banners": {"http": {"server": "nginx", "title": "VPN Portal"}},
                }
            ],
        },
        {
            "host": "www.example.com",
            "ips": [
                {
                    "ip": "5.6.7.8",
                    "asn": "AS456",
                    "asn_name": "Cloud Hosting Inc",
                    "asn_range": "5.6.7.0/24",
                    "country": "Singapore",
                    "country_code": "SG",
                    "banners": {},
                }
            ],
        },
        {
            "host": "a1b2c3d4e5f6g7h8.example.com",
            "ips": [{"ip": "9.8.7.6", "asn": "789", "asn_name": "Cloud Hosting Inc"}],
        },
    ],
    "cname": [{"host": "dev.example.com", "target": "dev-app.herokudns.com"}],
    "mx": [
        {
            "host": "mail.example.com",
            "priority": 10,
            "ips": [
                {
                    "ip": "10.20.30.40",
                    "asn": "999",
                    "asn_name": "Mail Provider",
                    "country": "Singapore",
                }
            ],
        }
    ],
    "ns": [{"host": "ns1.cloudflare.com"}],
    "txt": [{"host": "example.com", "entries": ["v=spf1 include:_spf.google.com ~all"]}],
    "total_a_recs": 3,
}


class TestDnsdumpsterProcessing(unittest.TestCase):
    def test_a_records_flattened_with_asn_normalised(self):
        out = _build_soc_summary("example.com", SAMPLE_RESPONSE)

        rows = {row["host"]: row for row in out["a_records"]}
        self.assertIn("vpn.example.com", rows)
        vpn = rows["vpn.example.com"]
        self.assertEqual(vpn["ip"], "1.2.3.4")
        # Bare ASN numbers are normalised to "AS<n>"; already-prefixed ones kept.
        self.assertEqual(vpn["asn"], "AS123")
        self.assertEqual(rows["www.example.com"]["asn"], "AS456")
        self.assertEqual(vpn["owner"], "Example Telecom")
        self.assertEqual(vpn["netblock"], "1.2.3.0/24")
        self.assertEqual(vpn["country_code"], "ID")
        self.assertEqual(out["total_a_recs"], 3)

    def test_open_services_from_banners(self):
        out = _build_soc_summary("example.com", SAMPLE_RESPONSE)

        self.assertEqual(len(out["open_services"]), 1)
        service = out["open_services"][0]
        self.assertEqual(service["host"], "vpn.example.com")
        self.assertEqual(service["ip"], "1.2.3.4")
        self.assertEqual(service["banner"], "HTTP:nginx (VPN Portal)")

    def test_cname_and_mail_dns_infra(self):
        out = _build_soc_summary("example.com", SAMPLE_RESPONSE)

        self.assertEqual(out["cname_map"], {"dev.example.com": "dev-app.herokudns.com"})

        mail = out["mail_dns_infra"]
        self.assertEqual(mail["mx"], ["mail.example.com"])
        self.assertEqual(mail["mx_details"][0]["priority"], 10)
        self.assertEqual(mail["mx_details"][0]["asn"], "AS999")
        self.assertEqual(mail["ns"], ["ns1.cloudflare.com"])
        self.assertIn("v=spf1 include:_spf.google.com ~all", mail["txt_highlights"])

    def test_red_flags_detected(self):
        out = _build_soc_summary("example.com", SAMPLE_RESPONSE)
        flags = out["red_flags"]

        self.assertIn("Sensitive host pattern: vpn.example.com", flags)
        self.assertIn("Residential/ISP owner: vpn.example.com (Example Telecom)", flags)
        self.assertIn(
            "Potential random/generated hostname: a1b2c3d4e5f6g7h8.example.com", flags
        )
        self.assertIn(
            "CNAME takeover risk: dev.example.com → dev-app.herokudns.com", flags
        )

    def test_network_enrichment_deduplicated(self):
        # Same host/ip/asn repeated across two A entries must collapse to one row.
        data = {
            "a": [
                {
                    "host": "www.example.com",
                    "ips": [{"ip": "5.6.7.8", "asn": "456", "asn_name": "Cloud Hosting Inc"}],
                },
                {
                    "host": "www.example.com",
                    "ips": [{"ip": "5.6.7.8", "asn": "456", "asn_name": "Cloud Hosting Inc"}],
                },
            ]
        }

        out = _build_soc_summary("example.com", data)

        self.assertEqual(len(out["network_enrichment"]), 1)
        self.assertEqual(
            out["network_enrichment"][0],
            {
                "host": "www.example.com",
                "ip": "5.6.7.8",
                "asn": "AS456",
                "network_owner": "Cloud Hosting Inc",
                "netblock": "",
                "ptr": "",
                "country": "",
                "country_code": "",
            },
        )

    def test_soc_summary_handles_empty(self):
        out = _build_soc_summary("example.com", {})

        self.assertEqual(out["domain"], "example.com")
        self.assertEqual(out["a_records"], [])
        self.assertEqual(out["cname_map"], {})
        self.assertEqual(out["open_services"], [])
        self.assertEqual(out["network_enrichment"], [])
        self.assertEqual(out["red_flags"], [])
        self.assertEqual(out["mail_dns_infra"]["mx"], [])
        self.assertEqual(out["total_a_recs"], 0)

    def test_soc_summary_handles_non_dict_payload(self):
        out = _build_soc_summary("example.com", "not-a-dict")

        self.assertEqual(out["a_records"], [])
        self.assertEqual(out["red_flags"], [])


if __name__ == "__main__":
    unittest.main()
