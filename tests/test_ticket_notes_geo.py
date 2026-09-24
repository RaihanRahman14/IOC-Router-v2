"""Ticket notes: ISP / country fallback Shodan -> AbuseIPDB -> VirusTotal."""
from __future__ import annotations

from unittest.mock import patch

from ui.components import output_renderer

IP = "203.0.113.7"


def _ticket_notes(
    *,
    geo: dict,
    abuse: dict | None = None,
    vt: dict | None = None,
    shodan: dict | None = None,
) -> list[str]:
    """Render ticket notes for one IP and return its lines."""
    run_results = {
        "summary": {},
        "rows": [{"Type": "ip", "Artifact": IP, "Verdict": "Unknown"}],
        "vt": {IP: vt} if vt is not None else {},
        "urlscan": {},
        "abuse": {IP: abuse} if abuse is not None else {},
        "tf": {},
        "mb": {},
        "shodan": {IP: shodan} if shodan is not None else {},
        "provider_flags": {"abuse": True, "vt": True, "tf": True, "shodan": True},
        "allowed_by_type": {"ip": ["abuse", "vt", "tf", "shodan"]},
    }
    with patch.object(output_renderer, "st") as fake_st, \
         patch.object(output_renderer, "fetch_geo_ip_api", return_value=geo):
        output_renderer.render_results_output("Ticket Notes", run_results)
    return fake_st.code.call_args[0][0].splitlines()


def _line(lines: list[str], prefix: str) -> str:
    return next(l for l in lines if l.startswith(prefix))


_EMPTY_SHODAN = {"ports": [], "vulns": [], "tags": [], "queriedIp": IP,
                 "risk_summary": {"risk_level": "UNKNOWN"}}


def test_shodan_without_scan_data_still_shows_isp_country() -> None:
    lines = _ticket_notes(
        geo={"isp": "Example ISP", "country": "Indonesia"},
        shodan=_EMPTY_SHODAN,
        abuse={"abuseConfidenceScore": 0, "isp": "Abuse ISP", "countryCode": "ID"},
    )
    assert _line(lines, "Shodan:") == "Shodan: Example ISP, Indonesia"
    # Shodan already carries it, so AbuseIPDB is not duplicated.
    assert "Abuse ISP" not in _line(lines, "AbuseIPDB:")


def test_shodan_with_scan_data_appends_isp_country() -> None:
    shodan = dict(_EMPTY_SHODAN, ports=[443], risk_summary={"risk_level": "LOW"})
    lines = _ticket_notes(geo={"isp": "Example ISP", "country": "Indonesia"}, shodan=shodan)
    assert _line(lines, "Shodan:") == "Shodan: LOW, 1 port(s), Example ISP, Indonesia"


def test_falls_back_to_abuseipdb() -> None:
    lines = _ticket_notes(
        geo={},
        shodan=_EMPTY_SHODAN,
        abuse={"abuseConfidenceScore": 5, "totalReports": 1, "isp": "Abuse ISP", "countryCode": "SG"},
        vt={"stats": {}, "attributes": {"as_owner": "VT Owner", "country": "US"}},
    )
    assert _line(lines, "Shodan:") == "Shodan: No data"
    assert _line(lines, "AbuseIPDB:").endswith(", Abuse ISP, SG")
    assert _line(lines, "VirusTotal:") == "VirusTotal: No data"


def test_falls_back_to_virustotal() -> None:
    lines = _ticket_notes(
        geo={},
        shodan=_EMPTY_SHODAN,
        abuse={"error": "boom"},
        vt={"stats": {}, "attributes": {"as_owner": "VT Owner", "country": "US"}},
    )
    assert _line(lines, "AbuseIPDB:") == "AbuseIPDB: No data"
    assert _line(lines, "VirusTotal:") == "VirusTotal: VT Owner, US"


def test_fields_fall_back_independently() -> None:
    lines = _ticket_notes(
        geo={"isp": "Example ISP"},
        shodan=_EMPTY_SHODAN,
        abuse={"abuseConfidenceScore": 0, "countryCode": "ID"},
    )
    assert _line(lines, "Shodan:") == "Shodan: Example ISP"
    assert _line(lines, "AbuseIPDB:").endswith(", ID")


def test_no_geo_anywhere_keeps_no_data() -> None:
    lines = _ticket_notes(geo={}, shodan=_EMPTY_SHODAN)
    assert _line(lines, "Shodan:") == "Shodan: No data"
