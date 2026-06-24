"""Settings loader for API keys."""
from __future__ import annotations

import os
from dataclasses import dataclass

try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None


@dataclass
class Settings:
    vt_key: str | None = None
    urlscan_key: str | None = None
    hybrid_analysis_key: str | None = None
    abuse_key: str | None = None
    shodan_key: str | None = None
    threatfox_key: str | None = None
    malwarebazaar_key: str | None = None
    dnsdumpster_key: str | None = None
    gemini_key: str | None = None
    gemini_key_backup: str | None = None
    gemini_model: str | None = None
    gemini_api_version: str | None = None
    groq_key: str | None = None
    mxtoolbox_key: str | None = None
    whoxy_key: str | None = None
    ransomware_live_key: str | None = None
    cve_nvd_key: str | None = None

    @classmethod
    def from_env(cls) -> "Settings":
        if load_dotenv:
            load_dotenv(override=True)
        return cls(
            vt_key=os.getenv("VT_KEY"),
            urlscan_key=os.getenv("URLSCAN_KEY"),
            hybrid_analysis_key=os.getenv("HYBRID_ANALYSIS_KEY"),
            abuse_key=os.getenv("ABUSEIPDB_KEY"),
            shodan_key=os.getenv("SHODAN_KEY"),
            threatfox_key=os.getenv("THREATFOX_KEY"),
            malwarebazaar_key=os.getenv("MALWAREBAZAAR_KEY"),
            dnsdumpster_key=os.getenv("DNSDUMPSTER_KEY"),
            gemini_key=os.getenv("GEMINI_KEY"),
            gemini_key_backup=os.getenv("GEMINI_KEY_BACKUP"),
            gemini_model=os.getenv("GEMINI_MODEL") or "gemini-2.5-flash",
            gemini_api_version=os.getenv("GEMINI_API_VERSION") or "v1",
            groq_key=os.getenv("GROQ_KEY"),
            mxtoolbox_key=os.getenv("MXTOOLBOX_KEY"),
            whoxy_key=os.getenv("WHOXY_KEY"),
            ransomware_live_key=os.getenv("RANSOMWARE_LIVE_KEY"),
            cve_nvd_key=os.getenv("CVE_NVD_KEY"),
        )
