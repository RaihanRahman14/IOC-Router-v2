"""Geolocation helpers — ip-api.com and Nominatim reverse geocode."""
from __future__ import annotations

import streamlit as st

from core.http import get_session


@st.cache_data(ttl=3600, show_spinner=False)
def fetch_geo_ip_api(ip: str) -> dict:
    """Fetch geolocation for an IP from ip-api.com. Returns empty dict on failure."""
    try:
        r = get_session().get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,message,country,countryCode,region,regionName,city,lat,lon,zip,isp,org,as,query"},
            timeout=8,
            headers={"User-Agent": "IOCRouter/1.0"},
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                return data
    except Exception:
        pass
    return {}


@st.cache_data(ttl=3600, show_spinner=False)
def fetch_nominatim(lat: float, lon: float) -> dict:
    """Reverse geocode coordinates via Nominatim. Returns empty dict on failure."""
    try:
        r = get_session().get(
            "https://nominatim.openstreetmap.org/reverse",
            params={"lat": lat, "lon": lon, "format": "json"},
            timeout=8,
            headers={"User-Agent": "IOCRouter/1.0"},
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}
