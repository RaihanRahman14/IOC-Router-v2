"""Groq client for ticket note generation."""
from __future__ import annotations

import requests

from config import Settings
from core.http import get_session


GROQ_BASE = "https://api.groq.com/openai/v1"


def groq_generate(prompt: str, settings: Settings, model: str = "llama-3.1-8b-instant") -> tuple[str, str]:
    if not settings.groq_key:
        return "", "Missing GROQ_KEY"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a SOC assistant."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
        "top_p": 0.9,
        "max_tokens": 4096,
    }
    try:
        r = get_session().post(
            f"{GROQ_BASE}/chat/completions",
            headers={"Authorization": f"Bearer {settings.groq_key}"},
            json=payload,
            timeout=20,
        )
    except requests.RequestException:
        return "", "Network error"
    if r.status_code != 200:
        return "", f"HTTP {r.status_code}: {r.text[:300]}"
    data = r.json()
    choices = data.get("choices", [])
    if not choices:
        return "", "No choices in response"
    content = choices[0].get("message", {}).get("content", "")
    return content.strip(), ""
