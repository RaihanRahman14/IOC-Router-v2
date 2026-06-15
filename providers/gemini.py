"""Gemini client for ticket note generation.

Wraps the Google Generative Language API (`generateContent` and `models` list
endpoints) and converts every failure mode the API can return — HTTP errors,
safety blocks, truncated responses, network problems — into short, human-
readable Indonesian messages. No raw JSON is ever surfaced to callers.
"""
from __future__ import annotations

import json
import logging
from typing import Any

import requests

from config import Settings


GEMINI_BASE = "https://generativelanguage.googleapis.com"

_GENERATE_TIMEOUT_SECONDS = 20
_LIST_MODELS_TIMEOUT_SECONDS = 15

logger = logging.getLogger(__name__)


_HTTP_ERROR_MESSAGES: dict[int, str] = {
    400: (
        "Permintaan tidak valid ke Gemini (Bad Request). "
        "Periksa isi prompt atau parameter generationConfig."
    ),
    401: "API key Gemini tidak terautentikasi (401). Pastikan GEMINI_KEY masih valid.",
    403: (
        "Akses Gemini ditolak (403 Forbidden). "
        "Kemungkinan: API key salah/dicabut, Generative Language API belum diaktifkan "
        "di Google Cloud project, key dibatasi (referer/IP), atau region tidak didukung."
    ),
    404: (
        "Model Gemini tidak ditemukan (404). "
        "Periksa nilai GEMINI_MODEL dan GEMINI_API_VERSION di .env."
    ),
    408: "Gemini timeout di sisi server (408). Coba ulangi.",
    413: "Payload terlalu besar untuk Gemini (413). Kurangi panjang prompt atau konteks.",
    429: (
        "Quota / rate limit Gemini terlampaui (429). "
        "Tunggu beberapa saat, kurangi frekuensi request, atau gunakan backup key."
    ),
    500: "Gemini mengalami error internal (500). Coba lagi beberapa saat.",
    502: "Bad Gateway dari Gemini (502). Coba ulangi.",
    503: "Layanan Gemini sedang sibuk / unavailable (503). Coba lagi nanti.",
    504: "Gateway timeout dari Gemini (504). Coba lagi nanti.",
}

_FINISH_REASON_MESSAGES: dict[str, str] = {
    "SAFETY": "Output diblokir oleh safety filter Gemini.",
    "RECITATION": (
        "Output diblokir karena dianggap recitation "
        "(kemiripan dengan konten berhak cipta)."
    ),
    "MAX_TOKENS": (
        "Output dipotong karena melebihi maxOutputTokens. "
        "Kurangi panjang prompt atau naikkan limit token."
    ),
    "OTHER": "Gemini menghentikan generasi dengan alasan tidak spesifik (OTHER).",
    "BLOCKLIST": "Output diblokir karena cocok dengan daftar terlarang Gemini.",
    "PROHIBITED_CONTENT": "Output diblokir karena dianggap konten terlarang oleh Gemini.",
    "SPII": "Output diblokir karena terdeteksi data sensitif/PII oleh Gemini.",
    "LANGUAGE": "Output dihentikan karena bahasa tidak didukung oleh model.",
}

_RETRYABLE_WITH_BACKUP: frozenset[int] = frozenset({401, 403, 429})


def _extract_api_error(body: str) -> tuple[str, str]:
    """Pull ``error.status`` and ``error.message`` from a Gemini error body.

    Args:
        body: Raw response body returned by the Gemini API.

    Returns:
        Tuple ``(status_code_string, human_message)``. Both may be empty
        strings when the body is missing, non-JSON, or lacks the expected
        ``error`` envelope.
    """
    if not body:
        return "", ""
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return "", ""
    if not isinstance(payload, dict):
        return "", ""
    err = payload.get("error", {})
    if not isinstance(err, dict):
        return "", ""
    status = str(err.get("status") or "").strip()
    message = str(err.get("message") or "").strip()
    if len(message) > 280:
        message = message[:280] + "..."
    return status, message


def _format_http_error(status_code: int, body: str) -> str:
    """Build a friendly Indonesian message from a Gemini HTTP failure.

    Args:
        status_code: HTTP status returned by the Gemini API.
        body: Raw response body (may contain a structured ``error`` object).

    Returns:
        Single-line message safe to display in UI; never raw JSON.
    """
    base = _HTTP_ERROR_MESSAGES.get(
        status_code, f"Gemini mengembalikan HTTP {status_code} yang tidak dikenali."
    )
    api_status, api_message = _extract_api_error(body)
    detail_parts: list[str] = []
    if api_status:
        detail_parts.append(api_status)
    if api_message:
        detail_parts.append(api_message)
    if detail_parts:
        return f"{base} ({' — '.join(detail_parts)})"
    return base


def _parse_generate_response(data: dict[str, Any]) -> tuple[str, str]:
    """Convert a 200-OK Gemini response into either text or a friendly error.

    Handles three failure modes that all return HTTP 200:
    - ``promptFeedback.blockReason`` set → prompt was blocked pre-generation.
    - ``candidates`` empty → model returned nothing.
    - First candidate has no text and a non-STOP ``finishReason`` → output
      was suppressed (safety, recitation, etc.).

    Args:
        data: Parsed JSON body from a ``generateContent`` call.

    Returns:
        Tuple ``(generated_text, error_message)``. When ``generated_text`` is
        non-empty the caller should consume it; otherwise ``error_message``
        explains why nothing was produced.
    """
    if not isinstance(data, dict):
        return "", "Gemini mengembalikan struktur response yang tidak dikenali."

    prompt_feedback = data.get("promptFeedback")
    if isinstance(prompt_feedback, dict):
        block_reason = prompt_feedback.get("blockReason")
        if block_reason:
            return "", (
                f"Prompt diblokir oleh safety filter Gemini "
                f"(alasan: {block_reason}). Coba ubah konten prompt."
            )

    candidates = data.get("candidates")
    if not candidates or not isinstance(candidates, list):
        return "", "Gemini tidak mengembalikan kandidat jawaban (response kosong)."

    first = candidates[0] if isinstance(candidates[0], dict) else {}
    finish_reason = str(first.get("finishReason") or "").strip()
    content = first.get("content") if isinstance(first, dict) else {}
    parts = content.get("parts", []) if isinstance(content, dict) else []
    texts = [
        p.get("text", "")
        for p in parts
        if isinstance(p, dict) and isinstance(p.get("text"), str) and p.get("text")
    ]
    text = "\n".join(texts).strip()

    if text:
        return text, ""

    if finish_reason in _FINISH_REASON_MESSAGES:
        return "", _FINISH_REASON_MESSAGES[finish_reason]
    if finish_reason:
        return "", f"Gemini tidak menghasilkan teks (finishReason: {finish_reason})."
    return "", "Gemini tidak menghasilkan teks dan tidak memberi alasan."


def gemini_list_models(settings: Settings) -> tuple[list[str], str]:
    """List Gemini models that support the ``generateContent`` method.

    Args:
        settings: Application settings containing ``gemini_key`` and
            ``gemini_api_version``.

    Returns:
        Tuple ``(model_names, error_message)``. On success ``error_message``
        is empty. On failure the message is human-readable Indonesian text
        (never raw JSON).
    """
    if not settings.gemini_key:
        return [], "GEMINI_KEY belum di-set di .env."
    version = settings.gemini_api_version or "v1beta"
    url = f"{GEMINI_BASE}/{version}/models"
    try:
        response = requests.get(
            url,
            headers={"x-goog-api-key": settings.gemini_key},
            timeout=_LIST_MODELS_TIMEOUT_SECONDS,
        )
    except requests.Timeout:
        return [], "Timeout saat mengambil daftar model Gemini (>15 detik)."
    except requests.ConnectionError:
        return [], "Tidak bisa terhubung ke server Gemini. Periksa koneksi internet."
    except requests.RequestException as exc:
        logger.warning("gemini_list_models network error: %s", exc)
        return [], "Network error saat memanggil Gemini."

    if response.status_code != 200:
        return [], _format_http_error(response.status_code, response.text)

    try:
        data = response.json()
    except ValueError:
        return [], "Gemini mengembalikan body non-JSON saat list models."

    models: list[str] = []
    for entry in data.get("models", []):
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        methods = entry.get("supportedGenerationMethods", [])
        if isinstance(name, str) and "generateContent" in methods:
            models.append(name.replace("models/", ""))
    return models, ""


def _generate_once(
    prompt: str, settings: Settings, *, use_backup: bool
) -> tuple[str, str, int]:
    """Call Gemini ``generateContent`` once with the requested key.

    Args:
        prompt: Text prompt to send.
        settings: Application settings.
        use_backup: If ``True``, use ``gemini_key_backup`` instead of
            ``gemini_key``.

    Returns:
        Tuple ``(text, error_message, http_status)``. ``http_status`` is
        ``0`` for pre-flight failures (missing key, network error, timeout)
        and otherwise the actual HTTP status returned by Gemini. ``text`` and
        ``error_message`` follow the same contract as :func:`gemini_generate`.
    """
    key = settings.gemini_key_backup if use_backup else settings.gemini_key
    if not key:
        label = "GEMINI_KEY_BACKUP" if use_backup else "GEMINI_KEY"
        return "", f"{label} belum di-set di .env.", 0

    version = settings.gemini_api_version or "v1beta"
    model = settings.gemini_model or "gemini-1.5-flash"
    url = f"{GEMINI_BASE}/{version}/models/{model}:generateContent"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.2,
            "topP": 0.9,
            "maxOutputTokens": 8192,
        },
    }
    try:
        response = requests.post(
            url,
            headers={"x-goog-api-key": key, "Content-Type": "application/json"},
            json=payload,
            timeout=_GENERATE_TIMEOUT_SECONDS,
        )
    except requests.Timeout:
        return "", "Gemini tidak merespon dalam 20 detik (timeout). Coba lagi.", 0
    except requests.ConnectionError:
        return "", "Tidak bisa terhubung ke server Gemini. Periksa koneksi internet.", 0
    except requests.RequestException as exc:
        logger.warning("gemini_generate network error (use_backup=%s): %s", use_backup, exc)
        return "", "Network error saat memanggil Gemini.", 0

    if response.status_code != 200:
        return (
            "",
            _format_http_error(response.status_code, response.text),
            response.status_code,
        )

    try:
        data = response.json()
    except ValueError:
        return "", "Gemini mengembalikan body non-JSON saat generate.", response.status_code

    text, err = _parse_generate_response(data)
    return text, err, response.status_code


def gemini_generate(
    prompt: str, settings: Settings, use_backup: bool = False
) -> tuple[str, str]:
    """Generate text from Gemini, with automatic backup-key fallback.

    If the primary call fails with an auth/quota error (HTTP 401, 403, or
    429) **and** ``GEMINI_KEY_BACKUP`` is configured, this function
    transparently retries once with the backup key. All error messages are
    human-readable Indonesian text — raw JSON is never returned.

    Args:
        prompt: Text prompt to send.
        settings: Application settings.
        use_backup: If ``True``, skip the primary key and use the backup key
            directly (no fallback is attempted in that case).

    Returns:
        Tuple ``(generated_text, error_message)``. When ``generated_text`` is
        non-empty ``error_message`` is empty. When generation fails
        ``error_message`` describes the failure in plain language suitable
        for direct display in the UI.
    """
    text, err, status = _generate_once(prompt, settings, use_backup=use_backup)
    if text:
        return text, ""

    should_retry = (
        not use_backup
        and status in _RETRYABLE_WITH_BACKUP
        and bool(settings.gemini_key_backup)
    )
    if not should_retry:
        return "", err

    logger.warning(
        "Gemini primary key gagal (HTTP %s). Mencoba GEMINI_KEY_BACKUP...", status
    )
    backup_text, backup_err, _ = _generate_once(prompt, settings, use_backup=True)
    if backup_text:
        return backup_text, ""
    return "", f"{err} | Backup key juga gagal: {backup_err}"
