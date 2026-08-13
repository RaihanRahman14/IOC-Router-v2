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
from core.http import get_session


GEMINI_BASE = "https://generativelanguage.googleapis.com"

_GENERATE_TIMEOUT_SECONDS = 20
_LIST_MODELS_TIMEOUT_SECONDS = 15

logger = logging.getLogger(__name__)


_HTTP_ERROR_MESSAGES: dict[int, str] = {
    400: (
        "Invalid request to Gemini (Bad Request). "
        "Check the prompt content or generationConfig parameters."
    ),
    401: "Gemini API key not authenticated (401). Make sure GEMINI_KEY is still valid.",
    403: (
        "Gemini access denied (403 Forbidden). "
        "Possible causes: API key invalid/revoked, Generative Language API not enabled "
        "in the Google Cloud project, key restricted (referer/IP), or region not supported."
    ),
    404: (
        "Gemini model not found (404). "
        "Check the GEMINI_MODEL and GEMINI_API_VERSION values in .env."
    ),
    408: "Server-side timeout from Gemini (408). Please retry.",
    413: "Payload too large for Gemini (413). Shorten the prompt or context.",
    429: (
        "Gemini quota / rate limit exceeded (429). "
        "Wait a moment, reduce request frequency, or use a backup key."
    ),
    500: "Gemini hit an internal error (500). Try again shortly.",
    502: "Bad Gateway from Gemini (502). Please retry.",
    503: "Gemini service is busy / unavailable (503). Please try again later.",
    504: "Gateway timeout from Gemini (504). Please try again later.",
}

_FINISH_REASON_MESSAGES: dict[str, str] = {
    "SAFETY": "Output blocked by Gemini's safety filter.",
    "RECITATION": (
        "Output blocked as recitation "
        "(too similar to copyrighted content)."
    ),
    "MAX_TOKENS": (
        "Output truncated — exceeded maxOutputTokens. "
        "Shorten the prompt or raise the token limit."
    ),
    "OTHER": "Gemini stopped generation for an unspecified reason (OTHER).",
    "BLOCKLIST": "Output blocked — matched Gemini's blocklist.",
    "PROHIBITED_CONTENT": "Output blocked — flagged as prohibited content by Gemini.",
    "SPII": "Output blocked — sensitive/PII data detected by Gemini.",
    "LANGUAGE": "Output stopped — language not supported by the model.",
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
        status_code, f"Gemini returned an unrecognised HTTP {status_code}."
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
        return "", "Gemini returned an unrecognised response structure."

    prompt_feedback = data.get("promptFeedback")
    if isinstance(prompt_feedback, dict):
        block_reason = prompt_feedback.get("blockReason")
        if block_reason:
            return "", (
                f"Prompt blocked by Gemini's safety filter "
                f"(reason: {block_reason}). Try modifying the prompt content."
            )

    candidates = data.get("candidates")
    if not candidates or not isinstance(candidates, list):
        return "", "Gemini returned no candidate responses (empty response)."

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
        return "", f"Gemini produced no text (finishReason: {finish_reason})."
    return "", "Gemini produced no text and gave no reason."


def gemini_list_models(settings: Settings) -> tuple[list[str], str]:
    """List Gemini models that support the ``generateContent`` method.

    Args:
        settings: Application settings containing ``gemini_key`` and
            ``gemini_api_version``.

    Returns:
        Tuple ``(model_names, error_message)``. On success ``error_message``
        is empty. On failure the message is human-readable English text
        (never raw JSON).
    """
    if not settings.gemini_key:
        return [], "GEMINI_KEY is not set in .env."
    version = settings.gemini_api_version or "v1beta"
    url = f"{GEMINI_BASE}/{version}/models"
    try:
        response = get_session().get(
            url,
            headers={"x-goog-api-key": settings.gemini_key},
            timeout=_LIST_MODELS_TIMEOUT_SECONDS,
        )
    except requests.Timeout:
        return [], "Timeout while fetching the Gemini model list (>15s)."
    except requests.ConnectionError:
        return [], "Cannot reach the Gemini server. Check your internet connection."
    except requests.RequestException as exc:
        logger.warning("gemini_list_models network error: %s", exc)
        return [], "Network error while calling Gemini."

    if response.status_code != 200:
        return [], _format_http_error(response.status_code, response.text)

    try:
        data = response.json()
    except ValueError:
        return [], "Gemini returned a non-JSON body for list models."

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
        return "", f"{label} is not set in .env.", 0

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
        response = get_session().post(
            url,
            headers={"x-goog-api-key": key, "Content-Type": "application/json"},
            json=payload,
            timeout=_GENERATE_TIMEOUT_SECONDS,
        )
    except requests.Timeout:
        return "", "Gemini did not respond within 20 seconds (timeout). Please retry.", 0
    except requests.ConnectionError:
        return "", "Cannot reach the Gemini server. Check your internet connection.", 0
    except requests.RequestException as exc:
        logger.warning("gemini_generate network error (use_backup=%s): %s", use_backup, exc)
        return "", "Network error while calling Gemini.", 0

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
        "Gemini primary key failed (HTTP %s). Trying GEMINI_KEY_BACKUP...", status
    )
    backup_text, backup_err, _ = _generate_once(prompt, settings, use_backup=True)
    if backup_text:
        return backup_text, ""
    return "", f"{err} | Backup key also failed: {backup_err}"
