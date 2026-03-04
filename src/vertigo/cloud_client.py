"""
XAHICO Vertigo — Cloud ML Client
All ML inference and sample submission is handled server-side.
This module is the sole network bridge between vertigo and the XAHICO cloud.
"""

import logging
import os
import time
from typing import Any, Dict, Optional

import urllib.request
import urllib.error
import json

logger = logging.getLogger("vertigo.cloud")

# ── Endpoint baked into the package at release time ──────────────────────────
# Update this URL when you deploy a new Cloud Function revision.
_CLOUD_ENDPOINT = "https://vertigo.services.xahico.com/"
_REQUEST_TIMEOUT = 15  # seconds
_MAX_RETRIES = 2

# ── Paths exposed by the Cloud Function ──────────────────────────────────────
_PATH_VALIDATE     = "/license/validate"
_PATH_CLASSIFY_FORM = "/ml/classify/form"
_PATH_CLASSIFY_PAGE = "/ml/classify/page"
_PATH_DETECT_ANOMALY = "/ml/detect/anomaly"
_PATH_SUBMIT_SAMPLE = "/sample/submit"


class CloudError(RuntimeError):
    """Raised when the cloud service returns a non-200 response."""


class CloudClient:
    """
    Thread-safe, retry-aware HTTP client for the XAHICO ML cloud service.

    Parameters
    ----------
    api_key : str | None
        XAHICO_VERTIGO_LICENSE_KEY.  If *None* only unauthenticated endpoints
        are reachable (sample submission only).
    debug : bool
        When *True* the client emits structured DEBUG log lines for every
        request / response cycle.
    """

    def __init__(self, api_key: Optional[str], debug: bool = False):
        self._api_key = api_key
        self._debug = debug

    # ── internal ─────────────────────────────────────────────────────────────

    def _headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._api_key:
            h["X-API-Key"] = self._api_key
        return h

    def _post(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = _CLOUD_ENDPOINT.rstrip("/") + path
        body = json.dumps(payload).encode()
        headers = self._headers()

        last_exc: Optional[Exception] = None
        for attempt in range(1, _MAX_RETRIES + 2):
            t0 = time.monotonic()
            try:
                req = urllib.request.Request(url, data=body, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT) as resp:
                    raw = resp.read()
                    elapsed = (time.monotonic() - t0) * 1000
                    data = json.loads(raw)
                    if self._debug:
                        logger.debug(
                            "CLOUD ← POST %s  status=200  elapsed=%.0fms  "
                            "attempt=%d  response_keys=%s",
                            path, elapsed, attempt, list(data.keys()),
                        )
                    return data

            except urllib.error.HTTPError as exc:
                elapsed = (time.monotonic() - t0) * 1000
                body_text = exc.read().decode(errors="replace")
                if self._debug:
                    logger.debug(
                        "CLOUD ← POST %s  status=%d  elapsed=%.0fms  attempt=%d  body=%r",
                        path, exc.code, elapsed, attempt, body_text[:200],
                    )
                if exc.code in (401, 403):
                    raise CloudError(f"Access denied (HTTP {exc.code}): {body_text}") from exc
                if exc.code < 500:
                    raise CloudError(f"Cloud service error (HTTP {exc.code}): {body_text}") from exc
                last_exc = exc  # 5xx — retry

            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                elapsed = (time.monotonic() - t0) * 1000
                if self._debug:
                    logger.debug(
                        "CLOUD ← POST %s  network_error=%r  elapsed=%.0fms  attempt=%d",
                        path, str(exc), elapsed, attempt,
                    )
                last_exc = exc

            if attempt <= _MAX_RETRIES:
                wait = 0.5 * attempt
                if self._debug:
                    logger.debug("CLOUD   retrying in %.1fs  (attempt %d/%d)", wait, attempt + 1, _MAX_RETRIES + 1)
                time.sleep(wait)

        raise CloudError(f"Cloud service unreachable after {_MAX_RETRIES + 1} attempts: {last_exc}") from last_exc

    # ── public API ────────────────────────────────────────────────────────────

    def validate_license(self) -> Dict[str, Any]:
        """
        Verify that the API key is valid and the licence has not expired.

        Returns a dict with at minimum:
            { "valid": bool, "expires_at": "ISO-8601", "plan": str }

        Raises CloudError if the request fails or the key is rejected.
        """
        if self._debug:
            logger.debug("CLOUD → POST %s  (license validation)", _PATH_VALIDATE)
        return self._post(_PATH_VALIDATE, {})

    def classify_form(self, form_text: str) -> Dict[str, Any]:
        """
        Ask the cloud to classify whether *form_text* represents a login form.

        Returns: { "is_login_form": bool, "confidence": float }
        """
        if self._debug:
            logger.debug(
                "CLOUD → POST %s  form_text_len=%d", _PATH_CLASSIFY_FORM, len(form_text)
            )
        return self._post(_PATH_CLASSIFY_FORM, {"form_text": form_text})

    def classify_page(
        self,
        page_text: str,
        url: str,
        title: str,
        response_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Ask the cloud to classify the type of the given page.

        Returns: { "page_type": str, "confidence": float }
        """
        if self._debug:
            logger.debug(
                "CLOUD → POST %s  url=%r  page_text_len=%d",
                _PATH_CLASSIFY_PAGE, url, len(page_text),
            )
        return self._post(
            _PATH_CLASSIFY_PAGE,
            {
                "page_text": page_text[:2000],
                "url": url,
                "title": title,
                "response_data": response_data,
            },
        )

    def detect_anomaly(self, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ask the cloud to score an HTTP response for anomalies.

        Returns: { "score": float }   (higher = more anomalous, 0.0–1.0)
        """
        if self._debug:
            logger.debug(
                "CLOUD → POST %s  status=%s  url=%r",
                _PATH_DETECT_ANOMALY,
                response_data.get("status_code"),
                response_data.get("url", ""),
            )
        return self._post(_PATH_DETECT_ANOMALY, {"response_data": response_data})

    def submit_sample(
        self,
        sample_type: str,          # "auth" | "scan"
        sample_data: Dict[str, Any],
        label: Optional[str] = None,
    ) -> None:
        """
        Submit a sample for cloud-side model improvement.
        This endpoint is accessible with *or* without an API key.
        Failures are swallowed — sample submission must never break user flow.
        """
        payload = {
            "type": sample_type,
            "data": sample_data,
        }
        if label is not None:
            payload["label"] = label

        if self._debug:
            logger.debug(
                "CLOUD → POST %s  type=%r  label=%r",
                _PATH_SUBMIT_SAMPLE, sample_type, label,
            )
        try:
            self._post(_PATH_SUBMIT_SAMPLE, payload)
        except Exception as exc:
            # Never let sample submission break the caller
            if self._debug:
                logger.debug("CLOUD   sample submission failed (non-fatal): %s", exc)
            else:
                logger.warning("Sample submission failed (non-fatal): %s", exc)


# ── Module-level singleton helpers ────────────────────────────────────────────

_client: Optional[CloudClient] = None


def get_client(debug: bool = False) -> CloudClient:
    """Return (or create) the process-wide CloudClient singleton."""
    global _client
    if _client is None:
        api_key = os.environ.get("XAHICO_VERTIGO_LICENSE_KEY") or None
        _client = CloudClient(api_key=api_key, debug=debug)
    return _client
