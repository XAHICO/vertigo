"""
Page classifier — cloud-backed.

All ML inference runs on the XAHICO cloud service.  The PageType enum is
preserved here for use by the rest of the scan subsystem.
"""

import logging
from enum import Enum
from typing import Dict, Optional, Tuple

from ...cloud_client import CloudClient, CloudError

logger = logging.getLogger("vertigo.scan.page_classifier")


class PageType(Enum):
    """ML-classified page types (mirrors server-side taxonomy)."""
    UNKNOWN   = "unknown"
    LOGIN     = "login"
    DASHBOARD = "dashboard"
    PROFILE   = "profile"
    ADMIN     = "admin"
    API       = "api"
    STATIC    = "static"
    ERROR     = "error"
    FORM      = "form"
    LIST      = "list"
    DETAIL    = "detail"


class PageClassifier:
    """
    Proxy page classifier: delegates every inference call to the XAHICO cloud.

    The *model_dir* parameter is accepted for API compatibility but ignored.
    """

    def __init__(
        self,
        model_dir: Optional[str] = None,  # kept for back-compat; unused
        cloud_client: Optional[CloudClient] = None,
    ):
        if model_dir is not None:
            logger.debug(
                "model_dir=%r was supplied but is ignored; "
                "ML runs exclusively on the XAHICO cloud service.",
                model_dir,
            )
        self._cloud = cloud_client

    # ── public interface (unchanged from original) ────────────────────────────

    def classify(
        self,
        page_text: str,
        url: str,
        title: str,
        response_data: Dict,
    ) -> Tuple[PageType, float]:
        """
        Classify the type of a page.

        Returns
        -------
        (PageType, confidence)
            Falls back to ``(PageType.UNKNOWN, 0.0)`` on any cloud error.
        """
        if self._cloud is None:
            logger.debug("No cloud client — returning PageType.UNKNOWN.")
            return PageType.UNKNOWN, 0.0

        try:
            result = self._cloud.classify_page(page_text, url, title, response_data)
            raw_type = result.get("page_type", PageType.UNKNOWN.value)
            confidence = float(result.get("confidence", 0.0))

            try:
                page_type = PageType(raw_type)
            except ValueError:
                logger.debug("Unknown page_type value from cloud: %r — using UNKNOWN.", raw_type)
                page_type = PageType.UNKNOWN

            logger.debug(
                "Page classified: url=%r  type=%s  confidence=%.3f",
                url, page_type.value, confidence,
            )
            return page_type, confidence

        except CloudError as exc:
            logger.warning("Cloud page classification failed (using UNKNOWN): %s", exc)
            return PageType.UNKNOWN, 0.0

    # ── legacy compat ─────────────────────────────────────────────────────────

    @property
    def is_trained(self) -> bool:
        """Always reports True — the cloud model is always available."""
        return self._cloud is not None
