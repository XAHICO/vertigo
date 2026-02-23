"""
Form classifier — cloud-backed.

All ML inference runs on the XAHICO cloud service.  This module is a
thin adapter that preserves the original FormClassifier interface so the
rest of the auth subsystem needs no changes.
"""

import logging
from typing import Optional, Tuple

from ...cloud_client import CloudClient, CloudError

logger = logging.getLogger("vertigo.auth.form_classifier")


class FormClassifier:
    """
    Proxy classifier: delegates every inference call to the XAHICO cloud.

    The *model_dir* parameter is accepted for API compatibility but ignored —
    no model artefacts are stored or read client-side.
    """

    def __init__(
        self,
        model_dir: Optional[str] = None,   # kept for back-compat; unused
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

    def classify(self, form_text: str) -> Tuple[bool, float]:
        """
        Classify whether *form_text* describes a login form.

        Returns
        -------
        (is_login_form, confidence)
            *is_login_form* is ``True`` if the cloud considers this a login
            form.  *confidence* is a 0–1 float.  On any cloud error the call
            degrades gracefully to ``(False, 0.0)``.
        """
        if self._cloud is None:
            logger.debug("No cloud client — returning default classification.")
            return False, 0.0

        try:
            result = self._cloud.classify_form(form_text)
            is_login = bool(result.get("is_login_form", False))
            confidence = float(result.get("confidence", 0.0))
            logger.debug(
                "Form classified: is_login=%s  confidence=%.3f", is_login, confidence
            )
            return is_login, confidence
        except CloudError as exc:
            logger.warning("Cloud form classification failed (using safe default): %s", exc)
            return False, 0.0

    def learn_from_result(self, form_text: str, was_login_form: bool) -> None:
        """
        Submit a labelled sample back to the cloud for model improvement.
        This call is fire-and-forget; failures are non-fatal.
        """
        if self._cloud is None:
            return
        self._cloud.submit_sample(
            sample_type="auth",
            sample_data={"form_text": form_text},
            label="login" if was_login_form else "other",
        )
