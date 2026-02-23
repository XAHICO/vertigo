"""
Anomaly detector — cloud-backed.

All ML inference runs on the XAHICO cloud service.  This module is a
thin adapter that preserves the original AnomalyDetector interface.
"""

import logging
from typing import Dict, List, Optional

from ...cloud_client import CloudClient, CloudError

logger = logging.getLogger("vertigo.scan.anomaly_detector")


class AnomalyDetector:
    """
    Proxy anomaly detector: delegates scoring to the XAHICO cloud.

    The *model_dir* parameter is accepted for API compatibility but ignored.
    The ``fit`` method submits samples to the cloud for server-side model
    improvement rather than training a local model.
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

    def score(self, response_data: Dict) -> float:
        """
        Return an anomaly score for *response_data*.

        Returns
        -------
        float
            A value in [0.0, 1.0].  Higher values indicate more anomalous
            responses.  Returns ``0.0`` on any cloud error (fail-open: do not
            suppress normal scan output because of a transient ML failure).
        """
        if self._cloud is None:
            logger.debug("No cloud client — anomaly score defaults to 0.0.")
            return 0.0

        try:
            result = self._cloud.detect_anomaly(response_data)
            score = float(result.get("score", 0.0))
            logger.debug(
                "Anomaly score for %r: %.4f",
                response_data.get("url", "<unknown>"), score,
            )
            return score
        except CloudError as exc:
            logger.warning("Cloud anomaly detection failed (defaulting to 0.0): %s", exc)
            return 0.0

    def fit(self, response_samples: List[Dict]) -> None:
        """
        Submit response samples to the cloud for server-side model improvement.
        Fire-and-forget; failures are non-fatal.
        """
        if self._cloud is None:
            return
        for sample in response_samples:
            self._cloud.submit_sample(sample_type="scan", sample_data=sample)

    # ── legacy compat ─────────────────────────────────────────────────────────

    def extract_features(self, response_data: Dict):
        """
        Kept for import compatibility.  Feature extraction now happens
        server-side; calling this client-side is a no-op.
        """
        logger.debug("extract_features() called client-side — this is a no-op.")
        return None

    @property
    def is_trained(self) -> bool:
        """Always reports True — the cloud model is always available."""
        return self._cloud is not None
