"""Backward-compatibility adapter for the legacy ``IPTI`` class.

Preserves ``from ipti import IPTI`` and ``IPTI(ip).ipti_check()`` returning a
dict. The returned dict now carries the new evidence-based fields (``decision``,
``scores``, ``threat_classification``, ``evidence_coverage``) *and* the legacy
``is_safe`` / ``safe_ratio`` / ``platforms`` keys for continuity. ``is_safe`` is
defined only as ``decision == APPROVE_WITH_CONTROLS`` and is deprecated.
"""

from __future__ import annotations

import asyncio
import warnings
from typing import Any

from .config import Settings, load_settings
from .engine import AssessmentEngine
from .models import Assessment, ProviderStatus
from .reporting.json_report import assessment_to_dict


class IPTI:
    """Legacy entry point. Prefer :class:`ipti.engine.AssessmentEngine`."""

    def __init__(
        self,
        ip: str,
        max_age_in_days: int = 30,
        score_threshold: int = 30,
        user_threshold: int = 3,
        safe_ratio: float = 0.75,
        *,
        settings: Settings | None = None,
        claimed_owner: str | None = None,
    ) -> None:
        self.ip = ip
        self.max_age_in_days = max_age_in_days
        self.score_threshold = score_threshold
        self.user_threshold = user_threshold  # retained for signature compat
        self.safe_ratio = safe_ratio
        self.claimed_owner = claimed_owner

        base = settings or load_settings()
        # Map legacy knobs onto the new settings, clamping to valid ranges so a
        # legacy call can't produce an invalid config (with_overrides skips the
        # load-time range checks).
        review = min(max(float(score_threshold), 0.0), base.threat_deny_threshold)
        self._settings = base.with_overrides(
            max_threat_age_days=max(int(max_age_in_days), 1),
            threat_review_threshold=review,
        )
        self._settings.validate()
        warnings.warn(
            "IPTI(...).ipti_check() now returns an evidence-based assessment. "
            "'is_safe' and 'safe_ratio' are deprecated; prefer result['decision'] "
            "and result['scores'].",
            DeprecationWarning,
            stacklevel=2,
        )

    def assess(self) -> Assessment:
        """Run the assessment synchronously and return the :class:`Assessment`."""
        return asyncio.run(self._run())

    async def _run(self) -> Assessment:
        async with AssessmentEngine(self._settings) as engine:
            return await engine.assess(self.ip, claimed_owner=self.claimed_owner)

    def ipti_check(self) -> dict[str, Any]:
        """Legacy-compatible dict result (superset of the old schema)."""
        assessment = self.assess()
        data = assessment_to_dict(assessment)
        data["check_date"] = assessment.checked_at.strftime("%Y-%m-%d %H:%M:%S")
        # Deprecated: derived from the threat score, not a proof of safety.
        data["safe_ratio"] = round(max(0.0, 1.0 - assessment.scores.threat / 100.0), 3)
        data["platforms"] = self._legacy_platforms(assessment)
        return data

    @staticmethod
    def _legacy_platforms(assessment: Assessment) -> dict[str, Any]:
        report: dict[str, bool] = {}
        considered = 0
        flagged_safe = 0
        for name, result in assessment.providers.items():
            if not result.enabled:
                continue
            considered += 1
            is_malicious = result.status is ProviderStatus.MALICIOUS
            report[name] = is_malicious
            if not is_malicious:
                flagged_safe += 1
        return {
            "malicious_report": report,
            "platforms_considered": considered,
            "platforms_flagged_as_safe": flagged_safe,
            "platforms_safe_ratio": (flagged_safe / considered) if considered else 0.0,
        }
