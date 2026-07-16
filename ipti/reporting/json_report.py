"""Stable, serializable JSON representation of an :class:`Assessment`."""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime
from typing import Any

from ..models import Assessment, ProviderResult


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone().isoformat() if value.tzinfo else value.isoformat()


def _provider_dict(result: ProviderResult) -> dict[str, Any]:
    return {
        "enabled": result.enabled,
        "status": result.status.value,
        "risk_score": result.risk_score,
        "confidence": round(result.confidence, 4),
        "data_freshness_days": result.data_freshness_days,
        "queried_at": _iso(result.queried_at),
        "observed_at": _iso(result.observed_at),
        "duration_ms": result.duration_ms,
        "reasons": result.reasons,
        "threat_categories": result.threat_categories,
        "raw_metrics": result.raw_metrics,
        "error_code": result.error_code,
        "error_message": result.error_message,
    }


def assessment_to_dict(assessment: Assessment) -> dict[str, Any]:
    """Convert an assessment into a JSON-serializable dictionary."""
    scores = assessment.scores
    summary = assessment.platform_summary
    return {
        "schema_version": assessment.schema_version,
        "ip": assessment.ip,
        "ip_version": assessment.ip_version,
        "checked_at": _iso(assessment.checked_at),
        "decision": assessment.decision.value,
        "threat_classification": assessment.threat_classification.value,
        # Deprecated: defined only as decision == APPROVE_WITH_CONTROLS.
        "is_safe": assessment.is_safe,
        "scores": {
            "threat": scores.threat,
            "identity_confidence": scores.identity_confidence,
            "exposure_risk": scores.exposure_risk,
            "evidence_coverage": scores.evidence_coverage,
        },
        "platform_summary": asdict(summary) if is_dataclass(summary) else summary,
        "providers": {
            name: _provider_dict(result) for name, result in assessment.providers.items()
        },
        "enrichment": assessment.enrichment,
        "hard_blocks": assessment.hard_blocks,
        "review_reasons": assessment.review_reasons,
        "recommended_controls": assessment.recommended_controls,
        "warnings": assessment.warnings,
    }


def render_json(assessment: Assessment, *, indent: int | None = 2) -> str:
    """Render a single assessment as a JSON string."""
    return json.dumps(assessment_to_dict(assessment), indent=indent, default=str)


def render_json_many(assessments: list[Assessment], *, indent: int | None = 2) -> str:
    """Render multiple assessments as a JSON array."""
    return json.dumps(
        [assessment_to_dict(a) for a in assessments], indent=indent, default=str
    )
