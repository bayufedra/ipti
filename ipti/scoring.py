"""Threat scoring and evidence coverage.

The threat score is a confidence-weighted, dynamically-normalized average over
*only* the providers that returned usable evidence. Disabled providers never
appear in any denominator; failed enabled providers reduce coverage but do not
count as clean. Contextual metadata (PTR, geography, ports) never enters this
score.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .config import THREAT_PROVIDERS, Settings
from .models import ProviderResult, ProviderStatus


@dataclass
class ThreatScoreResult:
    threat_score: float
    coverage: float
    usable_results: list[ProviderResult] = field(default_factory=list)
    successful_sources: int = 0
    malicious_sources: int = 0
    suspicious_sources: int = 0
    has_evidence: bool = False


def _is_usable(result: ProviderResult, settings: Settings) -> bool:
    if not result.enabled or result.risk_score is None or result.confidence <= 0:
        return False
    if result.status.produced_evidence:
        return True
    return result.status is ProviderStatus.STALE and settings.allow_stale_evidence


def compute_threat_score(
    results: dict[str, ProviderResult],
    settings: Settings,
) -> ThreatScoreResult:
    """Compute the weighted threat score and evidence coverage."""

    weights = {p: settings.providers[p].weight for p in THREAT_PROVIDERS}
    resolved = settings.resolved_providers()
    enabled = [p for p in THREAT_PROVIDERS if resolved[p].enabled]

    usable = [
        r
        for name, r in results.items()
        if name in THREAT_PROVIDERS and _is_usable(r, settings)
    ]

    # Dynamic, confidence-weighted normalization over usable providers only.
    effective_weight = sum(weights[r.provider] * r.confidence for r in usable)
    if effective_weight > 0:
        threat_score = (
            sum(
                (r.risk_score or 0.0) * weights[r.provider] * r.confidence for r in usable
            )
            / effective_weight
        )
    else:
        threat_score = 0.0

    configured_enabled_weight = sum(weights[p] for p in enabled)
    successful_weight = sum(weights[r.provider] for r in usable)
    coverage = (
        successful_weight / configured_enabled_weight
        if configured_enabled_weight > 0
        else 0.0
    )

    malicious = sum(1 for r in usable if r.status is ProviderStatus.MALICIOUS)
    suspicious = sum(1 for r in usable if r.status is ProviderStatus.SUSPICIOUS)

    return ThreatScoreResult(
        threat_score=round(threat_score, 2),
        coverage=round(coverage, 4),
        usable_results=usable,
        successful_sources=len(usable),
        malicious_sources=malicious,
        suspicious_sources=suspicious,
        has_evidence=bool(usable),
    )
