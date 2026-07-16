"""Typed data models and enumerations used throughout IPTI.

These replace the deeply-nested, unvalidated dictionaries used by the original
implementation. Every provider returns a :class:`ProviderResult`; enrichment
sources return :class:`EnrichmentResult`; the engine produces a single
:class:`Assessment`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class ProviderStatus(str, Enum):
    """Explicit, distinguishable provider outcomes.

    ``False`` used to mean *safe*, *disabled*, *failed*, *no-data* and *stale*
    all at once. These states are semantically different and must stay
    distinguishable so scoring and coverage can treat them correctly.
    """

    # Configuration / lifecycle states
    DISABLED_BY_CONFIG = "disabled_by_config"
    DISABLED_MISSING_CREDENTIALS = "disabled_missing_credentials"
    # Evidence states (a successful query produced a verdict)
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"
    STALE = "stale"
    # Operational failure states
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    ERROR = "error"

    @property
    def is_disabled(self) -> bool:
        return self in {
            ProviderStatus.DISABLED_BY_CONFIG,
            ProviderStatus.DISABLED_MISSING_CREDENTIALS,
        }

    @property
    def is_operational_failure(self) -> bool:
        """A failure that reduces evidence coverage (never treated as clean)."""
        return self in {
            ProviderStatus.RATE_LIMITED,
            ProviderStatus.TIMEOUT,
            ProviderStatus.ERROR,
        }

    @property
    def produced_evidence(self) -> bool:
        """Whether the query yielded a usable verdict for scoring."""
        return self in {
            ProviderStatus.CLEAN,
            ProviderStatus.SUSPICIOUS,
            ProviderStatus.MALICIOUS,
        }


class Decision(str, Enum):
    """Final whitelist recommendation."""

    APPROVE_WITH_CONTROLS = "APPROVE_WITH_CONTROLS"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    DENY = "DENY"
    INCOMPLETE = "INCOMPLETE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ThreatClassification(str, Enum):
    """Separate description of the threat evidence itself."""

    NO_KNOWN_THREAT = "NO_KNOWN_THREAT"
    LOW_RISK = "LOW_RISK"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    CONFIRMED_MALICIOUS = "CONFIRMED_MALICIOUS"
    UNKNOWN = "UNKNOWN"


class PtrStatus(str, Enum):
    """Result of forward-confirmed reverse DNS analysis."""

    CONFIRMED = "confirmed"
    FORWARD_MISMATCH = "forward_mismatch"
    GENERIC_PROVIDER_PTR = "generic_provider_ptr"
    ORGANIZATION_PTR = "organization_ptr"
    DYNAMIC_PTR = "dynamic_ptr"
    NO_PTR = "no_ptr"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class ProviderResult:
    """Normalized output from a single threat-intelligence provider.

    ``risk_score`` uses 0 (no current malicious evidence) .. 100 (strong
    malicious evidence). ``confidence`` uses 0.0 .. 1.0. An unknown or failed
    result MUST use ``risk_score=None`` — never a fake 0.
    """

    provider: str
    enabled: bool
    status: ProviderStatus

    risk_score: float | None = None
    confidence: float = 0.0
    data_freshness_days: int | None = None

    queried_at: datetime | None = None
    observed_at: datetime | None = None
    duration_ms: int | None = None

    reasons: list[str] = field(default_factory=list)
    threat_categories: list[str] = field(default_factory=list)
    raw_metrics: dict[str, Any] = field(default_factory=dict)

    error_code: str | None = None
    error_message: str | None = None

    @property
    def usable(self) -> bool:
        """True when this result contributes evidence to the threat score."""
        return (
            self.enabled
            and self.status.produced_evidence
            and self.risk_score is not None
            and self.confidence > 0.0
        )


@dataclass
class EnrichmentResult:
    """Normalized output from an optional enrichment provider (IPInfo/Shodan)."""

    provider: str
    enabled: bool
    status: ProviderStatus
    queried_at: datetime | None = None
    observed_at: datetime | None = None
    duration_ms: int | None = None
    data: dict[str, Any] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)
    error_code: str | None = None
    error_message: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.enabled and self.status not in {
            ProviderStatus.DISABLED_BY_CONFIG,
            ProviderStatus.DISABLED_MISSING_CREDENTIALS,
            ProviderStatus.ERROR,
            ProviderStatus.TIMEOUT,
            ProviderStatus.RATE_LIMITED,
        }


@dataclass
class PtrResult:
    """Forward-confirmed reverse DNS result. Identity evidence only."""

    status: PtrStatus
    ptr: str | None = None
    forward_addresses: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


@dataclass
class Scores:
    """The three independent measurements plus evidence coverage."""

    threat: float
    identity_confidence: float | None
    exposure_risk: float | None
    evidence_coverage: float


@dataclass
class PlatformSummary:
    """Counts of provider lifecycle states. Disabled providers are excluded
    from queried/succeeded/failed and from every scoring denominator."""

    platforms_available: int
    platforms_enabled: int
    platforms_disabled: int
    platforms_queried: int
    platforms_succeeded: int
    platforms_failed: int


@dataclass
class Assessment:
    """The complete, serializable result of assessing a single IP."""

    schema_version: str
    ip: str
    ip_version: int | None
    checked_at: datetime

    decision: Decision
    threat_classification: ThreatClassification

    scores: Scores
    platform_summary: PlatformSummary

    providers: dict[str, ProviderResult] = field(default_factory=dict)
    enrichment: dict[str, Any] = field(default_factory=dict)

    hard_blocks: list[str] = field(default_factory=list)
    review_reasons: list[str] = field(default_factory=list)
    recommended_controls: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def is_safe(self) -> bool:
        """Deprecated backward-compatible flag.

        Defined *only* as ``decision == APPROVE_WITH_CONTROLS``. "Safe" is too
        absolute — no threat feed can prove an IP is safe. Prefer ``decision``,
        ``scores.threat`` and ``scores.evidence_coverage``.
        """
        return self.decision == Decision.APPROVE_WITH_CONTROLS
