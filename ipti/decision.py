"""Final decision logic.

Turns the threat score, coverage, exposure, identity and policy signals into a
:class:`~ipti.models.Decision` plus a separate
:class:`~ipti.models.ThreatClassification`. Direct threat evidence can never be
cancelled by PTR, geography, provider metadata or open standard ports — those
can only *raise* concern or lower confidence, moving a decision toward review,
never toward approval.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .config import THREAT_PROVIDERS, Settings
from .models import Decision, ProviderResult, ProviderStatus, ThreatClassification
from .scoring import ThreatScoreResult

# High-confidence threshold above which a single malicious verdict is critical.
_CRITICAL_CONFIDENCE = 0.85

_BASE_CONTROLS = (
    "Allow only the required destination host and port",
    "Use a /32 IPv4 rule or /128 IPv6 rule",
    "Require application-level authentication",
    "Enable connection logging and alerting",
    "Configure an expiration date and schedule periodic re-review",
)


@dataclass
class DecisionResult:
    decision: Decision
    classification: ThreatClassification
    hard_blocks: list[str] = field(default_factory=list)
    review_reasons: list[str] = field(default_factory=list)
    recommended_controls: list[str] = field(default_factory=list)


def decide(
    *,
    threat: ThreatScoreResult,
    all_results: dict[str, ProviderResult],
    exposure: dict,
    identity: dict,
    ipinfo_data: dict | None,
    settings: Settings,
    identity_supplied: bool,
    policy: dict | None = None,
) -> DecisionResult:
    """Apply hard blocks, correlation rules and the decision flow."""

    policy = policy or {}
    hard_blocks = _hard_blocks(threat, exposure, identity, ipinfo_data, settings, policy)
    review_reasons = _review_reasons(
        threat, all_results, exposure, identity, settings, identity_supplied, policy
    )
    classification = _classify(threat, settings)

    decision = _decide(
        threat,
        hard_blocks,
        review_reasons,
        exposure,
        identity,
        settings,
        identity_supplied,
    )
    controls = _controls(decision, exposure, ipinfo_data)

    return DecisionResult(
        decision=decision,
        classification=classification,
        hard_blocks=hard_blocks,
        review_reasons=review_reasons,
        recommended_controls=controls,
    )


def _hard_blocks(threat, exposure, identity, ipinfo_data, settings, policy) -> list[str]:
    blocks: list[str] = []
    for result in threat.usable_results:
        if (
            result.status is ProviderStatus.MALICIOUS
            and result.confidence >= _CRITICAL_CONFIDENCE
        ):
            blocks.append(
                f"{result.provider} returned a high-confidence malicious verdict"
            )
    if threat.malicious_sources >= 2:
        blocks.append("Two or more independent providers returned malicious verdicts")
    elif threat.malicious_sources >= 1 and threat.suspicious_sources >= 1:
        blocks.append("One provider malicious with independent suspicious corroboration")

    if ipinfo_data:
        if ipinfo_data.get("is_tor") and settings.block_tor:
            blocks.append("Confirmed Tor node and policy blocks Tor")
        if (
            ipinfo_data.get("is_proxy") or ipinfo_data.get("is_residential_proxy")
        ) and settings.block_open_proxy:
            blocks.append("Confirmed open/residential proxy and policy blocks proxies")

    # Geography is policy context (never a threat verdict): a restricted country
    # is an org-policy hard block, not a claim that the IP is malicious.
    if policy.get("geographic_policy") == "restricted":
        blocks.append(
            policy.get(
                "geographic_reason", "Country is on the restricted-countries policy"
            )
        )

    if identity.get("ownership_mismatch"):
        blocks.append(
            "Claimed ownership is materially inconsistent with the observed network owner"
        )
    return blocks


def _review_reasons(
    threat, all_results, exposure, identity, settings, identity_supplied, policy
) -> list[str]:
    reasons: list[str] = []
    if threat.suspicious_sources > 0 and threat.malicious_sources == 0:
        reasons.append(
            f"{threat.suspicious_sources} provider(s) reported suspicious evidence"
        )
    # Geographic policy (context only, not a threat score change).
    geo = policy.get("geographic_policy")
    if geo == "require_approval":
        reasons.append(policy.get("geographic_reason", "Country requires approval"))
    elif geo == "unexpected":
        reasons.append(policy.get("geographic_reason", "Country is unexpected"))
    if threat.coverage < settings.min_threat_coverage:
        reasons.append(
            f"Evidence coverage {threat.coverage:.0%} is below the required "
            f"{settings.min_threat_coverage:.0%}"
        )
    for name in THREAT_PROVIDERS:
        result = all_results.get(name)
        if result is None or not result.enabled:
            continue
        if result.status.is_operational_failure:
            reasons.append(f"{name} was unavailable ({result.status.value})")
        elif result.status is ProviderStatus.STALE and not settings.allow_stale_evidence:
            reasons.append(f"{name} evidence is stale")
    exposure_risk = exposure.get("exposure_risk")
    if exposure_risk is not None and exposure_risk >= settings.exposure_review_threshold:
        reasons.append(f"Exposure risk {exposure_risk} at or above review threshold")
    if (
        identity_supplied
        and identity.get("identity_confidence", 100)
        < settings.identity_minimum_confidence
        and not identity.get("ownership_mismatch")
    ):
        reasons.append("Identity confidence is below the required minimum")
    return reasons


def _classify(threat: ThreatScoreResult, settings: Settings) -> ThreatClassification:
    if not threat.has_evidence:
        return ThreatClassification.UNKNOWN
    if (
        threat.malicious_sources >= 2
        or threat.threat_score >= settings.threat_deny_threshold
    ):
        return ThreatClassification.CONFIRMED_MALICIOUS
    if (
        threat.malicious_sources >= 1
        or threat.threat_score >= settings.threat_review_threshold
    ):
        return ThreatClassification.HIGH_RISK
    if threat.suspicious_sources >= 1 or threat.threat_score >= 10:
        return ThreatClassification.SUSPICIOUS
    if threat.threat_score > 0:
        return ThreatClassification.LOW_RISK
    return ThreatClassification.NO_KNOWN_THREAT


def _decide(
    threat, hard_blocks, review_reasons, exposure, identity, settings, identity_supplied
) -> Decision:
    if hard_blocks:
        return Decision.DENY
    if threat.threat_score >= settings.threat_deny_threshold:
        return Decision.DENY
    if threat.malicious_sources >= 2:
        return Decision.DENY
    if threat.successful_sources < settings.min_successful_threat_sources:
        return Decision.INCOMPLETE
    if threat.coverage < settings.min_threat_coverage:
        return Decision.MANUAL_REVIEW
    if threat.threat_score >= settings.threat_review_threshold:
        return Decision.MANUAL_REVIEW
    exposure_risk = exposure.get("exposure_risk")
    if exposure_risk is not None and exposure_risk >= settings.exposure_review_threshold:
        return Decision.MANUAL_REVIEW
    if (
        identity_supplied
        and identity.get("identity_confidence", 100)
        < settings.identity_minimum_confidence
    ):
        return Decision.MANUAL_REVIEW
    if review_reasons:
        return Decision.MANUAL_REVIEW
    return Decision.APPROVE_WITH_CONTROLS


def _controls(decision: Decision, exposure: dict, ipinfo_data: dict | None) -> list[str]:
    controls = list(_BASE_CONTROLS)
    if exposure.get("critical_services"):
        controls.append(
            "Do not expose administrative/database services publicly; restrict to "
            "VPN or bastion access"
        )
    if exposure.get("cves"):
        controls.append("Remediate known CVEs before granting access")
    if ipinfo_data and (ipinfo_data.get("is_vpn") or ipinfo_data.get("is_proxy")):
        controls.append("Treat anonymized-network origin as elevated risk")
    return controls
