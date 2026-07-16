"""Assessment engine.

Orchestrates validation, concurrent provider execution (fault-isolated via
``asyncio.gather(return_exceptions=True)``), enrichment, scoring and the final
decision into a single :class:`~ipti.models.Assessment`. One provider failing
never aborts the others, and disabled providers are never queried or counted.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone

import httpx

from .config import ENRICHMENT_PROVIDERS, THREAT_PROVIDERS, Settings
from .decision import decide
from .enrichment import analyze_ptr, assess_exposure, assess_identity, merge_privacy
from .exceptions import ValidationError
from .http_client import build_client
from .logging_config import get_logger
from .models import (
    Assessment,
    Decision,
    EnrichmentResult,
    PlatformSummary,
    ProviderResult,
    ProviderStatus,
    PtrResult,
    Scores,
    ThreatClassification,
)
from .policy import assess_policy
from .providers import ENRICHMENT_PROVIDER_CLASSES, THREAT_PROVIDER_CLASSES
from .scoring import compute_threat_score
from .validation import validate_ip

logger = get_logger(__name__)

SCHEMA_VERSION = "2.0"

# Human-friendly names used in warnings.
_DISPLAY = {
    "abuseipdb": "AbuseIPDB",
    "virustotal": "VirusTotal",
    "alienvault_otx": "AlienVault OTX",
    "ipinfo": "IPInfo",
    "shodan": "Shodan",
}


class AssessmentEngine:
    """Runs assessments against configured providers."""

    def __init__(self, settings: Settings, *, client: httpx.AsyncClient | None = None):
        self._settings = settings
        self._client = client
        self._owns_client = client is None
        self._resolved = settings.resolved_providers()
        # cache: (provider, ip) -> (expiry_monotonic, result). No lock needed:
        # asyncio is single-threaded and these are plain dict get/set.
        self._cache: dict[tuple[str, str], tuple[float, object]] = {}

    async def __aenter__(self) -> AssessmentEngine:
        self._ensure_client()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = build_client(self._settings)
        return self._client

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    # -- Public API ---------------------------------------------------------

    async def assess(self, ip: str, *, claimed_owner: str | None = None) -> Assessment:
        checked_at = datetime.now(timezone.utc)
        warnings = self._config_warnings()

        try:
            validated = validate_ip(ip, allow_non_global=self._settings.allow_non_global)
        except ValidationError as exc:
            return self._not_applicable(ip, checked_at, str(exc), warnings)

        self._ensure_client()
        threat_results, enrichment_results, ptr_result = await self._gather(validated)

        ipinfo_data = self._enrichment_data(enrichment_results.get("ipinfo"))
        shodan_data = self._enrichment_data(enrichment_results.get("shodan"))

        # Merge anonymization signals: IPInfo privacy (paid) + AbuseIPDB Tor (free).
        abuse = threat_results.get("abuseipdb")
        abuse_tor = bool(abuse and abuse.raw_metrics.get("is_tor"))
        anonymization = merge_privacy(ipinfo_data, abuseipdb_tor=abuse_tor)

        threat = compute_threat_score(threat_results, self._settings)
        exposure = assess_exposure(shodan_data, anonymization)
        identity = assess_identity(ipinfo_data, ptr_result, claimed_owner)
        policy = assess_policy(ipinfo_data, self._settings)

        result = decide(
            threat=threat,
            all_results=threat_results,
            exposure=exposure,
            identity=identity,
            ipinfo_data=anonymization,
            settings=self._settings,
            identity_supplied=claimed_owner is not None,
            policy=policy,
        )

        warnings.extend(self._runtime_warnings(threat_results, threat))
        warnings.extend(
            self._privacy_warnings(enrichment_results.get("ipinfo"), ipinfo_data)
        )

        return Assessment(
            schema_version=SCHEMA_VERSION,
            ip=validated.normalized,
            ip_version=validated.version,
            checked_at=checked_at,
            decision=result.decision,
            threat_classification=result.classification,
            scores=Scores(
                threat=threat.threat_score,
                identity_confidence=identity.get("identity_confidence"),
                exposure_risk=exposure.get("exposure_risk"),
                evidence_coverage=threat.coverage,
            ),
            platform_summary=self._platform_summary(threat_results),
            providers=threat_results,
            enrichment=self._enrichment_output(
                enrichment_results,
                ptr_result,
                exposure,
                identity,
                policy,
                anonymization,
            ),
            hard_blocks=result.hard_blocks,
            review_reasons=result.review_reasons,
            recommended_controls=result.recommended_controls,
            warnings=warnings,
        )

    async def assess_many(
        self, ips: list[str], *, claimed_owner: str | None = None
    ) -> list[Assessment]:
        """Assess many IPs with bounded concurrency, preserving input order."""
        from .validation import normalize_ip_list

        ordered = normalize_ip_list(ips)
        semaphore = asyncio.Semaphore(self._settings.max_concurrency)

        async def _one(ip: str) -> Assessment:
            async with semaphore:
                return await self.assess(ip, claimed_owner=claimed_owner)

        self._ensure_client()
        return await asyncio.gather(*(_one(ip) for ip in ordered))

    # -- Internal orchestration --------------------------------------------

    async def _gather(
        self, validated
    ) -> tuple[dict[str, ProviderResult], dict[str, EnrichmentResult | None], PtrResult]:
        addr = validated.address
        tasks: list[asyncio.Future] = []
        labels: list[str] = []

        for name in THREAT_PROVIDERS:
            if self._resolved[name].enabled:
                tasks.append(asyncio.ensure_future(self._run_threat(name, addr)))
                labels.append(f"threat:{name}")
        for name in ENRICHMENT_PROVIDERS:
            if self._resolved[name].enabled:
                tasks.append(asyncio.ensure_future(self._run_enrichment(name, addr)))
                labels.append(f"enrich:{name}")
        tasks.append(asyncio.ensure_future(analyze_ptr(validated.normalized)))
        labels.append("ptr")

        gathered = await asyncio.gather(*tasks, return_exceptions=True)

        threat_results: dict[str, ProviderResult] = {}
        enrichment_results: dict[str, EnrichmentResult | None] = {}
        ptr_result = PtrResult(
            status=self._ptr_error_status(), reasons=["PTR unavailable"]
        )

        for label, outcome in zip(labels, gathered, strict=True):
            kind, _, name = label.partition(":")
            if isinstance(outcome, BaseException):
                logger.warning("task=%s crashed: %s", label, type(outcome).__name__)
                if kind == "threat":
                    threat_results[name] = self._error_result(name)
                elif kind == "enrich":
                    enrichment_results[name] = None
                continue
            if kind == "threat":
                threat_results[name] = outcome
            elif kind == "enrich":
                enrichment_results[name] = outcome
            else:
                ptr_result = outcome

        # Fill in disabled/unqueried threat providers with synthetic results.
        for name in THREAT_PROVIDERS:
            threat_results.setdefault(name, self._disabled_result(name))
        return threat_results, enrichment_results, ptr_result

    async def _run_threat(self, name: str, addr) -> ProviderResult:
        cached = self._cache_get(name, str(addr))
        if isinstance(cached, ProviderResult):
            return cached
        provider = THREAT_PROVIDER_CLASSES[name](self._ensure_client(), self._settings)
        result = await provider.analyze(addr)
        self._cache_put(name, str(addr), result)
        return result

    async def _run_enrichment(self, name: str, addr) -> EnrichmentResult:
        cached = self._cache_get(name, str(addr))
        if isinstance(cached, EnrichmentResult):
            return cached
        provider = ENRICHMENT_PROVIDER_CLASSES[name](
            self._ensure_client(), self._settings
        )
        result = await provider.enrich(addr)
        self._cache_put(name, str(addr), result)
        return result

    # -- Caching ------------------------------------------------------------

    def _cache_get(self, provider: str, ip: str) -> object | None:
        entry = self._cache.get((provider, ip))
        if entry is None:
            return None
        expiry, value = entry
        if time.monotonic() >= expiry:
            self._cache.pop((provider, ip), None)
            return None
        logger.debug("cache hit provider=%s ip=%s", provider, ip)
        return value

    def _cache_put(self, provider: str, ip: str, result: object) -> None:
        ttl = self._cache_ttl_for(result)
        if ttl <= 0:
            return
        self._cache[(provider, ip)] = (time.monotonic() + ttl, result)

    def _cache_ttl_for(self, result: object) -> int:
        status = getattr(result, "status", None)
        error_code = getattr(result, "error_code", None)
        # Never cache auth failures as anything (they must not look clean later).
        if error_code in {"http_401", "http_403"}:
            return 0
        if isinstance(status, ProviderStatus) and status.is_operational_failure:
            return self._settings.error_cache_ttl_seconds
        return self._settings.cache_ttl_seconds

    # -- Result construction helpers ---------------------------------------

    def _disabled_result(self, name: str) -> ProviderResult:
        resolved = self._resolved[name]
        status = resolved.status or ProviderStatus.DISABLED_BY_CONFIG
        reason = (
            f"{_DISPLAY[name]} disabled by configuration"
            if status is ProviderStatus.DISABLED_BY_CONFIG
            else f"{name.upper()} API key is not configured"
        )
        return ProviderResult(
            provider=name,
            enabled=False,
            status=status,
            risk_score=None,
            confidence=0.0,
            reasons=[reason],
        )

    def _error_result(self, name: str) -> ProviderResult:
        return ProviderResult(
            provider=name,
            enabled=True,
            status=ProviderStatus.ERROR,
            risk_score=None,
            confidence=0.0,
            error_code="unexpected",
            reasons=["Provider task failed unexpectedly"],
        )

    @staticmethod
    def _ptr_error_status():
        from .models import PtrStatus

        return PtrStatus.ERROR

    def _enrichment_data(self, result: EnrichmentResult | None) -> dict | None:
        if result is None or not result.succeeded:
            return None
        return result.data

    def _platform_summary(
        self, threat_results: dict[str, ProviderResult]
    ) -> PlatformSummary:
        available = len(THREAT_PROVIDERS)
        enabled = [r for r in threat_results.values() if r.enabled]
        succeeded = [r for r in enabled if not r.status.is_operational_failure]
        failed = [r for r in enabled if r.status.is_operational_failure]
        return PlatformSummary(
            platforms_available=available,
            platforms_enabled=len(enabled),
            platforms_disabled=available - len(enabled),
            platforms_queried=len(enabled),
            platforms_succeeded=len(succeeded),
            platforms_failed=len(failed),
        )

    def _enrichment_output(
        self,
        enrichment_results,
        ptr_result: PtrResult,
        exposure: dict,
        identity: dict,
        policy: dict,
        anonymization: dict,
    ) -> dict:
        def render(name: str) -> dict:
            result = enrichment_results.get(name)
            if result is None:
                resolved = self._resolved[name]
                status = resolved.status or ProviderStatus.DISABLED_BY_CONFIG
                return {"enabled": resolved.enabled, "status": status.value, "data": {}}
            return {
                "enabled": result.enabled,
                "status": result.status.value,
                "data": result.data,
                "reasons": result.reasons,
            }

        return {
            "ipinfo": render("ipinfo"),
            "shodan": render("shodan"),
            "ptr": {
                "status": ptr_result.status.value,
                "ptr": ptr_result.ptr,
                "forward_addresses": ptr_result.forward_addresses,
                "reasons": ptr_result.reasons,
            },
            "exposure": exposure,
            "identity": identity,
            "policy": policy,
            "anonymization": anonymization,
        }

    # -- Warnings -----------------------------------------------------------

    def _config_warnings(self) -> list[str]:
        warnings: list[str] = []
        for name in THREAT_PROVIDERS + ENRICHMENT_PROVIDERS:
            resolved = self._resolved[name]
            if resolved.warning:
                warnings.append(resolved.warning)
            elif resolved.status is ProviderStatus.DISABLED_MISSING_CREDENTIALS:
                warnings.append(
                    f"{_DISPLAY[name]} was disabled because no API token was configured"
                )
        return warnings

    def _runtime_warnings(self, threat_results, threat) -> list[str]:
        warnings: list[str] = []
        if self._settings.min_successful_threat_sources == 1:
            warnings.append(
                "Operating with a single required threat source; "
                "results have reduced confidence"
            )
        if not threat.has_evidence:
            warnings.append(
                "No threat-intelligence provider produced usable "
                "evidence; result is INCOMPLETE, not safe"
            )
        return warnings

    def _privacy_warnings(self, ipinfo_result, ipinfo_data: dict | None) -> list[str]:
        """Warn when IPInfo is enabled but its plan omits privacy detection."""
        if ipinfo_result is None or ipinfo_data is None:
            return []
        privacy_keys = ("is_vpn", "is_proxy", "is_tor", "is_relay", "is_hosting")
        if all(ipinfo_data.get(key) is None for key in privacy_keys):
            return [
                "IPInfo returned no VPN/proxy/Tor/hosting data (this token's plan "
                "lacks privacy detection); those flags show 'unknown'. Tor is still "
                "checked via AbuseIPDB."
            ]
        return []

    def _not_applicable(
        self, ip: str, checked_at, message: str, warnings: list[str]
    ) -> Assessment:
        return Assessment(
            schema_version=SCHEMA_VERSION,
            ip=ip,
            ip_version=None,
            checked_at=checked_at,
            decision=Decision.NOT_APPLICABLE,
            threat_classification=ThreatClassification.UNKNOWN,
            scores=Scores(
                threat=0.0,
                identity_confidence=None,
                exposure_risk=None,
                evidence_coverage=0.0,
            ),
            platform_summary=PlatformSummary(
                len(THREAT_PROVIDERS), 0, len(THREAT_PROVIDERS), 0, 0, 0
            ),
            providers={},
            enrichment={},
            hard_blocks=[],
            review_reasons=[message],
            recommended_controls=[],
            warnings=[*warnings, message],
        )


async def assess_ip(
    ip: str, *, settings: Settings | None = None, claimed_owner: str | None = None
) -> Assessment:
    """Convenience: assess a single IP with a fresh engine."""
    from .config import load_settings

    settings = settings or load_settings()
    async with AssessmentEngine(settings) as engine:
        return await engine.assess(ip, claimed_owner=claimed_owner)
