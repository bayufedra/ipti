"""Typed, validated configuration for IPTI.

This replaces the untyped module-level globals of the original ``config.py``.
Settings are loaded from the environment (optionally via a ``.env`` file) and
validated eagerly so misconfiguration fails fast with a clear message instead of
producing a silently wrong risk score.

A typed-dataclass layer is used (explicitly permitted by the design) rather than
``pydantic-settings`` to keep the runtime dependency surface minimal; all
validation is implemented and unit-tested here.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import Enum

from .exceptions import ConfigurationError
from .models import ProviderStatus

# --- Provider identity -----------------------------------------------------

THREAT_PROVIDERS: tuple[str, ...] = ("abuseipdb", "virustotal", "alienvault_otx")
ENRICHMENT_PROVIDERS: tuple[str, ...] = ("ipinfo", "shodan")
ALL_PROVIDERS: tuple[str, ...] = THREAT_PROVIDERS + ENRICHMENT_PROVIDERS

# Environment variable names per provider (enabled flag + API key).
_ENV_ENABLED: Mapping[str, str] = {
    "abuseipdb": "IPTI_ABUSEIPDB_ENABLED",
    "virustotal": "IPTI_VIRUSTOTAL_ENABLED",
    "alienvault_otx": "IPTI_ALIENVAULT_OTX_ENABLED",
    "ipinfo": "IPTI_IPINFO_ENABLED",
    "shodan": "IPTI_SHODAN_ENABLED",
}
_ENV_KEY: Mapping[str, str] = {
    "abuseipdb": "ABUSEIPDB_API_KEY",
    "virustotal": "VIRUSTOTAL_API_KEY",
    "alienvault_otx": "ALIENVAULT_API_KEY",
    "ipinfo": "IPINFO_API_KEY",
    "shodan": "SHODAN_API_KEY",
}


class Enablement(str, Enum):
    """Tri-state provider enablement."""

    AUTO = "auto"
    TRUE = "true"
    FALSE = "false"

    @classmethod
    def parse(cls, raw: str | None, *, field_name: str) -> Enablement:
        if raw is None or raw.strip() == "":
            return cls.AUTO
        value = raw.strip().lower()
        aliases = {
            "1": "true",
            "yes": "true",
            "on": "true",
            "enable": "true",
            "0": "false",
            "no": "false",
            "off": "false",
            "disable": "false",
        }
        value = aliases.get(value, value)
        try:
            return cls(value)
        except ValueError as exc:
            raise ConfigurationError(
                f"{field_name} must be one of auto/true/false, got {raw!r}"
            ) from exc


@dataclass(frozen=True)
class ProviderConfig:
    """Static configuration for a single provider (before key resolution)."""

    name: str
    enablement: Enablement
    api_key: str | None
    weight: float = 0.0

    def resolve(self) -> ResolvedProvider:
        """Determine whether the provider is enabled and why.

        - ``auto``  → enabled iff a key is present.
        - ``true``  → enabled if a key is present, otherwise
          ``disabled_missing_credentials`` (a warning, never a crash).
        - ``false`` → always disabled, even if a key is present.
        """
        has_key = bool(self.api_key and self.api_key.strip())
        if self.enablement is Enablement.FALSE:
            return ResolvedProvider(
                self,
                enabled=False,
                status=ProviderStatus.DISABLED_BY_CONFIG,
                warning=None,
            )
        if self.enablement is Enablement.AUTO:
            if has_key:
                return ResolvedProvider(self, enabled=True, status=None, warning=None)
            return ResolvedProvider(
                self,
                enabled=False,
                status=ProviderStatus.DISABLED_MISSING_CREDENTIALS,
                warning=None,
            )
        # Enablement.TRUE
        if has_key:
            return ResolvedProvider(self, enabled=True, status=None, warning=None)
        return ResolvedProvider(
            self,
            enabled=False,
            status=ProviderStatus.DISABLED_MISSING_CREDENTIALS,
            warning=(
                f"{self.name} is enabled but {_ENV_KEY[self.name]} is not "
                f"configured; provider disabled"
            ),
        )


@dataclass(frozen=True)
class ResolvedProvider:
    """A provider after enablement resolution."""

    config: ProviderConfig
    enabled: bool
    status: ProviderStatus | None
    warning: str | None

    @property
    def name(self) -> str:
        return self.config.name


@dataclass(frozen=True)
class Settings:
    """Validated runtime settings."""

    providers: dict[str, ProviderConfig]

    # HTTP behavior
    connect_timeout: float = 3.05
    read_timeout: float = 15.0
    retries: int = 2
    cache_ttl_seconds: int = 3600
    error_cache_ttl_seconds: int = 60
    max_concurrency: int = 8
    user_agent: str = "IPTI/2.0 (+https://github.com/bayufedra/ipti)"

    # Evidence requirements
    min_successful_threat_sources: int = 2
    min_threat_coverage: float = 0.67
    max_threat_age_days: int = 90
    allow_stale_evidence: bool = False

    # Thresholds
    threat_review_threshold: float = 30.0
    threat_deny_threshold: float = 70.0
    exposure_review_threshold: float = 60.0
    identity_minimum_confidence: float = 85.0

    # Policy
    restricted_countries: frozenset[str] = frozenset()
    require_approval_countries: frozenset[str] = frozenset()
    expected_countries: frozenset[str] = frozenset()
    block_tor: bool = True
    block_open_proxy: bool = True

    # Behavior
    allow_non_global: bool = False

    def resolved_providers(self) -> dict[str, ResolvedProvider]:
        return {name: cfg.resolve() for name, cfg in self.providers.items()}

    def enabled_threat_providers(self) -> list[str]:
        resolved = self.resolved_providers()
        return [p for p in THREAT_PROVIDERS if resolved[p].enabled]

    def with_overrides(self, **kwargs: object) -> Settings:
        """Return a copy with fields replaced.

        This does **not** re-validate — call :meth:`validate` afterwards when the
        overrides come from untrusted input (e.g. CLI flags).
        """
        return replace(self, **kwargs)  # type: ignore[arg-type]

    def validate(self) -> None:
        """Re-run cross-field validation. Raises :class:`ConfigurationError`."""
        _validate(self)


# --- Loading & validation --------------------------------------------------

# Raw configured weights (need not sum to 1.0; normalized dynamically at score).
_DEFAULT_WEIGHTS: Mapping[str, float] = {
    "abuseipdb": 0.35,
    "virustotal": 0.40,
    "alienvault_otx": 0.25,
}


def _get_float(
    env: Mapping[str, str],
    key: str,
    default: float,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    raw = env.get(key)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{key} must be a number, got {raw!r}") from exc
    if minimum is not None and value < minimum:
        raise ConfigurationError(f"{key} must be >= {minimum}, got {value}")
    if maximum is not None and value > maximum:
        raise ConfigurationError(f"{key} must be <= {maximum}, got {value}")
    return value


def _get_int(
    env: Mapping[str, str],
    key: str,
    default: int,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    raw = env.get(key)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{key} must be an integer, got {raw!r}") from exc
    if minimum is not None and value < minimum:
        raise ConfigurationError(f"{key} must be >= {minimum}, got {value}")
    if maximum is not None and value > maximum:
        raise ConfigurationError(f"{key} must be <= {maximum}, got {value}")
    return value


def _get_bool(env: Mapping[str, str], key: str, default: bool) -> bool:
    raw = env.get(key)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _get_country_set(env: Mapping[str, str], key: str) -> frozenset[str]:
    raw = env.get(key, "")
    return frozenset(code.strip().upper() for code in raw.split(",") if code.strip())


def load_settings(
    env: Mapping[str, str] | None = None,
    *,
    load_dotenv: bool = True,
) -> Settings:
    """Build and validate :class:`Settings` from an environment mapping.

    Args:
        env: Mapping to read from (defaults to ``os.environ``).
        load_dotenv: When True and ``env`` is None, load a local ``.env`` first.
    """

    if env is None:
        if load_dotenv:
            try:
                from dotenv import load_dotenv as _load

                _load()
            except ImportError:  # pragma: no cover - dotenv optional
                pass
        env = os.environ

    providers: dict[str, ProviderConfig] = {}
    for name in ALL_PROVIDERS:
        enablement = Enablement.parse(
            env.get(_ENV_ENABLED[name]), field_name=_ENV_ENABLED[name]
        )
        weight = _get_float(
            env,
            f"IPTI_{name.upper()}_WEIGHT",
            _DEFAULT_WEIGHTS.get(name, 0.0),
            minimum=0.0,
        )
        providers[name] = ProviderConfig(
            name=name,
            enablement=enablement,
            api_key=env.get(_ENV_KEY[name]),
            weight=weight,
        )

    settings = Settings(
        providers=providers,
        connect_timeout=_get_float(
            env, "IPTI_REQUEST_CONNECT_TIMEOUT", 3.05, minimum=0.1, maximum=60.0
        ),
        read_timeout=_get_float(
            env, "IPTI_REQUEST_READ_TIMEOUT", 15.0, minimum=0.1, maximum=120.0
        ),
        retries=_get_int(env, "IPTI_REQUEST_RETRIES", 2, minimum=0, maximum=10),
        cache_ttl_seconds=_get_int(env, "IPTI_CACHE_TTL_SECONDS", 3600, minimum=0),
        error_cache_ttl_seconds=_get_int(
            env, "IPTI_ERROR_CACHE_TTL_SECONDS", 60, minimum=0
        ),
        max_concurrency=_get_int(env, "IPTI_MAX_CONCURRENCY", 8, minimum=1, maximum=64),
        min_successful_threat_sources=_get_int(
            env, "IPTI_MIN_SUCCESSFUL_THREAT_SOURCES", 2, minimum=1, maximum=3
        ),
        min_threat_coverage=_get_float(
            env, "IPTI_MIN_THREAT_COVERAGE", 0.67, minimum=0.0, maximum=1.0
        ),
        max_threat_age_days=_get_int(env, "IPTI_MAX_THREAT_AGE_DAYS", 90, minimum=1),
        allow_stale_evidence=_get_bool(env, "IPTI_ALLOW_STALE_EVIDENCE", False),
        threat_review_threshold=_get_float(
            env, "IPTI_THREAT_REVIEW_THRESHOLD", 30.0, minimum=0.0, maximum=100.0
        ),
        threat_deny_threshold=_get_float(
            env, "IPTI_THREAT_DENY_THRESHOLD", 70.0, minimum=0.0, maximum=100.0
        ),
        exposure_review_threshold=_get_float(
            env, "IPTI_EXPOSURE_REVIEW_THRESHOLD", 60.0, minimum=0.0, maximum=100.0
        ),
        identity_minimum_confidence=_get_float(
            env, "IPTI_IDENTITY_MINIMUM_CONFIDENCE", 85.0, minimum=0.0, maximum=100.0
        ),
        restricted_countries=_get_country_set(env, "IPTI_RESTRICTED_COUNTRIES"),
        require_approval_countries=_get_country_set(
            env, "IPTI_REQUIRE_APPROVAL_COUNTRIES"
        ),
        expected_countries=_get_country_set(env, "IPTI_EXPECTED_COUNTRIES"),
        block_tor=_get_bool(env, "IPTI_BLOCK_TOR", True),
        block_open_proxy=_get_bool(env, "IPTI_BLOCK_OPEN_PROXY", True),
        allow_non_global=_get_bool(env, "IPTI_ALLOW_NON_GLOBAL", False),
    )
    _validate(settings)
    return settings


def _validate(settings: Settings) -> None:
    """Cross-field validation (threshold ordering, weight sanity)."""
    if settings.threat_review_threshold > settings.threat_deny_threshold:
        raise ConfigurationError(
            "IPTI_THREAT_REVIEW_THRESHOLD must be <= IPTI_THREAT_DENY_THRESHOLD "
            f"({settings.threat_review_threshold} > {settings.threat_deny_threshold})"
        )
    if (
        settings.error_cache_ttl_seconds > settings.cache_ttl_seconds
        and settings.cache_ttl_seconds > 0
    ):
        raise ConfigurationError(
            "IPTI_ERROR_CACHE_TTL_SECONDS should not exceed IPTI_CACHE_TTL_SECONDS; "
            "errors must expire at least as fast as successful evidence"
        )
    total_threat_weight = sum(settings.providers[p].weight for p in THREAT_PROVIDERS)
    if total_threat_weight <= 0:
        raise ConfigurationError("The sum of threat-provider weights must be > 0")
