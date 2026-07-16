"""Provider base classes and shared helpers.

Every threat-intelligence provider implements :class:`ThreatIntelligenceProvider`
and returns a normalized :class:`~ipti.models.ProviderResult`. Enrichment
providers implement :class:`EnrichmentProvider` and return an
:class:`~ipti.models.EnrichmentResult`. Providers own their own endpoint
construction and response parsing, validate expected fields, never expose API
tokens, and translate transport/parse failures into normalized results — a
single provider failing must never abort the whole assessment.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv6Address

import httpx

from ..config import Settings
from ..exceptions import (
    ProviderAuthError,
    ProviderError,
    ProviderRateLimitError,
    ProviderResponseError,
    ProviderTimeoutError,
)
from ..logging_config import get_logger
from ..models import EnrichmentResult, ProviderResult, ProviderStatus

logger = get_logger(__name__)

IPAddress = IPv4Address | IPv6Address


class _BaseProvider(ABC):
    """Shared plumbing for both threat and enrichment providers."""

    name: str

    def __init__(self, client: httpx.AsyncClient, settings: Settings) -> None:
        self._client = client
        self._settings = settings
        self._api_key = settings.providers[self.name].api_key or ""

    def _auth_error_to_status(self, exc: ProviderError) -> ProviderStatus:
        if isinstance(exc, ProviderRateLimitError):
            return ProviderStatus.RATE_LIMITED
        if isinstance(exc, ProviderTimeoutError):
            return ProviderStatus.TIMEOUT
        return ProviderStatus.ERROR

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)


class ThreatIntelligenceProvider(_BaseProvider):
    """Abstract base for the three threat-intelligence providers."""

    async def analyze(self, ip: IPAddress) -> ProviderResult:
        """Query the provider and return a normalized result.

        This wrapper enforces uniform timing, error normalization and secret
        hygiene; subclasses implement :meth:`_analyze`.
        """

        started = time.perf_counter()
        queried_at = self._now()
        try:
            result = await self._analyze(ip)
        except ProviderAuthError as exc:
            return self._failure(
                queried_at, started, ProviderStatus.ERROR, exc.error_code, str(exc)
            )
        except ProviderError as exc:
            return self._failure(
                queried_at,
                started,
                self._auth_error_to_status(exc),
                exc.error_code,
                str(exc),
            )
        except Exception as exc:
            logger.warning(
                "provider=%s unexpected error: %s", self.name, type(exc).__name__
            )
            return self._failure(
                queried_at,
                started,
                ProviderStatus.ERROR,
                "unexpected",
                f"{type(exc).__name__}",
            )
        result.queried_at = queried_at
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        return result

    def _failure(
        self,
        queried_at: datetime,
        started: float,
        status: ProviderStatus,
        code: str,
        message: str,
    ) -> ProviderResult:
        return ProviderResult(
            provider=self.name,
            enabled=True,
            status=status,
            risk_score=None,
            confidence=0.0,
            queried_at=queried_at,
            duration_ms=int((time.perf_counter() - started) * 1000),
            reasons=[message],
            error_code=code,
            error_message=message,
        )

    @abstractmethod
    async def _analyze(self, ip: IPAddress) -> ProviderResult:
        """Provider-specific implementation returning a normalized result."""
        raise NotImplementedError


class EnrichmentProvider(_BaseProvider):
    """Abstract base for optional enrichment providers (IPInfo/Shodan)."""

    async def enrich(self, ip: IPAddress) -> EnrichmentResult:
        started = time.perf_counter()
        queried_at = self._now()
        try:
            result = await self._enrich(ip)
        except ProviderError as exc:
            return EnrichmentResult(
                provider=self.name,
                enabled=True,
                status=self._auth_error_to_status(exc),
                queried_at=queried_at,
                duration_ms=int((time.perf_counter() - started) * 1000),
                reasons=[str(exc)],
                error_code=exc.error_code,
                error_message=str(exc),
            )
        except Exception as exc:
            logger.warning(
                "provider=%s unexpected error: %s", self.name, type(exc).__name__
            )
            return EnrichmentResult(
                provider=self.name,
                enabled=True,
                status=ProviderStatus.ERROR,
                queried_at=queried_at,
                duration_ms=int((time.perf_counter() - started) * 1000),
                reasons=[type(exc).__name__],
                error_code="unexpected",
                error_message=type(exc).__name__,
            )
        result.queried_at = queried_at
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        return result

    @abstractmethod
    async def _enrich(self, ip: IPAddress) -> EnrichmentResult:
        raise NotImplementedError


def raise_for_common_status(provider: str, response: httpx.Response) -> None:
    """Translate common non-2xx statuses into typed provider exceptions.

    404 is intentionally *not* raised here: for several providers a 404 means
    "no data on this IP" which is a valid, non-error state the caller handles.
    """

    code = response.status_code
    if code in (401, 403):
        raise ProviderAuthError(
            provider,
            f"{provider} authentication failed (HTTP {code})",
            error_code=f"http_{code}",
        )
    if code == 429:
        raise ProviderRateLimitError(provider, f"{provider} rate limited (HTTP 429)")
    if code >= 400 and code != 404:
        raise ProviderResponseError(
            provider, f"{provider} returned HTTP {code}", error_code=f"http_{code}"
        )


def parse_json(provider: str, response: httpx.Response) -> dict:
    """Parse a JSON body, raising a typed error on malformed content."""
    try:
        payload = response.json()
    except ValueError as exc:
        raise ProviderResponseError(
            provider, f"{provider} returned malformed JSON", error_code="malformed_json"
        ) from exc
    if not isinstance(payload, dict):
        raise ProviderResponseError(
            provider,
            f"{provider} returned unexpected JSON shape",
            error_code="unexpected_shape",
        )
    return payload
