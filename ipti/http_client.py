"""Shared async HTTP client and safe retry helper.

Providers share a single :class:`httpx.AsyncClient` with connection pooling,
explicit connect/read timeouts, TLS verification and an identifying User-Agent.
The :func:`request_with_retries` helper retries only on transient failures with
exponential backoff and jitter, and honours ``Retry-After`` on 429.
"""

from __future__ import annotations

import asyncio
import random

import httpx

from .config import Settings
from .exceptions import (
    ProviderRateLimitError,
    ProviderResponseError,
    ProviderTimeoutError,
)
from .logging_config import get_logger

logger = get_logger(__name__)

# Status codes worth retrying (transient server / rate-limit conditions).
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
# Cap on response body we will read, guarding against hostile/huge responses.
_MAX_RESPONSE_BYTES = 5 * 1024 * 1024


def build_client(settings: Settings) -> httpx.AsyncClient:
    """Create a shared async client configured from settings."""
    timeout = httpx.Timeout(
        connect=settings.connect_timeout,
        read=settings.read_timeout,
        write=settings.read_timeout,
        pool=settings.connect_timeout,
    )
    limits = httpx.Limits(
        max_connections=settings.max_concurrency * 2,
        max_keepalive_connections=settings.max_concurrency,
    )
    return httpx.AsyncClient(
        timeout=timeout,
        limits=limits,
        headers={"User-Agent": settings.user_agent},
        follow_redirects=True,
        verify=True,
    )


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None


async def request_with_retries(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    provider: str,
    retries: int,
    headers: dict[str, str] | None = None,
    params: dict[str, str | int | bool] | None = None,
    data: dict[str, str] | None = None,
) -> httpx.Response:
    """Perform an HTTP request with bounded, cautious retries.

    Retries transient failures (429/5xx, timeouts, connection errors) up to
    ``retries`` times with exponential backoff + jitter. Never retries
    4xx client errors other than 429. Raises typed provider exceptions.
    """

    attempt = 0
    last_exc: Exception | None = None
    while attempt <= retries:
        try:
            response = await client.request(
                method, url, headers=headers, params=params, data=data
            )
        except httpx.TimeoutException as exc:
            last_exc = exc
            logger.debug("provider=%s attempt=%d timeout", provider, attempt)
        except httpx.HTTPError as exc:
            last_exc = exc
            logger.debug("provider=%s attempt=%d connection error", provider, attempt)
        else:
            if response.status_code == 429:
                retry_after = _parse_retry_after(response.headers.get("Retry-After"))
                if attempt >= retries:
                    raise ProviderRateLimitError(
                        provider,
                        f"{provider} rate limited (HTTP 429)",
                        retry_after=retry_after,
                    )
                delay = retry_after if retry_after is not None else _backoff(attempt)
                await asyncio.sleep(min(delay, 30.0))
                attempt += 1
                continue
            if response.status_code in _RETRYABLE_STATUS:
                if attempt >= retries:
                    raise ProviderResponseError(
                        provider,
                        f"{provider} returned HTTP {response.status_code}",
                        error_code=f"http_{response.status_code}",
                    )
                await asyncio.sleep(_backoff(attempt))
                attempt += 1
                continue
            # Non-retryable status (including 2xx and 4xx) — return as-is; the
            # provider decides how to interpret it.
            _guard_response_size(response, provider)
            return response

        # Reached only on a caught transient exception.
        if attempt >= retries:
            if isinstance(last_exc, httpx.TimeoutException):
                raise ProviderTimeoutError(provider, f"{provider} request timed out")
            raise ProviderResponseError(
                provider,
                f"{provider} connection error: {type(last_exc).__name__}",
                error_code="connection_error",
            )
        await asyncio.sleep(_backoff(attempt))
        attempt += 1

    # Unreachable, but keeps type checkers happy.
    raise ProviderResponseError(provider, f"{provider} request failed")


def _backoff(attempt: int) -> float:
    """Exponential backoff with full jitter, base 0.5s."""
    return random.uniform(0.0, min(0.5 * (2**attempt), 8.0))


def _guard_response_size(response: httpx.Response, provider: str) -> None:
    length = response.headers.get("Content-Length")
    if length is not None:
        try:
            if int(length) > _MAX_RESPONSE_BYTES:
                raise ProviderResponseError(
                    provider, f"{provider} response too large ({length} bytes)"
                )
        except ValueError:
            pass
