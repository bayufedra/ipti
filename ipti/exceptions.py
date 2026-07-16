"""Exception hierarchy for IPTI.

All exceptions raised by IPTI derive from :class:`IPTIError` so callers can
catch the whole family with a single ``except``. Provider-level failures are
normally *not* raised out of the engine — they are converted into
:class:`~ipti.models.ProviderResult` objects with an error status so that one
provider failing never aborts the whole assessment. These exception types exist
mainly for the configuration/validation boundary and for internal signalling.
"""

from __future__ import annotations


class IPTIError(Exception):
    """Base class for every error raised by IPTI."""


class ConfigurationError(IPTIError):
    """Raised when settings are missing or fail validation."""


class ValidationError(IPTIError):
    """Raised when an IP address is malformed or not permitted for analysis."""


class ProviderError(IPTIError):
    """Base class for provider-side failures.

    Attributes:
        provider: Name of the provider that failed.
        error_code: Short machine-readable code (e.g. ``"http_401"``).
    """

    def __init__(self, provider: str, message: str, error_code: str = "error") -> None:
        super().__init__(message)
        self.provider = provider
        self.error_code = error_code


class ProviderAuthError(ProviderError):
    """Authentication or authorization failed (HTTP 401/403)."""


class ProviderRateLimitError(ProviderError):
    """The provider reported a rate limit (HTTP 429)."""

    def __init__(
        self,
        provider: str,
        message: str,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(provider, message, error_code="rate_limited")
        self.retry_after = retry_after


class ProviderTimeoutError(ProviderError):
    """The provider request timed out."""

    def __init__(self, provider: str, message: str) -> None:
        super().__init__(provider, message, error_code="timeout")


class ProviderResponseError(ProviderError):
    """The provider returned a malformed or unexpected response."""
