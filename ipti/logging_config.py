"""Logging configuration for IPTI.

Library modules use module-level loggers and never call ``basicConfig``.
Configuration happens only through :func:`setup_logging`, which is invoked from
the CLI entry point. A :class:`SecretFilter` redacts anything that looks like an
API token or authorization header from every emitted record.
"""

from __future__ import annotations

import logging
import re

# Patterns that redact secrets from log output. Matches ``key=...`` /
# ``token=...`` / ``apikey=...`` query params and ``Authorization``/``x-apikey``
# style headers. Kept deliberately conservative so it errs toward over-redaction.
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    # bearer <token> — redact the token, keep the scheme word
    re.compile(r"(?i)(bearer)\s+([^\s,;\"']+)"),
    # key=... / token=... query params
    re.compile(r"(?i)(api[_-]?key|apikey|token|key|x-otx-api-key)=([^&\s\"']+)"),
    # Authorization / x-apikey style headers (value may contain spaces)
    re.compile(r"(?i)(authorization|x-apikey|x-otx-api-key|key)\s*[:=]\s*([^,;\"']+)"),
)

_REDACTED = "***REDACTED***"


class SecretFilter(logging.Filter):
    """Redacts API tokens and authorization values from log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - defensive
            return True
        redacted = message
        for pattern in _SECRET_PATTERNS:
            redacted = pattern.sub(lambda m: f"{m.group(1)}={_REDACTED}", redacted)
        if redacted != message:
            record.msg = redacted
            record.args = ()
        return True


def setup_logging(level: int | str = logging.WARNING, *, debug: bool = False) -> None:
    """Configure logging for the ``ipti`` logger tree.

    Called once from the CLI (or an explicit host setup). Reusable library code
    must not call this.
    """

    if debug:
        level = logging.DEBUG

    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    )
    handler.addFilter(SecretFilter())

    root = logging.getLogger("ipti")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    root.propagate = False


def get_logger(name: str) -> logging.Logger:
    """Return a module-level logger under the ``ipti`` namespace."""
    return logging.getLogger(name)
