"""Small shared helpers (date parsing, clamping)."""

from __future__ import annotations

from datetime import datetime, timezone


def parse_iso8601(value: str | None) -> datetime | None:
    """Parse an ISO-8601 timestamp into an aware UTC datetime, or None.

    Accepts a trailing ``Z`` and naive timestamps (assumed UTC). Returns None
    for empty/unparseable input rather than raising.
    """
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        # Fall back to date-only ("YYYY-MM-DD").
        try:
            parsed = datetime.strptime(text[:10], "%Y-%m-%d")
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def days_since(moment: datetime | None, *, now: datetime | None = None) -> int | None:
    """Whole days between ``moment`` and now (UTC). None if moment is None."""
    if moment is None:
        return None
    reference = now or datetime.now(timezone.utc)
    return max(0, (reference - moment).days)


def clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))
