"""IP address validation and input safety.

Uses the standard library :mod:`ipaddress` module. By default, only globally
routable public addresses are permitted for threat-intelligence checks. Private,
loopback, link-local, multicast, reserved, unspecified and documentation ranges
are rejected unless the caller explicitly opts in.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import AddressValueError, IPv4Address, IPv6Address, ip_address

from .exceptions import ValidationError

MAX_INPUT_FILE_BYTES = 5 * 1024 * 1024  # 5 MiB guard against oversized inputs


@dataclass(frozen=True)
class ValidatedIP:
    """A normalized, validated IP address."""

    original: str
    address: IPv4Address | IPv6Address

    @property
    def normalized(self) -> str:
        return str(self.address)

    @property
    def version(self) -> int:
        return self.address.version


def _classification(addr: IPv4Address | IPv6Address) -> str | None:
    """Return a reason string if the address is not globally routable, else None."""
    if addr.is_unspecified:
        return "unspecified address"
    if addr.is_loopback:
        return "loopback address"
    if addr.is_link_local:
        return "link-local address"
    if addr.is_multicast:
        return "multicast address"
    if addr.is_private:
        # is_private also covers reserved/documentation ranges for many inputs.
        return "private or reserved address"
    if addr.is_reserved:
        return "reserved address"
    if not addr.is_global:
        return "non-global address"
    return None


def validate_ip(value: str, *, allow_non_global: bool = False) -> ValidatedIP:
    """Validate and normalize a single IP string.

    Args:
        value: The raw IP string.
        allow_non_global: When True, non-global addresses are permitted
            (used only where technically justified). Truly invalid strings are
            still rejected.

    Raises:
        ValidationError: If the address is malformed or (by default) not global.
    """

    text = (value or "").strip()
    if not text:
        raise ValidationError("Empty IP address")
    # Reject obvious junk early; ipaddress accepts integers/bytes we don't want.
    if any(ch.isspace() for ch in text):
        raise ValidationError(f"Invalid IP address: {value!r}")
    try:
        addr = ip_address(text)
    except (AddressValueError, ValueError) as exc:
        raise ValidationError(
            f"Invalid IP address: {value!r}{_explain_invalid(text)}"
        ) from exc

    if not allow_non_global:
        reason = _classification(addr)
        if reason is not None:
            raise ValidationError(
                f"IP {addr} is a {reason}; public threat checks require a "
                f"globally routable address (use allow_non_global to override)"
            )
    return ValidatedIP(original=text, address=addr)


def _explain_invalid(text: str) -> str:
    """Return a parenthetical reason (e.g. octet out of range) when available."""
    try:
        if ":" in text:
            IPv6Address(text)
        elif text.count(".") == 3:
            IPv4Address(text)
    except AddressValueError as exc:
        # e.g. "Octet 302 (> 255) not permitted in '157.245.302.1'"
        return f" ({exc})"
    return ""


def normalize_ip_list(values: list[str]) -> list[str]:
    """Trim, drop blanks/comments and de-duplicate while preserving order.

    De-duplication is done on the raw string; canonical de-duplication is left
    to callers that validate first. Comments start with ``#``.
    """

    seen: set[str] = set()
    result: list[str] = []
    for raw in values:
        item = raw.strip()
        if not item or item.startswith("#"):
            continue
        # Allow inline "1.2.3.4  # note" entries.
        item = item.split("#", 1)[0].strip()
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def read_ip_file(path: str) -> list[str]:
    """Read IPs from a file safely, one per line.

    Guards against oversized files, invalid encodings, blank lines, comments,
    duplicate entries and stray whitespace. Ordering is preserved.
    """

    import os

    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise ValidationError(f"Cannot read IP file {path!r}: {exc}") from exc
    if size > MAX_INPUT_FILE_BYTES:
        raise ValidationError(
            f"IP file {path!r} is too large ({size} bytes > {MAX_INPUT_FILE_BYTES})"
        )
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.readlines()
    except UnicodeDecodeError as exc:
        raise ValidationError(f"IP file {path!r} is not valid UTF-8: {exc}") from exc
    except OSError as exc:
        raise ValidationError(f"Cannot read IP file {path!r}: {exc}") from exc
    return normalize_ip_list(lines)
