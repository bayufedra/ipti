"""Merge anonymization/privacy signals from multiple providers.

IPInfo's ``privacy`` object (VPN/proxy/Tor/relay/hosting) is a **paid** add-on;
free/basic tokens do not return it, so those fields stay ``None`` (unknown —
never coerced to ``False``). Tor, however, can be detected for free from
AbuseIPDB's ``isTor`` field, so we merge it in here. Each resolved flag records
which provider supplied it.
"""

from __future__ import annotations

_PRIVACY_KEYS = (
    "is_vpn",
    "is_proxy",
    "is_tor",
    "is_relay",
    "is_hosting",
    "is_residential_proxy",
)


def merge_privacy(ipinfo_data: dict | None, *, abuseipdb_tor: bool = False) -> dict:
    """Combine IPInfo privacy fields with AbuseIPDB's Tor signal.

    Args:
        ipinfo_data: Normalized IPInfo data (may be ``None`` if disabled/failed).
        abuseipdb_tor: Whether AbuseIPDB reported the address as a Tor node.

    Returns:
        A dict of tri-state flags (True/False/None) plus a ``sources`` map naming
        the provider behind each known flag.
    """

    data = ipinfo_data or {}
    merged: dict[str, object] = {key: data.get(key) for key in _PRIVACY_KEYS}
    sources: dict[str, str] = {
        key: "ipinfo" for key in _PRIVACY_KEYS if data.get(key) is not None
    }

    # AbuseIPDB confirms Tor even when the IPInfo plan omits privacy detection.
    if abuseipdb_tor and not merged.get("is_tor"):
        merged["is_tor"] = True
        sources["is_tor"] = "abuseipdb"

    merged["service_name"] = data.get("service_name")
    merged["sources"] = sources
    return merged
