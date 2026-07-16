"""Organization policy assessment (geography + provider/network).

Geography and hosting provider are **policy context**, not threat evidence. A
country's presence on a policy list never makes an IP "malicious" and never
mutates the threat score — instead it drives the *decision* toward manual review
or denial, per the organization's own configured lists. By default every list is
empty, so no country or provider is treated as risky out of the box; operators
opt in via ``IPTI_RESTRICTED_COUNTRIES`` / ``IPTI_REQUIRE_APPROVAL_COUNTRIES`` /
``IPTI_EXPECTED_COUNTRIES``.
"""

from __future__ import annotations

from .config import Settings

# Geographic policy states, ordered from most to least concerning.
GEO_RESTRICTED = "restricted"
GEO_REQUIRE_APPROVAL = "require_approval"
GEO_UNEXPECTED = "unexpected"
GEO_EXPECTED = "expected"
GEO_NEUTRAL = "neutral"
GEO_UNKNOWN = "unknown"


def assess_policy(ipinfo_data: dict | None, settings: Settings) -> dict:
    """Evaluate geographic and provider policy for display and decisioning."""
    country = (ipinfo_data or {}).get("country")
    cc = country.upper() if isinstance(country, str) and country else None

    status, reason = _geographic_status(cc, settings)
    asn_type = (ipinfo_data or {}).get("asn_type")
    org = (ipinfo_data or {}).get("org") or (ipinfo_data or {}).get("asn_name")

    return {
        "country": country,
        "geographic_policy": status,
        "geographic_reason": reason,
        "network_type": asn_type or "unknown",
        "provider": org,
        "provider_context": _provider_context(asn_type, org),
    }


def _geographic_status(cc: str | None, settings: Settings) -> tuple[str, str]:
    if cc is None:
        return GEO_UNKNOWN, "Country is unknown (enable IPInfo for geographic policy)"
    if cc in settings.restricted_countries:
        return GEO_RESTRICTED, f"{cc} is on the restricted-countries policy list"
    if cc in settings.require_approval_countries:
        return GEO_REQUIRE_APPROVAL, f"{cc} requires approval per organization policy"
    if settings.expected_countries:
        if cc in settings.expected_countries:
            return GEO_EXPECTED, f"{cc} is within the expected-countries list"
        return GEO_UNEXPECTED, f"{cc} is outside the expected-countries list"
    return GEO_NEUTRAL, f"{cc} is not on any policy list"


def _provider_context(asn_type: object, org: object) -> str:
    """Neutral description of the hosting/network — never a threat verdict."""
    parts: list[str] = []
    if org:
        parts.append(str(org))
    if isinstance(asn_type, str) and asn_type:
        parts.append(f"network type: {asn_type}")
    return " — ".join(parts) if parts else "unknown"
