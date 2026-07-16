"""IPInfo enrichment provider (optional).

Provides geolocation, ASN/ownership and — on paid plans — privacy detection.
Privacy fields are normalized to ``None`` when the plan/response does not
include them; unavailable is never coerced to ``False``. Geography is treated as
policy context, never as direct malicious evidence.

API docs: https://ipinfo.io/developers
"""

from __future__ import annotations

from typing import Any

from ..models import EnrichmentResult, ProviderStatus
from .base import EnrichmentProvider, IPAddress, parse_json, raise_for_common_status

_ENDPOINT = "https://ipinfo.io/{ip}/json"


def _as_dict(value: object) -> dict[str, Any]:
    """Return ``value`` if it is a dict, else an empty dict (typed for mypy)."""
    return value if isinstance(value, dict) else {}


class IPInfoProvider(EnrichmentProvider):
    name = "ipinfo"

    async def _enrich(self, ip: IPAddress) -> EnrichmentResult:
        from ..http_client import request_with_retries

        response = await request_with_retries(
            self._client,
            "GET",
            _ENDPOINT.format(ip=str(ip)),
            provider=self.name,
            retries=self._settings.retries,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Accept": "application/json",
            },
        )
        raise_for_common_status(self.name, response)
        payload = parse_json(self.name, response)
        return EnrichmentResult(
            provider=self.name,
            enabled=True,
            status=ProviderStatus.CLEAN,
            data=self._normalize(payload),
            reasons=["IPInfo enrichment retrieved"],
        )

    @staticmethod
    def _normalize(payload: dict) -> dict:
        privacy = _as_dict(payload.get("privacy"))
        asn_obj = _as_dict(payload.get("asn"))
        company = _as_dict(payload.get("company"))

        org = payload.get("org") or ""
        asn_number = asn_obj.get("asn") or _asn_from_org(org)
        asn_type = asn_obj.get("type") or company.get("type")

        def flag(key: str) -> bool | None:
            # ``None`` when privacy data is unavailable; never coerce to False.
            if key in privacy:
                return bool(privacy[key])
            return None

        return {
            "country": payload.get("country"),
            "region": payload.get("region"),
            "city": payload.get("city"),
            "org": org or None,
            "asn": asn_number,
            "asn_name": asn_obj.get("name") or company.get("name"),
            "asn_type": asn_type,
            "hostname": payload.get("hostname"),
            "is_vpn": flag("vpn"),
            "is_proxy": flag("proxy"),
            "is_tor": flag("tor"),
            "is_relay": flag("relay"),
            "is_hosting": flag("hosting"),
            "is_residential_proxy": (
                bool(privacy["service"]) if privacy.get("service") else None
            )
            if "service" in privacy
            else None,
            "service_name": privacy.get("service") or None,
        }


def _asn_from_org(org: str) -> str | None:
    """IPInfo free tier embeds the ASN in ``org`` like ``AS15169 Google LLC``."""
    if org.upper().startswith("AS"):
        token = org.split(" ", 1)[0]
        return token if token[2:].isdigit() else None
    return None
