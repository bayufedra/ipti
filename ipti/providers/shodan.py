"""Shodan enrichment provider (optional).

Fetches host/service data used for exposure analysis. "No Shodan record" is
represented as UNKNOWN (not clean, not a high safety score). Service banner
context (product/version/CVEs) is preserved so ports can be assessed with
context rather than by number alone.

API docs: https://developer.shodan.io/api
"""

from __future__ import annotations

from ..models import EnrichmentResult, ProviderStatus
from ..util import days_since, parse_iso8601
from .base import EnrichmentProvider, IPAddress, parse_json, raise_for_common_status

_ENDPOINT = "https://api.shodan.io/shodan/host/{ip}"


class ShodanProvider(EnrichmentProvider):
    name = "shodan"

    async def _enrich(self, ip: IPAddress) -> EnrichmentResult:
        from ..http_client import request_with_retries

        response = await request_with_retries(
            self._client,
            "GET",
            _ENDPOINT.format(ip=str(ip)),
            provider=self.name,
            retries=self._settings.retries,
            params={"key": self._api_key},
        )
        if response.status_code == 404:
            # No record is genuine "unknown", never proof that no ports are open.
            return EnrichmentResult(
                provider=self.name,
                enabled=True,
                status=ProviderStatus.UNKNOWN,
                data={"has_record": False, "ports": None},
                reasons=["No Shodan record for this IP (unknown, not clean)"],
            )
        raise_for_common_status(self.name, response)
        payload = parse_json(self.name, response)
        return EnrichmentResult(
            provider=self.name,
            enabled=True,
            status=ProviderStatus.CLEAN,
            data=self._normalize(payload),
            reasons=["Shodan host data retrieved"],
        )

    @staticmethod
    def _normalize(payload: dict) -> dict:
        services = []
        newest = None
        for entry in payload.get("data", []) or []:
            if not isinstance(entry, dict):
                continue
            timestamp = parse_iso8601(entry.get("timestamp"))
            if timestamp and (newest is None or timestamp > newest):
                newest = timestamp
            vulns = entry.get("vulns")
            services.append(
                {
                    "port": entry.get("port"),
                    "transport": entry.get("transport"),
                    "product": entry.get("product"),
                    "version": entry.get("version"),
                    "cpe": entry.get("cpe") or entry.get("cpe23"),
                    "module": (entry.get("_shodan") or {}).get("module"),
                    "cves": sorted(vulns.keys()) if isinstance(vulns, dict) else [],
                    "ssl": bool(entry.get("ssl")),
                    "timestamp": entry.get("timestamp"),
                }
            )
        last_update = parse_iso8601(payload.get("last_update"))
        return {
            "has_record": True,
            "ports": sorted(
                p for p in (payload.get("ports") or []) if isinstance(p, int)
            ),
            "services": services,
            "hostnames": payload.get("hostnames", []),
            "tags": payload.get("tags", []),
            "asn": payload.get("asn"),
            "org": payload.get("org"),
            "isp": payload.get("isp"),
            "os": payload.get("os"),
            "last_update": payload.get("last_update"),
            "data_age_days": days_since(newest or last_update),
        }
