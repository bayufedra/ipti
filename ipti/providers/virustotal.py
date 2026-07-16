"""VirusTotal provider.

Undetected/timeout engines are *not* counted as clean votes. Detection is
measured against the opinionated denominator only, and community reputation is
supporting evidence rather than a standalone malicious verdict.

API docs: https://docs.virustotal.com/reference/ip-object
"""

from __future__ import annotations

from datetime import datetime, timezone

from ..models import ProviderResult, ProviderStatus
from ..util import clamp
from .base import (
    IPAddress,
    ThreatIntelligenceProvider,
    parse_json,
    raise_for_common_status,
)

_ENDPOINT = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"


class VirusTotalProvider(ThreatIntelligenceProvider):
    name = "virustotal"

    async def _analyze(self, ip: IPAddress) -> ProviderResult:
        from ..http_client import request_with_retries

        response = await request_with_retries(
            self._client,
            "GET",
            _ENDPOINT.format(ip=str(ip)),
            provider=self.name,
            retries=self._settings.retries,
            headers={"x-apikey": self._api_key, "accept": "application/json"},
        )
        raise_for_common_status(self.name, response)
        payload = parse_json(self.name, response)
        attributes = (payload.get("data") or {}).get("attributes")
        if not isinstance(attributes, dict):
            return ProviderResult(
                provider=self.name,
                enabled=True,
                status=ProviderStatus.UNKNOWN,
                reasons=["VirusTotal response contained no attributes"],
            )
        return self._interpret(attributes)

    def _interpret(self, attributes: dict) -> ProviderResult:
        stats = attributes.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)
        undetected = int(stats.get("undetected", 0) or 0)
        timeout = int(stats.get("timeout", 0) or 0)

        # Undetected/timeout engines are excluded from the clean denominator.
        opinionated = malicious + suspicious + harmless
        detection_ratio = (malicious + suspicious * 0.5) / max(opinionated, 1)

        reputation = int(attributes.get("reputation", 0) or 0)
        max_age = self._settings.max_threat_age_days
        freshness = self._freshness_days(attributes.get("last_analysis_date"))
        recent = freshness is not None and freshness <= max_age

        raw = {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "timeout": timeout,
            "opinionated_engines": opinionated,
            "detection_ratio": round(detection_ratio, 4),
            "reputation": reputation,
            "as_owner": attributes.get("as_owner"),
            "asn": attributes.get("asn"),
            "tags": attributes.get("tags", []),
        }
        reasons = [
            f"{malicious} engines flagged malicious, {suspicious} suspicious, "
            f"{harmless} harmless ({opinionated} opinionated, "
            f"{undetected} undetected)",
            f"Detection ratio {detection_ratio:.2%}",
        ]
        if reputation:
            reasons.append(f"Community reputation {reputation}")
        if freshness is not None:
            reasons.append(f"Last analysis was {freshness} days ago")

        # --- Classification ---
        if opinionated == 0:
            return ProviderResult(
                provider=self.name,
                enabled=True,
                status=ProviderStatus.UNKNOWN,
                risk_score=None,
                confidence=0.0,
                data_freshness_days=freshness,
                reasons=["No VirusTotal engine expressed a usable opinion"],
                raw_metrics=raw,
            )

        malicious_class = malicious >= 5 or (
            malicious >= 3 and detection_ratio >= 0.10 and recent
        )
        material_suspicious = malicious >= 1 or suspicious >= 2 or reputation <= -20

        risk = clamp(
            max(
                detection_ratio * 100.0,
                malicious * 12.0,
                (-reputation) * 0.1 if reputation < 0 else 0.0,
            )
        )
        confidence = clamp(0.35 + opinionated / 60.0, high=0.95)

        if malicious_class:
            status = ProviderStatus.MALICIOUS
            risk = clamp(max(risk, 70.0))
        elif material_suspicious and freshness is not None and freshness > max_age:
            status = ProviderStatus.STALE
            reasons.append("Detections exist but the analysis is stale")
            confidence = clamp(confidence * 0.6, high=0.6)
        elif material_suspicious:
            status = ProviderStatus.SUSPICIOUS
            risk = clamp(max(risk, 30.0))
        else:
            status = ProviderStatus.CLEAN
            risk = clamp(detection_ratio * 100.0)
            if not recent and freshness is not None:
                confidence = clamp(confidence * 0.7)
                reasons.append(
                    "Clean, but the last analysis is older than the configured window"
                )

        return ProviderResult(
            provider=self.name,
            enabled=True,
            status=status,
            risk_score=risk,
            confidence=confidence,
            data_freshness_days=freshness,
            reasons=reasons,
            threat_categories=list(attributes.get("tags", []) or []),
            raw_metrics=raw,
        )

    @staticmethod
    def _freshness_days(epoch: object) -> int | None:
        if not isinstance(epoch, (int, float)):
            return None
        try:
            observed = datetime.fromtimestamp(float(epoch), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
        return max(0, (datetime.now(timezone.utc) - observed).days)
