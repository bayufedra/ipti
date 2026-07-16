"""AlienVault OTX provider.

Evaluates *all* relevant pulses (not just ``pulses[0]``), distinguishes pulse
*creation* from *modification* time, counts independent authors, and combines
the general + reputation sections. Supports both IPv4 and IPv6 endpoints.

API docs: https://otx.alienvault.com/api (IndicatorTypes IPv4/IPv6)
"""

from __future__ import annotations

from ..models import ProviderResult, ProviderStatus
from ..util import clamp, days_since, parse_iso8601
from .base import (
    IPAddress,
    ThreatIntelligenceProvider,
    parse_json,
    raise_for_common_status,
)

_BASE = "https://otx.alienvault.com/api/v1/indicators/{kind}/{ip}"

# Keywords in pulse names/tags that indicate active, high-severity threats.
_ACTIVE_THREAT_KEYWORDS = (
    "c2",
    "c&c",
    "command and control",
    "botnet",
    "phishing",
    "malware",
    "trojan",
    "ransomware",
    "exploit",
    "credential",
    "stealer",
    "apt",
    "backdoor",
    "scanner",
    "bruteforce",
    "brute force",
    "spam",
)


class AlienVaultOTXProvider(ThreatIntelligenceProvider):
    name = "alienvault_otx"

    async def _analyze(self, ip: IPAddress) -> ProviderResult:
        from ..http_client import request_with_retries

        kind = "IPv6" if ip.version == 6 else "IPv4"
        headers = {"X-OTX-API-KEY": self._api_key}

        general_resp = await request_with_retries(
            self._client,
            "GET",
            _BASE.format(kind=kind, ip=str(ip)) + "/general",
            provider=self.name,
            retries=self._settings.retries,
            headers=headers,
        )
        raise_for_common_status(self.name, general_resp)
        general = parse_json(self.name, general_resp)

        # Reputation is best-effort: never let it fail the whole provider.
        reputation: dict = {}
        try:
            rep_resp = await request_with_retries(
                self._client,
                "GET",
                _BASE.format(kind=kind, ip=str(ip)) + "/reputation",
                provider=self.name,
                retries=0,
                headers=headers,
            )
            if rep_resp.status_code == 200:
                reputation = parse_json(self.name, rep_resp)
        except Exception:
            reputation = {}

        return self._interpret(general, reputation)

    def _interpret(self, general: dict, reputation: dict) -> ProviderResult:
        max_age = self._settings.max_threat_age_days
        pulse_info = general.get("pulse_info") or {}
        pulses = pulse_info.get("pulses") or []
        if not isinstance(pulses, list):
            pulses = []

        analyzed = [
            self._analyze_pulse(p, max_age) for p in pulses if isinstance(p, dict)
        ]
        recent = [p for p in analyzed if p["recent"]]
        relevant = [p for p in analyzed if p["relevant"]]
        recent_relevant = [p for p in analyzed if p["recent"] and p["relevant"]]

        authors_recent = {p["author"] for p in recent_relevant if p["author"]}
        malware_families = sorted({m for p in analyzed for m in p["malware"]})
        matched_keywords = sorted({k for p in recent_relevant for k in p["keywords"]})
        freshness = min(
            (p["age"] for p in analyzed if p["age"] is not None), default=None
        )

        rep_threat = self._reputation_threat(reputation)

        raw = {
            "pulse_count": len(pulses),
            "recent_pulse_count": len(recent),
            "relevant_pulse_count": len(relevant),
            "independent_recent_authors": len(authors_recent),
            "malware_families": malware_families,
            "matched_keywords": matched_keywords,
            "reputation_threat_score": rep_threat,
        }
        reasons: list[str] = []

        # --- Classification ---
        if not pulses and rep_threat in (None, 0):
            return ProviderResult(
                provider=self.name,
                enabled=True,
                status=ProviderStatus.CLEAN,
                risk_score=5.0,
                confidence=0.7,
                data_freshness_days=freshness,
                reasons=["No active recent threat pulses were found"],
                raw_metrics=raw,
            )

        strong_reputation = rep_threat is not None and rep_threat >= 4
        malicious = bool(recent_relevant) and (
            len(authors_recent) >= 2 or bool(malware_families) or strong_reputation
        )

        risk = clamp(
            len(recent_relevant) * 20.0
            + len(malware_families) * 10.0
            + len(matched_keywords) * 8.0
            + (rep_threat or 0) * 8.0
        )
        confidence = clamp(
            0.45 + 0.1 * len(authors_recent) + 0.05 * min(len(recent_relevant), 4),
            high=0.9,
        )

        if malicious:
            status = ProviderStatus.MALICIOUS
            risk = clamp(max(risk, 70.0))
            reasons.append(
                f"{len(recent_relevant)} recent relevant pulse(s) from "
                f"{len(authors_recent)} independent author(s)"
            )
            if malware_families:
                reasons.append("Associated malware: " + ", ".join(malware_families))
            if matched_keywords:
                reasons.append("Threat indicators: " + ", ".join(matched_keywords))
        elif recent_relevant:
            status = ProviderStatus.SUSPICIOUS
            risk = clamp(max(risk, 30.0))
            reasons.append(f"{len(recent_relevant)} recent relevant pulse(s) found")
            if matched_keywords:
                reasons.append("Threat indicators: " + ", ".join(matched_keywords))
        elif relevant:
            # Historical, potentially-still-relevant evidence, but not recent.
            status = ProviderStatus.STALE
            risk = clamp(max(risk * 0.5, 20.0))
            confidence = clamp(confidence * 0.6, high=0.6)
            reasons.append(
                f"{len(relevant)} relevant pulse(s), all older than {max_age} days"
            )
        else:
            # Pulses exist but carry no active threat context (e.g. allow-lists).
            status = ProviderStatus.CLEAN
            risk = 8.0
            confidence = 0.6
            reasons.append(f"{len(pulses)} pulse(s), none with active threat context")

        if rep_threat:
            reasons.append(f"OTX reputation threat score {rep_threat}")

        return ProviderResult(
            provider=self.name,
            enabled=True,
            status=status,
            risk_score=risk,
            confidence=confidence,
            data_freshness_days=freshness,
            reasons=reasons,
            threat_categories=matched_keywords + malware_families,
            raw_metrics=raw,
        )

    def _analyze_pulse(self, pulse: dict, max_age: int) -> dict:
        created = parse_iso8601(pulse.get("created"))
        age = days_since(created)
        name = str(pulse.get("name", "")).lower()
        tags = [str(t).lower() for t in (pulse.get("tags") or [])]
        haystack = name + " " + " ".join(tags)
        keywords = [k for k in _ACTIVE_THREAT_KEYWORDS if k in haystack]
        malware = [str(m) for m in (pulse.get("malware_families") or []) if m]
        # Extract malware family names when given as objects.
        malware = [m if isinstance(m, str) else str(m) for m in malware]
        relevant = bool(keywords or malware)
        return {
            "author": pulse.get("author_name"),
            "created": created,
            "age": age,
            "recent": age is not None and age <= max_age,
            "relevant": relevant,
            "keywords": keywords,
            "malware": malware,
        }

    @staticmethod
    def _reputation_threat(reputation: dict) -> int | None:
        rep = reputation.get("reputation") if isinstance(reputation, dict) else None
        if not isinstance(rep, dict):
            return None
        score = rep.get("threat_score")
        if isinstance(score, (int, float)):
            return int(score)
        return None
