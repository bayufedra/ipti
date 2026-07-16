"""AbuseIPDB provider.

Replaces the original ``score >= t AND numDistinctUsers >= t`` boolean with a
structured, threshold-driven analysis. An abuse score of 100 reported by two
users is no longer silently treated as clean.

API docs: https://docs.abuseipdb.com/#check-endpoint
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

_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"

# AbuseIPDB report category ids we consider severe (subset of the official list).
_SEVERE_CATEGORIES = {
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    7: "Phishing",
    11: "Email Spam",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}
_CATEGORY_NAMES = dict(_SEVERE_CATEGORIES)


class AbuseIPDBProvider(ThreatIntelligenceProvider):
    name = "abuseipdb"

    async def _analyze(self, ip: IPAddress) -> ProviderResult:
        max_age = self._settings.max_threat_age_days
        response = await self._request(ip, max_age)
        raise_for_common_status(self.name, response)
        payload = parse_json(self.name, response)
        data = payload.get("data")
        if not isinstance(data, dict):
            return ProviderResult(
                provider=self.name,
                enabled=True,
                status=ProviderStatus.UNKNOWN,
                reasons=["AbuseIPDB response contained no data object"],
            )
        return self._interpret(data, max_age)

    async def _request(self, ip: IPAddress, max_age: int):
        from ..http_client import request_with_retries

        return await request_with_retries(
            self._client,
            "GET",
            _ENDPOINT,
            provider=self.name,
            retries=self._settings.retries,
            headers={"Key": self._api_key, "Accept": "application/json"},
            params={"ipAddress": str(ip), "maxAgeInDays": max_age, "verbose": True},
        )

    def _interpret(self, data: dict, max_age: int) -> ProviderResult:
        score = int(data.get("abuseConfidenceScore", 0) or 0)
        total_reports = int(data.get("totalReports", 0) or 0)
        distinct_users = int(data.get("numDistinctUsers", 0) or 0)
        is_tor = bool(data.get("isTor", False))
        is_whitelisted = bool(data.get("isWhitelisted", False))
        usage_type = data.get("usageType")
        last_reported = parse_iso8601(data.get("lastReportedAt"))
        freshness = days_since(last_reported)

        has_recent = freshness is not None and freshness <= max_age
        has_recent_7 = freshness is not None and freshness <= 7

        categories = self._recent_categories(data, max_age)
        severe = [name for cid, name in categories.items() if cid in _SEVERE_CATEGORIES]

        reasons: list[str] = [f"Abuse confidence score is {score}"]
        if total_reports:
            reasons.append(
                f"Reported by {distinct_users} distinct users "
                f"across {total_reports} reports"
            )
        if freshness is not None:
            reasons.append(f"Most recent report was {freshness} days ago")
        if severe:
            reasons.append("Observed categories include " + ", ".join(sorted(severe)))
        if is_tor:
            reasons.append("Reported as a Tor exit node")
        if is_whitelisted:
            reasons.append("Address is on the AbuseIPDB whitelist")
        if usage_type:
            reasons.append(f"Usage type: {usage_type}")

        raw = {
            "abuse_confidence_score": score,
            "total_reports": total_reports,
            "num_distinct_users": distinct_users,
            "is_tor": is_tor,
            "is_whitelisted": is_whitelisted,
            "usage_type": usage_type,
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "country_code": data.get("countryCode"),
            "categories": sorted(categories.values()),
        }

        # --- Classification ---
        malicious = (score >= 75 and distinct_users >= 3 and has_recent) or (
            score >= 90 and has_recent_7
        )
        # Evidence exists but is older than the allowed window.
        stale = (
            not malicious
            and score >= 25
            and freshness is not None
            and freshness > max_age
        )
        # AbuseIPDB whitelists known-good infrastructure; a confidence score of
        # ~0 there is authoritative, so misattributed reports on such addresses
        # must not raise a false "suspicious" verdict.
        whitelisted_benign = is_whitelisted and score < 25
        suspicious = (
            not malicious
            and not stale
            and not whitelisted_benign
            and (
                score >= 25
                or (has_recent and total_reports > 0)
                or bool(severe)
                or is_tor
            )
        )

        if malicious:
            status = ProviderStatus.MALICIOUS
            risk = clamp(max(float(score), 75.0))
            confidence = clamp(0.6 + 0.08 * min(distinct_users, 5), high=0.98)
        elif stale:
            status = ProviderStatus.STALE
            risk = clamp(float(score))
            confidence = 0.4
        elif suspicious:
            status = ProviderStatus.SUSPICIOUS
            risk = clamp(max(float(score), 30.0 if is_tor else float(score)))
            confidence = clamp(0.5 + 0.05 * min(distinct_users, 4), high=0.8)
        else:
            # Valid response, low/no score, no meaningful recent reports.
            status = ProviderStatus.CLEAN
            risk = clamp(float(score))
            confidence = 0.95 if is_whitelisted else 0.9
            if not reasons[1:]:
                reasons.append("No recent reports were returned")

        if stale and not self._settings.allow_stale_evidence:
            reasons.append("Evidence exceeds the configured maximum age")

        return ProviderResult(
            provider=self.name,
            enabled=True,
            status=status,
            risk_score=risk,
            confidence=confidence,
            data_freshness_days=freshness,
            observed_at=last_reported,
            reasons=reasons,
            threat_categories=sorted(categories.values()),
            raw_metrics=raw,
        )

    @staticmethod
    def _recent_categories(data: dict, max_age: int) -> dict[int, str]:
        """Collect category ids from reports within the age window."""
        found: dict[int, str] = {}
        reports = data.get("reports")
        if not isinstance(reports, list):
            return found
        for report in reports:
            if not isinstance(report, dict):
                continue
            reported_at = parse_iso8601(report.get("reportedAt"))
            age = days_since(reported_at)
            if age is not None and age > max_age:
                continue
            for cid in report.get("categories", []) or []:
                try:
                    cid_int = int(cid)
                except (TypeError, ValueError):
                    continue
                found[cid_int] = _CATEGORY_NAMES.get(cid_int, f"Category {cid_int}")
        return found
