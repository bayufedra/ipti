"""Identity / ownership analysis.

Produces an ``identity_confidence`` (0-100): how confidently the IP can be
associated with its expected organization or network role. Inputs are ASN,
organization, PTR/FCrDNS status and an optional caller-supplied claimed owner.
This is identity evidence only — it never reduces the threat score.
"""

from __future__ import annotations

import re

from ..models import PtrResult, PtrStatus
from ..util import clamp

_PTR_CONTRIBUTION = {
    PtrStatus.ORGANIZATION_PTR: 35.0,
    PtrStatus.CONFIRMED: 30.0,
    PtrStatus.GENERIC_PROVIDER_PTR: 25.0,
    PtrStatus.DYNAMIC_PTR: 5.0,
    PtrStatus.NO_PTR: 5.0,
    PtrStatus.FORWARD_MISMATCH: -15.0,
    PtrStatus.TIMEOUT: 0.0,
    PtrStatus.ERROR: 0.0,
}

_STOPWORDS = {
    "as",
    "inc",
    "llc",
    "ltd",
    "the",
    "co",
    "corp",
    "sa",
    "gmbh",
    "bv",
    "srl",
    "limited",
    "technologies",
    "networks",
    "network",
    "communications",
    "telecom",
    "hosting",
    "cloud",
}


def assess_identity(
    ipinfo_data: dict | None,
    ptr: PtrResult | None,
    claimed_owner: str | None = None,
) -> dict:
    """Compute identity confidence and detect ownership mismatch."""

    findings: list[str] = []
    confidence = 40.0  # neutral baseline

    asn = (ipinfo_data or {}).get("asn")
    org = (ipinfo_data or {}).get("org")
    asn_name = (ipinfo_data or {}).get("asn_name")
    asn_type = (ipinfo_data or {}).get("asn_type")

    ptr_status = ptr.status if ptr else None
    ptr_host = ptr.ptr if ptr else None

    if ptr_status is not None:
        confidence += _PTR_CONTRIBUTION.get(ptr_status, 0.0)
        findings.append(
            f"PTR status: {ptr_status.value}" + (f" ({ptr_host})" if ptr_host else "")
        )
    if asn:
        confidence += 10.0
        findings.append(f"ASN {asn}" + (f" — {asn_name}" if asn_name else ""))
    if org:
        confidence += 10.0

    network_type = _network_type(asn_type, ptr_status)
    if network_type != "unknown":
        findings.append(f"Network type: {network_type}")

    owner_match: bool | None = None
    ownership_mismatch = False
    if claimed_owner:
        haystacks = [org, asn_name, ptr_host]
        owner_match = _owner_matches(claimed_owner, haystacks)
        if owner_match:
            confidence = max(confidence, 85.0)
            findings.append(f"Claimed owner '{claimed_owner}' matches observed ownership")
        else:
            ownership_mismatch = True
            confidence = min(confidence, 40.0)
            findings.append(
                f"Claimed owner '{claimed_owner}' is inconsistent with "
                f"observed ownership ({org or asn_name or 'unknown'})"
            )

    return {
        "identity_confidence": round(clamp(confidence), 1),
        "ptr_status": ptr_status.value if ptr_status else None,
        "ptr": ptr_host,
        "asn": asn,
        "org": org,
        "network_type": network_type,
        "claimed_owner": claimed_owner,
        "owner_match": owner_match,
        "ownership_mismatch": ownership_mismatch,
        "findings": findings,
    }


def _network_type(asn_type: object, ptr_status: PtrStatus | None) -> str:
    if isinstance(asn_type, str):
        lowered = asn_type.lower()
        if lowered in {"hosting", "business", "education"}:
            return "hosting" if lowered == "hosting" else lowered
        if lowered == "isp":
            return "isp/residential"
    if ptr_status == PtrStatus.GENERIC_PROVIDER_PTR:
        return "hosting"
    if ptr_status == PtrStatus.DYNAMIC_PTR:
        return "isp/residential"
    return "unknown"


def _tokens(value: str) -> set[str]:
    words = re.split(r"[^a-z0-9]+", value.lower())
    return {w for w in words if w and w not in _STOPWORDS and len(w) > 1}


def _owner_matches(claimed: str, haystacks: list[object]) -> bool:
    claimed_tokens = _tokens(claimed)
    if not claimed_tokens:
        return False
    for hay in haystacks:
        if not isinstance(hay, str) or not hay:
            continue
        if claimed_tokens & _tokens(hay):
            return True
    return False
