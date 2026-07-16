"""Exposure analysis from Shodan service data (and privacy signals).

Produces an ``exposure_risk`` (0-100) describing how exposed/vulnerable the host
appears. Standard ports (443, 22, 80) are *not* automatically malicious; only
publicly-reachable databases/remote-admin services, unencrypted admin protocols
and hosts with known CVEs raise exposure. "No Shodan record" yields ``None``
(unknown), never a low-risk score.
"""

from __future__ import annotations

from ..util import clamp

# Publicly-reachable services that should almost never be internet-facing.
_CRITICAL_SERVICES = {
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
    5900: "VNC",
    1433: "MSSQL",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    11211: "Memcached",
    2375: "Docker API",
    5984: "CouchDB",
    2049: "NFS",
    5439: "Redshift",
    9000: "Portainer/PHP-FPM",
}
# Unencrypted protocols (exposure, not necessarily critical).
_UNENCRYPTED = {21: "FTP", 23: "Telnet", 25: "SMTP", 80: "HTTP", 110: "POP3", 143: "IMAP"}
# Ports considered routine for a public host.
_ROUTINE = {22, 53, 80, 443, 8080, 8443}


def assess_exposure(
    shodan_data: dict | None,
    ipinfo_data: dict | None,
) -> dict:
    """Assess host exposure from Shodan services plus privacy signals."""

    contributions: list[float] = []
    findings: list[str] = []
    critical: list[str] = []
    cves: list[str] = []
    open_ports: list[int] = []
    data_age = None
    have_signal = False

    if shodan_data and shodan_data.get("has_record"):
        have_signal = True
        open_ports = list(shodan_data.get("ports") or [])
        data_age = shodan_data.get("data_age_days")
        # Copy: never mutate the provider's data — it is reported verbatim in
        # `enrichment.shodan.data` and is cached by the engine.
        services = list(shodan_data.get("services") or [])
        # Fall back to bare port list when banner detail is absent.
        seen_ports = {s.get("port") for s in services if s.get("port") is not None}
        for port in open_ports:
            if port not in seen_ports:
                services.append({"port": port, "cves": []})
        for svc in services:
            risk, notes, svc_cves = _service_exposure(svc)
            contributions.append(risk)
            findings.extend(notes)
            cves.extend(svc_cves)
            port = svc.get("port")
            if isinstance(port, int) and port in _CRITICAL_SERVICES:
                critical.append(f"{port}/{_CRITICAL_SERVICES[port]}")
        if not open_ports:
            findings.append("Host present in Shodan with no open ports reported")

    # Privacy / anonymization signals contribute to exposure too.
    if ipinfo_data:
        if ipinfo_data.get("is_tor"):
            contributions.append(30.0)
            findings.append("IPInfo reports this address as a Tor node")
            have_signal = True
        if ipinfo_data.get("is_proxy") or ipinfo_data.get("is_residential_proxy"):
            contributions.append(20.0)
            findings.append("IPInfo reports proxy characteristics")
            have_signal = True
        if ipinfo_data.get("is_vpn"):
            contributions.append(10.0)
            findings.append("IPInfo reports VPN characteristics")
            have_signal = True

    if not have_signal:
        return {
            "exposure_risk": None,
            "risk_level": "unknown",
            "open_ports": [],
            "findings": [
                "No Shodan record; exposure is unknown (not evidence of low exposure)"
            ],
            "critical_services": [],
            "cves": [],
            "data_age_days": None,
            "data_source": "none",
        }

    exposure = clamp(sum(contributions))
    # A single critical exposed service should not be diluted below "high".
    if critical:
        exposure = clamp(max(exposure, 60.0))
    if cves:
        exposure = clamp(max(exposure, 55.0))

    return {
        "exposure_risk": round(exposure, 1),
        "risk_level": _risk_level(exposure),
        "open_ports": sorted(open_ports),
        "findings": findings or ["Only routine public services observed"],
        "critical_services": sorted(set(critical)),
        "cves": sorted(set(cves)),
        "data_age_days": data_age,
        "data_source": "shodan",
    }


def _service_exposure(svc: dict) -> tuple[float, list[str], list[str]]:
    port = svc.get("port")
    product = svc.get("product")
    version = svc.get("version")
    cves = [c for c in (svc.get("cves") or []) if c]
    label = _describe(port, product, version)
    notes: list[str] = []
    risk = 0.0

    if isinstance(port, int) and port in _CRITICAL_SERVICES:
        risk += 40.0
        notes.append(f"Publicly reachable {label} (high exposure risk)")
    elif isinstance(port, int) and port == 22:
        risk += 8.0
        notes.append(f"SSH exposed ({label})")
    elif isinstance(port, int) and port in _UNENCRYPTED:
        risk += 8.0
        notes.append(f"Unencrypted service {label}")
    elif isinstance(port, int) and port in _ROUTINE:
        risk += 3.0
        notes.append(f"Routine public service {label}")
    else:
        risk += 5.0
        notes.append(f"Open service {label}")

    if cves:
        risk += min(45.0, 12.0 + 8.0 * len(cves))
        notes.append(
            f"{label} has known CVEs: {', '.join(sorted(cves)[:8])}"
            + (" …" if len(cves) > 8 else "")
        )
    return risk, notes, cves


def _describe(port: object, product: object, version: object) -> str:
    parts = []
    if port is not None:
        parts.append(str(port))
    if product:
        detail = str(product)
        if version:
            detail += f" {version}"
        parts.append(f"({detail})")
    return "/".join(parts) if parts else "unknown service"


def _risk_level(exposure: float) -> str:
    if exposure >= 75:
        return "critical"
    if exposure >= 55:
        return "high"
    if exposure >= 30:
        return "moderate"
    return "low"
