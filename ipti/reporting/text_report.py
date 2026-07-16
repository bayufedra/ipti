"""Human-readable terminal report with optional ANSI color.

Color is emitted only when explicitly enabled by the caller (the CLI decides
based on TTY / ``NO_COLOR`` / ``--no-color`` / output format), so saved files
and piped output never contain escape codes unless requested.
"""

from __future__ import annotations

from ..models import Assessment, Decision, ProviderResult, ProviderStatus

_RESET = "\033[0m"
_COLORS = {
    "green": "\033[32m",
    "yellow": "\033[33m",
    "red": "\033[31m",
    "cyan": "\033[36m",
    "bold": "\033[1m",
    "dim": "\033[2m",
}

_DECISION_COLOR = {
    Decision.APPROVE_WITH_CONTROLS: "green",
    Decision.MANUAL_REVIEW: "yellow",
    Decision.DENY: "red",
    Decision.INCOMPLETE: "yellow",
    Decision.NOT_APPLICABLE: "dim",
}


class _Palette:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def paint(self, text: str, color: str) -> str:
        if not self.enabled or color not in _COLORS:
            return text
        return f"{_COLORS[color]}{text}{_RESET}"


def render_text(
    assessment: Assessment, *, color: bool = False, show_disabled: bool = False
) -> str:
    p = _Palette(color)
    a = assessment
    lines: list[str] = []

    lines.append(p.paint("=== IP Threat Intelligence Assessment ===", "bold"))
    lines.append(f"IP Address        : {a.ip}")
    lines.append(f"IP Version        : {a.ip_version or 'n/a'}")
    lines.append(f"Checked At        : {a.checked_at.isoformat()}")
    lines.append(f"Schema Version    : {a.schema_version}")
    lines.append("")

    decision_color = _DECISION_COLOR.get(a.decision, "yellow")
    lines.append(p.paint(f"Decision          : {a.decision.value}", decision_color))
    lines.append(f"Threat Class      : {a.threat_classification.value}")
    lines.append("")

    lines.append(p.paint("--- Scores ---", "cyan"))
    lines.append(f"Threat Score      : {a.scores.threat:.1f} / 100")
    lines.append(f"Evidence Coverage : {a.scores.evidence_coverage:.0%}")
    lines.append(f"Identity Conf.    : {_fmt(a.scores.identity_confidence)} / 100")
    lines.append(f"Exposure Risk     : {_fmt(a.scores.exposure_risk)} / 100")
    lines.append("")

    s = a.platform_summary
    lines.append(p.paint("--- Threat Providers ---", "cyan"))
    lines.append(
        f"Available {s.platforms_available}  Enabled {s.platforms_enabled}  "
        f"Disabled {s.platforms_disabled}  Queried {s.platforms_queried}  "
        f"Succeeded {s.platforms_succeeded}  Failed {s.platforms_failed}"
    )
    for name, result in a.providers.items():
        # Disabled providers are summarized in the counts line above and in the
        # warnings; list them individually only when --show-disabled is set.
        if not result.enabled and not show_disabled:
            continue
        lines.append(_provider_line(p, name, result))
        for reason in result.reasons[:4]:
            lines.append(f"      - {reason}")
    lines.append("")

    enrichment = a.enrichment
    if enrichment:
        ipinfo = (enrichment.get("ipinfo") or {}).get("data") or {}
        shodan = (enrichment.get("shodan") or {}).get("data") or {}
        ptr = enrichment.get("ptr", {})
        identity = enrichment.get("identity", {})
        exposure = enrichment.get("exposure", {})
        policy = enrichment.get("policy", {})
        anon = enrichment.get("anonymization", {})
        anon_sources = anon.get("sources", {}) if isinstance(anon, dict) else {}

        # Server information (geography/ownership context — never a threat verdict)
        lines.append(p.paint("--- Server Information ---", "cyan"))
        lines.append(f"Country           : {_val(ipinfo.get('country'))}")
        lines.append(f"City              : {_val(ipinfo.get('city'))}")
        lines.append(f"Region            : {_val(ipinfo.get('region'))}")
        org = ipinfo.get("org")
        asn = ipinfo.get("asn")
        org_line = _val(org)
        if asn and str(asn) not in str(org or ""):
            org_line += f" (ASN {asn})"
        lines.append(f"Organization      : {org_line}")
        if ipinfo.get("hostname"):
            lines.append(f"Hostname          : {ipinfo['hostname']}")
        lines.append("Privacy (unknown = provider plan does not report it, not False):")
        for label, key in (
            ("Proxy", "is_proxy"),
            ("VPN", "is_vpn"),
            ("Tor", "is_tor"),
            ("Relay", "is_relay"),
            ("Hosting", "is_hosting"),
        ):
            val = anon.get(key) if isinstance(anon, dict) else ipinfo.get(key)
            flag_color = (
                "dim"
                if val is None
                else (
                    "red" if (key == "is_tor" and val) else ("yellow" if val else "green")
                )
            )
            src = anon_sources.get(key)
            suffix = f"  (via {src})" if src else ""
            lines.append(f"  {label:<8}: " + p.paint(_flag(val), flag_color) + suffix)
        lines.append("")

        # Policy assessment (geography/provider are policy context, not threat
        # evidence; they move the decision, never the threat score).
        if policy:
            lines.append(p.paint("--- Policy Assessment ---", "cyan"))
            geo = policy.get("geographic_policy", "unknown")
            geo_color = {
                "restricted": "red",
                "require_approval": "yellow",
                "unexpected": "yellow",
                "expected": "green",
                "neutral": "green",
            }.get(geo, "dim")
            lines.append(
                "Geographic Policy : "
                + p.paint(geo, geo_color)
                + f" — {policy.get('geographic_reason', '')}"
            )
            lines.append(
                f"Provider/Network  : {policy.get('provider_context', 'unknown')}"
            )
            lines.append("")

        # Identity / ownership
        if identity:
            lines.append(p.paint("--- Identity / Ownership ---", "cyan"))
            lines.append(
                f"Identity Conf.    : {_fmt(identity.get('identity_confidence'))} / 100"
            )
            lines.append(f"Network Type      : {identity.get('network_type', 'unknown')}")
            lines.append(
                f"PTR Record        : {_val(ptr.get('ptr'))} ({ptr.get('status', 'n/a')})"
            )
            if identity.get("owner_match") is not None:
                lines.append(f"Owner Match       : {identity['owner_match']}")
            lines.append("")

        # Exposure / ports
        lines.append(p.paint("--- Exposure / Ports ---", "cyan"))
        level = exposure.get("risk_level", "unknown")
        level_color = {
            "critical": "red",
            "high": "red",
            "moderate": "yellow",
            "low": "green",
        }.get(level, "dim")
        lines.append(
            "Exposure Risk     : "
            + p.paint(
                f"{_fmt(exposure.get('exposure_risk'))} / 100 ({level})", level_color
            )
        )
        if exposure.get("data_age_days") is not None:
            lines.append(f"Data Age (days)   : {exposure['data_age_days']}")
        ports = exposure.get("open_ports") or []
        lines.append(f"Open Ports        : {', '.join(map(str, ports)) or 'none'}")
        services = shodan.get("services") or []
        if services:
            lines.append("Services:")
            for svc in services[:12]:
                cves = svc.get("cves") or []
                desc = f"  {_service_desc(svc)}"
                if cves:
                    desc = p.paint(f"{desc}  CVEs: {', '.join(cves[:4])}", "red")
                lines.append(desc)
        if exposure.get("critical_services"):
            lines.append(
                p.paint(
                    "Critical Services : " + ", ".join(exposure["critical_services"]),
                    "red",
                )
            )
        if exposure.get("cves"):
            lines.append(
                p.paint("Known CVEs        : " + ", ".join(exposure["cves"][:8]), "red")
            )
        if not ports and exposure.get("data_source") == "none":
            lines.append(
                p.paint("  (no Shodan record — exposure unknown, not low)", "dim")
            )
        lines.append("")

    if a.hard_blocks:
        lines.append(p.paint("--- Hard Blocks ---", "red"))
        lines.extend(f"  ✗ {reason}" for reason in a.hard_blocks)
        lines.append("")
    if a.review_reasons:
        lines.append(p.paint("--- Review Reasons ---", "yellow"))
        lines.extend(f"  • {reason}" for reason in a.review_reasons)
        lines.append("")
    if a.recommended_controls:
        lines.append(p.paint("--- Recommended Whitelist Controls ---", "cyan"))
        lines.extend(f"  → {control}" for control in a.recommended_controls)
        lines.append("")
    if a.warnings:
        lines.append(p.paint("--- Warnings ---", "yellow"))
        lines.extend(f"  ! {warning}" for warning in a.warnings)
        lines.append("")

    lines.append(
        p.paint(
            "Reminder: no threat feed can prove an IP is safe; 'is_safe' is deprecated.",
            "dim",
        )
    )
    return "\n".join(lines)


def render_summary(assessments: list[Assessment], *, color: bool = False) -> str:
    p = _Palette(color)
    lines = [
        p.paint("=== Assessment Summary ===", "bold"),
        f"Total IPs: {len(assessments)}",
    ]
    counts: dict[str, int] = {}
    for a in assessments:
        counts[a.decision.value] = counts.get(a.decision.value, 0) + 1
    for decision, count in sorted(counts.items()):
        lines.append(f"  {decision}: {count}")
    lines.append("")
    for i, a in enumerate(assessments, 1):
        color_name = _DECISION_COLOR.get(a.decision, "yellow")
        lines.append(
            f"{i}. {a.ip} — "
            + p.paint(a.decision.value, color_name)
            + f" (threat {a.scores.threat:.0f}, coverage "
            f"{a.scores.evidence_coverage:.0%}, {a.threat_classification.value})"
        )
    return "\n".join(lines)


def _provider_line(p: _Palette, name: str, result: ProviderResult) -> str:
    if not result.enabled:
        return f"  {name:<16}: " + p.paint(result.status.value, "dim")
    color = {
        ProviderStatus.CLEAN: "green",
        ProviderStatus.MALICIOUS: "red",
        ProviderStatus.SUSPICIOUS: "yellow",
        ProviderStatus.STALE: "yellow",
    }.get(result.status, "yellow")
    score = f" risk={result.risk_score:.0f}" if result.risk_score is not None else ""
    conf = f" conf={result.confidence:.2f}" if result.confidence else ""
    return f"  {name:<16}: " + p.paint(result.status.value, color) + score + conf


def _fmt(value: float | None) -> str:
    return f"{value:.1f}" if value is not None else "n/a"


def _val(value: object) -> str:
    """Render a value, or 'Unknown' when it is missing/empty."""
    return str(value) if value not in (None, "") else "Unknown"


def _flag(value: bool | None) -> str:
    """Render a tri-state privacy flag: True / False / unknown (never coerced)."""
    if value is None:
        return "unknown"
    return "True" if value else "False"


def _service_desc(svc: dict) -> str:
    port = svc.get("port")
    product = svc.get("product")
    version = svc.get("version")
    label = str(port) if port is not None else "?"
    if product:
        label += f"/{product}"
        if version:
            label += f" {version}"
    return label
