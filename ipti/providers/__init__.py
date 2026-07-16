"""Provider implementations for IPTI."""

from __future__ import annotations

from collections.abc import Callable

import httpx

from ..config import Settings
from .abuseipdb import AbuseIPDBProvider
from .alienvault_otx import AlienVaultOTXProvider
from .base import EnrichmentProvider, ThreatIntelligenceProvider
from .ipinfo import IPInfoProvider
from .shodan import ShodanProvider
from .virustotal import VirusTotalProvider

# Registries used by the engine to instantiate enabled providers. Typed as
# callables (a class is callable) so mypy accepts constructing concrete
# providers without an abstract-instantiation error.
ThreatFactory = Callable[[httpx.AsyncClient, Settings], ThreatIntelligenceProvider]
EnrichmentFactory = Callable[[httpx.AsyncClient, Settings], EnrichmentProvider]

THREAT_PROVIDER_CLASSES: dict[str, ThreatFactory] = {
    "abuseipdb": AbuseIPDBProvider,
    "virustotal": VirusTotalProvider,
    "alienvault_otx": AlienVaultOTXProvider,
}
ENRICHMENT_PROVIDER_CLASSES: dict[str, EnrichmentFactory] = {
    "ipinfo": IPInfoProvider,
    "shodan": ShodanProvider,
}

__all__ = [
    "ENRICHMENT_PROVIDER_CLASSES",
    "THREAT_PROVIDER_CLASSES",
    "AbuseIPDBProvider",
    "AlienVaultOTXProvider",
    "EnrichmentProvider",
    "IPInfoProvider",
    "ShodanProvider",
    "ThreatIntelligenceProvider",
    "VirusTotalProvider",
]
