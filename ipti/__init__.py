"""IPTI — evidence-based IP threat intelligence and risk assessment.

Public API:
    - :class:`IPTI` — backward-compatible synchronous entry point.
    - :class:`AssessmentEngine` — async engine for single/batch assessment.
    - :func:`assess_ip` — one-shot async helper.
    - :func:`load_settings` — build validated settings from the environment.
"""

from __future__ import annotations

__version__ = "2.0.0"

from .compat import IPTI
from .config import Settings, load_settings
from .engine import AssessmentEngine, assess_ip
from .models import (
    Assessment,
    Decision,
    ProviderResult,
    ProviderStatus,
    ThreatClassification,
)

__all__ = [
    "IPTI",
    "Assessment",
    "AssessmentEngine",
    "Decision",
    "ProviderResult",
    "ProviderStatus",
    "Settings",
    "ThreatClassification",
    "__version__",
    "assess_ip",
    "load_settings",
]
