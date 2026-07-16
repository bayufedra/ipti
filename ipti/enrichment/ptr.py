"""PTR / reverse-DNS analysis with forward-confirmation (FCrDNS).

PTR is treated as *identity* evidence, never as proof of safety or malice. A
missing PTR is not automatically high risk.

The blocking resolver runs in a worker thread and the caller's wait is bounded by
``asyncio.wait_for`` in :func:`analyze_ptr`. The process-wide
``socket.setdefaulttimeout`` is deliberately **not** touched: it is global state
shared with every other socket in the process (including the httpx client), and
concurrent lookups setting/restoring it race with each other and can leak a
timeout onto the whole process. The trade-off is that a wedged resolver thread
may linger until the OS resolver gives up — it never blocks the event loop or
the caller.
"""

from __future__ import annotations

import re
import socket

from ..logging_config import get_logger
from ..models import PtrResult, PtrStatus

logger = get_logger(__name__)

# Substrings that strongly indicate a dynamic/residential PTR.
_DYNAMIC_HINTS = (
    "dynamic",
    "dhcp",
    "dialup",
    "pool",
    "ppp",
    "pppoe",
    "adsl",
    "cable",
    "dsl",
    "broadband",
    "res.",
    "cust",
    "customer",
)
# Generic cloud/hosting PTR (neutral identity, not a threat signal).
_GENERIC_HINTS = (
    "amazonaws.com",
    "compute.amazonaws",
    "googleusercontent.com",
    "1e100.net",
    "azure",
    "cloudapp",
    "linode",
    "ovh.net",
    "digitalocean",
    "vultr",
    "hetzner",
    "compute.",
    "static.",
    "clients.your-server.de",
)


async def analyze_ptr(ip: str, *, timeout: float = 5.0) -> PtrResult:
    """Resolve and forward-confirm the PTR record for ``ip``.

    Runs the blocking resolver calls in a worker thread so the event loop is
    never blocked and the timeout is scoped to this lookup only.
    """

    import asyncio

    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_analyze_sync, ip), timeout=timeout
        )
    except asyncio.TimeoutError:
        return PtrResult(status=PtrStatus.TIMEOUT, reasons=["Reverse DNS timed out"])


def _resolve_ptr(ip: str) -> str:
    """Reverse lookup. Never mutates global socket state (see module docstring)."""
    return socket.gethostbyaddr(ip)[0]


def _forward_addresses(hostname: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(hostname, None)
    except OSError:
        return []
    return sorted({str(info[4][0]) for info in infos})


def _analyze_sync(ip: str) -> PtrResult:
    try:
        ptr = _resolve_ptr(ip)
    except TimeoutError:
        return PtrResult(status=PtrStatus.TIMEOUT, reasons=["Reverse DNS timed out"])
    except socket.herror:
        return PtrResult(
            status=PtrStatus.NO_PTR,
            reasons=["No PTR record (identity unknown, not malicious)"],
        )
    except OSError as exc:
        return PtrResult(status=PtrStatus.ERROR, reasons=[f"DNS error: {exc}"])

    ptr_lower = ptr.lower()
    forward = _forward_addresses(ptr)
    confirmed = ip in forward

    if confirmed:
        # FCrDNS passed: this is the strongest identity signal.
        if _is_generic(ptr_lower):
            return PtrResult(
                status=PtrStatus.GENERIC_PROVIDER_PTR,
                ptr=ptr,
                forward_addresses=forward,
                reasons=["Forward-confirmed generic provider PTR"],
            )
        if _is_dynamic(ptr_lower):
            return PtrResult(
                status=PtrStatus.DYNAMIC_PTR,
                ptr=ptr,
                forward_addresses=forward,
                reasons=["Forward-confirmed dynamic/residential PTR"],
            )
        return PtrResult(
            status=PtrStatus.ORGANIZATION_PTR,
            ptr=ptr,
            forward_addresses=forward,
            reasons=["Forward-confirmed organization PTR"],
        )

    if forward:
        return PtrResult(
            status=PtrStatus.FORWARD_MISMATCH,
            ptr=ptr,
            forward_addresses=forward,
            reasons=[f"PTR {ptr} does not forward-resolve back to {ip}"],
        )
    # PTR exists but forward resolution returned nothing.
    if _is_dynamic(ptr_lower):
        return PtrResult(
            status=PtrStatus.DYNAMIC_PTR,
            ptr=ptr,
            reasons=["Dynamic/residential PTR (no forward confirmation)"],
        )
    return PtrResult(
        status=PtrStatus.FORWARD_MISMATCH,
        ptr=ptr,
        reasons=["PTR present but not forward-confirmed"],
    )


def _is_dynamic(ptr_lower: str) -> bool:
    if any(hint in ptr_lower for hint in _DYNAMIC_HINTS):
        return True
    # An IP embedded in the hostname (e.g. 1-2-3-4.isp.net) suggests auto-generated.
    return bool(re.search(r"(?:\d{1,3}[-.]){3}\d{1,3}", ptr_lower))


def _is_generic(ptr_lower: str) -> bool:
    return any(hint in ptr_lower for hint in _GENERIC_HINTS)
