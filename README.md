# IPTI — IP Threat Intelligence

[![Black Hat Arsenal MEA 2025](https://img.shields.io/badge/Black%20Hat%20Arsenal-MEA%202025-white.svg)](https://blackhatmea.com/speaker/bayu-fedra-abdullah)

**IPTI** analyzes public IP addresses **before** they are considered for whitelisting into an organization's private network with an **evidence-based, explainable** assessment: a threat score, an evidence-coverage measure, an identity-confidence measure and an exposure-risk measure.

> ⚠️ **Disclaimer — no threat feed can prove an IP is safe.** A clean result
> means "no *current, known* malicious evidence was found across the enabled
> sources", not "safe". Whitelisting is an organizational risk decision; IPTI
> gives you the evidence and a recommendation, never a guarantee.

## Maintainer
Maintained by Bayu Fedra Abdullah ([LinkedIn](https://www.linkedin.com/in/bayufedra/)).
- Presented at Black Hat MEA 2025 Arsenal: https://blackhatmea.com/speaker/bayu-fedra-abdullah
- Security policy: see [SECURITY.md](SECURITY.md).

---

## Contents

1. [What it does](#what-it-does)
2. [Security limitations](#security-limitations)
3. [Providers](#providers)
4. [Automatic provider enablement](#automatic-provider-enablement)
5. [Installation](#installation)
6. [Configuration reference](#configuration-reference)
7. [CLI usage](#cli-usage)
8. [Python library usage](#python-library-usage)
9. [The decision model](#the-decision-model)
10. [Geography & provider policy](#geography--provider-policy)
11. [Scores: threat, identity, exposure, coverage](#scores)
12. [JSON output](#json-output)
13. [Text output](#text-output)
14. [Exit codes](#exit-codes)
15. [Caching](#caching)
16. [Error handling](#error-handling)
17. [IPv4 and IPv6 behavior](#ipv4-and-ipv6-behavior)
18. [Recommended whitelist controls](#recommended-whitelist-controls)
19. [Testing & quality](#testing--quality)
20. [Migration from v1](#migration-from-v1)

---

## What it does

Given one or more public IPs, IPTI:

- Queries up to three **threat-intelligence** providers concurrently and
  fault-isolated (one failing never aborts the others).
- Derives a **threat score** (0–100) from *only* the providers that returned
  usable evidence, dynamically normalized by configured weight × confidence.
- Measures **evidence coverage** so you know how much of your configured
  intelligence actually answered.
- Enriches with **identity** (ASN/owner/FCrDNS) and **exposure**
  (open services/CVEs) context — which can raise concern but can **never**
  cancel real threat evidence.
- Emits a **decision** (`APPROVE_WITH_CONTROLS` / `MANUAL_REVIEW` / `DENY` /
  `INCOMPLETE` / `NOT_APPLICABLE`), a **threat classification**, the reasons,
  and recommended whitelist controls.

## Security limitations

- Threat feeds have coverage gaps and reporting lag; absence of evidence is not
  evidence of absence.
- A determined attacker can use never-before-seen infrastructure that no feed
  knows about yet.
- Enrichment (IPInfo/Shodan) is a point-in-time snapshot and may be stale.
- IPTI does not scan the target itself; it consults third-party data.
- Geography and hosting provider are **policy context**, not proof of malice.

## Providers

| Provider | Role | Env key | Docs |
|---|---|---|---|
| **AbuseIPDB** | Threat intelligence | `ABUSEIPDB_API_KEY` | <https://docs.abuseipdb.com/> |
| **VirusTotal** | Threat intelligence | `VIRUSTOTAL_API_KEY` | <https://docs.virustotal.com/reference/ip-object> |
| **AlienVault OTX** | Threat intelligence | `ALIENVAULT_API_KEY` | <https://otx.alienvault.com/api> |
| IPInfo | Enrichment (identity/geo) | `IPINFO_API_KEY` | <https://ipinfo.io/developers> |
| Shodan | Enrichment (exposure) | `SHODAN_API_KEY` | <https://developer.shodan.io/api> |

Every provider is **optional and independent**. By default two threat providers
must succeed to avoid an `INCOMPLETE` result (`IPTI_MIN_SUCCESSFUL_THREAT_SOURCES=2`)
— set it to `1` (or pass `--min-sources 1`) if you intentionally run with a
single provider, which triggers a reduced-confidence warning.

### Privacy / anonymization detection (VPN / proxy / Tor / hosting)

These flags come from IPInfo's **privacy detection**, which is a **paid add-on**.
A free/basic IPInfo token returns only geolocation — no `privacy` object — so
those flags correctly show `unknown` (never a fabricated `False`), and IPTI
emits a warning telling you so. **Tor is the exception:** it is also detected for
free from **AbuseIPDB's `isTor`** field, so Tor still works without an IPInfo
upgrade. Each resolved flag shows its source, e.g. `Tor: True (via abuseipdb)`,
and the full set is in `enrichment.anonymization`. To populate VPN/proxy/relay/
hosting, use an IPInfo plan that includes privacy detection — IPTI parses it
automatically once the response contains it.

## Automatic provider enablement

Each provider has an `IPTI_<NAME>_ENABLED` flag accepting `auto` / `true` /
`false`:

| Mode | Key present | Key missing |
|---|---|---|
| `auto` (default) | **enabled** | **disabled** (silently) |
| `true` | **enabled** | **disabled**, with a warning (never a crash) |
| `false` | **disabled** | **disabled** |

A **disabled** provider is never queried, and is **excluded** from
`platforms_queried`, `platforms_succeeded`, `platforms_failed`, the scoring
denominator and the normalized weights. A **failed** enabled provider is *not*
treated as clean — it reduces evidence coverage instead.

## Installation

Requires **Python 3.10+**.

```bash
git clone https://github.com/bayufedra/ipti
cd ipti
python -m venv .venv && source .venv/bin/activate

# runtime only
pip install -r requirements.txt
# or install the package + console script + dev tools
pip install -e ".[dev]"

cp .env.example .env    # then fill in the API keys you have
```

## Configuration reference

Configuration is validated at load time; invalid values fail fast with a clear
message. See [`.env.example`](.env.example) for the full annotated list. Key
settings:

| Variable | Default | Meaning |
|---|---|---|
| `IPTI_<NAME>_ENABLED` | `auto` | `auto`/`true`/`false` per provider |
| `<NAME>_API_KEY` | – | Provider API token |
| `IPTI_REQUEST_CONNECT_TIMEOUT` | `3.05` | Connect timeout (s) |
| `IPTI_REQUEST_READ_TIMEOUT` | `15` | Read timeout (s) |
| `IPTI_REQUEST_RETRIES` | `2` | Retries on transient failures |
| `IPTI_MAX_CONCURRENCY` | `8` | Max concurrent IPs / connections |
| `IPTI_CACHE_TTL_SECONDS` | `3600` | TTL for successful evidence |
| `IPTI_ERROR_CACHE_TTL_SECONDS` | `60` | TTL for errors (must be ≤ success TTL) |
| `IPTI_MIN_SUCCESSFUL_THREAT_SOURCES` | `2` | Below this → `INCOMPLETE` |
| `IPTI_MIN_THREAT_COVERAGE` | `0.67` | Below this → `MANUAL_REVIEW` |
| `IPTI_MAX_THREAT_AGE_DAYS` | `90` | Older evidence is `STALE` |
| `IPTI_ABUSEIPDB_WEIGHT` | `0.35` | Raw weight (need not sum to 1.0) |
| `IPTI_VIRUSTOTAL_WEIGHT` | `0.40` | Raw weight |
| `IPTI_ALIENVAULT_OTX_WEIGHT` | `0.25` | Raw weight |
| `IPTI_THREAT_REVIEW_THRESHOLD` | `30` | Threat score → review |
| `IPTI_THREAT_DENY_THRESHOLD` | `70` | Threat score → deny |
| `IPTI_EXPOSURE_REVIEW_THRESHOLD` | `60` | Exposure risk → review |
| `IPTI_IDENTITY_MINIMUM_CONFIDENCE` | `85` | Identity floor (when owner supplied) |
| `IPTI_RESTRICTED_COUNTRIES` | – | Policy: hard-block these ISO codes (→ `DENY`) |
| `IPTI_REQUIRE_APPROVAL_COUNTRIES` | – | Policy: review these ISO codes (→ `MANUAL_REVIEW`) |
| `IPTI_EXPECTED_COUNTRIES` | – | Policy: any country *outside* this list → `MANUAL_REVIEW` |
| `IPTI_BLOCK_TOR` | `true` | Hard-block confirmed Tor |
| `IPTI_BLOCK_OPEN_PROXY` | `true` | Hard-block confirmed open/residential proxy |
| `IPTI_ALLOW_NON_GLOBAL` | `false` | Allow private/reserved IPs |

Weights need **not** sum to 1.0; they are normalized dynamically over the
providers that actually returned usable evidence. Disabled providers are never
normalized into the score.

## CLI usage

```bash
# Single IP
ipti -i 8.8.8.8

# Multiple IPs (IPv4 + IPv6), JSON output
ipti -i 1.1.1.1 2606:4700:4700::1111 -f json

# From a file, save a report, summary only
ipti -l ips.txt -o report.txt -S

# Override providers (CLI wins over env) and gate CI on review
ipti -i 203.0.113.5 --disable-provider shodan --fail-on-review

# Validate configuration without assessing anything
ipti --config-check
```

Useful flags: `--no-color`, `--verbose`, `--debug`,
`--show-disabled` (list disabled providers individually in the text report),
`--fail-on-review` (exit non-zero on review/incomplete), `--config-check`,
`--version`, `--claimed-owner NAME`, `--allow-non-global`,
`--enable-provider NAME` / `--disable-provider NAME` (repeatable; CLI overrides
env), and threshold overrides `--max-age`, `--review-threshold`,
`--deny-threshold`, `--min-sources`, `--min-coverage`. Color is emitted only to
an interactive terminal and is disabled by `--no-color`, `NO_COLOR`, JSON output
or file output.

(`python main.py ...` still works as a thin shim for the console script.)

## Python library usage

### Async engine — single and batch (recommended)

```python
import asyncio
from ipti import AssessmentEngine, load_settings

async def main():
    settings = load_settings()                       # reads .env / environment
    async with AssessmentEngine(settings) as engine:
        a = await engine.assess("8.8.8.8", claimed_owner="Google")
        print(a.decision.value, a.threat_classification.value)
        print("threat", a.scores.threat, "coverage", a.scores.evidence_coverage)

        # Batch: bounded concurrency, input order preserved, duplicates removed.
        for r in await engine.assess_many(["1.1.1.1", "8.8.8.8", "1.1.1.1"]):
            print(r.ip, r.decision.value)

asyncio.run(main())
```

`assess()` and `assess_many()` return `Assessment` objects. `decision` and
`threat_classification` are **enums** — use `.value` for the string form.
Structured fields: `a.scores` (`threat`, `identity_confidence`, `exposure_risk`,
`evidence_coverage`), `a.providers` (`dict[str, ProviderResult]`),
`a.enrichment` (`ipinfo`/`shodan`/`ptr`/`exposure`/`identity`/`policy`/
`anonymization`), `a.hard_blocks`, `a.review_reasons`, `a.recommended_controls`,
`a.warnings`, and `a.is_safe` (deprecated).

### One-shot async helper

```python
import asyncio
from ipti import assess_ip

assessment = asyncio.run(assess_ip("1.1.1.1"))
print(assessment.decision.value, assessment.scores.threat)
```

### Convert to a JSON-serializable dict

```python
import asyncio
from ipti import assess_ip
from ipti.reporting import assessment_to_dict, render_json

a = asyncio.run(assess_ip("8.8.8.8"))
data = assessment_to_dict(a)         # plain dict (what the CLI's -f json prints)
print(data["decision"], data["scores"]["threat"])
print(render_json(a))                # pretty JSON string
```

### Legacy synchronous API (backward compatible)

`IPTI(ip).ipti_check()` still works and returns a dict that is a **superset** of
the old schema. It emits a `DeprecationWarning`; `is_safe`/`safe_ratio` are
deprecated — prefer `decision` and `scores`.

```python
from ipti import IPTI

result = IPTI(
    "8.8.8.8",
    max_age_in_days=60,   # mapped onto IPTI_MAX_THREAT_AGE_DAYS
    score_threshold=50,   # mapped onto IPTI_THREAT_REVIEW_THRESHOLD
    user_threshold=5,     # accepted for signature compat; no longer used
    safe_ratio=0.8,       # accepted for signature compat; no longer used
).ipti_check()

print(result["ip"], result["decision"], result["is_safe"])
print("threat:", result["scores"]["threat"],
      "coverage:", result["scores"]["evidence_coverage"])
```

> The old batch loop (`for ip in IP_LIST: IPTI(ip).ipti_check()`) still works,
> but `AssessmentEngine.assess_many()` is faster (concurrent + pooled).

## The decision model

`decision` is one of:

| Decision | Meaning |
|---|---|
| `APPROVE_WITH_CONTROLS` | No hard block; threat below review threshold; coverage met; apply the recommended controls |
| `MANUAL_REVIEW` | Suspicious evidence, low coverage, an unavailable/stale required source, high exposure, low identity confidence, or a policy flag |
| `DENY` | A hard block, threat ≥ deny threshold, or ≥2 corroborating malicious sources |
| `INCOMPLETE` | Fewer than the required number of threat sources succeeded — **never** returned as "safe" |
| `NOT_APPLICABLE` | The input is not a valid, globally-routable IP |

A separate `threat_classification` describes the evidence itself:
`NO_KNOWN_THREAT`, `LOW_RISK`, `SUSPICIOUS`, `HIGH_RISK`, `CONFIRMED_MALICIOUS`,
`UNKNOWN`.

**Hard blocks** (→ `DENY`) include: a high-confidence malicious verdict from any
provider, two independent malicious verdicts, malicious + independent suspicious
corroboration, confirmed Tor/open-proxy when policy blocks them, a
restricted-country policy hit, or a material ownership mismatch. Contextual
metadata (PTR, geography, provider reputation, standard open ports) may raise
concern or lower confidence but can **never** reduce an already-computed threat
score or cancel direct threat evidence.

## Geography & provider policy

Geography and hosting provider are **policy context**, never threat evidence. In
v1 a "high-risk country" secretly lowered a safety score and hardcoded
CN/RU/OVH/etc. as risky — that produced false positives and is removed. In v2:

- No country or provider is risky out of the box (all policy lists are empty).
- You opt in per your org via `IPTI_RESTRICTED_COUNTRIES` (→ `DENY`),
  `IPTI_REQUIRE_APPROVAL_COUNTRIES` (→ `MANUAL_REVIEW`) and
  `IPTI_EXPECTED_COUNTRIES` (anything outside → `MANUAL_REVIEW`).
- A policy hit moves the **decision** toward review/deny — it **never** mutates
  the threat score. The result is transparent (shown in the *Policy Assessment*
  section and `enrichment.policy`) instead of a hidden numeric penalty.

```bash
# "Approve only IPs in these countries, deny these, review the rest"
IPTI_EXPECTED_COUNTRIES=US,GB,SG IPTI_RESTRICTED_COUNTRIES=KP ipti -i 203.0.113.5
```

## Scores

Three independent measurements plus a coverage figure — never averaged into one
misleading number:

- **Threat (0–100)** — how much evidence suggests current/recent malicious
  activity. Confidence-weighted, dynamically normalized over usable providers.
- **Identity confidence (0–100)** — how confidently the IP maps to its expected
  owner/role (ASN, org, forward-confirmed reverse DNS, optional claimed owner).
- **Exposure risk (0–100)** — how exposed the host appears (public services,
  unencrypted/admin/database ports, known CVEs, proxy/VPN/Tor). `null` when no
  Shodan record exists (**unknown**, not low).
- **Evidence coverage (0.0–1.0)** — configured-enabled weight that actually
  returned usable evidence. Disabled providers don't reduce it; failed ones do.

## JSON output

```jsonc
{
  "schema_version": "2.0",
  "ip": "8.8.8.8",
  "ip_version": 4,
  "checked_at": "2026-07-15T05:00:00+00:00",
  "decision": "APPROVE_WITH_CONTROLS",
  "threat_classification": "NO_KNOWN_THREAT",
  "is_safe": true,                       // deprecated: == (decision APPROVE_WITH_CONTROLS)
  "scores": {
    "threat": 1.0,
    "identity_confidence": 95.0,
    "exposure_risk": 9.0,
    "evidence_coverage": 1.0
  },
  "platform_summary": {
    "platforms_available": 3, "platforms_enabled": 3, "platforms_disabled": 0,
    "platforms_queried": 3, "platforms_succeeded": 3, "platforms_failed": 0
  },
  "providers": {
    // Each provider object also carries: data_freshness_days, queried_at,
    // observed_at, duration_ms, threat_categories, raw_metrics, error_code,
    // error_message. Disabled providers appear with enabled=false and a
    // "disabled_*" status (never omitted).
    "abuseipdb":  { "enabled": true,  "status": "clean", "risk_score": 0.0,
                    "confidence": 0.95, "reasons": ["Abuse confidence score is 0"] },
    "virustotal": { "enabled": true,  "status": "clean", "risk_score": 0.0,
                    "confidence": 0.95, "reasons": ["0 engines flagged malicious ..."] },
    "alienvault_otx": { "enabled": true, "status": "clean", "risk_score": 5.0,
                        "confidence": 0.70, "reasons": ["No active recent threat pulses"] }
  },
  "enrichment": {
    "ipinfo": { "enabled": true, "status": "clean",
                "data": { "country": "US", "city": "Mountain View",
                          "org": "AS15169 Google LLC", "asn": "AS15169" } },
    "shodan": { "enabled": true, "status": "clean",
                "data": { "ports": [53, 443] } },
    "ptr": { "status": "organization_ptr", "ptr": "dns.google",
             "forward_addresses": ["8.8.8.8"] },
    "exposure": { "exposure_risk": 9.0, "risk_level": "low",
                  "open_ports": [53, 443], "critical_services": [], "cves": [] },
    "identity": { "identity_confidence": 95.0, "network_type": "unknown",
                  "ptr_status": "organization_ptr" },
    "policy": { "country": "US", "geographic_policy": "neutral",
                "geographic_reason": "US is not on any policy list",
                "provider_context": "AS15169 Google LLC" },
    "anonymization": { "is_vpn": null, "is_proxy": null, "is_tor": null,
                       "is_relay": null, "is_hosting": null, "sources": {} }
  },
  "hard_blocks": [],
  "review_reasons": [],
  "recommended_controls": [
    "Allow only the required destination host and port",
    "Use a /32 IPv4 rule or /128 IPv6 rule",
    "Require application-level authentication",
    "Enable connection logging and alerting",
    "Configure an expiration date and schedule periodic re-review"
  ],
  "warnings": []
}
```

`schema_version` is present so future changes can be managed safely.

## Text output

```text
=== IP Threat Intelligence Assessment ===
IP Address        : 8.8.8.8
IP Version        : 4
Checked At        : 2026-07-15T05:00:00+00:00
Schema Version    : 2.0

Decision          : APPROVE_WITH_CONTROLS
Threat Class      : LOW_RISK

--- Scores ---
Threat Score      : 1.0 / 100
Evidence Coverage : 100%
Identity Conf.    : 95.0 / 100
Exposure Risk     : 9.0 / 100

--- Threat Providers ---
Available 3  Enabled 3  Disabled 0  Queried 3  Succeeded 3  Failed 0
  abuseipdb       : clean risk=0 conf=0.95
      - Abuse confidence score is 0
  virustotal      : clean risk=0 conf=0.95
  alienvault_otx  : clean risk=5 conf=0.70

--- Server Information ---
Country           : US
City              : Mountain View
Organization      : AS15169 Google LLC
Hostname          : dns.google
Privacy (unknown = provider plan does not report it, not False):
  Proxy   : unknown
  VPN     : unknown
  Tor     : unknown       (or e.g. "True  (via abuseipdb)")
  Relay   : unknown
  Hosting : unknown

--- Policy Assessment ---
Geographic Policy : neutral — US is not on any policy list
Provider/Network  : AS15169 Google LLC

--- Identity / Ownership ---
Identity Conf.    : 95.0 / 100
Network Type      : unknown
PTR Record        : dns.google (organization_ptr)

--- Exposure / Ports ---
Exposure Risk     : 9.0 / 100 (low)
Open Ports        : 53, 443

--- Recommended Whitelist Controls ---
  → Allow only the required destination host and port
  ...
```

Failed providers (`timeout`/`error`/`rate_limited`) are always shown with their
status; **disabled** providers are summarized in the counts line and listed
individually only with `--show-disabled`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Completed with no denial |
| `1` | One or more IPs **denied** (or review/incomplete when `--fail-on-review`) |
| `2` | One or more IPs need **manual review / incomplete / not-applicable** |
| `3` | Invalid input or configuration |
| `4` | Unexpected internal failure |

## Caching

Results are cached per `(provider, ip)` for the session. Successful evidence
uses `IPTI_CACHE_TTL_SECONDS`; operational errors use the shorter
`IPTI_ERROR_CACHE_TTL_SECONDS`; **authentication failures are never cached**
(they must not later look clean). Batch runs de-duplicate identical IPs and
reuse pooled HTTP connections. Cache hits are logged at debug level.

## Error handling

- One provider's failure is converted into a normalized result with an explicit
  status (`timeout`, `rate_limited`, `error`) — it never aborts the others.
- Transient failures (429/5xx, timeouts, connection resets) are retried with
  exponential backoff + jitter and honour `Retry-After`; 4xx (except 429) are
  not retried.
- Missing API keys never crash IPTI; the provider is simply disabled.
- API tokens and authorization headers are redacted from all logs.

## IPv4 and IPv6 behavior

Both are validated with the standard-library `ipaddress` module. By default only
globally-routable public addresses are assessed; private/loopback/link-local/
multicast/reserved/unspecified/documentation ranges are rejected (use
`--allow-non-global` / `IPTI_ALLOW_NON_GLOBAL` to override). AlienVault OTX uses
the IPv4 or IPv6 indicator endpoint automatically.

---

Licensed under GPL-3.0-or-later. Contributions welcome at
<https://github.com/bayufedra/ipti>.
