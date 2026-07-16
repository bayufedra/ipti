# IPTI - CHANGELOG

## Migration from v1

| v1 | v2 |
|---|---|
| `THREATBOOK_API_KEY` | **removed** — delete it from `.env` |
| all keys required or crash | every provider optional; missing key → disabled |
| `is_safe: bool` | still present but **deprecated**; use `decision` |
| `safe_ratio` | replaced by `scores.threat` + `scores.evidence_coverage` |
| `platforms.platforms_considered` / `platforms_flagged_as_safe` | still emitted by `IPTI().ipti_check()`; prefer `platform_summary` |
| `HIGH_RISK_COUNTRY` / `HIGH_RISK_PROVIDER` | replaced by `IPTI_RESTRICTED_COUNTRIES` / `IPTI_REQUIRE_APPROVAL_COUNTRIES` policy lists; hosting providers are no longer inherently "risky" |
| single averaged `safe_ratio` | three separate scores (threat / identity / exposure) + coverage |
| `python main.py --max-score 50 --max-user 5 --safe-ratio 0.8` | `ipti --review-threshold 50` (`python main.py` still works but now runs the new CLI, so use the new flags; `--max-user`/`--safe-ratio` are gone) |

`from ipti import IPTI` and `IPTI(ip).ipti_check()` still work and return a dict
that is a **superset** of the old one (adds `decision`, `scores`,
`evidence_coverage`, `schema_version`). Update your `.env` from
[`.env.example`](.env.example) — in particular remove any ThreatBook entry and
set the `IPTI_*_ENABLED` flags you want.
