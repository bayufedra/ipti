"""Command-line interface for IPTI.

Exit codes:
    0  assessment(s) completed with no denial
    1  one or more IPs denied (or review/incomplete when --fail-on-review)
    2  one or more IPs need manual review / incomplete / not-applicable
    3  invalid input or configuration
    4  unexpected internal failure
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys

from . import __version__
from .config import ALL_PROVIDERS, Enablement, Settings, load_settings
from .engine import AssessmentEngine
from .exceptions import ConfigurationError, IPTIError
from .logging_config import setup_logging
from .models import Assessment, Decision
from .reporting import render_json, render_json_many, render_summary, render_text
from .validation import read_ip_file

EXIT_OK = 0
EXIT_DENIED = 1
EXIT_REVIEW = 2
EXIT_INPUT = 3
EXIT_INTERNAL = 4


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ipti",
        description="IPTI — evidence-based IP risk assessment for whitelisting.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  ipti -i 8.8.8.8\n"
            "  ipti -i 1.1.1.1 2606:4700:4700::1111 -f json\n"
            "  ipti -l ips.txt -o report.txt\n"
            "  ipti -i 203.0.113.5 --disable-provider shodan --fail-on-review\n"
        ),
    )
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("--ip", "-i", nargs="+", help="IP address(es) to assess")
    group.add_argument("--list", "-l", help="File with one IP per line")

    parser.add_argument("--output-file", "-o", help="Write the report to this file")
    parser.add_argument(
        "--output-format",
        "-f",
        choices=["text", "json"],
        default="text",
        help="Report format (default: text)",
    )
    parser.add_argument(
        "--summary-only",
        "-S",
        action="store_true",
        help="For multiple IPs, print only the summary",
    )

    parser.add_argument("--claimed-owner", help="Expected owner/org for identity check")
    parser.add_argument(
        "--allow-non-global",
        action="store_true",
        help="Permit private/reserved IPs (override; use with care)",
    )

    parser.add_argument(
        "--max-age", "-a", type=int, help="Maximum threat-data age in days"
    )
    parser.add_argument(
        "--review-threshold",
        type=float,
        help="Threat score at/above which review is required",
    )
    parser.add_argument(
        "--deny-threshold",
        type=float,
        help="Threat score at/above which the IP is denied",
    )
    parser.add_argument(
        "--min-sources", type=int, help="Minimum successful threat sources (1-3)"
    )
    parser.add_argument(
        "--min-coverage", type=float, help="Minimum evidence coverage (0.0-1.0)"
    )

    parser.add_argument(
        "--enable-provider",
        action="append",
        default=[],
        choices=list(ALL_PROVIDERS),
        help="Force-enable a provider (repeatable)",
    )
    parser.add_argument(
        "--disable-provider",
        action="append",
        default=[],
        choices=list(ALL_PROVIDERS),
        help="Force-disable a provider (repeatable)",
    )

    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color")
    parser.add_argument(
        "--show-disabled",
        action="store_true",
        help="Include disabled providers in the text report",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    parser.add_argument("--debug", action="store_true", help="Debug logging")
    parser.add_argument(
        "--fail-on-review",
        action="store_true",
        help="Exit non-zero (1) on review/incomplete results",
    )
    parser.add_argument(
        "--config-check",
        action="store_true",
        help="Validate configuration and print provider status",
    )
    parser.add_argument("--version", action="version", version=f"ipti {__version__}")
    return parser


def _apply_overrides(settings: Settings, args: argparse.Namespace) -> Settings:
    """Apply CLI overrides on top of environment configuration (CLI wins)."""
    providers = dict(settings.providers)
    for name in args.disable_provider:
        providers[name] = _with_enablement(providers[name], Enablement.FALSE)
    for name in args.enable_provider:
        providers[name] = _with_enablement(providers[name], Enablement.TRUE)

    overrides: dict[str, object] = {"providers": providers}
    if args.max_age is not None:
        overrides["max_threat_age_days"] = args.max_age
    if args.review_threshold is not None:
        overrides["threat_review_threshold"] = args.review_threshold
    if args.deny_threshold is not None:
        overrides["threat_deny_threshold"] = args.deny_threshold
    if args.min_sources is not None:
        overrides["min_successful_threat_sources"] = args.min_sources
    if args.min_coverage is not None:
        overrides["min_threat_coverage"] = args.min_coverage
    if args.allow_non_global:
        overrides["allow_non_global"] = True
    overridden = settings.with_overrides(**overrides)
    # CLI values are untrusted input: re-run cross-field validation so e.g.
    # `--review-threshold 90 --deny-threshold 70` fails fast like .env does.
    overridden.validate()
    return overridden


def _with_enablement(provider, enablement: Enablement):
    from dataclasses import replace

    return replace(provider, enablement=enablement)


def _should_color(args: argparse.Namespace) -> bool:
    if args.no_color or args.output_format == "json" or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _config_check(settings: Settings) -> int:
    resolved = settings.resolved_providers()
    print("IPTI configuration check")
    print(f"  min successful sources : {settings.min_successful_threat_sources}")
    print(f"  min coverage           : {settings.min_threat_coverage:.0%}")
    print(
        f"  review / deny threshold: {settings.threat_review_threshold} / "
        f"{settings.threat_deny_threshold}"
    )
    print("  providers:")
    for name in ALL_PROVIDERS:
        r = resolved[name]
        state = "enabled" if r.enabled else (r.status.value if r.status else "disabled")
        weight = settings.providers[name].weight
        print(f"    {name:<16} {state:<28} weight={weight}")
        if r.warning:
            print(f"        warning: {r.warning}")
    return EXIT_OK


def _resolve_targets(args: argparse.Namespace) -> list[str]:
    if args.ip:
        return list(args.ip)
    if args.list:
        return read_ip_file(args.list)
    return []


def _render(
    assessments: list[Assessment], args: argparse.Namespace, *, color: bool
) -> str:
    if args.output_format == "json":
        return (
            render_json(assessments[0])
            if len(assessments) == 1
            else render_json_many(assessments)
        )
    show_disabled = args.show_disabled
    if len(assessments) == 1:
        return render_text(assessments[0], color=color, show_disabled=show_disabled)
    if args.summary_only:
        return render_summary(assessments, color=color)
    parts = [
        render_text(a, color=color, show_disabled=show_disabled) for a in assessments
    ]
    parts.append(render_summary(assessments, color=color))
    return ("\n\n" + "=" * 64 + "\n\n").join(parts)


def _exit_code(assessments: list[Assessment], *, fail_on_review: bool) -> int:
    decisions = {a.decision for a in assessments}
    if Decision.DENY in decisions:
        return EXIT_DENIED
    needs_attention = decisions & {
        Decision.MANUAL_REVIEW,
        Decision.INCOMPLETE,
        Decision.NOT_APPLICABLE,
    }
    if needs_attention:
        return EXIT_DENIED if fail_on_review else EXIT_REVIEW
    return EXIT_OK


async def _run(settings: Settings, targets: list[str]) -> list[Assessment]:
    async with AssessmentEngine(settings) as engine:
        return await engine.assess_many(targets)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    level = (
        logging.DEBUG
        if args.debug
        else (logging.INFO if args.verbose else logging.WARNING)
    )
    setup_logging(level, debug=args.debug)

    try:
        settings = load_settings()
        settings = _apply_overrides(settings, args)
    except ConfigurationError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return EXIT_INPUT

    if args.config_check:
        return _config_check(settings)

    if not args.ip and not args.list:
        print("Input error: one of --ip/-i or --list/-l is required", file=sys.stderr)
        return EXIT_INPUT

    try:
        targets = _resolve_targets(args)
    except IPTIError as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return EXIT_INPUT
    if not targets:
        print("No IP addresses to assess.", file=sys.stderr)
        return EXIT_INPUT

    # Claimed owner only applies to single-IP identity checks.
    if args.claimed_owner and len(targets) == 1:

        async def _single() -> list[Assessment]:
            async with AssessmentEngine(settings) as engine:
                return [await engine.assess(targets[0], claimed_owner=args.claimed_owner)]

        runner = _single()
    else:
        runner = _run(settings, targets)

    try:
        assessments = asyncio.run(runner)
    except KeyboardInterrupt:  # pragma: no cover
        print("Interrupted.", file=sys.stderr)
        return EXIT_INTERNAL
    except Exception as exc:
        print(f"Internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_INTERNAL

    color = _should_color(args)
    report = _render(assessments, args, color=color)
    print(report)

    if args.output_file:
        try:
            file_report = _render(assessments, args, color=False)
            with open(args.output_file, "w", encoding="utf-8") as handle:
                handle.write(file_report)
            print(f"\nReport saved to: {args.output_file}", file=sys.stderr)
        except OSError as exc:
            print(f"Error writing {args.output_file}: {exc}", file=sys.stderr)
            return EXIT_INPUT

    return _exit_code(assessments, fail_on_review=args.fail_on_review)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
