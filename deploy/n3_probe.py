"""Deployment wrapper CLI for honest N3 Linux/A11/LLM/Desktop readiness probing."""

from __future__ import annotations

import argparse
import json
from typing import Any

from src.doctor import CheckStatus
from src.n3_probe import N3ProbeReport, _format_human_n3, run_n3_probe


def build_deploy_n3_payload(report: N3ProbeReport) -> dict[str, Any]:
    """Build JSON payload for `python -m deploy.n3_probe --json`."""
    payload = report.model_dump(mode="json")
    payload["status"] = report.overall_status
    payload["egress_blocked"] = report.network_isolation_ready
    return payload


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `python -m deploy.n3_probe`."""
    parser = argparse.ArgumentParser(description="Grokbot-clon deploy N3 readiness probe")
    parser.add_argument("--json", action="store_true", help="Emit JSON N3 readiness payload.")
    parser.add_argument("--llm-origin", default=None, help="Optional local LLM origin to probe.")
    parser.add_argument(
        "--allow-private-lan",
        action="store_true",
        help="Allow RFC1918/ULA LAN origins for --llm-origin.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero unless overall_status == READY and all checks pass.",
    )
    args = parser.parse_args(argv)

    report = run_n3_probe(
        llm_origin=args.llm_origin,
        allow_private_lan=args.allow_private_lan,
    )
    if args.json:
        print(json.dumps(build_deploy_n3_payload(report), indent=2))
    else:
        print(_format_human_n3(report))

    has_fail = any(c.status == CheckStatus.FAIL for c in report.checks)
    if args.strict:
        if has_fail:
            return 2
        if report.overall_status != "READY":
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
