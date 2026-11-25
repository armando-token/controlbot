"""End-to-end local Pump 34 demonstration CLI (make demo)."""

from __future__ import annotations

import argparse
import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any

import httpx
from lab.maintenance_app import create_maintenance_app
from lab.scada_app import create_scada_app
from lab.testing import run_asgi_server

from src.adapters import MappingCredentialProvider, load_facility_config
from src.contracts.common import utc_now
from src.contracts.redaction import contains_unredacted_secret
from src.n3_probe import run_n3_probe
from src.runtime import build_runtime

_DEFAULT_FACILITY_PATH = (
    Path(__file__).resolve().parent.parent / "lab" / "configs" / "facility_a.json"
)
_DEFAULT_QUERY = (
    "¿Qué alarma apareció primero en la bomba 34 y qué se cambió en su última intervención?"
)


async def run_demo(
    *,
    facility_config_path: Path = _DEFAULT_FACILITY_PATH,
    query: str = _DEFAULT_QUERY,
    timeout_s: float = 30.0,
) -> dict[str, Any]:
    """Boot synthetic SCADA + Maintenance + GrokbotRuntime + Web UI and run Pump 34 query."""
    ref_time = utc_now()
    scada_app = create_scada_app(fixture_mode="default")
    maint_app = create_maintenance_app(fixture_mode="default")
    scada_app.state.scada_state.set_reference_time(ref_time)
    maint_app.state.maintenance_state.set_reference_time(ref_time)

    creds = MappingCredentialProvider(
        {
            ("operator_ro", "demo_prof", "scada"): ("operator_ro", "scada-pass-ro"),
            ("operator_ro", "demo_prof", "maintenance"): ("maint_ro", "maint-pass-ro"),
        }
    )

    n3_report = run_n3_probe()

    with tempfile.TemporaryDirectory(prefix="grokbot_demo_") as tmp_dir:
        tmp_path = Path(tmp_dir)
        async with (
            run_asgi_server(scada_app) as scada_origin,
            run_asgi_server(maint_app) as maint_origin,
        ):
            cfg = load_facility_config(
                facility_config_path,
                {"scada": scada_origin, "maintenance": maint_origin},
            )
            runtime = build_runtime(
                db_path=tmp_path / "demo.sqlite3",
                profile_root=tmp_path / "profiles",
                facility_config=cfg,
                credential_provider=creds,
                reference_time_fn=lambda: ref_time,
                auto_run=True,
                headless=True,
            )
            async with (
                runtime,
                run_asgi_server(runtime.app) as web_origin,
                httpx.AsyncClient(
                    base_url=web_origin,
                    timeout=10.0,
                    trust_env=False,
                    follow_redirects=False,
                ) as client,
            ):
                    submit_resp = await client.post(
                        "/api/tasks",
                        json={
                            "user_id": "operator_ro",
                            "profile_id": "demo_prof",
                            "facility_id": cfg.facility_id,
                            "allowed_origins": [scada_origin, maint_origin],
                            "allowed_areas": ["area-1"],
                            "read_only": True,
                            "query": query,
                        },
                    )
                    submit_resp.raise_for_status()
                    run_id = str(submit_resp.json()["run_id"])

                    await runtime.web_coordinator.wait_for_run(run_id, timeout=timeout_s)
                    snap_resp = await client.get(f"/api/tasks/{run_id}")
                    snap_resp.raise_for_status()
                    snapshot = snap_resp.json()

        receipts = snapshot.get("receipts", [])
        redaction_clean = not contains_unredacted_secret(snapshot)
        result = snapshot.get("result") or {}
        answer = str(result.get("answer", ""))
        observations = result.get("verified_observations", [])
        budget_usage = (snapshot.get("budget") or {}).get("usage") or {}

        ok = (
            snapshot.get("status") == "succeeded"
            and "ALM-3401" in answer
            and "WO-3408" in answer
            and redaction_clean
        )

        return {
            "ok": ok,
            "run_id": run_id,
            "status": snapshot.get("status"),
            "query": query,
            "answer": answer,
            "observations": [
                {
                    "source": o.get("source"),
                    "asset_id": o.get("asset_id"),
                    "record_id": (o.get("metadata") or {}).get("record_id"),
                    "value": o.get("value"),
                    "unit": o.get("unit"),
                    "source_time": o.get("source_time"),
                    "quality": o.get("quality"),
                    "area": o.get("area"),
                }
                for o in observations
            ],
            "receipt_count": len(receipts),
            "redaction_clean": redaction_clean,
            "budget_usage": budget_usage,
            "n3_status": n3_report.overall_status,
            "backend_mode": "emulated",
        }


def _format_human_demo(summary: dict[str, Any]) -> str:
    lines = [
        "=== Grokbot-clon Pump 34 End-to-End Demo ===",
        f"Run ID        : {summary['run_id']}",
        f"Status        : {summary['status']} (ok={summary['ok']})",
        f"Backend Mode  : {summary['backend_mode']}",
        f"N3 Env Status : {summary['n3_status']}",
        f"Query         : {summary['query']}",
        f"Answer        : {summary['answer']}",
        "",
        f"Verified Observations ({len(summary['observations'])}):",
    ]
    for obs in summary["observations"]:
        lines.append(
            f"  - [{obs['source']}] {obs['record_id']} | asset={obs['asset_id']} | "
            f"value={obs['value']} {obs['unit'] or ''} | time={obs['source_time']} | "
            f"quality={obs['quality']} | area={obs['area']}"
        )
    usage = summary["budget_usage"]
    lines.extend(
        [
            "",
            (
                f"Receipts      : {summary['receipt_count']} "
                f"(redaction_clean={summary['redaction_clean']})"
            ),
            (
                f"Budget Usage  : tool_calls={usage.get('tool_calls_used', 0)}, "
                f"model_calls={usage.get('model_calls_used', 0)}, "
                "tokens="
                f"{usage.get('prompt_tokens_used', 0) + usage.get('completion_tokens_used', 0)}"
            ),
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for make demo."""
    parser = argparse.ArgumentParser(description="Grokbot-clon Pump 34 end-to-end demo")
    parser.add_argument("--json", action="store_true", help="Emit JSON summary.")
    args = parser.parse_args(argv)

    summary = asyncio.run(run_demo())
    if args.json:
        print(json.dumps(summary, indent=2, default=str))
    else:
        print(_format_human_demo(summary))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
