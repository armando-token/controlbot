#!/usr/bin/env python3
"""Instant forensic failure report for live ControlBot testing.

Usage:
  .venv/bin/python scripts/diag_report.py [--limit 20] [--source SOURCE] [--request-id ID]
"""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
LOGS_DIR = REPO_ROOT / "var" / "logs"
SERVER_LOG = REPO_ROOT / "var" / "linux_server.log"


def _tail_jsonl(
    path: Path,
    limit: int,
    *,
    source: str | None = None,
    request_id: str | None = None,
) -> list[dict[str, Any]]:
    if not path.exists() or limit <= 0:
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if source is None and request_id is None:
        out: list[dict[str, Any]] = []
        for raw in lines[-max(limit * 4, 200) :]:
            if not raw.strip():
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                out.append(obj)
        return out

    matched: list[dict[str, Any]] = []
    for raw in reversed(lines):
        if not raw.strip():
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        if source is not None and obj.get("source") != source:
            continue
        if request_id is not None and obj.get("request_id") != request_id:
            continue
        matched.append(obj)
        if len(matched) >= limit:
            break
    matched.reverse()
    return matched


def _probe_http(url: str, timeout: float = 2.5) -> str:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return f"HTTP {resp.status}"
    except urllib.error.HTTPError as exc:
        return f"HTTP {exc.code}"
    except Exception as exc:
        return f"DOWN ({type(exc).__name__}: {exc})"


def _probe_tcp(host: str, port: int, timeout: float = 1.5) -> str:
    """Check listening TCP port via /proc/net/tcp* so VNC servers never blacklist probes."""
    del host, timeout
    port_hex = f":{port:04X}"
    for proc_path in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
        if not proc_path.is_file():
            continue
        try:
            for line in proc_path.read_text(encoding="ascii", errors="ignore").splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[3] == "0A" and parts[1].upper().endswith(port_hex):
                    return "OPEN"
        except OSError:
            continue
    return "CLOSED"


def main() -> int:
    parser = argparse.ArgumentParser(description="ControlBot live failure diagnostics report.")
    parser.add_argument("--limit", type=int, default=20, help="Number of recent failures to show.")
    parser.add_argument("--source", type=str, default=None, help="Filter failures by source.")
    parser.add_argument("--request-id", type=str, default=None, help="Filter by X-Request-Id.")
    parser.add_argument("--requests", type=int, default=10, help="Recent requests to display.")
    args = parser.parse_args()

    print("=== LIVE SERVICE HEALTH ===")
    print(f"  Port 8000 /health : {_probe_http('http://127.0.0.1:8000/health')}")
    print(f"  Port 8000 /app    : {_probe_http('http://127.0.0.1:8000/app')}")
    print(f"  Port 6080 noVNC   : {_probe_http('http://127.0.0.1:6080/')}")
    print(f"  Port 5900 AdminVNC: {_probe_tcp('127.0.0.1', 5900)}")
    print(f"  Port 5901 Bot VM  : {_probe_tcp('127.0.0.1', 5901)}")

    watchdog = _tail_jsonl(LOGS_DIR / "watchdog.jsonl", 5)
    if watchdog:
        last_wd = watchdog[-1]
        print(
            f"  Watchdog last tick: {last_wd.get('ts')} | ok={last_wd.get('all_ok')} "
            f"| 8000_ms={last_wd.get('app_ms')} | alerts={last_wd.get('alerts', [])}"
        )
    else:
        print("  Watchdog          : no entries yet")

    failures = _tail_jsonl(
        LOGS_DIR / "failures.jsonl",
        args.limit,
        source=args.source,
        request_id=args.request_id,
    )
    failures = failures[-args.limit :] if args.limit > 0 else []

    print(f"\n=== RECENT FAILURES ({len(failures)} shown from {LOGS_DIR / 'failures.jsonl'}) ===")
    if not failures:
        print("  (none recorded)")
    for item in failures:
        rid = item.get("request_id", "-")
        status_s = f" HTTP={item['status_code']}" if item.get("status_code") is not None else ""
        path_s = f" {item.get('method', '')} {item.get('path', '')}".strip()
        path_part = f" | {path_s}" if path_s else ""
        print(
            f"  [{item.get('ts')}] {item.get('source')}/{item.get('kind')} "
            f"(rid={rid}{status_s}{path_part}) -> {item.get('message')}"
        )
        detail = item.get("detail")
        if detail:
            print(f"      detail: {json.dumps(detail, ensure_ascii=False)[:400]}")
        tb = item.get("traceback")
        if tb:
            tb_lines = str(tb).strip().splitlines()
            snippet = " | ".join(tb_lines[-4:])
            print(f"      trace : {snippet[:400]}")

    reqs = _tail_jsonl(LOGS_DIR / "requests.jsonl", args.requests, request_id=args.request_id)
    reqs = reqs[-args.requests :] if args.requests > 0 else []
    print(f"\n=== RECENT REQUESTS ({len(reqs)} shown) ===")
    for r in reqs:
        print(
            f"  [{r.get('ts')}] {r.get('request_id')} {r.get('method')} {r.get('path')} "
            f"status={r.get('status_code')} ({r.get('duration_ms')}ms)"
        )

    if SERVER_LOG.exists():
        err_lines = [
            ln
            for ln in SERVER_LOG.read_text(encoding="utf-8", errors="replace").splitlines()[-200:]
            if any(tok in ln for tok in ("ERROR", "Traceback", "Exception", "500 ", "422 ", "404 "))
        ]
        print(f"\n=== SERVER LOG ERROR LINES (last {min(len(err_lines), 10)}) ===")
        for ln in err_lines[-10:]:
            print(f"  {ln[:220]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
