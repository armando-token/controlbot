#!/usr/bin/env python3
"""Lightweight background health & failure watchdog for live testing.

Probes ControlBot (:8000), noVNC (:6080), and Xtigervnc (:5900) every 15s and
writes structured JSONL snapshots + alerts to `var/logs/watchdog.jsonl`.
Any failure alert is also mirrored into `var/logs/failures.jsonl`.
"""

from __future__ import annotations

import json
import math
import os
import signal
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _parse_float_env(raw: str | None, default: float) -> float:
    cleaned = (raw or "").strip()
    if not cleaned:
        return default
    try:
        val = float(cleaned)
    except ValueError:
        return default
    return val if math.isfinite(val) and val > 0.0 else default


REPO_ROOT = Path(__file__).resolve().parent.parent
LOGS_DIR = REPO_ROOT / "var" / "logs"
WATCHDOG_LOG = LOGS_DIR / "watchdog.jsonl"
FAILURES_LOG = LOGS_DIR / "failures.jsonl"
INTERVAL_SECONDS = _parse_float_env(os.environ.get("CONTROLBOT_WATCHDOG_INTERVAL"), 15.0)
SLOW_THRESHOLD_MS = _parse_float_env(os.environ.get("CONTROLBOT_WATCHDOG_SLOW_MS"), 2500.0)
MAX_LOG_BYTES = 5 * 1024 * 1024

_STOP = False


def _handle_signal(_sig: int, _frame: Any) -> None:
    global _STOP
    _STOP = True


def _utc_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _append_jsonl(path: Path, obj: dict[str, Any]) -> None:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        if path.exists() and path.stat().st_size >= MAX_LOG_BYTES:
            os.replace(path, path.with_suffix(path.suffix + ".1"))
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(obj, ensure_ascii=False) + "\n")
    except OSError:
        pass


def _probe_http(url: str, timeout: float = 4.0) -> tuple[bool, int | None, float, str | None]:
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            ms = round((time.monotonic() - t0) * 1000.0, 1)
            return (200 <= resp.status < 400), int(resp.status), ms, None
    except urllib.error.HTTPError as exc:
        ms = round((time.monotonic() - t0) * 1000.0, 1)
        return False, int(exc.code), ms, f"HTTP {exc.code}"
    except Exception as exc:
        ms = round((time.monotonic() - t0) * 1000.0, 1)
        return False, None, ms, f"{type(exc).__name__}: {exc}"


def _probe_tcp(host: str, port: int, timeout: float = 2.0) -> tuple[bool, str | None]:
    """Check listening TCP port via /proc/net/tcp* without triggering TigerVNC blacklists."""
    del host, timeout
    port_hex = f":{port:04X}"
    for proc_path in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
        if not proc_path.is_file():
            continue
        try:
            for line in proc_path.read_text(encoding="ascii", errors="ignore").splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[3] == "0A" and parts[1].upper().endswith(port_hex):
                    return True, None
        except OSError:
            continue
    return False, "port not listening"


def _parse_vnc_port(raw: str | None, default: int = 5901) -> int:
    cleaned = (raw or "").strip()
    if not cleaned:
        return default
    try:
        port = int(cleaned)
    except ValueError:
        return default
    return port if 1 <= port <= 65535 else default


def main() -> int:
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    while not _STOP:
        health_ok, health_code, health_ms, health_err = _probe_http("http://127.0.0.1:8000/health")
        app_ok, app_code, app_ms, app_err = _probe_http("http://127.0.0.1:8000/app")
        novnc_ok, novnc_code, novnc_ms, novnc_err = _probe_http("http://127.0.0.1:6080/")
        vnc_ok, vnc_err = _probe_tcp("127.0.0.1", 5900)
        bot_vnc_port = _parse_vnc_port(os.environ.get("GROKBOT_VNC_PORT"), 5901)
        bot_vnc_ok, bot_vnc_err = _probe_tcp("127.0.0.1", bot_vnc_port)

        alerts: list[str] = []
        if not health_ok:
            alerts.append(f"port_8000_health_failed: {health_err or health_code}")
        if not app_ok:
            alerts.append(f"port_8000_app_failed: {app_err or app_code}")
        if app_ms > SLOW_THRESHOLD_MS:
            alerts.append(f"port_8000_slow: {app_ms}ms")
        if not novnc_ok:
            alerts.append(f"port_6080_novnc_failed: {novnc_err or novnc_code}")
        if not vnc_ok:
            alerts.append(f"port_5900_vnc_failed: {vnc_err}")
        if not bot_vnc_ok:
            alerts.append(f"port_{bot_vnc_port}_bot_vnc_failed: {bot_vnc_err}")

        ts = _utc_iso()
        snap = {
            "ts": ts,
            "all_ok": not alerts,
            "health_code": health_code,
            "health_ms": health_ms,
            "app_code": app_code,
            "app_ms": app_ms,
            "novnc_code": novnc_code,
            "novnc_ms": novnc_ms,
            "vnc_ok": vnc_ok,
            "bot_vnc_port": bot_vnc_port,
            "bot_vnc_ok": bot_vnc_ok,
            "alerts": alerts,
        }
        _append_jsonl(WATCHDOG_LOG, snap)

        if alerts:
            _append_jsonl(
                FAILURES_LOG,
                {
                    "id": f"wd_{int(time.time())}",
                    "ts": ts,
                    "source": "watchdog",
                    "kind": "service_health_alert",
                    "message": "; ".join(alerts),
                    "detail": snap,
                },
            )

        for _ in range(int(max(1, INTERVAL_SECONDS))):
            if _STOP:
                break
            time.sleep(1.0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
