"""Linux N3 environment, A11 network isolation, local LLM, and desktop probe."""

from __future__ import annotations

import argparse
import platform
import shutil
import subprocess
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field

from src.adapters.desktop import DesktopCapabilityReport, check_desktop_capabilities
from src.adapters.sessions import OriginNotAllowedError
from src.doctor import CheckResult, CheckStatus, EvidenceLevel
from src.model.http_client import validate_local_model_origin

N3Status = Literal["PENDING_N3_LINUX_ENV", "PENDING_LOCAL_LLM", "READY"]
CommandRunner = Callable[[Sequence[str]], tuple[int, str, str]]
HttpProbeFn = Callable[[str], tuple[bool, int | None, str]]


class N3ProbeReport(BaseModel):
    """Aggregated Linux N3 readiness report (never fakes readiness on macOS)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    timestamp_utc: str
    host_os: str
    host_release: str
    arch: str
    overall_status: N3Status
    linux_os_ready: bool
    network_isolation_ready: bool
    desktop_ready: bool
    local_llm_ready: bool
    checks: list[CheckResult]
    desktop_capabilities: DesktopCapabilityReport | None = None
    evidence_notes: list[str] = Field(default_factory=list)


def _default_cmd_runner(cmd: Sequence[str]) -> tuple[int, str, str]:
    proc = subprocess.run(list(cmd), capture_output=True, text=True, check=False)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def _default_http_probe(origin: str) -> tuple[bool, int | None, str]:
    last_status: int | None = None
    last_err = "no 2xx response"
    with httpx.Client(timeout=3.0, trust_env=False, follow_redirects=False) as client:
        for path in ("/v1/models", "/health"):
            try:
                resp = client.get(f"{origin}{path}")
                if 200 <= resp.status_code < 300:
                    return True, resp.status_code, f"Reachable at {origin}{path}"
                last_status = resp.status_code
                last_err = f"HTTP {resp.status_code} on {path}"
            except httpx.HTTPError as exc:
                last_err = str(exc)
                continue
        return False, last_status, f"Local LLM endpoint unreachable at {origin}: {last_err}"


def check_linux_os(
    *,
    system_name: str | None = None,
    os_release_path: Path = Path("/etc/os-release"),
) -> CheckResult:
    """Verify Linux kernel host and read /etc/os-release metadata."""
    os_name = system_name if system_name is not None else platform.system()
    if os_name != "Linux":
        return CheckResult(
            name="linux_os",
            status=CheckStatus.PENDING_N3_LINUX_ENV,
            required_for=EvidenceLevel.N3,
            summary=(
                f"PENDING_N3_LINUX_ENV: Host OS is {os_name}; "
                "Linux target environment is required for N3."
            ),
            detail={"is_linux": False, "system_name": os_name},
        )

    release_info = ""
    if os_release_path.exists():
        release_info = os_release_path.read_text(encoding="utf-8", errors="replace").strip()

    return CheckResult(
        name="linux_os",
        status=CheckStatus.PASS,
        required_for=EvidenceLevel.N3,
        summary="Linux host OS detected.",
        detail={"is_linux": True, "system_name": os_name, "os_release_present": bool(release_info)},
    )


def check_network_isolation_a11(
    *,
    system_name: str | None = None,
    which_fn: Callable[[str], str | None] = shutil.which,
    run_cmd: CommandRunner | None = None,
    probe_external_fn: Callable[[], bool] | None = None,
) -> CheckResult:
    """Inspect Linux netns/iptables/nft outbound-blocking evidence for A11."""
    os_name = system_name if system_name is not None else platform.system()
    if os_name != "Linux":
        return CheckResult(
            name="network_isolation_a11",
            status=CheckStatus.PENDING_N3_LINUX_ENV,
            required_for=EvidenceLevel.N3,
            summary=(
                "PENDING_N3_LINUX_ENV: Linux kernel network namespace / iptables "
                "egress isolation cannot be verified on non-Linux host."
            ),
            detail={"is_linux": False, "netns_verified": False, "iptables_verified": False},
        )

    runner = run_cmd if run_cmd is not None else _default_cmd_runner
    ip_bin = which_fn("ip")
    iptables_bin = which_fn("iptables")
    nft_bin = which_fn("nft")

    netns_list: list[str] = []
    if ip_bin:
        rc, out, _ = runner([ip_bin, "netns", "list"])
        if rc == 0 and out:
            netns_list = [line.strip() for line in out.splitlines() if line.strip()]

    firewall_rules_found = False
    if nft_bin:
        rc, out, _ = runner([nft_bin, "list", "ruleset"])
        if rc == 0 and ("drop" in out.lower() or "reject" in out.lower()):
            firewall_rules_found = True
    if not firewall_rules_found and iptables_bin:
        rc, out, _ = runner([iptables_bin, "-S", "OUTPUT"])
        if rc == 0 and ("DROP" in out or "REJECT" in out):
            firewall_rules_found = True

    external_reachable: bool | None = None
    if probe_external_fn is not None:
        external_reachable = bool(probe_external_fn())
        if external_reachable:
            return CheckResult(
                name="network_isolation_a11",
                status=CheckStatus.FAIL,
                required_for=EvidenceLevel.N3,
                summary="A11 egress check FAILED: external network connection succeeded.",
                detail={
                    "is_linux": True,
                    "netns_list": netns_list,
                    "firewall_rules_found": firewall_rules_found,
                    "external_reachable": True,
                },
            )

    netns_verified = bool(netns_list)
    iptables_verified = firewall_rules_found
    if (netns_verified or iptables_verified) and external_reachable is not True:
        return CheckResult(
            name="network_isolation_a11",
            status=CheckStatus.PASS,
            required_for=EvidenceLevel.N3,
            summary="Linux outbound network isolation controls detected.",
            detail={
                "is_linux": True,
                "netns_verified": netns_verified,
                "iptables_verified": iptables_verified,
                "netns_list": netns_list,
                "external_reachable": external_reachable,
            },
        )

    return CheckResult(
        name="network_isolation_a11",
        status=CheckStatus.PENDING_N3_LINUX_ENV,
        required_for=EvidenceLevel.N3,
        summary=(
            "PENDING_N3_LINUX_ENV: Linux host lacks verified netns/iptables/nft "
            "egress-blocking rules."
        ),
        detail={
            "is_linux": True,
            "netns_verified": netns_verified,
            "iptables_verified": iptables_verified,
            "external_reachable": external_reachable,
        },
    )


def check_local_llm_n3(
    *,
    system_name: str | None = None,
    llm_origin: str | None = None,
    allow_private_lan: bool = False,
    which_fn: Callable[[str], str | None] = shutil.which,
    http_probe_fn: HttpProbeFn | None = None,
) -> CheckResult:
    """Check local LLM runtimes and optionally probe an allowlisted local LLM endpoint."""
    os_name = system_name if system_name is not None else platform.system()
    is_linux = os_name == "Linux"
    llm_tools = ("ollama", "llama-server", "vllm")
    found_llms = {tool: which_fn(tool) for tool in llm_tools if which_fn(tool)}

    normalized_origin: str | None = None
    endpoint_reachable = False
    endpoint_status: int | None = None
    probe_note = ""

    if llm_origin is not None:
        try:
            normalized_origin = validate_local_model_origin(
                llm_origin, allow_private_lan=allow_private_lan
            )
        except (OriginNotAllowedError, ValueError) as exc:
            return CheckResult(
                name="local_llm_n3",
                status=CheckStatus.FAIL,
                required_for=EvidenceLevel.N3,
                summary=f"Disallowed or invalid local LLM origin: {exc}",
                detail={
                    "is_linux": is_linux,
                    "llm_origin": llm_origin,
                    "error": str(exc),
                },
            )
        probe_fn = http_probe_fn if http_probe_fn is not None else _default_http_probe
        endpoint_reachable, endpoint_status, probe_note = probe_fn(normalized_origin)

    detail: dict[str, Any] = {
        "is_linux": is_linux,
        "local_llm_runtimes": found_llms,
        "llm_origin": normalized_origin,
        "endpoint_reachable": endpoint_reachable,
        "endpoint_status": endpoint_status,
        "probe_note": probe_note,
    }

    if is_linux and (found_llms or endpoint_reachable):
        return CheckResult(
            name="local_llm_n3",
            status=CheckStatus.PASS,
            required_for=EvidenceLevel.N3,
            summary="Linux local LLM runtime/endpoint ready.",
            detail=detail,
        )

    pending_reason = "PENDING_LOCAL_LLM" if is_linux else "PENDING_N3_LINUX_ENV"
    detail["pending_reason"] = pending_reason
    return CheckResult(
        name="local_llm_n3",
        status=CheckStatus.PENDING_N3_LINUX_ENV,
        required_for=EvidenceLevel.N3,
        summary=(
            f"{pending_reason}: No Linux-backed local LLM runtime or reachable endpoint "
            f"(is_linux={is_linux}, runtimes={sorted(found_llms)})."
        ),
        detail=detail,
    )


def check_desktop_n3(
    *,
    system_name: str | None = None,
    env: Mapping[str, str] | None = None,
    which_fn: Callable[[str], str | None] = shutil.which,
    import_checker: Callable[[str], bool] | None = None,
    dbus_probe: Callable[[], bool] | None = None,
    vision_available: bool = False,
) -> tuple[CheckResult, DesktopCapabilityReport]:
    """Run desktop AT-SPI/X11/Wayland capability probe and wrap into CheckResult."""
    report = check_desktop_capabilities(
        system_name=system_name,
        env=env,
        which_fn=which_fn,
        import_checker=import_checker,
        dbus_probe=dbus_probe,
        vision_available=vision_available,
    )
    if report.status == "READY":
        status = CheckStatus.PASS
    elif report.status == "DEGRADED":
        status = CheckStatus.WARN
    else:
        status = CheckStatus.PENDING_N3_LINUX_ENV

    return (
        CheckResult(
            name="desktop_atspi_n3",
            status=status,
            required_for=EvidenceLevel.N3,
            summary=(
                f"Desktop capability status={report.status} "
                f"(display_server={report.display_server.value}, "
                f"at_spi={report.at_spi_available}, x11={report.x11_available}, "
                f"wayland={report.wayland_available})."
            ),
            detail=report.model_dump(mode="json"),
        ),
        report,
    )


def run_n3_probe(
    *,
    system_name: str | None = None,
    os_release_path: Path = Path("/etc/os-release"),
    llm_origin: str | None = None,
    allow_private_lan: bool = False,
    which_fn: Callable[[str], str | None] = shutil.which,
    run_cmd: CommandRunner | None = None,
    probe_external_fn: Callable[[], bool] | None = None,
    http_probe_fn: HttpProbeFn | None = None,
    env: Mapping[str, str] | None = None,
    import_checker: Callable[[str], bool] | None = None,
    dbus_probe: Callable[[], bool] | None = None,
    vision_available: bool = False,
) -> N3ProbeReport:
    """Run all N3 probes and aggregate an honest N3ProbeReport."""
    os_name = system_name if system_name is not None else platform.system()
    os_check = check_linux_os(system_name=os_name, os_release_path=os_release_path)
    net_check = check_network_isolation_a11(
        system_name=os_name,
        which_fn=which_fn,
        run_cmd=run_cmd,
        probe_external_fn=probe_external_fn,
    )
    llm_check = check_local_llm_n3(
        system_name=os_name,
        llm_origin=llm_origin,
        allow_private_lan=allow_private_lan,
        which_fn=which_fn,
        http_probe_fn=http_probe_fn,
    )
    desk_check, desk_report = check_desktop_n3(
        system_name=os_name,
        env=env,
        which_fn=which_fn,
        import_checker=import_checker,
        dbus_probe=dbus_probe,
        vision_available=vision_available,
    )

    checks = [os_check, net_check, llm_check, desk_check]
    linux_os_ready = os_check.status == CheckStatus.PASS
    network_isolation_ready = net_check.status == CheckStatus.PASS
    local_llm_ready = llm_check.status == CheckStatus.PASS
    desktop_ready = desk_check.status == CheckStatus.PASS

    overall_status: N3Status
    if linux_os_ready and network_isolation_ready and local_llm_ready:
        overall_status = "READY"
    elif linux_os_ready and network_isolation_ready and not local_llm_ready:
        overall_status = "PENDING_LOCAL_LLM"
    else:
        overall_status = "PENDING_N3_LINUX_ENV"

    notes: list[str] = []
    if not linux_os_ready:
        notes.append(
            f"Host OS is {os_name}; macOS/emulated results are NEVER attributed as Linux N3."
        )
    if not network_isolation_ready:
        notes.append("A11 kernel netns/iptables outbound-block verification is pending Linux env.")
    if not local_llm_ready:
        notes.append("Real local LLM server/weights N3 verification is pending.")
    if desk_report.limitations:
        notes.extend(desk_report.limitations)

    return N3ProbeReport(
        timestamp_utc=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        host_os=os_name,
        host_release=platform.release(),
        arch=platform.machine(),
        overall_status=overall_status,
        linux_os_ready=linux_os_ready,
        network_isolation_ready=network_isolation_ready,
        desktop_ready=desktop_ready,
        local_llm_ready=local_llm_ready,
        checks=checks,
        desktop_capabilities=desk_report,
        evidence_notes=notes,
    )


def _format_human_n3(report: N3ProbeReport) -> str:
    lines = [
        f"Grokbot-clon N3 Probe ({report.timestamp_utc})",
        f"Host: {report.host_os} {report.host_release} ({report.arch})",
        (
            f"Overall: {report.overall_status} | linux={report.linux_os_ready} | "
            f"net_a11={report.network_isolation_ready} | llm={report.local_llm_ready} | "
            f"desktop={report.desktop_ready}"
        ),
        "",
    ]
    for c in report.checks:
        lines.append(f"- [{c.status.value.upper()}] {c.name}: {c.summary}")
    if report.evidence_notes:
        lines.append("")
        lines.append("Notes:")
        for note in report.evidence_notes:
            lines.append(f"  * {note}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for N3 Linux/LLM/A11/Desktop readiness probe."""
    parser = argparse.ArgumentParser(description="Grokbot-clon Linux N3 readiness probe")
    parser.add_argument("--json", action="store_true", help="Emit JSON N3ProbeReport.")
    parser.add_argument("--llm-origin", default=None, help="Optional local LLM origin to probe.")
    parser.add_argument(
        "--allow-private-lan",
        action="store_true",
        help="Allow RFC1918/ULA LAN origins for --llm-origin.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 unless overall_status == READY.",
    )
    args = parser.parse_args(argv)

    report = run_n3_probe(
        llm_origin=args.llm_origin,
        allow_private_lan=args.allow_private_lan,
    )
    if args.json:
        print(report.model_dump_json(indent=2))
    else:
        print(_format_human_n3(report))

    if any(c.status == CheckStatus.FAIL for c in report.checks):
        return 2
    if args.strict and report.overall_status != "READY":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
