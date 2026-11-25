"""N1 unit tests for Linux desktop AT-SPI/X11/Wayland adapter & capability probe (F12)."""

from __future__ import annotations

from typing import Any

import pytest
from src.adapters._common import AdapterPermissionError
from src.adapters.desktop import (
    AccessibilityNode,
    DesktopActionRequest,
    DesktopBackendKind,
    DesktopCapabilityError,
    DesktopUnavailableError,
    DisplayServer,
    LinuxAtSpiDesktopAdapter,
    check_desktop_capabilities,
    get_desktop_tool_specs,
)
from src.contracts.common import utc_now
from src.contracts.enums import ReceiptOutcome
from src.contracts.models import TaskScope, TaskSpec
from src.contracts.redaction import REDACTED_PLACEHOLDER, contains_unredacted_secret
from src.engine.tool_registry import ToolExecutionContext, ToolRegistry


class _FakeAtSpiBackend:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []
        self.tree = AccessibilityNode(
            node_id="root-1",
            app_name="hmi_panel",
            role="frame",
            name="Pump Control",
            children=(
                AccessibilityNode(
                    node_id="btn-ack",
                    app_name="hmi_panel",
                    role="push_button",
                    name="Acknowledge",
                    actions=("press", "focus"),
                    bounds=(10, 20, 100, 40),
                ),
                AccessibilityNode(
                    node_id="txt-setpoint",
                    app_name="hmi_panel",
                    role="text",
                    name="Setpoint",
                    value="4.0",
                    actions=("set_value",),
                ),
            ),
        )

    def get_tree(self, app_name: str, max_depth: int = 6) -> AccessibilityNode:
        self.calls.append(("get_tree", (app_name, max_depth)))
        return self.tree

    def perform_element_action(
        self,
        app_name: str,
        node_id: str | None,
        role: str | None,
        name: str | None,
        action_name: str,
        value: str | None = None,
    ) -> bool:
        self.calls.append(
            ("perform_element_action", (app_name, node_id, role, name, action_name, value))
        )
        return True

    def coordinate_click(self, x: int, y: int) -> bool:
        self.calls.append(("coordinate_click", (x, y)))
        return True


class _FakeVisionProvider:
    def observe_region(
        self,
        app_name: str,
        region: tuple[int, int, int, int],
    ) -> dict[str, Any]:
        return {"app_name": app_name, "region": list(region), "label": "Gauge", "text": "8.4 mm/s"}


def _task(*, read_only: bool = True, allowed_tools: tuple[str, ...] = ()) -> TaskSpec:
    return TaskSpec(
        task_id="task-desk-1",
        user_id="operator",
        profile_id="prof",
        scope=TaskScope(
            facility_id="facility-a",
            allowed_origins=(),
            allowed_areas=("area-1",),
            allowed_tools=allowed_tools,
            read_only=read_only,
        ),
        query="Inspect HMI panel",
    )


@pytest.mark.n1
def test_desktop_capability_probe_darwin_reports_pending_n3() -> None:
    report = check_desktop_capabilities(system_name="Darwin")
    assert report.status == "PENDING_N3_LINUX_ENV"
    assert report.display_server == DisplayServer.NON_LINUX
    assert report.at_spi_available is False
    assert report.x11_available is False
    assert report.wayland_available is False
    assert report.supported_actions == ()
    assert any("PENDING_N3_LINUX_ENV" in item for item in report.limitations)


@pytest.mark.n1
def test_desktop_capability_probe_linux_x11_wayland_xwayland_separated() -> None:
    x11 = check_desktop_capabilities(
        system_name="Linux",
        env={
            "DISPLAY": ":0",
            "XDG_SESSION_TYPE": "x11",
            "AT_SPI_BUS_ADDRESS": "unix:path=/tmp/bus",
        },
        which_fn=lambda tool: f"/usr/bin/{tool}" if tool == "xdotool" else None,
        import_checker=lambda mod: mod == "gi",
    )
    assert x11.status == "READY"
    assert x11.display_server == DisplayServer.X11
    assert x11.x11_available is True
    assert x11.wayland_available is False
    assert "coordinate_click" in x11.supported_actions
    assert "press" in x11.supported_actions

    wayland = check_desktop_capabilities(
        system_name="Linux",
        env={
            "WAYLAND_DISPLAY": "wayland-0",
            "XDG_SESSION_TYPE": "wayland",
            "AT_SPI_BUS_ADDRESS": "unix:path=/tmp/bus",
        },
        which_fn=lambda tool: f"/usr/bin/{tool}" if tool == "wtype" else None,
        import_checker=lambda mod: mod == "pyatspi",
    )
    assert wayland.status == "READY"
    assert wayland.display_server == DisplayServer.WAYLAND
    assert wayland.wayland_available is True
    assert wayland.xwayland_available is False
    assert wayland.x11_available is False
    assert "coordinate_click" not in wayland.supported_actions
    assert "press" in wayland.supported_actions
    assert any("Native Wayland" in lim for lim in wayland.limitations)

    xwayland = check_desktop_capabilities(
        system_name="Linux",
        env={
            "DISPLAY": ":0",
            "WAYLAND_DISPLAY": "wayland-0",
            "XDG_SESSION_TYPE": "wayland",
            "AT_SPI_BUS_ADDRESS": "unix:path=/tmp/bus",
        },
        which_fn=lambda _: None,
        import_checker=lambda mod: mod == "gi",
    )
    assert xwayland.display_server == DisplayServer.XWAYLAND
    assert xwayland.xwayland_available is True
    assert "coordinate_click" in xwayland.supported_actions

    headless = check_desktop_capabilities(
        system_name="Linux",
        env={},
        which_fn=lambda _: None,
        import_checker=lambda _: False,
    )
    assert headless.status == "PENDING_N3_LINUX_ENV"
    assert headless.display_server == DisplayServer.UNKNOWN


@pytest.mark.n1
def test_linux_atspi_adapter_guard_observe_execute_verify_and_receipt() -> None:
    backend = _FakeAtSpiBackend()
    cap_x11 = check_desktop_capabilities(
        system_name="Linux",
        env={"DISPLAY": ":0", "AT_SPI_BUS_ADDRESS": "unix:path=/tmp/a"},
        which_fn=lambda _: None,
        import_checker=lambda mod: mod == "gi",
    )
    adapter = LinuxAtSpiDesktopAdapter(
        backend=backend,
        capability_report=cap_x11,
        allowed_apps=("hmi_panel",),
    )

    tree, obs = adapter.observe_tree(task=_task(read_only=True), app_name="hmi_panel")
    assert tree.app_name == "hmi_panel"
    assert len(obs) == 3

    res = adapter.execute_action(
        task=_task(read_only=False),
        request=DesktopActionRequest(
            app_name="hmi_panel",
            action_name="set_value",
            node_id="txt-setpoint",
            value="token=SECRET_SHOULD_REDACT",
        ),
    )
    assert res.succeeded is True
    assert res.backend_used == DesktopBackendKind.AT_SPI
    assert res.receipt is not None
    assert res.receipt.outcome == ReceiptOutcome.SUCCEEDED
    assert not contains_unredacted_secret(res.receipt.model_dump())

    res_secret = adapter.execute_action(
        task=_task(read_only=False),
        request=DesktopActionRequest(
            app_name="hmi_panel",
            action_name="press",
            node_id="btn-ack",
            value="http://op:secretpass@hmi.local",
        ),
    )
    assert res_secret.receipt is not None
    assert "secretpass" not in str(res_secret.receipt.redacted_args)
    assert REDACTED_PLACEHOLDER in str(res_secret.receipt.redacted_args)


@pytest.mark.n1
def test_linux_atspi_adapter_permission_readonly_and_wayland_coords_rejected() -> None:
    backend = _FakeAtSpiBackend()
    cap_wayland = check_desktop_capabilities(
        system_name="Linux",
        env={"WAYLAND_DISPLAY": "wayland-0", "AT_SPI_BUS_ADDRESS": "unix:path=/tmp/a"},
        which_fn=lambda _: None,
        import_checker=lambda mod: mod == "pyatspi",
    )
    adapter = LinuxAtSpiDesktopAdapter(
        backend=backend,
        capability_report=cap_wayland,
        allowed_apps=("hmi_panel",),
    )

    with pytest.raises(AdapterPermissionError):
        adapter.execute_action(
            task=_task(read_only=False),
            request=DesktopActionRequest(app_name="other_app", action_name="observe"),
        )

    adapter_empty_allowlist = LinuxAtSpiDesktopAdapter(
        backend=backend,
        capability_report=cap_wayland,
        allowed_apps=(),
    )
    with pytest.raises(AdapterPermissionError, match="allowed_apps"):
        adapter_empty_allowlist.observe_tree(task=_task(read_only=True), app_name="hmi_panel")
    with pytest.raises(AdapterPermissionError, match="allowed_apps"):
        adapter_empty_allowlist.execute_action(
            task=_task(read_only=False),
            request=DesktopActionRequest(app_name="hmi_panel", action_name="observe"),
        )

    with pytest.raises(AdapterPermissionError):
        adapter.execute_action(
            task=_task(read_only=True),
            request=DesktopActionRequest(
                app_name="hmi_panel",
                action_name="press",
                node_id="btn-ack",
            ),
        )

    with pytest.raises(DesktopCapabilityError, match="Wayland"):
        adapter.execute_action(
            task=_task(read_only=False),
            request=DesktopActionRequest(
                app_name="hmi_panel",
                action_name="coordinate_click",
                x=50,
                y=60,
            ),
        )
    assert backend.calls == []


@pytest.mark.n1
def test_linux_atspi_adapter_vision_region_fallback_and_unavailable_macos() -> None:
    cap_darwin = check_desktop_capabilities(system_name="Darwin")
    adapter_no_backend = LinuxAtSpiDesktopAdapter(
        backend=None,
        vision_provider=_FakeVisionProvider(),
        capability_report=cap_darwin,
        allowed_apps=("hmi_panel",),
    )
    with pytest.raises(DesktopUnavailableError, match="PENDING_N3_LINUX_ENV"):
        adapter_no_backend.observe_tree(task=_task(read_only=True), app_name="hmi_panel")

    vision_res = adapter_no_backend.execute_action(
        task=_task(read_only=True),
        request=DesktopActionRequest(
            app_name="hmi_panel",
            action_name="vision_region_read",
            region=(10, 20, 120, 40),
        ),
    )
    assert vision_res.succeeded is True
    assert vision_res.backend_used == DesktopBackendKind.VISION_REGION
    assert vision_res.observations[0].value == "8.4 mm/s"

    with pytest.raises(DesktopCapabilityError):
        adapter_no_backend.execute_action(
            task=_task(read_only=True),
            request=DesktopActionRequest(
                app_name="hmi_panel",
                action_name="vision_region_read",
                region=(10, 20, 0, 40),
            ),
        )


@pytest.mark.n1
async def test_desktop_tool_specs_integrate_with_tool_registry() -> None:
    specs = get_desktop_tool_specs(("hmi_panel",))
    backend = _FakeAtSpiBackend()
    cap_x11 = check_desktop_capabilities(
        system_name="Linux",
        env={"DISPLAY": ":0", "AT_SPI_BUS_ADDRESS": "unix:path=/tmp/a"},
        which_fn=lambda _: None,
        import_checker=lambda mod: mod == "gi",
    )
    adapter = LinuxAtSpiDesktopAdapter(
        backend=backend,
        capability_report=cap_x11,
        allowed_apps=("hmi_panel",),
    )

    registry = ToolRegistry()

    async def _observe_handler(
        args: dict[str, Any],
        ctx: ToolExecutionContext,
    ) -> dict[str, Any]:
        task = TaskSpec(
            task_id=ctx.task_id,
            user_id="operator",
            profile_id="prof",
            scope=ctx.scope,
            query="Observe desktop",
        )
        tree, obs = adapter.observe_tree(
            task=task,
            app_name=str(args["app_name"]),
            max_depth=int(args.get("max_depth", 6)),
        )
        return {
            "output": {
                "app_name": tree.app_name,
                "node_count": len(obs),
                "tree": tree.model_dump(mode="json"),
            },
            "observations": list(obs),
        }

    registry.register(specs["desktop.observe_tree"], _observe_handler)
    registry.register(
        specs["desktop.perform_action"],
        lambda args, ctx: {"succeeded": True, "backend_used": "at_spi", "display_server": "x11"},
    )

    ro_ctx = ToolExecutionContext(
        task_id="t-1",
        run_id="r-1",
        step_id="s-1",
        attempt=1,
        operation_key="op-1",
        scope=TaskScope(facility_id="facility-a", read_only=True),
        granted_permissions=("desktop:read", "desktop:write"),
        deadline_at=utc_now(),
    )
    obs_res = await registry.invoke("desktop.observe_tree", {"app_name": "hmi_panel"}, ro_ctx)
    assert obs_res.outcome == ReceiptOutcome.SUCCEEDED
    assert obs_res.output["node_count"] == 3

    denied = await registry.invoke(
        "desktop.perform_action",
        {"app_name": "hmi_panel", "action_name": "press"},
        ro_ctx,
    )
    assert denied.outcome == ReceiptOutcome.FAILED_PERMISSION
