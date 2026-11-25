"""Linux desktop AT-SPI / X11 / Wayland prototype interface and capability probe (F12)."""

from __future__ import annotations

import importlib.util
import os
import platform
import shutil
import time
import uuid
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping, Sequence
from enum import StrEnum
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import Field

from src.adapters._common import AdapterPermissionError, scrub_for_receipt
from src.contracts.common import FrozenModel, NonEmptyStr, utc_now
from src.contracts.enums import DataQuality, EffectClass, ReceiptOutcome
from src.contracts.models import ActionReceipt, Observation, RetryPolicy, TaskSpec, ToolSpec


class DisplayServer(StrEnum):
    """Detected Linux display server environment."""

    X11 = "x11"
    WAYLAND = "wayland"
    XWAYLAND = "xwayland"
    UNKNOWN = "unknown"
    NON_LINUX = "non_linux"


class DesktopBackendKind(StrEnum):
    """Desktop automation/observation backend selected for an operation."""

    AT_SPI = "at_spi"
    X11_XTEST = "x11_xtest"
    WAYLAND_PORTAL = "wayland_portal"
    VISION_REGION = "vision_region"
    UNAVAILABLE = "unavailable"


class DesktopError(RuntimeError):
    """Base error for Linux desktop adapter operations."""


class DesktopUnavailableError(DesktopError):
    """Raised when Linux AT-SPI/display backend is unavailable (e.g. macOS)."""


class DesktopCapabilityError(DesktopError):
    """Raised when an action is unsupported by the active display server (e.g. Wayland coords)."""


class DesktopCapabilityReport(FrozenModel):
    """Structured capability report separating X11, XWayland, Wayland, AT-SPI, and Vision."""

    host_os: str
    status: Literal["READY", "DEGRADED", "PENDING_N3_LINUX_ENV"]
    display_server: DisplayServer
    at_spi_available: bool
    x11_available: bool
    wayland_available: bool
    xwayland_available: bool
    vision_fallback_available: bool
    supported_actions: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    detail: dict[str, Any] = Field(default_factory=dict)


class AccessibilityNode(FrozenModel):
    """Immutable AT-SPI accessibility tree node."""

    node_id: NonEmptyStr
    app_name: NonEmptyStr
    role: NonEmptyStr
    name: str = ""
    text: str = ""
    value: str | None = None
    states: tuple[str, ...] = ()
    actions: tuple[str, ...] = ()
    bounds: tuple[int, int, int, int] | None = None
    children: tuple[AccessibilityNode, ...] = ()


class DesktopActionRequest(FrozenModel):
    """Requested desktop observation or element/region action."""

    app_name: NonEmptyStr
    action_name: Literal[
        "observe",
        "press",
        "set_value",
        "focus",
        "coordinate_click",
        "vision_region_read",
    ]
    node_id: str | None = None
    role: str | None = None
    name: str | None = None
    value: str | None = None
    x: int | None = None
    y: int | None = None
    region: tuple[int, int, int, int] | None = None


class DesktopActionResult(FrozenModel):
    """Verified outcome and redacted ActionReceipt for a desktop adapter call."""

    succeeded: bool
    backend_used: DesktopBackendKind
    display_server: DisplayServer
    observed_before: AccessibilityNode | None = None
    observed_after: AccessibilityNode | None = None
    observations: tuple[Observation, ...] = ()
    receipt: ActionReceipt | None = None
    detail: str = ""


def _default_import_checker(module_name: str) -> bool:
    try:
        return importlib.util.find_spec(module_name) is not None
    except (ImportError, ValueError):
        return False


def check_desktop_capabilities(
    *,
    system_name: str | None = None,
    env: Mapping[str, str] | None = None,
    which_fn: Callable[[str], str | None] = shutil.which,
    import_checker: Callable[[str], bool] | None = None,
    dbus_probe: Callable[[], bool] | None = None,
    vision_available: bool = False,
) -> DesktopCapabilityReport:
    """Probe Linux desktop AT-SPI, X11, Wayland, XWayland, and vision fallback capabilities."""
    os_name = system_name if system_name is not None else platform.system()
    if os_name != "Linux":
        return DesktopCapabilityReport(
            host_os=os_name,
            status="PENDING_N3_LINUX_ENV",
            display_server=DisplayServer.NON_LINUX,
            at_spi_available=False,
            x11_available=False,
            wayland_available=False,
            xwayland_available=False,
            vision_fallback_available=False,
            supported_actions=(),
            limitations=(
                f"PENDING_N3_LINUX_ENV: Linux desktop with AT-SPI/X11/Wayland required "
                f"(active OS={os_name}).",
            ),
            detail={"is_linux": False},
        )

    active_env = env if env is not None else os.environ
    check_import = import_checker if import_checker is not None else _default_import_checker

    session_type = active_env.get("XDG_SESSION_TYPE", "").strip().lower()
    display = active_env.get("DISPLAY", "").strip()
    wayland_display = active_env.get("WAYLAND_DISPLAY", "").strip()

    x11_available = False
    wayland_available = False
    xwayland_available = False
    if wayland_display and display:
        display_server = DisplayServer.XWAYLAND
        wayland_available = True
        xwayland_available = True
        x11_available = True
    elif wayland_display or session_type == "wayland":
        display_server = DisplayServer.WAYLAND
        wayland_available = True
    elif display or session_type == "x11":
        display_server = DisplayServer.X11
        x11_available = True
    else:
        display_server = DisplayServer.UNKNOWN

    has_pyatspi = check_import("pyatspi")
    has_gi_atspi = check_import("gi")
    at_spi_bus = bool(active_env.get("AT_SPI_BUS_ADDRESS", "").strip()) or (
        dbus_probe() if dbus_probe is not None else False
    )
    at_spi_bindings = has_pyatspi or has_gi_atspi
    at_spi_available = (
        at_spi_bindings
        and (at_spi_bus or display_server != DisplayServer.UNKNOWN)
    )

    x11_tools = {t: which_fn(t) for t in ("xdotool", "xclip") if which_fn(t)}
    wayland_tools = {t: which_fn(t) for t in ("wtype", "ydotool", "wl-paste") if which_fn(t)}

    actions: list[str] = []
    limitations: list[str] = []

    if at_spi_available:
        actions.extend(["observe", "press", "set_value", "focus"])
    else:
        limitations.append(
            "AT-SPI bindings (pyatspi/gi) or active accessibility bus unavailable."
        )

    if display_server in (DisplayServer.X11, DisplayServer.XWAYLAND):
        actions.append("coordinate_click")
        if display_server == DisplayServer.XWAYLAND:
            limitations.append(
                "XWayland active: coordinate clicks apply only to XWayland windows, "
                "not native Wayland surfaces."
            )
    elif display_server == DisplayServer.WAYLAND:
        limitations.append(
            "Native Wayland: absolute coordinate clicks unavailable; use AT-SPI element actions."
        )
    else:
        limitations.append(
            "PENDING_N3_LINUX_ENV: Neither DISPLAY (X11) nor WAYLAND_DISPLAY is active."
        )

    if vision_available:
        actions.append("vision_region_read")

    if display_server == DisplayServer.UNKNOWN or (
        not at_spi_available and not x11_available and not wayland_available
    ):
        status: Literal["READY", "DEGRADED", "PENDING_N3_LINUX_ENV"] = "PENDING_N3_LINUX_ENV"
    elif at_spi_available:
        status = "READY"
    else:
        status = "DEGRADED"

    return DesktopCapabilityReport(
        host_os=os_name,
        status=status,
        display_server=display_server,
        at_spi_available=at_spi_available,
        x11_available=x11_available,
        wayland_available=wayland_available,
        xwayland_available=xwayland_available,
        vision_fallback_available=vision_available,
        supported_actions=tuple(dict.fromkeys(actions)),
        limitations=tuple(limitations),
        detail={
            "is_linux": True,
            "xdg_session_type": session_type or None,
            "has_display": bool(display),
            "has_wayland_display": bool(wayland_display),
            "has_pyatspi": has_pyatspi,
            "has_gi": has_gi_atspi,
            "at_spi_bus": at_spi_bus,
            "x11_tools": sorted(x11_tools.keys()),
            "wayland_tools": sorted(wayland_tools.keys()),
        },
    )


@runtime_checkable
class AtSpiDesktopBackend(Protocol):
    """Low-level Linux AT-SPI / display-server backend contract."""

    def get_tree(self, app_name: str, max_depth: int = 6) -> AccessibilityNode:
        """Read the current accessibility tree for app_name."""
        ...

    def perform_element_action(
        self,
        app_name: str,
        node_id: str | None,
        role: str | None,
        name: str | None,
        action_name: str,
        value: str | None = None,
    ) -> bool:
        """Execute an AT-SPI semantic element action."""
        ...

    def coordinate_click(self, x: int, y: int) -> bool:
        """Execute an absolute screen coordinate click (X11/XWayland only)."""
        ...


@runtime_checkable
class VisionFallbackProvider(Protocol):
    """Bounded local vision fallback observing a concrete region."""

    def observe_region(
        self,
        app_name: str,
        region: tuple[int, int, int, int],
    ) -> dict[str, Any]:
        """Inspect a bounded (x, y, width, height) region locally and return structured info."""
        ...


class DesktopAdapter(ABC):
    """Abstract Linux desktop adapter interface."""

    @property
    @abstractmethod
    def capabilities(self) -> DesktopCapabilityReport:
        """Return capability report for the active desktop environment."""

    @abstractmethod
    def observe_tree(
        self,
        *,
        task: TaskSpec,
        app_name: str,
        max_depth: int = 6,
    ) -> tuple[AccessibilityNode, tuple[Observation, ...]]:
        """Observe an application's accessibility tree."""

    @abstractmethod
    def execute_action(
        self,
        *,
        task: TaskSpec,
        request: DesktopActionRequest,
        run_id: str = "run-desktop",
        step_id: str = "step-desktop",
        attempt: int = 1,
        operation_key: str = "op-desktop",
    ) -> DesktopActionResult:
        """Run the Observe -> Guard -> Execute -> Verify loop with redacted ActionReceipt."""


def _flatten_nodes(node: AccessibilityNode) -> list[AccessibilityNode]:
    nodes = [node]
    for child in node.children:
        nodes.extend(_flatten_nodes(child))
    return nodes


def _find_matching_node(
    tree: AccessibilityNode,
    request: DesktopActionRequest,
) -> AccessibilityNode | None:
    for node in _flatten_nodes(tree):
        if request.node_id is not None and node.node_id == request.node_id:
            return node
        if request.node_id is None:
            role_ok = request.role is None or node.role.lower() == request.role.lower()
            name_ok = request.name is None or node.name.lower() == request.name.lower()
            if role_ok and name_ok and (request.role is not None or request.name is not None):
                return node
    return None


class LinuxAtSpiDesktopAdapter(DesktopAdapter):
    """Guarded AT-SPI desktop adapter enforcing app allowlist, read_only, and Wayland limits."""

    def __init__(
        self,
        *,
        backend: AtSpiDesktopBackend | None = None,
        vision_provider: VisionFallbackProvider | None = None,
        capability_report: DesktopCapabilityReport | None = None,
        allowed_apps: Sequence[str] = (),
    ) -> None:
        self._backend = backend
        self._vision_provider = vision_provider
        self._capability_report = (
            capability_report
            if capability_report is not None
            else check_desktop_capabilities(vision_available=(vision_provider is not None))
        )
        self._allowed_apps = tuple(a.strip() for a in allowed_apps if a.strip())

    @property
    def capabilities(self) -> DesktopCapabilityReport:
        return self._capability_report

    def _guard_app_and_permissions(
        self,
        task: TaskSpec,
        request: DesktopActionRequest,
    ) -> None:
        if not self._allowed_apps:
            raise AdapterPermissionError(
                "Desktop adapter requires a non-empty allowed_apps allowlist; "
                f"denied app {request.app_name!r}."
            )
        if request.app_name not in self._allowed_apps:
            raise AdapterPermissionError(
                f"Desktop app {request.app_name!r} is outside allowed_apps {self._allowed_apps}."
            )
        is_read_action = request.action_name in ("observe", "vision_region_read")
        if task.scope.read_only and not is_read_action:
            raise AdapterPermissionError(
                f"Desktop action {request.action_name!r} denied when TaskScope.read_only=True."
            )
        tool_id = (
            "desktop.observe_tree"
            if is_read_action
            else "desktop.perform_action"
        )
        if task.scope.allowed_tools and tool_id not in task.scope.allowed_tools:
            raise AdapterPermissionError(
                f"Tool {tool_id!r} not in TaskScope.allowed_tools."
            )

    def _require_backend(self) -> AtSpiDesktopBackend:
        if self._backend is None:
            raise DesktopUnavailableError(
                f"PENDING_N3_LINUX_ENV: Linux AT-SPI backend unavailable "
                f"(status={self._capability_report.status}, "
                f"display_server={self._capability_report.display_server.value})."
            )
        return self._backend

    def observe_tree(
        self,
        *,
        task: TaskSpec,
        app_name: str,
        max_depth: int = 6,
    ) -> tuple[AccessibilityNode, tuple[Observation, ...]]:
        req = DesktopActionRequest(app_name=app_name, action_name="observe")
        self._guard_app_and_permissions(task, req)
        backend = self._require_backend()
        tree = backend.get_tree(app_name, max_depth=max_depth)
        now = utc_now()
        flat = _flatten_nodes(tree)
        obs = tuple(
            Observation(
                source="desktop_atspi",
                session_id=f"desktop:{app_name}",
                asset_id=node.node_id,
                observed_label=node.name or node.role,
                value=node.value if node.value is not None else node.text,
                unit=None,
                source_time=now,
                observed_at=now,
                quality=DataQuality.GOOD,
                authorized_evidence=True,
                area=task.scope.allowed_areas[0] if task.scope.allowed_areas else None,
                metadata={
                    "app_name": app_name,
                    "role": node.role,
                    "actions": list(node.actions),
                    "method": DesktopBackendKind.AT_SPI.value,
                },
            )
            for node in flat
        )
        return tree, obs

    def execute_action(
        self,
        *,
        task: TaskSpec,
        request: DesktopActionRequest,
        run_id: str = "run-desktop",
        step_id: str = "step-desktop",
        attempt: int = 1,
        operation_key: str = "op-desktop",
    ) -> DesktopActionResult:
        started = time.perf_counter()
        self._guard_app_and_permissions(task, request)

        display_server = self._capability_report.display_server
        tool_id = (
            "desktop.observe_tree"
            if request.action_name in ("observe", "vision_region_read")
            else "desktop.perform_action"
        )
        redacted_args = scrub_for_receipt(request.model_dump(mode="json"))

        if request.action_name == "vision_region_read":
            if self._vision_provider is None:
                raise DesktopUnavailableError(
                    "PENDING_N3_LINUX_ENV: Local VisionFallbackProvider is not configured."
                )
            if request.region is None:
                raise DesktopCapabilityError(
                    "vision_region_read requires a bounded (x, y, width, height) region."
                )
            rx, ry, rw, rh = request.region
            if rw <= 0 or rh <= 0 or rx < 0 or ry < 0:
                raise DesktopCapabilityError(
                    "vision_region_read region must have positive width/height, "
                    f"got {request.region}."
                )
            region_data = self._vision_provider.observe_region(request.app_name, request.region)
            duration_ms = (time.perf_counter() - started) * 1000.0
            now = utc_now()
            obs = Observation(
                source="desktop_vision_region",
                session_id=f"desktop:{request.app_name}",
                asset_id=f"{request.app_name}:region:{rx},{ry},{rw},{rh}",
                observed_label=str(region_data.get("label") or request.app_name),
                value=str(region_data.get("text") or ""),
                unit=None,
                source_time=now,
                observed_at=now,
                quality=DataQuality.UNCERTAIN,
                authorized_evidence=True,
                metadata={
                    "method": DesktopBackendKind.VISION_REGION.value,
                    "region": [rx, ry, rw, rh],
                    "display_server": display_server.value,
                },
            )
            receipt = ActionReceipt(
                receipt_id=f"rcpt-{uuid.uuid4().hex[:12]}",
                task_id=task.task_id,
                run_id=run_id,
                step_id=step_id,
                attempt=attempt,
                tool_id=tool_id,
                redacted_args=redacted_args,
                operation_key=operation_key,
                observed_before=scrub_for_receipt({"region": [rx, ry, rw, rh]}),
                observed_after=scrub_for_receipt(
                    {
                        "method": DesktopBackendKind.VISION_REGION.value,
                        "result": region_data,
                    }
                ),
                duration_ms=duration_ms,
                evidence_refs=(f"desktop_vision:{request.app_name}:{rx},{ry},{rw},{rh}",),
                outcome=ReceiptOutcome.SUCCEEDED,
            )
            return DesktopActionResult(
                succeeded=True,
                backend_used=DesktopBackendKind.VISION_REGION,
                display_server=display_server,
                observations=(obs,),
                receipt=receipt,
                detail="Bounded local vision region observation completed.",
            )

        backend = self._require_backend()

        if request.action_name == "coordinate_click":
            if display_server not in (DisplayServer.X11, DisplayServer.XWAYLAND):
                raise DesktopCapabilityError(
                    f"coordinate_click is unsupported on display_server={display_server.value!r}; "
                    "native Wayland does not expose absolute window geometry."
                )
            if request.x is None or request.y is None:
                raise DesktopCapabilityError(
                    "coordinate_click requires explicit x and y coordinates."
                )

        # 1. Observe before
        observed_before = backend.get_tree(request.app_name)

        if request.action_name == "observe":
            duration_ms = (time.perf_counter() - started) * 1000.0
            now = utc_now()
            obs_tuple = tuple(
                Observation(
                    source="desktop_atspi",
                    session_id=f"desktop:{request.app_name}",
                    asset_id=node.node_id,
                    observed_label=node.name or node.role,
                    value=node.value if node.value is not None else node.text,
                    source_time=now,
                    observed_at=now,
                    quality=DataQuality.GOOD,
                    authorized_evidence=True,
                    metadata={
                        "role": node.role,
                        "method": DesktopBackendKind.AT_SPI.value,
                    },
                )
                for node in _flatten_nodes(observed_before)
            )
            receipt = ActionReceipt(
                receipt_id=f"rcpt-{uuid.uuid4().hex[:12]}",
                task_id=task.task_id,
                run_id=run_id,
                step_id=step_id,
                attempt=attempt,
                tool_id=tool_id,
                redacted_args=redacted_args,
                operation_key=operation_key,
                observed_before=scrub_for_receipt(observed_before.model_dump(mode="json")),
                observed_after=scrub_for_receipt({"node_count": len(obs_tuple)}),
                duration_ms=duration_ms,
                evidence_refs=(f"desktop_atspi:{request.app_name}",),
                outcome=ReceiptOutcome.SUCCEEDED,
            )
            return DesktopActionResult(
                succeeded=True,
                backend_used=DesktopBackendKind.AT_SPI,
                display_server=display_server,
                observed_before=observed_before,
                observed_after=observed_before,
                observations=obs_tuple,
                receipt=receipt,
                detail="AT-SPI tree observed.",
            )

        # 2. Execute
        if request.action_name == "coordinate_click":
            assert request.x is not None and request.y is not None
            ok = backend.coordinate_click(request.x, request.y)
            backend_used = DesktopBackendKind.X11_XTEST
        else:
            target_node = _find_matching_node(observed_before, request)
            if target_node is None and (
                request.node_id is not None or request.role is not None or request.name is not None
            ):
                ok = False
            else:
                ok = backend.perform_element_action(
                    request.app_name,
                    request.node_id,
                    request.role,
                    request.name,
                    request.action_name,
                    value=request.value,
                )
            backend_used = DesktopBackendKind.AT_SPI

        # 3. Observe after & verify
        observed_after = backend.get_tree(request.app_name)
        duration_ms = (time.perf_counter() - started) * 1000.0
        outcome = ReceiptOutcome.SUCCEEDED if ok else ReceiptOutcome.FAILED_SEMANTIC
        receipt = ActionReceipt(
            receipt_id=f"rcpt-{uuid.uuid4().hex[:12]}",
            task_id=task.task_id,
            run_id=run_id,
            step_id=step_id,
            attempt=attempt,
            tool_id=tool_id,
            redacted_args=redacted_args,
            operation_key=operation_key,
            observed_before=scrub_for_receipt(observed_before.model_dump(mode="json")),
            observed_after=scrub_for_receipt(observed_after.model_dump(mode="json")),
            duration_ms=duration_ms,
            evidence_refs=(f"desktop:{request.app_name}:{request.action_name}",),
            outcome=outcome,
            error_detail=None if ok else f"Desktop action {request.action_name!r} failed.",
        )
        return DesktopActionResult(
            succeeded=ok,
            backend_used=backend_used,
            display_server=display_server,
            observed_before=observed_before,
            observed_after=observed_after,
            observations=(),
            receipt=receipt,
            detail="Action executed and verified." if ok else "Desktop target/action failed.",
        )


def get_desktop_tool_specs(allowed_apps: Sequence[str] = ()) -> dict[str, ToolSpec]:
    """Return ToolSpec contracts for desktop.observe_tree and desktop.perform_action."""
    app_enum = [a.strip() for a in allowed_apps if a.strip()]
    app_prop: dict[str, Any] = {"type": "string", "minLength": 1}
    if app_enum:
        app_prop["enum"] = app_enum

    return {
        "desktop.observe_tree": ToolSpec(
            tool_id="desktop.observe_tree",
            version="1.0.0",
            input_schema={
                "type": "object",
                "required": ["app_name"],
                "properties": {
                    "app_name": app_prop,
                    "max_depth": {"type": "integer", "minimum": 1},
                },
            },
            output_schema={
                "type": "object",
                "required": ["app_name", "node_count"],
                "properties": {
                    "app_name": {"type": "string"},
                    "node_count": {"type": "integer", "minimum": 0},
                    "tree": {"type": "object"},
                },
            },
            permissions=("desktop:read",),
            allowed_origins=(),
            effect_class=EffectClass.READ,
            timeout_s=10.0,
            verifier_name="verify_desktop_observation",
            retry_policy=RetryPolicy(max_retries=1, retry_on_transient=True, backoff_seconds=0.5),
        ),
        "desktop.perform_action": ToolSpec(
            tool_id="desktop.perform_action",
            version="1.0.0",
            input_schema={
                "type": "object",
                "required": ["app_name", "action_name"],
                "properties": {
                    "app_name": app_prop,
                    "action_name": {
                        "type": "string",
                        "enum": ["press", "set_value", "focus", "coordinate_click"],
                    },
                    "node_id": {"type": "string"},
                    "role": {"type": "string"},
                    "name": {"type": "string"},
                    "value": {"type": "string"},
                    "x": {"type": "integer"},
                    "y": {"type": "integer"},
                },
            },
            output_schema={
                "type": "object",
                "required": ["succeeded", "backend_used", "display_server"],
                "properties": {
                    "succeeded": {"type": "boolean"},
                    "backend_used": {"type": "string"},
                    "display_server": {"type": "string"},
                },
            },
            permissions=("desktop:write",),
            allowed_origins=(),
            effect_class=EffectClass.EFFECT,
            timeout_s=10.0,
            verifier_name="verify_desktop_action",
            retry_policy=RetryPolicy(max_retries=0, retry_on_transient=False, backoff_seconds=0.0),
        ),
    }
