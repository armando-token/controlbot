"""QA-0 / QA-1 baseline capture, React build verification, and /app surface gate."""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import fcntl
import hashlib
import json
import re
import shutil
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from src.contracts.common import utc_now
from src.doctor import run_doctor
from src.n3_probe import run_n3_probe
from src.qa.isolation import (
    LIVE_FORBIDDEN_PORTS,
    IsolatedLabServer,
    StrictPlaywrightSession,
    _has_unredacted_secret_any,
    _sanitize_record,
    _scrub_url_strict,
    assert_not_live_target,
    assert_safe_mutation_path,
    probe_live_readonly,
    summarize_active_logs,
)
from src.qa.models import BaselineReport, CampaignState, LaneName, ServedSurface, UIVariant

_ASSET_URL_RE = re.compile(r"/assets/[A-Za-z0-9_.\-/]+\.(?:js|css|mjs|woff2?|svg|png)")
_INLINE_ARRAY_RE = re.compile(r"var\s+(?:css|preloads|js|chunks)\s*=\s*(\[[^\]]*\])")
_REACT_TITLE = "Grok Bot — ControlBot Studio"
_LEGACY_ERROR_BOUNDARY_TEXT = "ControlBot Studio encountered a UI error"

REACT_EXCLUSIVE_SELECTORS: tuple[str, ...] = (
    'button[aria-label="New bot, group chat, or section"]',
    'button[aria-label="Search and commands"], button:has-text("Search or jump")',
    '[aria-label="Resize sidebar"]',
)
REACT_COMPOSER_SELECTOR = 'textarea[aria-label="Message composer"]'


@dataclass(frozen=True)
class AppHtmlInspection:
    """Structured markers extracted from /app HTML."""

    html_lang: str
    data_theme: str
    title: str
    has_root_div: bool
    has_legacy_markers: bool
    legacy_reasons: list[str] = field(default_factory=list)
    asset_urls: list[str] = field(default_factory=list)


class _AppHtmlParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.html_lang = ""
        self.data_theme = ""
        self.title = ""
        self.has_root_div = False
        self.legacy_reasons: list[str] = []
        self.asset_urls: list[str] = []
        self._in_title = False
        self._in_script = False
        self._title_parts: list[str] = []
        self._script_parts: list[str] = []

    def _attrs(self, attrs: list[tuple[str, str | None]]) -> dict[str, str]:
        return {k.lower(): (v or "") for k, v in attrs}

    def _add_asset(self, url: str) -> None:
        clean = url.split("?", 1)[0].strip()
        if clean.startswith("/assets/") and clean not in self.asset_urls:
            self.asset_urls.append(clean)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_low = tag.lower()
        attr_map = self._attrs(attrs)
        if tag_low == "html":
            self.html_lang = attr_map.get("lang", "").strip().lower()
            self.data_theme = attr_map.get("data-theme", "").strip().lower()
            if self.html_lang == "es":
                self.legacy_reasons.append("html_lang_es")
        elif tag_low == "title":
            self._in_title = True
            self._title_parts.clear()
        elif tag_low == "div" and attr_map.get("id") == "root":
            self.has_root_div = True
        elif tag_low == "link":
            href = attr_map.get("href", "")
            if href.startswith("/assets/"):
                self._add_asset(href)
        elif tag_low == "script":
            src = attr_map.get("src", "")
            if src.startswith("/assets/"):
                self._add_asset(src)
            self._in_script = True
            self._script_parts.clear()

        elem_id = attr_map.get("id", "")
        if elem_id in {"query-input", "toggle-plant-module", "comp-ram-pill", "layout"}:
            self.legacy_reasons.append(f"legacy_id:{elem_id}")
        cls = attr_map.get("class", "")
        if "computer-pane" in cls.split():
            self.legacy_reasons.append("legacy_class:computer-pane")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        tag_low = tag.lower()
        if tag_low == "title" and self._in_title:
            self._in_title = False
            self.title = "".join(self._title_parts).strip()
        elif tag_low == "script" and self._in_script:
            self._in_script = False
            script_body = "".join(self._script_parts)
            for match in _INLINE_ARRAY_RE.finditer(script_body):
                try:
                    items = json.loads(match.group(1))
                except json.JSONDecodeError:
                    items = []
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, str):
                            self._add_asset(item)
            for match in _ASSET_URL_RE.finditer(script_body):
                self._add_asset(match.group(0))
            if "controlbot.showPlantModule" in script_body:
                self.legacy_reasons.append("legacy_script:controlbot.showPlantModule")

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_parts.append(data)
        if self._in_script:
            self._script_parts.append(data)


def extract_app_assets_and_markers(html_text: str) -> AppHtmlInspection:
    """Parse /app HTML (including _render_studio_app_html inline loader arrays)."""
    parser = _AppHtmlParser()
    parser.feed(html_text)
    parser.close()

    reasons = list(parser.legacy_reasons)
    if parser.title == "ControlBot Studio":
        reasons.append("legacy_title:ControlBot Studio")
    if "Computador en Vivo" in html_text:
        reasons.append("legacy_text:Computador en Vivo")

    return AppHtmlInspection(
        html_lang=parser.html_lang,
        data_theme=parser.data_theme,
        title=parser.title,
        has_root_div=parser.has_root_div,
        has_legacy_markers=bool(reasons),
        legacy_reasons=sorted(set(reasons)),
        asset_urls=parser.asset_urls,
    )


def collect_frontend_dist_assets(dist_dir: Path) -> tuple[dict[str, str], list[str]]:
    """Collect expected /assets/* files from dist/index.html and dist/assets/*.{js,css,mjs}."""
    errors: list[str] = []
    index_path = dist_dir / "index.html"
    assets_dir = (dist_dir / "assets").resolve()

    if not index_path.is_file():
        errors.append(f"Missing compiled React index.html at {index_path}")
        return {}, errors
    if not assets_dir.is_dir():
        errors.append(f"Missing compiled React assets directory at {assets_dir}")
        return {}, errors

    raw_html = index_path.read_text(encoding="utf-8", errors="replace")
    inspection = extract_app_assets_and_markers(raw_html)
    if not inspection.asset_urls:
        errors.append(f"No /assets/* JS or CSS entries found in {index_path}")
        return {}, errors

    hashes: dict[str, str] = {}
    for asset_url in inspection.asset_urls:
        rel_name = asset_url.removeprefix("/assets/").lstrip("/")
        candidate = (assets_dir / rel_name).resolve()
        if not candidate.is_relative_to(assets_dir) or not candidate.is_file():
            errors.append(f"Referenced dist asset missing on disk: {asset_url}")
            continue
        hashes[asset_url] = hashlib.sha256(candidate.read_bytes()).hexdigest()

    for disk_file in sorted(assets_dir.rglob("*")):
        if not disk_file.is_file():
            continue
        if disk_file.suffix.lower() not in {".js", ".css", ".mjs"}:
            continue
        resolved_file = disk_file.resolve()
        if not resolved_file.is_relative_to(assets_dir):
            continue
        rel_posix = disk_file.relative_to(assets_dir).as_posix()
        asset_url = f"/assets/{rel_posix}"
        if asset_url not in hashes:
            hashes[asset_url] = hashlib.sha256(resolved_file.read_bytes()).hexdigest()

    has_js = any(url.endswith((".js", ".mjs")) for url in hashes)
    has_css = any(url.endswith(".css") for url in hashes)
    if not has_js or not has_css:
        errors.append("Compiled frontend/dist/index.html must reference both JS and CSS assets.")

    return hashes, errors


@dataclass(frozen=True)
class SurfaceHttpCheckResult:
    """Result of HTTP-level /app and /assets/* verification."""

    served_surface: ServedSurface
    ui_variant: UIVariant
    surface_verified: bool
    asset_hashes: dict[str, str] = field(default_factory=dict)
    asset_hash_mismatches: dict[str, dict[str, str]] = field(default_factory=dict)
    boot_errors: list[str] = field(default_factory=list)
    functional_errors: list[str] = field(default_factory=list)
    inspection: AppHtmlInspection | None = None
    reachable: bool = True


def verify_app_surface_http(
    client_or_url: httpx.Client | str,
    *,
    dist_dir: Path,
    token: str | None = None,
    check_subpath: bool = True,
) -> SurfaceHttpCheckResult:
    """Verify /app serves React (not studio.html) and /assets/* hashes match frontend/dist."""
    owned_client: httpx.Client | None = None
    if isinstance(client_or_url, str):
        owned_client = httpx.Client(
            base_url=client_or_url.rstrip("/"),
            timeout=10.0,
            trust_env=False,
            follow_redirects=False,
        )
        client = owned_client
    else:
        client = client_or_url

    boot_errors: list[str] = []
    functional_errors: list[str] = []
    served_hashes: dict[str, str] = {}
    mismatches: dict[str, dict[str, str]] = {}
    params = {"token": token} if token else None

    try:
        try:
            resp = client.get("/app", params=params)
        except Exception as exc:
            boot_errors.append(f"/app request failed: {type(exc).__name__}: {exc}")
            return SurfaceHttpCheckResult(
                served_surface="unreachable",
                ui_variant="unknown",
                surface_verified=False,
                boot_errors=boot_errors,
                reachable=False,
            )

        if resp.status_code != 200:
            boot_errors.append(f"/app returned unexpected HTTP {resp.status_code}")
            return SurfaceHttpCheckResult(
                served_surface="unreachable",
                ui_variant="unknown",
                surface_verified=False,
                boot_errors=boot_errors,
            )

        inspection = extract_app_assets_and_markers(resp.text)
        if inspection.has_legacy_markers:
            boot_errors.append(
                "Legacy studio.html fallback served at /app instead of compiled React build "
                f"({', '.join(inspection.legacy_reasons)})"
            )
            return SurfaceHttpCheckResult(
                served_surface="legacy_fallback",
                ui_variant="studio_legacy",
                surface_verified=False,
                boot_errors=boot_errors,
                inspection=inspection,
            )

        if not inspection.has_root_div or _REACT_TITLE not in inspection.title:
            boot_errors.append(
                "Served /app HTML is missing React root/title markers "
                f"(has_root={inspection.has_root_div}, title={inspection.title!r})"
            )
            return SurfaceHttpCheckResult(
                served_surface="unreachable",
                ui_variant="unknown",
                surface_verified=False,
                boot_errors=boot_errors,
                inspection=inspection,
            )

        dist_hashes, dist_errors = collect_frontend_dist_assets(dist_dir)
        boot_errors.extend(dist_errors)

        dist_index_path = dist_dir / "index.html"
        dist_index_assets: set[str] = set()
        if dist_index_path.is_file():
            dist_index_assets = set(
                extract_app_assets_and_markers(
                    dist_index_path.read_text(encoding="utf-8", errors="replace")
                ).asset_urls
            )

        served_set = set(inspection.asset_urls)
        missing_in_html = sorted(dist_index_assets - served_set)
        if missing_in_html:
            boot_errors.append(
                f"Served /app HTML omits dist assets: {', '.join(missing_in_html)}"
            )

        assets_to_fetch = sorted(served_set | set(dist_hashes))
        if not any(a.endswith((".js", ".mjs")) for a in assets_to_fetch) or not any(
            a.endswith(".css") for a in assets_to_fetch
        ):
            boot_errors.append("Served /app HTML does not reference both JS and CSS assets.")

        for asset_url in assets_to_fetch:
            try:
                asset_resp = client.get(asset_url, params=params)
            except Exception as exc:
                boot_errors.append(
                    f"Failed fetching asset {asset_url}: {type(exc).__name__}: {exc}"
                )
                continue
            if asset_resp.status_code != 200:
                boot_errors.append(f"Asset {asset_url} returned HTTP {asset_resp.status_code}")
                continue
            actual_sha = hashlib.sha256(asset_resp.content).hexdigest()
            served_hashes[asset_url] = actual_sha
            expected_sha = dist_hashes.get(asset_url)
            if expected_sha is None:
                if asset_url.endswith((".js", ".css", ".mjs")):
                    boot_errors.append(
                        "Unexpected /assets/ reference not found in "
                        f"frontend/dist/assets: {asset_url}"
                    )
            elif actual_sha != expected_sha:
                mismatches[asset_url] = {"expected": expected_sha, "actual": actual_sha}
                boot_errors.append(
                    f"Asset SHA-256 mismatch for {asset_url}: "
                    f"expected={expected_sha[:12]} actual={actual_sha[:12]}"
                )

        subpath_legacy = False
        if check_subpath:
            try:
                sub_resp = client.get("/app/qa-surface-check", params=params)
                if sub_resp.status_code != 200:
                    boot_errors.append(
                        f"/app/qa-surface-check returned HTTP {sub_resp.status_code}"
                    )
                else:
                    sub_insp = extract_app_assets_and_markers(sub_resp.text)
                    if sub_insp.has_legacy_markers:
                        subpath_legacy = True
                        boot_errors.append(
                            "/app/qa-surface-check served legacy studio.html markers "
                            f"({', '.join(sub_insp.legacy_reasons)})."
                        )
                    else:
                        if not sub_insp.has_root_div or _REACT_TITLE not in sub_insp.title:
                            boot_errors.append(
                                "/app/qa-surface-check did not serve React root/title markers "
                                f"(has_root={sub_insp.has_root_div}, title={sub_insp.title!r})."
                            )
                        sub_missing_assets = sorted(dist_index_assets - set(sub_insp.asset_urls))
                        if sub_missing_assets:
                            boot_errors.append(
                                "/app/qa-surface-check omits dist assets: "
                                f"{', '.join(sub_missing_assets)}"
                            )
            except Exception as exc:
                boot_errors.append(
                    f"/app/qa-surface-check failed: {type(exc).__name__}: {exc}"
                )

        final_surface: ServedSurface = "legacy_fallback" if subpath_legacy else "react"
        final_variant: UIVariant = "studio_legacy" if subpath_legacy else "react_dist"
        surface_ok = not boot_errors
        return SurfaceHttpCheckResult(
            served_surface=final_surface,
            ui_variant=final_variant,
            surface_verified=surface_ok,
            asset_hashes=served_hashes,
            asset_hash_mismatches=mismatches,
            boot_errors=boot_errors,
            functional_errors=functional_errors,
            inspection=inspection,
        )
    finally:
        if owned_client is not None:
            owned_client.close()


@dataclass(frozen=True)
class BrowserSurfaceResult:
    """Outcome of Playwright React DOM surface verification."""

    verified: bool
    controls_verified: list[str] = field(default_factory=list)
    boot_errors: list[str] = field(default_factory=list)
    functional_errors: list[str] = field(default_factory=list)


async def verify_app_surface_browser(
    base_url: str,
    *,
    user_data_dir: Path | None = None,
    token: str | None = None,
    timeout_ms: int = 10_000,
    expect_message_composer: bool | None = None,
) -> BrowserSurfaceResult:
    """Open /app in isolated headless Chromium and verify React-exclusive ARIA controls render."""
    assert_not_live_target(base_url, allow_readonly=False)
    clean_base = base_url.rstrip("/")
    target = f"{clean_base}/app"
    if token:
        from urllib.parse import urlencode

        target = f"{target}?{urlencode({'token': token})}"

    controls_verified: list[str] = []
    boot_errors: list[str] = []
    functional_errors: list[str] = []

    has_bots = False
    if expect_message_composer is not None:
        has_bots = expect_message_composer
    else:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        try:
            async with httpx.AsyncClient(
                base_url=clean_base,
                headers=headers,
                timeout=5.0,
                trust_env=False,
            ) as client:
                bots_resp = await client.get("/api/v1/bots")
                if bots_resp.status_code == 200:
                    payload = bots_resp.json()
                    if isinstance(payload, dict) and isinstance(payload.get("bots"), list):
                        has_bots = len(payload["bots"]) > 0
                    elif isinstance(payload, list):
                        has_bots = len(payload) > 0
        except Exception:
            has_bots = False

    async with StrictPlaywrightSession(user_data_dir=user_data_dir) as session:
        page = session.page
        try:
            response = await page.goto(target, wait_until="networkidle", timeout=timeout_ms)
        except Exception as exc:
            boot_errors.append(f"Playwright navigation to /app failed: {type(exc).__name__}: {exc}")
            return BrowserSurfaceResult(
                verified=False,
                controls_verified=controls_verified,
                boot_errors=boot_errors,
                functional_errors=functional_errors,
            )

        if response is None or response.status >= 400:
            status_code = response.status if response is not None else "none"
            boot_errors.append(f"Playwright /app navigation HTTP status={status_code}")

        title = await page.title()
        if title != _REACT_TITLE:
            boot_errors.append(f"Unexpected browser document.title={title!r}")

        theme = await page.evaluate("() => document.documentElement.getAttribute('data-theme')")
        if theme not in {"light", "dark"}:
            boot_errors.append(f"Missing or invalid html[data-theme]={theme!r}")

        root_children = await page.evaluate("() => document.querySelectorAll('#root > *').length")
        if not isinstance(root_children, int) or root_children <= 0:
            boot_errors.append("React #root container has zero mounted child elements.")

        if await page.locator(f"text={_LEGACY_ERROR_BOUNDARY_TEXT}").count() > 0:
            boot_errors.append("DiagnosticsErrorBoundary rendered UI error screen.")

        for legacy_sel in ("#query-input", "#toggle-plant-module"):
            if await page.locator(legacy_sel).count() > 0:
                boot_errors.append(f"Legacy studio.html control {legacy_sel!r} rendered at /app.")

        for selector in REACT_EXCLUSIVE_SELECTORS:
            try:
                await page.locator(selector).first.wait_for(state="visible", timeout=timeout_ms)
                controls_verified.append(selector)
            except Exception as exc:
                boot_errors.append(
                    f"React-exclusive control {selector!r} did not become visible: "
                    f"{type(exc).__name__}"
                )

        if has_bots:
            try:
                await page.locator(REACT_COMPOSER_SELECTOR).first.wait_for(
                    state="visible",
                    timeout=timeout_ms,
                )
                controls_verified.append(REACT_COMPOSER_SELECTOR)
            except Exception as exc:
                boot_errors.append(
                    f"React composer {REACT_COMPOSER_SELECTOR!r} did not become visible: "
                    f"{type(exc).__name__}"
                )

        for perr in session.page_errors:
            boot_errors.append(f"Browser pageerror: {perr}")

        for status_code, err_url in session.http_errors:
            parsed_path = urlparse(err_url).path
            if parsed_path.startswith("/assets/") or parsed_path.startswith("/app"):
                boot_errors.append(f"Boot HTTP {status_code} on {err_url}")
            else:
                functional_errors.append(f"Browser HTTP {status_code} on {err_url}")

        for cerr in session.console_errors:
            if (
                "Failed to load module script" in cerr
                or "Loading chunk" in cerr
                or "net::ERR_EMPTY_RESPONSE" in cerr
                or "net::ERR_CONNECTION_REFUSED" in cerr
                or "net::ERR_CONNECTION_RESET" in cerr
            ):
                boot_errors.append(f"Module boot console.error: {cerr}")
            else:
                functional_errors.append(f"Browser console.error: {cerr}")

        for ext_url in session.external_requests:
            functional_errors.append(f"Blocked external browser request: {ext_url}")

    return BrowserSurfaceResult(
        verified=not boot_errors,
        controls_verified=controls_verified,
        boot_errors=boot_errors,
        functional_errors=functional_errors,
    )


def _run_coro_sync(coro: Any) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def _git_info(repo_root: Path) -> tuple[str, list[str], list[str]]:
    errors: list[str] = []
    sha_proc = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    if sha_proc.returncode != 0 or not sha_proc.stdout.strip():
        errors.append(f"git rev-parse HEAD failed: {sha_proc.stderr.strip()}")
        repo_sha = "unknown"
    else:
        repo_sha = sha_proc.stdout.strip()

    status_proc = subprocess.run(
        ["git", "-C", str(repo_root), "status", "--porcelain"],
        capture_output=True,
        text=True,
        check=False,
    )
    dirty_files: list[str] = []
    if status_proc.returncode == 0:
        for line in status_proc.stdout.splitlines():
            stripped = line.rstrip()
            if stripped:
                dirty_files.append(stripped)
    return repo_sha, dirty_files, errors


def _infer_deployed_sha(
    live_snapshot: dict[str, Any],
    repo_sha: str,
    dist_hashes: dict[str, str],
) -> str | None:
    excerpt = live_snapshot.get("app_html_excerpt")
    if not isinstance(excerpt, str) or not excerpt.strip():
        return None
    live_insp = extract_app_assets_and_markers(excerpt)
    if live_insp.has_legacy_markers:
        return "legacy_fallback (not React dist)"
    if not live_insp.asset_urls:
        return "unknown (no /assets/* found in live /app excerpt)"
    if dist_hashes and set(live_insp.asset_urls).issubset(set(dist_hashes)):
        return f"{repo_sha} (inferred: live /app assets match local frontend/dist)"
    return f"unknown (live assets={live_insp.asset_urls})"


def render_baseline_markdown(report: BaselineReport) -> str:
    """Render human-readable BASELINE.md from a BaselineReport."""
    lines: list[str] = [
        f"# ControlBot QA Baseline — {report.campaign_id}",
        "",
        f"- **Generated at**: `{report.generated_at.isoformat()}`",
        f"- **Lane**: `{report.lane}`",
        f"- **Repo SHA**: `{report.repo_sha}`",
        f"- **Deployed SHA**: `{report.deployed_sha or 'unknown'}`",
        f"- **UI Variant**: `{report.ui_variant}` (`served_surface={report.served_surface}`)",
        f"- **Surface Verified**: `{report.surface_verified}`",
        (
            f"- **Backend Mode**: `{report.backend_mode}` | "
            f"**Runtime Mode**: `{report.runtime_mode}` | **Emulated**: `{report.emulated}`"
        ),
        (
            f"- **Model**: `id={report.model_id}` `version={report.model_version}` "
            f"`quantization={report.quantization}`"
        ),
        (
            "- **Real Services**: "
            f"`{', '.join(report.real_services) if report.real_services else 'none'}`"
        ),
        (
            "- **Simulated Services**: "
            f"`{', '.join(report.simulated_services) if report.simulated_services else 'none'}`"
        ),
        f"- **N3 Status**: `{report.n3_status}`",
        f"- **Overall Passed**: `{report.overall_passed}` (exit_code=`{report.exit_code}`)",
        "",
        "## Dirty Working Tree Files",
    ]
    if report.git_dirty_files:
        lines.extend(f"- `{entry}`" for entry in report.git_dirty_files)
    else:
        lines.append("- (clean)")

    lines.extend(["", "## Served Asset SHA-256 Hashes"])
    if report.asset_hashes:
        lines.extend(
            f"- `{url}` -> `{digest}`" for url, digest in sorted(report.asset_hashes.items())
        )
    else:
        lines.append("- (none verified)")

    lines.extend(["", "## React Controls Verified"])
    if report.react_controls_verified:
        lines.extend(f"- `{sel}`" for sel in report.react_controls_verified)
    else:
        lines.append("- (none)")

    lines.extend(["", "## Skipped Checks (Skip != Pass)"])
    if report.skipped_checks:
        lines.extend(f"- `{item}`" for item in report.skipped_checks)
    else:
        lines.append("- (none)")

    lines.extend(["", "## Boot / Surface Errors"])
    if report.boot_errors:
        lines.extend(f"- {err}" for err in report.boot_errors)
    else:
        lines.append("- (none)")

    lines.extend(["", "## Functional Errors"])
    if report.functional_errors:
        lines.extend(f"- {err}" for err in report.functional_errors)
    else:
        lines.append("- (none)")

    lines.extend(
        [
            "",
            "## Active Log Summary (Read-Only Redacted)",
            "```json",
            json.dumps(report.active_log_summary, indent=2, ensure_ascii=False),
            "```",
            "",
            "## Live Snapshot (Read-Only)",
            "```json",
            json.dumps(report.live_snapshot, indent=2, ensure_ascii=False),
            "```",
        ]
    )
    return "\n".join(lines) + "\n"


def _compute_catalog_hash(repo_root: Path) -> str:
    megaplan = repo_root / "docs" / "MEGAPLAN_CONTROLBOT_QA_DIFERENCIAL_Y_AUTORREPARACION.md"
    if megaplan.is_file():
        return hashlib.sha256(megaplan.read_bytes()).hexdigest()[:16]
    return "no-megaplan"


@contextlib.contextmanager
def _frontend_dist_lock(repo_root: Path, *, exclusive: bool) -> Iterator[None]:
    """Coordinate concurrent frontend builds vs dist reads via advisory flock."""
    lock_path: Path | None = None
    git_entry = repo_root / ".git"
    if git_entry.exists():
        proc = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "--git-common-dir"],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            common_dir = Path(proc.stdout.strip())
            if not common_dir.is_absolute():
                common_dir = (repo_root / common_dir).resolve()
            if common_dir.is_dir():
                lock_path = common_dir / "qa_frontend_build.lock"
    if lock_path is None:
        node_modules = repo_root / "frontend" / "node_modules"
        if git_entry.is_dir():
            lock_path = git_entry / "qa_frontend_build.lock"
        elif node_modules.is_dir():
            lock_path = node_modules / ".qa_frontend_build.lock"
        else:
            yield
            return
    with lock_path.open("a+") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def run_baseline(
    *,
    repo_root: Path,
    output_dir: Path,
    target_url: str = "http://127.0.0.1:8000",
    token: str | None = None,
    lane: LaneName = "local_deterministic",
    build_frontend: bool = True,
    skip_browser: bool = False,
    use_isolated_lab: bool | None = None,
    log_dir: Path | None = None,
    campaign_id: str | None = None,
    model_id: str | None = None,
    model_version: str | None = None,
    quantization: str | None = None,
) -> BaselineReport:
    """Execute QA-0/QA-1 baseline capture, React surface check, and write campaign artifacts."""
    resolved_repo = repo_root.resolve()
    safe_output_dir = assert_safe_mutation_path(output_dir, repo_root=resolved_repo)
    safe_output_dir.mkdir(parents=True, exist_ok=True)

    repo_sha, dirty_files, git_errors = _git_info(resolved_repo)
    resolved_campaign_id = campaign_id or (
        f"qa-{utc_now().strftime('%Y%m%dT%H%M%SZ')}-{repo_sha[:7]}"
    )

    boot_errors: list[str] = list(git_errors)
    functional_errors: list[str] = []
    skipped_checks: list[str] = []

    parsed_target = urlparse(target_url if "://" in target_url else f"http://{target_url}")
    target_port = parsed_target.port
    is_live_target = target_port in LIVE_FORBIDDEN_PORTS
    effective_isolated = use_isolated_lab if use_isolated_lab is not None else is_live_target
    if is_live_target and not effective_isolated and not skip_browser:
        assert_not_live_target(target_url, allow_readonly=False)

    live_snapshot: dict[str, Any] = {}
    if is_live_target or effective_isolated:
        live_snapshot = probe_live_readonly(target_url, token=token)

    effective_log_dir = log_dir if log_dir is not None else (resolved_repo / "var" / "logs")
    active_log_summary = summarize_active_logs(effective_log_dir)

    doctor_report = run_doctor()
    doctor_status = doctor_report.model_dump(mode="json")
    if not (doctor_report.n1_ready and doctor_report.n2_ready):
        failed_checks = [
            f"{chk.name}: {chk.summary}"
            for chk in doctor_report.checks
            if chk.status.value == "fail"
        ]
        functional_errors.append(
            "Doctor N1/N2 readiness failed: " + ("; ".join(failed_checks) or "unknown")
        )

    n3_report = run_n3_probe()
    n3_probe_dict = n3_report.model_dump(mode="json")
    n3_status = n3_report.overall_status
    if n3_status != "READY":
        skipped_checks.append(f"n3_probe:{n3_status}")
        if lane == "linux_real":
            notes = "; ".join(n3_report.evidence_notes) or n3_status
            functional_errors.append(
                f"Lane 'linux_real' requires N3 readiness (n3_status={n3_status}): {notes}"
            )

    if lane == "agy_real" and shutil.which("agy") is None:
        functional_errors.append(
            "Lane 'agy_real' requires 'agy' executable in PATH, but 'agy' was not found."
        )

    build_executed = False
    build_passed: bool | None = None
    if build_frontend:
        build_executed = True
        with _frontend_dist_lock(resolved_repo, exclusive=True):
            build_proc = subprocess.run(
                ["npm", "--prefix", str(resolved_repo / "frontend"), "run", "build"],
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
        if build_proc.returncode == 0:
            build_passed = True
        else:
            build_passed = False
            tail_err = (build_proc.stderr or build_proc.stdout)[-800:].strip()
            boot_errors.append(f"Frontend build failed (rc={build_proc.returncode}): {tail_err}")

    with _frontend_dist_lock(resolved_repo, exclusive=False):
        dist_dir = resolved_repo / "frontend" / "dist"
        dist_hashes, _ = collect_frontend_dist_assets(dist_dir)
        deployed_sha = _infer_deployed_sha(live_snapshot, repo_sha, dist_hashes)

        served_surface: ServedSurface = "unreachable"
        ui_variant: UIVariant = "unknown"
        surface_verified = False
        asset_hashes: dict[str, str] = {}
        asset_hash_mismatches: dict[str, dict[str, str]] = {}
        react_controls_verified: list[str] = []
        backend_mode = "unreachable"
        runtime_mode = "unreachable"
        emulated = True
        real_services: list[str] = []
        simulated_services: list[str] = []
        lab_url: str | None = None
        resolved_model_id = model_id
        resolved_model_version = model_version
        resolved_quantization = quantization

        def _verify_base_url(verify_url: str, pw_user_data_dir: Path | None) -> None:
            nonlocal served_surface, ui_variant, surface_verified, asset_hashes
            nonlocal asset_hash_mismatches, react_controls_verified
            nonlocal backend_mode, runtime_mode, emulated, real_services, simulated_services
            nonlocal resolved_model_id

            headers = {"Authorization": f"Bearer {token}"} if token else {}
            api_transport_dropped = False
            with httpx.Client(
                base_url=verify_url.rstrip("/"),
                headers=headers,
                timeout=10.0,
                trust_env=False,
                follow_redirects=False,
            ) as client:
                http_res = verify_app_surface_http(client, dist_dir=dist_dir, token=token)
                served_surface = http_res.served_surface
                ui_variant = http_res.ui_variant
                asset_hashes = dict(http_res.asset_hashes)
                asset_hash_mismatches = dict(http_res.asset_hash_mismatches)
                boot_errors.extend(http_res.boot_errors)
                functional_errors.extend(http_res.functional_errors)

                if http_res.reachable:
                    try:
                        sys_resp = client.get("/api/system/info")
                        if sys_resp.status_code == 200:
                            sys_data = sys_resp.json()
                            if isinstance(sys_data, dict):
                                backend_mode = str(sys_data.get("backend_mode") or "unknown")
                                runtime_mode = str(sys_data.get("runtime_mode") or "unknown")
                                emulated = backend_mode in {"emulated", "stub"}
                                if resolved_model_id is None and sys_data.get("llm_model_id"):
                                    resolved_model_id = str(sys_data["llm_model_id"])
                                if backend_mode == "local_http":
                                    real_services = ["controlbot_web", "local_http_llm"]
                                    simulated_services = []
                                elif backend_mode in {"agy", "agy_real"}:
                                    real_services = ["controlbot_web", "agy_cli"]
                                    simulated_services = []
                                else:
                                    real_services = ["controlbot_web"]
                                    simulated_services = ["emulated_runtime"]
                        else:
                            functional_errors.append(
                                f"/api/system/info returned HTTP {sys_resp.status_code}"
                            )
                    except (httpx.RequestError, ConnectionError, TimeoutError, OSError) as exc:
                        api_transport_dropped = True
                        boot_errors.append(
                            f"/api/system/info unreachable: {type(exc).__name__}: {exc}"
                        )
                    except Exception as exc:
                        functional_errors.append(
                            f"/api/system/info request failed: {type(exc).__name__}: {exc}"
                        )

                    try:
                        bots_resp = client.get("/api/v1/bots")
                        if bots_resp.status_code >= 400:
                            functional_errors.append(
                                f"/api/v1/bots returned HTTP {bots_resp.status_code}"
                            )
                    except (httpx.RequestError, ConnectionError, TimeoutError, OSError) as exc:
                        api_transport_dropped = True
                        boot_errors.append(
                            f"/api/v1/bots unreachable: {type(exc).__name__}: {exc}"
                        )
                    except Exception as exc:
                        functional_errors.append(
                            f"/api/v1/bots request failed: {type(exc).__name__}: {exc}"
                        )

                    if lane == "agy_real":
                        if (
                            backend_mode in {"emulated", "stub", "unknown"}
                            or runtime_mode == "stub"
                        ):
                            functional_errors.append(
                                "Lane 'agy_real' engine mismatch: target server reported "
                                f"backend_mode={backend_mode!r}, runtime_mode={runtime_mode!r} "
                                "(emulated/stub backend cannot satisfy agy_real)."
                            )
                        try:
                            agy_resp = client.get("/api/agy/models")
                            if agy_resp.status_code >= 400:
                                functional_errors.append(
                                    f"/api/agy/models returned HTTP {agy_resp.status_code}"
                                )
                            else:
                                agy_data = agy_resp.json()
                                if (
                                    not isinstance(agy_data, dict)
                                    or agy_data.get("available") is not True
                                ):
                                    functional_errors.append(
                                        "Lane 'agy_real' requires target server "
                                        "/api/agy/models available=true."
                                    )
                                elif "agy_cli" not in real_services:
                                    real_services.append("agy_cli")
                        except (httpx.RequestError, ConnectionError, TimeoutError, OSError) as exc:
                            api_transport_dropped = True
                            boot_errors.append(
                                f"/api/agy/models unreachable: {type(exc).__name__}: {exc}"
                            )
                        except Exception as exc:
                            functional_errors.append(
                                f"/api/agy/models request failed: {type(exc).__name__}: {exc}"
                            )

            if skip_browser:
                skipped_checks.append("playwright_browser_surface")
                surface_verified = http_res.surface_verified and not boot_errors
            elif http_res.served_surface == "react" and not api_transport_dropped:
                browser_res = _run_coro_sync(
                    verify_app_surface_browser(
                        verify_url,
                        user_data_dir=pw_user_data_dir,
                        token=token,
                    )
                )
                react_controls_verified = list(browser_res.controls_verified)
                boot_errors.extend(browser_res.boot_errors)
                functional_errors.extend(browser_res.functional_errors)
                surface_verified = (
                    http_res.surface_verified and browser_res.verified and not boot_errors
                )
            else:
                surface_verified = False

        if build_passed is False and not (dist_dir / "index.html").is_file():
            served_surface = "unreachable"
            surface_verified = False
        elif effective_isolated:
            try:
                with IsolatedLabServer(repo_root=resolved_repo, web_token=token) as lab:
                    lab_url = lab.base_url
                    _verify_base_url(lab.base_url, lab.workspace.playwright_user_data_dir)
            except Exception as exc:
                boot_errors.append(f"IsolatedLabServer boot failed: {type(exc).__name__}: {exc}")
                served_surface = "unreachable"
                surface_verified = False
        else:
            _verify_base_url(target_url, None)

    if (
        lane == "linux_real"
        and skipped_checks
        and not any("linux_real" in err for err in functional_errors)
    ):
        functional_errors.append(
            f"Lane 'linux_real' cannot pass with skipped checks: {', '.join(skipped_checks)}"
        )

    overall_passed = surface_verified and (not boot_errors) and (not functional_errors)
    if overall_passed:
        exit_code = 0
    elif (not surface_verified) or boot_errors:
        exit_code = 2
    else:
        exit_code = 3

    clean_target_url = _scrub_url_strict(target_url)
    report = BaselineReport(
        campaign_id=resolved_campaign_id,
        repo_sha=repo_sha,
        deployed_sha=deployed_sha,
        git_dirty_files=dirty_files,
        surface_verified=surface_verified,
        served_surface=served_surface,
        asset_hashes=asset_hashes,
        backend_mode=backend_mode,
        runtime_mode=runtime_mode,
        doctor_status=_sanitize_record(doctor_status),
        n3_status=n3_status,
        boot_errors=[str(_sanitize_record(err)) for err in boot_errors],
        functional_errors=[str(_sanitize_record(err)) for err in functional_errors],
        active_log_summary=active_log_summary,
        lane=lane,
        ui_variant=ui_variant,
        target_url=clean_target_url,
        lab_url=lab_url,
        model_id=resolved_model_id,
        model_version=resolved_model_version,
        quantization=resolved_quantization,
        emulated=emulated,
        real_services=real_services,
        simulated_services=simulated_services,
        build_executed=build_executed,
        build_passed=build_passed,
        react_controls_verified=react_controls_verified,
        asset_hash_mismatches=asset_hash_mismatches,
        live_snapshot=live_snapshot,
        n3_probe=_sanitize_record(n3_probe_dict),
        skipped_checks=skipped_checks,
        overall_passed=overall_passed,
        exit_code=exit_code,
    )

    serialized_report = json.loads(report.model_dump_json())
    if _has_unredacted_secret_any(serialized_report):
        raise RuntimeError("BaselineReport failed strict secret redaction verification.")

    baseline_json_path = safe_output_dir / "baseline.json"
    baseline_md_path = safe_output_dir / "BASELINE.md"
    campaign_json_path = safe_output_dir / "campaign.json"

    baseline_json_path.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    baseline_md_path.write_text(render_baseline_markdown(report), encoding="utf-8")

    catalog_hash = _compute_catalog_hash(resolved_repo)
    campaign_state = CampaignState(
        campaign_id=resolved_campaign_id,
        base_sha=repo_sha,
        last_accepted_sha=repo_sha if overall_passed else None,
        catalog_hash=catalog_hash,
        criteria_hash=hashlib.sha256(
            json.dumps(sorted(REACT_EXCLUSIVE_SELECTORS)).encode("utf-8")
        ).hexdigest()[:16],
        lane=lane,
        target_url=clean_target_url,
        limits={"max_parallel_repairers": 2, "max_attempts_per_item": 2},
        attempts={},
        artifacts={
            "baseline_json": str(baseline_json_path),
            "baseline_md": str(baseline_md_path),
        },
        output_dir=str(safe_output_dir),
    )
    campaign_json_path.write_text(campaign_state.model_dump_json(indent=2) + "\n", encoding="utf-8")

    return report


__all__ = [
    "AppHtmlInspection",
    "BrowserSurfaceResult",
    "REACT_COMPOSER_SELECTOR",
    "REACT_EXCLUSIVE_SELECTORS",
    "SurfaceHttpCheckResult",
    "collect_frontend_dist_assets",
    "extract_app_assets_and_markers",
    "render_baseline_markdown",
    "run_baseline",
    "verify_app_surface_browser",
    "verify_app_surface_http",
]
