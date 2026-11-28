"""Typed schemas and contracts for ControlBot differential QA and self-repair."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from src.contracts.common import FrozenModel, NonEmptyStr, UtcDatetime, utc_now

LaneName = Literal["local_deterministic", "linux_real", "external_reference", "agy_real"]
QAItemState = Literal[
    "observed",
    "reproduced",
    "flaky",
    "in_repair",
    "candidate_verified",
    "accepted_qa",
    "blocked",
    "parked",
]
Severity = Literal["P0", "P1", "P2", "P3"]
CoverageStatus = Literal["covered", "blocked", "pending", "out_of_scope"]
ServedSurface = Literal["react", "legacy_fallback", "unreachable"]
UIVariant = Literal["react_dist", "studio_legacy", "unknown"]


class BaselineReport(FrozenModel):
    """QA-0 / QA-1 baseline capture and /app surface verification report."""

    campaign_id: NonEmptyStr
    generated_at: UtcDatetime = Field(default_factory=utc_now)
    repo_sha: NonEmptyStr
    deployed_sha: str | None = None
    git_dirty_files: list[str] = Field(default_factory=list)
    surface_verified: bool
    served_surface: ServedSurface
    asset_hashes: dict[str, str] = Field(default_factory=dict)
    backend_mode: str
    runtime_mode: str
    doctor_status: dict[str, Any] = Field(default_factory=dict)
    n3_status: str
    boot_errors: list[str] = Field(default_factory=list)
    functional_errors: list[str] = Field(default_factory=list)
    active_log_summary: dict[str, Any] = Field(default_factory=dict)

    lane: LaneName = "local_deterministic"
    ui_variant: UIVariant = "react_dist"
    target_url: str | None = None
    lab_url: str | None = None
    model_id: str | None = None
    model_version: str | None = None
    quantization: str | None = None
    emulated: bool = True
    real_services: list[str] = Field(default_factory=list)
    simulated_services: list[str] = Field(default_factory=list)
    build_executed: bool = False
    build_passed: bool | None = None
    react_controls_verified: list[str] = Field(default_factory=list)
    asset_hash_mismatches: dict[str, dict[str, str]] = Field(default_factory=dict)
    live_snapshot: dict[str, Any] = Field(default_factory=dict)
    n3_probe: dict[str, Any] = Field(default_factory=dict)
    skipped_checks: list[str] = Field(default_factory=list)
    overall_passed: bool = False
    exit_code: int = 2


class RunRecord(FrozenModel):
    """Unified run metadata and assertion record for a QA execution."""

    campaign_id: NonEmptyStr
    case_id: NonEmptyStr
    run_id: NonEmptyStr
    base_sha: NonEmptyStr
    candidate_sha: str | None = None
    build_hash: str | None = None
    lane: LaneName
    profile: str = "default"
    ui_variant: UIVariant = "react_dist"
    backend_mode: str
    runtime_mode: str = "live_runtime"
    model_id: str | None = None
    model_version: str | None = None
    quantization: str | None = None
    emulated: bool = True
    real_services: list[str] = Field(default_factory=list)
    simulated_services: list[str] = Field(default_factory=list)
    fixture_version: str | None = None
    browser: str | None = None
    started_at: UtcDatetime
    finished_at: UtcDatetime
    duration_ms: float = Field(ge=0.0)
    thread_id: str | None = None
    message_id: str | None = None
    action_id: str | None = None
    request_ids: list[str] = Field(default_factory=list)
    passed: bool
    assertions: dict[str, bool] = Field(default_factory=dict)
    artifact_paths: list[str] = Field(default_factory=list)
    error_summary: str | None = None
    blocked_reason: str | None = None


class QAFailureItem(FrozenModel):
    """Deduplicated QA failure queue item linked to M7 Factory backlog."""

    item_id: NonEmptyStr
    dedup_key: NonEmptyStr
    case_id: NonEmptyStr
    subsystem: NonEmptyStr
    normalized_signature: NonEmptyStr
    severity: Severity
    state: QAItemState = "observed"
    summary: NonEmptyStr
    first_seen_sha: NonEmptyStr
    last_seen_sha: NonEmptyStr
    environment_lane: LaneName
    repro_command: str = ""
    evidence_paths: list[str] = Field(default_factory=list)
    factory_item_id: str | None = None
    attempts: int = Field(default=0, ge=0)
    run_ids: list[str] = Field(default_factory=list)
    occurrence_count: int = Field(default=1, ge=1)
    first_seen_at: UtcDatetime = Field(default_factory=utc_now)
    last_seen_at: UtcDatetime = Field(default_factory=utc_now)
    blocked_reason: str | None = None
    next_diagnostic: str | None = None
    source: Literal["log", "diagnostics_api", "e2e", "ux", "watchdog"] = "e2e"
    parent_item_id: str | None = None
    correlation_ids: list[str] = Field(default_factory=list)
    pass_count: int = Field(default=0, ge=0)
    fail_count: int = Field(default=1, ge=0)
    flaky_reason: str | None = None
    repro_test_path: str | None = None
    candidate_ids: list[str] = Field(default_factory=list)
    repro_test_hash: str | None = None
    locked_criterion_hash: str | None = None


class CampaignState(FrozenModel):
    """Persisted state for a QA campaign (`campaign.json`)."""

    campaign_id: NonEmptyStr
    base_sha: NonEmptyStr
    last_accepted_sha: str | None = None
    qa_branch: str = "qa/autopilot"
    catalog_hash: str = ""
    criteria_hash: str = ""
    lane: LaneName = "local_deterministic"
    target_url: str | None = None
    max_parallel_repairers: int = Field(default=2, ge=1, le=2)
    max_attempts_per_item: int = Field(default=2, ge=1)
    limits: dict[str, int] = Field(default_factory=dict)
    attempts: dict[str, int] = Field(default_factory=dict)
    artifacts: dict[str, str] = Field(default_factory=dict)
    status: Literal["active", "paused", "completed", "halted_p0"] = "active"
    active_leases: dict[str, str] = Field(default_factory=dict)
    output_dir: str
    last_requested_command: str | None = None
    created_at: UtcDatetime = Field(default_factory=utc_now)
    updated_at: UtcDatetime = Field(default_factory=utc_now)
    author_model: str | None = None
    reviewer_model: str | None = None
    auditor_model: str | None = "pro"
    cross_model_audit: bool = True
    same_sha_passes: dict[str, int] = Field(default_factory=dict)
    last_green_sha: str | None = None
    p0_halt_reason: str | None = None
    active_worker_pids: dict[str, int] = Field(default_factory=dict)
    factory_db_path: str | None = None


class CandidateManifest(FrozenModel):
    """Candidate repair patch manifest and evaluation outcome."""

    candidate_id: NonEmptyStr
    item_id: NonEmptyStr
    campaign_id: NonEmptyStr
    base_sha: NonEmptyStr
    candidate_sha: str | None = None
    branch_name: NonEmptyStr
    build_hash: str | None = None
    diff_stat: str = ""
    files_modified: list[str] = Field(default_factory=list)
    repro_test_path: str | None = None
    rerun_command: NonEmptyStr
    baseline_passed: bool
    candidate_passed: bool
    audit_passed: bool = False
    auditor_model: str | None = None
    rollback_manifest_path: str | None = None
    status: Literal[
        "pending",
        "candidate_verified",
        "accepted_qa",
        "rejected",
        "rolled_back",
    ] = "pending"
    created_at: UtcDatetime = Field(default_factory=utc_now)
    author_model: str | None = None
    reviewer_model: str | None = None
    proposal_hash: str | None = None
    rollback_sha: str | None = None
    evaluator_summary: str | None = None
    write_area: str | None = None
    lease_id: str | None = None
    lease_generation: int | None = None
    repro_test_hash: str | None = None
    locked_criterion_hash: str | None = None
    audit_notes: str | None = None


class QARollbackManifest(FrozenModel):
    """Machine-readable QA-branch rollback manifest emitted on candidate acceptance."""

    candidate_id: NonEmptyStr
    item_id: NonEmptyStr
    campaign_id: NonEmptyStr
    qa_branch: NonEmptyStr
    previous_accepted_sha: NonEmptyStr
    rolled_back_sha: NonEmptyStr
    restore_command: NonEmptyStr
    reason: str = ""
    rolled_back_at: UtcDatetime = Field(default_factory=utc_now)


class ControlInventoryItem(FrozenModel):
    """Discovered UI control and state transition contract."""

    control_id: NonEmptyStr
    module: NonEmptyStr
    route: NonEmptyStr
    role: NonEmptyStr
    accessible_name: str
    selector: NonEmptyStr
    initial_state: str
    post_state: str = ""
    precondition: str = ""
    observable_effect: str = ""
    keyboard_accessible: bool = False
    repeatable: bool = True
    test_case_id: str | None = None
    coverage_status: CoverageStatus = "pending"
    blocked_reason: str | None = None


class CoverageReport(FrozenModel):
    """Aggregated UI control coverage report (`coverage.json`)."""

    campaign_id: NonEmptyStr
    generated_at: UtcDatetime = Field(default_factory=utc_now)
    repo_sha: NonEmptyStr
    total_controls: int = Field(ge=0)
    covered_count: int = Field(ge=0)
    blocked_count: int = Field(ge=0)
    pending_count: int = Field(ge=0)
    out_of_scope_count: int = Field(ge=0)
    by_module: dict[str, dict[str, int]] = Field(default_factory=dict)
    items: list[ControlInventoryItem] = Field(default_factory=list)


class ReferenceBehaviorCard(FrozenModel):
    """Differential observation card for Grok Bot (`main`/`test` ONLY) or REF_UNAVAILABLE."""

    card_id: NonEmptyStr
    case_id: NonEmptyStr
    source: Literal["grok_bot_app", "grok_bot_docs", "ref_unavailable"]
    status: Literal["observed", "documented", "REF_UNAVAILABLE"]
    unavailable_reason: str | None = None
    bot_used: Literal["main", "test"] | None = None
    app_version: str | None = None
    observed_at: UtcDatetime = Field(default_factory=utc_now)
    conditions: dict[str, Any] = Field(default_factory=dict)
    discoverability: str = ""
    state_transition: str = ""
    independent_verification: str = ""
    missing_data_or_permission: str = ""
    efficiency_notes: str = ""
    expected_controlbot_contract: str = ""


__all__ = [
    "BaselineReport",
    "CampaignState",
    "CandidateManifest",
    "ControlInventoryItem",
    "CoverageReport",
    "CoverageStatus",
    "LaneName",
    "QAFailureItem",
    "QAItemState",
    "QARollbackManifest",
    "ReferenceBehaviorCard",
    "RunRecord",
    "ServedSurface",
    "Severity",
    "UIVariant",
]
