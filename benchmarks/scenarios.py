"""Megaplan §6.1-6.2 benchmark scenario definitions (>=12 N1/N2 + explicit A11 N3 status)."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal

from pydantic import Field
from src.contracts.common import FrozenModel, NonEmptyStr


class BenchmarkScenario(FrozenModel):
    """Single reproducible comparative benchmark scenario."""

    scenario_id: NonEmptyStr
    name: NonEmptyStr
    category: NonEmptyStr
    description: NonEmptyStr
    evidence_tier: Literal["N1", "N2", "N3"]
    n3_pending: bool = False
    n3_reason: str | None = None
    expected_status: str
    expects_abstention: bool = False
    expects_contradictions: bool = False
    max_tool_calls: int = Field(default=16, ge=1)


BENCHMARK_SCENARIOS: tuple[BenchmarkScenario, ...] = (
    BenchmarkScenario(
        scenario_id="A01",
        name="Normal Cross-Source Query",
        category="cross_source_query",
        description=(
            "Query Pump 34 across healthy SCADA and Maintenance apps with consistent "
            "clocks, source attribution, and redacted receipts."
        ),
        evidence_tier="N2",
        expected_status="succeeded",
    ),
    BenchmarkScenario(
        scenario_id="A02",
        name="Ambiguous Identity Abstention & Resume",
        category="ambiguity_abstention",
        description=(
            "Duplicate 'bomba 34' in area-1 and area-2 requires abstention before guessing "
            "and scoped execution after operator disambiguation."
        ),
        evidence_tier="N2",
        expected_status="succeeded",
        expects_abstention=True,
    ),
    BenchmarkScenario(
        scenario_id="A03",
        name="Quality & Time-Window Filtering",
        category="quality_window",
        description=(
            "Reject stale, bad-quality, and out-of-window records while synthesizing "
            "chronological facts from authorized evidence only."
        ),
        evidence_tier="N2",
        expected_status="succeeded",
    ),
    BenchmarkScenario(
        scenario_id="A04",
        name="Partial Source Unavailability",
        category="partial_source",
        description=(
            "SCADA returns HTTP 503 while Maintenance is healthy; report partial result "
            "explicitly flagging missing source without failing valid evidence."
        ),
        evidence_tier="N2",
        expected_status="partial",
        expects_abstention=True,
    ),
    BenchmarkScenario(
        scenario_id="A05",
        name="Session & Profile Isolation + Origin Guard",
        category="isolation",
        description=(
            "Concurrent user sessions keep isolated cookies/profiles and block navigation "
            "to disallowed origins."
        ),
        evidence_tier="N2",
        expected_status="succeeded",
    ),
    BenchmarkScenario(
        scenario_id="A06",
        name="Identical-Repeat Loop Halt",
        category="loop_control",
        description=(
            "Detect repeated identical successful tool calls with zero progress and halt "
            "before exhausting the tool-call budget."
        ),
        evidence_tier="N1",
        expected_status="failed",
        expects_abstention=True,
        max_tool_calls=3,
    ),
    BenchmarkScenario(
        scenario_id="A07",
        name="Alternating-Cycle Loop Halt",
        category="loop_control",
        description=(
            "Detect alternating tool-call cycles with unchanged state and halt cleanly "
            "before budget exhaustion."
        ),
        evidence_tier="N1",
        expected_status="failed",
        expects_abstention=True,
        max_tool_calls=4,
    ),
    BenchmarkScenario(
        scenario_id="A08",
        name="Crash-Before-Confirm Side-Effect Reconciliation",
        category="effect_reconciliation",
        description=(
            "Reconcile persisted effect after crash before confirmation via state lookup "
            "without replaying duplicate side effects."
        ),
        evidence_tier="N2",
        expected_status="succeeded",
    ),
    BenchmarkScenario(
        scenario_id="A09",
        name="Live Cancel & Late-Result Fencing",
        category="cancellation",
        description=(
            "Cancel an in-flight step and fence late tool results via lease generation so "
            "terminal CANCELLED state remains immutable."
        ),
        evidence_tier="N2",
        expected_status="cancelled",
        expects_abstention=True,
    ),
    BenchmarkScenario(
        scenario_id="A10",
        name="Auth Expiry Pause & Re-Auth Resume",
        category="auth_expiry",
        description=(
            "Detect expired session (401/login redirect), pause for human re-auth, and "
            "resume cleanly once credentials/session are restored."
        ),
        evidence_tier="N2",
        expected_status="succeeded",
        expects_abstention=True,
    ),
    BenchmarkScenario(
        scenario_id="A11",
        name="Linux Network Isolation & Local LLM Execution",
        category="egress_isolation",
        description=(
            "Linux netns/iptables outbound blocking with real local LLM weights (N3). "
            "Never faked on non-Linux hosts."
        ),
        evidence_tier="N3",
        n3_pending=True,
        n3_reason="PENDING_N3_LINUX_ENV: Linux netns/iptables and local LLM weights required.",
        expected_status="PENDING_N3_LINUX_ENV",
    ),
    BenchmarkScenario(
        scenario_id="A12",
        name="Facility B Area-2 Config-Only Portability",
        category="portability",
        description=(
            "Transfer workflow to Facility B (area-2, distinct source_ids SC-77/CMMS-77, "
            "reordered Spanish-labeled DOM columns) via config only with zero engine edits."
        ),
        evidence_tier="N2",
        expected_status="succeeded",
    ),
    BenchmarkScenario(
        scenario_id="A13",
        name="Contradictory Evidence Preservation",
        category="contradiction_preservation",
        description=(
            "Preserve intra-source and cross-source asset/label conflicts as PARTIAL with "
            "unresolved ContradictionRecords instead of silently merging."
        ),
        evidence_tier="N2",
        expected_status="partial",
        expects_abstention=True,
        expects_contradictions=True,
    ),
    BenchmarkScenario(
        scenario_id="A14",
        name="Restart Budget & Reservation Recovery",
        category="budget_recovery",
        description=(
            "Preserve SQLite WAL budget counters and clean expired reservations across "
            "coordinator restart without resetting usage."
        ),
        evidence_tier="N2",
        expected_status="succeeded",
    ),
)


def get_all_scenarios(selected: Sequence[str] | None = None) -> tuple[BenchmarkScenario, ...]:
    """Return all benchmark scenarios (including N3-pending A11), optionally filtered by ID."""
    if not selected:
        return BENCHMARK_SCENARIOS
    wanted = {s.strip().upper() for s in selected if s.strip()}
    unknown = sorted(wanted - {s.scenario_id for s in BENCHMARK_SCENARIOS})
    if unknown:
        raise ValueError(f"Unknown scenario ID(s): {', '.join(unknown)}")
    return tuple(s for s in BENCHMARK_SCENARIOS if s.scenario_id in wanted)


def get_runnable_scenarios(
    selected: Sequence[str] | None = None,
) -> tuple[BenchmarkScenario, ...]:
    """Return executable N1/N2 scenarios (>=12 when unfiltered)."""
    return tuple(s for s in get_all_scenarios(selected) if not s.n3_pending)
