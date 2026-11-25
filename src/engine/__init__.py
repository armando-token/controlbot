"""Core execution engine package (F04, F06, F07, F08)."""

from src.engine.budget import BudgetManager, validate_duration_seconds
from src.engine.coordinator import Coordinator, CoordinatorConfig, RecoverySummary
from src.engine.loop_detector import (
    LoopConfig,
    LoopDetector,
    LoopGuardDecision,
    canonical_json_hash,
)
from src.engine.redaction import (
    contains_unredacted_secret_strict,
    is_sensitive_key_strict,
    redact_payload_strict,
    redact_string_strict,
)
from src.engine.tool_registry import (
    McpToolAdapter,
    McpToolDescriptor,
    PermissionToolError,
    ReconcilerFn,
    SemanticToolError,
    ToolExecutionContext,
    ToolExecutionResult,
    ToolHandler,
    ToolRegistry,
    TransientToolError,
    VerifierFn,
    validate_json_schema,
)

__all__ = [
    "BudgetManager",
    "Coordinator",
    "CoordinatorConfig",
    "LoopConfig",
    "LoopDetector",
    "LoopGuardDecision",
    "McpToolAdapter",
    "McpToolDescriptor",
    "PermissionToolError",
    "ReconcilerFn",
    "RecoverySummary",
    "SemanticToolError",
    "ToolExecutionContext",
    "ToolExecutionResult",
    "ToolHandler",
    "ToolRegistry",
    "TransientToolError",
    "VerifierFn",
    "canonical_json_hash",
    "contains_unredacted_secret_strict",
    "is_sensitive_key_strict",
    "redact_payload_strict",
    "redact_string_strict",
    "validate_duration_seconds",
    "validate_json_schema",
]
