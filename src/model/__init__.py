"""Model client protocol and deterministic emulator package (F09)."""

from src.model.emulator import VALID_EMULATOR_MODES, EmulatedModelClient, EmulatedTurn, EmulatorMode
from src.model.http_client import (
    LocalHttpModelClient,
    LocalModelConfig,
    build_model_client,
    validate_local_model_origin,
)
from src.model.protocol import (
    BudgetRemaining,
    ModelClient,
    ModelDecision,
    ModelDelegationRequest,
    ModelProtocolError,
    ModelToolCall,
    ModelUsage,
    PromptContext,
    TransientModelError,
)

__all__ = [
    "BudgetRemaining",
    "EmulatedModelClient",
    "EmulatedTurn",
    "EmulatorMode",
    "LocalHttpModelClient",
    "LocalModelConfig",
    "ModelClient",
    "ModelDecision",
    "ModelDelegationRequest",
    "ModelProtocolError",
    "ModelToolCall",
    "ModelUsage",
    "PromptContext",
    "TransientModelError",
    "VALID_EMULATOR_MODES",
    "build_model_client",
    "validate_local_model_origin",
]
