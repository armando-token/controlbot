"""M7 autonomous local software factory package (F16)."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.factory.db import FactoryStore, open_factory_connection
    from src.factory.demo import run_factory_demo
    from src.factory.engine import EvalResult, FactoryEngine, rollback_from_manifest
    from src.factory.errors import (
        DuplicateProposalError,
        FactoryBudgetError,
        FactoryError,
        FactoryLeaseError,
        IsolationBoundaryError,
        PolicyImmutabilityError,
    )
    from src.factory.models import (
        BacklogItem,
        CandidatePatch,
        CandidateRunRecord,
        CycleBudget,
        FactoryCycleResult,
        FactoryLease,
        FactoryStatus,
        LessonRecord,
        RollbackManifest,
        compute_proposal_hash,
    )
    from src.factory.policy import (
        IMMUTABLE_PATH_PREFIXES,
        ISOLATION_BOUNDARY_VIOLATION,
        POLICY_IMMUTABILITY_VIOLATION,
        IsolationGuard,
        PolicyGuard,
    )

_EXPORTS: dict[str, tuple[str, str]] = {
    "BacklogItem": ("src.factory.models", "BacklogItem"),
    "CandidatePatch": ("src.factory.models", "CandidatePatch"),
    "CandidateRunRecord": ("src.factory.models", "CandidateRunRecord"),
    "CycleBudget": ("src.factory.models", "CycleBudget"),
    "DuplicateProposalError": ("src.factory.errors", "DuplicateProposalError"),
    "EvalResult": ("src.factory.engine", "EvalResult"),
    "FactoryBudgetError": ("src.factory.errors", "FactoryBudgetError"),
    "FactoryCycleResult": ("src.factory.models", "FactoryCycleResult"),
    "FactoryEngine": ("src.factory.engine", "FactoryEngine"),
    "FactoryError": ("src.factory.errors", "FactoryError"),
    "FactoryLease": ("src.factory.models", "FactoryLease"),
    "FactoryLeaseError": ("src.factory.errors", "FactoryLeaseError"),
    "FactoryStatus": ("src.factory.models", "FactoryStatus"),
    "FactoryStore": ("src.factory.db", "FactoryStore"),
    "IMMUTABLE_PATH_PREFIXES": ("src.factory.policy", "IMMUTABLE_PATH_PREFIXES"),
    "ISOLATION_BOUNDARY_VIOLATION": ("src.factory.policy", "ISOLATION_BOUNDARY_VIOLATION"),
    "IsolationBoundaryError": ("src.factory.errors", "IsolationBoundaryError"),
    "IsolationGuard": ("src.factory.policy", "IsolationGuard"),
    "LessonRecord": ("src.factory.models", "LessonRecord"),
    "POLICY_IMMUTABILITY_VIOLATION": ("src.factory.policy", "POLICY_IMMUTABILITY_VIOLATION"),
    "PolicyGuard": ("src.factory.policy", "PolicyGuard"),
    "PolicyImmutabilityError": ("src.factory.errors", "PolicyImmutabilityError"),
    "RollbackManifest": ("src.factory.models", "RollbackManifest"),
    "compute_proposal_hash": ("src.factory.models", "compute_proposal_hash"),
    "open_factory_connection": ("src.factory.db", "open_factory_connection"),
    "rollback_from_manifest": ("src.factory.engine", "rollback_from_manifest"),
    "run_factory_demo": ("src.factory.demo", "run_factory_demo"),
}

__all__ = [
    "BacklogItem",
    "CandidatePatch",
    "CandidateRunRecord",
    "CycleBudget",
    "DuplicateProposalError",
    "EvalResult",
    "FactoryBudgetError",
    "FactoryCycleResult",
    "FactoryEngine",
    "FactoryError",
    "FactoryLease",
    "FactoryLeaseError",
    "FactoryStatus",
    "FactoryStore",
    "IMMUTABLE_PATH_PREFIXES",
    "ISOLATION_BOUNDARY_VIOLATION",
    "IsolationBoundaryError",
    "IsolationGuard",
    "LessonRecord",
    "POLICY_IMMUTABILITY_VIOLATION",
    "PolicyGuard",
    "PolicyImmutabilityError",
    "RollbackManifest",
    "compute_proposal_hash",
    "open_factory_connection",
    "rollback_from_manifest",
    "run_factory_demo",
]


def __getattr__(name: str) -> Any:
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    mod_name, attr_name = target
    mod = importlib.import_module(mod_name)
    return getattr(mod, attr_name)
