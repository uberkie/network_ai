"""Local-only evidence handling for the Network AI Phase 1 foundation.

This package deliberately contains no collectors, network clients, router APIs,
model loaders, or response actions.
"""

from .contracts import IntakeContext, SourceType
from .ingest import IngestItem, IngestResult, IngestService
from .outcomes import (
    AnalysisOutcome,
    AuditState,
    AuthorityOutcome,
    CorrelationOutcome,
    EnforcementOutcome,
    IngestionOutcome,
    NetworkState,
    OutcomeContractError,
    ProcessingStage,
    StageOutcome,
)
from .replay import ReplayError, ReplayTrace, ReplayTraceStore, replay_trace
from .store import AuditCheckpoint, FileEvidenceStore

__all__ = [
    "AuditCheckpoint",
    "AuditState",
    "AnalysisOutcome",
    "AuthorityOutcome",
    "CorrelationOutcome",
    "EnforcementOutcome",
    "FileEvidenceStore",
    "IngestItem",
    "IngestResult",
    "IngestService",
    "IngestionOutcome",
    "IntakeContext",
    "NetworkState",
    "OutcomeContractError",
    "ProcessingStage",
    "ReplayError",
    "ReplayTrace",
    "ReplayTraceStore",
    "SourceType",
    "StageOutcome",
    "replay_trace",
]
