"""Closed, data-only terminal outcome contracts for local processing stages.

This module deliberately defines vocabulary and validation only.  It contains
no collectors, model execution, authority evaluator, router client, or action
executor.  An outcome records what was observed; it never infers a successful
state transition from missing evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .contracts import ValidationError, require_safe_id


OUTCOME_CONTRACT_VERSION = "stage-outcome.v1"


class ProcessingStage(str, Enum):
    INGESTION = "ingestion"
    CORRELATION = "correlation"
    ANALYSIS = "analysis"
    AUTHORITY = "authority"
    ENFORCEMENT = "enforcement"


class IngestionOutcome(str, Enum):
    ACCEPTED = "accepted"
    DUPLICATE_DELIVERY = "duplicate_delivery"
    QUARANTINED = "quarantined"
    UNSUPPORTED_VERSION = "unsupported_version"
    MALFORMED = "malformed"
    REJECTED = "rejected"
    PERSISTENCE_FAILED = "persistence_failed"


class CorrelationOutcome(str, Enum):
    MATCH = "match"  # Reserved; current correlation deliberately never emits it.
    PROBABLE_MATCH = "probable_match"
    AMBIGUOUS = "ambiguous"
    NO_MATCH = "no_match"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class AnalysisOutcome(str, Enum):
    NORMAL = "normal"
    CANDIDATE = "candidate"
    INCONCLUSIVE = "inconclusive"
    ANALYSIS_FAILED = "analysis_failed"


class AuthorityOutcome(str, Enum):
    APPROVED = "approved"
    DENIED = "denied"
    REQUIRES_REVIEW = "requires_review"
    AUTHORITY_UNAVAILABLE = "authority_unavailable"


class EnforcementOutcome(str, Enum):
    APPLIED = "applied"
    REJECTED = "rejected"
    EXPIRED = "expired"
    ROLLED_BACK = "rolled_back"
    EXECUTION_FAILED = "execution_failed"


class AuditState(str, Enum):
    """What the caller can truthfully say about the audit commit."""

    WRITTEN = "written"
    PREEXISTING_EVIDENCE = "preexisting_evidence"
    UNAVAILABLE = "unavailable"  # A commit could not be confirmed.
    NOT_APPLICABLE = "not_applicable"


class NetworkState(str, Enum):
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"
    CONFIRMED_APPLIED = "confirmed_applied"
    CONFIRMED_NOT_APPLIED = "confirmed_not_applied"


class OutcomeContractError(ValueError):
    """Raised when a caller tries to create an invalid terminal outcome."""


_STAGE_OUTCOME_TYPES = {
    ProcessingStage.INGESTION: IngestionOutcome,
    ProcessingStage.CORRELATION: CorrelationOutcome,
    ProcessingStage.ANALYSIS: AnalysisOutcome,
    ProcessingStage.AUTHORITY: AuthorityOutcome,
    ProcessingStage.ENFORCEMENT: EnforcementOutcome,
}

_MALFORMED_REASONS = frozenset(
    (
        "duplicate_json_key",
        "invalid_json",
        "invalid_network_address",
        "invalid_network_port",
        "invalid_network_port_for_protocol",
        "invalid_network_protocol",
        "invalid_session_reference",
        "invalid_source_event_id",
        "invalid_suricata_severity",
        "invalid_timestamp",
        "invalid_utf8",
        "json_array_items_exceeded",
        "json_nesting_exceeded",
        "json_object_members_exceeded",
        "json_root_not_object",
        "missing_or_invalid_required_field",
        "non_finite_number",
        "session_observed_at_outside_intake_skew",
        "session_observed_at_outside_validity_interval",
        "session_validity_interval_exceeded",
        "timestamp_timezone_required",
        "zeek_timestamp_out_of_range",
        "zeek_timestamp_precision_exceeded",
    )
)

_REJECTED_REASONS = frozenset(
    (
        "batch_byte_limit_exceeded",
        "batch_iterator_failure",
        "batch_record_limit_exceeded",
        "delivery_identity_conflict",
        "forbidden_mikrotik_field",
        "invalid_allowlisted_field",
        "invalid_batch_iterable",
        "invalid_ingest_item",
        "invalid_intake_context",
        "non_bytes_input",
        "record_size_exceeded",
        "unsupported_mikrotik_session_field",
    )
)

_REASON_CODES = {
    (ProcessingStage.INGESTION, IngestionOutcome.ACCEPTED.value): frozenset(("accepted",)),
    (ProcessingStage.INGESTION, IngestionOutcome.DUPLICATE_DELIVERY.value): frozenset(("duplicate_delivery",)),
    (ProcessingStage.INGESTION, IngestionOutcome.QUARANTINED.value): frozenset(("parser_failure", "unmapped_validation_error")),
    (ProcessingStage.INGESTION, IngestionOutcome.UNSUPPORTED_VERSION.value): frozenset(
        ("unsupported_format_profile", "unsupported_source", "unsupported_suricata_event_type", "unsupported_zeek_log_type")
    ),
    (ProcessingStage.INGESTION, IngestionOutcome.MALFORMED.value): _MALFORMED_REASONS,
    (ProcessingStage.INGESTION, IngestionOutcome.REJECTED.value): _REJECTED_REASONS,
    (ProcessingStage.INGESTION, IngestionOutcome.PERSISTENCE_FAILED.value): frozenset(("persistence_failure",)),
}
for _outcome_type in (CorrelationOutcome, AnalysisOutcome, AuthorityOutcome, EnforcementOutcome):
    for _outcome in _outcome_type:
        _REASON_CODES[
            (
                ProcessingStage.CORRELATION
                if _outcome_type is CorrelationOutcome
                else ProcessingStage.ANALYSIS
                if _outcome_type is AnalysisOutcome
                else ProcessingStage.AUTHORITY
                if _outcome_type is AuthorityOutcome
                else ProcessingStage.ENFORCEMENT,
                _outcome.value,
            )
        ] = frozenset(("reported",))

_INPUT_ONLY_REJECTIONS = frozenset(
    ("batch_byte_limit_exceeded", "batch_iterator_failure", "batch_record_limit_exceeded", "invalid_batch_iterable", "invalid_ingest_item", "invalid_intake_context", "non_bytes_input")
)

_DURABLE_QUARANTINE_CODES = (
    _MALFORMED_REASONS
    | _REJECTED_REASONS
    | _REASON_CODES[(ProcessingStage.INGESTION, IngestionOutcome.UNSUPPORTED_VERSION.value)]
    | frozenset(("parser_failure", "unmapped_validation_error"))
)


@dataclass(frozen=True)
class StageOutcome:
    """A typed terminal result with no raw payload or exception detail."""

    stage: ProcessingStage
    outcome: IngestionOutcome | CorrelationOutcome | AnalysisOutcome | AuthorityOutcome | EnforcementOutcome
    reason_code: str
    evidence_refs: tuple[str, ...] = ()
    audit_state: AuditState = AuditState.NOT_APPLICABLE
    audit_entry_index: int | None = None
    network_state: NetworkState = NetworkState.NOT_APPLICABLE

    def __post_init__(self) -> None:
        if not isinstance(self.stage, ProcessingStage):
            raise OutcomeContractError("invalid_processing_stage")
        expected_type = _STAGE_OUTCOME_TYPES[self.stage]
        if not isinstance(self.outcome, expected_type):
            raise OutcomeContractError("invalid_stage_outcome_pair")
        allowed_reasons = _REASON_CODES.get((self.stage, self.outcome.value), frozenset())
        if not isinstance(self.reason_code, str) or self.reason_code not in allowed_reasons:
            raise OutcomeContractError("invalid_outcome_reason_code")
        if not isinstance(self.evidence_refs, tuple):
            raise OutcomeContractError("evidence_refs_must_be_tuple")
        try:
            for evidence_id in self.evidence_refs:
                require_safe_id(evidence_id, "evidence_ref")
        except ValidationError as exc:
            raise OutcomeContractError("invalid_outcome_evidence_ref") from exc
        if self.evidence_refs != tuple(sorted(set(self.evidence_refs))):
            raise OutcomeContractError("outcome_evidence_refs_must_be_unique_and_sorted")
        if not isinstance(self.audit_state, AuditState):
            raise OutcomeContractError("invalid_outcome_audit_state")
        if self.audit_entry_index is not None and (
            isinstance(self.audit_entry_index, bool) or not isinstance(self.audit_entry_index, int) or self.audit_entry_index < 0
        ):
            raise OutcomeContractError("invalid_outcome_audit_entry_index")
        if not isinstance(self.network_state, NetworkState):
            raise OutcomeContractError("invalid_outcome_network_state")
        if self.stage is not ProcessingStage.INGESTION:
            if self.audit_state is not AuditState.NOT_APPLICABLE or self.audit_entry_index is not None:
                raise OutcomeContractError("non_ingestion_audit_state_must_be_not_applicable")
        else:
            self._validate_ingestion_audit_state()
        if self.stage is ProcessingStage.ENFORCEMENT:
            self._validate_enforcement_network_state()
        elif self.network_state is not NetworkState.NOT_APPLICABLE:
            raise OutcomeContractError("non_enforcement_network_state_not_applicable")

    def _validate_ingestion_audit_state(self) -> None:
        if self.outcome is IngestionOutcome.ACCEPTED:
            if (
                self.audit_state is not AuditState.WRITTEN
                or self.audit_entry_index is None
                or len(self.evidence_refs) != 1
            ):
                raise OutcomeContractError("accepted_requires_written_audit_and_evidence_reference")
            return
        if self.outcome is IngestionOutcome.DUPLICATE_DELIVERY:
            if (
                self.audit_state is not AuditState.PREEXISTING_EVIDENCE
                or self.audit_entry_index is None
                or len(self.evidence_refs) != 1
            ):
                raise OutcomeContractError("duplicate_delivery_requires_preexisting_audit_reference")
            return
        if self.outcome is IngestionOutcome.PERSISTENCE_FAILED:
            if self.audit_state is not AuditState.UNAVAILABLE or self.audit_entry_index is not None or self.evidence_refs:
                raise OutcomeContractError("persistence_failure_requires_unavailable_audit_state")
            return
        if self.outcome in (
            IngestionOutcome.QUARANTINED,
            IngestionOutcome.UNSUPPORTED_VERSION,
            IngestionOutcome.MALFORMED,
        ):
            if self.audit_state is not AuditState.WRITTEN or self.audit_entry_index is None or self.evidence_refs:
                raise OutcomeContractError("durable_quarantine_requires_written_audit_without_evidence_reference")
            return
        if self.outcome is IngestionOutcome.REJECTED:
            if self.reason_code in _INPUT_ONLY_REJECTIONS:
                if self.audit_state is AuditState.NOT_APPLICABLE and self.audit_entry_index is None and not self.evidence_refs:
                    return
            elif self.audit_state is AuditState.WRITTEN and self.audit_entry_index is not None and not self.evidence_refs:
                return
        raise OutcomeContractError("invalid_ingestion_audit_state")

    def _validate_enforcement_network_state(self) -> None:
        allowed_states = {
            EnforcementOutcome.APPLIED: frozenset((NetworkState.CONFIRMED_APPLIED,)),
            EnforcementOutcome.REJECTED: frozenset((NetworkState.CONFIRMED_NOT_APPLIED,)),
            EnforcementOutcome.EXPIRED: frozenset((NetworkState.CONFIRMED_NOT_APPLIED,)),
            EnforcementOutcome.ROLLED_BACK: frozenset((NetworkState.CONFIRMED_NOT_APPLIED,)),
            EnforcementOutcome.EXECUTION_FAILED: frozenset((NetworkState.UNKNOWN, NetworkState.CONFIRMED_NOT_APPLIED)),
        }
        if self.network_state not in allowed_states[self.outcome]:
            raise OutcomeContractError("invalid_enforcement_outcome_network_state_pair")

    def as_manifest(self) -> dict[str, object]:
        return {
            "audit_entry_index": self.audit_entry_index,
            "audit_state": self.audit_state.value,
            "contract_version": OUTCOME_CONTRACT_VERSION,
            "evidence_refs": list(self.evidence_refs),
            "network_state": self.network_state.value,
            "outcome": self.outcome.value,
            "reason_code": self.reason_code,
            "stage": self.stage.value,
        }


def correlation_stage_outcome(
    outcome: CorrelationOutcome, *, evidence_refs: tuple[str, ...],
) -> StageOutcome:
    """Create a validated derived outcome for an existing correlation result."""
    return StageOutcome(
        stage=ProcessingStage.CORRELATION,
        outcome=outcome,
        reason_code="reported",
        evidence_refs=evidence_refs,
    )


def ingestion_outcome_for_validation_code(code: str) -> tuple[IngestionOutcome, str]:
    """Map every known validation code without exposing arbitrary parser text."""
    if code == "parser_failure":
        return IngestionOutcome.QUARANTINED, "parser_failure"
    if code in _MALFORMED_REASONS:
        return IngestionOutcome.MALFORMED, code
    if code in _REJECTED_REASONS:
        return IngestionOutcome.REJECTED, code
    if code in _REASON_CODES[(ProcessingStage.INGESTION, IngestionOutcome.UNSUPPORTED_VERSION.value)]:
        return IngestionOutcome.UNSUPPORTED_VERSION, code
    return IngestionOutcome.QUARANTINED, "unmapped_validation_error"


def is_durable_quarantine_code(code: str) -> bool:
    """Return whether a ledgered quarantine code belongs to the frozen registry."""
    return isinstance(code, str) and code in _DURABLE_QUARANTINE_CODES
