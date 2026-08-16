"""Bounded fixture ingestion with explicit, terminal outcomes.

Bytes are supplied directly by a local caller. This module does not fetch
telemetry from a network, and it never converts an unknown parser or storage
condition into acceptance.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .adapters import create_envelope
from .contracts import MAX_BATCH_BYTES, MAX_BATCH_RECORDS, MAX_RECORD_BYTES, IntakeContext, ValidationError
from .outcomes import (
    AuditState,
    IngestionOutcome,
    ProcessingStage,
    StageOutcome,
    ingestion_outcome_for_validation_code,
)
from .store import FileEvidenceStore, PersistResult
from .strict_json import parse_strict_json


@dataclass(frozen=True)
class IngestItem:
    context: IntakeContext
    raw: bytes


@dataclass(frozen=True)
class IngestResult:
    """Legacy persistence status plus the canonical terminal stage outcome."""

    status: str
    stage_outcome: StageOutcome
    evidence_id: str | None = None
    quarantine_code: str | None = None
    audit_entry_index: int | None = None


class IngestService:
    """The fixture-only API: parser and storage failures stay visible."""

    def __init__(self, store: FileEvidenceStore) -> None:
        self._store = store

    @property
    def store(self) -> FileEvidenceStore:
        """The local evidence store used by this fixture-only service."""
        return self._store

    def ingest(self, item: IngestItem) -> IngestResult:
        preflight = self._validate_item(item)
        if preflight is not None:
            return preflight
        assert isinstance(item, IngestItem)
        assert isinstance(item.context, IntakeContext)
        assert isinstance(item.raw, bytes)
        trusted_item = IngestItem(self._revalidated_context(item.context), item.raw)
        if len(trusted_item.raw) > MAX_RECORD_BYTES:
            return self._quarantine(trusted_item, "record_size_exceeded")
        try:
            parsed = parse_strict_json(trusted_item.raw)
            envelope = create_envelope(trusted_item.context, trusted_item.raw, parsed)
        except ValidationError as exc:
            _, durable_code = ingestion_outcome_for_validation_code(exc.code)
            return self._quarantine(trusted_item, durable_code)
        except Exception:
            # Details never become a public reason code. The record is only
            # called quarantined if the ledger append confirms the audit entry.
            return self._quarantine(trusted_item, "parser_failure")
        try:
            persisted = self._store.append_evidence(envelope, trusted_item.raw)
        except Exception:
            return self._persistence_failure()
        return self._from_persisted(persisted)

    def ingest_batch(self, items: Iterable[IngestItem]) -> tuple[IngestResult, ...]:
        """Consume a bounded iterable prefix and return its terminal results.

        Batch limit errors intentionally return explicit rejected outcomes
        rather than the former ``ValueError``. At most
        ``MAX_BATCH_RECORDS + 1`` values are requested, so an unbounded input
        is not materialized and its unread suffix has no claimed outcome.
        """
        try:
            iterator = iter(items)
        except Exception:
            return (self._input_rejected("invalid_batch_iterable"),)
        buffered: list[object] = []
        preflight: list[IngestResult | None] = []
        total_bytes = 0
        while len(buffered) <= MAX_BATCH_RECORDS:
            try:
                item = next(iterator)
            except StopIteration:
                break
            except Exception:
                return self._batch_iterator_failure(buffered, preflight)
            buffered.append(item)
            result = self._validate_item(item)
            preflight.append(result)
            if len(buffered) > MAX_BATCH_RECORDS:
                return self._batch_rejected(buffered, preflight, "batch_record_limit_exceeded")
            if result is None:
                assert isinstance(item, IngestItem) and isinstance(item.raw, bytes)
                total_bytes += len(item.raw)
                if total_bytes > MAX_BATCH_BYTES:
                    return self._batch_rejected(buffered, preflight, "batch_byte_limit_exceeded")
        results: list[IngestResult] = []
        for item, result in zip(buffered, preflight, strict=True):
            results.append(result if result is not None else self.ingest(item))
        return tuple(results)

    def _validate_item(self, item: object) -> IngestResult | None:
        if not isinstance(item, IngestItem):
            return self._input_rejected("invalid_ingest_item")
        if not isinstance(item.context, IntakeContext):
            return self._input_rejected("invalid_intake_context")
        if not isinstance(item.raw, bytes):
            return self._input_rejected("non_bytes_input")
        try:
            self._revalidated_context(item.context)
        except Exception:
            return self._input_rejected("invalid_intake_context")
        return None

    @staticmethod
    def _revalidated_context(context: IntakeContext) -> IntakeContext:
        """Rebuild trusted metadata to reject post-construction mutation."""
        return IntakeContext(
            source=context.source,
            sensor_id=context.sensor_id,
            delivery_id=context.delivery_id,
            format_profile=context.format_profile,
            observed_at=context.observed_at,
            ingested_at=context.ingested_at,
            clock_quality=context.clock_quality,
            acquisition_config_sha256=context.acquisition_config_sha256,
        )

    def _batch_rejected(
        self, buffered: list[object], preflight: list[IngestResult | None], reason_code: str,
    ) -> tuple[IngestResult, ...]:
        return tuple(
            result if result is not None else self._input_rejected(reason_code)
            for _, result in zip(buffered, preflight, strict=True)
        )

    def _batch_iterator_failure(
        self, buffered: list[object], preflight: list[IngestResult | None],
    ) -> tuple[IngestResult, ...]:
        prefix = self._batch_rejected(buffered, preflight, "batch_iterator_failure")
        return prefix + (self._input_rejected("batch_iterator_failure"),)

    @staticmethod
    def _input_rejected(reason_code: str) -> IngestResult:
        return IngestResult(
            status="rejected",
            stage_outcome=StageOutcome(
                stage=ProcessingStage.INGESTION,
                outcome=IngestionOutcome.REJECTED,
                reason_code=reason_code,
            ),
        )

    def _quarantine(self, item: IngestItem, code: str) -> IngestResult:
        try:
            persisted: PersistResult = self._store.append_quarantine(item.context, item.raw, code)
        except Exception:
            return self._persistence_failure()
        return self._from_persisted(persisted)

    @staticmethod
    def _persistence_failure() -> IngestResult:
        return IngestResult(
            status="persistence_failed",
            stage_outcome=StageOutcome(
                stage=ProcessingStage.INGESTION,
                outcome=IngestionOutcome.PERSISTENCE_FAILED,
                reason_code="persistence_failure",
                audit_state=AuditState.UNAVAILABLE,
            ),
        )

    @staticmethod
    def _from_persisted(persisted: PersistResult) -> IngestResult:
        if persisted.status == "accepted":
            if not isinstance(persisted.evidence_id, str) or persisted.audit_entry_index < 0:
                return IngestService._persistence_failure()
            outcome = StageOutcome(
                stage=ProcessingStage.INGESTION,
                outcome=IngestionOutcome.ACCEPTED,
                reason_code="accepted",
                evidence_refs=(persisted.evidence_id,),
                audit_state=AuditState.WRITTEN,
                audit_entry_index=persisted.audit_entry_index,
            )
            return IngestResult("accepted", outcome, persisted.evidence_id, audit_entry_index=persisted.audit_entry_index)
        if persisted.status == "duplicate_delivery":
            if not isinstance(persisted.evidence_id, str) or persisted.audit_entry_index < 0:
                return IngestService._persistence_failure()
            outcome = StageOutcome(
                stage=ProcessingStage.INGESTION,
                outcome=IngestionOutcome.DUPLICATE_DELIVERY,
                reason_code="duplicate_delivery",
                evidence_refs=(persisted.evidence_id,),
                audit_state=AuditState.PREEXISTING_EVIDENCE,
                audit_entry_index=persisted.audit_entry_index,
            )
            return IngestResult("duplicate_delivery", outcome, persisted.evidence_id, audit_entry_index=persisted.audit_entry_index)
        if persisted.status == "quarantined" and isinstance(persisted.quarantine_code, str) and persisted.audit_entry_index >= 0:
            outcome_kind, reason_code = ingestion_outcome_for_validation_code(persisted.quarantine_code)
            outcome = StageOutcome(
                stage=ProcessingStage.INGESTION,
                outcome=outcome_kind,
                reason_code=reason_code,
                audit_state=AuditState.WRITTEN,
                audit_entry_index=persisted.audit_entry_index,
            )
            return IngestResult("quarantined", outcome, quarantine_code=persisted.quarantine_code, audit_entry_index=persisted.audit_entry_index)
        return IngestService._persistence_failure()
