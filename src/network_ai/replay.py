"""Bounded, read-only reconstruction of durable local processing outcomes."""

from __future__ import annotations

from dataclasses import dataclass
import errno
import json
import os
from pathlib import Path
from typing import Any, Mapping

from .contracts import (
    CONTRACT_VERSION,
    ClockQuality,
    DataClassification,
    IntakeContext,
    PayloadAccessPolicy,
    RedactionStatus,
    RetentionPolicy,
    SourceType,
    ValidationError,
    MAX_RECORD_BYTES,
    canonical_json,
    require_sha256,
    sha256_bytes,
)
from .correlation import (
    CorrelationConfig,
    CorrelationError,
    CorrelationResult,
    SessionCorrelationConfig,
    _correlate_snapshot,
    _correlate_with_session_snapshot,
    _references_from_snapshot,
    _source_reference,
)
from .outcomes import AuditState, IngestionOutcome, OutcomeContractError, ProcessingStage, StageOutcome, ingestion_outcome_for_validation_code, is_durable_quarantine_code
from .store import FileEvidenceStore, VerifiedAuditEntry


REPLAY_CONTRACT_VERSION = "replay-trace.v1"
MAX_REPLAY_AUDIT_ENTRIES = 2_048
MAX_REPLAY_LEDGER_BYTES = 16 * 1024 * 1024
MAX_REPLAY_OUTPUT_BYTES = 256 * 1024
# A normal size-rejected intake is one byte over the input limit and remains
# replayable. Larger preserved quarantines are outside this bounded trace view.
MAX_REPLAY_ARTIFACT_BYTES = MAX_RECORD_BYTES + 1
_COVERAGE = "durable_ledger_entries_only"
_LIMITATIONS = (
    "duplicate_delivery_attempts_are_not_durable_ledger_entries",
    "invalid_api_and_batch_rejections_without_audit_are_not_replayable",
    "persistence_failures_without_confirmed_audit_are_not_replayable",
    "durable_artifacts_above_replay_artifact_limit_are_not_replayable",
)


class ReplayError(ValueError):
    pass


def _checkpoint_manifest(checkpoint: Any) -> dict[str, Any] | None:
    if checkpoint is None:
        return None
    return {
        "byte_offset": checkpoint.byte_offset,
        "entry_hash": checkpoint.entry_hash,
        "entry_index": checkpoint.entry_index,
        "ledger_id": checkpoint.ledger_id,
    }


def _semantic_outcome(outcome: StageOutcome) -> dict[str, object]:
    value = outcome.as_manifest()
    value.pop("audit_entry_index")
    return value


def _replay_entry_id(material: Mapping[str, Any]) -> str:
    return sha256_bytes(canonical_json(material).encode("utf-8"))


def _trusted_context(value: Any) -> IntakeContext:
    if not isinstance(value, Mapping) or set(value) != {
        "acquisition_config_sha256", "clock_quality", "delivery_id", "format_profile", "ingested_at", "observed_at", "sensor_id", "source",
    }:
        raise ReplayError("invalid_replay_intake_context")
    try:
        return IntakeContext(
            source=SourceType(value["source"]),
            sensor_id=value["sensor_id"],
            delivery_id=value["delivery_id"],
            format_profile=value["format_profile"],
            observed_at=value["observed_at"],
            ingested_at=value["ingested_at"],
            clock_quality=ClockQuality(value["clock_quality"]),
            acquisition_config_sha256=value["acquisition_config_sha256"],
        )
    except Exception as exc:
        raise ReplayError("invalid_replay_intake_context") from exc


def _validated_entry(entry: VerifiedAuditEntry) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    manifest = entry.manifest
    outcome = manifest.get("outcome")
    if outcome == "accepted":
        try:
            reference = _source_reference(manifest)
            stage = StageOutcome(
                ProcessingStage.INGESTION,
                IngestionOutcome.ACCEPTED,
                "accepted",
                evidence_refs=(reference["evidence_id"],),
                audit_state=AuditState.WRITTEN,
                audit_entry_index=entry.index,
            )
        except (CorrelationError, OutcomeContractError, ValidationError, KeyError, TypeError, ValueError) as exc:
            raise ReplayError("invalid_replay_accepted_manifest") from exc
        semantic = {
            "entry_kind": "accepted",
            "evidence_id": reference["evidence_id"],
            "event_time": reference["event_time"],
            "format_profile": reference["format_profile"],
            "raw_sha256": reference["raw_sha256"],
            "sensor_id": reference["sensor_id"],
            "source": reference["source"],
        }
        return manifest, {"entry_id": _replay_entry_id(semantic), "semantic_outcome": _semantic_outcome(stage), "stage_outcome": stage.as_manifest()}
    expected = {
        "classification", "contract_version", "intake", "outcome", "payload_access_policy", "quarantine", "redaction_status", "retention_policy",
    }
    quarantine = manifest.get("quarantine")
    if (
        outcome != "quarantined"
        or set(manifest) != expected
        or manifest.get("contract_version") != CONTRACT_VERSION
        or manifest.get("classification") != DataClassification.SYNTHETIC_NETWORK_METADATA.value
        or manifest.get("payload_access_policy") != PayloadAccessPolicy.OWNER_ONLY_LOCAL_FIXTURE.value
        or manifest.get("redaction_status") != RedactionStatus.SYNTHETIC.value
        or manifest.get("retention_policy") != RetentionPolicy.FIXTURE_30_DAYS.value
        or not isinstance(quarantine, Mapping)
        or set(quarantine) != {"code", "raw_sha256", "size_bytes"}
        or not is_durable_quarantine_code(quarantine.get("code"))
        or isinstance(quarantine.get("size_bytes"), bool)
        or not isinstance(quarantine.get("size_bytes"), int)
        or quarantine["size_bytes"] < 0
    ):
        raise ReplayError("invalid_replay_quarantine_manifest")
    try:
        require_sha256(quarantine["raw_sha256"], "quarantine.raw_sha256")
    except Exception as exc:
        raise ReplayError("invalid_replay_quarantine_manifest") from exc
    context = _trusted_context(manifest["intake"])
    outcome_kind, reason_code = ingestion_outcome_for_validation_code(quarantine["code"])
    stage = StageOutcome(
        ProcessingStage.INGESTION,
        outcome_kind,
        reason_code,
        audit_state=AuditState.WRITTEN,
        audit_entry_index=entry.index,
    )
    semantic = {
        "entry_kind": "quarantined",
        "intake": context.as_manifest(),
        "quarantine_code": quarantine["code"],
        "raw_sha256": quarantine["raw_sha256"],
        "size_bytes": quarantine["size_bytes"],
    }
    return None, {"entry_id": _replay_entry_id(semantic), "semantic_outcome": _semantic_outcome(stage), "stage_outcome": stage.as_manifest()}


def _correlation_projection(result: CorrelationResult) -> dict[str, Any]:
    payload = result.payload
    traffic = payload.get("traffic", payload)
    if not isinstance(traffic, Mapping):
        raise ReplayError("invalid_replay_correlation_result")
    return {
        "rationale": traffic["rationale"],
        "semantic_correlation_id": result.semantic_correlation_id,
        "stage_outcome": result.stage_outcome.as_manifest(),
    }


def _session_projection(result: CorrelationResult) -> dict[str, Any] | None:
    outcome = result.session_stage_outcome
    if outcome is None:
        return None
    payload = result.payload["session_association"]
    return {
        "rationale": payload["rationale"],
        "semantic_correlation_id": result.semantic_correlation_id,
        "stage_outcome": outcome.as_manifest(),
    }


@dataclass(frozen=True)
class ReplayTrace:
    semantic_replay_id: str
    derivation_id: str
    canonical_json: str

    def __post_init__(self) -> None:
        try:
            require_sha256(self.semantic_replay_id, "semantic_replay_id")
            require_sha256(self.derivation_id, "derivation_id")
        except ValidationError as exc:
            raise ReplayError("invalid_replay_trace") from exc
        try:
            payload = json.loads(self.canonical_json)
        except json.JSONDecodeError as exc:
            raise ReplayError("invalid_replay_trace") from exc
        if not isinstance(payload, dict) or canonical_json(payload) != self.canonical_json:
            raise ReplayError("invalid_replay_trace")
        if payload.get("semantic_replay_id") != self.semantic_replay_id or payload.get("derivation_id") != self.derivation_id:
            raise ReplayError("invalid_replay_trace")
        semantic = payload.get("semantic")
        if not isinstance(semantic, dict) or sha256_bytes(canonical_json(semantic).encode("utf-8")) != self.semantic_replay_id:
            raise ReplayError("invalid_replay_trace")
        derivation = dict(payload)
        derivation.pop("derivation_id")
        if sha256_bytes(canonical_json(derivation).encode("utf-8")) != self.derivation_id:
            raise ReplayError("invalid_replay_trace")

    @property
    def payload(self) -> dict[str, Any]:
        value = json.loads(self.canonical_json)
        if not isinstance(value, dict):
            raise RuntimeError("invalid_replay_trace")
        return value


def replay_trace(
    store: FileEvidenceStore, traffic_config: CorrelationConfig | None = None, session_config: SessionCorrelationConfig | None = None,
) -> ReplayTrace:
    if not isinstance(store, FileEvidenceStore):
        raise TypeError("store_must_be_FileEvidenceStore")
    if session_config is not None and traffic_config is None:
        raise ReplayError("session_replay_requires_traffic_config")
    try:
        snapshot = store.verified_audit_snapshot(
            max_entries=MAX_REPLAY_AUDIT_ENTRIES,
            max_bytes=MAX_REPLAY_LEDGER_BYTES,
            max_artifact_bytes=MAX_REPLAY_ARTIFACT_BYTES,
        )
    except RuntimeError as exc:
        raise ReplayError(str(exc)) from exc
    accepted: list[dict[str, Any]] = []
    detailed_entries: list[dict[str, Any]] = []
    for entry in snapshot.entries:
        accepted_manifest, projection = _validated_entry(entry)
        if accepted_manifest is not None:
            accepted.append(accepted_manifest)
        detailed_entries.append({"audit_entry_index": entry.index, **projection})
    accepted_snapshot = snapshot.accepted_snapshot
    # `_validated_entry` and `_source_reference` validate every accepted item,
    # even when no correlation policy is requested.
    try:
        _references_from_snapshot(accepted_snapshot)
    except (CorrelationError, ValidationError, KeyError, TypeError, ValueError) as exc:
        raise ReplayError("invalid_replay_accepted_manifest") from exc
    traffic_results: tuple[CorrelationResult, ...] = ()
    if traffic_config is not None:
        try:
            traffic_results = (
                _correlate_with_session_snapshot(accepted_snapshot, traffic_config, session_config)
                if session_config is not None
                else _correlate_snapshot(accepted_snapshot, traffic_config, _references_from_snapshot(accepted_snapshot))
            )
        except (CorrelationError, ValidationError, KeyError, TypeError, ValueError) as exc:
            raise ReplayError("invalid_replay_correlation_input") from exc
    traffic = sorted((_correlation_projection(item) for item in traffic_results), key=lambda item: item["semantic_correlation_id"])
    sessions = sorted((item for result in traffic_results if (item := _session_projection(result)) is not None), key=lambda item: item["semantic_correlation_id"])
    semantic_entries = sorted(
        ({"entry_id": item["entry_id"], "stage_outcome": item["semantic_outcome"]} for item in detailed_entries),
        key=lambda item: (item["entry_id"], canonical_json(item)),
    )
    semantic = {
        "config": {
            "session_config_sha256": session_config.sha256 if session_config is not None else "none",
            "traffic_config_sha256": traffic_config.sha256 if traffic_config is not None else "none",
        },
        "contract_version": REPLAY_CONTRACT_VERSION,
        "coverage": _COVERAGE,
        "intake_outcomes": semantic_entries,
        "limitations": list(_LIMITATIONS),
        "session_correlation_outcomes": sessions,
        "traffic_correlation_outcomes": traffic,
    }
    semantic_id = sha256_bytes(canonical_json(semantic).encode("utf-8"))
    payload = dict(semantic)
    payload["semantic"] = semantic
    payload["semantic_replay_id"] = semantic_id
    payload["audit_entry_order"] = detailed_entries
    payload["source_ledger_checkpoint"] = _checkpoint_manifest(snapshot.checkpoint)
    encoded_without_derivation = canonical_json(payload)
    if len(encoded_without_derivation.encode("utf-8")) > MAX_REPLAY_OUTPUT_BYTES:
        raise ReplayError("replay_output_size_exceeded")
    derivation_id = sha256_bytes(encoded_without_derivation.encode("utf-8"))
    payload["derivation_id"] = derivation_id
    encoded = canonical_json(payload)
    if len(encoded.encode("utf-8")) > MAX_REPLAY_OUTPUT_BYTES:
        raise ReplayError("replay_output_size_exceeded")
    return ReplayTrace(semantic_id, derivation_id, encoded)


class ReplayTraceStore:
    """Owner-only, idempotent local persistence for already-validated traces."""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)
        if self.root.exists() and self.root.is_symlink():
            raise ReplayError("replay_store_root_must_not_be_symlink")
        self.root.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            self.root.chmod(0o700)

    def persist(self, trace: ReplayTrace) -> str:
        if not isinstance(trace, ReplayTrace):
            raise TypeError("trace_must_be_ReplayTrace")
        # Frozen dataclasses can still be bypassed by hostile callers using
        # object.__setattr__. Reconstruct before an identifier reaches a path.
        verified = ReplayTrace(trace.semantic_replay_id, trace.derivation_id, trace.canonical_json)
        data = verified.canonical_json.encode("utf-8") + b"\n"
        path = self.root / f"{verified.derivation_id}.json"
        if path.exists() and path.is_symlink():
            raise ReplayError("replay_trace_must_not_be_symlink")
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise
            if path.read_bytes() != data:
                raise ReplayError("replay_trace_collision_or_tamper")
            return "duplicate"
        try:
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("unable_to_write_replay_trace")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if os.name != "nt":
            path.chmod(0o600)
        return "persisted"
