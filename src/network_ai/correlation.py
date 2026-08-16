"""Fixture-only, deterministic Suricata-to-Zeek correlation (Phase 2a).

This module deliberately consumes a verified local evidence-store snapshot. It
does not read logs, sockets, raw evidence files, or router state. A five-tuple
and time-window link is *probable*, never proof of the same traffic or cause.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import errno
import ipaddress
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping

from .contracts import (
    ADAPTER_VERSION,
    CONTRACT_VERSION,
    MIKROTIK_SESSION_ADAPTER_VERSION,
    MIKROTIK_SESSION_FORMAT_PROFILE,
    MIKROTIK_SESSION_SCHEMA_VERSION,
    PARSER_VERSION,
    SCHEMA_VERSION,
    canonical_json,
    format_rfc3339,
    parse_rfc3339,
    require_safe_id,
    require_sha256,
    sha256_bytes,
)
from .outcomes import CorrelationOutcome, StageOutcome, correlation_stage_outcome
from .store import FileEvidenceStore, VerifiedEvidenceSnapshot


CORRELATION_CONTRACT_VERSION = "fixture-correlation.v2"
RULE_ID = "suricata-zeek-five-tuple.v2"
MATCH_BASIS = "exact_5_tuple_event_time_window"
SESSION_CORRELATION_CONTRACT_VERSION = "fixture-session-association.v1"
SESSION_RULE_ID = "suricata-mikrotik-session-ip-time.v1"
MAX_SESSION_CANDIDATES_PER_ANCHOR = 32
MAX_SESSION_VALIDITY_SECONDS = 31 * 24 * 60 * 60
MAX_ACCEPTED_MANIFESTS = 1_024
MAX_ALERT_ANCHORS = 256
MAX_CANDIDATES_PER_ANCHOR = 32
MAX_RESULT_BYTES = 64 * 1024
_PORT_BEARING_PROTOCOLS = frozenset(("TCP", "UDP", "SCTP"))
_NETWORK_PROTOCOLS = _PORT_BEARING_PROTOCOLS | frozenset(("ICMP", "ICMPV6"))
_OBSERVATION_PROFILE_MATRIX = {
    ("suricata", "suricata-eve-alert.v1"): ("suricata.alert", ADAPTER_VERSION, PARSER_VERSION, SCHEMA_VERSION),
    ("zeek", "zeek-json-conn.v1"): ("zeek.conn", ADAPTER_VERSION, PARSER_VERSION, SCHEMA_VERSION),
    ("mikrotik", "mikrotik-telemetry-allowlist.v1"): ("mikrotik.telemetry", ADAPTER_VERSION, PARSER_VERSION, SCHEMA_VERSION),
    ("mikrotik", MIKROTIK_SESSION_FORMAT_PROFILE): (
        "mikrotik.session_binding",
        MIKROTIK_SESSION_ADAPTER_VERSION,
        PARSER_VERSION,
        MIKROTIK_SESSION_SCHEMA_VERSION,
    ),
}


class CorrelationError(ValueError):
    pass


@dataclass(frozen=True)
class FixtureCoverage:
    """A narrow synthetic assertion that a Zeek fixture window is complete."""

    coverage_id: str
    zeek_sensor_id: str
    starts_at: str
    ends_at: str
    fixture_scope_sha256: str

    def __post_init__(self) -> None:
        require_safe_id(self.coverage_id, "coverage_id")
        require_safe_id(self.zeek_sensor_id, "zeek_sensor_id")
        require_sha256(self.fixture_scope_sha256, "fixture_scope_sha256")
        if parse_rfc3339(self.ends_at, field_name="coverage.ends_at") < parse_rfc3339(self.starts_at, field_name="coverage.starts_at"):
            raise CorrelationError("invalid_coverage_window")

    @property
    def sha256(self) -> str:
        return sha256_bytes(canonical_json(self.as_manifest()).encode("utf-8"))

    def as_manifest(self) -> dict[str, str]:
        return {
            "coverage_id": self.coverage_id,
            "ends_at": format_rfc3339(parse_rfc3339(self.ends_at, field_name="coverage.ends_at")),
            "fixture_scope_sha256": self.fixture_scope_sha256,
            "source": "zeek",
            "starts_at": format_rfc3339(parse_rfc3339(self.starts_at, field_name="coverage.starts_at")),
            "zeek_sensor_id": self.zeek_sensor_id,
        }

    def covers(self, start: datetime, end: datetime) -> bool:
        return parse_rfc3339(self.starts_at, field_name="coverage.starts_at") <= start and end <= parse_rfc3339(self.ends_at, field_name="coverage.ends_at")


@dataclass(frozen=True)
class CorrelationConfig:
    """Versioned, bounded fixture correlation policy."""

    window_seconds: int
    sensor_pairs: tuple[tuple[str, str], ...]
    coverage: tuple[FixtureCoverage, ...]
    rule_id: str = RULE_ID

    def __post_init__(self) -> None:
        if not 1 <= self.window_seconds <= 300:
            raise CorrelationError("invalid_correlation_window")
        require_safe_id(self.rule_id, "rule_id")
        if len(self.sensor_pairs) > 64 or len(self.coverage) > 64:
            raise CorrelationError("correlation_config_limit_exceeded")
        seen_alert_sensors: set[str] = set()
        for suricata_sensor, zeek_sensor in self.sensor_pairs:
            require_safe_id(suricata_sensor, "suricata_sensor_id")
            require_safe_id(zeek_sensor, "zeek_sensor_id")
            if suricata_sensor in seen_alert_sensors:
                raise CorrelationError("duplicate_suricata_sensor_mapping")
            seen_alert_sensors.add(suricata_sensor)
        if len({item.coverage_id for item in self.coverage}) != len(self.coverage):
            raise CorrelationError("duplicate_coverage_id")

    @property
    def sha256(self) -> str:
        return sha256_bytes(canonical_json(self.as_manifest()).encode("utf-8"))

    def as_manifest(self) -> dict[str, Any]:
        return {
            "contract_version": CORRELATION_CONTRACT_VERSION,
            "coverage": [item.as_manifest() | {"sha256": item.sha256} for item in sorted(self.coverage, key=lambda item: item.coverage_id)],
            "rule_id": self.rule_id,
            "sensor_pairs": [[left, right] for left, right in sorted(self.sensor_pairs)],
            "window_seconds": self.window_seconds,
        }

    def zeek_sensor_for(self, suricata_sensor: str) -> str | None:
        return dict(self.sensor_pairs).get(suricata_sensor)

    def coverage_for(self, sensor_id: str, start: datetime, end: datetime) -> tuple[FixtureCoverage, ...]:
        return tuple(sorted((item for item in self.coverage if item.zeek_sensor_id == sensor_id and item.covers(start, end)), key=lambda item: item.coverage_id))


@dataclass(frozen=True)
class FixtureSessionCoverage:
    """A synthetic assertion that session bindings are complete for one window."""

    coverage_id: str
    mikrotik_sensor_id: str
    starts_at: str
    ends_at: str
    fixture_scope_sha256: str

    def __post_init__(self) -> None:
        require_safe_id(self.coverage_id, "session_coverage_id")
        require_safe_id(self.mikrotik_sensor_id, "mikrotik_sensor_id")
        require_sha256(self.fixture_scope_sha256, "session_fixture_scope_sha256")
        if parse_rfc3339(self.ends_at, field_name="session_coverage.ends_at") < parse_rfc3339(self.starts_at, field_name="session_coverage.starts_at"):
            raise CorrelationError("invalid_session_coverage_window")

    @property
    def sha256(self) -> str:
        return sha256_bytes(canonical_json(self.as_manifest()).encode("utf-8"))

    def as_manifest(self) -> dict[str, str]:
        return {
            "coverage_id": self.coverage_id,
            "ends_at": format_rfc3339(parse_rfc3339(self.ends_at, field_name="session_coverage.ends_at")),
            "fixture_scope_sha256": self.fixture_scope_sha256,
            "format_profile": MIKROTIK_SESSION_FORMAT_PROFILE,
            "source": "mikrotik",
            "starts_at": format_rfc3339(parse_rfc3339(self.starts_at, field_name="session_coverage.starts_at")),
            "mikrotik_sensor_id": self.mikrotik_sensor_id,
        }

    def covers(self, start: datetime, end: datetime) -> bool:
        return parse_rfc3339(self.starts_at, field_name="session_coverage.starts_at") <= start and end <= parse_rfc3339(self.ends_at, field_name="session_coverage.ends_at")


@dataclass(frozen=True)
class SessionCorrelationConfig:
    """Bounded, explicit mapping from alert sensors to session-binding sensors."""

    sensor_pairs: tuple[tuple[str, str], ...]
    coverage: tuple[FixtureSessionCoverage, ...]
    rule_id: str = SESSION_RULE_ID

    def __post_init__(self) -> None:
        require_safe_id(self.rule_id, "session_rule_id")
        if len(self.sensor_pairs) > 64 or len(self.coverage) > 64:
            raise CorrelationError("session_correlation_config_limit_exceeded")
        seen_alert_sensors: set[str] = set()
        for suricata_sensor, mikrotik_sensor in self.sensor_pairs:
            require_safe_id(suricata_sensor, "suricata_sensor_id")
            require_safe_id(mikrotik_sensor, "mikrotik_sensor_id")
            if suricata_sensor in seen_alert_sensors:
                raise CorrelationError("duplicate_session_suricata_sensor_mapping")
            seen_alert_sensors.add(suricata_sensor)
        if len({item.coverage_id for item in self.coverage}) != len(self.coverage):
            raise CorrelationError("duplicate_session_coverage_id")

    @property
    def sha256(self) -> str:
        return sha256_bytes(canonical_json(self.as_manifest()).encode("utf-8"))

    def as_manifest(self) -> dict[str, Any]:
        return {
            "contract_version": SESSION_CORRELATION_CONTRACT_VERSION,
            "coverage": [item.as_manifest() | {"sha256": item.sha256} for item in sorted(self.coverage, key=lambda item: item.coverage_id)],
            "rule_id": self.rule_id,
            "sensor_pairs": [[left, right] for left, right in sorted(self.sensor_pairs)],
        }

    def mikrotik_sensor_for(self, suricata_sensor: str) -> str | None:
        return dict(self.sensor_pairs).get(suricata_sensor)

    def coverage_for(self, sensor_id: str, start: datetime, end: datetime) -> tuple[FixtureSessionCoverage, ...]:
        return tuple(sorted((item for item in self.coverage if item.mikrotik_sensor_id == sensor_id and item.covers(start, end)), key=lambda item: item.coverage_id))


@dataclass(frozen=True)
class CorrelationResult:
    """An immutable canonical derived interpretation, never a source mutation."""

    semantic_correlation_id: str
    derivation_id: str
    canonical_json: str

    def __post_init__(self) -> None:
        require_sha256(self.semantic_correlation_id, "semantic_correlation_id")
        require_sha256(self.derivation_id, "derivation_id")
        try:
            payload = json.loads(self.canonical_json)
        except json.JSONDecodeError as exc:
            raise CorrelationError("invalid_correlation_result") from exc
        if (
            not isinstance(payload, dict)
            or canonical_json(payload) != self.canonical_json
            or payload.get("correlation_id") != self.semantic_correlation_id
            or payload.get("semantic_correlation_id") != self.semantic_correlation_id
            or payload.get("derivation_id") != self.derivation_id
        ):
            raise CorrelationError("invalid_correlation_result")
        derivation_material = dict(payload)
        derivation_material.pop("derivation_id")
        if sha256_bytes(canonical_json(derivation_material).encode("utf-8")) != self.derivation_id:
            raise CorrelationError("invalid_correlation_result")
        semantic_material = dict(derivation_material)
        semantic_material.pop("source_ledger_checkpoint")
        semantic_material.pop("correlation_id")
        semantic_material.pop("semantic_correlation_id")
        if sha256_bytes(canonical_json(semantic_material).encode("utf-8")) != self.semantic_correlation_id:
            raise CorrelationError("invalid_correlation_result")

    @property
    def correlation_id(self) -> str:
        """Compatibility alias for the stable semantic correlation identity."""
        return self.semantic_correlation_id

    @property
    def payload(self) -> dict[str, Any]:
        value = json.loads(self.canonical_json)
        if not isinstance(value, dict):
            raise RuntimeError("invalid_correlation_result")
        return value

    @property
    def stage_outcome(self) -> StageOutcome:
        """A typed view of the existing traffic outcome without altering IDs."""
        payload = self.payload
        traffic = payload.get("traffic", payload)
        if not isinstance(traffic, Mapping):
            raise CorrelationError("invalid_correlation_result")
        references = [traffic["anchor_evidence_id"]]
        references.extend(item["evidence_id"] for item in traffic["candidate_evidence_refs"])
        return correlation_stage_outcome(
            CorrelationOutcome(traffic["outcome"]),
            evidence_refs=tuple(sorted(set(references))),
        )

    @property
    def session_stage_outcome(self) -> StageOutcome | None:
        """Return the separate session component as a correlation-stage outcome."""
        payload = self.payload
        session = payload.get("session_association")
        traffic = payload.get("traffic")
        if not isinstance(session, Mapping) or not isinstance(traffic, Mapping):
            return None
        anchor_id = traffic.get("anchor_evidence_id")
        candidate_ids = session.get("session_evidence_ids")
        if not isinstance(anchor_id, str) or not isinstance(candidate_ids, list) or not all(isinstance(item, str) for item in candidate_ids):
            raise CorrelationError("invalid_session_correlation_result")
        return correlation_stage_outcome(
            CorrelationOutcome(session["outcome"]),
            evidence_refs=tuple(sorted(set((anchor_id, *candidate_ids)))),
        )


def _checkpoint_manifest(checkpoint: Any) -> dict[str, Any] | None:
    if checkpoint is None:
        return None
    return {
        "byte_offset": checkpoint.byte_offset,
        "entry_hash": checkpoint.entry_hash,
        "entry_index": checkpoint.entry_index,
        "ledger_id": checkpoint.ledger_id,
    }


def _source_reference(manifest: Mapping[str, Any]) -> dict[str, Any]:
    if manifest.get("outcome") != "accepted":
        raise CorrelationError("non_accepted_manifest")
    evidence_id = manifest.get("evidence_id")
    intake = manifest.get("intake")
    raw = manifest.get("raw")
    if not isinstance(evidence_id, str) or not isinstance(intake, Mapping) or not isinstance(raw, Mapping):
        raise CorrelationError("invalid_source_manifest")
    source = intake.get("source")
    sensor_id = intake.get("sensor_id")
    clock_quality = intake.get("clock_quality")
    format_profile = intake.get("format_profile")
    event_time = manifest.get("event_time")
    raw_sha256 = raw.get("raw_sha256")
    if source not in ("suricata", "zeek", "mikrotik") or clock_quality not in ("synchronized", "unknown", "degraded"):
        raise CorrelationError("invalid_source_manifest")
    require_safe_id(evidence_id, "evidence_id")
    require_safe_id(str(sensor_id), "sensor_id")
    require_sha256(str(raw_sha256), "raw_sha256")
    payload = manifest.get("normalized_payload")
    if not isinstance(payload, Mapping):
        raise CorrelationError("invalid_source_manifest")
    expected_profile = _OBSERVATION_PROFILE_MATRIX.get((source, format_profile))
    if expected_profile is None:
        raise CorrelationError("unsupported_observation_profile")
    expected_kind, expected_adapter, expected_parser, expected_schema = expected_profile
    if (
        manifest.get("contract_version") != CONTRACT_VERSION
        or manifest.get("adapter_version") != expected_adapter
        or manifest.get("parser_version") != expected_parser
        or manifest.get("schema_version") != expected_schema
    ):
        raise CorrelationError("unsupported_observation_version")
    if payload.get("kind") != expected_kind:
        raise CorrelationError("unsupported_observation_profile")
    return {
        "adapter_version": manifest["adapter_version"],
        "clock_quality": clock_quality,
        "contract_version": manifest["contract_version"],
        "event_time": format_rfc3339(parse_rfc3339(str(event_time), field_name="event_time")),
        "evidence_id": evidence_id,
        "format_profile": format_profile,
        "normalized_payload": dict(payload),
        "parser_version": manifest["parser_version"],
        "raw_sha256": raw_sha256,
        "schema_version": manifest["schema_version"],
        "sensor_id": sensor_id,
        "source": source,
        "source_event_id": manifest.get("source_event_id"),
    }


def _network_key(reference: Mapping[str, Any]) -> tuple[str, str, str, int, int] | None:
    payload = reference["normalized_payload"]
    network = payload.get("network") if isinstance(payload, Mapping) else None
    if not isinstance(network, Mapping):
        raise CorrelationError("invalid_network_observation")
    source_ip, destination_ip, protocol = network.get("source_ip"), network.get("destination_ip"), network.get("protocol")
    try:
        source = str(ipaddress.ip_address(source_ip))
        destination = str(ipaddress.ip_address(destination_ip))
    except ValueError as exc:
        raise CorrelationError("invalid_network_observation") from exc
    if not isinstance(protocol, str) or protocol not in _NETWORK_PROTOCOLS:
        raise CorrelationError("invalid_network_observation")
    if protocol not in _PORT_BEARING_PROTOCOLS:
        return None
    source_port, destination_port = network.get("source_port"), network.get("destination_port")
    if (
        isinstance(source_port, bool)
        or isinstance(destination_port, bool)
        or not isinstance(source_port, int)
        or not isinstance(destination_port, int)
        or not 1 <= source_port <= 65_535
        or not 1 <= destination_port <= 65_535
    ):
        raise CorrelationError("invalid_network_observation")
    return source, destination, protocol, source_port, destination_port


def _source_ip(reference: Mapping[str, Any]) -> str:
    payload = reference["normalized_payload"]
    network = payload.get("network") if isinstance(payload, Mapping) else None
    if not isinstance(network, Mapping):
        raise CorrelationError("invalid_network_observation")
    try:
        return str(ipaddress.ip_address(network.get("source_ip")))
    except ValueError as exc:
        raise CorrelationError("invalid_network_observation") from exc


def _session_binding(reference: Mapping[str, Any]) -> tuple[str, datetime, datetime] | None:
    """Return owner-only session fields for internal eligibility checks only."""
    if (
        reference["source"] != "mikrotik"
        or reference["format_profile"] != MIKROTIK_SESSION_FORMAT_PROFILE
        or reference["normalized_payload"].get("kind") != "mikrotik.session_binding"
    ):
        return None
    payload = reference["normalized_payload"]
    try:
        assigned_ip = str(ipaddress.ip_address(payload.get("assigned_ip")))
    except ValueError as exc:
        raise CorrelationError("invalid_session_observation") from exc
    valid_from = parse_rfc3339(payload.get("valid_from"), field_name="session.valid_from")
    valid_until = parse_rfc3339(payload.get("valid_until"), field_name="session.valid_until")
    if valid_until < valid_from or (valid_until - valid_from).total_seconds() > MAX_SESSION_VALIDITY_SECONDS:
        raise CorrelationError("invalid_session_observation")
    return assigned_ip, valid_from, valid_until


def _intervals_intersect(left_start: datetime, left_end: datetime, right_start: datetime, right_end: datetime) -> bool:
    return left_start <= right_end and right_start <= left_end


def _coverage_scope_sha256(references: tuple[Mapping[str, Any], ...], sensor_id: str, start: datetime, end: datetime) -> str:
    """Hash exactly the supplied Zeek fixture evidence claimed as coverage."""
    material = [
        {"event_time": item["event_time"], "evidence_id": item["evidence_id"], "raw_sha256": item["raw_sha256"], "sensor_id": item["sensor_id"]}
        for item in references
        if item["source"] == "zeek" and item["sensor_id"] == sensor_id and start <= parse_rfc3339(item["event_time"], field_name="event_time") <= end
    ]
    return sha256_bytes(canonical_json(sorted(material, key=lambda item: item["evidence_id"])).encode("utf-8"))


def fixture_coverage_scope_sha256(store: FileEvidenceStore, zeek_sensor_id: str, starts_at: str, ends_at: str) -> str:
    """Build a coverage assertion from a verified fixture-store snapshot."""
    require_safe_id(zeek_sensor_id, "zeek_sensor_id")
    start = parse_rfc3339(starts_at, field_name="coverage.starts_at")
    end = parse_rfc3339(ends_at, field_name="coverage.ends_at")
    if end < start:
        raise CorrelationError("invalid_coverage_window")
    snapshot = store.verified_snapshot()
    references = tuple(_source_reference(item) for item in snapshot.manifests)
    return _coverage_scope_sha256(references, zeek_sensor_id, start, end)


def _session_coverage_scope_sha256(
    references: tuple[Mapping[str, Any], ...], sensor_id: str, start: datetime, end: datetime,
) -> str:
    """Hash every declared session binding whose validity intersects coverage."""
    material: list[dict[str, str]] = []
    for item in references:
        binding = _session_binding(item)
        if binding is None or item["sensor_id"] != sensor_id:
            continue
        _, valid_from, valid_until = binding
        if _intervals_intersect(valid_from, valid_until, start, end):
            material.append(
                {
                    "evidence_id": item["evidence_id"],
                    "raw_sha256": item["raw_sha256"],
                    "sensor_id": item["sensor_id"],
                    "valid_from": format_rfc3339(valid_from),
                    "valid_until": format_rfc3339(valid_until),
                }
            )
    return sha256_bytes(canonical_json(sorted(material, key=lambda item: item["evidence_id"])).encode("utf-8"))


def fixture_session_coverage_scope_sha256(
    store: FileEvidenceStore, mikrotik_sensor_id: str, starts_at: str, ends_at: str,
) -> str:
    """Build a session-coverage assertion from one verified fixture snapshot."""
    require_safe_id(mikrotik_sensor_id, "mikrotik_sensor_id")
    start = parse_rfc3339(starts_at, field_name="session_coverage.starts_at")
    end = parse_rfc3339(ends_at, field_name="session_coverage.ends_at")
    if end < start:
        raise CorrelationError("invalid_session_coverage_window")
    snapshot = store.verified_snapshot()
    return _session_coverage_scope_sha256(_references_from_snapshot(snapshot), mikrotik_sensor_id, start, end)


_REFERENCE_FIELDS = (
    "adapter_version",
    "clock_quality",
    "contract_version",
    "event_time",
    "evidence_id",
    "format_profile",
    "parser_version",
    "raw_sha256",
    "schema_version",
    "sensor_id",
    "source",
    "source_event_id",
)


def _public_reference(item: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item[key] for key in _REFERENCE_FIELDS}


def _result(
    *, anchor: Mapping[str, Any], candidates: tuple[Mapping[str, Any], ...], outcome: CorrelationOutcome,
    rationale: str, config: CorrelationConfig, checkpoint: Any, coverage: tuple[FixtureCoverage, ...],
    candidate_count: int | None = None, match_basis: str | None = MATCH_BASIS,
) -> CorrelationResult:
    anchor_time = parse_rfc3339(anchor["event_time"], field_name="event_time")
    semantic_material = {
        "anchor": _public_reference(anchor),
        "anchor_evidence_id": anchor["evidence_id"],
        "candidate_count": candidate_count if candidate_count is not None else len(candidates),
        "candidate_evidence_refs": [_public_reference(item) for item in sorted(candidates, key=lambda item: item["evidence_id"])],
        "config": config.as_manifest(),
        "config_sha256": config.sha256,
        "contract_version": CORRELATION_CONTRACT_VERSION,
        "coverage": [{"coverage_id": item.coverage_id, "sha256": item.sha256} for item in coverage],
        "match_basis": match_basis,
        "outcome": outcome.value,
        "rationale": rationale,
        "rule_id": config.rule_id,
        "time_window": {
            "end": format_rfc3339(anchor_time + timedelta(seconds=config.window_seconds)),
            "inclusive": True,
            "start": format_rfc3339(anchor_time - timedelta(seconds=config.window_seconds)),
            "uses": "event_time",
            "window_seconds": config.window_seconds,
        },
    }
    semantic_encoded = canonical_json(semantic_material)
    if len(semantic_encoded.encode("utf-8")) > MAX_RESULT_BYTES:
        raise CorrelationError("correlation_result_size_exceeded")
    semantic_correlation_id = sha256_bytes(semantic_encoded.encode("utf-8"))
    derivation_material = dict(semantic_material)
    derivation_material["correlation_id"] = semantic_correlation_id
    derivation_material["semantic_correlation_id"] = semantic_correlation_id
    derivation_material["source_ledger_checkpoint"] = _checkpoint_manifest(checkpoint)
    encoded = canonical_json(derivation_material)
    if len(encoded.encode("utf-8")) > MAX_RESULT_BYTES:
        raise CorrelationError("correlation_result_size_exceeded")
    derivation_id = sha256_bytes(encoded.encode("utf-8"))
    payload = dict(derivation_material)
    payload["derivation_id"] = derivation_id
    return CorrelationResult(semantic_correlation_id, derivation_id, canonical_json(payload))


def _references_from_snapshot(snapshot: VerifiedEvidenceSnapshot) -> tuple[dict[str, Any], ...]:
    if len(snapshot.manifests) > MAX_ACCEPTED_MANIFESTS:
        raise CorrelationError("accepted_manifest_limit_exceeded")
    references = tuple(_source_reference(item) for item in snapshot.manifests)
    if len({item["evidence_id"] for item in references}) != len(references):
        raise CorrelationError("duplicate_evidence_id")
    return references


def _correlate_snapshot(
    snapshot: VerifiedEvidenceSnapshot, config: CorrelationConfig, references: tuple[Mapping[str, Any], ...],
) -> tuple[CorrelationResult, ...]:
    """Derive Phase 2a results from exactly one already-verified snapshot."""
    alerts = tuple(sorted((item for item in references if item["source"] == "suricata"), key=lambda item: item["evidence_id"]))
    if len(alerts) > MAX_ALERT_ANCHORS:
        raise CorrelationError("alert_anchor_limit_exceeded")
    results: list[CorrelationResult] = []
    for anchor in alerts:
        if anchor["clock_quality"] != "synchronized":
            results.append(_result(anchor=anchor, candidates=(), outcome=CorrelationOutcome.INSUFFICIENT_EVIDENCE, rationale="anchor_clock_quality_not_synchronized", config=config, checkpoint=snapshot.checkpoint, coverage=()))
            continue
        target_sensor = config.zeek_sensor_for(anchor["sensor_id"])
        if target_sensor is None:
            results.append(_result(anchor=anchor, candidates=(), outcome=CorrelationOutcome.INSUFFICIENT_EVIDENCE, rationale="no_configured_zeek_sensor_mapping", config=config, checkpoint=snapshot.checkpoint, coverage=()))
            continue
        anchor_time = parse_rfc3339(anchor["event_time"], field_name="event_time")
        start, end = anchor_time - timedelta(seconds=config.window_seconds), anchor_time + timedelta(seconds=config.window_seconds)
        declared_coverage = config.coverage_for(target_sensor, start, end)
        coverage = tuple(item for item in declared_coverage if item.fixture_scope_sha256 == _coverage_scope_sha256(references, target_sensor, parse_rfc3339(item.starts_at, field_name="coverage.starts_at"), parse_rfc3339(item.ends_at, field_name="coverage.ends_at")))
        eligible = [item for item in references if item["source"] == "zeek" and item["sensor_id"] == target_sensor and item["clock_quality"] == "synchronized"]
        anchor_key = _network_key(anchor)
        if anchor_key is None:
            results.append(_result(anchor=anchor, candidates=(), outcome=CorrelationOutcome.INSUFFICIENT_EVIDENCE, rationale="protocol_not_supported_by_five_tuple_correlation", config=config, checkpoint=snapshot.checkpoint, coverage=(), match_basis=None))
            continue
        candidates = tuple(sorted((item for item in eligible if _network_key(item) == anchor_key and start <= parse_rfc3339(item["event_time"], field_name="event_time") <= end), key=lambda item: item["evidence_id"]))
        # A degraded/unknown Zeek clock cannot safely establish that a matching
        # observation is outside the event-time window.  Once its reported
        # event time falls in verified, declared-complete fixture coverage, it
        # makes a no-match conclusion unsafe even when it appears just outside
        # the nominal window.
        unsynchronized_matches = tuple(
            item
            for item in references
            if item["source"] == "zeek"
            and item["sensor_id"] == target_sensor
            and item["clock_quality"] != "synchronized"
            and _network_key(item) == anchor_key
            and any(
                parse_rfc3339(coverage_item.starts_at, field_name="coverage.starts_at")
                <= parse_rfc3339(item["event_time"], field_name="event_time")
                <= parse_rfc3339(coverage_item.ends_at, field_name="coverage.ends_at")
                for coverage_item in coverage
            )
        )
        if unsynchronized_matches:
            results.append(_result(anchor=anchor, candidates=unsynchronized_matches, outcome=CorrelationOutcome.INSUFFICIENT_EVIDENCE, rationale="matching_zeek_observation_clock_quality_not_synchronized", config=config, checkpoint=snapshot.checkpoint, coverage=coverage))
            continue
        if len(candidates) > MAX_CANDIDATES_PER_ANCHOR:
            results.append(_result(anchor=anchor, candidates=(), outcome=CorrelationOutcome.INSUFFICIENT_EVIDENCE, rationale="candidate_limit_exceeded", config=config, checkpoint=snapshot.checkpoint, coverage=coverage, candidate_count=len(candidates)))
        elif len(candidates) == 1:
            results.append(_result(anchor=anchor, candidates=candidates, outcome=CorrelationOutcome.PROBABLE_MATCH, rationale="one supplied Zeek observation shares the configured five-tuple and inclusive event-time window; this is not causation", config=config, checkpoint=snapshot.checkpoint, coverage=coverage))
        elif candidates:
            results.append(_result(anchor=anchor, candidates=candidates, outcome=CorrelationOutcome.AMBIGUOUS, rationale="multiple supplied Zeek observations share the configured five-tuple and inclusive event-time window; none is preferred", config=config, checkpoint=snapshot.checkpoint, coverage=coverage))
        elif coverage:
            results.append(_result(anchor=anchor, candidates=(), outcome=CorrelationOutcome.NO_MATCH, rationale="no matching eligible observation in the supplied, declared-complete fixture coverage", config=config, checkpoint=snapshot.checkpoint, coverage=coverage))
        elif declared_coverage:
            results.append(_result(anchor=anchor, candidates=(), outcome=CorrelationOutcome.INSUFFICIENT_EVIDENCE, rationale="fixture_coverage_scope_hash_mismatch", config=config, checkpoint=snapshot.checkpoint, coverage=()))
        else:
            results.append(_result(anchor=anchor, candidates=(), outcome=CorrelationOutcome.INSUFFICIENT_EVIDENCE, rationale="no matching observation and no declared-complete fixture coverage for the full correlation window", config=config, checkpoint=snapshot.checkpoint, coverage=()))
    return tuple(results)


def correlate(store: FileEvidenceStore, config: CorrelationConfig) -> tuple[CorrelationResult, ...]:
    """Correlate one verified fixture snapshot without reading raw telemetry."""
    if not isinstance(store, FileEvidenceStore):
        raise TypeError("store_must_be_FileEvidenceStore")
    snapshot: VerifiedEvidenceSnapshot = store.verified_snapshot()
    return _correlate_snapshot(snapshot, config, _references_from_snapshot(snapshot))


def _traffic_component(result: CorrelationResult) -> dict[str, Any]:
    payload = result.payload
    return {
        "anchor_evidence_id": payload["anchor_evidence_id"],
        "candidate_count": payload["candidate_count"],
        "candidate_evidence_refs": payload["candidate_evidence_refs"],
        "match_basis": payload["match_basis"],
        "outcome": payload["outcome"],
        "rationale": payload["rationale"],
        "semantic_correlation_id": result.semantic_correlation_id,
    }


def _session_component(
    *, anchor: Mapping[str, Any], references: tuple[Mapping[str, Any], ...], traffic_config: CorrelationConfig,
    session_config: SessionCorrelationConfig,
) -> dict[str, Any]:
    """Produce a provisional session component without exposing opaque identity fields."""
    base = {
        "candidate_count": 0,
        "coverage": [],
        "session_evidence_ids": [],
        "time_policy": "suricata_anchor_event_time_inclusive_session_validity_interval",
    }
    if anchor["clock_quality"] != "synchronized":
        return base | {"outcome": CorrelationOutcome.INSUFFICIENT_EVIDENCE.value, "rationale": "anchor_clock_quality_not_synchronized"}
    target_sensor = session_config.mikrotik_sensor_for(anchor["sensor_id"])
    if target_sensor is None:
        return base | {"outcome": CorrelationOutcome.INSUFFICIENT_EVIDENCE.value, "rationale": "no_configured_mikrotik_session_sensor_mapping"}
    anchor_time = parse_rfc3339(anchor["event_time"], field_name="event_time")
    start = anchor_time - timedelta(seconds=traffic_config.window_seconds)
    end = anchor_time + timedelta(seconds=traffic_config.window_seconds)
    declared_coverage = session_config.coverage_for(target_sensor, start, end)
    coverage = tuple(
        item
        for item in declared_coverage
        if item.fixture_scope_sha256
        == _session_coverage_scope_sha256(
            references,
            target_sensor,
            parse_rfc3339(item.starts_at, field_name="session_coverage.starts_at"),
            parse_rfc3339(item.ends_at, field_name="session_coverage.ends_at"),
        )
    )
    coverage_refs = [{"coverage_id": item.coverage_id, "sha256": item.sha256} for item in coverage]
    base["coverage"] = coverage_refs
    source_ip = _source_ip(anchor)
    session_records = [
        (item, binding)
        for item in references
        if item["sensor_id"] == target_sensor
        for binding in (_session_binding(item),)
        if binding is not None
    ]
    unsynchronized = tuple(
        item
        for item, (assigned_ip, valid_from, valid_until) in session_records
        if item["clock_quality"] != "synchronized"
        and assigned_ip == source_ip
        and (
            valid_from <= anchor_time <= valid_until
            or any(
                _intervals_intersect(
                    valid_from,
                    valid_until,
                    parse_rfc3339(coverage_item.starts_at, field_name="session_coverage.starts_at"),
                    parse_rfc3339(coverage_item.ends_at, field_name="session_coverage.ends_at"),
                )
                for coverage_item in coverage
            )
        )
    )
    if unsynchronized:
        return base | {
            "outcome": CorrelationOutcome.INSUFFICIENT_EVIDENCE.value,
            "rationale": "matching_mikrotik_session_clock_quality_not_synchronized",
        }
    candidates = tuple(
        sorted(
            (
                item
                for item, (assigned_ip, valid_from, valid_until) in session_records
                if item["clock_quality"] == "synchronized" and assigned_ip == source_ip and valid_from <= anchor_time <= valid_until
            ),
            key=lambda item: item["evidence_id"],
        )
    )
    if len(candidates) > MAX_SESSION_CANDIDATES_PER_ANCHOR:
        return base | {
            "candidate_count": len(candidates),
            "outcome": CorrelationOutcome.INSUFFICIENT_EVIDENCE.value,
            "rationale": "session_candidate_limit_exceeded",
        }
    if len(candidates) == 1:
        return base | {
            "candidate_count": 1,
            "outcome": CorrelationOutcome.PROBABLE_MATCH.value,
            "rationale": "source IP matched one supplied, retrospectively declared session binding at the anchor event time; this is not a contemporaneous subscriber attribution, ownership, or causation",
            "relationship": "source_ip_matched_declared_session_binding_at_event_time",
            "session_evidence_ids": [candidates[0]["evidence_id"]],
        }
    if candidates:
        return base | {
            "candidate_count": len(candidates),
            "outcome": CorrelationOutcome.AMBIGUOUS.value,
            "rationale": "multiple supplied declared session bindings match the source IP and anchor event time; none is preferred",
            "relationship": "source_ip_matched_declared_session_binding_at_event_time",
            "session_evidence_ids": [item["evidence_id"] for item in candidates],
        }
    if coverage:
        return base | {
            "outcome": CorrelationOutcome.NO_MATCH.value,
            "rationale": "no matching declared session binding in the supplied, verified complete fixture coverage",
        }
    if declared_coverage:
        return base | {
            "outcome": CorrelationOutcome.INSUFFICIENT_EVIDENCE.value,
            "rationale": "session_fixture_coverage_scope_hash_mismatch",
        }
    return base | {
        "outcome": CorrelationOutcome.INSUFFICIENT_EVIDENCE.value,
        "rationale": "no matching session binding and no declared-complete fixture coverage for the full traffic window",
    }


def _combined_result(
    *, traffic: CorrelationResult, session: Mapping[str, Any], traffic_config: CorrelationConfig,
    session_config: SessionCorrelationConfig, checkpoint: Any,
) -> CorrelationResult:
    semantic_material = {
        "contract_version": SESSION_CORRELATION_CONTRACT_VERSION,
        "session_association": dict(session),
        "session_config": session_config.as_manifest(),
        "session_config_sha256": session_config.sha256,
        "traffic": _traffic_component(traffic),
        "traffic_config": traffic_config.as_manifest(),
        "traffic_config_sha256": traffic_config.sha256,
    }
    semantic_encoded = canonical_json(semantic_material)
    if len(semantic_encoded.encode("utf-8")) > MAX_RESULT_BYTES:
        raise CorrelationError("session_correlation_result_size_exceeded")
    semantic_correlation_id = sha256_bytes(semantic_encoded.encode("utf-8"))
    derivation_material = dict(semantic_material)
    derivation_material["correlation_id"] = semantic_correlation_id
    derivation_material["semantic_correlation_id"] = semantic_correlation_id
    derivation_material["source_ledger_checkpoint"] = _checkpoint_manifest(checkpoint)
    encoded = canonical_json(derivation_material)
    if len(encoded.encode("utf-8")) > MAX_RESULT_BYTES:
        raise CorrelationError("session_correlation_result_size_exceeded")
    derivation_id = sha256_bytes(encoded.encode("utf-8"))
    payload = dict(derivation_material)
    payload["derivation_id"] = derivation_id
    return CorrelationResult(semantic_correlation_id, derivation_id, canonical_json(payload))


def correlate_with_session(
    store: FileEvidenceStore, traffic_config: CorrelationConfig, session_config: SessionCorrelationConfig,
) -> tuple[CorrelationResult, ...]:
    """Correlate fixture traffic and declared session bindings from one snapshot."""
    if not isinstance(store, FileEvidenceStore):
        raise TypeError("store_must_be_FileEvidenceStore")
    snapshot = store.verified_snapshot()
    return _correlate_with_session_snapshot(snapshot, traffic_config, session_config)


def _correlate_with_session_snapshot(
    snapshot: VerifiedEvidenceSnapshot, traffic_config: CorrelationConfig, session_config: SessionCorrelationConfig,
) -> tuple[CorrelationResult, ...]:
    """Derive combined results from an already-verified, immutable snapshot."""
    references = _references_from_snapshot(snapshot)
    traffic_results = _correlate_snapshot(snapshot, traffic_config, references)
    references_by_id = {item["evidence_id"]: item for item in references}
    results: list[CorrelationResult] = []
    for traffic in traffic_results:
        anchor_id = traffic.payload["anchor_evidence_id"]
        anchor = references_by_id.get(anchor_id)
        if anchor is None:
            raise CorrelationError("traffic_anchor_missing_from_snapshot")
        session = _session_component(
            anchor=anchor,
            references=references,
            traffic_config=traffic_config,
            session_config=session_config,
        )
        results.append(
            _combined_result(
                traffic=traffic,
                session=session,
                traffic_config=traffic_config,
                session_config=session_config,
                checkpoint=snapshot.checkpoint,
            )
        )
    return tuple(results)


class CorrelationResultStore:
    """Owner-only immutable files for derived results; source evidence is untouched."""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)
        if self.root.exists() and self.root.is_symlink():
            raise CorrelationError("correlation_store_root_must_not_be_symlink")
        self.root.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            self.root.chmod(0o700)

    def persist(self, result: CorrelationResult) -> str:
        data = result.canonical_json.encode("utf-8") + b"\n"
        path = self.root / f"{result.derivation_id}.json"
        if path.exists() and path.is_symlink():
            raise CorrelationError("correlation_result_must_not_be_symlink")
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise
            if path.read_bytes() != data:
                raise CorrelationError("correlation_result_collision_or_tamper")
            return "duplicate"
        try:
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("unable_to_write_correlation_result")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if os.name != "nt":
            path.chmod(0o600)
        return "persisted"
