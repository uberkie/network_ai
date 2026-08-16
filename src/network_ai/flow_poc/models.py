"""Immutable structures shared by the bounded flow-analysis POC."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


PARSER_VERSION = "flow-parser.v2"
PROFILE_VERSION = "network-ai-flow-poc.v2"
RULE_VERSION = "flow-threshold-rules.v2"
SOURCE_TRUST_STATE = "ip_allowlisted_unauthenticated"
MAX_RETAINED_FLOW_RECORDS = 100_000
MAX_CANDIDATE_FLOW_REFS = 64
MAX_CANDIDATE_BASIS_BYTES = 4_096
MAX_INPUT_SNAPSHOT_BYTES = 4_096
ANALYSIS_SNAPSHOT_VERSION = "flow-analysis-input-snapshot.v1"


class FlowDecodeError(ValueError):
    """Stable parser failure that contains no hostile flow data."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class SessionIdentity:
    exporter_ip: str
    exporter_port: int
    collector_ip: str
    collector_port: int
    protocol_version: int
    observation_domain_id: int

    @property
    def key(self) -> str:
        return "|".join(
            (
                self.exporter_ip,
                str(self.exporter_port),
                self.collector_ip,
                str(self.collector_port),
                str(self.protocol_version),
                str(self.observation_domain_id),
            )
        )


@dataclass(frozen=True)
class TemplateField:
    information_element_id: int
    length: int


@dataclass(frozen=True)
class FlowTemplate:
    session_key: str
    template_id: int
    fields: tuple[TemplateField, ...]
    fingerprint: str
    expires_at_monotonic: float
    is_options: bool = False


@dataclass(frozen=True)
class DatagramHeader:
    protocol_version: int
    sequence_number: int
    observation_domain_id: int
    export_time: datetime
    system_uptime_ms: int | None
    message_length: int


@dataclass(frozen=True)
class ParsedFlow:
    record_index: int
    template_id: int
    template_fingerprint: str
    source_ip: str
    destination_ip: str
    source_port: int | None
    destination_port: int | None
    protocol: int | None
    byte_count: int
    packet_count: int | None
    event_time: datetime
    flow_start_time: datetime | None
    flow_end_time: datetime | None
    ip_version: int | None
    direction: int | None
    uncertainty: tuple[str, ...]
    fingerprint: str


@dataclass(frozen=True)
class DecodedDatagram:
    header: DatagramHeader
    session: SessionIdentity
    flows: tuple[ParsedFlow, ...]
    next_templates: dict[tuple[str, int], FlowTemplate]
    template_fingerprints: tuple[str, ...]
    options_data_sets_ignored: int = 0
    options_data_records_ignored: int = 0


@dataclass(frozen=True)
class Candidate:
    candidate_id: str
    rule_id: str
    rule_version: str
    created_at: datetime
    window_start: datetime
    window_end: datetime
    threshold: int
    observed_value: int
    source_ip: str | None
    destination_ip: str | None
    destination_port: int | None
    protocol: int | None
    session_key: str | None
    flow_ids: tuple[str, ...]
    uncertainty: tuple[str, ...]
    identity_material_json: str
    basis_json: str
    explanation: str


def json_safe_flow(flow: ParsedFlow) -> dict[str, Any]:
    """Return only allowlisted normalized metadata; raw datagrams stay in storage."""
    return {
        "byte_count": flow.byte_count,
        "destination_ip": flow.destination_ip,
        "destination_port": flow.destination_port,
        "direction": flow.direction,
        "event_time": flow.event_time.isoformat(),
        "flow_end_time": flow.flow_end_time.isoformat() if flow.flow_end_time else None,
        "flow_start_time": flow.flow_start_time.isoformat() if flow.flow_start_time else None,
        "ip_version": flow.ip_version,
        "packet_count": flow.packet_count,
        "protocol": flow.protocol,
        "source_ip": flow.source_ip,
        "source_port": flow.source_port,
        "template_fingerprint": flow.template_fingerprint,
        "template_id": flow.template_id,
        "uncertainty": list(flow.uncertainty),
    }
