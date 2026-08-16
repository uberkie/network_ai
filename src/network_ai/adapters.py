"""Allowlisted adapters for the three synthetic Phase 1 telemetry profiles."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import ipaddress
from typing import Any, Mapping

from .contracts import (
    EvidenceEnvelope,
    ID_RE,
    IntakeContext,
    MIKROTIK_SESSION_FORMAT_PROFILE,
    SourceType,
    ValidationError,
    canonical_json,
    format_rfc3339,
    parse_rfc3339,
    semantic_json_sha256,
    sha256_bytes,
)


SUPPORTED_PROFILES = {
    SourceType.SURICATA: frozenset(("suricata-eve-alert.v1",)),
    SourceType.ZEEK: frozenset(("zeek-json-conn.v1",)),
    SourceType.MIKROTIK: frozenset(("mikrotik-telemetry-allowlist.v1", MIKROTIK_SESSION_FORMAT_PROFILE)),
}
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_ZEEK_MIN = datetime(2000, 1, 1, tzinfo=timezone.utc)
_ZEEK_MAX = datetime(2100, 1, 1, tzinfo=timezone.utc)
_NETWORK_PROTOCOLS = frozenset(("TCP", "UDP", "ICMP", "ICMPV6", "SCTP"))
_PORT_BEARING_PROTOCOLS = frozenset(("TCP", "UDP", "SCTP"))
_MIKROTIK_TELEMETRY_FORMAT_PROFILE = "mikrotik-telemetry-allowlist.v1"
_SESSION_FIELDS = frozenset(("assigned_ip", "observed_at", "session_ref", "subscriber_ref", "valid_from", "valid_until"))
_MAX_SESSION_VALIDITY = timedelta(days=31)
_MAX_SESSION_OBSERVED_SKEW = timedelta(minutes=5)


def _required_string(record: Mapping[str, Any], field: str) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value or len(value) > 4_096:
        raise ValidationError("missing_or_invalid_required_field", field)
    return value


def _optional_string(record: Mapping[str, Any], field: str) -> str | None:
    value = record.get(field)
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > 128:
        raise ValidationError("invalid_source_event_id", field)
    return value


def _required_int(record: Mapping[str, Any], field: str) -> int:
    value = record.get(field)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError("missing_or_invalid_required_field", field)
    return value


def _required_ip(record: Mapping[str, Any], field: str) -> str:
    value = _required_string(record, field)
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValidationError("invalid_network_address", field) from exc


def _required_protocol(record: Mapping[str, Any], field: str) -> str:
    value = _required_string(record, field).upper()
    if value not in _NETWORK_PROTOCOLS:
        raise ValidationError("invalid_network_protocol", field)
    return value


def _required_network_port(record: Mapping[str, Any], field: str) -> int:
    value = record.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65_535:
        raise ValidationError("invalid_network_port", field)
    return value


def _normalized_network(
    record: Mapping[str, Any], *, source_ip_field: str, destination_ip_field: str,
    source_port_field: str, destination_port_field: str,
) -> dict[str, Any]:
    protocol = _required_protocol(record, "proto")
    network: dict[str, Any] = {
        "destination_ip": _required_ip(record, destination_ip_field),
        "protocol": protocol,
        "source_ip": _required_ip(record, source_ip_field),
    }
    if protocol in _PORT_BEARING_PROTOCOLS:
        network["destination_port"] = _required_network_port(record, destination_port_field)
        network["source_port"] = _required_network_port(record, source_port_field)
    elif source_port_field in record or destination_port_field in record:
        raise ValidationError("invalid_network_port_for_protocol")
    return network


def _required_session_ref(record: Mapping[str, Any], field: str) -> str:
    value = _required_string(record, field)
    if not ID_RE.fullmatch(value):
        raise ValidationError("invalid_session_reference", field)
    return value


def _parse_zeek_time(value: Any) -> str:
    if isinstance(value, str):
        return format_rfc3339(parse_rfc3339(value, field_name="ts"))
    if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
        raise ValidationError("missing_or_invalid_required_field", "ts")
    seconds = Decimal(value)
    scaled_microseconds = seconds * Decimal(1_000_000)
    if scaled_microseconds != scaled_microseconds.to_integral_value():
        raise ValidationError("zeek_timestamp_precision_exceeded")
    try:
        timestamp = _EPOCH + timedelta(microseconds=int(scaled_microseconds))
    except OverflowError as exc:
        raise ValidationError("invalid_timestamp", "ts") from exc
    if not (_ZEEK_MIN <= timestamp <= _ZEEK_MAX):
        raise ValidationError("zeek_timestamp_out_of_range")
    return format_rfc3339(timestamp)


def _adapt_suricata(record: Mapping[str, Any]) -> tuple[str, str | None, dict[str, Any]]:
    if record.get("event_type") != "alert":
        raise ValidationError("unsupported_suricata_event_type")
    alert = record.get("alert")
    if not isinstance(alert, Mapping):
        raise ValidationError("missing_or_invalid_required_field", "alert")
    signature_id = _required_int(alert, "signature_id")
    severity = _required_int(alert, "severity")
    if severity < 1 or severity > 4:
        raise ValidationError("invalid_suricata_severity")
    event_time = format_rfc3339(parse_rfc3339(_required_string(record, "timestamp"), field_name="timestamp"))
    payload = {
        "alert": {
            "severity": severity,
            "signature": _required_string(alert, "signature"),
            "signature_id": signature_id,
        },
        "kind": "suricata.alert",
        "network": _normalized_network(
            record,
            source_ip_field="src_ip",
            destination_ip_field="dest_ip",
            source_port_field="src_port",
            destination_port_field="dest_port",
        ),
    }
    return event_time, _optional_string(record, "event_id"), payload


def _adapt_zeek(record: Mapping[str, Any]) -> tuple[str, str | None, dict[str, Any]]:
    event_time = _parse_zeek_time(record.get("ts"))
    if record.get("_path") != "conn":
        raise ValidationError("unsupported_zeek_log_type")
    payload: dict[str, Any] = {
        "kind": "zeek.conn",
        "network": _normalized_network(
            record,
            source_ip_field="id.orig_h",
            destination_ip_field="id.resp_h",
            source_port_field="id.orig_p",
            destination_port_field="id.resp_p",
        ),
        "uid": _required_string(record, "uid"),
    }
    for field in ("conn_state", "service"):
        value = record.get(field)
        if value is not None:
            if not isinstance(value, str) or len(value) > 128:
                raise ValidationError("invalid_allowlisted_field", field)
            payload[field] = value
    return event_time, payload["uid"], payload


def _adapt_mikrotik(record: Mapping[str, Any]) -> tuple[str, str | None, dict[str, Any]]:
    allowed_top_level = {
        "board_name",
        "collected_at",
        "identity",
        "interfaces",
        "routeros_version",
        "snapshot_id",
        "uptime_seconds",
    }
    unknown = set(record) - allowed_top_level
    if unknown:
        raise ValidationError("forbidden_mikrotik_field")
    event_time = format_rfc3339(
        parse_rfc3339(_required_string(record, "collected_at"), field_name="collected_at")
    )
    interfaces = record.get("interfaces")
    if not isinstance(interfaces, list) or not interfaces or len(interfaces) > 128:
        raise ValidationError("missing_or_invalid_required_field", "interfaces")
    normalized_interfaces: list[dict[str, Any]] = []
    allowed_interface_fields = {"name", "running", "rx_bytes", "tx_bytes"}
    for interface in interfaces:
        if not isinstance(interface, Mapping) or set(interface) - allowed_interface_fields:
            raise ValidationError("forbidden_mikrotik_field")
        running = interface.get("running")
        if not isinstance(running, bool):
            raise ValidationError("missing_or_invalid_required_field", "interfaces.running")
        normalized_interfaces.append(
            {
                "name": _required_string(interface, "name"),
                "running": running,
                "rx_bytes": _required_int(interface, "rx_bytes"),
                "tx_bytes": _required_int(interface, "tx_bytes"),
            }
        )
    payload: dict[str, Any] = {
        "identity": _required_string(record, "identity"),
        "interfaces": normalized_interfaces,
        "kind": "mikrotik.telemetry",
        "routeros_version": _required_string(record, "routeros_version"),
    }
    for field in ("board_name",):
        if field in record:
            payload[field] = _required_string(record, field)
    if "uptime_seconds" in record:
        payload["uptime_seconds"] = _required_int(record, "uptime_seconds")
    return event_time, _optional_string(record, "snapshot_id"), payload


def _adapt_mikrotik_session(context: IntakeContext, record: Mapping[str, Any]) -> tuple[str, str | None, dict[str, Any]]:
    if set(record) != _SESSION_FIELDS:
        raise ValidationError("unsupported_mikrotik_session_field")
    observed_at = format_rfc3339(parse_rfc3339(_required_string(record, "observed_at"), field_name="observed_at"))
    valid_from = format_rfc3339(parse_rfc3339(_required_string(record, "valid_from"), field_name="valid_from"))
    valid_until = format_rfc3339(parse_rfc3339(_required_string(record, "valid_until"), field_name="valid_until"))
    observed = parse_rfc3339(observed_at, field_name="observed_at")
    starts = parse_rfc3339(valid_from, field_name="valid_from")
    ends = parse_rfc3339(valid_until, field_name="valid_until")
    trusted_observed = parse_rfc3339(context.observed_at, field_name="intake.observed_at")
    if not starts <= observed <= ends:
        raise ValidationError("session_observed_at_outside_validity_interval")
    if ends - starts > _MAX_SESSION_VALIDITY:
        raise ValidationError("session_validity_interval_exceeded")
    if abs(observed - trusted_observed) > _MAX_SESSION_OBSERVED_SKEW:
        raise ValidationError("session_observed_at_outside_intake_skew")
    payload = {
        "assigned_ip": _required_ip(record, "assigned_ip"),
        "kind": "mikrotik.session_binding",
        "session_ref": _required_session_ref(record, "session_ref"),
        "subscriber_ref": _required_session_ref(record, "subscriber_ref"),
        "valid_from": valid_from,
        "valid_until": valid_until,
    }
    # The opaque session reference remains owner-only normalized source evidence.
    # It is deliberately not used as a public source_event_id.
    return observed_at, None, payload


def adapt_record(context: IntakeContext, record: Mapping[str, Any]) -> tuple[str, str | None, dict[str, Any]]:
    if context.format_profile not in SUPPORTED_PROFILES[context.source]:
        raise ValidationError("unsupported_format_profile")
    if context.source is SourceType.SURICATA:
        return _adapt_suricata(record)
    if context.source is SourceType.ZEEK:
        return _adapt_zeek(record)
    if context.source is SourceType.MIKROTIK:
        if context.format_profile == _MIKROTIK_TELEMETRY_FORMAT_PROFILE:
            return _adapt_mikrotik(record)
        if context.format_profile == MIKROTIK_SESSION_FORMAT_PROFILE:
            return _adapt_mikrotik_session(context, record)
    raise ValidationError("unsupported_source")


def create_envelope(context: IntakeContext, raw: bytes, parsed: Mapping[str, Any]) -> EvidenceEnvelope:
    event_time, source_event_id, normalized = adapt_record(context, parsed)
    raw_sha256 = sha256_bytes(raw)
    evidence_material = "\0".join(
        (context.source.value, context.sensor_id, context.delivery_id, raw_sha256)
    ).encode("utf-8")
    evidence_id = sha256_bytes(evidence_material)
    uncertainty = (
        "source-clock-quality-unknown"
        if context.clock_quality.value == "unknown"
        else "source-clock-quality-degraded"
        if context.clock_quality.value == "degraded"
        else None
    )
    return EvidenceEnvelope(
        evidence_id=evidence_id,
        context=context,
        raw_sha256=raw_sha256,
        canonical_sha256=semantic_json_sha256(parsed),
        raw_size_bytes=len(raw),
        event_time=event_time,
        source_event_id=source_event_id,
        normalized_payload_json=canonical_json(normalized),
        uncertainty=uncertainty,
    )
