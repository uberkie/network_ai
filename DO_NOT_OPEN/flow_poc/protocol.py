"""Strict parser for a deliberately narrow NetFlow v9/IPFIX POC profile."""

from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import struct
import time
from typing import Any, Mapping

from network_ai.contracts import canonical_json

from .models import (
    DatagramHeader,
    DecodedDatagram,
    FlowDecodeError,
    FlowTemplate,
    ParsedFlow,
    SessionIdentity,
    TemplateField,
)


MAX_DATAGRAM_BYTES = 65_535
MAX_SETS_PER_DATAGRAM = 64
MAX_TEMPLATES_PER_DATAGRAM = 16
MAX_FIELDS_PER_TEMPLATE = 32
MAX_RECORDS_PER_DATAGRAM = 1_000
MAX_GLOBAL_TEMPLATES = 512
MAX_SESSION_TEMPLATES = 32
TEMPLATE_TTL_SECONDS = 600

NETFLOW_V9_HEADER_LENGTH = 20
IPFIX_HEADER_LENGTH = 16

# Information Elements retained by the POC. All lengths are exact except
# reduced-size counters, which remain unsigned integers of one to eight bytes.
# Other standard fixed-length fields are deliberately skipped: MikroTik v9
# templates commonly add fields such as ToS, TCP flags, masks and interfaces.
# They are needed to locate record boundaries but are neither persisted nor
# exposed by this deliberately minimal evidence profile.
_IE_LENGTHS: dict[int, tuple[int, ...]] = {
    1: tuple(range(1, 9)),  # octetDeltaCount
    2: tuple(range(1, 9)),  # packetDeltaCount
    4: (1,),  # protocolIdentifier
    7: (2,),  # sourceTransportPort
    8: (4,),  # sourceIPv4Address
    11: (2,),  # destinationTransportPort
    12: (4,),  # destinationIPv4Address
    21: (4,),  # flowEndSysUpTime (NetFlow v9 only)
    22: (4,),  # flowStartSysUpTime (NetFlow v9 only)
    27: (16,),  # sourceIPv6Address
    28: (16,),  # destinationIPv6Address
    60: (1,),  # ipVersion
    61: (1,),  # flowDirection
    152: (8,),  # flowStartMilliseconds
    153: (8,),  # flowEndMilliseconds
}


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _utc_from_seconds(value: int) -> datetime:
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise FlowDecodeError("invalid_export_time") from exc


def _utc_from_milliseconds(value: int) -> datetime:
    try:
        return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=value)
    except OverflowError as exc:
        raise FlowDecodeError("invalid_flow_timestamp") from exc


def inspect_header(raw: bytes) -> DatagramHeader:
    """Validate only a message header; no template/cache state is changed."""
    if not isinstance(raw, bytes) or len(raw) < 2 or len(raw) > MAX_DATAGRAM_BYTES:
        raise FlowDecodeError("invalid_datagram_size")
    version = struct.unpack_from("!H", raw, 0)[0]
    if version == 9:
        if len(raw) < NETFLOW_V9_HEADER_LENGTH:
            raise FlowDecodeError("short_netflow_v9_header")
        _, _count, uptime, export_seconds, sequence, source_id = struct.unpack_from("!HHIIII", raw, 0)
        return DatagramHeader(9, sequence, source_id, _utc_from_seconds(export_seconds), uptime, len(raw))
    if version == 10:
        if len(raw) < IPFIX_HEADER_LENGTH:
            raise FlowDecodeError("short_ipfix_header")
        _, message_length, export_seconds, sequence, domain_id = struct.unpack_from("!HHIII", raw, 0)
        if message_length != len(raw):
            raise FlowDecodeError("ipfix_declared_length_mismatch")
        return DatagramHeader(10, sequence, domain_id, _utc_from_seconds(export_seconds), None, message_length)
    raise FlowDecodeError("unsupported_flow_protocol_version")


class TemplateCache:
    """Bounded, per-process template cache. It is intentionally empty on restart."""

    def __init__(self) -> None:
        self._templates: OrderedDict[tuple[str, int], FlowTemplate] = OrderedDict()

    def snapshot(self, now_monotonic: float | None = None) -> dict[tuple[str, int], FlowTemplate]:
        now = time.monotonic() if now_monotonic is None else now_monotonic
        return {
            key: template
            for key, template in self._templates.items()
            if template.expires_at_monotonic > now
        }

    def invalidate_session(self, session_key: str) -> None:
        self._templates = OrderedDict(
            (key, template) for key, template in self._templates.items() if template.session_key != session_key
        )

    def replace(self, templates: Mapping[tuple[str, int], FlowTemplate], now_monotonic: float | None = None) -> None:
        now = time.monotonic() if now_monotonic is None else now_monotonic
        retained = OrderedDict(
            (key, value) for key, value in templates.items() if value.expires_at_monotonic > now
        )
        if len(retained) > MAX_GLOBAL_TEMPLATES:
            raise FlowDecodeError("template_cache_global_limit")
        session_counts: dict[str, int] = {}
        for template in retained.values():
            session_counts[template.session_key] = session_counts.get(template.session_key, 0) + 1
        if any(count > MAX_SESSION_TEMPLATES for count in session_counts.values()):
            raise FlowDecodeError("template_cache_session_limit")
        self._templates = retained


def _template_fingerprint(
    version: int, template_id: int, fields: tuple[TemplateField, ...], *, is_options: bool = False,
) -> str:
    material = canonical_json(
        {
            "fields": [[field.information_element_id, field.length] for field in fields],
            "is_options": is_options,
            "template_id": template_id,
            "version": version,
        }
    ).encode("utf-8")
    return _sha256(material)


def _parse_template_fields(payload: bytes, offset: int, field_count: int) -> tuple[tuple[TemplateField, ...], int]:
    """Parse bounded fixed-width field metadata without retaining values."""
    if field_count < 1 or field_count > MAX_FIELDS_PER_TEMPLATE:
        raise FlowDecodeError("template_limit_exceeded")
    fields: list[TemplateField] = []
    for _ in range(field_count):
        if len(payload) - offset < 4:
            raise FlowDecodeError("short_template_field")
        field_type, field_length = struct.unpack_from("!HH", payload, offset)
        offset += 4
        if field_type & 0x8000:
            raise FlowDecodeError("unsupported_enterprise_information_element")
        if field_length == 65_535:
            raise FlowDecodeError("unsupported_variable_length_field")
        allowed_lengths = _IE_LENGTHS.get(field_type)
        if allowed_lengths is not None and field_length not in allowed_lengths:
            raise FlowDecodeError(f"unsupported_information_element_{field_type}_length_{field_length}")
        if allowed_lengths is None and not 1 <= field_length <= 32:
            raise FlowDecodeError(f"unsupported_unretained_information_element_{field_type}_length_{field_length}")
        fields.append(TemplateField(field_type, field_length))
    return tuple(fields), offset


def _parse_template_set(
    payload: bytes,
    *,
    header: DatagramHeader,
    session: SessionIdentity,
    templates: dict[tuple[str, int], FlowTemplate],
    now_monotonic: float,
) -> tuple[dict[tuple[str, int], FlowTemplate], tuple[str, ...]]:
    offset = 0
    created = 0
    fingerprints: list[str] = []
    next_templates = dict(templates)
    while offset < len(payload):
        tail = payload[offset:]
        if tail and len(tail) <= 3 and not any(tail):
            break
        if len(payload) - offset < 4:
            raise FlowDecodeError("short_template_record")
        template_id, field_count = struct.unpack_from("!HH", payload, offset)
        offset += 4
        if template_id < 256:
            raise FlowDecodeError("invalid_template_id")
        if field_count == 0:
            next_templates.pop((session.key, template_id), None)
            continue
        created += 1
        if created > MAX_TEMPLATES_PER_DATAGRAM:
            raise FlowDecodeError("template_limit_exceeded")
        frozen_fields, offset = _parse_template_fields(payload, offset, field_count)
        existing = next_templates.get((session.key, template_id))
        if existing is not None and existing.is_options:
            raise FlowDecodeError("template_type_collision")
        fingerprint = _template_fingerprint(header.protocol_version, template_id, frozen_fields)
        next_templates[(session.key, template_id)] = FlowTemplate(
            session_key=session.key,
            template_id=template_id,
            fields=frozen_fields,
            fingerprint=fingerprint,
            expires_at_monotonic=now_monotonic + TEMPLATE_TTL_SECONDS,
        )
        fingerprints.append(fingerprint)
    return next_templates, tuple(fingerprints)


def _parse_options_template_set(
    payload: bytes,
    *,
    header: DatagramHeader,
    session: SessionIdentity,
    templates: dict[tuple[str, int], FlowTemplate],
    now_monotonic: float,
) -> tuple[dict[tuple[str, int], FlowTemplate], tuple[str, ...]]:
    """Cache only structurally valid options-template metadata.

    Options values are deliberately never decoded as flows. Keeping their
    fixed-width field layout lets a later options data set be identified and
    skipped without confusing it for a normal flow template.
    """
    offset = 0
    created = 0
    fingerprints: list[str] = []
    next_templates = dict(templates)
    while offset < len(payload):
        tail = payload[offset:]
        if tail and len(tail) <= 3 and not any(tail):
            break
        if header.protocol_version == 9:
            if len(payload) - offset < 6:
                raise FlowDecodeError("short_options_template_record")
            template_id, scope_length, option_length = struct.unpack_from("!HHH", payload, offset)
            offset += 6
            if scope_length % 4 or option_length % 4:
                raise FlowDecodeError("invalid_options_template_field_length")
            field_count = (scope_length + option_length) // 4
        else:
            if len(payload) - offset < 6:
                raise FlowDecodeError("short_options_template_record")
            template_id, field_count, scope_count = struct.unpack_from("!HHH", payload, offset)
            offset += 6
            if scope_count > field_count:
                raise FlowDecodeError("invalid_options_template_scope_count")
        if template_id < 256:
            raise FlowDecodeError("invalid_template_id")
        created += 1
        if created > MAX_TEMPLATES_PER_DATAGRAM:
            raise FlowDecodeError("template_limit_exceeded")
        fields, offset = _parse_template_fields(payload, offset, field_count)
        existing = next_templates.get((session.key, template_id))
        if existing is not None and not existing.is_options:
            raise FlowDecodeError("template_type_collision")
        fingerprint = _template_fingerprint(header.protocol_version, template_id, fields, is_options=True)
        next_templates[(session.key, template_id)] = FlowTemplate(
            session_key=session.key,
            template_id=template_id,
            fields=fields,
            fingerprint=fingerprint,
            expires_at_monotonic=now_monotonic + TEMPLATE_TTL_SECONDS,
            is_options=True,
        )
        fingerprints.append(fingerprint)
    if created == 0:
        raise FlowDecodeError("empty_options_template_set")
    return next_templates, tuple(fingerprints)


def _decode_field(field: TemplateField, raw: bytes) -> Any:
    ie = field.information_element_id
    if ie in (8, 12):
        return str(ipaddress.IPv4Address(raw))
    if ie in (27, 28):
        return str(ipaddress.IPv6Address(raw))
    return int.from_bytes(raw, byteorder="big", signed=False)


def _build_flow(
    values: Mapping[int, Any], template: FlowTemplate, header: DatagramHeader, record_index: int
) -> ParsedFlow:
    source_ip = values.get(8, values.get(27))
    destination_ip = values.get(12, values.get(28))
    byte_count = values.get(1)
    if not isinstance(source_ip, str) or not isinstance(destination_ip, str) or not isinstance(byte_count, int):
        raise FlowDecodeError("unsupported_flow_profile")
    flow_start: datetime | None = None
    flow_end: datetime | None = None
    if 152 in values:
        flow_start = _utc_from_milliseconds(values[152])
    elif 22 in values and header.system_uptime_ms is not None:
        flow_start = header.export_time - timedelta(milliseconds=header.system_uptime_ms - values[22])
    if 153 in values:
        flow_end = _utc_from_milliseconds(values[153])
    elif 21 in values and header.system_uptime_ms is not None:
        flow_end = header.export_time - timedelta(milliseconds=header.system_uptime_ms - values[21])
    event_time = flow_end or header.export_time
    uncertainty = ["sampling-unknown", "ip-allowlisted-unauthenticated"]
    fingerprint_material = canonical_json(
        {
            "bytes": byte_count,
            "destination": destination_ip,
            "destination_port": values.get(11),
            "event_time": event_time.isoformat(),
            "packets": values.get(2),
            "protocol": values.get(4),
            "source": source_ip,
            "source_port": values.get(7),
            "session": template.session_key,
            "template": template.fingerprint,
        }
    ).encode("utf-8")
    return ParsedFlow(
        record_index=record_index,
        template_id=template.template_id,
        template_fingerprint=template.fingerprint,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=values.get(7),
        destination_port=values.get(11),
        protocol=values.get(4),
        byte_count=byte_count,
        packet_count=values.get(2),
        event_time=event_time,
        flow_start_time=flow_start,
        flow_end_time=flow_end,
        ip_version=values.get(60),
        direction=values.get(61),
        uncertainty=tuple(uncertainty),
        fingerprint=_sha256(fingerprint_material),
    )


def _parse_data_set(
    payload: bytes,
    *,
    template: FlowTemplate,
    header: DatagramHeader,
    record_offset: int,
) -> tuple[tuple[ParsedFlow, ...], int]:
    record_length = sum(field.length for field in template.fields)
    if not record_length:
        raise FlowDecodeError("empty_template")
    remainder = len(payload) % record_length
    if remainder:
        padding = payload[-remainder:]
        if remainder > 3 or any(padding):
            raise FlowDecodeError("data_set_record_length_mismatch")
        payload = payload[:-remainder]
    records: list[ParsedFlow] = []
    for start in range(0, len(payload), record_length):
        if len(records) + record_offset >= MAX_RECORDS_PER_DATAGRAM:
            raise FlowDecodeError("record_limit_exceeded")
        raw_record = payload[start : start + record_length]
        cursor = 0
        values: dict[int, Any] = {}
        for field in template.fields:
            end = cursor + field.length
            if field.information_element_id in _IE_LENGTHS:
                values[field.information_element_id] = _decode_field(field, raw_record[cursor:end])
            cursor = end
        records.append(_build_flow(values, template, header, record_offset + len(records)))
    return tuple(records), record_offset + len(records)


def _validate_ignored_options_data_set(payload: bytes, template: FlowTemplate) -> int:
    """Validate ignored options records without exposing their metadata values."""
    record_length = sum(field.length for field in template.fields)
    if record_length < 1:
        raise FlowDecodeError("empty_options_template")
    remainder = len(payload) % record_length
    if remainder:
        padding = payload[-remainder:]
        if remainder > 3 or any(padding):
            raise FlowDecodeError("options_data_set_record_length_mismatch")
        payload = payload[:-remainder]
    record_count = len(payload) // record_length
    if record_count > MAX_RECORDS_PER_DATAGRAM:
        raise FlowDecodeError("record_limit_exceeded")
    return record_count


def decode_datagram(
    raw: bytes,
    *,
    exporter_ip: str,
    exporter_port: int,
    collector_ip: str,
    collector_port: int,
    cache: TemplateCache,
    now_monotonic: float | None = None,
    reset_session: bool = False,
) -> DecodedDatagram:
    """Decode one complete message without mutating the caller's template cache.

    Call :meth:`TemplateCache.replace` only after persistence commits.
    """
    now = time.monotonic() if now_monotonic is None else now_monotonic
    header = inspect_header(raw)
    session = SessionIdentity(
        exporter_ip=exporter_ip,
        exporter_port=exporter_port,
        collector_ip=collector_ip,
        collector_port=collector_port,
        protocol_version=header.protocol_version,
        observation_domain_id=header.observation_domain_id,
    )
    templates = cache.snapshot(now)
    if reset_session:
        # A sequence reset/conflict is evaluated against fresh template state
        # without mutating the caller's cache until persistence succeeds.
        templates = {key: template for key, template in templates.items() if template.session_key != session.key}
    start = NETFLOW_V9_HEADER_LENGTH if header.protocol_version == 9 else IPFIX_HEADER_LENGTH
    offset = start
    set_count = 0
    record_index = 0
    flows: list[ParsedFlow] = []
    fingerprints: list[str] = []
    options_data_sets_ignored = 0
    options_data_records_ignored = 0
    while offset < header.message_length:
        set_count += 1
        if set_count > MAX_SETS_PER_DATAGRAM or header.message_length - offset < 4:
            raise FlowDecodeError("set_limit_or_short_header")
        set_id, set_length = struct.unpack_from("!HH", raw, offset)
        if set_length < 4 or set_length > header.message_length - offset:
            raise FlowDecodeError("invalid_set_length")
        payload = raw[offset + 4 : offset + set_length]
        offset += set_length
        is_template = (header.protocol_version == 9 and set_id == 0) or (header.protocol_version == 10 and set_id == 2)
        is_options = (header.protocol_version == 9 and set_id == 1) or (header.protocol_version == 10 and set_id == 3)
        if is_template:
            templates, new_fingerprints = _parse_template_set(
                payload, header=header, session=session, templates=templates, now_monotonic=now
            )
            fingerprints.extend(new_fingerprints)
        elif is_options:
            templates, new_fingerprints = _parse_options_template_set(
                payload, header=header, session=session, templates=templates, now_monotonic=now
            )
            fingerprints.extend(new_fingerprints)
        elif set_id >= 256:
            template = templates.get((session.key, set_id))
            if template is None:
                raise FlowDecodeError("template_missing_or_expired")
            if template.is_options:
                # The enclosing set length was validated above, and the exact
                # session-scoped cached template identifies this as metadata.
                # Values are not decoded, persisted as flows, or analyzed.
                options_data_records_ignored += _validate_ignored_options_data_set(payload, template)
                options_data_sets_ignored += 1
                continue
            parsed, record_index = _parse_data_set(
                payload, template=template, header=header, record_offset=record_index
            )
            flows.extend(parsed)
        else:
            raise FlowDecodeError("unsupported_set_id")
    if offset != header.message_length:
        raise FlowDecodeError("message_cursor_mismatch")
    # Check cache limits before persistence. No cache state has been changed.
    TemplateCache().replace(templates, now)
    return DecodedDatagram(
        header,
        session,
        tuple(flows),
        templates,
        tuple(fingerprints),
        options_data_sets_ignored,
        options_data_records_ignored,
    )
