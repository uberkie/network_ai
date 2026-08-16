"""Synthetic binary NetFlow v9/IPFIX messages used by tests and the POC demo."""

from __future__ import annotations

import ipaddress
import struct
from typing import Iterable


FIELD_SPECS: tuple[tuple[int, int], ...] = (
    (8, 4),   # source IPv4
    (12, 4),  # destination IPv4
    (7, 2),   # source port
    (11, 2),  # destination port
    (4, 1),   # protocol
    (2, 4),   # packets
    (1, 4),   # bytes
)
TEMPLATE_ID = 256
EXPORT_SECONDS = 1_786_780_800  # synthetic 2026-08-15T00:00:00Z


def _template_set(set_id: int = 0) -> bytes:
    fields = b"".join(struct.pack("!HH", information_element, length) for information_element, length in FIELD_SPECS)
    record = struct.pack("!HH", TEMPLATE_ID, len(FIELD_SPECS)) + fields
    return struct.pack("!HH", set_id, 4 + len(record)) + record


def _record(source: str, destination: str, *, source_port: int = 50000, destination_port: int = 443, protocol: int = 6, packets: int = 10, byte_count: int = 1_024) -> bytes:
    return b"".join(
        (
            ipaddress.IPv4Address(source).packed,
            ipaddress.IPv4Address(destination).packed,
            struct.pack("!H", source_port),
            struct.pack("!H", destination_port),
            struct.pack("!B", protocol),
            struct.pack("!I", packets),
            struct.pack("!I", byte_count),
        )
    )


def _data_set(records: Iterable[bytes]) -> bytes:
    payload = b"".join(records)
    return struct.pack("!HH", TEMPLATE_ID, 4 + len(payload)) + payload


def netflow_v9_message(*, sequence: int, source_id: int = 42, include_template: bool, records: Iterable[bytes]) -> bytes:
    record_list = tuple(records)
    body = (_template_set(0) if include_template else b"") + _data_set(record_list)
    header = struct.pack("!HHIIII", 9, len(record_list), 60_000, EXPORT_SECONDS, sequence, source_id)
    return header + body


def ipfix_message(*, sequence: int, domain_id: int = 84, include_template: bool, records: Iterable[bytes]) -> bytes:
    record_list = tuple(records)
    body = (_template_set(2) if include_template else b"") + _data_set(record_list)
    header = struct.pack("!HHIII", 10, 16 + len(body), EXPORT_SECONDS + 1, sequence, domain_id)
    return header + body


def synthetic_demo_messages() -> tuple[bytes, ...]:
    fanout_records = tuple(
        _record(
            "198.51.100.10",
            f"203.0.113.{20 + index}",
            destination_port=443,
            byte_count=60 * 1024 * 1024 if index == 0 else 2_048,
        )
        for index in range(20)
    )
    ipfix_record = _record("198.51.100.50", "203.0.113.90", destination_port=53, protocol=17, byte_count=4_096)
    return (
        netflow_v9_message(sequence=1, include_template=True, records=fanout_records),
        ipfix_message(sequence=1, include_template=True, records=(ipfix_record,)),
    )
