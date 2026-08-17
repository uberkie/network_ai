"""Read-only analyst projections for already-persisted local evidence.

This module does not tail Suricata/Zeek logs, open a MikroTik API, recover a
ledger, create stores, or start a collector. Unknown or unreadable sources stay
visible as explicit limitations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from typing import Any, Mapping

from .contracts import LEDGER_VERSION, canonical_json, format_rfc3339, sha256_bytes
from .strict_json import parse_strict_json


ANALYST_CONTRACT_VERSION = "read-only-analyst.v1"
MAX_ANALYST_LEDGER_BYTES = 16 * 1024 * 1024
MAX_ANALYST_AUDIT_ENTRIES = 2_048
MAX_ANALYST_CORRELATION_FILES = 256
MAX_ANALYST_CORRELATION_BYTES = 64 * 1024
MAX_ANALYST_FLOW_ROWS = 200
MAX_ANALYST_CANDIDATE_ROWS = 50
_REDACTED_KEYS = frozenset({"session_ref", "subscriber_ref"})
_LIMITATIONS = (
    "live_suricata_reader_not_authorized",
    "live_zeek_reader_not_authorized",
    "live_mikrotik_reader_not_authorized",
    "raw_artifacts_are_not_opened",
    "correlation_is_evidence_linkage_not_identity_or_causation",
    "session_association_is_not_subscriber_attribution",
)


def _utc_now() -> str:
    return format_rfc3339(datetime.now(tz=timezone.utc))


def _empty_snapshot(*, problems: tuple[str, ...] = (), evidence_root: str | None = None, flow_root: str | None = None) -> dict[str, Any]:
    return {
        "contract_version": ANALYST_CONTRACT_VERSION,
        "correlations": [],
        "evidence": [],
        "flows": {"available": False, "candidates": [], "flow_count": 0, "rows": [], "summary": {}},
        "generated_at": _utc_now(),
        "limitations": list(_LIMITATIONS),
        "overview": {
            "accepted_count": 0,
            "alerts_by_severity": {},
            "correlation_outcomes": {},
            "quarantined_count": 0,
            "source_counts": {},
            "top_destinations": [],
            "top_protocols": [],
            "top_sources": [],
        },
        "problems": list(problems),
        "sensors": _sensor_health([], flow_available=False),
        "store": {
            "available": False,
            "entry_count": 0,
            "evidence_root": evidence_root,
            "flow_root": flow_root,
            "ledger_id": None,
        },
    }


def _sensor_health(evidence: list[dict[str, Any]], *, flow_available: bool) -> dict[str, Any]:
    last_seen: dict[str, str] = {}
    for row in evidence:
        source = row.get("source")
        event_time = row.get("event_time")
        if isinstance(source, str) and isinstance(event_time, str):
            previous = last_seen.get(source)
            if previous is None or event_time > previous:
                last_seen[source] = event_time
    return {
        "flow": {
            "live_reader": "not_authorized_here",
            "store": "available" if flow_available else "unavailable",
        },
        "mikrotik": {
            "last_evidence_at": last_seen.get("mikrotik"),
            "live_reader": "not_authorized",
        },
        "suricata": {
            "last_evidence_at": last_seen.get("suricata"),
            "live_reader": "not_authorized",
            "log_access": "unavailable",
        },
        "zeek": {
            "last_evidence_at": last_seen.get("zeek"),
            "live_reader": "not_authorized",
            "log_access": "unavailable",
        },
    }


def _ledger_material(index: int, previous_entry_hash: str | None, manifest: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "entry_index": index,
        "ledger_version": LEDGER_VERSION,
        "manifest": manifest,
        "previous_entry_hash": previous_entry_hash,
    }


def _read_ledger_metadata(path: Path) -> tuple[str | None, list[str]]:
    if not path.is_file() or path.is_symlink():
        return None, []
    try:
        metadata = parse_strict_json(path.read_bytes())
    except Exception:
        return None, ["invalid_ledger_metadata"]
    ledger_id = metadata.get("ledger_id") if isinstance(metadata, dict) else None
    if not isinstance(metadata, dict) or metadata.get("ledger_version") != LEDGER_VERSION or not isinstance(ledger_id, str):
        return None, ["invalid_ledger_metadata"]
    return ledger_id, []


def _network_view(payload: Mapping[str, Any]) -> dict[str, Any] | None:
    network = payload.get("network")
    if not isinstance(network, Mapping):
        return None
    view: dict[str, Any] = {}
    for key in ("source_ip", "destination_ip", "protocol"):
        value = network.get(key)
        if isinstance(value, str) and value:
            view[key] = value
    for key in ("source_port", "destination_port"):
        value = network.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            view[key] = value
    return view or None


def _summary(kind: str | None, payload: Mapping[str, Any], network: Mapping[str, Any] | None) -> str:
    if kind == "suricata.alert":
        alert = payload.get("alert")
        if isinstance(alert, Mapping):
            signature = alert.get("signature")
            severity = alert.get("severity")
            if isinstance(signature, str):
                return f"{signature} (severity {severity})" if severity is not None else signature
    if kind == "zeek.conn":
        parts = ["zeek conn"]
        for key in ("service", "conn_state", "uid"):
            value = payload.get(key)
            if isinstance(value, str) and value:
                parts.append(value)
        return " ".join(parts)
    if kind == "mikrotik.telemetry":
        identity = payload.get("identity")
        board = payload.get("board_name")
        if isinstance(identity, str):
            return f"mikrotik telemetry {identity}" + (f" ({board})" if isinstance(board, str) else "")
        return "mikrotik telemetry"
    if kind == "mikrotik.session_binding":
        assigned = payload.get("assigned_ip")
        if isinstance(assigned, str):
            return f"declared session binding for {assigned}"
        return "declared session binding"
    if network:
        protocol = network.get("protocol", "?")
        source = network.get("source_ip", "?")
        destination = network.get("destination_ip", "?")
        return f"{protocol} {source} -> {destination}"
    return kind or "evidence"


def _detail(kind: str | None, payload: Mapping[str, Any]) -> dict[str, Any]:
    if kind == "suricata.alert":
        alert = payload.get("alert")
        if isinstance(alert, Mapping):
            detail: dict[str, Any] = {}
            if isinstance(alert.get("signature"), str):
                detail["signature"] = alert["signature"]
            if isinstance(alert.get("signature_id"), int) and not isinstance(alert.get("signature_id"), bool):
                detail["signature_id"] = alert["signature_id"]
            if isinstance(alert.get("severity"), int) and not isinstance(alert.get("severity"), bool):
                detail["severity"] = alert["severity"]
            return detail
    if kind == "zeek.conn":
        return {
            key: payload[key]
            for key in ("uid", "service", "conn_state")
            if isinstance(payload.get(key), str)
        }
    if kind == "mikrotik.telemetry":
        detail = {
            key: payload[key]
            for key in ("identity", "board_name", "routeros_version")
            if isinstance(payload.get(key), str)
        }
        if isinstance(payload.get("uptime_seconds"), int) and not isinstance(payload.get("uptime_seconds"), bool):
            detail["uptime_seconds"] = payload["uptime_seconds"]
        interfaces = payload.get("interfaces")
        if isinstance(interfaces, list):
            cleaned: list[dict[str, Any]] = []
            for item in interfaces[:32]:
                if not isinstance(item, Mapping):
                    continue
                entry = {key: item[key] for key in ("name", "running", "rx_bytes", "tx_bytes") if key in item}
                if entry:
                    cleaned.append(entry)
            if cleaned:
                detail["interfaces"] = cleaned
        return detail
    if kind == "mikrotik.session_binding":
        detail = {}
        if isinstance(payload.get("assigned_ip"), str):
            detail["assigned_ip"] = payload["assigned_ip"]
        for key in ("valid_from", "valid_until"):
            if isinstance(payload.get(key), str):
                detail[key] = payload[key]
        return detail
    return {}


def _contains_redacted(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(key in _REDACTED_KEYS or _contains_redacted(item) for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_redacted(item) for item in value)
    return False


def _project_accepted(index: int, manifest: Mapping[str, Any]) -> dict[str, Any] | None:
    intake = manifest.get("intake")
    payload = manifest.get("normalized_payload")
    if not isinstance(intake, Mapping) or not isinstance(payload, Mapping):
        return None
    kind = payload.get("kind") if isinstance(payload.get("kind"), str) else None
    network = _network_view(payload)
    evidence_id = manifest.get("evidence_id")
    row = {
        "clock_quality": intake.get("clock_quality"),
        "detail": _detail(kind, payload),
        "event_time": manifest.get("event_time"),
        "evidence_id": evidence_id if isinstance(evidence_id, str) else None,
        "format_profile": intake.get("format_profile"),
        "ingested_at": intake.get("ingested_at"),
        "kind": kind,
        "ledger_index": index,
        "network": network,
        "observed_at": intake.get("observed_at"),
        "outcome": "accepted",
        "reason_code": "accepted",
        "row_id": f"{index}:accepted:{evidence_id}",
        "sensor_id": intake.get("sensor_id"),
        "source": intake.get("source"),
        "source_event_id": manifest.get("source_event_id"),
        "summary": _summary(kind, payload, network),
        "uncertainty": manifest.get("uncertainty"),
    }
    if _contains_redacted(row):
        return None
    return row


def _project_quarantine(index: int, manifest: Mapping[str, Any]) -> dict[str, Any] | None:
    intake = manifest.get("intake")
    quarantine = manifest.get("quarantine")
    if not isinstance(intake, Mapping) or not isinstance(quarantine, Mapping):
        return None
    code = quarantine.get("code")
    raw_sha256 = quarantine.get("raw_sha256")
    return {
        "clock_quality": intake.get("clock_quality"),
        "detail": {"quarantine_code": code} if isinstance(code, str) else {},
        "event_time": intake.get("observed_at"),
        "evidence_id": None,
        "format_profile": intake.get("format_profile"),
        "ingested_at": intake.get("ingested_at"),
        "kind": None,
        "ledger_index": index,
        "network": None,
        "observed_at": intake.get("observed_at"),
        "outcome": "quarantined",
        "reason_code": code if isinstance(code, str) else "quarantined",
        "row_id": f"{index}:quarantined:{raw_sha256}",
        "sensor_id": intake.get("sensor_id"),
        "source": intake.get("source"),
        "source_event_id": None,
        "summary": f"quarantined:{code}" if isinstance(code, str) else "quarantined",
        "uncertainty": None,
    }


def _read_ledger(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    if not path.exists():
        return [], ["ledger_unavailable"]
    if path.is_symlink() or not path.is_file():
        return [], ["ledger_unavailable"]
    try:
        size = path.stat().st_size
    except OSError:
        return [], ["ledger_unreadable"]
    if size > MAX_ANALYST_LEDGER_BYTES:
        return [], ["ledger_byte_limit_exceeded"]
    try:
        data = path.read_bytes()
    except OSError:
        return [], ["ledger_unreadable"]
    rows: list[dict[str, Any]] = []
    problems: list[str] = []
    offset = 0
    previous_entry_hash: str | None = None
    index = 0
    while offset < len(data):
        if index >= MAX_ANALYST_AUDIT_ENTRIES:
            problems.append("ledger_entry_limit_exceeded")
            break
        newline = data.find(b"\n", offset)
        if newline < 0:
            if data[offset:]:
                problems.append("invalid_ledger_tail")
            break
        line = data[offset:newline]
        offset = newline + 1
        try:
            text = line.decode("utf-8")
            full_entry = parse_strict_json(line)
        except Exception:
            problems.append("invalid_ledger_tail")
            break
        expected_fields = {"entry_hash", "entry_index", "ledger_version", "manifest", "previous_entry_hash"}
        manifest = full_entry.get("manifest") if isinstance(full_entry, dict) else None
        if (
            not isinstance(full_entry, dict)
            or set(full_entry) != expected_fields
            or canonical_json(full_entry) != text
            or not isinstance(manifest, dict)
        ):
            problems.append("invalid_ledger_tail")
            break
        material = _ledger_material(index, previous_entry_hash, manifest)
        expected_hash = sha256_bytes(canonical_json(material).encode("utf-8"))
        if (
            full_entry.get("entry_index") != index
            or full_entry.get("ledger_version") != LEDGER_VERSION
            or full_entry.get("previous_entry_hash") != previous_entry_hash
            or full_entry.get("entry_hash") != expected_hash
        ):
            problems.append("invalid_ledger_tail")
            break
        outcome = manifest.get("outcome")
        projected = _project_accepted(index, manifest) if outcome == "accepted" else _project_quarantine(index, manifest) if outcome == "quarantined" else None
        if projected is None:
            problems.append(f"unprojected_ledger_entry:{index}")
        else:
            rows.append(projected)
        previous_entry_hash = expected_hash
        index += 1
    return rows, problems


def _project_correlation(payload: Mapping[str, Any]) -> dict[str, Any] | None:
    traffic = payload.get("traffic", payload)
    if not isinstance(traffic, Mapping):
        return None
    session = payload.get("session_association") if isinstance(payload.get("session_association"), Mapping) else None
    candidate_ids: list[str] = []
    refs = traffic.get("candidate_evidence_refs")
    if isinstance(refs, list):
        for item in refs:
            if isinstance(item, Mapping) and isinstance(item.get("evidence_id"), str):
                candidate_ids.append(item["evidence_id"])
    session_ids = []
    if session is not None:
        values = session.get("session_evidence_ids")
        if isinstance(values, list):
            session_ids = [item for item in values if isinstance(item, str)]
    projected = {
        "anchor_evidence_id": traffic.get("anchor_evidence_id"),
        "derivation_id": payload.get("derivation_id"),
        "semantic_correlation_id": payload.get("semantic_correlation_id") or payload.get("correlation_id"),
        "session_evidence_ids": session_ids,
        "session_outcome": session.get("outcome") if session is not None else None,
        "session_rationale": session.get("rationale") if session is not None else None,
        "traffic_candidate_ids": candidate_ids,
        "traffic_outcome": traffic.get("outcome"),
        "traffic_rationale": traffic.get("rationale"),
    }
    if _contains_redacted(projected):
        return None
    return projected


def _read_correlations(root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    directory = root / "derived-correlation"
    if not directory.is_dir() or directory.is_symlink():
        return [], []
    rows: list[dict[str, Any]] = []
    problems: list[str] = []
    try:
        paths = sorted(path for path in directory.glob("*.json") if path.is_file() and not path.is_symlink())
    except OSError:
        return [], ["correlation_store_unreadable"]
    if len(paths) > MAX_ANALYST_CORRELATION_FILES:
        problems.append("correlation_file_limit_exceeded")
        paths = paths[:MAX_ANALYST_CORRELATION_FILES]
    for path in paths:
        try:
            raw = path.read_bytes()
        except OSError:
            problems.append("correlation_file_unreadable")
            continue
        if len(raw) > MAX_ANALYST_CORRELATION_BYTES:
            problems.append("correlation_file_too_large")
            continue
        try:
            payload = parse_strict_json(raw)
        except Exception:
            problems.append("invalid_correlation_file")
            continue
        if not isinstance(payload, dict):
            problems.append("invalid_correlation_file")
            continue
        projected = _project_correlation(payload)
        if projected is None:
            problems.append("unprojected_correlation_file")
            continue
        rows.append(projected)
    rows.sort(key=lambda item: str(item.get("semantic_correlation_id") or ""))
    return rows, problems


def _read_flows(root: Path | None) -> tuple[dict[str, Any], list[str]]:
    empty = {"available": False, "candidates": [], "flow_count": 0, "rows": [], "summary": {}}
    if root is None:
        return empty, []
    if root.exists() and root.is_symlink():
        return empty, ["flow_store_must_not_be_symlink"]
    database = root / "flow-poc.sqlite3"
    if not database.is_file() or database.is_symlink():
        return empty, []
    try:
        connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    except sqlite3.Error:
        return empty, ["flow_store_unreadable"]
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        flow_count = int(connection.execute("SELECT COUNT(*) FROM flows").fetchone()[0])
        flow_rows = connection.execute(
            """SELECT flow_id, event_time, source_ip, destination_ip, source_port, destination_port,
                      protocol, byte_count, packet_count
               FROM flows ORDER BY event_time DESC, flow_id LIMIT ?""",
            (MAX_ANALYST_FLOW_ROWS,),
        ).fetchall()
        try:
            candidate_rows = connection.execute(
                """SELECT candidate_id, rule_id, created_at, source_ip, destination_ip, destination_port,
                          protocol, observed_value, explanation
                   FROM candidates ORDER BY created_at DESC, candidate_id LIMIT ?""",
                (MAX_ANALYST_CANDIDATE_ROWS,),
            ).fetchall()
        except sqlite3.Error:
            candidate_rows = []
        rows = [{key: row[key] for key in row.keys()} for row in flow_rows]
        candidates = [{key: row[key] for key in row.keys()} for row in candidate_rows]
    except sqlite3.Error:
        return empty, ["flow_store_unreadable"]
    finally:
        connection.close()
    return {
        "available": True,
        "candidates": candidates,
        "flow_count": flow_count,
        "rows": rows,
        "summary": {"displayed_rows": len(rows), "flow_count": flow_count},
    }, []


def _count(values: list[Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        if value is None or value == "":
            continue
        key = str(value)
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def _top(counts: Mapping[str, int], *, limit: int = 5) -> list[dict[str, Any]]:
    return [{"count": count, "value": value} for value, count in list(counts.items())[:limit]]


def _overview(evidence: list[dict[str, Any]], correlations: list[dict[str, Any]]) -> dict[str, Any]:
    accepted = [row for row in evidence if row.get("outcome") == "accepted"]
    quarantined = [row for row in evidence if row.get("outcome") == "quarantined"]
    protocols: list[Any] = []
    sources: list[Any] = []
    destinations: list[Any] = []
    severities: list[Any] = []
    for row in accepted:
        network = row.get("network") if isinstance(row.get("network"), Mapping) else {}
        if isinstance(network, Mapping):
            protocols.append(network.get("protocol"))
            sources.append(network.get("source_ip"))
            destinations.append(network.get("destination_ip"))
        detail = row.get("detail") if isinstance(row.get("detail"), Mapping) else {}
        if isinstance(detail, Mapping) and "severity" in detail:
            severities.append(detail.get("severity"))
    return {
        "accepted_count": len(accepted),
        "alerts_by_severity": _count(severities),
        "correlation_outcomes": _count([item.get("traffic_outcome") for item in correlations]),
        "quarantined_count": len(quarantined),
        "source_counts": _count([row.get("source") for row in evidence]),
        "top_destinations": _top(_count(destinations)),
        "top_protocols": _top(_count(protocols)),
        "top_sources": _top(_count(sources)),
    }


def filter_evidence(
    rows: list[dict[str, Any]],
    *,
    source: str = "",
    text: str = "",
    protocol: str = "",
) -> list[dict[str, Any]]:
    """Apply bounded, case-insensitive Discover filters to already-projected rows."""
    needle = text.strip().lower()
    wanted_source = source.strip().lower()
    wanted_protocol = protocol.strip().upper()
    filtered: list[dict[str, Any]] = []
    for row in rows:
        if wanted_source and str(row.get("source") or "").lower() != wanted_source:
            continue
        network = row.get("network") if isinstance(row.get("network"), Mapping) else {}
        if wanted_protocol and str((network or {}).get("protocol") or "").upper() != wanted_protocol:
            continue
        if needle:
            haystack = canonical_json(
                {
                    "detail": row.get("detail"),
                    "evidence_id": row.get("evidence_id"),
                    "network": row.get("network"),
                    "reason_code": row.get("reason_code"),
                    "row_id": row.get("row_id"),
                    "summary": row.get("summary"),
                }
            ).lower()
            if needle not in haystack:
                continue
        filtered.append(row)
    return filtered


def build_analyst_snapshot(evidence_root: str | Path | None, flow_root: str | Path | None = None) -> dict[str, Any]:
    """Return one bounded, read-only projection. Never mutates source stores."""
    evidence_path = Path(evidence_root) if evidence_root is not None else None
    flow_path = Path(flow_root) if flow_root is not None else None
    if evidence_path is None:
        snapshot = _empty_snapshot(problems=("evidence_store_unconfigured",), flow_root=str(flow_path) if flow_path else None)
        flows, flow_problems = _read_flows(flow_path)
        snapshot["flows"] = flows
        snapshot["problems"].extend(flow_problems)
        snapshot["sensors"] = _sensor_health([], flow_available=bool(flows["available"]))
        return snapshot
    if evidence_path.exists() and evidence_path.is_symlink():
        return _empty_snapshot(
            problems=("evidence_store_must_not_be_symlink",),
            evidence_root=str(evidence_path),
            flow_root=str(flow_path) if flow_path else None,
        )
    if not evidence_path.is_dir():
        return _empty_snapshot(
            problems=("evidence_store_unavailable",),
            evidence_root=str(evidence_path),
            flow_root=str(flow_path) if flow_path else None,
        )
    ledger_id, metadata_problems = _read_ledger_metadata(evidence_path / "ledger-meta.v1.json")
    evidence, ledger_problems = _read_ledger(evidence_path / "ledger.v1.jsonl")
    correlations, correlation_problems = _read_correlations(evidence_path)
    flows, flow_problems = _read_flows(flow_path)
    problems = [*metadata_problems, *ledger_problems, *correlation_problems, *flow_problems]
    evidence.sort(key=lambda item: (str(item.get("event_time") or ""), str(item.get("row_id") or "")))
    return {
        "contract_version": ANALYST_CONTRACT_VERSION,
        "correlations": correlations,
        "evidence": evidence,
        "flows": flows,
        "generated_at": _utc_now(),
        "limitations": list(_LIMITATIONS),
        "overview": _overview(evidence, correlations),
        "problems": problems,
        "sensors": _sensor_health(evidence, flow_available=bool(flows["available"])),
        "store": {
            "available": True,
            "entry_count": len(evidence),
            "evidence_root": str(evidence_path),
            "flow_root": str(flow_path) if flow_path else None,
            "ledger_id": ledger_id,
        },
    }
