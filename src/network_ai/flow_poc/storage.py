"""Single-user SQLite persistence for normalized flow evidence and raw BLOBs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import sqlite3
from typing import Any, Iterable, Mapping
import uuid

from network_ai.contracts import canonical_json

from .models import (
    ANALYSIS_SNAPSHOT_VERSION,
    MAX_CANDIDATE_BASIS_BYTES,
    MAX_CANDIDATE_FLOW_REFS,
    MAX_INPUT_SNAPSHOT_BYTES,
    MAX_RETAINED_FLOW_RECORDS,
    Candidate,
    DecodedDatagram,
    PARSER_VERSION,
    PROFILE_VERSION,
    SOURCE_TRUST_STATE,
    SessionIdentity,
)


DEFAULT_MAX_STORAGE_BYTES = 128 * 1024 * 1024
DEFAULT_MAX_FLOW_RECORDS = MAX_RETAINED_FLOW_RECORDS
DEFAULT_MAX_CANDIDATES = 5_000
DEFAULT_MAX_CANDIDATE_INSTANCES = 20_000
DEFAULT_MAX_CANDIDATE_FLOW_REFERENCES = DEFAULT_MAX_CANDIDATES * MAX_CANDIDATE_FLOW_REFS
MAX_COLLECTION_RUNS = 1_000
MAX_ANALYSIS_RUNS = 1_000
MAX_CANDIDATE_INSTANCES = 20_000
COLLECTION_RUN_STALE_SECONDS = 30
REPLAY_WINDOW_SECONDS = 600

ANALYSIS_RUN_REASON_CODES = frozenset(
    (
        "analysis_candidate_limit_exceeded",
        "analysis_failure",
        "analysis_input_limit_exceeded",
        "analysis_repository_limit_unsupported",
        "analysis_snapshot_legacy_unknown",
        "analysis_source_generation_unavailable",
        "candidate_retention_capacity_exceeded",
        "periodic_candidate_limit_exceeded",
        "periodic_group_limit_exceeded",
        "stale_source_snapshot",
    )
)


@dataclass(frozen=True)
class PersistOutcome:
    status: str
    datagram_id: str
    inserted_flow_ids: tuple[str, ...]


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


SNAPSHOT_MATERIAL_FIELDS = (
    "byte_count",
    "destination_ip",
    "destination_port",
    "event_time",
    "flow_end_time",
    "flow_id",
    "protocol",
    "session_key",
    "source_ip",
    "source_port",
)


def _canonical_digest(items: Iterable[Mapping[str, Any]]) -> str:
    digest = hashlib.sha256()
    for item in items:
        encoded = canonical_json(dict(item)).encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _snapshot_material(row: Mapping[str, Any]) -> dict[str, Any]:
    return {field: row[field] for field in SNAPSHOT_MATERIAL_FIELDS}


def _canonical_object(text: str, *, maximum_bytes: int) -> dict[str, Any]:
    if not isinstance(text, str) or len(text.encode("utf-8")) > maximum_bytes:
        raise ValueError("analysis_snapshot_invalid")
    try:
        value = json.loads(text)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("analysis_snapshot_invalid") from exc
    if not isinstance(value, dict) or canonical_json(value) != text:
        raise ValueError("analysis_snapshot_invalid")
    return value


def _validate_input_snapshot(snapshot_json: str, *, require_complete: bool) -> dict[str, Any]:
    snapshot = _canonical_object(snapshot_json, maximum_bytes=MAX_INPUT_SNAPSHOT_BYTES)
    if snapshot.get("version") != ANALYSIS_SNAPSHOT_VERSION or not isinstance(snapshot.get("selection"), str):
        raise ValueError("analysis_snapshot_invalid")
    state = snapshot.get("snapshot_state")
    if require_complete and state != "complete":
        raise ValueError("analysis_snapshot_invalid")
    if state == "complete":
        if (
            type(snapshot.get("effective_flow_limit")) is not int
            or type(snapshot.get("flow_count")) is not int
            or type(snapshot.get("source_generation_lte")) is not int
            or not isinstance(snapshot.get("material_sha256"), str)
            or len(str(snapshot["material_sha256"])) != 64
        ):
            raise ValueError("analysis_snapshot_invalid")
    return snapshot


class FlowRepository:
    """A bounded local repository. It assumes a trusted single-user host."""

    def __init__(
        self,
        root: Path | str,
        *,
        max_storage_bytes: int = DEFAULT_MAX_STORAGE_BYTES,
        max_flow_records: int = DEFAULT_MAX_FLOW_RECORDS,
        max_candidates: int = DEFAULT_MAX_CANDIDATES,
        max_candidate_instances: int = MAX_CANDIDATE_INSTANCES,
        max_candidate_flow_references: int = DEFAULT_MAX_CANDIDATE_FLOW_REFERENCES,
    ) -> None:
        self.root = Path(root)
        if self.root.exists() and self.root.is_symlink():
            raise ValueError("flow_store_root_must_not_be_symlink")
        self.root.mkdir(parents=True, exist_ok=True)
        self._owner_mode(self.root, 0o700)
        self.database_path = self.root / "flow-poc.sqlite3"
        if self.database_path.exists() and self.database_path.is_symlink():
            raise ValueError("flow_database_must_not_be_symlink")
        self.max_storage_bytes = max_storage_bytes
        self.max_flow_records = max_flow_records
        self.max_candidates = max_candidates
        self.max_candidate_instances = max_candidate_instances
        self.max_candidate_flow_references = max_candidate_flow_references
        if (
            type(max_flow_records) is not int
            or not 1 <= max_flow_records <= MAX_RETAINED_FLOW_RECORDS
            or type(max_candidates) is not int
            or not 1 <= max_candidates <= DEFAULT_MAX_CANDIDATES
            or type(max_candidate_instances) is not int
            or not 1 <= max_candidate_instances <= MAX_CANDIDATE_INSTANCES
            or type(max_candidate_flow_references) is not int
            or not 1 <= max_candidate_flow_references <= DEFAULT_MAX_CANDIDATE_FLOW_REFERENCES
        ):
            raise ValueError("flow_repository_limits_invalid")
        self._initialize()

    @staticmethod
    def _owner_mode(path: Path, mode: int) -> None:
        if os.name != "nt" and path.exists():
            path.chmod(mode)

    def _set_database_modes(self) -> None:
        for path in self.root.glob("flow-poc.sqlite3*"):
            self._owner_mode(path, 0o600)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=3000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS raw_datagrams (
                    raw_sha256 TEXT PRIMARY KEY,
                    raw_blob BLOB NOT NULL,
                    first_stored_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS datagrams (
                    datagram_id TEXT PRIMARY KEY,
                    session_key TEXT NOT NULL,
                    protocol_version INTEGER NOT NULL,
                    observation_domain_id INTEGER NOT NULL,
                    sequence_number INTEGER NOT NULL,
                    exporter_ip TEXT NOT NULL,
                    exporter_port INTEGER NOT NULL,
                    collector_ip TEXT NOT NULL,
                    collector_port INTEGER NOT NULL,
                    export_time TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    raw_sha256 TEXT NOT NULL REFERENCES raw_datagrams(raw_sha256),
                    parser_version TEXT NOT NULL,
                    profile_version TEXT NOT NULL,
                    configuration_sha256 TEXT NOT NULL,
                    source_trust_state TEXT NOT NULL,
                    template_fingerprints_json TEXT NOT NULL,
                    sequence_state TEXT NOT NULL,
                    status TEXT NOT NULL,
                    UNIQUE(session_key, sequence_number, raw_sha256)
                );
                CREATE INDEX IF NOT EXISTS datagrams_session_sequence ON datagrams(session_key, sequence_number);
                CREATE TABLE IF NOT EXISTS deliveries (
                    delivery_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    datagram_id TEXT REFERENCES datagrams(datagram_id),
                    raw_sha256 TEXT NOT NULL REFERENCES raw_datagrams(raw_sha256),
                    received_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    reason_code TEXT
                );
                CREATE INDEX IF NOT EXISTS deliveries_received_at ON deliveries(received_at);
                CREATE TABLE IF NOT EXISTS flows (
                    flow_id TEXT PRIMARY KEY,
                    datagram_id TEXT NOT NULL REFERENCES datagrams(datagram_id) ON DELETE CASCADE,
                    session_key TEXT NOT NULL,
                    record_index INTEGER NOT NULL,
                    fingerprint TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    event_time TEXT NOT NULL,
                    flow_start_time TEXT,
                    flow_end_time TEXT,
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT NOT NULL,
                    source_port INTEGER,
                    destination_port INTEGER,
                    protocol INTEGER,
                    byte_count INTEGER NOT NULL,
                    packet_count INTEGER,
                    ip_version INTEGER,
                    direction INTEGER,
                    template_id INTEGER NOT NULL,
                    template_fingerprint TEXT NOT NULL,
                    uncertainty_json TEXT NOT NULL,
                    source_trust_state TEXT NOT NULL,
                    source_generation INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS flows_fingerprint_received ON flows(fingerprint, received_at);
                CREATE INDEX IF NOT EXISTS flows_event_source ON flows(event_time, source_ip);
                CREATE TABLE IF NOT EXISTS flow_store_state (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    current_generation INTEGER NOT NULL
                );
                INSERT OR IGNORE INTO flow_store_state(singleton, current_generation) VALUES (1, 0);
                CREATE TABLE IF NOT EXISTS candidates (
                    candidate_id TEXT PRIMARY KEY,
                    rule_id TEXT NOT NULL,
                    rule_version TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    window_start TEXT NOT NULL,
                    window_end TEXT NOT NULL,
                    threshold INTEGER NOT NULL,
                    observed_value INTEGER NOT NULL,
                    source_ip TEXT,
                    destination_ip TEXT,
                    destination_port INTEGER,
                    protocol INTEGER,
                    session_key TEXT,
                    uncertainty_json TEXT NOT NULL,
                    basis_json TEXT NOT NULL DEFAULT '{}',
                    explanation TEXT NOT NULL,
                    source_trust_state TEXT NOT NULL,
                    detector_configuration_sha256 TEXT NOT NULL DEFAULT 'legacy-unknown',
                    identity_material_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS candidate_flows (
                    candidate_id TEXT NOT NULL REFERENCES candidates(candidate_id) ON DELETE CASCADE,
                    flow_id TEXT NOT NULL REFERENCES flows(flow_id) ON DELETE CASCADE,
                    PRIMARY KEY(candidate_id, flow_id)
                );
                CREATE TABLE IF NOT EXISTS collection_runs (
                    run_id TEXT PRIMARY KEY,
                    collector_configuration_sha256 TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    heartbeat_at TEXT NOT NULL,
                    completed_at TEXT,
                    state TEXT NOT NULL,
                    counters_json TEXT NOT NULL,
                    last_received_at TEXT,
                    last_persisted_at TEXT,
                    last_error_code TEXT,
                    audit_state TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS collection_runs_started_at ON collection_runs(started_at DESC);
                CREATE TABLE IF NOT EXISTS analysis_runs (
                    analysis_run_id TEXT PRIMARY KEY,
                    collection_run_id TEXT REFERENCES collection_runs(run_id),
                    detector_configuration_sha256 TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    candidate_count INTEGER NOT NULL,
                    reason_code TEXT,
                    input_snapshot_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS analysis_runs_started_at ON analysis_runs(started_at DESC);
                CREATE TABLE IF NOT EXISTS analysis_run_candidates (
                    analysis_run_id TEXT NOT NULL REFERENCES analysis_runs(analysis_run_id) ON DELETE CASCADE,
                    candidate_id TEXT NOT NULL REFERENCES candidates(candidate_id) ON DELETE CASCADE,
                    PRIMARY KEY(analysis_run_id, candidate_id)
                );
                CREATE INDEX IF NOT EXISTS analysis_run_candidates_candidate ON analysis_run_candidates(candidate_id);
                """
            )
            candidate_columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(candidates)")}
            if "detector_configuration_sha256" not in candidate_columns:
                connection.execute(
                    "ALTER TABLE candidates ADD COLUMN detector_configuration_sha256 TEXT NOT NULL DEFAULT 'legacy-unknown'"
                )
            if "destination_ip" not in candidate_columns:
                connection.execute("ALTER TABLE candidates ADD COLUMN destination_ip TEXT")
            if "destination_port" not in candidate_columns:
                connection.execute("ALTER TABLE candidates ADD COLUMN destination_port INTEGER")
            if "basis_json" not in candidate_columns:
                connection.execute("ALTER TABLE candidates ADD COLUMN basis_json TEXT NOT NULL DEFAULT '{}'")
            if "identity_material_json" not in candidate_columns:
                connection.execute("ALTER TABLE candidates ADD COLUMN identity_material_json TEXT NOT NULL DEFAULT '{}'")
            flow_columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(flows)")}
            if "source_generation" not in flow_columns:
                connection.execute("ALTER TABLE flows ADD COLUMN source_generation INTEGER NOT NULL DEFAULT 0")
            connection.execute("CREATE INDEX IF NOT EXISTS flows_source_generation ON flows(source_generation, flow_id)")
            connection.execute("UPDATE flows SET source_generation = rowid WHERE source_generation = 0")
            maximum_generation = int(connection.execute("SELECT COALESCE(MAX(source_generation), 0) FROM flows").fetchone()[0])
            connection.execute(
                "UPDATE flow_store_state SET current_generation = MAX(current_generation, ?) WHERE singleton = 1",
                (maximum_generation,),
            )
            analysis_columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(analysis_runs)")}
            if "input_snapshot_json" not in analysis_columns:
                connection.execute("ALTER TABLE analysis_runs ADD COLUMN input_snapshot_json TEXT NOT NULL DEFAULT '{}'")
            connection.execute("BEGIN IMMEDIATE")
            try:
                # A completed result must survive the same source and
                # candidate-fact verification required for a new commit.  A
                # non-empty but legacy/malformed snapshot is no safer than
                # the old '{}' placeholder, so demote every unverifiable row
                # atomically before a dashboard can present it as clean.
                self._demote_unverifiable_completed_runs(connection)
                # A process that ended before its final update must not look
                # healthy. The next local repository open makes that explicit.
                stale_before = _iso(datetime.now(tz=timezone.utc) - timedelta(seconds=COLLECTION_RUN_STALE_SECONDS))
                connection.execute(
                    "UPDATE collection_runs SET state = 'unclean_shutdown', completed_at = heartbeat_at, audit_state = 'written' "
                    "WHERE state = 'running' AND heartbeat_at < ?",
                    (stale_before,),
                )
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
        self._set_database_modes()

    def foreign_keys_enabled(self) -> bool:
        with self._connect() as connection:
            return bool(connection.execute("PRAGMA foreign_keys").fetchone()[0])

    def _root_usage_bytes(self) -> int:
        return sum(path.stat().st_size for path in self.root.glob("flow-poc.sqlite3*") if path.is_file())

    def _ensure_capacity(self, connection: sqlite3.Connection, raw_size: int, flow_count: int) -> None:
        count = connection.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
        if count + flow_count > self.max_flow_records:
            raise ValueError("flow_record_capacity_exceeded")
        # The estimate leaves room for SQLite page/WAL growth; final page usage
        # is checked before commit and rolls back if it still exceeds the cap.
        estimate = raw_size + 65_536 + flow_count * 1_024
        if self._root_usage_bytes() + estimate > self.max_storage_bytes:
            raise ValueError("flow_store_quota_exceeded")

    @staticmethod
    def _datagram_id(session_key: str, sequence_number: int, raw_sha256: str) -> str:
        return _digest(f"{session_key}\0{sequence_number}\0{raw_sha256}".encode("utf-8"))

    def sequence_raw_hashes(self, session_key: str, sequence_number: int) -> tuple[str, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT raw_sha256 FROM datagrams WHERE session_key = ? AND sequence_number = ? ORDER BY raw_sha256",
                (session_key, sequence_number),
            ).fetchall()
        return tuple(str(row[0]) for row in rows)

    def persist_rejected_delivery(
        self,
        *,
        raw: bytes,
        session: SessionIdentity,
        header: Any,
        received_at: datetime,
        status: str,
        reason_code: str,
        configuration_sha256: str,
    ) -> PersistOutcome:
        raw_sha256 = _digest(raw)
        datagram_id = self._datagram_id(session.key, header.sequence_number, raw_sha256)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._ensure_capacity(connection, len(raw), 0)
                connection.execute(
                    "INSERT OR IGNORE INTO raw_datagrams(raw_sha256, raw_blob, first_stored_at) VALUES (?, ?, ?)",
                    (raw_sha256, raw, _iso(received_at)),
                )
                connection.execute(
                    """INSERT OR IGNORE INTO datagrams(
                        datagram_id, session_key, protocol_version, observation_domain_id, sequence_number,
                        exporter_ip, exporter_port, collector_ip, collector_port, export_time, received_at,
                        raw_sha256, parser_version, profile_version, configuration_sha256, source_trust_state,
                        template_fingerprints_json, sequence_state, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        datagram_id,
                        session.key,
                        header.protocol_version,
                        header.observation_domain_id,
                        header.sequence_number,
                        session.exporter_ip,
                        session.exporter_port,
                        session.collector_ip,
                        session.collector_port,
                        _iso(header.export_time),
                        _iso(received_at),
                        raw_sha256,
                        PARSER_VERSION,
                        PROFILE_VERSION,
                        configuration_sha256,
                        SOURCE_TRUST_STATE,
                        "[]",
                        status,
                        status,
                    ),
                )
                connection.execute(
                    "INSERT INTO deliveries(datagram_id, raw_sha256, received_at, status, reason_code) VALUES (?, ?, ?, ?, ?)",
                    (datagram_id, raw_sha256, _iso(received_at), status, reason_code),
                )
                if self._root_usage_bytes() > self.max_storage_bytes:
                    raise ValueError("flow_store_quota_exceeded")
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                raise
        self._set_database_modes()
        return PersistOutcome(status, datagram_id, ())

    def persist_decoded(
        self,
        decoded: DecodedDatagram,
        raw: bytes,
        *,
        received_at: datetime,
        configuration_sha256: str,
        sequence_state: str,
    ) -> PersistOutcome:
        raw_sha256 = _digest(raw)
        datagram_id = self._datagram_id(decoded.session.key, decoded.header.sequence_number, raw_sha256)
        inserted_flow_ids: list[str] = []
        status = "accepted"
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._ensure_capacity(connection, len(raw), len(decoded.flows))
                connection.execute(
                    "INSERT OR IGNORE INTO raw_datagrams(raw_sha256, raw_blob, first_stored_at) VALUES (?, ?, ?)",
                    (raw_sha256, raw, _iso(received_at)),
                )
                connection.execute(
                    """INSERT INTO datagrams(
                        datagram_id, session_key, protocol_version, observation_domain_id, sequence_number,
                        exporter_ip, exporter_port, collector_ip, collector_port, export_time, received_at,
                        raw_sha256, parser_version, profile_version, configuration_sha256, source_trust_state,
                        template_fingerprints_json, sequence_state, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        datagram_id,
                        decoded.session.key,
                        decoded.header.protocol_version,
                        decoded.header.observation_domain_id,
                        decoded.header.sequence_number,
                        decoded.session.exporter_ip,
                        decoded.session.exporter_port,
                        decoded.session.collector_ip,
                        decoded.session.collector_port,
                        _iso(decoded.header.export_time),
                        _iso(received_at),
                        raw_sha256,
                        PARSER_VERSION,
                        PROFILE_VERSION,
                        configuration_sha256,
                        SOURCE_TRUST_STATE,
                        canonical_json(list(decoded.template_fingerprints)),
                        sequence_state,
                        "accepted",
                    ),
                )
                connection.execute(
                    "INSERT INTO deliveries(datagram_id, raw_sha256, received_at, status) VALUES (?, ?, ?, ?)",
                    (datagram_id, raw_sha256, _iso(received_at), "accepted"),
                )
                replay_cutoff = _iso(received_at - timedelta(seconds=REPLAY_WINDOW_SECONDS))
                source_generation = 0
                if decoded.flows:
                    source_generation = int(
                        connection.execute(
                            "SELECT current_generation FROM flow_store_state WHERE singleton = 1"
                        ).fetchone()[0]
                    ) + 1
                    connection.execute(
                        "UPDATE flow_store_state SET current_generation = ? WHERE singleton = 1",
                        (source_generation,),
                    )
                for flow in decoded.flows:
                    prior = connection.execute(
                        "SELECT flow_id FROM flows WHERE session_key = ? AND fingerprint = ? AND received_at >= ? LIMIT 1",
                        (decoded.session.key, flow.fingerprint, replay_cutoff),
                    ).fetchone()
                    if prior is not None:
                        status = "possible_replay"
                        continue
                    flow_id = _digest(f"{datagram_id}\0{flow.record_index}\0{flow.fingerprint}".encode("utf-8"))
                    connection.execute(
                        """INSERT INTO flows(
                            flow_id, datagram_id, session_key, record_index, fingerprint, received_at, event_time,
                            flow_start_time, flow_end_time, source_ip, destination_ip, source_port,
                            destination_port, protocol, byte_count, packet_count, ip_version, direction,
                            template_id, template_fingerprint, uncertainty_json, source_trust_state, source_generation
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            flow_id,
                            datagram_id,
                            decoded.session.key,
                            flow.record_index,
                            flow.fingerprint,
                            _iso(received_at),
                            _iso(flow.event_time),
                            _iso(flow.flow_start_time) if flow.flow_start_time else None,
                            _iso(flow.flow_end_time) if flow.flow_end_time else None,
                            flow.source_ip,
                            flow.destination_ip,
                            flow.source_port,
                            flow.destination_port,
                            flow.protocol,
                            flow.byte_count,
                            flow.packet_count,
                            flow.ip_version,
                            flow.direction,
                            flow.template_id,
                            flow.template_fingerprint,
                            canonical_json(list(flow.uncertainty)),
                            SOURCE_TRUST_STATE,
                            source_generation,
                        ),
                    )
                    inserted_flow_ids.append(flow_id)
                # The WAL receives transaction frames before COMMIT, so this
                # full-root check covers the database, WAL, and SHM together
                # while the transaction can still be rolled back safely.
                if self._root_usage_bytes() > self.max_storage_bytes:
                    raise ValueError("flow_store_quota_exceeded")
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                raise
        self._set_database_modes()
        return PersistOutcome(status, datagram_id, tuple(inserted_flow_ids))

    def flow_rows(self, *, limit: int | None = 10_000, newest_first: bool = False) -> tuple[dict[str, Any], ...]:
        with self._connect() as connection:
            statement = """SELECT flow_id, datagram_id, session_key, event_time, source_ip, destination_ip, source_port,
                          destination_port, protocol, byte_count, packet_count, flow_start_time, flow_end_time, template_id,
                          template_fingerprint, uncertainty_json, source_trust_state
                   FROM flows ORDER BY event_time """ + ("DESC" if newest_first else "ASC") + ", flow_id"
            if limit is not None:
                statement += " LIMIT ?"
                rows = connection.execute(statement, (limit,)).fetchall()
            else:
                rows = connection.execute(statement).fetchall()
        return tuple({key: row[key] for key in row.keys()} for row in rows)

    def analysis_source_snapshot(self, *, limit: int) -> tuple[tuple[dict[str, Any], ...], int]:
        """Return one exact, generation-bounded source view for analysis.

        The boundary and rows are read in the same SQLite snapshot.  Later
        inserts have higher generations and therefore cannot alter a later
        verification of this committed selection.
        """
        if type(limit) is not int or not 1 <= limit <= MAX_RETAINED_FLOW_RECORDS + 1:
            raise ValueError("analysis_repository_limit_unsupported")
        with self._connect() as connection:
            connection.execute("BEGIN")
            try:
                unversioned = int(
                    connection.execute("SELECT COUNT(*) FROM flows WHERE source_generation <= 0").fetchone()[0]
                )
                if unversioned:
                    raise ValueError("analysis_source_generation_unavailable")
                source_generation = int(
                    connection.execute(
                        "SELECT current_generation FROM flow_store_state WHERE singleton = 1"
                    ).fetchone()[0]
                )
                rows = connection.execute(
                    """SELECT flow_id, datagram_id, session_key, event_time, source_ip, destination_ip, source_port,
                              destination_port, protocol, byte_count, packet_count, flow_start_time, flow_end_time,
                              template_id, template_fingerprint, uncertainty_json, source_trust_state, source_generation
                       FROM flows WHERE source_generation <= ? ORDER BY event_time, flow_id LIMIT ?""",
                    (source_generation, limit),
                ).fetchall()
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
        return tuple({key: row[key] for key in row.keys()} for row in rows), source_generation

    @staticmethod
    def _delete_unreferenced_candidate_facts(connection: sqlite3.Connection) -> None:
        connection.execute(
            """DELETE FROM candidates WHERE candidate_id NOT IN (
                SELECT candidate_id FROM analysis_run_candidates
            )"""
        )

    @staticmethod
    def _oldest_evictable_analysis_run_id(
        connection: sqlite3.Connection,
        *,
        allow_replace_latest_failed: bool,
    ) -> str | None:
        """Prefer completed history, preserving the newest failed explanation."""
        row = connection.execute(
            "SELECT analysis_run_id FROM analysis_runs WHERE status = 'completed' ORDER BY started_at, analysis_run_id LIMIT 1"
        ).fetchone()
        if row is None:
            newest_failed = connection.execute(
                "SELECT analysis_run_id FROM analysis_runs WHERE status = 'failed' "
                "ORDER BY started_at DESC, analysis_run_id DESC LIMIT 1"
            ).fetchone()
            if newest_failed is not None:
                row = connection.execute(
                    "SELECT analysis_run_id FROM analysis_runs WHERE status = 'failed' AND analysis_run_id != ? "
                    "ORDER BY started_at, analysis_run_id LIMIT 1",
                    (newest_failed[0],),
                ).fetchone()
                if row is None and allow_replace_latest_failed:
                    # The caller has already completed a new derivation and
                    # writes it atomically. A rollback restores this failure;
                    # a commit makes the new result the current explanation.
                    row = newest_failed
        return str(row[0]) if row is not None else None

    def _make_analysis_history_room(
        self,
        connection: sqlite3.Connection,
        *,
        required_candidate_instances: int,
        candidates: tuple[Candidate, ...],
        allow_replace_latest_failed: bool = False,
    ) -> None:
        if required_candidate_instances > self.max_candidate_instances:
            raise ValueError("candidate_instance_capacity_exceeded")
        candidate_ids = tuple(candidate.candidate_id for candidate in candidates)
        required_candidate_references = sum(len(candidate.flow_ids) for candidate in candidates)
        if required_candidate_references > self.max_candidate_flow_references:
            raise ValueError("candidate_retention_capacity_exceeded")
        self._delete_unreferenced_candidate_facts(connection)
        while True:
            run_count = int(connection.execute("SELECT COUNT(*) FROM analysis_runs").fetchone()[0])
            instance_count = int(connection.execute("SELECT COUNT(*) FROM analysis_run_candidates").fetchone()[0])
            candidate_count = int(connection.execute("SELECT COUNT(*) FROM candidates").fetchone()[0])
            reference_count = int(connection.execute("SELECT COUNT(*) FROM candidate_flows").fetchone()[0])
            existing_ids = {
                str(row[0])
                for row in connection.execute(
                    f"SELECT candidate_id FROM candidates WHERE candidate_id IN ({','.join('?' for _ in candidate_ids)})",
                    candidate_ids,
                )
            } if candidate_ids else set()
            required_new_candidate_ids = len(set(candidate_ids) - existing_ids)
            required_new_references = sum(
                len(candidate.flow_ids) for candidate in candidates if candidate.candidate_id not in existing_ids
            )
            if (
                run_count < MAX_ANALYSIS_RUNS
                and instance_count + required_candidate_instances <= self.max_candidate_instances
                and candidate_count + required_new_candidate_ids <= self.max_candidates
                and reference_count + required_new_references <= self.max_candidate_flow_references
            ):
                return
            oldest = self._oldest_evictable_analysis_run_id(
                connection,
                allow_replace_latest_failed=allow_replace_latest_failed,
            )
            if oldest is None:
                raise ValueError("candidate_retention_capacity_exceeded")
            connection.execute("DELETE FROM analysis_runs WHERE analysis_run_id = ?", (oldest,))
            self._delete_unreferenced_candidate_facts(connection)

    @classmethod
    def _candidate_values_for_analysis_run(
        cls,
        connection: sqlite3.Connection,
        analysis_run_id: str,
    ) -> tuple[Candidate, ...]:
        """Materialize one persisted candidate mapping without raw payloads."""
        rows = connection.execute(
            """SELECT candidates.candidate_id, candidates.rule_id, candidates.rule_version, candidates.created_at,
                      candidates.window_start, candidates.window_end, candidates.threshold, candidates.observed_value,
                      candidates.source_ip, candidates.destination_ip, candidates.destination_port, candidates.protocol,
                      candidates.session_key, candidates.uncertainty_json, candidates.identity_material_json,
                      candidates.basis_json, candidates.explanation
               FROM candidates JOIN analysis_run_candidates
                 ON analysis_run_candidates.candidate_id = candidates.candidate_id
               WHERE analysis_run_candidates.analysis_run_id = ?
               ORDER BY candidates.candidate_id""",
            (analysis_run_id,),
        ).fetchall()
        candidates: list[Candidate] = []
        for row in rows:
            try:
                uncertainty = json.loads(str(row[13]))
                identity_material_json = str(row[14])
                basis_json = str(row[15])
                _canonical_object(identity_material_json, maximum_bytes=MAX_CANDIDATE_BASIS_BYTES)
                _canonical_object(basis_json, maximum_bytes=MAX_CANDIDATE_BASIS_BYTES)
                if not isinstance(uncertainty, list) or not all(isinstance(value, str) for value in uncertainty):
                    raise ValueError("candidate_fact_invalid")
                flow_ids = tuple(
                    str(flow[0])
                    for flow in connection.execute(
                        "SELECT flow_id FROM candidate_flows WHERE candidate_id = ? ORDER BY flow_id",
                        (row[0],),
                    )
                )
                candidates.append(
                    Candidate(
                        candidate_id=str(row[0]),
                        rule_id=str(row[1]),
                        rule_version=str(row[2]),
                        created_at=_parse_iso(str(row[3])),
                        window_start=_parse_iso(str(row[4])),
                        window_end=_parse_iso(str(row[5])),
                        threshold=int(row[6]),
                        observed_value=int(row[7]),
                        source_ip=row[8],
                        destination_ip=row[9],
                        destination_port=row[10],
                        protocol=row[11],
                        session_key=row[12],
                        flow_ids=flow_ids,
                        uncertainty=tuple(uncertainty),
                        identity_material_json=identity_material_json,
                        basis_json=basis_json,
                        explanation=str(row[16]),
                    )
                )
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise ValueError("candidate_fact_invalid") from exc
        cls._validate_candidate_values(tuple(candidates))
        return tuple(candidates)

    def _demote_unverifiable_completed_runs(self, connection: sqlite3.Connection) -> None:
        """Remove completed status from any legacy or tampered derivation."""
        completed = connection.execute(
            """SELECT analysis_run_id, candidate_count, input_snapshot_json
                 FROM analysis_runs WHERE status = 'completed' ORDER BY analysis_run_id"""
        ).fetchall()
        invalid_ids: list[str] = []
        for row in completed:
            analysis_run_id = str(row[0])
            try:
                snapshot = _validate_input_snapshot(str(row[2]), require_complete=True)
                source_rows = self._validate_source_snapshot(connection, snapshot)
                candidates = self._candidate_values_for_analysis_run(connection, analysis_run_id)
                if len(candidates) != int(row[1]):
                    raise ValueError("analysis_snapshot_invalid")
                self._validate_candidates_against_source(candidates, source_rows)
            except (TypeError, ValueError, sqlite3.Error):
                invalid_ids.append(analysis_run_id)
        if not invalid_ids:
            return
        placeholders = ", ".join("?" for _ in invalid_ids)
        legacy_snapshot = canonical_json(
            {
                "selection": "legacy-unknown",
                "snapshot_state": "legacy_unknown",
                "version": ANALYSIS_SNAPSHOT_VERSION,
            }
        )
        connection.execute(
            f"DELETE FROM analysis_run_candidates WHERE analysis_run_id IN ({placeholders})",
            invalid_ids,
        )
        connection.execute(
            f"UPDATE analysis_runs SET status = 'failed', candidate_count = 0, "
            "reason_code = 'analysis_snapshot_legacy_unknown', input_snapshot_json = ? "
            f"WHERE analysis_run_id IN ({placeholders})",
            (legacy_snapshot, *invalid_ids),
        )
        self._delete_unreferenced_candidate_facts(connection)

    @staticmethod
    def _validate_candidate_values(candidates: tuple[Candidate, ...]) -> None:
        identifiers = tuple(candidate.candidate_id for candidate in candidates)
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("duplicate_candidate_identity")
        for candidate in candidates:
            if (
                len(candidate.candidate_id) != 64
                or any(character not in "0123456789abcdef" for character in candidate.candidate_id)
                or not 1 <= len(candidate.flow_ids) <= MAX_CANDIDATE_FLOW_REFS
                or len(set(candidate.flow_ids)) != len(candidate.flow_ids)
                or any(len(flow_id) != 64 for flow_id in candidate.flow_ids)
            ):
                raise ValueError("invalid_candidate_identity")
            identity = _canonical_object(candidate.identity_material_json, maximum_bytes=MAX_CANDIDATE_BASIS_BYTES)
            basis = _canonical_object(candidate.basis_json, maximum_bytes=MAX_CANDIDATE_BASIS_BYTES)
            expected = hashlib.sha256(
                f"{candidate.rule_id}\0{canonical_json(identity)}".encode("utf-8")
            ).hexdigest()
            if (
                expected != candidate.candidate_id
                or "contributor_material" not in basis
                or identity.get("contributor_material") != basis.get("contributor_material")
            ):
                raise ValueError("invalid_candidate_identity")

    @staticmethod
    def _validate_contributor_material(material: object, flow_ids: tuple[str, ...]) -> None:
        if not isinstance(material, dict):
            raise ValueError("invalid_candidate_identity")
        expected = {
            "count": len(flow_ids),
            "sha256": _canonical_digest({"flow_id": flow_id} for flow_id in sorted(flow_ids)),
            "version": "candidate-contributors.v1",
        }
        if material != expected:
            raise ValueError("invalid_candidate_identity")

    @staticmethod
    def _source_rows_at_boundary(connection: sqlite3.Connection, source_generation: int) -> tuple[dict[str, Any], ...]:
        rows = connection.execute(
            """SELECT flow_id, session_key, event_time, source_ip, destination_ip, source_port, destination_port,
                      protocol, byte_count, flow_end_time, source_generation
               FROM flows WHERE source_generation <= ? ORDER BY flow_id""",
            (source_generation,),
        ).fetchall()
        return tuple({key: row[key] for key in row.keys()} for row in rows)

    @classmethod
    def _validate_source_snapshot(cls, connection: sqlite3.Connection, snapshot: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
        if snapshot.get("selection") != "complete_retained_flow_repository.v1":
            raise ValueError("analysis_snapshot_invalid")
        rows = cls._source_rows_at_boundary(connection, int(snapshot["source_generation_lte"]))
        material = tuple(_snapshot_material(row) for row in rows)
        if len(rows) != snapshot["flow_count"] or _canonical_digest(material) != snapshot["material_sha256"]:
            raise ValueError("stale_source_snapshot")
        return rows

    @classmethod
    def _validate_candidates_against_source(
        cls,
        candidates: tuple[Candidate, ...],
        source_rows: tuple[dict[str, Any], ...],
    ) -> None:
        """Recompute every supported rule from the verified source snapshot.

        Candidate IDs protect the self-declared identity material, not the
        truth of a caller's claimed observation.  This is the storage trust
        boundary: facts are committed only when their fields, rule basis and
        contributor material can all be regenerated from retained flows.
        """
        # A local import keeps the persistence module independent during
        # package initialization while pinning commits to the default,
        # versioned detector contract used by ``analyze_and_record``.
        from .analysis import FlowAnalyzer, PERIODIC_SUPPORTED_PROTOCOLS

        analyzer = FlowAnalyzer()
        source_ids = {str(row["flow_id"]) for row in source_rows}
        source_by_id = {str(row["flow_id"]): row for row in source_rows}

        def canonical_ip(value: object) -> str | None:
            if not isinstance(value, str):
                return None
            try:
                parsed = ipaddress.ip_address(value)
            except ValueError:
                return None
            return value if str(parsed) == value else None

        def valid_port(value: object) -> int | None:
            return value if type(value) is int and 1 <= value <= 65_535 else None

        def require(condition: bool) -> None:
            if not condition:
                raise ValueError("invalid_candidate_identity")

        for candidate in candidates:
            if not set(candidate.flow_ids).issubset(source_ids):
                raise ValueError("stale_source_snapshot")
            basis = _canonical_object(candidate.basis_json, maximum_bytes=MAX_CANDIDATE_BASIS_BYTES)
            identity = _canonical_object(candidate.identity_material_json, maximum_bytes=MAX_CANDIDATE_BASIS_BYTES)

            if candidate.rule_id == "high-volume.v1":
                require(candidate.rule_version == "high-volume.v1" and len(candidate.flow_ids) == 1)
                row = source_by_id[candidate.flow_ids[0]]
                event_time = _parse_iso(str(row["event_time"]))
                contributor_material = {
                    "count": 1,
                    "sha256": _canonical_digest(({"flow_id": str(row["flow_id"])},)),
                    "version": "candidate-contributors.v1",
                }
                expected_identity = {
                    "contributor_material": contributor_material,
                    "flow_id": row["flow_id"],
                    "rule_version": "high-volume.v1",
                    "threshold": analyzer.high_volume_bytes,
                }
                expected_basis = {
                    "basis": "exporter_reported_byte_count.v2",
                    "contributor_material": contributor_material,
                    "flow_id": row["flow_id"],
                }
                require(
                    identity == expected_identity
                    and basis == expected_basis
                    and candidate.threshold == analyzer.high_volume_bytes
                    and row["byte_count"] >= analyzer.high_volume_bytes
                    and candidate.observed_value == row["byte_count"]
                    and candidate.source_ip == row["source_ip"]
                    and candidate.destination_ip == row["destination_ip"]
                    and candidate.destination_port == row["destination_port"]
                    and candidate.protocol == row["protocol"]
                    and candidate.session_key == row["session_key"]
                    and candidate.window_start == event_time
                    and candidate.window_end == event_time
                    and candidate.uncertainty == ("sampling-unknown", "ip-allowlisted-unauthenticated")
                )
                continue

            if candidate.rule_id == "periodic-flow.v1":
                require(candidate.rule_version == "periodic-flow.v1" and len(candidate.flow_ids) == analyzer.periodic_min_records)
                selected = tuple(source_by_id[flow_id] for flow_id in candidate.flow_ids)
                source_ip = canonical_ip(selected[0].get("source_ip"))
                destination_ip = canonical_ip(selected[0].get("destination_ip"))
                destination_port = valid_port(selected[0].get("destination_port"))
                protocol = selected[0].get("protocol")
                require(
                    source_ip is not None
                    and destination_ip is not None
                    and destination_port is not None
                    and type(protocol) is int
                    and protocol in PERIODIC_SUPPORTED_PROTOCOLS
                    and all(valid_port(row.get("source_port")) is not None for row in selected)
                )
                session_key = selected[0]["session_key"]
                require(
                    all(
                        row["session_key"] == session_key
                        and canonical_ip(row.get("source_ip")) == source_ip
                        and canonical_ip(row.get("destination_ip")) == destination_ip
                        and valid_port(row.get("destination_port")) == destination_port
                        and row.get("protocol") == protocol
                        for row in selected
                    )
                )
                try:
                    ordered = tuple(sorted(((_parse_iso(str(row["flow_end_time"])), row) for row in selected), key=lambda item: (item[0], str(item[1]["flow_id"]))))
                except (TypeError, ValueError) as exc:
                    raise ValueError("invalid_candidate_identity") from exc
                require(all(later[0] > earlier[0] for earlier, later in zip(ordered, ordered[1:])))
                times = tuple(item[0] for item in ordered)
                intervals = tuple(
                    (later - earlier).days * 86_400_000_000 + (later - earlier).seconds * 1_000_000 + (later - earlier).microseconds
                    for earlier, later in zip(times, times[1:])
                )
                require(
                    all(analyzer.periodic_min_interval_microseconds <= value <= analyzer.periodic_max_interval_microseconds for value in intervals)
                )
                median_interval = sorted(intervals)[len(intervals) // 2]
                allowed_deviation = max(
                    analyzer.periodic_min_tolerance_microseconds,
                    (median_interval * analyzer.periodic_tolerance_ppm) // 1_000_000,
                )
                maximum_deviation = max(abs(value - median_interval) for value in intervals)
                require(maximum_deviation <= allowed_deviation)
                flow_ids_chronological = tuple(str(item[1]["flow_id"]) for item in ordered)
                contributor_material = {
                    "count": len(flow_ids_chronological),
                    "sha256": _canonical_digest({"flow_id": flow_id} for flow_id in sorted(flow_ids_chronological)),
                    "version": "candidate-contributors.v1",
                }
                policy = {
                    "allowed_deviation_microseconds": allowed_deviation,
                    "flow_end_times_utc": [item.isoformat() for item in times],
                    "flow_ids_chronological": list(flow_ids_chronological),
                    "interval_microseconds": list(intervals),
                    "maximum_deviation_microseconds": maximum_deviation,
                    "median_interval_microseconds": median_interval,
                    "minimum_records": analyzer.periodic_min_records,
                    "minimum_tolerance_microseconds": analyzer.periodic_min_tolerance_microseconds,
                    "periodic_interval_maximum_microseconds": analyzer.periodic_max_interval_microseconds,
                    "periodic_interval_minimum_microseconds": analyzer.periodic_min_interval_microseconds,
                    "periodic_tolerance_ppm": analyzer.periodic_tolerance_ppm,
                    "source_port_excluded_from_group": True,
                }
                expected_identity = {
                    "contributor_material": contributor_material,
                    "destination_ip": destination_ip,
                    "destination_port": destination_port,
                    "group_session_key": session_key,
                    "policy": policy,
                    "protocol": protocol,
                    "rule_version": "periodic-flow.v1",
                    "source_ip": source_ip,
                }
                expected_basis = {
                    "basis": "exporter_reported_endpoint_periodicity.v1",
                    "contributor_material": contributor_material,
                    **policy,
                }
                require(
                    identity == expected_identity
                    and basis == expected_basis
                    and set(candidate.flow_ids) == set(flow_ids_chronological)
                    and candidate.threshold == analyzer.periodic_min_records
                    and candidate.observed_value == analyzer.periodic_min_records
                    and candidate.source_ip == source_ip
                    and candidate.destination_ip == destination_ip
                    and candidate.destination_port == destination_port
                    and candidate.protocol == protocol
                    and candidate.session_key == session_key
                    and candidate.window_start == times[0]
                    and candidate.window_end == times[-1]
                    and candidate.uncertainty
                    == (
                        "exporter-reported-flow-end-time",
                        "ip-allowlisted-unauthenticated",
                        "sampling-unknown",
                        "source-port-excluded-from-endpoint-group",
                    )
                )
                continue

            require(candidate.rule_id == "destination-fanout.v2" and candidate.rule_version == "destination-fanout.v2")
            scope = basis.get("contributor_scope")
            if not isinstance(scope, dict) or basis.get("reference_flow_ids") != list(candidate.flow_ids):
                raise ValueError("invalid_candidate_identity")
            try:
                window_start = _parse_iso(str(scope["window_start"]))
                window_end = _parse_iso(str(scope["window_end"]))
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError("invalid_candidate_identity") from exc
            matching = tuple(
                row for row in source_rows
                if row["session_key"] == scope.get("session_key")
                and row["source_ip"] == scope.get("source_ip")
                and row["protocol"] == scope.get("protocol")
                and window_start <= _parse_iso(str(row["event_time"])) < window_end
            )
            contributors = tuple(
                sorted(
                    ({"destination_ip": str(row["destination_ip"]), "flow_id": str(row["flow_id"])} for row in matching),
                    key=lambda item: (item["destination_ip"], item["flow_id"]),
                )
            )
            expected_material = {
                "count": len(contributors),
                "sha256": _canonical_digest(contributors),
                "version": "candidate-contributors.v1",
            }
            if basis.get("contributor_material") != expected_material:
                raise ValueError("stale_source_snapshot")
            selected: list[str] = []
            seen: set[str] = set()
            for row in sorted(matching, key=lambda item: (item["destination_ip"], item["event_time"], item["flow_id"])):
                destination = str(row["destination_ip"])
                if destination not in seen:
                    seen.add(destination)
                    selected.append(str(row["flow_id"]))
                    if len(selected) == candidate.threshold:
                        break
            unique_destination_count = len({row["destination_ip"] for row in matching})
            expected_identity = {
                "contributor_material": expected_material,
                "contributor_scope": scope,
                "reference_flow_ids": sorted(selected),
                "rule_version": "destination-fanout.v2",
                "threshold": analyzer.fanout_destinations,
                "unique_destination_count": unique_destination_count,
            }
            expected_basis = {
                "basis": "unique_destination_fanout.v2",
                "contributor_material": expected_material,
                "contributor_scope": scope,
                "reference_selection": "one_flow_per_destination.destination_event_time_flow_id.v1",
                "reference_flow_ids": sorted(selected),
                "references_representative_bounded": True,
                "unique_destination_count": unique_destination_count,
            }
            require(
                identity == expected_identity
                and basis == expected_basis
                and tuple(sorted(selected)) == candidate.flow_ids
                and candidate.threshold == analyzer.fanout_destinations
                and candidate.observed_value == unique_destination_count
                and candidate.source_ip == scope["source_ip"]
                and candidate.destination_ip is None
                and candidate.destination_port is None
                and candidate.protocol == scope["protocol"]
                and candidate.session_key == scope["session_key"]
                and candidate.window_start == window_start
                and candidate.window_end == window_end
                and candidate.uncertainty == ("sampling-unknown", "ip-allowlisted-unauthenticated")
                and unique_destination_count >= analyzer.fanout_destinations
            )

    def _insert_candidate_facts(
        self,
        connection: sqlite3.Connection,
        *,
        candidates: tuple[Candidate, ...],
        detector_configuration_sha256: str,
    ) -> None:
        for candidate in candidates:
            connection.execute(
                """INSERT OR IGNORE INTO candidates(
                    candidate_id, rule_id, rule_version, created_at, window_start, window_end,
                    threshold, observed_value, source_ip, destination_ip, destination_port, protocol, session_key,
                    uncertainty_json, identity_material_json, basis_json, explanation, source_trust_state, detector_configuration_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    candidate.candidate_id,
                    candidate.rule_id,
                    candidate.rule_version,
                    _iso(candidate.created_at),
                    _iso(candidate.window_start),
                    _iso(candidate.window_end),
                    candidate.threshold,
                    candidate.observed_value,
                    candidate.source_ip,
                    candidate.destination_ip,
                    candidate.destination_port,
                    candidate.protocol,
                    candidate.session_key,
                    canonical_json(list(candidate.uncertainty)),
                    candidate.identity_material_json,
                    candidate.basis_json,
                    candidate.explanation,
                    SOURCE_TRUST_STATE,
                    detector_configuration_sha256,
                ),
            )
            connection.executemany(
                "INSERT OR IGNORE INTO candidate_flows(candidate_id, flow_id) VALUES (?, ?)",
                ((candidate.candidate_id, flow_id) for flow_id in candidate.flow_ids),
            )

    def commit_analysis_success(
        self,
        *,
        collection_run_id: str | None,
        detector_configuration_sha256: str,
        started_at: datetime,
        completed_at: datetime,
        candidates: Iterable[Candidate],
        input_snapshot_json: str,
    ) -> str:
        candidate_values = tuple(candidates)
        self._validate_candidate_values(candidate_values)
        snapshot = _validate_input_snapshot(input_snapshot_json, require_complete=True)
        analysis_run_id = uuid.uuid4().hex
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._delete_unreferenced_candidate_facts(connection)
                self._make_analysis_history_room(
                    connection,
                    required_candidate_instances=len(candidate_values),
                    candidates=candidate_values,
                    allow_replace_latest_failed=True,
                )
                # Recheck the exact immutable-generation source material in
                # this write transaction. A concurrent prune invalidates the
                # derivation instead of permitting evidence-less candidates.
                source_rows = self._validate_source_snapshot(connection, snapshot)
                self._validate_candidates_against_source(candidate_values, source_rows)
                connection.execute(
                    """INSERT INTO analysis_runs(
                        analysis_run_id, collection_run_id, detector_configuration_sha256, started_at, completed_at,
                        status, candidate_count, reason_code, input_snapshot_json
                    ) VALUES (?, ?, ?, ?, ?, 'completed', ?, NULL, ?)""",
                    (
                        analysis_run_id,
                        collection_run_id,
                        detector_configuration_sha256,
                        _iso(started_at),
                        _iso(completed_at),
                        len(candidate_values),
                        input_snapshot_json,
                    ),
                )
                self._insert_candidate_facts(
                    connection,
                    candidates=candidate_values,
                    detector_configuration_sha256=detector_configuration_sha256,
                )
                connection.executemany(
                    "INSERT INTO analysis_run_candidates(analysis_run_id, candidate_id) VALUES (?, ?)",
                    ((analysis_run_id, candidate.candidate_id) for candidate in candidate_values),
                )
                if self._root_usage_bytes() > self.max_storage_bytes:
                    raise ValueError("flow_store_quota_exceeded")
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                raise
        self._set_database_modes()
        return analysis_run_id

    @staticmethod
    def _run_payload(
        *, counters: Mapping[str, Any], last_received_at: datetime | None, last_persisted_at: datetime | None,
        last_error_code: str | None,
    ) -> tuple[str, str | None, str | None, str | None]:
        return (
            canonical_json(counters),
            _iso(last_received_at) if last_received_at is not None else None,
            _iso(last_persisted_at) if last_persisted_at is not None else None,
            last_error_code,
        )

    def start_collection_run(self, *, collector_configuration_sha256: str, started_at: datetime) -> str:
        run_id = uuid.uuid4().hex
        started = _iso(started_at)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    """INSERT INTO collection_runs(
                        run_id, collector_configuration_sha256, started_at, heartbeat_at, completed_at, state,
                        counters_json, last_received_at, last_persisted_at, last_error_code, audit_state
                    ) VALUES (?, ?, ?, ?, NULL, 'running', '{}', NULL, NULL, NULL, 'written')""",
                    (run_id, collector_configuration_sha256, started, started),
                )
                expired_run_ids = tuple(
                    str(row[0])
                    for row in connection.execute(
                        """SELECT run_id FROM collection_runs WHERE completed_at IS NOT NULL
                           ORDER BY started_at DESC LIMIT -1 OFFSET ?""",
                        (MAX_COLLECTION_RUNS,),
                    )
                )
                if expired_run_ids:
                    placeholders = ", ".join("?" for _ in expired_run_ids)
                    # Analysis derivations are only meaningful with their
                    # collection-run provenance.  Prune both sides together
                    # so bounded retention cannot leave dangling references
                    # or fail at a foreign-key rollover.
                    connection.execute(
                        f"DELETE FROM analysis_runs WHERE collection_run_id IN ({placeholders})",
                        expired_run_ids,
                    )
                    connection.execute(
                        f"DELETE FROM collection_runs WHERE run_id IN ({placeholders})",
                        expired_run_ids,
                    )
                    self._delete_unreferenced_candidate_facts(connection)
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
        self._set_database_modes()
        return run_id

    def heartbeat_collection_run(
        self,
        run_id: str,
        *,
        observed_at: datetime,
        counters: Mapping[str, Any],
        last_received_at: datetime | None,
        last_persisted_at: datetime | None,
        last_error_code: str | None,
    ) -> None:
        counters_json, last_received, last_persisted, error = self._run_payload(
            counters=counters,
            last_received_at=last_received_at,
            last_persisted_at=last_persisted_at,
            last_error_code=last_error_code,
        )
        with self._connect() as connection:
            changed = connection.execute(
                """UPDATE collection_runs SET heartbeat_at = ?, counters_json = ?, last_received_at = ?,
                   last_persisted_at = ?, last_error_code = ?
                   WHERE run_id = ? AND state = 'running' AND audit_state = 'written'""",
                (_iso(observed_at), counters_json, last_received, last_persisted, error, run_id),
            ).rowcount
        if changed != 1:
            raise RuntimeError("collection_run_heartbeat_unavailable")
        self._set_database_modes()

    def finish_collection_run(
        self,
        run_id: str,
        *,
        completed_at: datetime,
        state: str,
        counters: Mapping[str, Any],
        last_received_at: datetime | None,
        last_persisted_at: datetime | None,
        last_error_code: str | None,
    ) -> None:
        counters_json, last_received, last_persisted, error = self._run_payload(
            counters=counters,
            last_received_at=last_received_at,
            last_persisted_at=last_persisted_at,
            last_error_code=last_error_code,
        )
        with self._connect() as connection:
            changed = connection.execute(
                """UPDATE collection_runs SET heartbeat_at = ?, completed_at = ?, state = ?, counters_json = ?,
                   last_received_at = ?, last_persisted_at = ?, last_error_code = ?, audit_state = 'written'
                   WHERE run_id = ? AND state = 'running' AND audit_state = 'written'""",
                (_iso(completed_at), _iso(completed_at), state, counters_json, last_received, last_persisted, error, run_id),
            ).rowcount
        if changed != 1:
            raise RuntimeError("collection_run_finalization_unavailable")
        self._set_database_modes()

    def mark_collection_run_audit_unavailable(self, run_id: str, *, observed_at: datetime) -> None:
        """Best-effort durable warning when normal finalization was unavailable."""
        with self._connect() as connection:
            changed = connection.execute(
                """UPDATE collection_runs SET heartbeat_at = ?, completed_at = ?, state = 'finalization_unavailable',
                   last_error_code = 'collection_run_finalization_unavailable', audit_state = 'unavailable'
                   WHERE run_id = ? AND state = 'running'""",
                (_iso(observed_at), _iso(observed_at), run_id),
            ).rowcount
        if changed != 1:
            raise RuntimeError("collection_run_unavailable_marker_failed")
        self._set_database_modes()

    def record_analysis_run(
        self,
        *,
        collection_run_id: str | None,
        detector_configuration_sha256: str,
        started_at: datetime,
        completed_at: datetime,
        status: str,
        candidate_count: int,
        reason_code: str | None,
        input_snapshot_json: str,
    ) -> str:
        valid_failed = status == "failed" and candidate_count == 0 and reason_code in ANALYSIS_RUN_REASON_CODES
        # Completed results, including an exact zero-candidate result, must
        # take commit_analysis_success so the source-generation boundary is
        # recomputed inside its write transaction.
        if not valid_failed:
            raise ValueError("invalid_analysis_run")
        _validate_input_snapshot(input_snapshot_json, require_complete=False)
        analysis_run_id = uuid.uuid4().hex
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._make_analysis_history_room(
                    connection,
                    required_candidate_instances=0,
                    candidates=(),
                )
                if self._root_usage_bytes() + 65_536 > self.max_storage_bytes:
                    raise ValueError("flow_store_quota_exceeded")
                connection.execute(
                    """INSERT INTO analysis_runs(
                        analysis_run_id, collection_run_id, detector_configuration_sha256, started_at, completed_at,
                        status, candidate_count, reason_code, input_snapshot_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        analysis_run_id,
                        collection_run_id,
                        detector_configuration_sha256,
                        _iso(started_at),
                        _iso(completed_at),
                        status,
                        candidate_count,
                        reason_code,
                        input_snapshot_json,
                    ),
                )
                if self._root_usage_bytes() > self.max_storage_bytes:
                    raise ValueError("flow_store_quota_exceeded")
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                raise
        self._set_database_modes()
        return analysis_run_id

    @staticmethod
    def _analysis_run_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        try:
            input_snapshot = json.loads(row[8])
        except (TypeError, json.JSONDecodeError):
            input_snapshot = {"snapshot_state": "invalid"}
        return {
            "analysis_run_id": row[0],
            "candidate_count": row[6],
            "collection_run_id": row[1],
            "completed_at": row[4],
            "detector_configuration_sha256": row[2],
            "reason_code": row[7],
            "input_snapshot": input_snapshot if isinstance(input_snapshot, dict) else {"snapshot_state": "invalid"},
            "started_at": row[3],
            "status": row[5],
        }

    def latest_analysis_run(self) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """SELECT analysis_run_id, collection_run_id, detector_configuration_sha256, started_at, completed_at, status,
                          candidate_count, reason_code, input_snapshot_json
                   FROM analysis_runs ORDER BY started_at DESC, analysis_run_id DESC LIMIT 1"""
            ).fetchone()
        return self._analysis_run_row(row)

    def latest_analysis_run_for_collection(self, collection_run_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """SELECT analysis_run_id, collection_run_id, detector_configuration_sha256, started_at, completed_at, status,
                          candidate_count, reason_code, input_snapshot_json
                   FROM analysis_runs WHERE collection_run_id = ?
                   ORDER BY started_at DESC, analysis_run_id DESC LIMIT 1""",
                (collection_run_id,),
            ).fetchone()
        return self._analysis_run_row(row)

    def latest_collection_run(self) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """SELECT run_id, collector_configuration_sha256, started_at, heartbeat_at, completed_at, state,
                          counters_json, last_received_at, last_persisted_at, last_error_code, audit_state
                   FROM collection_runs ORDER BY started_at DESC LIMIT 1"""
            ).fetchone()
        if row is None:
            return None
        try:
            counters = json.loads(row[6])
        except (TypeError, json.JSONDecodeError):
            counters = {"health_record_invalid": 1}
        return {
            "audit_state": row[10],
            "collector_configuration_sha256": row[1],
            "completed_at": row[4],
            "counters": counters,
            "heartbeat_at": row[3],
            "last_error_code": row[9],
            "last_persisted_at": row[8],
            "last_received_at": row[7],
            "run_id": row[0],
            "started_at": row[2],
            "state": row[5],
            "terminal_state_confirmed": row[5] != "running" and row[10] == "written",
        }

    def candidate_rows(
        self,
        *,
        limit: int = 500,
        analysis_run_id: str | None = None,
    ) -> tuple[dict[str, Any], ...]:
        with self._connect() as connection:
            source_rows: tuple[dict[str, Any], ...] | None = None
            if analysis_run_id is not None:
                analysis = connection.execute(
                    "SELECT status, input_snapshot_json FROM analysis_runs WHERE analysis_run_id = ?",
                    (analysis_run_id,),
                ).fetchone()
                if analysis is None or analysis[0] != "completed":
                    return ()
                source_rows = self._validate_source_snapshot(
                    connection,
                    _validate_input_snapshot(str(analysis[1]), require_complete=True),
                )
            if analysis_run_id is None:
                rows = connection.execute(
                    """SELECT candidate_id, rule_id, rule_version, created_at, window_start, window_end, threshold,
                              observed_value, source_ip, destination_ip, destination_port, protocol, session_key,
                              uncertainty_json, identity_material_json, basis_json, explanation, source_trust_state,
                              detector_configuration_sha256
                       FROM candidates ORDER BY created_at DESC, candidate_id LIMIT ?""",
                    (limit,),
                ).fetchall()
            else:
                rows = connection.execute(
                    """SELECT candidates.candidate_id, candidates.rule_id, candidates.rule_version, candidates.created_at,
                              candidates.window_start, candidates.window_end, candidates.threshold, candidates.observed_value,
                              candidates.source_ip, candidates.destination_ip, candidates.destination_port, candidates.protocol,
                              candidates.session_key, candidates.uncertainty_json, candidates.identity_material_json, candidates.basis_json, candidates.explanation,
                              candidates.source_trust_state, candidates.detector_configuration_sha256
                       FROM candidates JOIN analysis_run_candidates
                         ON analysis_run_candidates.candidate_id = candidates.candidate_id
                       WHERE analysis_run_candidates.analysis_run_id = ?
                       ORDER BY candidates.created_at DESC, candidates.candidate_id LIMIT ?""",
                    (analysis_run_id, limit),
                ).fetchall()
            result: list[dict[str, Any]] = []
            candidate_values: list[Candidate] = []
            for row in rows:
                values = {key: row[key] for key in row.keys()}
                try:
                    basis_text = str(values.pop("basis_json"))
                    identity_material_json = str(values.pop("identity_material_json"))
                    basis = _canonical_object(basis_text, maximum_bytes=MAX_CANDIDATE_BASIS_BYTES)
                    identity = _canonical_object(identity_material_json, maximum_bytes=MAX_CANDIDATE_BASIS_BYTES)
                except (TypeError, ValueError, json.JSONDecodeError):
                    raise ValueError("candidate_fact_invalid")
                expected_id = hashlib.sha256(
                    f"{values['rule_id']}\0{canonical_json(identity)}".encode("utf-8")
                ).hexdigest()
                if expected_id != values["candidate_id"]:
                    raise ValueError("candidate_fact_invalid")
                flow_ids = tuple(
                    flow[0]
                    for flow in connection.execute(
                        "SELECT flow_id FROM candidate_flows WHERE candidate_id = ? ORDER BY flow_id",
                        (row["candidate_id"],),
                    )
                )
                if not 1 <= len(flow_ids) <= MAX_CANDIDATE_FLOW_REFS:
                    raise ValueError("candidate_fact_invalid")
                candidate_values.append(
                    Candidate(
                        candidate_id=str(values["candidate_id"]),
                        rule_id=str(values["rule_id"]),
                        rule_version=str(values["rule_version"]),
                        created_at=_parse_iso(str(values["created_at"])),
                        window_start=_parse_iso(str(values["window_start"])),
                        window_end=_parse_iso(str(values["window_end"])),
                        threshold=int(values["threshold"]),
                        observed_value=int(values["observed_value"]),
                        source_ip=values["source_ip"],
                        destination_ip=values["destination_ip"],
                        destination_port=values["destination_port"],
                        protocol=values["protocol"],
                        session_key=values["session_key"],
                        flow_ids=flow_ids,
                        uncertainty=tuple(json.loads(str(values["uncertainty_json"]))),
                        identity_material_json=identity_material_json,
                        basis_json=basis_text,
                        explanation=str(values["explanation"]),
                    )
                )
                values["basis"] = basis
                values["flow_ids"] = list(flow_ids)
                result.append(values)
            self._validate_candidate_values(tuple(candidate_values))
            if source_rows is not None:
                self._validate_candidates_against_source(tuple(candidate_values), source_rows)
        return tuple(result)

    def summary(self) -> dict[str, Any]:
        with self._connect() as connection:
            flow_count = connection.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
            candidate_count = connection.execute("SELECT COUNT(*) FROM candidates").fetchone()[0]
            candidate_instance_count = connection.execute("SELECT COUNT(*) FROM analysis_run_candidates").fetchone()[0]
            datagram_count = connection.execute("SELECT COUNT(*) FROM datagrams").fetchone()[0]
            top_sources = connection.execute(
                """SELECT source_ip, SUM(byte_count) AS byte_count FROM flows
                   GROUP BY source_ip ORDER BY byte_count DESC, source_ip LIMIT 10"""
            ).fetchall()
        return {
            "candidate_count": candidate_count,
            "candidate_instance_count": candidate_instance_count,
            "datagram_count": datagram_count,
            "flow_count": flow_count,
            "source_trust_state": SOURCE_TRUST_STATE,
            "storage_bytes": self._root_usage_bytes(),
            "latest_collection_run": self.latest_collection_run(),
            "latest_analysis_run": self.latest_analysis_run(),
            "top_sources": [{"source_ip": row[0], "byte_count": row[1]} for row in top_sources],
        }

    def prune_expired(self, cutoff: datetime) -> dict[str, int]:
        """Atomically prune expired evidence and only orphaned raw BLOBs.

        Completed analyses and candidates are removed so an analyst never sees
        a source snapshot or candidate whose contributing-flow set was pruned.
        Re-run analysis afterwards.
        """
        cutoff_text = _iso(cutoff)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                delivery_count = connection.execute("SELECT COUNT(*) FROM deliveries WHERE received_at < ?", (cutoff_text,)).fetchone()[0]
                analysis_run_count = connection.execute("DELETE FROM analysis_runs WHERE status = 'completed'").rowcount
                connection.execute("DELETE FROM candidates")
                connection.execute("DELETE FROM deliveries WHERE received_at < ?", (cutoff_text,))
                datagram_count = connection.execute(
                    "DELETE FROM datagrams WHERE NOT EXISTS (SELECT 1 FROM deliveries WHERE deliveries.datagram_id = datagrams.datagram_id)"
                ).rowcount
                raw_count = connection.execute(
                    """DELETE FROM raw_datagrams
                       WHERE NOT EXISTS (SELECT 1 FROM deliveries WHERE deliveries.raw_sha256 = raw_datagrams.raw_sha256)
                         AND NOT EXISTS (SELECT 1 FROM datagrams WHERE datagrams.raw_sha256 = raw_datagrams.raw_sha256)"""
                ).rowcount
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
        self._set_database_modes()
        return {
            "analysis_runs": analysis_run_count,
            "deliveries": delivery_count,
            "datagrams": datagram_count,
            "raw_datagrams": raw_count,
        }
