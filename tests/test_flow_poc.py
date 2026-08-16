from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from http.client import HTTPConnection
import json
from pathlib import Path
import socket
import sqlite3
import struct
import tempfile
import threading
import unittest
from unittest.mock import patch

from network_ai.contracts import canonical_json
from network_ai.flow_poc.analysis import FlowAnalyzer, analyze_and_record
from network_ai.flow_poc.collector import CollectorStats, FlowCollector, ListenerPolicy
from network_ai.flow_poc.__main__ import _listener_policy, _run_analyze, _run_listen
from network_ai.flow_poc.dashboard import dashboard_server
from network_ai.flow_poc.demo_data import _record, ipfix_message, netflow_v9_message, synthetic_demo_messages
from network_ai.flow_poc.models import FlowDecodeError
from network_ai.flow_poc.storage import FlowRepository


class FlowPocTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_directory.name) / "flow-store"
        self.repository = FlowRepository(self.root, max_storage_bytes=4 * 1024 * 1024)
        self.collector = FlowCollector(self.repository, ListenerPolicy())
        self.received_at = datetime(2026, 8, 15, tzinfo=timezone.utc)

    def tearDown(self) -> None:
        self.temp_directory.cleanup()

    def _ingest(self, raw: bytes, *, received_offset: int = 0):
        return self.collector.ingest_datagram(
            raw,
            exporter_ip="127.0.0.1",
            exporter_port=20_555,
            received_at=self.received_at + timedelta(seconds=received_offset),
            now_monotonic=float(received_offset),
        )

    def _persist_periodic_rows(
        self,
        offsets_microseconds: tuple[int, ...],
        *,
        destination_port: int = 443,
        protocol: int = 6,
    ) -> tuple[dict[str, object], ...]:
        records = tuple(
            _record(
                "198.51.100.200",
                "203.0.113.200",
                source_port=40_000 + index,
                destination_port=destination_port,
                protocol=protocol,
            )
            for index in range(len(offsets_microseconds))
        )
        self._ingest(netflow_v9_message(sequence=1, include_template=True, records=records))
        with self.repository._connect() as connection:
            flow_ids = [
                str(row[0])
                for row in connection.execute("SELECT flow_id FROM flows ORDER BY record_index, flow_id")
            ]
            for flow_id, offset in zip(flow_ids, offsets_microseconds):
                value = (self.received_at + timedelta(microseconds=offset)).isoformat(timespec="microseconds").replace("+00:00", "Z")
                connection.execute(
                    "UPDATE flows SET event_time = ?, flow_start_time = ?, flow_end_time = ? WHERE flow_id = ?",
                    (value, value, value, flow_id),
                )
        return self.repository.flow_rows(limit=None)

    def _periodic_row(
        self,
        index: int,
        offset_microseconds: int,
        *,
        source_port: int = 40_000,
        destination_port: int = 443,
        protocol: int = 6,
    ) -> dict[str, object]:
        value = (self.received_at + timedelta(microseconds=offset_microseconds)).isoformat(timespec="microseconds").replace("+00:00", "Z")
        return {
            "flow_id": f"{index:064x}",
            "session_key": "synthetic-session",
            "event_time": value,
            "flow_end_time": value,
            "source_ip": "198.51.100.200",
            "destination_ip": "203.0.113.200",
            "source_port": source_port,
            "destination_port": destination_port,
            "protocol": protocol,
            "byte_count": 1_024,
            "packet_count": 1,
        }

    @staticmethod
    def _complete_input_snapshot() -> str:
        return canonical_json(
            {
                "effective_flow_limit": 1,
                "flow_count": 0,
                "material_sha256": "0" * 64,
                "selection": "complete_retained_flow_repository.v1",
                "snapshot_state": "complete",
                "source_generation_lte": 0,
                "version": "flow-analysis-input-snapshot.v1",
            }
        )

    @staticmethod
    def _failed_input_snapshot() -> str:
        return canonical_json(
            {
                "selection": "complete_retained_flow_repository.v1",
                "snapshot_state": "unavailable",
                "version": "flow-analysis-input-snapshot.v1",
            }
        )

    def _commit_completed_analysis(
        self,
        repository: FlowRepository | None = None,
        *,
        at: datetime | None = None,
        collection_run_id: str | None = None,
    ) -> str:
        target = repository or self.repository
        completed_at = at or self.received_at
        analyzer = FlowAnalyzer()
        derivation = analyzer.derive_repository(target, now=completed_at)
        return target.commit_analysis_success(
            collection_run_id=collection_run_id,
            detector_configuration_sha256=analyzer.configuration_sha256,
            started_at=completed_at,
            completed_at=completed_at,
            candidates=derivation.candidates,
            input_snapshot_json=derivation.input_snapshot_json,
        )

    @staticmethod
    def _options_template_set(version: int, template_id: int = 300) -> bytes:
        # Retained only as bounded metadata: octet count is never decoded.
        field = struct.pack("!HH", 1, 4)
        record = (
            struct.pack("!HHH", template_id, 4, 0) + field
            if version == 9
            else struct.pack("!HHH", template_id, 1, 1) + field
        )
        return struct.pack("!HH", 1 if version == 9 else 3, 4 + len(record)) + record

    @staticmethod
    def _data_set(template_id: int, payload: bytes) -> bytes:
        return struct.pack("!HH", template_id, 4 + len(payload)) + payload

    @staticmethod
    def _with_extra_set(message: bytes, version: int, extra_set: bytes) -> bytes:
        header_length = 20 if version == 9 else 16
        body = extra_set + message[header_length:]
        if version == 9:
            _version, count, uptime, export_seconds, sequence, source_id = struct.unpack("!HHIIII", message[:20])
            return struct.pack("!HHIIII", 9, count, uptime, export_seconds, sequence, source_id) + body
        _version, _length, export_seconds, sequence, domain_id = struct.unpack("!HHIII", message[:16])
        return struct.pack("!HHIII", 10, 16 + len(body), export_seconds, sequence, domain_id) + body

    @staticmethod
    def _unused_loopback_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind(("127.0.0.1", 0))
            return int(probe.getsockname()[1])

    def _serve_loopback(self, message: bytes, *, root: Path) -> tuple[FlowRepository, object]:
        repository = FlowRepository(root)
        port = self._unused_loopback_port()
        collector = FlowCollector(
            repository,
            ListenerPolicy(port=port, duration_seconds=5, max_datagrams=1),
            auto_analyze=True,
        )
        ready = threading.Event()
        holder: dict[str, object] = {}
        thread = threading.Thread(target=lambda: holder.setdefault("stats", collector.serve(ready_event=ready)), daemon=True)
        thread.start()
        self.assertTrue(ready.wait(timeout=3))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.sendto(message, ("127.0.0.1", port))
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        return repository, holder["stats"]

    def test_end_to_end_v9_ipfix_analysis_and_provenance(self) -> None:
        outcomes = [self._ingest(message, received_offset=index) for index, message in enumerate(synthetic_demo_messages())]
        self.assertEqual([outcome.status for outcome in outcomes], ["accepted", "accepted"])
        self.assertEqual(sum(len(outcome.inserted_flow_ids) for outcome in outcomes), 21)
        self.assertTrue(self.repository.foreign_keys_enabled())
        analysis = analyze_and_record(self.repository, now=self.received_at + timedelta(seconds=10), bounded=False)
        candidates = analysis.candidates
        self.assertEqual({candidate.rule_id for candidate in candidates}, {"high-volume.v1", "destination-fanout.v2"})
        assert analysis.analysis_run_id is not None
        stored = self.repository.candidate_rows(analysis_run_id=analysis.analysis_run_id)
        self.assertEqual(len(stored), 2)
        self.assertTrue(all(row["source_trust_state"] == "ip_allowlisted_unauthenticated" for row in stored))
        self.assertTrue(all(row["flow_ids"] for row in stored))

    def test_periodic_flow_candidate_has_stable_exporter_time_basis_and_ignores_source_port_churn(self) -> None:
        rows = tuple(
            self._periodic_row(index, index * 60 * 1_000_000, source_port=40_000 + index)
            for index in range(4)
        )
        reversed_rows = tuple(reversed(rows))
        candidates = FlowAnalyzer().analyze(rows, now=self.received_at)
        reversed_candidates = FlowAnalyzer().analyze(reversed_rows, now=self.received_at)
        periodic = tuple(candidate for candidate in candidates if candidate.rule_id == "periodic-flow.v1")
        self.assertEqual(len(periodic), 1)
        self.assertEqual(periodic[0].candidate_id, next(candidate for candidate in reversed_candidates if candidate.rule_id == "periodic-flow.v1").candidate_id)
        self.assertEqual(periodic[0].flow_ids, tuple(row["flow_id"] for row in rows))
        basis = json.loads(periodic[0].basis_json)
        self.assertEqual(basis["median_interval_microseconds"], 60 * 1_000_000)
        self.assertEqual(basis["allowed_deviation_microseconds"], 6 * 1_000_000)
        self.assertEqual(basis["maximum_deviation_microseconds"], 0)
        self.assertTrue(basis["source_port_excluded_from_group"])
        self.assertNotIn("raw", periodic[0].basis_json.lower())
        self.assertIn("not causation", periodic[0].explanation)

    def test_periodic_flow_boundaries_and_ineligible_endpoint_data_never_force_a_candidate(self) -> None:
        at_tolerance = tuple(
            self._periodic_row(index, offset, source_port=40_000 + index)
            for index, offset in enumerate((0, 60_000_000, 126_000_000, 186_000_000))
        )
        self.assertEqual(
            len([candidate for candidate in FlowAnalyzer().analyze(at_tolerance, now=self.received_at) if candidate.rule_id == "periodic-flow.v1"]),
            1,
        )
        outside_tolerance = tuple(
            self._periodic_row(index, offset, source_port=40_000 + index)
            for index, offset in enumerate((0, 60_000_000, 126_000_001, 186_000_001))
        )
        self.assertEqual(
            [candidate for candidate in FlowAnalyzer().analyze(outside_tolerance, now=self.received_at) if candidate.rule_id == "periodic-flow.v1"],
            [],
        )
        invalid_variants = (
            tuple({**row, "flow_end_time": None} for row in at_tolerance),
            tuple({**row, "source_port": 0} for row in at_tolerance),
            tuple({**row, "destination_port": 0} for row in at_tolerance),
            tuple({**row, "protocol": 1} for row in at_tolerance),
            tuple({**row, "destination_port": 8443 if index % 2 else 443} for index, row in enumerate(at_tolerance)),
            tuple({**row, "protocol": 17 if index % 2 else 6} for index, row in enumerate(at_tolerance)),
            tuple({**row, "flow_end_time": at_tolerance[0]["flow_end_time"]} for row in at_tolerance),
        )
        for variant in invalid_variants:
            with self.subTest(variant=variant[0].get("protocol")):
                self.assertEqual(
                    [candidate for candidate in FlowAnalyzer().analyze(variant, now=self.received_at) if candidate.rule_id == "periodic-flow.v1"],
                    [],
                )

    def test_periodic_group_cap_is_fail_visible_before_partial_candidate_output(self) -> None:
        rows = (
            self._periodic_row(0, 0, destination_port=443),
            self._periodic_row(1, 60_000_000, destination_port=8443),
        )
        with patch("network_ai.flow_poc.analysis.MAX_PERIODIC_GROUPS", 1):
            with self.assertRaisesRegex(ValueError, "periodic_group_limit_exceeded"):
                FlowAnalyzer().analyze(rows, now=self.received_at)

    def test_periodic_single_endpoint_group_is_bounded_by_snapshot_not_a_group_record_cap(self) -> None:
        rows = tuple(
            self._periodic_row(index, index * 60_000_000, source_port=40_000 + index)
            for index in range(5)
        )
        with patch("network_ai.flow_poc.analysis.MAX_PERIODIC_GROUPS", 1):
            candidates = FlowAnalyzer().analyze(rows, now=self.received_at)
        periodic = tuple(candidate for candidate in candidates if candidate.rule_id == "periodic-flow.v1")
        self.assertEqual(len(periodic), 2)
        self.assertEqual(periodic[0].flow_ids, tuple(row["flow_id"] for row in rows[:4]))
        self.assertEqual(periodic[1].flow_ids, tuple(row["flow_id"] for row in rows[1:]))

    def test_periodic_snapshot_history_is_atomic_bounded_and_never_current_after_failure(self) -> None:
        rows = self._persist_periodic_rows((0, 60_000_000, 120_000_000, 180_000_000, 240_000_000))
        first = analyze_and_record(self.repository, now=self.received_at, bounded=False)
        second = analyze_and_record(self.repository, now=self.received_at + timedelta(seconds=1), bounded=False)
        self.assertEqual(first.status, "completed")
        self.assertEqual(second.status, "completed")
        assert first.analysis_run_id is not None and second.analysis_run_id is not None
        first_rows = self.repository.candidate_rows(analysis_run_id=first.analysis_run_id)
        second_rows = self.repository.candidate_rows(analysis_run_id=second.analysis_run_id)
        self.assertEqual({row["candidate_id"] for row in first_rows}, {row["candidate_id"] for row in second_rows})
        self.assertEqual(self.repository.summary()["candidate_instance_count"], len(first_rows) + len(second_rows))
        periodic = next(row for row in second_rows if row["rule_id"] == "periodic-flow.v1")
        self.assertEqual(periodic["destination_ip"], "203.0.113.200")
        self.assertEqual(periodic["destination_port"], 443)
        self.assertEqual(periodic["basis"]["minimum_records"], 4)

        with patch("network_ai.flow_poc.analysis.MAX_ANALYSIS_CANDIDATES", 1):
            failed = analyze_and_record(self.repository, now=self.received_at + timedelta(seconds=2), bounded=False)
        self.assertEqual(failed.status, "failed")
        self.assertEqual(failed.reason_code, "periodic_candidate_limit_exceeded")
        failed_snapshot = self.repository.latest_analysis_run()
        assert failed_snapshot is not None
        self.assertEqual(failed_snapshot["input_snapshot"]["snapshot_state"], "complete")
        self.assertEqual(failed_snapshot["input_snapshot"]["flow_count"], len(rows))
        self.assertIsInstance(failed_snapshot["input_snapshot"]["source_generation_lte"], int)
        self.assertEqual(len(failed_snapshot["input_snapshot"]["material_sha256"]), 64)
        self.assertIsNone(self.repository.latest_analysis_run_for_collection("not-a-run"))
        latest = self.repository.summary()["latest_analysis_run"]
        assert latest is not None
        self.assertEqual(latest["status"], "failed")
        self.assertEqual(self.repository.candidate_rows(analysis_run_id=latest["analysis_run_id"]), ())
        self.assertEqual({row["candidate_id"] for row in self.repository.candidate_rows(analysis_run_id=second.analysis_run_id)}, {row["candidate_id"] for row in second_rows})
        server = dashboard_server(self.root, port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
            connection.request("GET", "/api/candidates")
            payload = json.loads(connection.getresponse().read().decode("utf-8"))
            self.assertEqual(payload["analysis_status"], "failed")
            self.assertEqual(payload["candidates"], [])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

        with patch("network_ai.flow_poc.storage.MAX_ANALYSIS_RUNS", 1):
            retained = analyze_and_record(self.repository, now=self.received_at + timedelta(seconds=3), bounded=False)
        self.assertEqual(retained.status, "completed")
        with self.repository._connect() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM analysis_runs").fetchone()[0], 1)
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM analysis_run_candidates").fetchone()[0],
                len(self.repository.candidate_rows(analysis_run_id=self.repository.summary()["latest_analysis_run"]["analysis_run_id"])),
            )
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_candidate_snapshot_commit_rolls_back_on_post_fact_write_failure(self) -> None:
        self._persist_periodic_rows((0, 60_000_000, 120_000_000, 180_000_000))
        original = self.repository._insert_candidate_facts

        def fail_after_insert(*args, **kwargs):
            original(*args, **kwargs)
            raise RuntimeError("test_commit_failure")

        with patch.object(self.repository, "_insert_candidate_facts", side_effect=fail_after_insert):
            outcome = analyze_and_record(self.repository, now=self.received_at, bounded=False)
        self.assertEqual(outcome.audit_state, "unavailable")
        self.assertIsNone(outcome.analysis_run_id)
        self.assertEqual(self.repository.summary()["candidate_count"], 0)
        self.assertEqual(self.repository.summary()["candidate_instance_count"], 0)
        self.assertIsNone(self.repository.summary()["latest_analysis_run"])

    def test_commit_recomputes_high_volume_and_periodic_candidates_from_source(self) -> None:
        self._ingest(synthetic_demo_messages()[0])
        analyzer = FlowAnalyzer()
        high_derivation = analyzer.derive_repository(self.repository, now=self.received_at)
        high = next(candidate for candidate in high_derivation.candidates if candidate.rule_id == "high-volume.v1")
        forged_high = replace(high, observed_value=high.observed_value + 1)
        with self.assertRaisesRegex(ValueError, "invalid_candidate_identity"):
            self.repository.commit_analysis_success(
                collection_run_id=None,
                detector_configuration_sha256=analyzer.configuration_sha256,
                started_at=self.received_at,
                completed_at=self.received_at,
                candidates=(forged_high,),
                input_snapshot_json=high_derivation.input_snapshot_json,
            )

        periodic_root = Path(self.temp_directory.name) / "periodic-forgery"
        periodic_repository = FlowRepository(periodic_root, max_storage_bytes=4 * 1024 * 1024)
        periodic_collector = FlowCollector(periodic_repository, ListenerPolicy())
        records = tuple(
            _record("198.51.100.201", "203.0.113.201", source_port=40_100 + index)
            for index in range(4)
        )
        periodic_collector.ingest_datagram(
            netflow_v9_message(sequence=1, include_template=True, records=records),
            exporter_ip="127.0.0.1",
            exporter_port=20_556,
            received_at=self.received_at,
        )
        with periodic_repository._connect() as connection:
            flow_ids = tuple(str(row[0]) for row in connection.execute("SELECT flow_id FROM flows ORDER BY record_index"))
            for index, flow_id in enumerate(flow_ids):
                value = (self.received_at + timedelta(seconds=index * 60)).isoformat(timespec="microseconds").replace("+00:00", "Z")
                connection.execute(
                    "UPDATE flows SET event_time = ?, flow_start_time = ?, flow_end_time = ? WHERE flow_id = ?",
                    (value, value, value, flow_id),
                )
        periodic_derivation = analyzer.derive_repository(periodic_repository, now=self.received_at)
        periodic = next(candidate for candidate in periodic_derivation.candidates if candidate.rule_id == "periodic-flow.v1")
        forged_periodic = replace(periodic, destination_port=8443)
        with self.assertRaisesRegex(ValueError, "invalid_candidate_identity"):
            periodic_repository.commit_analysis_success(
                collection_run_id=None,
                detector_configuration_sha256=analyzer.configuration_sha256,
                started_at=self.received_at,
                completed_at=self.received_at,
                candidates=(forged_periodic,),
                input_snapshot_json=periodic_derivation.input_snapshot_json,
            )
        self.assertIsNone(periodic_repository.latest_analysis_run())

    def test_periodic_candidate_history_mapping_is_bounded_without_orphans(self) -> None:
        self._persist_periodic_rows((0, 60_000_000, 120_000_000, 180_000_000))
        self.repository.max_candidate_instances = 1
        first = analyze_and_record(self.repository, now=self.received_at, bounded=False)
        second = analyze_and_record(self.repository, now=self.received_at + timedelta(seconds=1), bounded=False)
        self.assertEqual(first.status, "completed")
        self.assertEqual(second.status, "completed")
        assert second.analysis_run_id is not None
        self.assertEqual(self.repository.summary()["candidate_instance_count"], 1)
        self.assertEqual(len(self.repository.candidate_rows(analysis_run_id=second.analysis_run_id)), 1)
        with self.repository._connect() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM analysis_runs").fetchone()[0], 1)
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_template_cache_allows_later_data_and_malformed_input_has_no_state_mutation(self) -> None:
        first_record = _record("198.51.100.1", "203.0.113.1")
        self._ingest(netflow_v9_message(sequence=1, include_template=True, records=(first_record,)))
        second_record = _record("198.51.100.1", "203.0.113.2")
        self._ingest(netflow_v9_message(sequence=2, include_template=False, records=(second_record,)), received_offset=1)
        self.assertEqual(self.repository.summary()["flow_count"], 2)
        malformed = netflow_v9_message(sequence=3, include_template=False, records=(second_record,))[:-2]
        with self.assertRaisesRegex(FlowDecodeError, "invalid_set_length"):
            self._ingest(malformed, received_offset=2)
        third_record = _record("198.51.100.1", "203.0.113.3")
        self._ingest(netflow_v9_message(sequence=4, include_template=False, records=(third_record,)), received_offset=3)
        self.assertEqual(self.repository.summary()["flow_count"], 3)

    def test_standard_unretained_template_fields_are_skipped_safely(self) -> None:
        # MikroTik v9 templates may include fields such as ToS (5) that this
        # POC does not retain.  The fixed-width field remains part of the
        # record boundary, but it must not prevent decoding core flow metadata.
        fields = (
            (8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (2, 4), (1, 4), (5, 1),
        )
        template_id = 300
        template = struct.pack("!HH", template_id, len(fields)) + b"".join(struct.pack("!HH", *field) for field in fields)
        template_set = struct.pack("!HH", 0, 4 + len(template)) + template
        record = _record("198.51.100.2", "203.0.113.2") + b"\x00"
        data_set = struct.pack("!HH", template_id, 4 + len(record)) + record
        message = struct.pack("!HHIIII", 9, 1, 60_000, 1_786_780_800, 1, 42) + template_set + data_set
        self.assertEqual(self._ingest(message).status, "accepted")
        stored = self.repository.flow_rows(limit=None)
        self.assertEqual(stored[0]["source_ip"], "198.51.100.2")

    def test_duplicate_replay_conflict_and_reset_require_new_template(self) -> None:
        record = _record("198.51.100.2", "203.0.113.2")
        initial = netflow_v9_message(sequence=1, include_template=True, records=(record,))
        self.assertEqual(self._ingest(initial).status, "accepted")
        self.assertEqual(self._ingest(initial, received_offset=1).status, "duplicate_delivery")
        replay = netflow_v9_message(sequence=2, include_template=False, records=(record,))
        self.assertEqual(self._ingest(replay, received_offset=2).status, "possible_replay")
        conflict = netflow_v9_message(sequence=2, include_template=True, records=(_record("198.51.100.2", "203.0.113.3"),))
        self.assertEqual(self._ingest(conflict, received_offset=3).status, "sequence_conflict")
        with self.assertRaisesRegex(FlowDecodeError, "template_missing_or_expired"):
            self._ingest(netflow_v9_message(sequence=3, include_template=False, records=(record,)), received_offset=4)
        recovered = self._ingest(
            netflow_v9_message(sequence=4, include_template=True, records=(_record("198.51.100.2", "203.0.113.4"),)),
            received_offset=5,
        )
        self.assertEqual(recovered.status, "accepted")
        self.assertGreaterEqual(self.collector.stats.sequence_conflicts, 1)

    def test_listener_policy_filters_before_parser_and_rejects_unsafe_bind(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsafe_or_invalid_bind"):
            ListenerPolicy(bind_host="0.0.0.0")
        with self.assertRaisesRegex(ValueError, "nonloopback_requires_explicit_opt_in"):
            ListenerPolicy(bind_host="192.0.2.10", exporter_allowlist=("192.0.2.20/32",))
        with self.assertRaisesRegex(ValueError, "bind_host_must_be_literal_ip"):
            ListenerPolicy(bind_host="collector.example")
        with self.assertRaisesRegex(ValueError, "nonloopback_requires_host_exporter_allowlist"):
            ListenerPolicy(
                bind_host="192.0.2.10",
                exporter_allowlist=("0.0.0.0/0",),
                allow_nonloopback=True,
            )
        with self.assertRaisesRegex(ValueError, "listener_runtime_limits_invalid"):
            ListenerPolicy(duration_seconds=3_601)
        with self.assertRaisesRegex(FlowDecodeError, "exporter_not_allowlisted"):
            self.collector.ingest_datagram(
                b"not parsed",
                exporter_ip="192.0.2.99",
                exporter_port=2055,
                received_at=self.received_at,
            )
        self.assertEqual(self.repository.summary()["datagram_count"], 0)

    def test_ipfix_and_untrusted_template_forms_are_handled_without_state_mutation(self) -> None:
        valid = ipfix_message(
            sequence=1,
            include_template=True,
            records=(_record("198.51.100.6", "203.0.113.6", protocol=17),),
        )
        self.assertEqual(self._ingest(valid).status, "accepted")
        malformed_length = bytearray(valid)
        struct.pack_into("!H", malformed_length, 2, len(valid) - 1)
        with self.assertRaisesRegex(FlowDecodeError, "ipfix_declared_length_mismatch"):
            self._ingest(bytes(malformed_length), received_offset=1)
        variable_template = (
            struct.pack("!HHIII", 10, 28, 1_786_780_800, 2, 84)
            + struct.pack("!HHHHHH", 2, 12, 300, 1, 1, 65_535)
        )
        with self.assertRaisesRegex(FlowDecodeError, "unsupported_variable_length_field"):
            self._ingest(variable_template, received_offset=2)
        options_message = struct.pack("!HHIIIHH", 10, 20, 1_786_780_800, 3, 84, 3, 4)
        with self.assertRaisesRegex(FlowDecodeError, "empty_options_template_set"):
            self._ingest(options_message, received_offset=3)
        self.assertEqual(self.repository.summary()["flow_count"], 1)

    def test_options_metadata_is_ignored_without_losing_mixed_v9_or_ipfix_flows(self) -> None:
        for version, message in (
            (9, netflow_v9_message(sequence=1, include_template=True, records=(_record("198.51.100.61", "203.0.113.61"),))),
            (10, ipfix_message(sequence=1, include_template=True, records=(_record("198.51.100.62", "203.0.113.62"),))),
        ):
            with self.subTest(version=version):
                repository = FlowRepository(Path(self.temp_directory.name) / f"options-{version}")
                collector = FlowCollector(repository, ListenerPolicy())
                mixed = self._with_extra_set(message, version, self._options_template_set(version))
                outcome = collector.ingest_datagram(
                    mixed,
                    exporter_ip="127.0.0.1",
                    exporter_port=20_555,
                    received_at=self.received_at,
                    now_monotonic=0,
                )
                self.assertEqual(outcome.status, "accepted")
                self.assertEqual(repository.summary()["flow_count"], 1)

                data_only = (
                    netflow_v9_message(sequence=2, include_template=False, records=(_record("198.51.100.61", "203.0.113.63"),))
                    if version == 9
                    else ipfix_message(sequence=2, include_template=False, records=(_record("198.51.100.62", "203.0.113.64"),))
                )
                with_options_data = self._with_extra_set(data_only, version, self._data_set(300, b"\x00\x00\x00\x00"))
                self.assertEqual(
                    collector.ingest_datagram(
                        with_options_data,
                        exporter_ip="127.0.0.1",
                        exporter_port=20_555,
                        received_at=self.received_at + timedelta(seconds=1),
                        now_monotonic=1,
                    ).status,
                    "accepted",
                )
                self.assertEqual(repository.summary()["flow_count"], 2)
                self.assertEqual(collector.stats.options_data_ignored, 1)

                malformed_options = self._with_extra_set(data_only, version, self._data_set(300, b"\x01"))
                before_malformed = repository.summary()["flow_count"]
                with self.assertRaisesRegex(FlowDecodeError, "options_data_set_record_length_mismatch"):
                    collector.ingest_datagram(
                        malformed_options,
                        exporter_ip="127.0.0.1",
                        exporter_port=20_555,
                        received_at=self.received_at + timedelta(seconds=2),
                        now_monotonic=2,
                    )
                self.assertEqual(repository.summary()["flow_count"], before_malformed)

                unknown_options = self._with_extra_set(data_only, version, self._data_set(301, b"\x00\x00\x00\x00"))
                before = repository.summary()["flow_count"]
                with self.assertRaisesRegex(FlowDecodeError, "template_missing_or_expired"):
                    collector.ingest_datagram(
                        unknown_options,
                        exporter_ip="127.0.0.1",
                        exporter_port=20_555,
                        received_at=self.received_at + timedelta(seconds=3),
                        now_monotonic=3,
                    )
                self.assertEqual(repository.summary()["flow_count"], before)

                collision = self._with_extra_set(message, version, self._options_template_set(version, template_id=256))
                with self.assertRaisesRegex(FlowDecodeError, "template_type_collision"):
                    collector.ingest_datagram(
                        collision,
                        exporter_ip="127.0.0.1",
                        exporter_port=20_555,
                        received_at=self.received_at + timedelta(seconds=4),
                        now_monotonic=4,
                    )
                self.assertEqual(repository.summary()["flow_count"], before)

    def test_templates_are_isolated_by_exporter_udp_port(self) -> None:
        template_and_data = netflow_v9_message(
            sequence=1,
            include_template=True,
            records=(_record("198.51.100.7", "203.0.113.7"),),
        )
        self._ingest(template_and_data)
        data_only = netflow_v9_message(
            sequence=2,
            include_template=False,
            records=(_record("198.51.100.7", "203.0.113.8"),),
        )
        with self.assertRaisesRegex(FlowDecodeError, "template_missing_or_expired"):
            self.collector.ingest_datagram(
                data_only,
                exporter_ip="127.0.0.1",
                exporter_port=20_556,
                received_at=self.received_at,
            )

    def test_ttl_eviction_requires_a_fresh_template_before_reappearance(self) -> None:
        first = netflow_v9_message(sequence=1, include_template=True, records=(_record("198.51.100.70", "203.0.113.70"),))
        self._ingest(first)
        data_only = netflow_v9_message(sequence=2, include_template=False, records=(_record("198.51.100.70", "203.0.113.71"),))
        with self.assertRaisesRegex(FlowDecodeError, "template_missing_or_expired"):
            self._ingest(data_only, received_offset=601)
        reappeared = netflow_v9_message(sequence=3, include_template=True, records=(_record("198.51.100.70", "203.0.113.72"),))
        self.assertEqual(self._ingest(reappeared, received_offset=602).status, "accepted")

    def test_live_loopback_udp_v9_and_ipfix_persist_and_update_dashboard_health(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for version, message in (
                (9, netflow_v9_message(sequence=1, include_template=True, records=(_record("198.51.100.81", "203.0.113.81"),))),
                (10, ipfix_message(sequence=1, include_template=True, records=(_record("198.51.100.82", "203.0.113.82"),))),
            ):
                with self.subTest(version=version):
                    repository, stats = self._serve_loopback(message, root=Path(directory) / f"live-{version}")
                    self.assertEqual(stats.run_state, "completed")
                    self.assertEqual(repository.summary()["flow_count"], 1)
                    latest = repository.summary()["latest_collection_run"]
                    assert latest is not None
                    self.assertEqual(latest["state"], "completed")
                    self.assertEqual(latest["counters"]["accepted"], 1)
                    analysis = repository.summary()["latest_analysis_run"]
                    assert analysis is not None
                    self.assertEqual(analysis["status"], "completed")
                    self.assertEqual(len(analysis["detector_configuration_sha256"]), 64)
                    server = dashboard_server(repository.root, port=0)
                    thread = threading.Thread(target=server.serve_forever, daemon=True)
                    thread.start()
                    try:
                        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                        connection.request("GET", "/api/summary")
                        payload = connection.getresponse().read().decode("utf-8")
                        self.assertIn('"flow_count": 1', payload)
                        self.assertIn('"latest_collection_run"', payload)
                    finally:
                        server.shutdown()
                        server.server_close()
                        thread.join(timeout=3)

    def test_dashboard_initializes_its_repository_once_for_multiple_requests(self) -> None:
        with patch("network_ai.flow_poc.dashboard.FlowRepository", wraps=FlowRepository) as repository_factory:
            server = dashboard_server(self.root, port=0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                connection.request("GET", "/api/summary")
                self.assertEqual(connection.getresponse().status, 200)
                connection.request("GET", "/api/flows")
                self.assertEqual(connection.getresponse().status, 200)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)
        self.assertEqual(repository_factory.call_count, 1)

    def test_state_capacity_is_visible_before_parsing_or_persisting(self) -> None:
        first = netflow_v9_message(sequence=1, include_template=True, records=(_record("198.51.100.90", "203.0.113.90"),))
        second = netflow_v9_message(sequence=1, include_template=True, records=(_record("198.51.100.91", "203.0.113.91"),))
        with patch("network_ai.flow_poc.collector.MAX_TRACKED_SESSIONS", 1):
            self._ingest(first)
            with self.assertRaisesRegex(FlowDecodeError, "session_state_limit"):
                self.collector.ingest_datagram(
                    second,
                    exporter_ip="127.0.0.1",
                    exporter_port=20_556,
                    received_at=self.received_at + timedelta(seconds=1),
                    now_monotonic=1,
                )
        self.assertEqual(self.repository.summary()["flow_count"], 1)
        self.assertEqual(self.collector.stats.session_state_rejected, 1)

    def test_headers_and_cli_allowlists_have_visible_exact_terminal_policy(self) -> None:
        for raw in (struct.pack("!H", 5), b"\x00"):
            with self.assertRaises(FlowDecodeError):
                self._ingest(raw)
        self.assertEqual(self.collector.stats.malformed, 2)
        self.assertEqual(sum(self.collector.stats.decode_error_codes.values()), 2)

        supplied = _listener_policy(
            SimpleNamespace(
                host="127.0.0.1",
                port=2055,
                exporter_allowlist=["192.0.2.20/32"],
                allow_nonloopback=False,
                duration_seconds=60,
                max_datagrams=10,
            )
        )
        self.assertEqual(supplied.exporter_allowlist, ("192.0.2.20/32",))
        defaulted = _listener_policy(
            SimpleNamespace(
                host="127.0.0.1",
                port=2055,
                exporter_allowlist=None,
                allow_nonloopback=False,
                duration_seconds=60,
                max_datagrams=10,
            )
        )
        self.assertEqual(defaulted.exporter_allowlist, ("127.0.0.1/32",))

    def test_ipfix_options_records_advance_sequence_without_false_discontinuity(self) -> None:
        first = self._with_extra_set(
            ipfix_message(sequence=1, include_template=True, records=(_record("198.51.100.94", "203.0.113.94"),)),
            10,
            self._options_template_set(10),
        )
        self.assertEqual(self._ingest(first).status, "accepted")
        second = self._with_extra_set(
            ipfix_message(sequence=2, include_template=False, records=(_record("198.51.100.94", "203.0.113.95"),)),
            10,
            self._data_set(300, b"\x00\x00\x00\x00"),
        )
        self.assertEqual(self._ingest(second, received_offset=1).status, "accepted")
        third = ipfix_message(sequence=4, include_template=False, records=(_record("198.51.100.94", "203.0.113.96"),))
        self.assertEqual(self._ingest(third, received_offset=2).status, "accepted")
        self.assertEqual(self.collector.stats.sequence_discontinuities, 0)

    def test_live_no_traffic_storage_failure_and_analysis_failure_are_visible(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            no_traffic = FlowRepository(Path(directory) / "no-traffic")
            stats = FlowCollector(no_traffic, ListenerPolicy(port=self._unused_loopback_port(), duration_seconds=1, max_datagrams=1)).serve()
            self.assertEqual(stats.run_state, "completed_no_accepted_datagrams")
            latest = no_traffic.summary()["latest_collection_run"]
            assert latest is not None
            self.assertEqual(latest["state"], "completed_no_accepted_datagrams")

            constrained_root = Path(directory) / "constrained-live"
            constrained = FlowRepository(constrained_root, max_storage_bytes=1_024)
            port = self._unused_loopback_port()
            collector = FlowCollector(constrained, ListenerPolicy(port=port, duration_seconds=5, max_datagrams=1))
            ready = threading.Event()
            holder: dict[str, object] = {}
            thread = threading.Thread(target=lambda: holder.setdefault("stats", collector.serve(ready_event=ready)), daemon=True)
            thread.start()
            self.assertTrue(ready.wait(timeout=3))
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                sender.sendto(netflow_v9_message(sequence=1, include_template=True, records=(_record("198.51.100.92", "203.0.113.92"),)), ("127.0.0.1", port))
            thread.join(timeout=5)
            self.assertEqual(holder["stats"].run_state, "persistence_failed")
            failed_run = constrained.summary()["latest_collection_run"]
            assert failed_run is not None
            self.assertEqual(failed_run["state"], "persistence_failed")

            with patch("network_ai.flow_poc.analysis.FlowAnalyzer.derive_repository", side_effect=RuntimeError("test")):
                analyzed, analyzed_stats = self._serve_loopback(
                    netflow_v9_message(sequence=1, include_template=True, records=(_record("198.51.100.93", "203.0.113.93"),)),
                    root=Path(directory) / "analysis-failed",
                )
            self.assertEqual(analyzed.summary()["flow_count"], 1)
            self.assertEqual(analyzed_stats.analysis_failures, 1)
            failed_analysis_run = analyzed.summary()["latest_collection_run"]
            assert failed_analysis_run is not None
            self.assertEqual(failed_analysis_run["counters"]["analysis_failures"], 1)

            unavailable = FlowRepository(Path(directory) / "run-audit-unavailable")
            with patch.object(unavailable, "start_collection_run", side_effect=RuntimeError("test")):
                unavailable_stats = FlowCollector(
                    unavailable,
                    ListenerPolicy(port=self._unused_loopback_port(), duration_seconds=1, max_datagrams=1),
                ).serve()
            self.assertEqual(unavailable_stats.run_state, "collection_run_audit_unavailable")
            self.assertEqual(unavailable_stats.run_audit_state, "unavailable")

            finalization = FlowRepository(Path(directory) / "finalization-unavailable")
            with patch.object(finalization, "finish_collection_run", side_effect=RuntimeError("test")):
                finalization_stats = FlowCollector(
                    finalization,
                    ListenerPolicy(port=self._unused_loopback_port(), duration_seconds=1, max_datagrams=1),
                ).serve()
            self.assertEqual(finalization_stats.run_audit_state, "unavailable")
            finalization_run = finalization.summary()["latest_collection_run"]
            assert finalization_run is not None
            self.assertEqual(finalization_run["state"], "finalization_unavailable")
            self.assertFalse(finalization_run["terminal_state_confirmed"])

    def test_live_finalization_retries_transient_sqlite_contention(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = FlowRepository(Path(directory) / "finalization-retry")
            collector = FlowCollector(
                repository,
                ListenerPolicy(port=self._unused_loopback_port(), duration_seconds=1, max_datagrams=1),
            )
            original_finish = repository.finish_collection_run
            failures = iter((sqlite3.OperationalError("database is locked"), None))

            def finish_after_one_transient_failure(*args, **kwargs):
                failure = next(failures)
                if failure is not None:
                    raise failure
                return original_finish(*args, **kwargs)

            with patch.object(repository, "finish_collection_run", side_effect=finish_after_one_transient_failure) as finish:
                stats = collector.serve()
            self.assertEqual(finish.call_count, 2)
            self.assertEqual(stats.run_audit_state, "written")
            self.assertEqual(stats.collection_run_audit_failures, 0)
            latest = repository.summary()["latest_collection_run"]
            assert latest is not None
            self.assertEqual(latest["state"], "completed_no_accepted_datagrams")
            self.assertTrue(latest["terminal_state_confirmed"])

    def test_analysis_audit_failure_does_not_relabel_a_completed_derivation(self) -> None:
        collector = FlowCollector(self.repository, ListenerPolicy(), auto_analyze=True)
        with patch.object(self.repository, "commit_analysis_success", side_effect=RuntimeError("audit unavailable")):
            outcome = collector.ingest_datagram(
                synthetic_demo_messages()[0],
                exporter_ip="127.0.0.1",
                exporter_port=20_555,
                received_at=self.received_at,
                now_monotonic=0,
            )
        self.assertEqual(outcome.status, "accepted")
        self.assertEqual(self.repository.summary()["flow_count"], 20)
        self.assertEqual(self.repository.summary()["candidate_count"], 0)
        self.assertEqual(collector.stats.analysis_runs, 1)
        self.assertEqual(collector.stats.analysis_failures, 0)
        self.assertEqual(collector.stats.analysis_audit_failures, 1)
        self.assertEqual(collector.stats.last_error_code, "analysis_audit_unavailable")
        self.assertIsNone(self.repository.summary()["latest_analysis_run"])

    def test_analysis_run_history_and_quota_are_bounded(self) -> None:
        with patch("network_ai.flow_poc.storage.MAX_ANALYSIS_RUNS", 2):
            for offset in range(3):
                self._commit_completed_analysis(at=self.received_at + timedelta(seconds=offset))
        with self.repository._connect() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM analysis_runs").fetchone()[0], 2)

        with tempfile.TemporaryDirectory() as directory:
            failed_repository = FlowRepository(Path(directory) / "failed-analysis-history")
            with patch("network_ai.flow_poc.storage.MAX_ANALYSIS_RUNS", 2):
                for offset in range(3):
                    failed_repository.record_analysis_run(
                        collection_run_id=None,
                        detector_configuration_sha256="a" * 64,
                        started_at=self.received_at + timedelta(seconds=offset),
                        completed_at=self.received_at + timedelta(seconds=offset),
                        status="failed",
                        candidate_count=0,
                        reason_code="analysis_input_limit_exceeded",
                        input_snapshot_json=self._failed_input_snapshot(),
                    )
            with failed_repository._connect() as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM analysis_runs").fetchone()[0], 2)

        with tempfile.TemporaryDirectory() as directory:
            constrained = FlowRepository(Path(directory) / "analysis-quota", max_storage_bytes=1_024)
            with self.assertRaisesRegex(ValueError, "flow_store_quota_exceeded"):
                self._commit_completed_analysis(constrained)
            with constrained._connect() as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM analysis_runs").fetchone()[0], 0)

    def test_collection_run_retention_prunes_referenced_analysis_rows_transactionally(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = FlowRepository(Path(directory) / "retention")
            with patch("network_ai.flow_poc.storage.MAX_COLLECTION_RUNS", 1):
                first = repository.start_collection_run(
                    collector_configuration_sha256="a" * 64,
                    started_at=self.received_at,
                )
                repository.finish_collection_run(
                    first,
                    completed_at=self.received_at,
                    state="completed",
                    counters={},
                    last_received_at=None,
                    last_persisted_at=None,
                    last_error_code=None,
                )
                self._commit_completed_analysis(repository, collection_run_id=first)
                second = repository.start_collection_run(
                    collector_configuration_sha256="a" * 64,
                    started_at=self.received_at + timedelta(seconds=1),
                )
                repository.finish_collection_run(
                    second,
                    completed_at=self.received_at + timedelta(seconds=1),
                    state="completed",
                    counters={},
                    last_received_at=None,
                    last_persisted_at=None,
                    last_error_code=None,
                )
                repository.start_collection_run(
                    collector_configuration_sha256="a" * 64,
                    started_at=self.received_at + timedelta(seconds=2),
                )
            with repository._connect() as connection:
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM analysis_runs WHERE collection_run_id = ?", (first,)).fetchone()[0],
                    0,
                )

    def test_manual_analysis_and_listener_exit_codes_require_durable_outcomes(self) -> None:
        self._ingest(netflow_v9_message(sequence=1, include_template=True, records=(_record("198.51.100.98", "203.0.113.98"),)))
        self.assertEqual(_run_analyze(SimpleNamespace(database=self.root)), 0)
        analysis = self.repository.summary()["latest_analysis_run"]
        assert analysis is not None
        self.assertEqual(analysis["status"], "completed")
        self.assertEqual(analysis["candidate_count"], 0)

        with patch("network_ai.flow_poc.analysis.FlowAnalyzer.derive_repository", side_effect=RuntimeError("test")):
            self.assertEqual(_run_analyze(SimpleNamespace(database=self.root)), 2)
        failed = self.repository.summary()["latest_analysis_run"]
        assert failed is not None
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["reason_code"], "analysis_failure")

        arguments = SimpleNamespace(
            database=self.root,
            host="127.0.0.1",
            port=self._unused_loopback_port(),
            exporter_allowlist=None,
            allow_nonloopback=False,
            duration_seconds=1,
            max_datagrams=1,
        )
        with patch(
            "network_ai.flow_poc.__main__.FlowCollector.serve",
            return_value=CollectorStats(run_state="completed", run_audit_state="unavailable"),
        ):
            self.assertEqual(_run_listen(arguments), 2)
        with patch(
            "network_ai.flow_poc.__main__.FlowCollector.serve",
            return_value=CollectorStats(run_state="completed", run_audit_state="written"),
        ):
            self.assertEqual(_run_listen(arguments), 0)
        with patch(
            "network_ai.flow_poc.__main__.FlowCollector.serve",
            return_value=CollectorStats(run_state="completed", run_audit_state="written", analysis_failures=1),
        ):
            self.assertEqual(_run_listen(arguments), 2)
        with patch(
            "network_ai.flow_poc.__main__.FlowCollector.serve",
            return_value=CollectorStats(run_state="completed", run_audit_state="written", analysis_audit_failures=1),
        ):
            self.assertEqual(_run_listen(arguments), 2)

    def test_explicit_analysis_binds_to_the_latest_durable_collection_run(self) -> None:
        collection_run_id = self.repository.start_collection_run(
            collector_configuration_sha256="a" * 64,
            started_at=self.received_at,
        )
        self.repository.finish_collection_run(
            collection_run_id,
            completed_at=self.received_at,
            state="completed",
            counters={},
            last_received_at=None,
            last_persisted_at=None,
            last_error_code=None,
        )
        self._ingest(
            netflow_v9_message(
                sequence=1,
                include_template=True,
                records=(_record("198.51.100.77", "203.0.113.77"),),
            )
        )
        self.assertEqual(_run_analyze(SimpleNamespace(database=self.root)), 0)
        latest = self.repository.summary()["latest_analysis_run"]
        assert latest is not None
        self.assertEqual(latest["collection_run_id"], collection_run_id)

    def test_stale_running_collection_run_is_marked_unclean_on_later_open(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "stale-run"
            repository = FlowRepository(root)
            repository.start_collection_run(
                collector_configuration_sha256="a" * 64,
                started_at=self.received_at - timedelta(minutes=1),
            )
            reopened = FlowRepository(root)
            latest = reopened.summary()["latest_collection_run"]
            assert latest is not None
            self.assertEqual(latest["state"], "unclean_shutdown")

    def test_ipfix_sequence_counts_data_records_and_allows_template_refresh(self) -> None:
        first = ipfix_message(
            sequence=10,
            include_template=True,
            records=(
                _record("198.51.100.8", "203.0.113.8"),
                _record("198.51.100.8", "203.0.113.9"),
            ),
        )
        self.assertEqual(self._ingest(first).status, "accepted")
        refresh = ipfix_message(sequence=10, include_template=True, records=())
        self.assertEqual(self._ingest(refresh, received_offset=1).status, "accepted")
        after_two_records = ipfix_message(
            sequence=12,
            include_template=False,
            records=(_record("198.51.100.8", "203.0.113.10"),),
        )
        self.assertEqual(self._ingest(after_two_records, received_offset=2).status, "accepted")
        self.assertEqual(self.collector.stats.sequence_discontinuities, 0)

    def test_ipfix_sequence_wrap_retains_the_template(self) -> None:
        first = ipfix_message(
            sequence=0xFFFFFFFF,
            include_template=True,
            records=(_record("198.51.100.80", "203.0.113.80"),),
        )
        self.assertEqual(self._ingest(first).status, "accepted")
        wrapped = ipfix_message(
            sequence=0,
            include_template=False,
            records=(_record("198.51.100.80", "203.0.113.81"),),
        )
        self.assertEqual(self._ingest(wrapped, received_offset=1).status, "accepted")
        self.assertEqual(self.collector.stats.sequence_discontinuities, 0)

    def test_malformed_same_sequence_body_is_never_retained_as_conflict_evidence(self) -> None:
        valid = netflow_v9_message(sequence=1, include_template=True, records=(_record("198.51.100.9", "203.0.113.9"),))
        self._ingest(valid)
        malicious = struct.pack("!HHIIII", 9, 0, 60_000, 1_786_780_800, 1, 42) + b"PAYLOAD-MUST-NOT-BE-STORED"
        with self.assertRaises(FlowDecodeError):
            self._ingest(malicious, received_offset=1)
        with self.repository._connect() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM raw_datagrams").fetchone()[0], 1)

    def test_replay_and_fanout_are_scoped_to_the_full_exporter_session(self) -> None:
        first = netflow_v9_message(
            sequence=1,
            include_template=True,
            records=tuple(_record("198.51.100.10", f"203.0.113.{20 + number}") for number in range(10)),
        )
        self._ingest(first)
        second = netflow_v9_message(
            sequence=1,
            include_template=True,
            records=tuple(_record("198.51.100.10", f"203.0.113.{30 + number}") for number in range(10)),
        )
        outcome = self.collector.ingest_datagram(
            second,
            exporter_ip="127.0.0.1",
            exporter_port=20_556,
            received_at=self.received_at,
        )
        self.assertEqual(outcome.status, "accepted")
        self.assertEqual(self.repository.summary()["flow_count"], 20)
        candidates = FlowAnalyzer(fanout_destinations=20).analyze_repository(self.repository, now=self.received_at)
        self.assertEqual(candidates, ())

    def test_manual_pruning_keeps_shared_raw_blob_until_every_reference_expires(self) -> None:
        raw = netflow_v9_message(sequence=1, include_template=True, records=(_record("198.51.100.5", "203.0.113.5"),))
        self._ingest(raw, received_offset=0)
        self._ingest(raw, received_offset=172_800)
        self.repository.prune_expired(self.received_at + timedelta(days=1))
        with self.repository._connect() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM raw_datagrams").fetchone()[0], 1)
        self.repository.prune_expired(self.received_at + timedelta(days=3))
        with self.repository._connect() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM raw_datagrams").fetchone()[0], 0)

    def test_pruning_invalidates_completed_snapshots_and_rolls_back_as_one_transaction(self) -> None:
        self._ingest(synthetic_demo_messages()[0])
        analysis = analyze_and_record(self.repository, now=self.received_at)
        assert analysis.analysis_run_id is not None
        self.assertTrue(self.repository.candidate_rows(analysis_run_id=analysis.analysis_run_id))
        with self.repository._connect() as connection:
            connection.execute(
                "CREATE TRIGGER fail_prune BEFORE DELETE ON deliveries "
                "BEGIN SELECT RAISE(ABORT, 'forced_prune_failure'); END"
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.repository.prune_expired(self.received_at + timedelta(days=1))
        self.assertEqual(self.repository.latest_analysis_run()["status"], "completed")
        self.assertTrue(self.repository.candidate_rows(analysis_run_id=analysis.analysis_run_id))
        with self.repository._connect() as connection:
            connection.execute("DROP TRIGGER fail_prune")
        result = self.repository.prune_expired(self.received_at + timedelta(days=1))
        self.assertGreaterEqual(result["analysis_runs"], 1)
        self.assertIsNone(self.repository.latest_analysis_run())
        self.assertEqual(self.repository.summary()["candidate_count"], 0)

    def test_completed_snapshot_legacy_migration_and_prune_race_are_visible(self) -> None:
        self._ingest(synthetic_demo_messages()[0])
        analyzer = FlowAnalyzer()
        derivation = analyzer.derive_repository(self.repository, now=self.received_at)
        self.repository.prune_expired(self.received_at + timedelta(days=1))
        with self.assertRaisesRegex(ValueError, "stale_source_snapshot"):
            self.repository.commit_analysis_success(
                collection_run_id=None,
                detector_configuration_sha256=analyzer.configuration_sha256,
                started_at=self.received_at,
                completed_at=self.received_at,
                candidates=derivation.candidates,
                input_snapshot_json=derivation.input_snapshot_json,
            )
        self.assertIsNone(self.repository.latest_analysis_run())

        self._ingest(synthetic_demo_messages()[0], received_offset=1)
        completed = analyze_and_record(self.repository, now=self.received_at + timedelta(seconds=1))
        assert completed.analysis_run_id is not None
        with self.repository._connect() as connection:
            connection.execute(
                "UPDATE analysis_runs SET input_snapshot_json = ? WHERE analysis_run_id = ?",
                (self._complete_input_snapshot(), completed.analysis_run_id),
            )
        reopened = FlowRepository(self.root, max_storage_bytes=4 * 1024 * 1024)
        migrated = reopened.latest_analysis_run()
        assert migrated is not None
        self.assertEqual(migrated["status"], "failed")
        self.assertEqual(migrated["reason_code"], "analysis_snapshot_legacy_unknown")
        self.assertEqual(reopened.summary()["candidate_count"], 0)

    def test_legacy_flow_store_adds_generation_column_before_its_index(self) -> None:
        self._ingest(netflow_v9_message(sequence=1, include_template=True, records=(_record("198.51.100.44", "203.0.113.44"),)))
        with self.repository._connect() as connection:
            connection.execute("DROP INDEX flows_source_generation")
            connection.execute("ALTER TABLE flows DROP COLUMN source_generation")
        reopened = FlowRepository(self.root, max_storage_bytes=4 * 1024 * 1024)
        rows, generation = reopened.analysis_source_snapshot(limit=2)
        self.assertEqual(len(rows), 1)
        self.assertGreater(generation, 0)
        self.assertGreater(rows[0]["source_generation"], 0)

    def test_quota_failure_rolls_back_raw_blob_and_related_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            constrained = FlowRepository(Path(directory) / "constrained", max_storage_bytes=1_024)
            collector = FlowCollector(constrained, ListenerPolicy())
            with self.assertRaisesRegex(ValueError, "flow_store_quota_exceeded"):
                collector.ingest_datagram(
                    synthetic_demo_messages()[0],
                    exporter_ip="127.0.0.1",
                    exporter_port=20_555,
                    received_at=self.received_at,
                )
            with constrained._connect() as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM raw_datagrams").fetchone()[0], 0)
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM datagrams").fetchone()[0], 0)

    def test_local_dashboard_escapes_output_and_exposes_json(self) -> None:
        self._ingest(synthetic_demo_messages()[0])
        self.assertEqual(analyze_and_record(self.repository, now=self.received_at, bounded=False).status, "completed")
        server = dashboard_server(self.root, port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
            connection.request("GET", "/")
            response = connection.getresponse()
            page = response.read().decode("utf-8")
            self.assertEqual(response.status, 200)
            self.assertIn("Current analyst candidates", page)
            self.assertIn("Analysis status", page)
            self.assertIn("Detector configuration", page)
            self.assertNotIn("<script", page.lower())
            connection.request("GET", "/api/summary")
            self.assertEqual(connection.getresponse().status, 200)
            connection.request("GET", "/api/candidates")
            candidates = json.loads(connection.getresponse().read().decode("utf-8"))
            self.assertEqual(candidates["analysis_status"], "completed")
            self.assertIsInstance(candidates["candidates"], list)
            self.assertIn("bounded stored-flow snapshot", candidates["scope"])
            self.assertNotIn("raw", json.dumps(candidates, sort_keys=True).lower())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_dashboard_marks_failed_analysis_as_degraded_not_clean_zero_candidates(self) -> None:
        self.repository.record_analysis_run(
            collection_run_id=None,
            detector_configuration_sha256="a" * 64,
            started_at=self.received_at,
            completed_at=self.received_at,
            status="failed",
            candidate_count=0,
            reason_code="analysis_failure",
            input_snapshot_json=self._failed_input_snapshot(),
        )
        server = dashboard_server(self.root, port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
            connection.request("GET", "/")
            page = connection.getresponse().read().decode("utf-8")
            self.assertIn("analysis_failure", page)
            self.assertIn("Analysis is degraded", page)
            self.assertIn("candidate state is unknown", page)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_forged_completed_zero_candidate_record_is_rejected_and_dashboard_is_unknown(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid_analysis_run"):
            self.repository.record_analysis_run(
                collection_run_id=None,
                detector_configuration_sha256="a" * 64,
                started_at=self.received_at,
                completed_at=self.received_at,
                status="completed",
                candidate_count=0,
                reason_code=None,
                input_snapshot_json=self._complete_input_snapshot(),
            )
        self.assertIsNone(self.repository.latest_analysis_run())
        server = dashboard_server(self.root, port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
            connection.request("GET", "/api/candidates")
            payload = json.loads(connection.getresponse().read().decode("utf-8"))
            self.assertEqual(payload["analysis_status"], "unknown")
            self.assertEqual(payload["candidates"], [])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_dashboard_does_not_reuse_historical_analysis_for_new_collection_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "dashboard-analysis-scope"
            repository, first_stats = self._serve_loopback(
                netflow_v9_message(sequence=1, include_template=True, records=(_record("198.51.100.99", "203.0.113.99"),)),
                root=root,
            )
            self.assertEqual(first_stats.run_state, "completed")
            self.assertIsNotNone(repository.summary()["latest_analysis_run"])
            second_stats = FlowCollector(
                repository,
                ListenerPolicy(port=self._unused_loopback_port(), duration_seconds=1, max_datagrams=1),
                auto_analyze=True,
            ).serve()
            self.assertEqual(second_stats.run_state, "completed_no_accepted_datagrams")
            server = dashboard_server(root, port=0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                connection.request("GET", "/")
                page = connection.getresponse().read().decode("utf-8")
                self.assertIn("No durable analysis result has been recorded for the displayed collection run", page)
                self.assertIn("Candidate state is unknown", page)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)
