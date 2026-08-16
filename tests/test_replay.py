from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from network_ai import FileEvidenceStore, IngestItem, IngestService, SourceType
from network_ai.contracts import MAX_RECORD_BYTES, MIKROTIK_SESSION_FORMAT_PROFILE, canonical_json
from network_ai.correlation import CorrelationConfig, FixtureCoverage, FixtureSessionCoverage, SessionCorrelationConfig, fixture_coverage_scope_sha256, fixture_session_coverage_scope_sha256
from network_ai.replay import MAX_REPLAY_ARTIFACT_BYTES, ReplayError, ReplayTrace, ReplayTraceStore, replay_trace
from network_ai.store import VerifiedAuditEntry, VerifiedAuditSnapshot

from .helpers import context, fixture_bytes


class ReplayTests(unittest.TestCase):
    def _configs(self, store: FileEvidenceStore) -> tuple[CorrelationConfig, SessionCorrelationConfig]:
        start, end = "2026-08-15T07:58:00Z", "2026-08-15T08:02:00Z"
        traffic = CorrelationConfig(60, (("sensor-lab-01", "sensor-lab-01"),), (FixtureCoverage("replay-zeek", "sensor-lab-01", start, end, fixture_coverage_scope_sha256(store, "sensor-lab-01", start, end)),))
        session = SessionCorrelationConfig((("sensor-lab-01", "sensor-lab-01"),), (FixtureSessionCoverage("replay-session", "sensor-lab-01", start, end, fixture_session_coverage_scope_sha256(store, "sensor-lab-01", start, end)),))
        return traffic, session

    def _store(self, root: Path, order: tuple[str, ...] = ("alert", "zeek", "session", "bad")) -> FileEvidenceStore:
        store = FileEvidenceStore(root, ledger_id="replay-ledger")
        service = IngestService(store)
        records = {
            "alert": (SourceType.SURICATA, "replay-alert", fixture_bytes("suricata/alert.json"), None),
            "zeek": (SourceType.ZEEK, "replay-zeek", fixture_bytes("zeek/conn.json"), None),
            "session": (SourceType.MIKROTIK, "replay-session", fixture_bytes("mikrotik/session-binding.json"), MIKROTIK_SESSION_FORMAT_PROFILE),
            "bad": (SourceType.ZEEK, "replay-bad", b"{bad", None),
        }
        for name in order:
            source, delivery, raw, profile = records[name]
            service.ingest(IngestItem(context(source, delivery, format_profile=profile), raw))
        return store

    def test_replay_is_snapshot_bound_private_and_idempotently_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(Path(directory) / "evidence")
            traffic, session = self._configs(store)
            with patch.object(store, "verified_audit_snapshot", wraps=store.verified_audit_snapshot) as snapshot:
                trace = replay_trace(store, traffic, session)
            self.assertEqual(snapshot.call_count, 1)
            payload = trace.payload
            self.assertEqual(payload["coverage"], "durable_ledger_entries_only")
            self.assertEqual(len(payload["audit_entry_order"]), 4)
            self.assertEqual(len(payload["traffic_correlation_outcomes"]), 1)
            self.assertEqual(len(payload["session_correlation_outcomes"]), 1)
            self.assertIn("duplicate_delivery_attempts_are_not_durable_ledger_entries", payload["limitations"])
            encoded = trace.canonical_json
            for forbidden in ("normalized_payload", "candidate_evidence_refs", "subscriber-C6127", "session-C6127-001"):
                self.assertNotIn(forbidden, encoded)
            persisted = ReplayTraceStore(Path(directory) / "traces")
            self.assertEqual(persisted.persist(trace), "persisted")
            self.assertEqual(persisted.persist(trace), "duplicate")
            object.__setattr__(trace, "derivation_id", "../escaped")
            with self.assertRaisesRegex(ReplayError, "invalid_replay_trace"):
                persisted.persist(trace)
            self.assertFalse((Path(directory) / "escaped.json").exists())

    def test_replay_semantics_ignore_ledger_order_but_derivation_retains_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            forward_store = self._store(Path(directory) / "forward")
            reverse_store = self._store(Path(directory) / "reverse", ("bad", "session", "zeek", "alert"))
            forward = replay_trace(forward_store, *self._configs(forward_store))
            reverse = replay_trace(reverse_store, *self._configs(reverse_store))
        self.assertEqual(forward.semantic_replay_id, reverse.semantic_replay_id)
        self.assertNotEqual(forward.derivation_id, reverse.derivation_id)

    def test_replay_rejects_invalid_pair_limits_tamper_and_forgery_without_source_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            store = self._store(root)
            _, session = self._configs(store)
            with self.assertRaisesRegex(ReplayError, "session_replay_requires_traffic_config"):
                replay_trace(store, session_config=session)
            with patch("network_ai.replay.MAX_REPLAY_AUDIT_ENTRIES", 1):
                with self.assertRaisesRegex(ReplayError, "replay_ledger_entry_limit_exceeded"):
                    replay_trace(store)
            ledger = root / "ledger.v1.jsonl"
            original = ledger.read_bytes()
            ledger.write_bytes(original + b'{"bad":')
            recovery_before = list((root / "recovery").glob("*"))
            with self.assertRaisesRegex(ReplayError, "invalid_replay_ledger_tail"):
                replay_trace(store)
            self.assertEqual(ledger.read_bytes(), original + b'{"bad":')
            self.assertEqual(list((root / "recovery").glob("*")), recovery_before)
        with self.assertRaisesRegex(ReplayError, "invalid_replay_trace"):
            ReplayTrace("0" * 64, "0" * 64, '{"derivation_id":"0","semantic_replay_id":"0"}')

    def test_replay_rejects_oversized_artifact_and_unsupported_accepted_manifest_without_writes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            store = self._store(root)
            ledger = root / "ledger.v1.jsonl"
            original_ledger = ledger.read_bytes()
            manifest = store.accepted_manifests()[0]
            raw_path = root / "raw" / f"{manifest['raw']['raw_sha256']}.bin"
            raw_path.write_bytes(b"x" * (MAX_REPLAY_ARTIFACT_BYTES + 1))
            with self.assertRaisesRegex(ReplayError, "source_evidence_verification_failed"):
                replay_trace(store)
            self.assertEqual(ledger.read_bytes(), original_ledger)

            # The snapshot is deliberately forged only in memory. Replay must
            # turn unsupported durable accepted evidence into its public error.
            forged = json.loads(canonical_json(manifest))
            forged["intake"]["format_profile"] = "unsupported-profile.v999"
            snapshot = VerifiedAuditSnapshot(
                store.ledger_id,
                None,
                (VerifiedAuditEntry(0, canonical_json(forged)),),
            )
            with patch.object(store, "verified_audit_snapshot", return_value=snapshot):
                with self.assertRaisesRegex(ReplayError, "invalid_replay_accepted_manifest"):
                    replay_trace(store)
            self.assertEqual(ledger.read_bytes(), original_ledger)

    def test_replay_includes_normal_size_rejection_and_caps_larger_preserved_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            store = FileEvidenceStore(root, ledger_id="replay-sized-ledger")
            service = IngestService(store)
            normal = service.ingest(
                IngestItem(context(SourceType.ZEEK, "normal-size-rejection"), b"x" * (MAX_RECORD_BYTES + 1))
            )
            self.assertEqual(normal.status, "quarantined")
            trace = replay_trace(store)
            self.assertEqual(trace.payload["intake_outcomes"][0]["stage_outcome"]["reason_code"], "record_size_exceeded")

            large = service.ingest(
                IngestItem(context(SourceType.ZEEK, "large-rejection"), b"x" * (MAX_REPLAY_ARTIFACT_BYTES + 1))
            )
            self.assertEqual(large.status, "quarantined")
            with self.assertRaisesRegex(ReplayError, "source_evidence_verification_failed"):
                replay_trace(store)
