from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from network_ai import FileEvidenceStore, IngestItem, IngestService, SourceType
from network_ai.contracts import ClockQuality, canonical_json
from network_ai.correlation import (
    CorrelationConfig,
    CorrelationError,
    CorrelationOutcome,
    CorrelationResult,
    CorrelationResultStore,
    FixtureCoverage,
    correlate,
    fixture_coverage_scope_sha256,
)
from network_ai.store import VerifiedEvidenceSnapshot

from .helpers import context, fixture_bytes


class CorrelationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        self.store = FileEvidenceStore(Path(self.temp_directory.name) / "evidence", ledger_id="correlation-ledger")
        self.service = IngestService(self.store)

    def tearDown(self) -> None:
        self.temp_directory.cleanup()

    def _ingest(
        self,
        source: SourceType,
        delivery_id: str,
        raw: bytes,
        *,
        service: IngestService | None = None,
        clock: ClockQuality = ClockQuality.SYNCHRONIZED,
    ):
        target = service or self.service
        intake = replace(context(source, delivery_id), clock_quality=clock)
        result = target.ingest(IngestItem(intake, raw))
        self.assertEqual(result.status, "accepted")
        return result

    def _baseline(self, *, service: IngestService | None = None) -> tuple[object, object]:
        return (
            self._ingest(SourceType.SURICATA, "suricata-one", fixture_bytes("suricata/alert.json"), service=service),
            self._ingest(SourceType.ZEEK, "zeek-one", fixture_bytes("zeek/conn.json"), service=service),
        )

    @staticmethod
    def _config(
        store: FileEvidenceStore,
        *,
        window_seconds: int = 60,
        starts_at: str = "2026-08-15T07:55:00Z",
        ends_at: str = "2026-08-15T08:05:00Z",
        coverage_id: str = "coverage-lab-001",
    ) -> CorrelationConfig:
        coverage = FixtureCoverage(
            coverage_id=coverage_id,
            zeek_sensor_id="sensor-lab-01",
            starts_at=starts_at,
            ends_at=ends_at,
            fixture_scope_sha256=fixture_coverage_scope_sha256(store, "sensor-lab-01", starts_at, ends_at),
        )
        return CorrelationConfig(window_seconds, (("sensor-lab-01", "sensor-lab-01"),), (coverage,))

    def test_exact_five_tuple_is_probable_match_with_no_raw_payload(self) -> None:
        self._baseline()
        result = correlate(self.store, self._config(self.store))[0]
        payload = result.payload
        self.assertEqual(payload["outcome"], CorrelationOutcome.PROBABLE_MATCH.value)
        self.assertNotEqual(payload["outcome"], CorrelationOutcome.MATCH.value)
        self.assertEqual(payload["match_basis"], "exact_5_tuple_event_time_window")
        self.assertEqual(payload["candidate_count"], 1)
        self.assertEqual(len(payload["candidate_evidence_refs"]), 1)
        self.assertTrue(payload["source_ledger_checkpoint"])
        self.assertEqual({item["parser_version"] for item in payload["candidate_evidence_refs"]}, {"strict-json.v1"})
        self.assertEqual({item["adapter_version"] for item in payload["candidate_evidence_refs"]}, {"allowlisted-adapters.v2"})
        self.assertNotIn("normalized_payload", payload["anchor"])
        self.assertNotIn("normalized_payload", payload["candidate_evidence_refs"][0])
        self.assertEqual(result.stage_outcome.outcome, CorrelationOutcome.PROBABLE_MATCH)
        self.assertEqual(result.stage_outcome.reason_code, "reported")
        self.assertEqual(result.stage_outcome.evidence_refs, tuple(sorted((payload["anchor_evidence_id"], payload["candidate_evidence_refs"][0]["evidence_id"]))))
        self.assertTrue(self.store.verify().valid)

    def test_multiple_wisp_style_candidates_are_ambiguous_and_all_retained(self) -> None:
        alert = json.loads(fixture_bytes("suricata/alert.json"))
        alert.update({"timestamp": "2026-08-15T06:25:01Z", "src_ip": "10.20.5.17", "dest_ip": "1.1.1.1", "src_port": 49152, "dest_port": 443})
        self._ingest(SourceType.SURICATA, "wisp-alert", json.dumps(alert, separators=(",", ":")).encode())
        candidate_ids: list[str] = []
        for delivery_id, uid, timestamp in (
            ("wisp-zeek-a", "CwispA", "2026-08-15T06:25:00.800000Z"),
            ("wisp-zeek-b", "CwispB", "2026-08-15T06:25:01.400000Z"),
            ("wisp-zeek-c", "CwispC", "2026-08-15T06:25:02.100000Z"),
        ):
            zeek = json.loads(fixture_bytes("zeek/conn.json"))
            zeek.update({"uid": uid, "ts": timestamp, "id.orig_h": "10.20.5.17", "id.resp_h": "1.1.1.1", "id.orig_p": 49152, "id.resp_p": 443})
            result = self._ingest(SourceType.ZEEK, delivery_id, json.dumps(zeek, separators=(",", ":")).encode())
            assert result.evidence_id is not None
            candidate_ids.append(result.evidence_id)
        config = self._config(self.store, starts_at="2026-08-15T06:20:00Z", ends_at="2026-08-15T06:30:00Z")
        result = correlate(self.store, config)[0]
        payload = result.payload
        self.assertEqual(payload["outcome"], CorrelationOutcome.AMBIGUOUS.value)
        self.assertEqual(payload["candidate_count"], 3)
        self.assertEqual([item["evidence_id"] for item in payload["candidate_evidence_refs"]], sorted(candidate_ids))
        self.assertIn("none is preferred", payload["rationale"])
        self.assertEqual(result.stage_outcome.outcome, CorrelationOutcome.AMBIGUOUS)
        self.assertEqual(result.stage_outcome.evidence_refs, tuple(sorted((payload["anchor_evidence_id"], *candidate_ids))))
        with tempfile.TemporaryDirectory() as directory:
            derived = CorrelationResultStore(Path(directory) / "derived")
            self.assertEqual(derived.persist(result), "persisted")
            self.assertEqual(derived.persist(result), "duplicate")

    def test_time_window_is_inclusive_and_outside_identical_key_is_no_match(self) -> None:
        self._ingest(SourceType.SURICATA, "boundary-alert", fixture_bytes("suricata/alert.json"))
        for delivery, uid, timestamp in (
            ("boundary-before", "CboundaryBefore", "2026-08-15T07:59:51.123456Z"),
            ("boundary-after", "CboundaryAfter", "2026-08-15T08:00:11.123456Z"),
        ):
            zeek = json.loads(fixture_bytes("zeek/conn.json")); zeek.update({"uid": uid, "ts": timestamp})
            self._ingest(SourceType.ZEEK, delivery, json.dumps(zeek, separators=(",", ":")).encode())
        inclusive = correlate(self.store, self._config(self.store, window_seconds=10))[0].payload
        self.assertEqual(inclusive["outcome"], "ambiguous")
        self.assertEqual(inclusive["candidate_count"], 2)

        with tempfile.TemporaryDirectory() as directory:
            store = FileEvidenceStore(Path(directory) / "evidence", ledger_id="outside-window")
            service = IngestService(store)
            self._ingest(SourceType.SURICATA, "outside-alert", fixture_bytes("suricata/alert.json"), service=service)
            zeek = json.loads(fixture_bytes("zeek/conn.json")); zeek["ts"] = "2026-08-15T08:00:11.123457Z"
            self._ingest(SourceType.ZEEK, "outside-zeek", json.dumps(zeek, separators=(",", ":")).encode(), service=service)
            no_match = correlate(store, self._config(store, window_seconds=10))[0].payload
            self.assertEqual(no_match["outcome"], "no_match")
            self.assertEqual(no_match["candidate_count"], 0)

    def test_missing_evidence_and_identifying_field_conflict_are_not_forced_matches(self) -> None:
        self._ingest(SourceType.SURICATA, "only-alert", fixture_bytes("suricata/alert.json"))
        no_evidence = correlate(self.store, CorrelationConfig(60, (("sensor-lab-01", "sensor-lab-01"),), ()))[0].payload
        self.assertEqual(no_evidence["outcome"], "insufficient_evidence")

        with tempfile.TemporaryDirectory() as directory:
            store = FileEvidenceStore(Path(directory) / "evidence", ledger_id="port-conflict")
            service = IngestService(store)
            self._ingest(SourceType.SURICATA, "conflict-alert", fixture_bytes("suricata/alert.json"), service=service)
            zeek = json.loads(fixture_bytes("zeek/conn.json")); zeek["id.resp_p"] = 8443
            self._ingest(SourceType.ZEEK, "conflict-zeek", json.dumps(zeek, separators=(",", ":")).encode(), service=service)
            conflict = correlate(store, self._config(store))[0].payload
            self.assertEqual(conflict["outcome"], "no_match")
            self.assertEqual(conflict["candidate_count"], 0)
            invalid_coverage = FixtureCoverage(
                "forged-full-coverage",
                "sensor-lab-01",
                "2026-08-15T07:55:00Z",
                "2026-08-15T08:05:00Z",
                "0" * 64,
            )
            forged_coverage = correlate(
                store,
                CorrelationConfig(60, (("sensor-lab-01", "sensor-lab-01"),), (invalid_coverage,)),
            )[0].payload
            self.assertEqual(forged_coverage["outcome"], "insufficient_evidence")
            self.assertEqual(forged_coverage["rationale"], "fixture_coverage_scope_hash_mismatch")

    def test_duplicate_delivery_adds_no_evidence_and_preserves_result(self) -> None:
        self._baseline()
        config = self._config(self.store)
        first = correlate(self.store, config)[0]
        retry = self.service.ingest(IngestItem(context(SourceType.ZEEK, "zeek-one"), fixture_bytes("zeek/conn.json")))
        self.assertEqual(retry.status, "duplicate_delivery")
        second = correlate(self.store, config)[0]
        self.assertEqual(first, second)
        self.assertEqual(len(self.store.accepted_manifests()), 2)
        self.assertEqual(second.payload["candidate_count"], 1)

    def test_reverse_ingestion_has_same_semantic_correlation_and_distinct_audit_derivation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            def build(name: str, order: tuple[SourceType, SourceType]):
                store = FileEvidenceStore(Path(directory) / name, ledger_id="order-invariance")
                service = IngestService(store)
                raw = {
                    SourceType.SURICATA: fixture_bytes("suricata/alert.json"),
                    SourceType.ZEEK: fixture_bytes("zeek/conn.json"),
                }
                delivery = {SourceType.SURICATA: "ordered-alert", SourceType.ZEEK: "ordered-zeek"}
                for source in order:
                    self._ingest(source, delivery[source], raw[source], service=service)
                return correlate(store, self._config(store))[0]

            forward = build("forward", (SourceType.SURICATA, SourceType.ZEEK))
            reverse = build("reverse", (SourceType.ZEEK, SourceType.SURICATA))
        self.assertEqual(forward.semantic_correlation_id, reverse.semantic_correlation_id)
        self.assertEqual(forward.correlation_id, reverse.correlation_id)
        self.assertNotEqual(forward.derivation_id, reverse.derivation_id)
        self.assertEqual(
            [item["evidence_id"] for item in forward.payload["candidate_evidence_refs"]],
            [item["evidence_id"] for item in reverse.payload["candidate_evidence_refs"]],
        )
        self.assertNotEqual(forward.payload["source_ledger_checkpoint"], reverse.payload["source_ledger_checkpoint"])

    def test_synchronized_clock_skew_inside_documented_window_is_probable(self) -> None:
        alert = json.loads(fixture_bytes("suricata/alert.json")); alert["timestamp"] = "2026-08-15T10:00:05Z"
        zeek = json.loads(fixture_bytes("zeek/conn.json")); zeek["ts"] = "2026-08-15T10:00:00Z"
        self._ingest(SourceType.SURICATA, "skew-alert", json.dumps(alert, separators=(",", ":")).encode())
        self._ingest(SourceType.ZEEK, "skew-zeek", json.dumps(zeek, separators=(",", ":")).encode())
        payload = correlate(self.store, self._config(self.store, window_seconds=10, starts_at="2026-08-15T09:55:00Z", ends_at="2026-08-15T10:05:00Z"))[0].payload
        self.assertEqual(payload["outcome"], "probable_match")
        self.assertEqual(payload["time_window"], {"end": "2026-08-15T10:00:15Z", "inclusive": True, "start": "2026-08-15T09:59:55Z", "uses": "event_time", "window_seconds": 10})

    def test_degraded_matching_zeek_blocks_no_match_even_outside_nominal_window(self) -> None:
        self._ingest(SourceType.SURICATA, "suricata-sync", fixture_bytes("suricata/alert.json"))
        late = json.loads(fixture_bytes("zeek/conn.json")); late["ts"] = "2026-08-15T08:01:02.123456Z"
        self._ingest(SourceType.ZEEK, "zeek-degraded-late", json.dumps(late, separators=(",", ":")).encode(), clock=ClockQuality.DEGRADED)
        payload = correlate(self.store, self._config(self.store))[0].payload
        self.assertEqual(payload["outcome"], "insufficient_evidence")
        self.assertEqual(payload["rationale"], "matching_zeek_observation_clock_quality_not_synchronized")

    def test_icmp_is_explicitly_outside_the_port_bearing_profile(self) -> None:
        alert = json.loads(fixture_bytes("suricata/alert.json")); alert["proto"] = "icmp"; alert.pop("src_port"); alert.pop("dest_port")
        zeek = json.loads(fixture_bytes("zeek/conn.json")); zeek["proto"] = "icmp"; zeek.pop("id.orig_p"); zeek.pop("id.resp_p")
        self._ingest(SourceType.SURICATA, "icmp-alert", json.dumps(alert, separators=(",", ":")).encode())
        self._ingest(SourceType.ZEEK, "icmp-zeek", json.dumps(zeek, separators=(",", ":")).encode())
        payload = correlate(self.store, self._config(self.store))[0].payload
        self.assertEqual(payload["outcome"], "insufficient_evidence")
        self.assertEqual(payload["rationale"], "protocol_not_supported_by_five_tuple_correlation")
        self.assertIsNone(payload["match_basis"])

    def test_candidate_overflow_is_incomplete_not_truncated(self) -> None:
        self._baseline()
        raw = json.loads(fixture_bytes("zeek/conn.json"))
        for number in range(33):
            raw["uid"] = f"Coverflow{number:04d}"
            self._ingest(SourceType.ZEEK, f"overflow-{number}", json.dumps(raw, separators=(",", ":")).encode())
        payload = correlate(self.store, self._config(self.store))[0].payload
        self.assertEqual(payload["outcome"], "insufficient_evidence")
        self.assertEqual(payload["rationale"], "candidate_limit_exceeded")
        self.assertGreater(payload["candidate_count"], 32)
        self.assertEqual(payload["candidate_evidence_refs"], [])

    def test_unsupported_stored_versions_are_rejected_without_mutating_source_evidence(self) -> None:
        self._baseline()
        config = self._config(self.store)
        snapshot = self.store.verified_snapshot()
        for field, value in (("schema_version", "observation-schema.v1"), ("contract_version", "evidence-envelope.v1")):
            with self.subTest(field=field):
                manifests = list(snapshot.manifests)
                manifests[0][field] = value
                stale_snapshot = VerifiedEvidenceSnapshot(snapshot.checkpoint, canonical_json(manifests))
                with patch.object(self.store, "verified_snapshot", return_value=stale_snapshot):
                    with self.assertRaisesRegex(CorrelationError, "unsupported_observation_version"):
                        correlate(self.store, config)
        self.assertTrue(self.store.verify().valid)

    def test_derived_result_validation_rejects_forgery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            derived = CorrelationResultStore(Path(directory) / "derived")
            with self.assertRaisesRegex(CorrelationError, "invalid_correlation_result"):
                derived.persist(CorrelationResult("0" * 64, "1" * 64, '{"correlation_id":"../escaped"}'))
