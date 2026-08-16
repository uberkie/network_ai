from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from network_ai import FileEvidenceStore, IngestItem, IngestService, SourceType
from network_ai.contracts import ClockQuality, MIKROTIK_SESSION_FORMAT_PROFILE, canonical_json
from network_ai.correlation import (
    CorrelationConfig,
    CorrelationError,
    FixtureCoverage,
    FixtureSessionCoverage,
    SessionCorrelationConfig,
    correlate_with_session,
    fixture_coverage_scope_sha256,
    fixture_session_coverage_scope_sha256,
)
from network_ai.store import VerifiedEvidenceSnapshot

from .helpers import context, fixture_bytes


class SessionCorrelationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        self.store = FileEvidenceStore(Path(self.temp_directory.name) / "evidence", ledger_id="session-correlation")
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
        format_profile: str | None = None,
        clock: ClockQuality = ClockQuality.SYNCHRONIZED,
        observed_at: str = "2026-08-15T08:00:05Z",
        sensor_id: str = "sensor-lab-01",
        ingested_at: str = "2026-08-15T08:00:06Z",
    ):
        target = service or self.service
        intake = replace(
            context(
                source,
                delivery_id,
                format_profile=format_profile,
                observed_at=observed_at,
                sensor_id=sensor_id,
                ingested_at=ingested_at,
            ),
            clock_quality=clock,
        )
        result = target.ingest(IngestItem(intake, raw))
        self.assertEqual(result.status, "accepted")
        return result

    def _traffic_config(
        self,
        store: FileEvidenceStore,
        *,
        start: str = "2026-08-15T07:58:00Z",
        end: str = "2026-08-15T08:02:00Z",
        alert_sensor: str = "sensor-lab-01",
        zeek_sensor: str = "sensor-lab-01",
        window_seconds: int = 60,
    ) -> CorrelationConfig:
        coverage = FixtureCoverage(
            "traffic-coverage",
            zeek_sensor,
            start,
            end,
            fixture_coverage_scope_sha256(store, zeek_sensor, start, end),
        )
        return CorrelationConfig(window_seconds, ((alert_sensor, zeek_sensor),), (coverage,))

    def _session_config(
        self,
        store: FileEvidenceStore,
        *,
        start: str = "2026-08-15T07:58:00Z",
        end: str = "2026-08-15T08:02:00Z",
        alert_sensor: str = "sensor-lab-01",
        session_sensor: str = "sensor-lab-01",
    ) -> SessionCorrelationConfig:
        coverage = FixtureSessionCoverage(
            "session-coverage",
            session_sensor,
            start,
            end,
            fixture_session_coverage_scope_sha256(store, session_sensor, start, end),
        )
        return SessionCorrelationConfig(((alert_sensor, session_sensor),), (coverage,))

    def _baseline(self, *, service: IngestService | None = None, session_raw: bytes | None = None, session_clock: ClockQuality = ClockQuality.SYNCHRONIZED) -> tuple[object, object, object]:
        return (
            self._ingest(SourceType.SURICATA, "alert", fixture_bytes("suricata/alert.json"), service=service),
            self._ingest(SourceType.ZEEK, "zeek", fixture_bytes("zeek/conn.json"), service=service),
            self._ingest(
                SourceType.MIKROTIK,
                "session",
                session_raw or fixture_bytes("mikrotik/session-binding.json"),
                service=service,
                format_profile=MIKROTIK_SESSION_FORMAT_PROFILE,
                clock=session_clock,
            ),
        )

    def test_exact_session_association_uses_one_snapshot_and_hides_opaque_refs(self) -> None:
        self._baseline()
        traffic_config, session_config = self._traffic_config(self.store), self._session_config(self.store)
        with patch.object(self.store, "verified_snapshot", wraps=self.store.verified_snapshot) as verified_snapshot:
            result = correlate_with_session(self.store, traffic_config, session_config)[0]
        self.assertEqual(verified_snapshot.call_count, 1)
        payload = result.payload
        self.assertEqual(payload["traffic"]["outcome"], "probable_match")
        self.assertEqual(payload["session_association"]["outcome"], "probable_match")
        self.assertEqual(payload["session_association"]["candidate_count"], 1)
        self.assertEqual(payload["session_association"]["relationship"], "source_ip_matched_declared_session_binding_at_event_time")
        self.assertEqual(len(payload["session_association"]["session_evidence_ids"]), 1)
        self.assertEqual(result.stage_outcome.outcome.value, "probable_match")
        self.assertIsNotNone(result.session_stage_outcome)
        assert result.session_stage_outcome is not None
        self.assertEqual(result.session_stage_outcome.outcome.value, "probable_match")
        self.assertEqual(
            result.session_stage_outcome.evidence_refs,
            tuple(sorted((payload["traffic"]["anchor_evidence_id"], *payload["session_association"]["session_evidence_ids"]))),
        )
        self.assertNotIn("subscriber-C6127", result.canonical_json)
        self.assertNotIn("session-C6127-001", result.canonical_json)
        self.assertNotIn("normalized_payload", result.canonical_json)
        self.assertTrue(self.store.verify().valid)
        retry = self.service.ingest(
            IngestItem(
                context(
                    SourceType.MIKROTIK,
                    "session",
                    format_profile=MIKROTIK_SESSION_FORMAT_PROFILE,
                ),
                fixture_bytes("mikrotik/session-binding.json"),
            )
        )
        self.assertEqual(retry.status, "duplicate_delivery")
        self.assertEqual(correlate_with_session(self.store, traffic_config, session_config)[0], result)
        alternate_coverage = FixtureSessionCoverage(
            "session-coverage-revision",
            "sensor-lab-01",
            "2026-08-15T07:58:00Z",
            "2026-08-15T08:02:00Z",
            fixture_session_coverage_scope_sha256(self.store, "sensor-lab-01", "2026-08-15T07:58:00Z", "2026-08-15T08:02:00Z"),
        )
        alternate = correlate_with_session(
            self.store,
            traffic_config,
            SessionCorrelationConfig((("sensor-lab-01", "sensor-lab-01"),), (alternate_coverage,)),
        )[0]
        self.assertNotEqual(alternate.semantic_correlation_id, result.semantic_correlation_id)

    def test_overlapping_sessions_are_ambiguous_and_all_evidence_ids_are_retained(self) -> None:
        _, _, first = self._baseline()
        second = json.loads(fixture_bytes("mikrotik/session-binding.json"))
        second["session_ref"] = "session-C6127-002"
        second["subscriber_ref"] = "subscriber-C6128"
        second_result = self._ingest(
            SourceType.MIKROTIK,
            "session-overlap",
            json.dumps(second, separators=(",", ":")).encode(),
            format_profile=MIKROTIK_SESSION_FORMAT_PROFILE,
        )
        result = correlate_with_session(self.store, self._traffic_config(self.store), self._session_config(self.store))[0].payload
        self.assertEqual(result["traffic"]["outcome"], "probable_match")
        self.assertEqual(result["session_association"]["outcome"], "ambiguous")
        self.assertEqual(result["session_association"]["candidate_count"], 2)
        self.assertEqual(result["session_association"]["session_evidence_ids"], sorted((first.evidence_id, second_result.evidence_id)))
        self.assertIn("none is preferred", result["session_association"]["rationale"])

    def test_session_validity_endpoints_are_inclusive_and_one_microsecond_outside_is_no_match(self) -> None:
        anchor_time = "2026-08-15T08:00:01.123456Z"
        endpoint = json.loads(fixture_bytes("mikrotik/session-binding.json"))
        endpoint.update({"observed_at": anchor_time, "valid_from": anchor_time, "valid_until": anchor_time})
        self._baseline(session_raw=json.dumps(endpoint, separators=(",", ":")).encode())
        endpoint_payload = correlate_with_session(self.store, self._traffic_config(self.store), self._session_config(self.store))[0].payload
        self.assertEqual(endpoint_payload["session_association"]["outcome"], "probable_match")

        with tempfile.TemporaryDirectory() as directory:
            store = FileEvidenceStore(Path(directory) / "clean-evidence", ledger_id="outside-session-clean")
            service = IngestService(store)
            self._ingest(SourceType.SURICATA, "alert", fixture_bytes("suricata/alert.json"), service=service)
            self._ingest(SourceType.ZEEK, "zeek", fixture_bytes("zeek/conn.json"), service=service)
            early = json.loads(fixture_bytes("mikrotik/session-binding.json"))
            early.update({"observed_at": "2026-08-15T08:00:01Z", "valid_from": "2026-08-15T08:00:00Z", "valid_until": "2026-08-15T08:00:01.123455Z", "session_ref": "session-outside"})
            self._ingest(SourceType.MIKROTIK, "session-outside", json.dumps(early, separators=(",", ":")).encode(), service=service, format_profile=MIKROTIK_SESSION_FORMAT_PROFILE)
            outside = correlate_with_session(store, self._traffic_config(store), self._session_config(store))[0].payload
            self.assertEqual(outside["session_association"]["outcome"], "no_match")
            self.assertNotIn("relationship", outside["session_association"])

    def test_temporal_handover_endpoints_gap_and_dynamic_ip_reuse_are_deterministic(self) -> None:
        """Two sequential bindings must retain an explicit one-second gap."""
        alert_sensor, zeek_sensor, session_sensor = "suricata-temporal", "zeek-temporal", "session-temporal"
        coverage_start, coverage_end = "2026-08-15T07:58:00Z", "2026-08-15T10:02:00Z"

        def alert_at(timestamp: str) -> bytes:
            alert = json.loads(fixture_bytes("suricata/alert.json"))
            alert.update({"timestamp": timestamp, "src_ip": "10.20.11.54"})
            return json.dumps(alert, separators=(",", ":")).encode()

        def binding(
            *, session_ref: str, subscriber_ref: str, observed_at: str, valid_from: str, valid_until: str,
        ) -> bytes:
            record = json.loads(fixture_bytes("mikrotik/session-binding.json"))
            record.update(
                {
                    "assigned_ip": "10.20.11.54",
                    "observed_at": observed_at,
                    "session_ref": session_ref,
                    "subscriber_ref": subscriber_ref,
                    "valid_from": valid_from,
                    "valid_until": valid_until,
                }
            )
            return json.dumps(record, separators=(",", ":")).encode()

        # These are deliberately later than the earliest anchors.  They are
        # acquisition provenance, not a substitute temporal join key.
        session_a = self._ingest(
            SourceType.MIKROTIK,
            "temporal-session-a",
            binding(
                session_ref="session-temporal-a",
                subscriber_ref="subscriber-temporal-a",
                observed_at="2026-08-15T08:30:00Z",
                valid_from="2026-08-15T08:00:00Z",
                valid_until="2026-08-15T09:00:00Z",
            ),
            format_profile=MIKROTIK_SESSION_FORMAT_PROFILE,
            sensor_id=session_sensor,
            observed_at="2026-08-15T08:30:00Z",
            ingested_at="2026-08-15T08:30:01Z",
        )
        session_b = self._ingest(
            SourceType.MIKROTIK,
            "temporal-session-b",
            binding(
                session_ref="session-temporal-b",
                subscriber_ref="subscriber-temporal-b",
                observed_at="2026-08-15T09:30:00Z",
                valid_from="2026-08-15T09:00:01Z",
                valid_until="2026-08-15T10:00:00Z",
            ),
            format_profile=MIKROTIK_SESSION_FORMAT_PROFILE,
            sensor_id=session_sensor,
            observed_at="2026-08-15T09:30:00Z",
            ingested_at="2026-08-15T09:30:01Z",
        )
        expected = {
            "2026-08-15T07:59:59.999999Z": ("no_match", ()),
            "2026-08-15T08:00:00Z": ("probable_match", (session_a.evidence_id,)),
            "2026-08-15T08:59:59Z": ("probable_match", (session_a.evidence_id,)),
            "2026-08-15T09:00:00Z": ("probable_match", (session_a.evidence_id,)),
            "2026-08-15T09:00:00.500000Z": ("no_match", ()),
            "2026-08-15T09:00:01Z": ("probable_match", (session_b.evidence_id,)),
            "2026-08-15T10:00:00Z": ("probable_match", (session_b.evidence_id,)),
            "2026-08-15T10:00:00.000001Z": ("no_match", ()),
        }
        anchors = {
            self._ingest(
                SourceType.SURICATA,
                f"temporal-alert-{index}",
                alert_at(timestamp),
                sensor_id=alert_sensor,
            ).evidence_id: timestamp
            for index, timestamp in enumerate(expected, start=1)
        }
        traffic_config = self._traffic_config(
            self.store,
            start=coverage_start,
            end=coverage_end,
            alert_sensor=alert_sensor,
            zeek_sensor=zeek_sensor,
            window_seconds=1,
        )
        session_config = self._session_config(
            self.store,
            start=coverage_start,
            end=coverage_end,
            alert_sensor=alert_sensor,
            session_sensor=session_sensor,
        )
        results = correlate_with_session(self.store, traffic_config, session_config)
        self.assertEqual(len(results), len(expected))
        observed = {
            anchors[result.payload["traffic"]["anchor_evidence_id"]]: result.payload["session_association"]
            for result in results
        }
        for timestamp, (outcome, evidence_ids) in expected.items():
            with self.subTest(anchor_time=timestamp):
                association = observed[timestamp]
                self.assertEqual(association["outcome"], outcome)
                self.assertEqual(association["session_evidence_ids"], list(evidence_ids))
                if outcome == "no_match":
                    self.assertNotIn("relationship", association)
                else:
                    self.assertEqual(
                        association["rationale"],
                        "source IP matched one supplied, retrospectively declared session binding at the anchor event time; this is not a contemporaneous subscriber attribution, ownership, or causation",
                    )
        for result in results:
            self.assertNotIn("subscriber-temporal", result.canonical_json)
            self.assertNotIn("session-temporal-", result.canonical_json)
            self.assertNotIn("normalized_payload", result.canonical_json)

    def test_session_coverage_requires_full_window_and_current_scope(self) -> None:
        alert_sensor, zeek_sensor, session_sensor = "suricata-scope", "zeek-scope", "session-scope"
        gap_time = "2026-08-15T09:00:00.500000Z"
        alert = json.loads(fixture_bytes("suricata/alert.json"))
        alert.update({"timestamp": gap_time, "src_ip": "10.20.11.54"})
        self._ingest(SourceType.SURICATA, "scope-alert", json.dumps(alert, separators=(",", ":")).encode(), sensor_id=alert_sensor)
        traffic_config = self._traffic_config(
            self.store,
            start="2026-08-15T08:58:00Z",
            end="2026-08-15T09:02:00Z",
            alert_sensor=alert_sensor,
            zeek_sensor=zeek_sensor,
            window_seconds=1,
        )
        partial_start = partial_end = gap_time
        partial = FixtureSessionCoverage(
            "partial-window",
            session_sensor,
            partial_start,
            partial_end,
            fixture_session_coverage_scope_sha256(self.store, session_sensor, partial_start, partial_end),
        )
        partial_result = correlate_with_session(
            self.store,
            traffic_config,
            SessionCorrelationConfig(((alert_sensor, session_sensor),), (partial,)),
        )[0].payload["session_association"]
        self.assertEqual(partial_result["outcome"], "insufficient_evidence")
        self.assertEqual(
            partial_result["rationale"],
            "no matching session binding and no declared-complete fixture coverage for the full traffic window",
        )

        def binding(*, reference: str, address: str, observed_at: str, start: str, end: str) -> bytes:
            record = json.loads(fixture_bytes("mikrotik/session-binding.json"))
            record.update(
                {
                    "assigned_ip": address,
                    "observed_at": observed_at,
                    "session_ref": reference,
                    "subscriber_ref": f"subscriber-{reference}",
                    "valid_from": start,
                    "valid_until": end,
                }
            )
            return json.dumps(record, separators=(",", ":")).encode()

        self._ingest(
            SourceType.MIKROTIK,
            "scope-session-a",
            binding(
                reference="scope-a",
                address="10.20.11.54",
                observed_at="2026-08-15T08:30:00Z",
                start="2026-08-15T08:00:00Z",
                end="2026-08-15T09:00:00Z",
            ),
            format_profile=MIKROTIK_SESSION_FORMAT_PROFILE,
            sensor_id=session_sensor,
            observed_at="2026-08-15T08:30:00Z",
            ingested_at="2026-08-15T08:30:01Z",
        )
        full_start, full_end = "2026-08-15T08:58:00Z", "2026-08-15T09:02:00Z"
        stale = FixtureSessionCoverage(
            "scope-before-second-binding",
            session_sensor,
            full_start,
            full_end,
            fixture_session_coverage_scope_sha256(self.store, session_sensor, full_start, full_end),
        )
        self._ingest(
            SourceType.MIKROTIK,
            "scope-session-b",
            binding(
                reference="scope-b",
                address="10.20.11.55",
                observed_at="2026-08-15T09:30:00Z",
                start="2026-08-15T09:00:01Z",
                end="2026-08-15T10:00:00Z",
            ),
            format_profile=MIKROTIK_SESSION_FORMAT_PROFILE,
            sensor_id=session_sensor,
            observed_at="2026-08-15T09:30:00Z",
            ingested_at="2026-08-15T09:30:01Z",
        )
        stale_result = correlate_with_session(
            self.store,
            traffic_config,
            SessionCorrelationConfig(((alert_sensor, session_sensor),), (stale,)),
        )[0].payload["session_association"]
        self.assertEqual(stale_result["outcome"], "insufficient_evidence")
        self.assertEqual(stale_result["rationale"], "session_fixture_coverage_scope_hash_mismatch")

    def test_duplicate_delivery_does_not_change_result_but_repeated_binding_is_ambiguous(self) -> None:
        _, _, first = self._baseline()
        traffic_config, session_config = self._traffic_config(self.store), self._session_config(self.store)
        initial = correlate_with_session(self.store, traffic_config, session_config)[0]
        retry = self.service.ingest(
            IngestItem(
                context(
                    SourceType.MIKROTIK,
                    "session",
                    format_profile=MIKROTIK_SESSION_FORMAT_PROFILE,
                ),
                fixture_bytes("mikrotik/session-binding.json"),
            )
        )
        self.assertEqual(retry.status, "duplicate_delivery")
        self.assertEqual(correlate_with_session(self.store, traffic_config, session_config)[0], initial)

        repeated = self._ingest(
            SourceType.MIKROTIK,
            "session-repeated-content-new-delivery",
            fixture_bytes("mikrotik/session-binding.json"),
            format_profile=MIKROTIK_SESSION_FORMAT_PROFILE,
        )
        refreshed_session_config = self._session_config(self.store)
        ambiguous = correlate_with_session(self.store, traffic_config, refreshed_session_config)[0]
        association = ambiguous.payload["session_association"]
        self.assertEqual(association["outcome"], "ambiguous")
        self.assertEqual(association["session_evidence_ids"], sorted((first.evidence_id, repeated.evidence_id)))
        self.assertEqual(association["candidate_count"], 2)
        self.assertNotIn("subscriber-C6127", ambiguous.canonical_json)
        self.assertNotIn("session-C6127-001", ambiguous.canonical_json)
        self.assertNotIn("normalized_payload", ambiguous.canonical_json)

    def test_unmapped_session_sensor_with_same_address_cannot_block_selected_sensor_no_match(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = FileEvidenceStore(Path(directory) / "sensor-scope", ledger_id="sensor-scope")
            service = IngestService(store)
            alert_sensor, zeek_sensor = "suricata-explicit", "zeek-explicit"
            selected_session_sensor, other_session_sensor = "session-selected", "session-other"
            self._ingest(
                SourceType.SURICATA,
                "explicit-sensor-alert",
                fixture_bytes("suricata/alert.json"),
                service=service,
                sensor_id=alert_sensor,
            )
            self._ingest(
                SourceType.MIKROTIK,
                "same-address-other-sensor",
                fixture_bytes("mikrotik/session-binding.json"),
                service=service,
                format_profile=MIKROTIK_SESSION_FORMAT_PROFILE,
                sensor_id=other_session_sensor,
            )
            traffic_config = self._traffic_config(
                store,
                alert_sensor=alert_sensor,
                zeek_sensor=zeek_sensor,
            )
            session_config = self._session_config(
                store,
                alert_sensor=alert_sensor,
                session_sensor=selected_session_sensor,
            )
            association = correlate_with_session(store, traffic_config, session_config)[0].payload["session_association"]
            self.assertEqual(association["outcome"], "no_match")
            self.assertEqual(association["session_evidence_ids"], [])
            self.assertNotIn("relationship", association)
            self.assertTrue(store.verify().valid)

    def test_missing_or_forged_session_coverage_is_insufficient(self) -> None:
        self._ingest(SourceType.SURICATA, "alert", fixture_bytes("suricata/alert.json"))
        self._ingest(SourceType.ZEEK, "zeek", fixture_bytes("zeek/conn.json"))
        missing = correlate_with_session(
            self.store,
            self._traffic_config(self.store),
            SessionCorrelationConfig((("sensor-lab-01", "sensor-lab-01"),), ()),
        )[0].payload
        self.assertEqual(missing["session_association"]["outcome"], "insufficient_evidence")
        self.assertNotIn("relationship", missing["session_association"])

        different_ip = json.loads(fixture_bytes("mikrotik/session-binding.json")); different_ip["assigned_ip"] = "198.51.100.99"
        self._ingest(SourceType.MIKROTIK, "different-ip", json.dumps(different_ip, separators=(",", ":")).encode(), format_profile=MIKROTIK_SESSION_FORMAT_PROFILE)
        forged = FixtureSessionCoverage("forged", "sensor-lab-01", "2026-08-15T07:58:00Z", "2026-08-15T08:02:00Z", "0" * 64)
        result = correlate_with_session(
            self.store,
            self._traffic_config(self.store),
            SessionCorrelationConfig((("sensor-lab-01", "sensor-lab-01"),), (forged,)),
        )[0].payload
        self.assertEqual(result["session_association"]["outcome"], "insufficient_evidence")
        self.assertEqual(result["session_association"]["rationale"], "session_fixture_coverage_scope_hash_mismatch")

    def test_degraded_or_excessive_session_candidates_are_insufficient(self) -> None:
        self._baseline(session_clock=ClockQuality.DEGRADED)
        degraded = correlate_with_session(self.store, self._traffic_config(self.store), self._session_config(self.store))[0].payload
        self.assertEqual(degraded["session_association"]["outcome"], "insufficient_evidence")
        self.assertEqual(degraded["session_association"]["rationale"], "matching_mikrotik_session_clock_quality_not_synchronized")

        with tempfile.TemporaryDirectory() as directory:
            store = FileEvidenceStore(Path(directory) / "unknown-session-clock", ledger_id="unknown-session-clock")
            service = IngestService(store)
            self._baseline(service=service, session_clock=ClockQuality.UNKNOWN)
            unknown = correlate_with_session(store, self._traffic_config(store), self._session_config(store))[0].payload
            self.assertEqual(unknown["session_association"]["outcome"], "insufficient_evidence")
            self.assertEqual(unknown["session_association"]["rationale"], "matching_mikrotik_session_clock_quality_not_synchronized")
            self.assertNotIn("relationship", unknown["session_association"])

        with tempfile.TemporaryDirectory() as directory:
            store = FileEvidenceStore(Path(directory) / "outside-coverage", ledger_id="degraded-session-coverage")
            service = IngestService(store)
            self._ingest(SourceType.SURICATA, "alert", fixture_bytes("suricata/alert.json"), service=service)
            self._ingest(SourceType.ZEEK, "zeek", fixture_bytes("zeek/conn.json"), service=service)
            late = json.loads(fixture_bytes("mikrotik/session-binding.json"))
            late.update({"observed_at": "2026-08-15T08:01:30Z", "valid_from": "2026-08-15T08:01:30Z", "valid_until": "2026-08-15T08:01:31Z", "session_ref": "session-degraded-late"})
            self._ingest(
                SourceType.MIKROTIK,
                "session-degraded-late",
                json.dumps(late, separators=(",", ":")).encode(),
                service=service,
                format_profile=MIKROTIK_SESSION_FORMAT_PROFILE,
                clock=ClockQuality.DEGRADED,
                observed_at="2026-08-15T08:01:30Z",
            )
            late_payload = correlate_with_session(store, self._traffic_config(store), self._session_config(store))[0].payload
            self.assertEqual(late_payload["session_association"]["outcome"], "insufficient_evidence")
            self.assertEqual(late_payload["session_association"]["rationale"], "matching_mikrotik_session_clock_quality_not_synchronized")

        with tempfile.TemporaryDirectory() as directory:
            store = FileEvidenceStore(Path(directory) / "evidence", ledger_id="session-overflow")
            service = IngestService(store)
            self._ingest(SourceType.SURICATA, "alert", fixture_bytes("suricata/alert.json"), service=service)
            self._ingest(SourceType.ZEEK, "zeek", fixture_bytes("zeek/conn.json"), service=service)
            raw = json.loads(fixture_bytes("mikrotik/session-binding.json"))
            for number in range(33):
                raw["session_ref"] = f"session-overflow-{number:02d}"
                self._ingest(SourceType.MIKROTIK, f"session-{number:02d}", json.dumps(raw, separators=(",", ":")).encode(), service=service, format_profile=MIKROTIK_SESSION_FORMAT_PROFILE)
            overflow = correlate_with_session(store, self._traffic_config(store), self._session_config(store))[0].payload
            self.assertEqual(overflow["session_association"]["outcome"], "insufficient_evidence")
            self.assertEqual(overflow["session_association"]["rationale"], "session_candidate_limit_exceeded")
            self.assertEqual(overflow["session_association"]["candidate_count"], 33)
            self.assertEqual(overflow["session_association"]["session_evidence_ids"], [])

    def test_reverse_ingestion_preserves_semantics_but_not_audit_derivation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            def build(name: str, order: tuple[str, str, str]):
                store = FileEvidenceStore(Path(directory) / name, ledger_id="session-order")
                service = IngestService(store)
                inputs = {
                    "alert": (SourceType.SURICATA, "alert", fixture_bytes("suricata/alert.json"), None),
                    "zeek": (SourceType.ZEEK, "zeek", fixture_bytes("zeek/conn.json"), None),
                    "session": (SourceType.MIKROTIK, "session", fixture_bytes("mikrotik/session-binding.json"), MIKROTIK_SESSION_FORMAT_PROFILE),
                }
                for name in order:
                    source, delivery, raw, profile = inputs[name]
                    self._ingest(source, delivery, raw, service=service, format_profile=profile)
                return correlate_with_session(store, self._traffic_config(store), self._session_config(store))[0]

            forward = build("forward", ("alert", "zeek", "session"))
            reverse = build("reverse", ("session", "zeek", "alert"))
        self.assertEqual(forward.semantic_correlation_id, reverse.semantic_correlation_id)
        self.assertNotEqual(forward.derivation_id, reverse.derivation_id)
        self.assertEqual(forward.payload["session_association"]["session_evidence_ids"], reverse.payload["session_association"]["session_evidence_ids"])

    def test_profile_or_version_mismatch_is_rejected_without_source_mutation(self) -> None:
        self._baseline()
        traffic_config, session_config = self._traffic_config(self.store), self._session_config(self.store)
        snapshot = self.store.verified_snapshot()
        for field, value, error in (
            ("adapter_version", "allowlisted-adapters.v2", "unsupported_observation_version"),
            ("schema_version", "observation-schema.v2", "unsupported_observation_version"),
        ):
            with self.subTest(field=field):
                manifests = list(snapshot.manifests)
                session = next(item for item in manifests if item["normalized_payload"]["kind"] == "mikrotik.session_binding")
                session[field] = value
                stale = VerifiedEvidenceSnapshot(snapshot.checkpoint, canonical_json(manifests))
                with patch.object(self.store, "verified_snapshot", return_value=stale):
                    with self.assertRaisesRegex(CorrelationError, error):
                        correlate_with_session(self.store, traffic_config, session_config)
        manifests = list(snapshot.manifests)
        session = next(item for item in manifests if item["normalized_payload"]["kind"] == "mikrotik.session_binding")
        session["normalized_payload"]["kind"] = "mikrotik.telemetry"
        stale = VerifiedEvidenceSnapshot(snapshot.checkpoint, canonical_json(manifests))
        with patch.object(self.store, "verified_snapshot", return_value=stale):
            with self.assertRaisesRegex(CorrelationError, "unsupported_observation_profile"):
                correlate_with_session(self.store, traffic_config, session_config)
        self.assertTrue(self.store.verify().valid)
