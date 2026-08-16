from __future__ import annotations

import json
import hashlib
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from network_ai import FileEvidenceStore, IngestItem, IngestService, SourceType
from network_ai.contracts import MAX_RECORD_BYTES, MIKROTIK_SESSION_FORMAT_PROFILE
from network_ai.outcomes import AuditState, IngestionOutcome, ProcessingStage, ingestion_outcome_for_validation_code

from .helpers import CONFIG_HASH, FIXTURES, context, fixture_bytes


class IngestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        self.store = FileEvidenceStore(Path(self.temp_directory.name) / "evidence", ledger_id="test-ledger")
        self.service = IngestService(self.store)

    def tearDown(self) -> None:
        self.temp_directory.cleanup()

    def test_ingests_all_supported_synthetic_profiles(self) -> None:
        records = (
            (SourceType.SURICATA, "suricata-delivery-001", "suricata/alert.json"),
            (SourceType.ZEEK, "zeek-delivery-001", "zeek/conn.json"),
            (SourceType.MIKROTIK, "mikrotik-delivery-001", "mikrotik/telemetry.json"),
        )
        results = [
            self.service.ingest(IngestItem(context(source, delivery), fixture_bytes(path)))
            for source, delivery, path in records
        ]
        self.assertEqual([result.status for result in results], ["accepted", "accepted", "accepted"])
        manifests = self.store.accepted_manifests()
        self.assertEqual(len(manifests), 3)
        self.assertTrue(self.store.verify().valid)
        kinds = {manifest["normalized_payload"]["kind"] for manifest in manifests}
        self.assertEqual(kinds, {"suricata.alert", "zeek.conn", "mikrotik.telemetry"})
        for manifest in manifests:
            self.assertEqual(manifest["parser_version"], "strict-json.v1")
            self.assertEqual(manifest["adapter_version"], "allowlisted-adapters.v2")
            self.assertEqual(manifest["schema_version"], "observation-schema.v2")
            self.assertEqual(manifest["intake"]["acquisition_config_sha256"], CONFIG_HASH)

    def test_quarantines_malformed_oversized_and_secret_records(self) -> None:
        duplicate = self.service.ingest(
            IngestItem(context(SourceType.SURICATA, "invalid-duplicate"), fixture_bytes("invalid/duplicate-key.json"))
        )
        secret = self.service.ingest(
            IngestItem(context(SourceType.MIKROTIK, "invalid-secret"), fixture_bytes("invalid/mikrotik-secret.json"))
        )
        oversized = self.service.ingest(
            IngestItem(context(SourceType.SURICATA, "invalid-oversized"), b"x" * (MAX_RECORD_BYTES + 1))
        )
        self.assertEqual(duplicate.quarantine_code, "duplicate_json_key")
        self.assertEqual(secret.quarantine_code, "forbidden_mikrotik_field")
        self.assertEqual(oversized.quarantine_code, "record_size_exceeded")
        self.assertEqual(self.store.accepted_manifests(), ())
        self.assertTrue(self.store.verify().valid)

    def test_quarantines_invalid_network_addresses_and_protocols(self) -> None:
        invalid_ip = fixture_bytes("suricata/alert.json").replace(b'"src_ip":"198.51.100.10"', b'"src_ip":"not-an-ip"')
        invalid_protocol = fixture_bytes("zeek/conn.json").replace(b'"proto":"tcp"', b'"proto":"madeup"')
        first = self.service.ingest(IngestItem(context(SourceType.SURICATA, "invalid-ip"), invalid_ip))
        second = self.service.ingest(IngestItem(context(SourceType.ZEEK, "invalid-protocol"), invalid_protocol))
        self.assertEqual(first.quarantine_code, "invalid_network_address")
        self.assertEqual(second.quarantine_code, "invalid_network_protocol")

    def test_quarantines_invalid_transport_ports_and_unsupported_input_profile(self) -> None:
        for label, value in (
            ("missing", None),
            ("string", "443"),
            ("boolean", True),
            ("zero", 0),
            ("negative", -1),
            ("too-large", 65_536),
            ("decimal", 443.5),
        ):
            record = json.loads(fixture_bytes("suricata/alert.json"))
            if value is None:
                record.pop("src_port")
            else:
                record["src_port"] = value
            result = self.service.ingest(
                IngestItem(
                    context(SourceType.SURICATA, f"invalid-suricata-port-{label}"),
                    json.dumps(record, separators=(",", ":")).encode(),
                )
            )
            self.assertEqual(result.quarantine_code, "invalid_network_port")
        zeek = json.loads(fixture_bytes("zeek/conn.json")); zeek["id.resp_p"] = "443"
        wrong_zeek_field = self.service.ingest(
            IngestItem(
                context(SourceType.ZEEK, "invalid-zeek-port"),
                json.dumps(zeek, separators=(",", ":")).encode(),
            )
        )
        self.assertEqual(wrong_zeek_field.quarantine_code, "invalid_network_port")
        unsupported_context = replace(
            context(SourceType.ZEEK, "unsupported-schema-version"),
            format_profile="zeek-json-conn.v999",
        )
        unsupported = self.service.ingest(IngestItem(unsupported_context, fixture_bytes("zeek/conn.json")))
        self.assertEqual(unsupported.quarantine_code, "unsupported_format_profile")

    def test_quarantines_malformed_zeek_record(self) -> None:
        malformed = json.loads(fixture_bytes("zeek/conn.json")); malformed.pop("id.orig_p")
        result = self.service.ingest(
            IngestItem(
                context(SourceType.ZEEK, "malformed-zeek"),
                json.dumps(malformed, separators=(",", ":")).encode(),
            )
        )
        self.assertEqual(result.quarantine_code, "invalid_network_port")

    def test_session_binding_profile_has_explicit_versions_and_quarantines_hostile_inputs(self) -> None:
        session_context = context(
            SourceType.MIKROTIK,
            "session-binding-accepted",
            format_profile=MIKROTIK_SESSION_FORMAT_PROFILE,
        )
        accepted = self.service.ingest(
            IngestItem(session_context, fixture_bytes("mikrotik/session-binding.json"))
        )
        self.assertEqual(accepted.status, "accepted")
        manifest = next(item for item in self.store.accepted_manifests() if item["evidence_id"] == accepted.evidence_id)
        self.assertEqual(manifest["adapter_version"], "mikrotik-session-binding-adapter.v1")
        self.assertEqual(manifest["schema_version"], "mikrotik-session-binding.v1")
        self.assertIsNone(manifest["source_event_id"])

        cases = (
            ("extra-private-field", lambda item: item.__setitem__("username", "not-allowed"), "unsupported_mikrotik_session_field"),
            ("extra-nas-field", lambda item: item.__setitem__("nas_id", "not-allowed"), "unsupported_mikrotik_session_field"),
            ("missing-end", lambda item: item.pop("valid_until"), "unsupported_mikrotik_session_field"),
            ("unsafe-ref", lambda item: item.__setitem__("subscriber_ref", "../../bad"), "invalid_session_reference"),
            ("long-interval", lambda item: item.__setitem__("valid_until", "2026-10-15T08:00:00Z"), "session_validity_interval_exceeded"),
            ("out-of-interval", lambda item: item.__setitem__("observed_at", "2026-08-15T07:49:59Z"), "session_observed_at_outside_validity_interval"),
            ("intake-skew", lambda item: item.__setitem__("observed_at", "2026-08-15T08:06:00Z"), "session_observed_at_outside_intake_skew"),
        )
        for label, mutate, code in cases:
            record = json.loads(fixture_bytes("mikrotik/session-binding.json"))
            mutate(record)
            result = self.service.ingest(
                IngestItem(
                    context(
                        SourceType.MIKROTIK,
                        f"session-binding-{label}",
                        format_profile=MIKROTIK_SESSION_FORMAT_PROFILE,
                    ),
                    json.dumps(record, separators=(",", ":")).encode(),
                )
            )
            self.assertEqual(result.quarantine_code, code)

    def test_duplicate_delivery_and_repeated_content_are_distinct_semantics(self) -> None:
        raw = fixture_bytes("suricata/alert.json")
        first = self.service.ingest(IngestItem(context(SourceType.SURICATA, "delivery-one"), raw))
        retry = self.service.ingest(IngestItem(context(SourceType.SURICATA, "delivery-one"), raw))
        repeat = self.service.ingest(IngestItem(context(SourceType.SURICATA, "delivery-two"), raw))
        self.assertEqual(first.status, "accepted")
        self.assertEqual(retry.status, "duplicate_delivery")
        self.assertEqual(repeat.status, "accepted")
        manifests = self.store.accepted_manifests()
        self.assertEqual(len(manifests), 2)
        repeated = next(manifest for manifest in manifests if manifest["evidence_id"] == repeat.evidence_id)
        self.assertEqual(repeated["suspected_prior_content_ids"], [first.evidence_id])

    def test_delivery_conflict_is_quarantined(self) -> None:
        accepted = self.service.ingest(
            IngestItem(context(SourceType.SURICATA, "same-delivery"), fixture_bytes("suricata/alert.json"))
        )
        conflicting_raw = fixture_bytes("suricata/alert.json").replace(b"\"severity\":2", b"\"severity\":3")
        conflicting = self.service.ingest(
            IngestItem(context(SourceType.SURICATA, "same-delivery"), conflicting_raw)
        )
        self.assertEqual(accepted.status, "accepted")
        self.assertEqual(conflicting.status, "quarantined")
        self.assertEqual(conflicting.quarantine_code, "delivery_identity_conflict")

    def test_batch_is_bounded(self) -> None:
        item = IngestItem(context(SourceType.SURICATA, "batch-one"), fixture_bytes("suricata/alert.json"))
        result = self.service.ingest_batch((item,))
        self.assertEqual(result[0].status, "accepted")
        seen = 0

        def unbounded():
            nonlocal seen
            while True:
                seen += 1
                yield IngestItem(context(SourceType.SURICATA, f"batch-{seen}"), fixture_bytes("suricata/alert.json"))

        limited = self.service.ingest_batch(unbounded())
        self.assertEqual(len(limited), 1_025)
        self.assertEqual(seen, 1_025)
        self.assertEqual({item.status for item in limited}, {"rejected"})
        self.assertEqual(
            {item.stage_outcome.reason_code for item in limited},
            {"batch_record_limit_exceeded"},
        )
        self.assertEqual(len(self.store.accepted_manifests()), 1)

    def test_terminal_ingestion_outcomes_cover_validation_storage_and_iterator_failures(self) -> None:
        accepted = self.service.ingest(
            IngestItem(context(SourceType.SURICATA, "outcome-accepted"), fixture_bytes("suricata/alert.json"))
        )
        self.assertEqual(accepted.stage_outcome.outcome, IngestionOutcome.ACCEPTED)
        self.assertEqual(accepted.stage_outcome.audit_state, AuditState.WRITTEN)
        self.assertEqual(accepted.stage_outcome.evidence_refs, (accepted.evidence_id,))

        duplicate = self.service.ingest(
            IngestItem(context(SourceType.SURICATA, "outcome-accepted"), fixture_bytes("suricata/alert.json"))
        )
        self.assertEqual(duplicate.status, "duplicate_delivery")
        self.assertEqual(duplicate.stage_outcome.outcome, IngestionOutcome.DUPLICATE_DELIVERY)
        self.assertEqual(duplicate.stage_outcome.audit_state, AuditState.PREEXISTING_EVIDENCE)
        self.assertEqual(duplicate.audit_entry_index, accepted.audit_entry_index)
        self.assertEqual(duplicate.stage_outcome.evidence_refs, (accepted.evidence_id,))

        malformed = self.service.ingest(
            IngestItem(context(SourceType.SURICATA, "outcome-malformed"), b"{bad")
        )
        self.assertEqual(malformed.stage_outcome.outcome, IngestionOutcome.MALFORMED)
        self.assertEqual(malformed.stage_outcome.reason_code, "invalid_json")
        self.assertEqual(malformed.stage_outcome.audit_state, AuditState.WRITTEN)

        unsupported_context = replace(context(SourceType.ZEEK, "outcome-unsupported"), format_profile="zeek-json-conn.v999")
        unsupported = self.service.ingest(IngestItem(unsupported_context, fixture_bytes("zeek/conn.json")))
        self.assertEqual(unsupported.stage_outcome.outcome, IngestionOutcome.UNSUPPORTED_VERSION)
        self.assertEqual(unsupported.stage_outcome.reason_code, "unsupported_format_profile")

        rejected = self.service.ingest(
            IngestItem(context(SourceType.SURICATA, "outcome-oversized"), b"x" * (MAX_RECORD_BYTES + 1))
        )
        self.assertEqual(rejected.stage_outcome.outcome, IngestionOutcome.REJECTED)
        self.assertEqual(rejected.stage_outcome.reason_code, "record_size_exceeded")
        self.assertEqual(rejected.stage_outcome.audit_state, AuditState.WRITTEN)

        non_bytes = self.service.ingest(IngestItem(context(SourceType.SURICATA, "outcome-non-bytes"), "not-bytes"))  # type: ignore[arg-type]
        self.assertEqual(non_bytes.status, "rejected")
        self.assertEqual(non_bytes.stage_outcome.reason_code, "non_bytes_input")
        self.assertEqual(non_bytes.stage_outcome.audit_state, AuditState.NOT_APPLICABLE)
        self.assertEqual(self.store.verify().valid, True)

        mutated_context = context(SourceType.SURICATA, "outcome-mutated-context")
        object.__setattr__(mutated_context, "sensor_id", "../outside")
        before_mutated_context = len(self.store.accepted_manifests())
        invalid_context = self.service.ingest(IngestItem(mutated_context, fixture_bytes("suricata/alert.json")))
        self.assertEqual(invalid_context.status, "rejected")
        self.assertEqual(invalid_context.stage_outcome.reason_code, "invalid_intake_context")
        self.assertEqual(invalid_context.stage_outcome.audit_state, AuditState.NOT_APPLICABLE)
        self.assertEqual(len(self.store.accepted_manifests()), before_mutated_context)

        with patch("network_ai.ingest.parse_strict_json", side_effect=RuntimeError("unexpected parser detail")):
            parser_failure = self.service.ingest(
                IngestItem(context(SourceType.SURICATA, "outcome-parser-failure"), fixture_bytes("suricata/alert.json"))
            )
        self.assertEqual(parser_failure.stage_outcome.outcome, IngestionOutcome.QUARANTINED)
        self.assertEqual(parser_failure.stage_outcome.reason_code, "parser_failure")
        self.assertEqual(parser_failure.stage_outcome.audit_state, AuditState.WRITTEN)

        with patch.object(self.store, "append_evidence", side_effect=OSError("disk unavailable")):
            accepted_store_failure = self.service.ingest(
                IngestItem(context(SourceType.SURICATA, "outcome-accepted-store-failure"), fixture_bytes("suricata/alert.json"))
            )
        self.assertEqual(accepted_store_failure.status, "persistence_failed")
        self.assertEqual(accepted_store_failure.stage_outcome.outcome, IngestionOutcome.PERSISTENCE_FAILED)
        self.assertEqual(accepted_store_failure.stage_outcome.audit_state, AuditState.UNAVAILABLE)
        self.assertEqual(accepted_store_failure.evidence_id, None)

        with patch.object(self.store, "append_quarantine", side_effect=OSError("disk unavailable")):
            quarantine_store_failure = self.service.ingest(
                IngestItem(context(SourceType.SURICATA, "outcome-quarantine-store-failure"), b"{bad")
            )
        self.assertEqual(quarantine_store_failure.status, "persistence_failed")
        self.assertEqual(quarantine_store_failure.stage_outcome.audit_state, AuditState.UNAVAILABLE)
        self.assertTrue(self.store.verify().valid)

        valid = IngestItem(context(SourceType.SURICATA, "batch-valid"), fixture_bytes("suricata/alert.json"))
        invalid = IngestItem(context(SourceType.SURICATA, "batch-invalid"), "not-bytes")  # type: ignore[arg-type]
        mixed = self.service.ingest_batch((valid, invalid))
        self.assertEqual([item.status for item in mixed], ["accepted", "rejected"])
        self.assertEqual(mixed[1].stage_outcome.reason_code, "non_bytes_input")

        def broken_after_prefix():
            yield IngestItem(context(SourceType.SURICATA, "broken-prefix"), fixture_bytes("suricata/alert.json"))
            raise RuntimeError("iterator detail")

        broken = self.service.ingest_batch(broken_after_prefix())
        self.assertEqual([item.status for item in broken], ["rejected", "rejected"])
        self.assertEqual({item.stage_outcome.reason_code for item in broken}, {"batch_iterator_failure"})
        self.assertEqual(self.service.ingest_batch(None)[0].stage_outcome.reason_code, "invalid_batch_iterable")  # type: ignore[arg-type]
        self.assertTrue(self.store.verify().valid)

    def test_validation_code_mapping_is_closed_and_total(self) -> None:
        expected = {
            IngestionOutcome.MALFORMED: (
                "duplicate_json_key", "invalid_json", "invalid_network_address", "invalid_network_port",
                "invalid_network_port_for_protocol", "invalid_network_protocol", "invalid_session_reference",
                "invalid_source_event_id", "invalid_suricata_severity", "invalid_timestamp", "invalid_utf8",
                "json_array_items_exceeded", "json_nesting_exceeded", "json_object_members_exceeded",
                "json_root_not_object", "missing_or_invalid_required_field", "non_finite_number",
                "session_observed_at_outside_intake_skew", "session_observed_at_outside_validity_interval",
                "session_validity_interval_exceeded", "timestamp_timezone_required", "zeek_timestamp_out_of_range",
                "zeek_timestamp_precision_exceeded",
            ),
            IngestionOutcome.REJECTED: (
                "batch_byte_limit_exceeded", "batch_iterator_failure", "batch_record_limit_exceeded",
                "delivery_identity_conflict", "forbidden_mikrotik_field", "invalid_allowlisted_field",
                "invalid_batch_iterable", "invalid_ingest_item", "invalid_intake_context", "non_bytes_input",
                "record_size_exceeded", "unsupported_mikrotik_session_field",
            ),
            IngestionOutcome.UNSUPPORTED_VERSION: (
                "unsupported_format_profile", "unsupported_source", "unsupported_suricata_event_type",
                "unsupported_zeek_log_type",
            ),
        }
        for outcome, codes in expected.items():
            for code in codes:
                with self.subTest(code=code):
                    self.assertEqual(ingestion_outcome_for_validation_code(code), (outcome, code))
        self.assertEqual(
            ingestion_outcome_for_validation_code("unrecognized_adapter_code"),
            (IngestionOutcome.QUARANTINED, "unmapped_validation_error"),
        )

    def test_fixture_manifest_hashes_and_synthetic_provenance(self) -> None:
        manifest = json.loads((FIXTURES / "MANIFEST.json").read_text(encoding="utf-8"))
        self.assertEqual(CONFIG_HASH, hashlib.sha256((FIXTURES / "MANIFEST.json").read_bytes()).hexdigest())
        self.assertEqual(manifest["fixture_contract_version"], "fixtures.v3")
        self.assertEqual(manifest["origin"], "synthetic-only")
        self.assertIn("credentials", manifest["prohibited_content"])
        for relative_path, specification in manifest["files"].items():
            self.assertRegex(specification["sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(
                specification["sha256"],
                hashlib.sha256((FIXTURES / relative_path).read_bytes()).hexdigest(),
            )
