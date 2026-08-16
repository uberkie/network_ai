from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest

from network_ai import FileEvidenceStore, IngestItem, IngestService, SourceType
from network_ai.contracts import ClockQuality, IntakeContext, ValidationError, semantic_json_sha256
from network_ai.outcomes import (
    AnalysisOutcome,
    AuthorityOutcome,
    AuditState,
    CorrelationOutcome,
    EnforcementOutcome,
    IngestionOutcome,
    NetworkState,
    OutcomeContractError,
    ProcessingStage,
    StageOutcome,
)
from network_ai.strict_json import parse_strict_json

from .helpers import CONFIG_HASH, context, fixture_bytes


class ContractTests(unittest.TestCase):
    def test_trusted_context_rejects_path_like_identifiers(self) -> None:
        with self.assertRaises(ValidationError):
            IntakeContext(
                source=SourceType.SURICATA,
                sensor_id="../../bad",
                delivery_id="delivery",
                format_profile="suricata-eve-alert.v1",
                observed_at="2026-08-15T08:00:05Z",
                ingested_at="2026-08-15T08:00:06Z",
                clock_quality=ClockQuality.SYNCHRONIZED,
                acquisition_config_sha256=CONFIG_HASH,
            )

    def test_decimal_semantic_hash_is_deterministic_and_type_distinct(self) -> None:
        integer = parse_strict_json(b'{"value":1}')
        decimal = parse_strict_json(b'{"value":1.0}')
        tagged_object = parse_strict_json(b'{"value":["decimal","1.0"]}')
        self.assertEqual(semantic_json_sha256(decimal), semantic_json_sha256(parse_strict_json(b'{"value":1.0}')))
        self.assertNotEqual(semantic_json_sha256(integer), semantic_json_sha256(decimal))
        self.assertNotEqual(semantic_json_sha256(decimal), semantic_json_sha256(tagged_object))

    def test_envelope_payload_is_deeply_immutable_from_callers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            service = IngestService(FileEvidenceStore(Path(directory) / "store", ledger_id="contract-test"))
            result = service.ingest(
                IngestItem(context(SourceType.MIKROTIK, "immutable-one"), fixture_bytes("mikrotik/telemetry.json"))
            )
            manifest = next(item for item in service.store.accepted_manifests() if item["evidence_id"] == result.evidence_id)
            payload = manifest["normalized_payload"]
            payload["interfaces"][0]["name"] = "mutated"
            fresh_manifest = next(item for item in service.store.accepted_manifests() if item["evidence_id"] == result.evidence_id)
            self.assertEqual(fresh_manifest["normalized_payload"]["interfaces"][0]["name"], "ether1")

    def test_raw_and_canonical_hashes_are_separate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = FileEvidenceStore(Path(directory) / "store", ledger_id="hash-test")
            service = IngestService(store)
            first_raw = fixture_bytes("suricata/alert.json")
            second_raw = b"{\n  \"timestamp\": \"2026-08-15T08:00:01.123456+00:00\", \"event_type\": \"alert\", \"event_id\": \"suricata-alert-001\", \"src_ip\": \"198.51.100.10\", \"src_port\": 49152, \"dest_ip\": \"203.0.113.20\", \"dest_port\": 443, \"proto\": \"tcp\", \"alert\": {\"signature_id\": 2100365, \"signature\": \"ET POLICY Synthetic test alert\", \"severity\": 2}\n}"
            first = service.ingest(IngestItem(context(SourceType.SURICATA, "hash-one"), first_raw))
            second = service.ingest(IngestItem(context(SourceType.SURICATA, "hash-two"), second_raw))
            manifests = {item["evidence_id"]: item for item in store.accepted_manifests()}
            self.assertNotEqual(manifests[first.evidence_id]["raw"]["raw_sha256"], manifests[second.evidence_id]["raw"]["raw_sha256"])
            self.assertEqual(manifests[first.evidence_id]["raw"]["canonical_sha256"], manifests[second.evidence_id]["raw"]["canonical_sha256"])

    def test_stage_outcomes_are_closed_typed_and_do_not_hide_network_state(self) -> None:
        correlation = StageOutcome(
            ProcessingStage.CORRELATION,
            CorrelationOutcome.AMBIGUOUS,
            "reported",
            ("evidence-a", "evidence-b"),
        )
        self.assertEqual(correlation.as_manifest()["outcome"], "ambiguous")
        self.assertEqual(correlation.as_manifest()["evidence_refs"], ["evidence-a", "evidence-b"])
        self.assertEqual(
            StageOutcome(
                ProcessingStage.ANALYSIS,
                AnalysisOutcome.INCONCLUSIVE,
                "reported",
            ).as_manifest()["outcome"],
            "inconclusive",
        )
        self.assertEqual(
            StageOutcome(
                ProcessingStage.AUTHORITY,
                AuthorityOutcome.REQUIRES_REVIEW,
                "reported",
            ).as_manifest()["outcome"],
            "requires_review",
        )
        enforcement = StageOutcome(
            ProcessingStage.ENFORCEMENT,
            EnforcementOutcome.EXECUTION_FAILED,
            "reported",
            network_state=NetworkState.UNKNOWN,
        )
        self.assertEqual(enforcement.as_manifest()["network_state"], "unknown")
        with self.assertRaisesRegex(OutcomeContractError, "invalid_stage_outcome_pair"):
            StageOutcome(ProcessingStage.CORRELATION, AnalysisOutcome.NORMAL, "reported")
        with self.assertRaisesRegex(OutcomeContractError, "invalid_outcome_reason_code"):
            StageOutcome(ProcessingStage.CORRELATION, CorrelationOutcome.AMBIGUOUS, "nearest_candidate")
        with self.assertRaisesRegex(OutcomeContractError, "outcome_evidence_refs_must_be_unique_and_sorted"):
            StageOutcome(ProcessingStage.CORRELATION, CorrelationOutcome.AMBIGUOUS, "reported", ("evidence-b", "evidence-a"))
        with self.assertRaisesRegex(OutcomeContractError, "non_enforcement_network_state_not_applicable"):
            StageOutcome(
                ProcessingStage.CORRELATION,
                CorrelationOutcome.NO_MATCH,
                "reported",
                network_state=NetworkState.UNKNOWN,
            )
        with self.assertRaisesRegex(OutcomeContractError, "invalid_enforcement_outcome_network_state_pair"):
            StageOutcome(ProcessingStage.ENFORCEMENT, EnforcementOutcome.REJECTED, "reported")
        with self.assertRaisesRegex(OutcomeContractError, "invalid_enforcement_outcome_network_state_pair"):
            StageOutcome(
                ProcessingStage.ENFORCEMENT,
                EnforcementOutcome.APPLIED,
                "reported",
                network_state=NetworkState.UNKNOWN,
            )
        with self.assertRaisesRegex(OutcomeContractError, "non_ingestion_audit_state_must_be_not_applicable"):
            StageOutcome(
                ProcessingStage.CORRELATION,
                CorrelationOutcome.NO_MATCH,
                "reported",
                audit_state=AuditState.WRITTEN,
                audit_entry_index=0,
            )
        with self.assertRaisesRegex(OutcomeContractError, "accepted_requires_written_audit_and_evidence_reference"):
            StageOutcome(
                ProcessingStage.INGESTION,
                IngestionOutcome.ACCEPTED,
                "accepted",
                audit_state=AuditState.WRITTEN,
                audit_entry_index=0,
            )
        with self.assertRaisesRegex(OutcomeContractError, "durable_quarantine_requires_written_audit_without_evidence_reference"):
            StageOutcome(
                ProcessingStage.INGESTION,
                IngestionOutcome.MALFORMED,
                "invalid_json",
                evidence_refs=("forged-evidence",),
                audit_state=AuditState.WRITTEN,
                audit_entry_index=0,
            )
        with self.assertRaisesRegex(OutcomeContractError, "invalid_ingestion_audit_state"):
            StageOutcome(
                ProcessingStage.INGESTION,
                IngestionOutcome.REJECTED,
                "non_bytes_input",
                audit_state=AuditState.WRITTEN,
                audit_entry_index=0,
            )
