from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from network_ai import FileEvidenceStore, IngestItem, IngestService, SourceType
from network_ai.analyst import build_analyst_snapshot, filter_evidence
from network_ai.demo import run_demo

from .helpers import FIXTURES, context, fixture_bytes


class AnalystProjectionTests(unittest.TestCase):
    def test_demo_snapshot_is_read_only_and_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            run_demo(root, FIXTURES)
            ledger = root / "ledger.v1.jsonl"
            before = (ledger.stat().st_mtime_ns, ledger.stat().st_size, ledger.read_bytes())
            snapshot = build_analyst_snapshot(root, None)
            after = (ledger.stat().st_mtime_ns, ledger.stat().st_size, ledger.read_bytes())
        self.assertEqual(before, after)
        self.assertTrue(snapshot["store"]["available"])
        self.assertEqual(snapshot["overview"]["accepted_count"], 4)
        self.assertEqual(snapshot["overview"]["source_counts"]["suricata"], 1)
        self.assertEqual(snapshot["overview"]["source_counts"]["zeek"], 1)
        self.assertEqual(snapshot["overview"]["source_counts"]["mikrotik"], 2)
        self.assertEqual(snapshot["correlations"][0]["traffic_outcome"], "probable_match")
        self.assertEqual(snapshot["correlations"][0]["session_outcome"], "probable_match")
        encoded = json.dumps(snapshot)
        self.assertNotIn("subscriber-C6127", encoded)
        self.assertNotIn("session-C6127-001", encoded)
        self.assertFalse(snapshot["flows"]["available"])
        kinds = {row["kind"] for row in snapshot["evidence"] if row["outcome"] == "accepted"}
        self.assertEqual(kinds, {"suricata.alert", "zeek.conn", "mikrotik.telemetry", "mikrotik.session_binding"})
        suricata_only = filter_evidence(snapshot["evidence"], source="suricata")
        self.assertEqual([row["source"] for row in suricata_only], ["suricata"])
        self.assertEqual(len(filter_evidence(snapshot["evidence"], text="ET POLICY")), 1)

    def test_missing_store_is_visible_and_not_created(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "absent"
            snapshot = build_analyst_snapshot(missing, None)
            self.assertFalse(missing.exists())
        self.assertFalse(snapshot["store"]["available"])
        self.assertIn("evidence_store_unavailable", snapshot["problems"])
        self.assertEqual(snapshot["evidence"], [])

    def test_symlink_store_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            real = Path(directory) / "real"
            real.mkdir()
            link = Path(directory) / "link"
            link.symlink_to(real)
            snapshot = build_analyst_snapshot(link, None)
        self.assertIn("evidence_store_must_not_be_symlink", snapshot["problems"])
        self.assertFalse(snapshot["store"]["available"])

    def test_quarantined_rows_are_projected_without_raw_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            service = IngestService(FileEvidenceStore(root, ledger_id="analyst-quarantine"))
            result = service.ingest(
                IngestItem(context(SourceType.SURICATA, "bad-json"), fixture_bytes("invalid/duplicate-key.json"))
            )
            self.assertEqual(result.status, "quarantined")
            snapshot = build_analyst_snapshot(root, None)
        self.assertEqual(snapshot["overview"]["quarantined_count"], 1)
        row = snapshot["evidence"][0]
        self.assertEqual(row["outcome"], "quarantined")
        self.assertEqual(row["reason_code"], "duplicate_json_key")
        self.assertIsNone(row["evidence_id"])
        self.assertNotIn("raw", row)
        self.assertNotIn("normalized_payload", row)
