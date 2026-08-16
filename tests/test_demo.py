from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from network_ai.demo import run_demo

from .helpers import FIXTURES


class DemoTests(unittest.TestCase):
    def test_demo_runs_end_to_end_and_reingest_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "demo-store"
            first = run_demo(root, FIXTURES)
            second = run_demo(root, FIXTURES)
        self.assertTrue(first["audit_valid"])
        self.assertEqual(first["accepted_evidence_count"], 4)
        self.assertEqual([item["status"] for item in first["results"]], ["accepted", "accepted", "accepted", "accepted"])
        self.assertEqual(first["session_associations"][0]["outcome"], "probable_match")
        self.assertNotIn("subscriber-C6127", str(first["session_associations"]))
        self.assertTrue(second["audit_valid"])
        self.assertEqual(second["accepted_evidence_count"], 4)
        self.assertEqual(
            [item["status"] for item in second["results"]],
            ["duplicate_delivery", "duplicate_delivery", "duplicate_delivery", "duplicate_delivery"],
        )
