from __future__ import annotations

import ast
from pathlib import Path
import tempfile
import unittest

from network_ai import AuditCheckpoint, FileEvidenceStore, IngestItem, IngestService, SourceType

from .helpers import context, fixture_bytes


class StoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_directory.name) / "store"
        self.store = FileEvidenceStore(self.root, ledger_id="store-test-ledger")
        self.service = IngestService(self.store)

    def tearDown(self) -> None:
        self.temp_directory.cleanup()

    def _ingest_suricata(self, delivery: str, *, sensor: str = "sensor-lab-01") -> str:
        result = self.service.ingest(
            IngestItem(context(SourceType.SURICATA, delivery, sensor_id=sensor), fixture_bytes("suricata/alert.json"))
        )
        self.assertEqual(result.status, "accepted")
        assert result.evidence_id is not None
        return result.evidence_id

    def test_checkpoint_proves_extension_and_detects_raw_tampering(self) -> None:
        self._ingest_suricata("checkpoint-one")
        checkpoint = self.store.checkpoint()
        assert checkpoint is not None
        second = self.service.ingest(
            IngestItem(context(SourceType.ZEEK, "checkpoint-two"), fixture_bytes("zeek/conn.json"))
        )
        self.assertEqual(second.status, "accepted")
        self.assertTrue(self.store.verify(checkpoint).valid)
        manifest = next(item for item in self.store.accepted_manifests() if item["evidence_id"] == second.evidence_id)
        raw_path = self.root / "raw" / f"{manifest['raw']['raw_sha256']}.bin"
        raw_path.write_bytes(b"tampered")
        verification = self.store.verify(checkpoint)
        self.assertFalse(verification.valid)
        self.assertTrue(any(problem.startswith("raw_artifact_hash_mismatch") for problem in verification.problems))

    def test_invalid_ledger_tail_is_quarantined_before_reopen(self) -> None:
        self._ingest_suricata("recovery-one")
        ledger = self.root / "ledger.v1.jsonl"
        original_size = ledger.stat().st_size
        ledger.write_bytes(ledger.read_bytes() + b'{"partial":')
        reopened = FileEvidenceStore(self.root, ledger_id="store-test-ledger")
        self.assertEqual(ledger.stat().st_size, original_size)
        self.assertTrue(list((self.root / "recovery").glob("*.bin")))
        self.assertTrue(reopened.verify().valid)

    def test_source_and_sensor_are_part_of_delivery_identity(self) -> None:
        first = self._ingest_suricata("delivery-shared", sensor="sensor-a")
        second = self._ingest_suricata("delivery-shared", sensor="sensor-b")
        manifests = {item["evidence_id"]: item for item in self.store.accepted_manifests()}
        self.assertEqual(manifests[second]["suspected_prior_content_ids"], [first])

    def test_checkpoint_mismatch_fails(self) -> None:
        self._ingest_suricata("checkpoint-mismatch")
        checkpoint = self.store.checkpoint()
        assert checkpoint is not None
        forged = AuditCheckpoint(
            ledger_id=checkpoint.ledger_id,
            entry_index=checkpoint.entry_index,
            byte_offset=checkpoint.byte_offset,
            entry_hash="0" * 64,
        )
        self.assertFalse(self.store.verify(forged).valid)


class StaticBoundaryTests(unittest.TestCase):
    def test_package_contains_no_direct_network_process_or_deserialization_capabilities(self) -> None:
        source_root = Path(__file__).resolve().parents[1] / "src" / "network_ai"
        forbidden_modules = {
            "ftplib",
            "http",
            "importlib",
            "joblib",
            "paramiko",
            "pickle",
            "requests",
            "socket",
            "ssl",
            "subprocess",
            "telnetlib",
            "urllib",
        }
        forbidden_calls = {
            "__import__",
            "asyncio.create_subprocess_exec",
            "asyncio.create_subprocess_shell",
            "os.popen",
            "os.system",
        }
        violations: list[str] = []
        for source_file in source_root.glob("*.py"):
            tree = ast.parse(source_file.read_text(encoding="utf-8"), filename=str(source_file))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    violations.extend(
                        f"{source_file.name}:import:{alias.name}"
                        for alias in node.names
                        if alias.name.split(".")[0] in forbidden_modules
                    )
                elif isinstance(node, ast.ImportFrom) and node.module:
                    if node.module.split(".")[0] in forbidden_modules:
                        violations.append(f"{source_file.name}:from:{node.module}")
                elif isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        name = node.func.id
                    elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                        name = f"{node.func.value.id}.{node.func.attr}"
                    else:
                        continue
                    if name in forbidden_calls:
                        violations.append(f"{source_file.name}:call:{name}")
        self.assertEqual(violations, [])

    def test_outcome_contract_has_no_enforcement_executor_or_router_path(self) -> None:
        outcome_file = Path(__file__).resolve().parents[1] / "src" / "network_ai" / "outcomes.py"
        tree = ast.parse(outcome_file.read_text(encoding="utf-8"), filename=str(outcome_file))
        forbidden_functions = {"apply", "execute", "enforce", "rollback", "request_router"}
        self.assertEqual(
            {node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))} & forbidden_functions,
            set(),
        )
        self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "__import__" for node in ast.walk(tree)))
