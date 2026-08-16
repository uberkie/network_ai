"""Single-process, owner-only, tamper-evident local evidence storage.

The ledger is not WORM storage. Structural verification detects corruption and
anchored verification detects changes before a checkpoint that the caller keeps
outside this directory. An owner who can replace both the directory and an
external checkpoint is outside the Phase 1 threat model.
"""

from __future__ import annotations

from dataclasses import dataclass
import errno
import json
import os
from pathlib import Path
import threading
import uuid
from typing import Any, Mapping

from .contracts import (
    CONTRACT_VERSION,
    LEDGER_VERSION,
    DataClassification,
    EvidenceEnvelope,
    PayloadAccessPolicy,
    RedactionStatus,
    RetentionPolicy,
    ValidationError,
    canonical_json,
    require_sha256,
    sha256_bytes,
)
from .strict_json import parse_strict_json


@dataclass(frozen=True)
class AuditCheckpoint:
    ledger_id: str
    entry_index: int
    byte_offset: int
    entry_hash: str


@dataclass(frozen=True)
class PersistResult:
    status: str
    evidence_id: str | None
    audit_entry_index: int
    quarantine_code: str | None = None


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    problems: tuple[str, ...]
    terminal_checkpoint: AuditCheckpoint | None


@dataclass(frozen=True)
class VerifiedEvidenceSnapshot:
    """One lock-consistent, verified view for derived fixture processing."""

    checkpoint: AuditCheckpoint | None
    manifests_json: str

    @property
    def manifests(self) -> tuple[dict[str, Any], ...]:
        value = json.loads(self.manifests_json)
        if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
            raise RuntimeError("invalid_snapshot_manifests")
        return tuple(value)


@dataclass(frozen=True)
class VerifiedAuditEntry:
    """One immutable, durable ledger entry for read-only replay."""

    index: int
    manifest_json: str

    @property
    def manifest(self) -> dict[str, Any]:
        value = json.loads(self.manifest_json)
        if not isinstance(value, dict):
            raise RuntimeError("invalid_audit_snapshot_manifest")
        return value


@dataclass(frozen=True)
class VerifiedAuditSnapshot:
    """A single read-only audit view; no recovery is performed to create it."""

    ledger_id: str
    checkpoint: AuditCheckpoint | None
    entries: tuple[VerifiedAuditEntry, ...]

    @property
    def accepted_snapshot(self) -> VerifiedEvidenceSnapshot:
        manifests = [entry.manifest for entry in self.entries if entry.manifest.get("outcome") == "accepted"]
        manifests.sort(key=lambda item: item.get("evidence_id", ""))
        return VerifiedEvidenceSnapshot(self.checkpoint, canonical_json(manifests))


@dataclass(frozen=True)
class _LedgerEntry:
    index: int
    offset: int
    entry_hash: str
    manifest: dict[str, Any]


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("unable to write complete file")
        view = view[written:]


def _fsync_directory(directory: Path) -> None:
    """Best-effort directory durability on platforms that support it."""
    if os.name == "nt":
        return
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class FileEvidenceStore:
    """A thread-safe store intended for one process and synthetic fixtures only.

    Commit protocol: raw bytes are persisted first, then a single fsynced ledger
    entry commits the manifest. Orphan raw artifacts have no valid ledger entry,
    are never queried, and can be safely committed by a later identical ingest.
    """

    def __init__(self, root: Path | str, *, ledger_id: str | None = None) -> None:
        self.root = Path(root)
        self.raw_root = self.root / "raw"
        self.quarantine_raw_root = self.root / "quarantine" / "raw"
        self.recovery_root = self.root / "recovery"
        self.ledger_path = self.root / "ledger.v1.jsonl"
        self.metadata_path = self.root / "ledger-meta.v1.json"
        self._lock = threading.RLock()
        for directory in (self.root, self.raw_root, self.quarantine_raw_root, self.recovery_root):
            directory.mkdir(parents=True, exist_ok=True)
            self._set_owner_mode(directory, 0o700)
        self.ledger_id = self._initialize_metadata(ledger_id)
        self._entries: list[_LedgerEntry] = []
        with self._lock:
            self._recover_ledger()

    @staticmethod
    def _set_owner_mode(path: Path, mode: int) -> None:
        if os.name != "nt":
            path.chmod(mode)

    def _initialize_metadata(self, requested_ledger_id: str | None) -> str:
        if self.metadata_path.exists():
            try:
                metadata = parse_strict_json(self.metadata_path.read_bytes())
            except ValidationError as exc:
                raise RuntimeError("invalid_ledger_metadata") from exc
            ledger_id = metadata.get("ledger_id")
            if metadata.get("ledger_version") != LEDGER_VERSION or not isinstance(ledger_id, str):
                raise RuntimeError("invalid_ledger_metadata")
            if requested_ledger_id is not None and requested_ledger_id != ledger_id:
                raise RuntimeError("ledger_id_mismatch")
            return ledger_id
        ledger_id = requested_ledger_id or uuid.uuid4().hex
        metadata = canonical_json({"ledger_id": ledger_id, "ledger_version": LEDGER_VERSION}).encode("utf-8")
        self._atomic_replace(self.metadata_path, metadata)
        return ledger_id

    def _atomic_replace(self, target: Path, data: bytes) -> None:
        temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            _write_all(descriptor, data)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, target)
        self._set_owner_mode(target, 0o600)
        _fsync_directory(target.parent)

    def _write_content_addressed(self, directory: Path, raw_sha256: str, raw: bytes) -> Path:
        path = directory / f"{raw_sha256}.bin"
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise
            existing = path.read_bytes()
            if existing != raw or sha256_bytes(existing) != raw_sha256:
                raise RuntimeError("content_address_collision_or_tamper")
            return path
        try:
            _write_all(descriptor, raw)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._set_owner_mode(path, 0o600)
        _fsync_directory(directory)
        return path

    @staticmethod
    def _ledger_material(index: int, previous_entry_hash: str | None, manifest: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "entry_index": index,
            "ledger_version": LEDGER_VERSION,
            "manifest": manifest,
            "previous_entry_hash": previous_entry_hash,
        }

    def _parse_ledger_line(
        self, line: bytes, *, index: int, offset: int, previous_entry_hash: str | None
    ) -> _LedgerEntry:
        try:
            text = line.decode("utf-8", errors="strict")
            full_entry = parse_strict_json(line)
        except (UnicodeDecodeError, ValidationError) as exc:
            raise ValidationError("invalid_ledger_entry") from exc
        expected_fields = {
            "entry_hash",
            "entry_index",
            "ledger_version",
            "manifest",
            "previous_entry_hash",
        }
        if set(full_entry) != expected_fields or canonical_json(full_entry) != text:
            raise ValidationError("invalid_ledger_entry")
        manifest = full_entry["manifest"]
        if not isinstance(manifest, dict):
            raise ValidationError("invalid_ledger_entry")
        material = self._ledger_material(index, previous_entry_hash, manifest)
        expected_hash = sha256_bytes(canonical_json(material).encode("utf-8"))
        if (
            full_entry.get("entry_index") != index
            or full_entry.get("ledger_version") != LEDGER_VERSION
            or full_entry.get("previous_entry_hash") != previous_entry_hash
            or full_entry.get("entry_hash") != expected_hash
        ):
            raise ValidationError("invalid_ledger_entry")
        return _LedgerEntry(index=index, offset=offset, entry_hash=expected_hash, manifest=manifest)

    def _scan_ledger(self) -> tuple[list[_LedgerEntry], int, bytes]:
        if not self.ledger_path.exists():
            return [], 0, b""
        data = self.ledger_path.read_bytes()
        entries: list[_LedgerEntry] = []
        offset = 0
        previous_entry_hash: str | None = None
        while offset < len(data):
            newline = data.find(b"\n", offset)
            if newline < 0:
                return entries, offset, data[offset:]
            line = data[offset:newline]
            try:
                entry = self._parse_ledger_line(
                    line,
                    index=len(entries),
                    offset=offset,
                    previous_entry_hash=previous_entry_hash,
                )
            except ValidationError:
                return entries, offset, data[offset:]
            entries.append(entry)
            previous_entry_hash = entry.entry_hash
            offset = newline + 1
        return entries, offset, b""

    def _scan_ledger_for_replay(self, *, max_entries: int, max_bytes: int) -> list[_LedgerEntry]:
        """Read a bounded ledger view without recovery, truncation, or writes."""
        if max_entries < 1 or max_bytes < 1:
            raise RuntimeError("invalid_replay_snapshot_limit")
        if not self.ledger_path.exists():
            return []
        if self.ledger_path.stat().st_size > max_bytes:
            raise RuntimeError("replay_ledger_byte_limit_exceeded")
        entries: list[_LedgerEntry] = []
        offset = 0
        previous_entry_hash: str | None = None
        # A ledger line is structurally bounded by the snapshot byte limit.
        with self.ledger_path.open("rb") as handle:
            while True:
                line = handle.readline(max_bytes + 1)
                if not line:
                    break
                if len(line) > max_bytes or not line.endswith(b"\n"):
                    raise RuntimeError("invalid_replay_ledger_tail")
                if offset + len(line) > max_bytes:
                    raise RuntimeError("replay_ledger_byte_limit_exceeded")
                if len(entries) >= max_entries:
                    raise RuntimeError("replay_ledger_entry_limit_exceeded")
                try:
                    entry = self._parse_ledger_line(
                        line[:-1],
                        index=len(entries),
                        offset=offset,
                        previous_entry_hash=previous_entry_hash,
                    )
                except ValidationError as exc:
                    raise RuntimeError("invalid_replay_ledger_entry") from exc
                entries.append(entry)
                previous_entry_hash = entry.entry_hash
                offset += len(line)
        return entries

    def _artifact_problems(self, entries: list[_LedgerEntry], *, max_artifact_bytes: int | None = None) -> list[str]:
        """Verify artifacts, optionally applying a bounded reader cap.

        General audit verification still validates intentionally oversized
        quarantines. Replay passes a cap before any artifact is opened.
        """
        if max_artifact_bytes is not None and (
            isinstance(max_artifact_bytes, bool) or not isinstance(max_artifact_bytes, int) or max_artifact_bytes < 0
        ):
            raise ValueError("invalid_artifact_verification_limit")
        problems: list[str] = []
        for entry in entries:
            manifest = entry.manifest
            outcome = manifest.get("outcome")
            if outcome == "accepted":
                raw = manifest.get("raw", {})
                raw_hash = raw.get("raw_sha256") if isinstance(raw, dict) else None
                raw_size = raw.get("size_bytes") if isinstance(raw, dict) else None
                directory = self.raw_root
                problem_prefix = "missing_raw_hash"
            else:
                quarantine = manifest.get("quarantine", {})
                raw_hash = quarantine.get("raw_sha256") if isinstance(quarantine, dict) else None
                raw_size = quarantine.get("size_bytes") if isinstance(quarantine, dict) else None
                directory = self.quarantine_raw_root
                problem_prefix = "missing_quarantine_hash"
            if (
                isinstance(raw_size, bool)
                or not isinstance(raw_size, int)
                or raw_size < 0
                or (max_artifact_bytes is not None and raw_size > max_artifact_bytes)
            ):
                problems.append(f"invalid_raw_artifact_size:{entry.index}")
                continue
            try:
                require_sha256(raw_hash, "raw_sha256")
            except ValidationError:
                problems.append(f"{problem_prefix}:{entry.index}")
                continue
            path = directory / f"{raw_hash}.bin"
            if path.is_symlink():
                problems.append(f"raw_artifact_hash_mismatch:{entry.index}")
                continue
            try:
                actual_size = path.stat().st_size
            except OSError:
                problems.append(f"raw_artifact_hash_mismatch:{entry.index}")
                continue
            if (
                actual_size != raw_size
                or (max_artifact_bytes is not None and actual_size > max_artifact_bytes)
                or sha256_bytes(path.read_bytes()) != raw_hash
            ):
                problems.append(f"raw_artifact_hash_mismatch:{entry.index}")
        return problems

    def _recover_ledger(self) -> None:
        entries, valid_end, invalid_tail = self._scan_ledger()
        if invalid_tail:
            tail_hash = sha256_bytes(invalid_tail)
            self._write_content_addressed(self.recovery_root, tail_hash, invalid_tail)
            descriptor = os.open(self.ledger_path, os.O_RDWR)
            try:
                os.ftruncate(descriptor, valid_end)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            _fsync_directory(self.root)
        self._entries = entries

    def _append_manifest(self, manifest: dict[str, Any]) -> AuditCheckpoint:
        index = len(self._entries)
        previous_entry_hash = self._entries[-1].entry_hash if self._entries else None
        material = self._ledger_material(index, previous_entry_hash, manifest)
        entry_hash = sha256_bytes(canonical_json(material).encode("utf-8"))
        full_entry = dict(material)
        full_entry["entry_hash"] = entry_hash
        line = canonical_json(full_entry).encode("utf-8") + b"\n"
        offset = self.ledger_path.stat().st_size if self.ledger_path.exists() else 0
        descriptor = os.open(self.ledger_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            _write_all(descriptor, line)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._set_owner_mode(self.ledger_path, 0o600)
        _fsync_directory(self.root)
        self._entries.append(_LedgerEntry(index=index, offset=offset, entry_hash=entry_hash, manifest=manifest))
        return AuditCheckpoint(self.ledger_id, index, offset, entry_hash)

    def _accepted_by_delivery(self) -> dict[str, _LedgerEntry]:
        result: dict[str, _LedgerEntry] = {}
        for entry in self._entries:
            manifest = entry.manifest
            if manifest.get("outcome") == "accepted":
                delivery_hash = manifest.get("delivery_identity_sha256")
                if isinstance(delivery_hash, str):
                    result[delivery_hash] = entry
        return result

    def append_evidence(self, envelope: EvidenceEnvelope, raw: bytes) -> PersistResult:
        with self._lock:
            self._recover_ledger()
            known_delivery = self._accepted_by_delivery().get(envelope.context.delivery_identity_sha256)
            if known_delivery is not None:
                known_raw = known_delivery.manifest.get("raw", {}).get("raw_sha256")
                if known_raw == envelope.raw_sha256:
                    return PersistResult("duplicate_delivery", known_delivery.manifest.get("evidence_id"), known_delivery.index)
                return self._append_quarantine_locked(envelope.context, raw, "delivery_identity_conflict")
            prior_content_ids = tuple(
                entry.manifest["evidence_id"]
                for entry in self._entries
                if entry.manifest.get("outcome") == "accepted"
                and entry.manifest.get("raw", {}).get("raw_sha256") == envelope.raw_sha256
            )
            self._write_content_addressed(self.raw_root, envelope.raw_sha256, raw)
            manifest = envelope.as_manifest(suspected_prior_content_ids=prior_content_ids)
            manifest["delivery_identity_sha256"] = envelope.context.delivery_identity_sha256
            manifest["outcome"] = "accepted"
            checkpoint = self._append_manifest(manifest)
            return PersistResult("accepted", envelope.evidence_id, checkpoint.entry_index)

    def _append_quarantine_locked(self, context: Any, raw: bytes, code: str) -> PersistResult:
        raw_sha256 = sha256_bytes(raw)
        self._write_content_addressed(self.quarantine_raw_root, raw_sha256, raw)
        manifest = {
            "classification": DataClassification.SYNTHETIC_NETWORK_METADATA.value,
            "contract_version": CONTRACT_VERSION,
            "intake": context.as_manifest(),
            "outcome": "quarantined",
            "payload_access_policy": PayloadAccessPolicy.OWNER_ONLY_LOCAL_FIXTURE.value,
            "quarantine": {
                "code": code,
                "raw_sha256": raw_sha256,
                "size_bytes": len(raw),
            },
            "redaction_status": RedactionStatus.SYNTHETIC.value,
            "retention_policy": RetentionPolicy.FIXTURE_30_DAYS.value,
        }
        checkpoint = self._append_manifest(manifest)
        return PersistResult("quarantined", None, checkpoint.entry_index, code)

    def append_quarantine(self, context: Any, raw: bytes, code: str) -> PersistResult:
        with self._lock:
            self._recover_ledger()
            return self._append_quarantine_locked(context, raw, code)

    def accepted_manifests(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            self._recover_ledger()
            manifests = [entry.manifest for entry in self._entries if entry.manifest.get("outcome") == "accepted"]
            # JSON round-trip returns an independent deep copy without exposing
            # mutable nested objects kept by the in-memory ledger cache.
            return tuple(
                json.loads(canonical_json(manifest))
                for manifest in sorted(manifests, key=lambda item: item["evidence_id"])
            )

    def verified_snapshot(self) -> VerifiedEvidenceSnapshot:
        """Return accepted source evidence and its checkpoint under one lock."""
        with self._lock:
            self._recover_ledger()
            verification = self.verify()
            if not verification.valid:
                raise RuntimeError("source_evidence_verification_failed")
            # A separate store instance may have appended after the preceding
            # verification. Re-scan once and bind *both* the manifest set and
            # checkpoint to this single structural ledger view.
            entries, _, invalid_tail = self._scan_ledger()
            if invalid_tail:
                raise RuntimeError("source_evidence_verification_failed")
            manifests = [entry.manifest for entry in entries if entry.manifest.get("outcome") == "accepted"]
            manifests.sort(key=lambda item: item["evidence_id"])
            terminal = entries[-1] if entries else None
            return VerifiedEvidenceSnapshot(
                checkpoint=AuditCheckpoint(self.ledger_id, terminal.index, terminal.offset, terminal.entry_hash) if terminal else None,
                manifests_json=canonical_json(manifests),
            )

    def verified_audit_snapshot(
        self, *, max_entries: int, max_bytes: int, max_artifact_bytes: int | None = None,
    ) -> VerifiedAuditSnapshot:
        """Return one bounded, verified replay view without mutating the store."""
        with self._lock:
            entries = self._scan_ledger_for_replay(max_entries=max_entries, max_bytes=max_bytes)
            if self._artifact_problems(entries, max_artifact_bytes=max_artifact_bytes):
                raise RuntimeError("source_evidence_verification_failed")
            terminal = entries[-1] if entries else None
            checkpoint = (
                AuditCheckpoint(self.ledger_id, terminal.index, terminal.offset, terminal.entry_hash)
                if terminal is not None
                else None
            )
            return VerifiedAuditSnapshot(
                self.ledger_id,
                checkpoint,
                tuple(VerifiedAuditEntry(entry.index, canonical_json(entry.manifest)) for entry in entries),
            )

    def checkpoint(self) -> AuditCheckpoint | None:
        with self._lock:
            self._recover_ledger()
            if not self._entries:
                return None
            terminal = self._entries[-1]
            return AuditCheckpoint(self.ledger_id, terminal.index, terminal.offset, terminal.entry_hash)

    def verify(self, checkpoint: AuditCheckpoint | None = None) -> VerificationResult:
        """Validate raw artifacts and an optional checkpoint held outside the store."""
        with self._lock:
            entries, _, invalid_tail = self._scan_ledger()
            problems: list[str] = []
            if invalid_tail:
                problems.append("invalid_ledger_tail")
            problems.extend(self._artifact_problems(entries))
            terminal: AuditCheckpoint | None = None
            if entries:
                last = entries[-1]
                terminal = AuditCheckpoint(self.ledger_id, last.index, last.offset, last.entry_hash)
            if checkpoint is not None:
                if checkpoint.ledger_id != self.ledger_id:
                    problems.append("checkpoint_ledger_id_mismatch")
                elif checkpoint.entry_index >= len(entries):
                    problems.append("checkpoint_missing")
                else:
                    entry = entries[checkpoint.entry_index]
                    if entry.offset != checkpoint.byte_offset or entry.entry_hash != checkpoint.entry_hash:
                        problems.append("checkpoint_mismatch")
            return VerificationResult(not problems, tuple(problems), terminal)
