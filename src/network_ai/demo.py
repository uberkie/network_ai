"""Run the Phase 1 synthetic evidence workflow without network access."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .contracts import ClockQuality, IntakeContext, MIKROTIK_SESSION_FORMAT_PROFILE, SourceType
from .correlation import (
    CorrelationConfig,
    CorrelationResultStore,
    FixtureCoverage,
    FixtureSessionCoverage,
    SessionCorrelationConfig,
    correlate_with_session,
    fixture_coverage_scope_sha256,
    fixture_session_coverage_scope_sha256,
)
from .ingest import IngestItem, IngestService
from .store import FileEvidenceStore


def _context(
    source: SourceType, delivery_id: str, *, acquisition_config_sha256: str, format_profile: str | None = None,
) -> IntakeContext:
    profiles = {
        SourceType.SURICATA: "suricata-eve-alert.v1",
        SourceType.ZEEK: "zeek-json-conn.v1",
        SourceType.MIKROTIK: "mikrotik-telemetry-allowlist.v1",
    }
    return IntakeContext(
        source=source,
        sensor_id="synthetic-lab-01",
        delivery_id=delivery_id,
        format_profile=format_profile or profiles[source],
        observed_at="2026-08-15T08:00:05Z",
        ingested_at="2026-08-15T08:00:06Z",
        clock_quality=ClockQuality.SYNCHRONIZED,
        acquisition_config_sha256=acquisition_config_sha256,
    )


def run_demo(store_root: Path, fixture_root: Path) -> dict[str, object]:
    """Ingest the three approved synthetic samples and return safe metadata."""
    service = IngestService(FileEvidenceStore(store_root, ledger_id="network-ai-phase1-demo"))
    acquisition_config_sha256 = hashlib.sha256((fixture_root / "MANIFEST.json").read_bytes()).hexdigest()
    records = (
        (SourceType.SURICATA, "demo-suricata-001", "suricata/alert.json", None),
        (SourceType.ZEEK, "demo-zeek-001", "zeek/conn.json", None),
        (SourceType.MIKROTIK, "demo-mikrotik-001", "mikrotik/telemetry.json", None),
        (SourceType.MIKROTIK, "demo-session-001", "mikrotik/session-binding.json", MIKROTIK_SESSION_FORMAT_PROFILE),
    )
    results = [
        service.ingest(
            IngestItem(
                _context(
                    source,
                    delivery_id,
                    acquisition_config_sha256=acquisition_config_sha256,
                    format_profile=format_profile,
                ),
                (fixture_root / relative_path).read_bytes(),
            )
        )
        for source, delivery_id, relative_path, format_profile in records
    ]
    verification = service.store.verify()
    coverage = FixtureCoverage(
        coverage_id="demo-zeek-coverage-001",
        zeek_sensor_id="synthetic-lab-01",
        starts_at="2026-08-15T07:58:00Z",
        ends_at="2026-08-15T08:02:00Z",
        fixture_scope_sha256=fixture_coverage_scope_sha256(
            service.store, "synthetic-lab-01", "2026-08-15T07:58:00Z", "2026-08-15T08:02:00Z"
        ),
    )
    traffic_config = CorrelationConfig(60, (("synthetic-lab-01", "synthetic-lab-01"),), (coverage,))
    session_coverage = FixtureSessionCoverage(
        coverage_id="demo-session-coverage-001",
        mikrotik_sensor_id="synthetic-lab-01",
        starts_at="2026-08-15T07:58:00Z",
        ends_at="2026-08-15T08:02:00Z",
        fixture_scope_sha256=fixture_session_coverage_scope_sha256(
            service.store, "synthetic-lab-01", "2026-08-15T07:58:00Z", "2026-08-15T08:02:00Z"
        ),
    )
    correlations = correlate_with_session(
        service.store,
        traffic_config,
        SessionCorrelationConfig((("synthetic-lab-01", "synthetic-lab-01"),), (session_coverage,)),
    )
    derived_store = CorrelationResultStore(store_root / "derived-correlation")
    return {
        "accepted_evidence_count": len(service.store.accepted_manifests()),
        "audit_valid": verification.valid,
        "correlations": [
            {
                "candidate_evidence_ids": [item["evidence_id"] for item in result.payload["traffic"]["candidate_evidence_refs"]],
                "correlation_id": result.payload["traffic"]["semantic_correlation_id"],
                "outcome": result.payload["traffic"]["outcome"],
                "persistence_status": derived_store.persist(result),
                "rationale": result.payload["traffic"]["rationale"],
                "stage_outcome": result.stage_outcome.as_manifest(),
            }
            for result in correlations
        ],
        "session_associations": [
            {
                "correlation_id": result.semantic_correlation_id,
                "derivation_id": result.derivation_id,
                "outcome": result.payload["session_association"]["outcome"],
                "session_evidence_ids": result.payload["session_association"]["session_evidence_ids"],
                "rationale": result.payload["session_association"]["rationale"],
                "stage_outcome": result.session_stage_outcome.as_manifest() if result.session_stage_outcome else None,
            }
            for result in correlations
        ],
        "results": [
            {
                "evidence_id": result.evidence_id,
                "quarantine_code": result.quarantine_code,
                "status": result.status,
                "stage_outcome": result.stage_outcome.as_manifest(),
            }
            for result in results
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Network AI's local synthetic Phase 1/Phase 2a demo.")
    parser.add_argument("--store", type=Path, required=True, help="New or existing local evidence-store directory")
    parser.add_argument(
        "--fixtures",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "fixtures",
        help="Synthetic fixture directory",
    )
    arguments = parser.parse_args()
    print(json.dumps(run_demo(arguments.store, arguments.fixtures), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
