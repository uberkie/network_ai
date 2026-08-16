from __future__ import annotations

import hashlib
from pathlib import Path

from network_ai import IntakeContext, SourceType
from network_ai.contracts import ClockQuality


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
CONFIG_HASH = hashlib.sha256((FIXTURES / "MANIFEST.json").read_bytes()).hexdigest()


def fixture_bytes(relative_path: str) -> bytes:
    return (FIXTURES / relative_path).read_bytes()


def context(
    source: SourceType,
    delivery_id: str,
    *,
    sensor_id: str = "sensor-lab-01",
    format_profile: str | None = None,
    observed_at: str = "2026-08-15T08:00:05Z",
    ingested_at: str = "2026-08-15T08:00:06Z",
) -> IntakeContext:
    profiles = {
        SourceType.SURICATA: "suricata-eve-alert.v1",
        SourceType.ZEEK: "zeek-json-conn.v1",
        SourceType.MIKROTIK: "mikrotik-telemetry-allowlist.v1",
    }
    return IntakeContext(
        source=source,
        sensor_id=sensor_id,
        delivery_id=delivery_id,
        format_profile=format_profile or profiles[source],
        observed_at=observed_at,
        ingested_at=ingested_at,
        clock_quality=ClockQuality.SYNCHRONIZED,
        acquisition_config_sha256=CONFIG_HASH,
    )
