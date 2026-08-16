"""Versioned, immutable evidence contracts and trusted intake context."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
import hashlib
import json
import re
from typing import Any, Mapping


CONTRACT_VERSION = "evidence-envelope.v2"
LEDGER_VERSION = "ledger.v1"
PARSER_VERSION = "strict-json.v1"
ADAPTER_VERSION = "allowlisted-adapters.v2"
SCHEMA_VERSION = "observation-schema.v2"
MIKROTIK_SESSION_FORMAT_PROFILE = "mikrotik-session-binding.v1"
MIKROTIK_SESSION_ADAPTER_VERSION = "mikrotik-session-binding-adapter.v1"
MIKROTIK_SESSION_SCHEMA_VERSION = "mikrotik-session-binding.v1"
MAX_RECORD_BYTES = 256 * 1024
MAX_BATCH_RECORDS = 1_024
MAX_BATCH_BYTES = 4 * 1024 * 1024
ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class SourceType(str, Enum):
    SURICATA = "suricata"
    ZEEK = "zeek"
    MIKROTIK = "mikrotik"


class ClockQuality(str, Enum):
    SYNCHRONIZED = "synchronized"
    UNKNOWN = "unknown"
    DEGRADED = "degraded"


class DataClassification(str, Enum):
    SYNTHETIC_NETWORK_METADATA = "synthetic-network-metadata"


class RedactionStatus(str, Enum):
    SYNTHETIC = "synthetic"


class RetentionPolicy(str, Enum):
    FIXTURE_30_DAYS = "test-fixture-30d"


class PayloadAccessPolicy(str, Enum):
    OWNER_ONLY_LOCAL_FIXTURE = "owner-only-local-fixture"


class ValidationError(ValueError):
    """A safe, stable reason for quarantining one hostile input record."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(code)


def require_safe_id(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        raise ValidationError("invalid_trusted_context", field_name)
    return value


def require_sha256(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ValidationError("invalid_trusted_context", field_name)
    return value


def parse_rfc3339(value: str, *, field_name: str) -> datetime:
    """Parse a timezone-aware RFC 3339 timestamp and normalize it to UTC."""
    if not isinstance(value, str) or len(value) > 64:
        raise ValidationError("invalid_timestamp", field_name)
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValidationError("invalid_timestamp", field_name) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValidationError("timestamp_timezone_required", field_name)
    return parsed.astimezone(timezone.utc)


def format_rfc3339(value: datetime) -> str:
    value = value.astimezone(timezone.utc)
    if value.microsecond:
        return value.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_json(value: Any) -> str:
    """The exact JSON encoding used for manifests and ledger chain material."""
    return json.dumps(value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _semantic_form(value: Any) -> Any:
    """A type-tagged canonical form with no collision with arbitrary JSON values."""
    if value is None:
        return ["null"]
    if isinstance(value, bool):
        return ["bool", value]
    if isinstance(value, str):
        return ["str", value]
    if isinstance(value, int):
        return ["int", str(value)]
    if isinstance(value, Decimal):
        return ["decimal", format(value, "f")]
    if isinstance(value, list):
        return ["list", [_semantic_form(item) for item in value]]
    if isinstance(value, Mapping):
        return [
            "object",
            [[key, _semantic_form(value[key])] for key in sorted(value)],
        ]
    raise TypeError(f"Unsupported JSON value: {type(value)!r}")


def semantic_json_sha256(parsed_json: Mapping[str, Any]) -> str:
    """Hash parsed JSON without converting Decimal values to binary floats."""
    return sha256_bytes(canonical_json(_semantic_form(parsed_json)).encode("utf-8"))


@dataclass(frozen=True)
class IntakeContext:
    """Metadata supplied by the trusted fixture manifest or adapter invocation.

    None of these values are read from the hostile telemetry record itself.
    """

    source: SourceType
    sensor_id: str
    delivery_id: str
    format_profile: str
    observed_at: str
    ingested_at: str
    clock_quality: ClockQuality
    acquisition_config_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.source, SourceType):
            raise ValidationError("invalid_trusted_context", "source")
        require_safe_id(self.sensor_id, "sensor_id")
        require_safe_id(self.delivery_id, "delivery_id")
        require_safe_id(self.format_profile, "format_profile")
        parse_rfc3339(self.observed_at, field_name="observed_at")
        parse_rfc3339(self.ingested_at, field_name="ingested_at")
        if not isinstance(self.clock_quality, ClockQuality):
            raise ValidationError("invalid_trusted_context", "clock_quality")
        require_sha256(self.acquisition_config_sha256, "acquisition_config_sha256")

    def as_manifest(self) -> dict[str, str]:
        return {
            "acquisition_config_sha256": self.acquisition_config_sha256,
            "clock_quality": self.clock_quality.value,
            "delivery_id": self.delivery_id,
            "format_profile": self.format_profile,
            "ingested_at": format_rfc3339(parse_rfc3339(self.ingested_at, field_name="ingested_at")),
            "observed_at": format_rfc3339(parse_rfc3339(self.observed_at, field_name="observed_at")),
            "sensor_id": self.sensor_id,
            "source": self.source.value,
        }

    @property
    def delivery_identity_sha256(self) -> str:
        material = "\0".join((self.source.value, self.sensor_id, self.delivery_id)).encode("utf-8")
        return sha256_bytes(material)


def observation_versions(context: IntakeContext) -> tuple[str, str]:
    """Return the explicit adapter/schema pair for one allowlisted profile."""
    if context.source is SourceType.MIKROTIK and context.format_profile == MIKROTIK_SESSION_FORMAT_PROFILE:
        return MIKROTIK_SESSION_ADAPTER_VERSION, MIKROTIK_SESSION_SCHEMA_VERSION
    return ADAPTER_VERSION, SCHEMA_VERSION


@dataclass(frozen=True)
class EvidenceEnvelope:
    """Immutable metadata with byte-preserved raw evidence stored separately."""

    evidence_id: str
    context: IntakeContext
    raw_sha256: str
    canonical_sha256: str
    raw_size_bytes: int
    event_time: str
    source_event_id: str | None
    normalized_payload_json: str
    uncertainty: str | None

    @property
    def normalized_payload(self) -> dict[str, Any]:
        """Return a fresh decoded copy; mutation cannot alter this envelope."""
        result = json.loads(self.normalized_payload_json)
        if not isinstance(result, dict):  # Defensive contract check.
            raise RuntimeError("normalized_payload_json is not an object")
        return result

    def as_manifest(self, *, suspected_prior_content_ids: tuple[str, ...]) -> dict[str, Any]:
        adapter_version, schema_version = observation_versions(self.context)
        return {
            "classification": DataClassification.SYNTHETIC_NETWORK_METADATA.value,
            "adapter_version": adapter_version,
            "contract_version": CONTRACT_VERSION,
            "evidence_id": self.evidence_id,
            "event_time": self.event_time,
            "intake": self.context.as_manifest(),
            "normalized_payload": self.normalized_payload,
            "payload_access_policy": PayloadAccessPolicy.OWNER_ONLY_LOCAL_FIXTURE.value,
            "parser_version": PARSER_VERSION,
            "raw": {
                "canonical_sha256": self.canonical_sha256,
                "raw_sha256": self.raw_sha256,
                "size_bytes": self.raw_size_bytes,
            },
            "redaction_status": RedactionStatus.SYNTHETIC.value,
            "retention_policy": RetentionPolicy.FIXTURE_30_DAYS.value,
            "schema_version": schema_version,
            "source_event_id": self.source_event_id,
            "suspected_prior_content_ids": list(suspected_prior_content_ids),
            "uncertainty": self.uncertainty,
        }
