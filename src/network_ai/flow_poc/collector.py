"""Explicitly bounded UDP collection for authorized, read-only flow export."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import ipaddress
import socket
import sqlite3
import time
from typing import Any

from network_ai.contracts import canonical_json

from .models import FlowDecodeError, PARSER_VERSION, PROFILE_VERSION, SessionIdentity
from .protocol import (
    MAX_DATAGRAM_BYTES,
    MAX_FIELDS_PER_TEMPLATE,
    MAX_GLOBAL_TEMPLATES,
    MAX_RECORDS_PER_DATAGRAM,
    MAX_SESSION_TEMPLATES,
    MAX_SETS_PER_DATAGRAM,
    MAX_TEMPLATES_PER_DATAGRAM,
    TEMPLATE_TTL_SECONDS,
    TemplateCache,
    decode_datagram,
    inspect_header,
)
from .storage import FlowRepository, PersistOutcome


MAX_TRACKED_EXPORTERS = 256
MAX_TRACKED_SESSIONS = 256
SESSION_STATE_TTL_SECONDS = 600
ANALYSIS_MIN_INTERVAL_SECONDS = 5
RUN_HEARTBEAT_INTERVAL_SECONDS = 1
FINALIZATION_WRITE_ATTEMPTS = 3
FINALIZATION_RETRY_SECONDS = 0.1


@dataclass(frozen=True)
class ListenerPolicy:
    """Network bind policy; source filtering is not exporter authentication."""

    bind_host: str = "127.0.0.1"
    port: int = 2055
    exporter_allowlist: tuple[str, ...] = ("127.0.0.1/32",)
    allow_nonloopback: bool = False
    duration_seconds: int = 300
    max_datagrams: int = 3_000
    rate_per_minute: int = 600

    def __post_init__(self) -> None:
        try:
            address = ipaddress.ip_address(self.bind_host)
        except ValueError as exc:
            raise ValueError("bind_host_must_be_literal_ip") from exc
        if address.is_unspecified or self.port < 1 or self.port > 65_535:
            raise ValueError("unsafe_or_invalid_bind")
        if not self.exporter_allowlist:
            raise ValueError("exporter_allowlist_required")
        try:
            networks = tuple(ipaddress.ip_network(value, strict=False) for value in self.exporter_allowlist)
        except ValueError as exc:
            raise ValueError("invalid_exporter_allowlist") from exc
        canonical_allowlist = tuple(sorted(str(network) for network in networks))
        object.__setattr__(self, "bind_host", str(address))
        object.__setattr__(self, "exporter_allowlist", canonical_allowlist)
        if not address.is_loopback:
            if not self.allow_nonloopback:
                raise ValueError("nonloopback_requires_explicit_opt_in")
            if any(
                (network.version == 4 and network.prefixlen != 32)
                or (network.version == 6 and network.prefixlen != 128)
                for network in networks
            ):
                raise ValueError("nonloopback_requires_host_exporter_allowlist")
        if self.duration_seconds < 1 or self.duration_seconds > 3_600 or self.max_datagrams < 1 or self.max_datagrams > 10_000:
            raise ValueError("listener_runtime_limits_invalid")
        if self.rate_per_minute < 1 or self.rate_per_minute > 10_000:
            raise ValueError("listener_rate_limit_invalid")

    @property
    def allowlist_networks(self) -> tuple[ipaddress._BaseNetwork, ...]:
        return tuple(ipaddress.ip_network(value, strict=False) for value in self.exporter_allowlist)

    def permits_exporter(self, exporter_ip: str) -> bool:
        try:
            address = ipaddress.ip_address(exporter_ip)
        except ValueError:
            return False
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        return any(address in network for network in self.allowlist_networks)

    @property
    def configuration_sha256(self) -> str:
        data = canonical_json(
            {
                "allowlist": list(self.exporter_allowlist),
                "allow_nonloopback": self.allow_nonloopback,
                "bind_host": self.bind_host,
                "duration_seconds": self.duration_seconds,
                "max_datagrams": self.max_datagrams,
                "parser_limits": {
                    "max_datagram_bytes": MAX_DATAGRAM_BYTES,
                    "max_fields_per_template": MAX_FIELDS_PER_TEMPLATE,
                    "max_global_templates": MAX_GLOBAL_TEMPLATES,
                    "max_records_per_datagram": MAX_RECORDS_PER_DATAGRAM,
                    "max_session_templates": MAX_SESSION_TEMPLATES,
                    "max_sets_per_datagram": MAX_SETS_PER_DATAGRAM,
                    "max_templates_per_datagram": MAX_TEMPLATES_PER_DATAGRAM,
                    "template_ttl_seconds": TEMPLATE_TTL_SECONDS,
                },
                "port": self.port,
                "parser_version": PARSER_VERSION,
                "profile_version": PROFILE_VERSION,
                "supported_protocols": [9, 10],
                "rate_per_minute": self.rate_per_minute,
            }
        ).encode("utf-8")
        return hashlib.sha256(data).hexdigest()


@dataclass
class CollectorStats:
    received: int = 0
    accepted: int = 0
    rejected_policy: int = 0
    malformed: int = 0
    template_missing: int = 0
    rate_dropped: int = 0
    sequence_conflicts: int = 0
    persistence_failures: int = 0
    sequence_discontinuities: int = 0
    interrupted: int = 0
    session_state_rejected: int = 0
    exporter_state_rejected: int = 0
    options_data_ignored: int = 0
    analysis_failures: int = 0
    analysis_runs: int = 0
    analysis_audit_failures: int = 0
    collection_run_audit_failures: int = 0
    last_received_at: datetime | None = None
    last_persisted_at: datetime | None = None
    last_error_code: str | None = None
    run_state: str = "not_started"
    run_audit_state: str = "not_applicable"
    decode_error_codes: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            name: value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
            if isinstance(value := getattr(self, name), datetime)
            else value
            for name in self.__dataclass_fields__
        }

    def run_counters(self) -> dict[str, Any]:
        return {
            name: value
            for name, value in self.as_dict().items()
            if isinstance(value, int) and not isinstance(value, bool)
        } | {"decode_error_codes": dict(self.decode_error_codes)}


class FlowCollector:
    """A small UDP collector. It makes no claim of authenticated exporter identity."""

    def __init__(
        self,
        repository: FlowRepository,
        policy: ListenerPolicy,
        *,
        auto_analyze: bool = False,
        analysis_min_interval_seconds: int = ANALYSIS_MIN_INTERVAL_SECONDS,
    ) -> None:
        if analysis_min_interval_seconds < 1 or analysis_min_interval_seconds > 300:
            raise ValueError("analysis_interval_invalid")
        self.repository = repository
        self.policy = policy
        self.auto_analyze = auto_analyze
        self.cache = TemplateCache()
        self.stats = CollectorStats()
        self._sequence_observations: dict[str, tuple[int, int, int]] = {}
        self._blocked_sessions: set[str] = set()
        self._buckets: dict[str, tuple[float, float]] = {}
        self._session_last_seen: dict[str, float] = {}
        self._last_analysis_at: float | None = None
        self._analysis_min_interval_seconds = analysis_min_interval_seconds
        self._analysis_pending = False
        self._collection_run_id: str | None = None

    @property
    def configuration_sha256(self) -> str:
        detector_configuration_sha256: str | None = None
        if self.auto_analyze:
            from .analysis import FlowAnalyzer

            detector_configuration_sha256 = FlowAnalyzer().configuration_sha256
        material = canonical_json(
            {
                "analysis_min_interval_seconds": self._analysis_min_interval_seconds,
                "auto_analyze": self.auto_analyze,
                "collector_policy_sha256": self.policy.configuration_sha256,
                "detector_configuration_sha256": detector_configuration_sha256,
                "max_storage_bytes": self.repository.max_storage_bytes,
                "max_flow_records": self.repository.max_flow_records,
                "max_candidates": self.repository.max_candidates,
                "max_candidate_instances": self.repository.max_candidate_instances,
                "max_candidate_flow_references": self.repository.max_candidate_flow_references,
                "max_tracked_exporters": MAX_TRACKED_EXPORTERS,
                "max_tracked_sessions": MAX_TRACKED_SESSIONS,
                "session_state_ttl_seconds": SESSION_STATE_TTL_SECONDS,
            }
        ).encode("utf-8")
        return hashlib.sha256(material).hexdigest()

    def _record_decode_failure(self, exc: FlowDecodeError) -> None:
        self.stats.decode_error_codes[exc.code] = self.stats.decode_error_codes.get(exc.code, 0) + 1
        if exc.code == "template_missing_or_expired":
            self.stats.template_missing += 1
        else:
            self.stats.malformed += 1

    def _prune_expired_state(self, now_monotonic: float) -> None:
        expired_sessions = tuple(
            session_key
            for session_key, last_seen in self._session_last_seen.items()
            if now_monotonic - last_seen > SESSION_STATE_TTL_SECONDS
        )
        for session_key in expired_sessions:
            # Session eviction must be atomic: a future data-only datagram is
            # forced through template lookup again rather than using stale data.
            self._session_last_seen.pop(session_key, None)
            self._sequence_observations.pop(session_key, None)
            self._blocked_sessions.discard(session_key)
            self.cache.invalidate_session(session_key)
        for exporter_ip, (_tokens, last_seen) in tuple(self._buckets.items()):
            if now_monotonic - last_seen > SESSION_STATE_TTL_SECONDS:
                self._buckets.pop(exporter_ip, None)

    def _rate_admission_error(self, exporter_ip: str, now_monotonic: float) -> str | None:
        capacity = float(self.policy.rate_per_minute)
        existing = self._buckets.get(exporter_ip)
        if existing is None and len(self._buckets) >= MAX_TRACKED_EXPORTERS:
            self.stats.exporter_state_rejected += 1
            return "exporter_rate_state_limit"
        tokens, last = existing or (capacity, now_monotonic)
        tokens = min(capacity, tokens + (now_monotonic - last) * (capacity / 60.0))
        if tokens < 1.0:
            self._buckets[exporter_ip] = (tokens, now_monotonic)
            return "datagram_rate_limit"
        self._buckets[exporter_ip] = (tokens - 1.0, now_monotonic)
        return None

    def _session_admission_error(self, session_key: str) -> str | None:
        if session_key not in self._session_last_seen and len(self._session_last_seen) >= MAX_TRACKED_SESSIONS:
            self.stats.session_state_rejected += 1
            return "session_state_limit"
        return None

    @staticmethod
    def _has_fresh_flow_template(decoded: Any) -> bool:
        fingerprints = set(decoded.template_fingerprints)
        return any(
            template.session_key == decoded.session.key
            and not template.is_options
            and template.fingerprint in fingerprints
            for template in decoded.next_templates.values()
        )

    def _maybe_analyze(self, now_monotonic: float, *, force: bool = False) -> None:
        if not self.auto_analyze or not self._analysis_pending or (
            not force
            and
            self._last_analysis_at is not None
            and now_monotonic - self._last_analysis_at < self._analysis_min_interval_seconds
        ):
            return
        from .analysis import analyze_and_record

        outcome = analyze_and_record(
            self.repository,
            collection_run_id=self._collection_run_id,
            bounded=True,
        )
        # Rate-limit every completed attempt, including a failure, so a
        # persistent repository/detector error cannot make UDP processing
        # scale with incoming traffic.
        self._last_analysis_at = now_monotonic
        self._analysis_pending = False
        if outcome.status == "completed":
            self.stats.analysis_runs += 1
        else:
            self.stats.analysis_failures += 1
            self.stats.last_error_code = "analysis_failed"
        if outcome.audit_state != "written":
            self.stats.analysis_audit_failures += 1
            self.stats.last_error_code = "analysis_audit_unavailable"

    def ingest_datagram(
        self,
        raw: bytes,
        *,
        exporter_ip: str,
        exporter_port: int,
        collector_ip: str | None = None,
        collector_port: int | None = None,
        received_at: datetime | None = None,
        now_monotonic: float | None = None,
    ) -> PersistOutcome:
        """Process one datagram after source filtering and resource checks."""
        self.stats.received += 1
        now = time.monotonic() if now_monotonic is None else now_monotonic
        received = received_at or datetime.now(tz=timezone.utc)
        self.stats.last_received_at = received
        if not self.policy.permits_exporter(exporter_ip):
            self.stats.rejected_policy += 1
            raise FlowDecodeError("exporter_not_allowlisted")
        self._prune_expired_state(now)
        if len(raw) > MAX_DATAGRAM_BYTES:
            self.stats.rate_dropped += 1
            raise FlowDecodeError("datagram_size_limit")
        rate_error = self._rate_admission_error(exporter_ip, now)
        if rate_error is not None:
            self.stats.rate_dropped += 1
            raise FlowDecodeError(rate_error)
        try:
            header = inspect_header(raw)
        except FlowDecodeError as exc:
            self._record_decode_failure(exc)
            raise
        actual_collector_ip = collector_ip or self.policy.bind_host
        actual_collector_port = collector_port or self.policy.port
        session = SessionIdentity(
            exporter_ip=exporter_ip,
            exporter_port=exporter_port,
            collector_ip=actual_collector_ip,
            collector_port=actual_collector_port,
            protocol_version=header.protocol_version,
            observation_domain_id=header.observation_domain_id,
        )
        session_error = self._session_admission_error(session.key)
        if session_error is not None:
            raise FlowDecodeError(session_error)
        raw_sha = hashlib.sha256(raw).hexdigest()
        seen = self.repository.sequence_raw_hashes(session.key, header.sequence_number)
        if raw_sha in seen:
            return self.repository.persist_rejected_delivery(
                raw=raw,
                session=session,
                header=header,
                received_at=received,
                status="duplicate_delivery",
                reason_code="same_session_sequence_raw_hash",
                configuration_sha256=self.configuration_sha256,
            )
        previous = self._sequence_observations.get(session.key)
        # IPFIX's modulo-32-bit sequence may validly roll over from 0xffffffff
        # to zero after the preceding message's Data Record count is applied.
        is_ipfix_rollover_advance = (
            previous is not None
            and header.protocol_version == 10
            and previous[2] == 10
            and header.sequence_number == (previous[0] + previous[1]) % (2**32)
        )
        requires_fresh_template = (
            session.key in self._blocked_sessions
            or (previous is not None and header.sequence_number < previous[0] and not is_ipfix_rollover_advance)
        )
        try:
            decoded = decode_datagram(
                raw,
                exporter_ip=exporter_ip,
                exporter_port=exporter_port,
                collector_ip=actual_collector_ip,
                collector_port=actual_collector_port,
                cache=self.cache,
                now_monotonic=now,
                reset_session=requires_fresh_template,
            )
            if requires_fresh_template and not self._has_fresh_flow_template(decoded):
                raise FlowDecodeError("fresh_template_required_after_reset_or_conflict")
            if seen and decoded.flows:
                # The packet passed the narrow field profile, so it can be
                # retained as conflict evidence. Its flow records are never
                # persisted or analysed until a fresh template/reset path.
                outcome = self.repository.persist_rejected_delivery(
                    raw=raw,
                    session=session,
                    header=header,
                    received_at=received,
                    status="sequence_conflict",
                    reason_code="same_session_sequence_different_valid_flow_datagram",
                    configuration_sha256=self.configuration_sha256,
                )
                self.cache.invalidate_session(session.key)
                self._blocked_sessions.add(session.key)
                self._session_last_seen[session.key] = now
                self.stats.sequence_conflicts += 1
                self.stats.last_persisted_at = received
                return outcome
            data_record_count = len(decoded.flows) + decoded.options_data_records_ignored
            sequence_state = self._sequence_state(header.protocol_version, header.sequence_number, data_record_count, previous)
            if sequence_state == "sequence_discontinuity":
                self.stats.sequence_discontinuities += 1
            outcome = self.repository.persist_decoded(
                decoded,
                raw,
                received_at=received,
                configuration_sha256=self.configuration_sha256,
                sequence_state=sequence_state,
            )
            self.cache.replace(decoded.next_templates, now)
            self._blocked_sessions.discard(session.key)
            self._session_last_seen[session.key] = now
            if previous is not None and header.sequence_number < previous[0] and not is_ipfix_rollover_advance:
                self.stats.sequence_discontinuities += 1
            if sequence_state != "template_refresh":
                self._sequence_observations[session.key] = (
                    header.sequence_number,
                    data_record_count,
                    header.protocol_version,
                )
            self.stats.accepted += 1
            self.stats.options_data_ignored += decoded.options_data_sets_ignored
            self.stats.last_persisted_at = received
            if outcome.inserted_flow_ids:
                self._analysis_pending = True
                self._maybe_analyze(now)
            return outcome
        except FlowDecodeError as exc:
            self._record_decode_failure(exc)
            raise
        except Exception:
            self.stats.persistence_failures += 1
            self.stats.last_error_code = "persistence_failure"
            raise

    @staticmethod
    def _sequence_state(
        protocol_version: int,
        sequence_number: int,
        data_record_count: int,
        previous: tuple[int, int, int] | None,
    ) -> str:
        """Classify sequence evidence without treating UDP gaps as attacks.

        IPFIX advances by the number of preceding Data Records. Template-only
        messages therefore may legitimately repeat the preceding sequence.
        """
        if previous is None:
            return "first"
        previous_sequence, previous_data_records, previous_version = previous
        if previous_version != protocol_version:
            return "protocol_session_reset"
        if protocol_version == 10:
            expected = (previous_sequence + previous_data_records) % (2**32)
            if sequence_number == previous_sequence and data_record_count == 0:
                return "template_refresh"
            if sequence_number == expected:
                return "advance"
            if sequence_number < previous_sequence:
                return "reset_suspected"
            return "sequence_discontinuity"
        if sequence_number < previous_sequence:
            return "reset_suspected"
        if sequence_number == previous_sequence and data_record_count == 0:
            return "template_refresh"
        return "advance"

    def _heartbeat_run(self, run_id: str, now: datetime) -> None:
        self.repository.heartbeat_collection_run(
            run_id,
            observed_at=now,
            counters=self.stats.run_counters(),
            last_received_at=self.stats.last_received_at,
            last_persisted_at=self.stats.last_persisted_at,
            last_error_code=self.stats.last_error_code,
        )

    def serve(self, *, ready_event: Any | None = None) -> CollectorStats:
        """Listen for one bounded run; never binds wildcard/DNS addresses."""
        bind_address = ipaddress.ip_address(self.policy.bind_host)
        family = socket.AF_INET6 if bind_address.version == 6 else socket.AF_INET
        deadline = time.monotonic() + self.policy.duration_seconds
        started_at = datetime.now(tz=timezone.utc)
        try:
            run_id = self.repository.start_collection_run(
                collector_configuration_sha256=self.configuration_sha256,
                started_at=started_at,
            )
        except Exception:
            self.stats.persistence_failures += 1
            self.stats.last_error_code = "collection_run_creation_unavailable"
            self.stats.run_state = "collection_run_audit_unavailable"
            self.stats.run_audit_state = "unavailable"
            return self.stats
        self.stats.run_state = "running"
        self.stats.run_audit_state = "written"
        self._collection_run_id = run_id
        terminal_state = "completed"
        last_heartbeat = time.monotonic()
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as listener:
                listener.bind((self.policy.bind_host, self.policy.port))
                listener.settimeout(0.25)
                if ready_event is not None:
                    ready_event.set()
                processed = 0
                while processed < self.policy.max_datagrams and time.monotonic() < deadline:
                    if time.monotonic() - last_heartbeat >= RUN_HEARTBEAT_INTERVAL_SECONDS:
                        self._heartbeat_run(run_id, datetime.now(tz=timezone.utc))
                        last_heartbeat = time.monotonic()
                    try:
                        raw, peer = listener.recvfrom(MAX_DATAGRAM_BYTES + 1)
                    except TimeoutError:
                        continue
                    processed += 1
                    if len(raw) > MAX_DATAGRAM_BYTES:
                        self.stats.rate_dropped += 1
                        self.stats.last_received_at = datetime.now(tz=timezone.utc)
                        continue
                    try:
                        local_ip, local_port = listener.getsockname()[:2]
                        self.ingest_datagram(
                            raw,
                            exporter_ip=peer[0],
                            exporter_port=peer[1],
                            collector_ip=local_ip,
                            collector_port=local_port,
                        )
                    except FlowDecodeError:
                        # Capacity and parser failures are counted by ingest_datagram
                        # and must not make the bounded listener accumulate work.
                        continue
                    except Exception:
                        # Repository capacity or persistence failures end this
                        # run visibly. Continuing would imply collection health.
                        terminal_state = "persistence_failed"
                        self.stats.last_error_code = self.stats.last_error_code or "persistence_failure"
                        break
                if self.stats.accepted == 0 and terminal_state == "completed":
                    terminal_state = "completed_no_accepted_datagrams"
        except KeyboardInterrupt:
            self.stats.interrupted += 1
            terminal_state = "interrupted"
        except Exception:
            terminal_state = "bind_or_runtime_failure"
            self.stats.last_error_code = self.stats.last_error_code or "bind_or_runtime_failure"
        finally:
            if terminal_state == "completed" and self._analysis_pending:
                self._maybe_analyze(time.monotonic(), force=True)
            self.stats.run_state = terminal_state
            try:
                for attempt in range(FINALIZATION_WRITE_ATTEMPTS):
                    try:
                        self.repository.finish_collection_run(
                            run_id,
                            completed_at=datetime.now(tz=timezone.utc),
                            state=terminal_state,
                            counters=self.stats.run_counters(),
                            last_received_at=self.stats.last_received_at,
                            last_persisted_at=self.stats.last_persisted_at,
                            last_error_code=self.stats.last_error_code,
                        )
                        break
                    except sqlite3.OperationalError:
                        if attempt + 1 == FINALIZATION_WRITE_ATTEMPTS:
                            raise
                        time.sleep(FINALIZATION_RETRY_SECONDS)
            except Exception:
                self.stats.collection_run_audit_failures += 1
                self.stats.run_audit_state = "unavailable"
                try:
                    self.repository.mark_collection_run_audit_unavailable(
                        run_id,
                        observed_at=datetime.now(tz=timezone.utc),
                    )
                except Exception:
                    pass
            finally:
                self._collection_run_id = None
        return self.stats
