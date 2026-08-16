"""Deterministic, evidence-linked threshold candidates for flow review."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
from typing import Any

from network_ai.contracts import canonical_json

from .models import (
    ANALYSIS_SNAPSHOT_VERSION,
    MAX_CANDIDATE_FLOW_REFS,
    MAX_RETAINED_FLOW_RECORDS,
    Candidate,
    PROFILE_VERSION,
    RULE_VERSION,
)


MAX_ANALYSIS_FLOW_ROWS = MAX_RETAINED_FLOW_RECORDS
# This is deliberately aligned with the repository's default immutable
# candidate-fact capacity.  A bounded 10,000-flow snapshot can yield more
# than 1,000 legitimate review candidates on ordinary live traffic; exceeding
# this cap remains a visible incomplete analysis, never a truncated result.
MAX_ANALYSIS_CANDIDATES = 5_000
# A periodic group is created only from a bounded analysis snapshot.  Keeping
# this equal to the snapshot limit prevents ordinary high-cardinality live
# traffic from failing before all bounded input can be examined, while still
# placing a hard upper bound on state and work.
MAX_PERIODIC_GROUPS = MAX_ANALYSIS_FLOW_ROWS
PERIODIC_SUPPORTED_PROTOCOLS = frozenset((6, 17, 132))  # TCP, UDP, SCTP
PERIODIC_MIN_RECORDS = 4
PERIODIC_MIN_INTERVAL_MICROSECONDS = 30 * 1_000_000
PERIODIC_MAX_INTERVAL_MICROSECONDS = 3_600 * 1_000_000
PERIODIC_TOLERANCE_PPM = 100_000  # 10 percent
PERIODIC_MIN_TOLERANCE_MICROSECONDS = 2 * 1_000_000
BASELINE_HISTORY_WINDOWS = 3
BASELINE_RATE_MULTIPLIER = 3
BASELINE_MIN_OBSERVED_FLOWS = 10

ANALYSIS_FAILURE_CODES = frozenset(
    (
        "analysis_candidate_limit_exceeded",
        "analysis_failure",
        "analysis_input_limit_exceeded",
        "analysis_repository_limit_unsupported",
        "analysis_snapshot_legacy_unknown",
        "analysis_source_generation_unavailable",
        "candidate_retention_capacity_exceeded",
        "periodic_candidate_limit_exceeded",
        "periodic_group_limit_exceeded",
        "stale_source_snapshot",
    )
)


@dataclass(frozen=True)
class AnalysisRunOutcome:
    """The fail-visible result of one bounded detector execution.

    Candidate persistence is part of the analysis derivation.  Recording the
    derivation is a separate durable-audit operation, so an audit outage must
    never rewrite a completed analysis as a failed one.
    """

    candidates: tuple[Candidate, ...]
    status: str
    audit_state: str
    reason_code: str | None
    detector_configuration_sha256: str
    analysis_run_id: str | None


@dataclass(frozen=True)
class AnalysisDerivation:
    candidates: tuple[Candidate, ...]
    input_snapshot_json: str


class AnalysisInputLimitError(ValueError):
    """A complete retained snapshot exceeded the declared hard input bound."""

    def __init__(self, snapshot_json: str) -> None:
        self.snapshot_json = snapshot_json
        super().__init__("analysis_input_limit_exceeded")


class AnalysisDerivationError(ValueError):
    """A rule failure after a complete source snapshot was captured.

    A terminal failed analysis still needs to name the precise retained input
    that was examined.  Without this wrapper an overflow would be durable as
    an opaque ``unavailable`` result even though the source boundary and
    canonical material were already known.
    """

    def __init__(self, code: str, snapshot_json: str) -> None:
        self.snapshot_json = snapshot_json
        super().__init__(code)


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timezone_required")
    return parsed.astimezone(timezone.utc)


def _candidate_id(rule_id: str, values: dict[str, Any]) -> str:
    return hashlib.sha256(f"{rule_id}\0{canonical_json(values)}".encode("utf-8")).hexdigest()


def _identity_material(values: dict[str, Any]) -> str:
    return canonical_json(values)


def _canonical_digest(items: tuple[dict[str, Any], ...]) -> str:
    """Hash an ordered canonical projection without creating one large blob."""
    digest = hashlib.sha256()
    for item in items:
        encoded = canonical_json(item).encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _flow_id_contributor_material(flow_ids: tuple[str, ...]) -> dict[str, Any]:
    ordered = tuple(sorted(flow_ids))
    return {
        "count": len(ordered),
        "sha256": _canonical_digest(tuple({"flow_id": flow_id} for flow_id in ordered)),
        "version": "candidate-contributors.v1",
    }


def _snapshot_material(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "byte_count": row["byte_count"],
        "destination_ip": row["destination_ip"],
        "destination_port": row["destination_port"],
        "event_time": row["event_time"],
        "flow_end_time": row["flow_end_time"],
        "flow_id": row["flow_id"],
        "protocol": row["protocol"],
        "session_key": row["session_key"],
        "source_ip": row["source_ip"],
        "source_port": row["source_port"],
    }


def _floor_window(value: datetime, seconds: int) -> datetime:
    epoch = int(value.timestamp())
    return datetime.fromtimestamp(epoch - (epoch % seconds), tz=timezone.utc)


def _microseconds(delta: timedelta) -> int:
    return (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds


def _canonical_ip(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return None
    return str(parsed) if str(parsed) == value else None


def _valid_port(value: object) -> int | None:
    if type(value) is not int or not 1 <= value <= 65_535:
        return None
    return value


class FlowAnalyzer:
    """Rules intentionally generate review candidates, never incident claims."""

    def __init__(
        self,
        *,
        high_volume_bytes: int = 50 * 1024 * 1024,
        fanout_destinations: int = 20,
        window_seconds: int = 300,
        periodic_min_records: int = PERIODIC_MIN_RECORDS,
        periodic_min_interval_microseconds: int = PERIODIC_MIN_INTERVAL_MICROSECONDS,
        periodic_max_interval_microseconds: int = PERIODIC_MAX_INTERVAL_MICROSECONDS,
        periodic_tolerance_ppm: int = PERIODIC_TOLERANCE_PPM,
        periodic_min_tolerance_microseconds: int = PERIODIC_MIN_TOLERANCE_MICROSECONDS,
    ) -> None:
        if (
            high_volume_bytes <= 0
            or fanout_destinations <= 1
            or fanout_destinations > MAX_CANDIDATE_FLOW_REFS
            or window_seconds <= 0
        ):
            raise ValueError("analysis_thresholds_must_be_positive")
        if (
            periodic_min_records != PERIODIC_MIN_RECORDS
            or periodic_min_interval_microseconds < 1
            or periodic_max_interval_microseconds < periodic_min_interval_microseconds
            or periodic_tolerance_ppm < 0
            or periodic_min_tolerance_microseconds < 0
        ):
            raise ValueError("periodic_analysis_policy_invalid")
        self.high_volume_bytes = high_volume_bytes
        self.fanout_destinations = fanout_destinations
        self.window_seconds = window_seconds
        self.periodic_min_records = periodic_min_records
        self.periodic_min_interval_microseconds = periodic_min_interval_microseconds
        self.periodic_max_interval_microseconds = periodic_max_interval_microseconds
        self.periodic_tolerance_ppm = periodic_tolerance_ppm
        self.periodic_min_tolerance_microseconds = periodic_min_tolerance_microseconds

    @property
    def configuration_sha256(self) -> str:
        return hashlib.sha256(
            canonical_json(
                {
                    "fanout_destinations": self.fanout_destinations,
                    "high_volume_bytes": self.high_volume_bytes,
                    "max_candidates": MAX_ANALYSIS_CANDIDATES,
                    "max_flow_rows": MAX_ANALYSIS_FLOW_ROWS,
                    "snapshot_selection": "complete_retained_flow_repository.v1",
                    "flow_rate_baseline": {
                        "history_windows": BASELINE_HISTORY_WINDOWS,
                        "minimum_observed_flows": BASELINE_MIN_OBSERVED_FLOWS,
                        "rate_multiplier": BASELINE_RATE_MULTIPLIER,
                        "window_seconds": self.window_seconds,
                    },
                    "periodic": {
                        "max_groups": MAX_PERIODIC_GROUPS,
                        "minimum_records": self.periodic_min_records,
                        "minimum_tolerance_microseconds": self.periodic_min_tolerance_microseconds,
                        "permitted_protocols": sorted(PERIODIC_SUPPORTED_PROTOCOLS),
                        "source_port_excluded_from_group": True,
                        "tolerance_ppm": self.periodic_tolerance_ppm,
                        "window_maximum_microseconds": self.periodic_max_interval_microseconds,
                        "window_minimum_microseconds": self.periodic_min_interval_microseconds,
                    },
                    "profile_version": PROFILE_VERSION,
                    "rule_version": RULE_VERSION,
                    "window_seconds": self.window_seconds,
                }
            ).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _append_candidate(candidates: list[Candidate], candidate: Candidate, *, overflow_code: str) -> None:
        if len(candidates) >= MAX_ANALYSIS_CANDIDATES:
            raise ValueError(overflow_code)
        candidates.append(candidate)

    def analyze(self, flow_rows: tuple[dict[str, Any], ...], *, now: datetime | None = None) -> tuple[Candidate, ...]:
        created_at = now or datetime.now(tz=timezone.utc)
        candidates: list[Candidate] = []
        for row in flow_rows:
            if row["byte_count"] < self.high_volume_bytes:
                continue
            event_time = _parse_time(row["event_time"])
            contributor_material = _flow_id_contributor_material((str(row["flow_id"]),))
            identity = {
                "contributor_material": contributor_material,
                "flow_id": row["flow_id"],
                "rule_version": "high-volume.v1",
                "threshold": self.high_volume_bytes,
            }
            identity_material_json = _identity_material(identity)
            candidate_id = _candidate_id("high-volume.v1", identity)
            self._append_candidate(
                candidates,
                Candidate(
                    candidate_id=candidate_id,
                    rule_id="high-volume.v1",
                    rule_version="high-volume.v1",
                    created_at=created_at,
                    window_start=event_time,
                    window_end=event_time,
                    threshold=self.high_volume_bytes,
                    observed_value=row["byte_count"],
                    source_ip=row["source_ip"],
                    destination_ip=row["destination_ip"],
                    destination_port=row["destination_port"],
                    protocol=row["protocol"],
                    session_key=row["session_key"],
                    flow_ids=(row["flow_id"],),
                    uncertainty=("sampling-unknown", "ip-allowlisted-unauthenticated"),
                    identity_material_json=identity_material_json,
                    basis_json=canonical_json(
                        {
                            "basis": "exporter_reported_byte_count.v2",
                            "contributor_material": contributor_material,
                            "flow_id": row["flow_id"],
                        }
                    ),
                    explanation=(
                        "Threshold candidate for analyst review: exporter-reported byte counter met or exceeded "
                        f"the configured {self.high_volume_bytes}-byte threshold. Sampling state is unknown."
                    ),
                ),
                overflow_code="analysis_candidate_limit_exceeded",
            )
        grouped: dict[tuple[str, str, int | None, datetime], list[dict[str, Any]]] = defaultdict(list)
        for row in flow_rows:
            event_time = _parse_time(row["event_time"])
            grouped[(row["session_key"], row["source_ip"], row["protocol"], _floor_window(event_time, self.window_seconds))].append(row)
        for (session_key, source_ip, protocol, start), rows in grouped.items():
            destinations = {row["destination_ip"] for row in rows}
            if len(destinations) < self.fanout_destinations:
                continue
            contributors = tuple(
                sorted(
                    (
                        {"destination_ip": str(row["destination_ip"]), "flow_id": str(row["flow_id"])}
                        for row in rows
                    ),
                    key=lambda item: (item["destination_ip"], item["flow_id"]),
                )
            )
            contributor_material = {
                "count": len(contributors),
                "sha256": _canonical_digest(contributors),
                "version": "candidate-contributors.v1",
            }
            witness_rows: list[dict[str, Any]] = []
            witnessed_destinations: set[str] = set()
            for row in sorted(rows, key=lambda item: (item["destination_ip"], item["event_time"], item["flow_id"])):
                destination = str(row["destination_ip"])
                if destination in witnessed_destinations:
                    continue
                witnessed_destinations.add(destination)
                witness_rows.append(row)
                if len(witness_rows) == self.fanout_destinations:
                    break
            # Candidate-flow storage is a set keyed by flow ID, so retain its
            # canonical sorted representation while the basis pins the
            # deterministic destination/event/flow selection policy.
            witness_flow_ids = tuple(sorted(str(row["flow_id"]) for row in witness_rows))
            window_end = start + timedelta(seconds=self.window_seconds)
            scope = {
                "protocol": protocol,
                "session_key": session_key,
                "source_ip": source_ip,
                "window_end": window_end.isoformat(),
                "window_start": start.isoformat(),
            }
            identity = {
                "contributor_material": contributor_material,
                "contributor_scope": scope,
                "reference_flow_ids": witness_flow_ids,
                "rule_version": "destination-fanout.v2",
                "threshold": self.fanout_destinations,
                "unique_destination_count": len(destinations),
            }
            identity_material_json = _identity_material(identity)
            candidate_id = _candidate_id("destination-fanout.v2", identity)
            self._append_candidate(
                candidates,
                Candidate(
                    candidate_id=candidate_id,
                    rule_id="destination-fanout.v2",
                    rule_version="destination-fanout.v2",
                    created_at=created_at,
                    window_start=start,
                    window_end=window_end,
                    threshold=self.fanout_destinations,
                    observed_value=len(destinations),
                    source_ip=source_ip,
                    destination_ip=None,
                    destination_port=None,
                    protocol=protocol,
                    session_key=session_key,
                    flow_ids=witness_flow_ids,
                    uncertainty=("sampling-unknown", "ip-allowlisted-unauthenticated"),
                    identity_material_json=identity_material_json,
                    basis_json=canonical_json(
                        {
                            "basis": "unique_destination_fanout.v2",
                            "contributor_material": contributor_material,
                            "contributor_scope": scope,
                            "reference_selection": "one_flow_per_destination.destination_event_time_flow_id.v1",
                            "reference_flow_ids": witness_flow_ids,
                            "references_representative_bounded": True,
                            "unique_destination_count": len(destinations),
                        }
                    ),
                    explanation=(
                        "Threshold candidate for analyst review: bounded representative flow references establish the "
                        f"configured {self.fanout_destinations}-destination threshold within this {self.window_seconds}-second "
                        "window; the contributor digest covers the full supplied group. Sampling state is unknown."
                    ),
                ),
                overflow_code="analysis_candidate_limit_exceeded",
            )
        self._append_flow_rate_baseline_candidates(flow_rows, candidates, created_at)
        self._append_periodic_candidates(flow_rows, candidates, created_at)
        ordered = tuple(sorted(candidates, key=lambda candidate: candidate.candidate_id))
        return ordered

    def _append_flow_rate_baseline_candidates(
        self,
        flow_rows: tuple[dict[str, Any], ...],
        candidates: list[Candidate],
        created_at: datetime,
    ) -> None:
        grouped: dict[tuple[str, str, int | None], dict[datetime, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
        for row in flow_rows:
            event_time = _parse_time(row["event_time"])
            grouped[(str(row["session_key"]), str(row["source_ip"]), row["protocol"])][
                _floor_window(event_time, self.window_seconds)
            ].append(row)

        for (session_key, source_ip, protocol), windows in sorted(grouped.items()):
            for window_start, rows in sorted(windows.items()):
                historical_starts = tuple(
                    window_start - timedelta(seconds=self.window_seconds * offset)
                    for offset in range(BASELINE_HISTORY_WINDOWS, 0, -1)
                )
                if any(start not in windows for start in historical_starts):
                    continue
                observed_count = len(rows)
                if observed_count < BASELINE_MIN_OBSERVED_FLOWS:
                    continue
                baseline_counts = tuple(len(windows[start]) for start in historical_starts)
                median_baseline_count = sorted(baseline_counts)[BASELINE_HISTORY_WINDOWS // 2]
                threshold = median_baseline_count * BASELINE_RATE_MULTIPLIER
                if observed_count < threshold:
                    continue
                contributor_rows = tuple(sorted(str(row["flow_id"]) for row in rows))
                contributor_material = _flow_id_contributor_material(contributor_rows)
                reference_flow_ids = contributor_rows[:MAX_CANDIDATE_FLOW_REFS]
                window_end = window_start + timedelta(seconds=self.window_seconds)
                scope = {
                    "protocol": protocol,
                    "session_key": session_key,
                    "source_ip": source_ip,
                    "window_end": window_end.isoformat(),
                    "window_start": window_start.isoformat(),
                }
                policy = {
                    "baseline_counts": baseline_counts,
                    "history_windows": BASELINE_HISTORY_WINDOWS,
                    "minimum_observed_flows": BASELINE_MIN_OBSERVED_FLOWS,
                    "rate_multiplier": BASELINE_RATE_MULTIPLIER,
                    "window_seconds": self.window_seconds,
                }
                identity = {
                    "contributor_material": contributor_material,
                    "contributor_scope": scope,
                    "policy": policy,
                    "reference_flow_ids": reference_flow_ids,
                    "rule_version": "flow-rate-baseline.v1",
                    "threshold": threshold,
                }
                identity_material_json = _identity_material(identity)
                candidate_id = _candidate_id("flow-rate-baseline.v1", identity)
                self._append_candidate(
                    candidates,
                    Candidate(
                        candidate_id=candidate_id,
                        rule_id="flow-rate-baseline.v1",
                        rule_version="flow-rate-baseline.v1",
                        created_at=created_at,
                        window_start=window_start,
                        window_end=window_end,
                        threshold=threshold,
                        observed_value=observed_count,
                        source_ip=source_ip,
                        destination_ip=None,
                        destination_port=None,
                        protocol=protocol,
                        session_key=session_key,
                        flow_ids=reference_flow_ids,
                        uncertainty=(
                            "ip-allowlisted-unauthenticated",
                            "sampling-unknown",
                            "baseline-derived-from-supplied-retained-windows",
                        ),
                        identity_material_json=identity_material_json,
                        basis_json=canonical_json(
                            {
                                "basis": "contiguous_window_flow_rate_baseline.v1",
                                "contributor_material": contributor_material,
                                "contributor_scope": scope,
                                **policy,
                                "reference_flow_ids": reference_flow_ids,
                                "references_representative_bounded": len(reference_flow_ids) < observed_count,
                            }
                        ),
                        explanation=(
                            "Flow-rate candidate for analyst review: the supplied source/session/protocol window met "
                            "the configured multiple of three immediately preceding contiguous retained windows; "
                            "this is not proof of abnormal network activity or compromise."
                        ),
                    ),
                    overflow_code="analysis_candidate_limit_exceeded",
                )

    def _append_periodic_candidates(
        self,
        flow_rows: tuple[dict[str, Any], ...],
        candidates: list[Candidate],
        created_at: datetime,
    ) -> None:
        groups: dict[tuple[str, str, str, int, int], list[tuple[datetime, dict[str, Any]]]] = defaultdict(list)
        for row in flow_rows:
            source_ip = _canonical_ip(row.get("source_ip"))
            destination_ip = _canonical_ip(row.get("destination_ip"))
            source_port = _valid_port(row.get("source_port"))
            destination_port = _valid_port(row.get("destination_port"))
            protocol = row.get("protocol")
            flow_end_value = row.get("flow_end_time")
            if (
                source_ip is None
                or destination_ip is None
                or source_port is None
                or destination_port is None
                or type(protocol) is not int
                or protocol not in PERIODIC_SUPPORTED_PROTOCOLS
                or not isinstance(flow_end_value, str)
            ):
                continue
            try:
                flow_end = _parse_time(flow_end_value)
            except (TypeError, ValueError):
                continue
            key = (str(row.get("session_key")), source_ip, destination_ip, destination_port, protocol)
            if key not in groups and len(groups) >= MAX_PERIODIC_GROUPS:
                raise ValueError("periodic_group_limit_exceeded")
            groups[key].append((flow_end, row))

        for (session_key, source_ip, destination_ip, destination_port, protocol), values in sorted(groups.items()):
            ordered = sorted(values, key=lambda item: (item[0], str(item[1].get("flow_id"))))
            if any(later[0] <= earlier[0] for earlier, later in zip(ordered, ordered[1:])):
                # Equal timestamps cannot establish a unique ordered cadence.
                continue
            for start_index in range(len(ordered) - self.periodic_min_records + 1):
                window = ordered[start_index : start_index + self.periodic_min_records]
                times = tuple(item[0] for item in window)
                intervals = tuple(_microseconds(later - earlier) for earlier, later in zip(times, times[1:]))
                if not all(
                    self.periodic_min_interval_microseconds <= interval <= self.periodic_max_interval_microseconds
                    for interval in intervals
                ):
                    continue
                median_interval = sorted(intervals)[len(intervals) // 2]
                allowed_deviation = max(
                    self.periodic_min_tolerance_microseconds,
                    (median_interval * self.periodic_tolerance_ppm) // 1_000_000,
                )
                maximum_deviation = max(abs(interval - median_interval) for interval in intervals)
                if maximum_deviation > allowed_deviation:
                    continue
                flow_ids_chronological = tuple(str(item[1]["flow_id"]) for item in window)
                flow_end_times = tuple(item[0].isoformat() for item in window)
                contributor_material = _flow_id_contributor_material(flow_ids_chronological)
                policy = {
                    "allowed_deviation_microseconds": allowed_deviation,
                    "flow_end_times_utc": flow_end_times,
                    "flow_ids_chronological": flow_ids_chronological,
                    "interval_microseconds": intervals,
                    "maximum_deviation_microseconds": maximum_deviation,
                    "median_interval_microseconds": median_interval,
                    "minimum_records": self.periodic_min_records,
                    "minimum_tolerance_microseconds": self.periodic_min_tolerance_microseconds,
                    "periodic_interval_maximum_microseconds": self.periodic_max_interval_microseconds,
                    "periodic_interval_minimum_microseconds": self.periodic_min_interval_microseconds,
                    "periodic_tolerance_ppm": self.periodic_tolerance_ppm,
                    "source_port_excluded_from_group": True,
                }
                identity = {
                    "contributor_material": contributor_material,
                    "destination_ip": destination_ip,
                    "destination_port": destination_port,
                    "group_session_key": session_key,
                    "policy": policy,
                    "protocol": protocol,
                    "rule_version": "periodic-flow.v1",
                    "source_ip": source_ip,
                }
                identity_material_json = _identity_material(identity)
                candidate_id = _candidate_id("periodic-flow.v1", identity)
                self._append_candidate(
                    candidates,
                    Candidate(
                        candidate_id=candidate_id,
                        rule_id="periodic-flow.v1",
                        rule_version="periodic-flow.v1",
                        created_at=created_at,
                        window_start=times[0],
                        window_end=times[-1],
                        threshold=self.periodic_min_records,
                        observed_value=self.periodic_min_records,
                        source_ip=source_ip,
                        destination_ip=destination_ip,
                        destination_port=destination_port,
                        protocol=protocol,
                        session_key=session_key,
                        flow_ids=flow_ids_chronological,
                        uncertainty=(
                            "exporter-reported-flow-end-time",
                            "ip-allowlisted-unauthenticated",
                            "sampling-unknown",
                            "source-port-excluded-from-endpoint-group",
                        ),
                        identity_material_json=identity_material_json,
                        basis_json=canonical_json(
                            {
                                "basis": "exporter_reported_endpoint_periodicity.v1",
                                "contributor_material": contributor_material,
                                **policy,
                            }
                        ),
                        explanation=(
                            "Periodic-flow candidate for analyst review: four supplied exporter-reported flow-end times "
                            "share the configured endpoint group and fall within the fixed interval/tolerance policy; "
                            "this is not causation or compromise."
                        ),
                    ),
                    overflow_code="periodic_candidate_limit_exceeded",
                )

    def derive_repository(self, repository: Any, *, now: datetime | None = None) -> AnalysisDerivation:
        """Derive from one exact, complete retained-flow source snapshot."""
        configured_limit = getattr(repository, "max_flow_records", None)
        if type(configured_limit) is not int or not 1 <= configured_limit <= MAX_ANALYSIS_FLOW_ROWS:
            raise ValueError("analysis_repository_limit_unsupported")
        rows, source_generation = repository.analysis_source_snapshot(limit=configured_limit + 1)
        if len(rows) > configured_limit:
            failure_snapshot = canonical_json(
                {
                    "effective_flow_limit": configured_limit,
                    "flow_count_at_least": len(rows),
                    "selection": "complete_retained_flow_repository.v1",
                    "snapshot_state": "input_limit_exceeded",
                    "source_generation_lte": source_generation,
                    "version": ANALYSIS_SNAPSHOT_VERSION,
                }
            )
            raise AnalysisInputLimitError(failure_snapshot)
        material = tuple(
            _snapshot_material(row)
            for row in sorted(rows, key=lambda item: str(item["flow_id"]))
        )
        snapshot_json = canonical_json(
            {
                "effective_flow_limit": configured_limit,
                "flow_count": len(rows),
                "material_sha256": _canonical_digest(material),
                "selection": "complete_retained_flow_repository.v1",
                "snapshot_state": "complete",
                "source_generation_lte": source_generation,
                "version": ANALYSIS_SNAPSHOT_VERSION,
            }
        )
        try:
            candidates = self.analyze(rows, now=now)
        except ValueError as exc:
            raise AnalysisDerivationError(str(exc), snapshot_json) from exc
        return AnalysisDerivation(candidates=candidates, input_snapshot_json=snapshot_json)

    def analyze_repository(self, repository: Any, *, now: datetime | None = None, bounded: bool = False) -> tuple[Candidate, ...]:
        """Compatibility wrapper for callers that only need deterministic candidates."""
        if not bounded:
            return self.analyze(repository.flow_rows(limit=None), now=now)
        return self.derive_repository(repository, now=now).candidates


def _analysis_failure_reason(exc: Exception) -> str:
    code = str(exc)
    return code if code in ANALYSIS_FAILURE_CODES else "analysis_failure"


def analyze_and_record(
    repository: Any,
    *,
    collection_run_id: str | None = None,
    now: datetime | None = None,
    bounded: bool = True,
) -> AnalysisRunOutcome:
    """Run deterministic analysis and independently record its terminal state.

    A completed derivation whose audit-row write fails remains ``completed``
    with ``audit_state='unavailable'``.  This distinction prevents previously
    persisted candidates from being represented as a failed analysis.
    """

    analyzer = FlowAnalyzer()
    started_at = now or datetime.now(tz=timezone.utc)
    try:
        # Persisted analysis is always based on the one bounded, complete
        # source snapshot; ``bounded`` remains a compatibility argument only.
        derivation = analyzer.derive_repository(repository, now=now)
    except Exception as exc:
        reason_code = _analysis_failure_reason(exc)
        input_snapshot_json = getattr(
            exc,
            "snapshot_json",
            canonical_json(
                {
                    "selection": "complete_retained_flow_repository.v1",
                    "snapshot_state": "unavailable",
                    "version": ANALYSIS_SNAPSHOT_VERSION,
                }
            ),
        )
        try:
            analysis_run_id = repository.record_analysis_run(
                collection_run_id=collection_run_id,
                detector_configuration_sha256=analyzer.configuration_sha256,
                started_at=started_at,
                completed_at=datetime.now(tz=timezone.utc),
                status="failed",
                candidate_count=0,
                reason_code=reason_code,
                input_snapshot_json=input_snapshot_json,
            )
        except Exception:
            return AnalysisRunOutcome(
                candidates=(),
                status="failed",
                audit_state="unavailable",
                reason_code="analysis_audit_unavailable",
                detector_configuration_sha256=analyzer.configuration_sha256,
                analysis_run_id=None,
            )
        return AnalysisRunOutcome(
            candidates=(),
            status="failed",
            audit_state="written",
            reason_code=reason_code,
            detector_configuration_sha256=analyzer.configuration_sha256,
            analysis_run_id=analysis_run_id,
        )

    try:
        analysis_run_id = repository.commit_analysis_success(
            collection_run_id=collection_run_id,
            detector_configuration_sha256=analyzer.configuration_sha256,
            started_at=started_at,
            completed_at=datetime.now(tz=timezone.utc),
            candidates=derivation.candidates,
            input_snapshot_json=derivation.input_snapshot_json,
        )
    except ValueError as exc:
        reason_code = _analysis_failure_reason(exc)
        if reason_code in {"stale_source_snapshot", "candidate_retention_capacity_exceeded"}:
            try:
                analysis_run_id = repository.record_analysis_run(
                    collection_run_id=collection_run_id,
                    detector_configuration_sha256=analyzer.configuration_sha256,
                    started_at=started_at,
                    completed_at=datetime.now(tz=timezone.utc),
                    status="failed",
                    candidate_count=0,
                    reason_code=reason_code,
                    input_snapshot_json=derivation.input_snapshot_json,
                )
            except Exception:
                return AnalysisRunOutcome(
                    candidates=(),
                    status="failed",
                    audit_state="unavailable",
                    reason_code="analysis_audit_unavailable",
                    detector_configuration_sha256=analyzer.configuration_sha256,
                    analysis_run_id=None,
                )
            return AnalysisRunOutcome(
                candidates=(),
                status="failed",
                audit_state="written",
                reason_code=reason_code,
                detector_configuration_sha256=analyzer.configuration_sha256,
                analysis_run_id=analysis_run_id,
            )
        return AnalysisRunOutcome(
            candidates=derivation.candidates,
            status="completed",
            audit_state="unavailable",
            reason_code="analysis_audit_unavailable",
            detector_configuration_sha256=analyzer.configuration_sha256,
            analysis_run_id=None,
        )
    except Exception:
        return AnalysisRunOutcome(
            candidates=derivation.candidates,
            status="completed",
            audit_state="unavailable",
            reason_code="analysis_audit_unavailable",
            detector_configuration_sha256=analyzer.configuration_sha256,
            analysis_run_id=None,
        )
    return AnalysisRunOutcome(
        candidates=derivation.candidates,
        status="completed",
        audit_state="written",
        reason_code=None,
        detector_configuration_sha256=analyzer.configuration_sha256,
        analysis_run_id=analysis_run_id,
    )
