"""ReactPy-Django query functions for already-running, read-only stores."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from django.conf import settings

from network_ai.analyst import build_analyst_snapshot, filter_evidence


def _process_observed(names: frozenset[str]) -> str:
    proc = Path("/proc")
    if not proc.is_dir():
        return "unknown"
    try:
        entries = proc.iterdir()
    except OSError:
        return "unknown"
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            comm = (entry / "comm").read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if comm in names:
            return "observed"
    return "not_observed"


def _with_process_health(snapshot: dict[str, Any]) -> dict[str, Any]:
    sensors = dict(snapshot.get("sensors") or {})
    suricata = dict(sensors.get("suricata") or {})
    zeek = dict(sensors.get("zeek") or {})
    mikrotik = dict(sensors.get("mikrotik") or {})
    flow = dict(sensors.get("flow") or {})
    suricata["process"] = _process_observed(frozenset({"suricata"}))
    zeek["process"] = _process_observed(frozenset({"zeek", "bro"}))
    mikrotik["process"] = "not_applicable"
    flow["process"] = "not_observed"
    snapshot["sensors"] = {
        "flow": flow,
        "mikrotik": mikrotik,
        "suricata": suricata,
        "zeek": zeek,
    }
    return snapshot


def analyst_snapshot() -> dict[str, Any]:
    flow_root = getattr(settings, "ANALYST_FLOW_ROOT", None)
    return _with_process_health(
        build_analyst_snapshot(getattr(settings, "ANALYST_EVIDENCE_ROOT", None), flow_root)
    )


def discover_rows(source: str = "", text: str = "", protocol: str = "") -> dict[str, Any]:
    snapshot = analyst_snapshot()
    snapshot["evidence"] = filter_evidence(
        list(snapshot.get("evidence") or []),
        source=source,
        text=text,
        protocol=protocol,
    )
    return snapshot
