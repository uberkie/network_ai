"""CLI for the bounded, read-only NetFlow v9/IPFIX collector."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

from .analysis import analyze_and_record
from .collector import FlowCollector, ListenerPolicy
from .dashboard import dashboard_server
from .demo_data import synthetic_demo_messages
from .storage import FlowRepository


def _repository(arguments: argparse.Namespace) -> FlowRepository:
    return FlowRepository(arguments.database)


def _run_demo(arguments: argparse.Namespace) -> int:
    repository = _repository(arguments)
    collector = FlowCollector(repository, ListenerPolicy(), auto_analyze=True)
    received_at = datetime(2026, 8, 15, tzinfo=timezone.utc)
    outcomes = [
        collector.ingest_datagram(
            message,
            exporter_ip="127.0.0.1",
            exporter_port=20_555,
            received_at=received_at + timedelta(seconds=index),
            now_monotonic=float(index),
        )
        for index, message in enumerate(synthetic_demo_messages())
    ]
    analysis = analyze_and_record(repository, now=received_at + timedelta(seconds=10), bounded=False)
    print(
        json.dumps(
            {
                "candidate_count": len(analysis.candidates),
                "analysis_audit_state": analysis.audit_state,
                "analysis_status": analysis.status,
                "collector_stats": collector.stats.as_dict(),
                "outcomes": [{"flow_count": len(item.inserted_flow_ids), "status": item.status} for item in outcomes],
                "summary": repository.summary(),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if analysis.status == "completed" and analysis.audit_state == "written" else 2


def _run_analyze(arguments: argparse.Namespace) -> int:
    repository = _repository(arguments)
    # An explicit analysis pass is a review of the bounded local repository
    # snapshot, which can include retained flows from earlier collections.
    # When collection evidence exists, associate the derivation audit with the
    # latest durable run so the dashboard can show it as current without
    # claiming that every input flow came from that one collection run.
    latest_collection = repository.latest_collection_run()
    collection_run_id = str(latest_collection["run_id"]) if latest_collection is not None else None
    analysis = analyze_and_record(repository, collection_run_id=collection_run_id)
    print(
        json.dumps(
            {
                "analysis_audit_state": analysis.audit_state,
                "analysis_run_id": analysis.analysis_run_id,
                "analysis_status": analysis.status,
                "candidate_count": len(analysis.candidates),
                "collection_run_id": collection_run_id,
                "reason_code": analysis.reason_code,
                "summary": repository.summary(),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if analysis.status == "completed" and analysis.audit_state == "written" else 2


def _listener_policy(arguments: argparse.Namespace) -> ListenerPolicy:
    return ListenerPolicy(
        bind_host=arguments.host,
        port=arguments.port,
        exporter_allowlist=tuple(arguments.exporter_allowlist or ("127.0.0.1/32",)),
        allow_nonloopback=arguments.allow_nonloopback,
        duration_seconds=arguments.duration_seconds,
        max_datagrams=arguments.max_datagrams,
    )


def _run_listen(arguments: argparse.Namespace) -> int:
    policy = _listener_policy(arguments)
    collector = FlowCollector(_repository(arguments), policy, auto_analyze=True)
    stats = collector.serve()
    print(json.dumps(stats.as_dict(), indent=2, sort_keys=True))
    return 0 if (
        stats.run_state in {"completed", "completed_no_accepted_datagrams", "interrupted"}
        and stats.run_audit_state == "written"
        and stats.analysis_failures == 0
        and stats.analysis_audit_failures == 0
    ) else 2


def _run_dashboard(arguments: argparse.Namespace) -> int:
    server = dashboard_server(arguments.database, host=arguments.host, port=arguments.port)
    print(f"Local dashboard: http://{arguments.host}:{server.server_port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()


def _run_prune(arguments: argparse.Namespace) -> int:
    cutoff = datetime.now(tz=timezone.utc) - timedelta(hours=arguments.older_than_hours)
    print(json.dumps(_repository(arguments).prune_expired(cutoff), indent=2, sort_keys=True))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Network AI bounded, read-only NetFlow v9/IPFIX collector (v5 unsupported)")
    subcommands = parser.add_subparsers(dest="command", required=True)

    for name in ("demo", "analyze", "prune"):
        command = subcommands.add_parser(name)
        command.add_argument("--database", type=Path, required=True, help="single-user local SQLite store directory")
        if name == "prune":
            command.add_argument("--older-than-hours", type=int, default=24)

    listen = subcommands.add_parser("listen")
    listen.add_argument("--database", type=Path, required=True)
    listen.add_argument("--host", default="127.0.0.1")
    listen.add_argument("--port", type=int, default=2055)
    listen.add_argument("--exporter-allowlist", action="append", default=None)
    listen.add_argument("--allow-nonloopback", action="store_true")
    listen.add_argument("--duration-seconds", type=int, default=300)
    listen.add_argument("--max-datagrams", type=int, default=3000)

    dashboard = subcommands.add_parser("dashboard")
    dashboard.add_argument("--database", type=Path, required=True)
    dashboard.add_argument("--host", default="127.0.0.1")
    dashboard.add_argument("--port", type=int, default=8081)

    arguments = parser.parse_args()
    if arguments.command == "demo":
        return _run_demo(arguments)
    if arguments.command == "analyze":
        return _run_analyze(arguments)
    if arguments.command == "listen":
        return _run_listen(arguments)
    if arguments.command == "dashboard":
        return _run_dashboard(arguments)
    if arguments.command == "prune":
        return _run_prune(arguments)
    raise AssertionError("unknown command")


if __name__ == "__main__":
    raise SystemExit(main())
