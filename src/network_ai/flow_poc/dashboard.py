"""Local-only, read-only dashboard for a trusted single-user POC host."""

from __future__ import annotations

from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from typing import Type

from .storage import FlowRepository


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True).encode("utf-8")


def _current_candidate_view(repository: FlowRepository) -> tuple[dict[str, object], dict[str, object] | None, dict[str, object] | None, tuple[dict[str, object], ...], str]:
    """Resolve candidates only through the analysis snapshot they belong to."""

    summary = repository.summary()
    latest_run = summary["latest_collection_run"]
    latest_analysis = (
        repository.latest_analysis_run_for_collection(str(latest_run["run_id"]))
        if latest_run is not None
        else summary["latest_analysis_run"]
    )
    if latest_analysis is not None and latest_analysis["status"] == "completed":
        candidates = repository.candidate_rows(limit=50, analysis_run_id=str(latest_analysis["analysis_run_id"]))
    else:
        candidates = ()
    scope = (
        "analysis associated with this collection run; input is a bounded stored-flow snapshot"
        if latest_run is not None
        else "an independent bounded stored-flow snapshot"
    )
    return summary, latest_run, latest_analysis, candidates, scope


def _candidate_metric(candidate: dict[str, object]) -> str:
    if candidate.get("rule_id") != "periodic-flow.v1":
        return f"{candidate.get('observed_value')} / {candidate.get('threshold')}"
    basis = candidate.get("basis")
    if not isinstance(basis, dict):
        return "periodicity basis unavailable"
    return (
        f"{basis.get('minimum_records')} events; median {basis.get('median_interval_microseconds')} us; "
        f"deviation {basis.get('maximum_deviation_microseconds')} / {basis.get('allowed_deviation_microseconds')} us"
    )


def _candidate_endpoint(candidate: dict[str, object]) -> str:
    destination = candidate.get("destination_ip") or "multiple destinations"
    port = candidate.get("destination_port")
    protocol = candidate.get("protocol")
    return f"{destination}:{port if port is not None else 'n/a'} / protocol {protocol if protocol is not None else 'n/a'}"


def dashboard_server(root: Path | str, *, host: str = "127.0.0.1", port: int = 8081) -> ThreadingHTTPServer:
    if host != "127.0.0.1":
        raise ValueError("dashboard_must_bind_literal_ipv4_loopback")
    repository = FlowRepository(root)

    class Handler(BaseHTTPRequestHandler):
        server_version = "NetworkAIFlowPOC/1.0"
        sys_version = ""

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            if self.path == "/api/summary":
                self._send(200, _json_bytes(repository.summary()), "application/json; charset=utf-8")
                return
            if self.path == "/api/flows":
                self._send(200, _json_bytes(repository.flow_rows(limit=200)), "application/json; charset=utf-8")
                return
            if self.path == "/api/candidates":
                _summary, _run, analysis, candidates, scope = _current_candidate_view(repository)
                self._send(
                    200,
                    _json_bytes(
                        {
                            "analysis_run_id": analysis["analysis_run_id"] if analysis is not None else None,
                            "analysis_status": analysis["status"] if analysis is not None else "unknown",
                            "input_snapshot": analysis["input_snapshot"] if analysis is not None else {"snapshot_state": "unknown"},
                            "candidates": candidates,
                            "scope": scope,
                        }
                    ),
                    "application/json; charset=utf-8",
                )
                return
            if self.path != "/":
                self._send(404, b"not found\n", "text/plain; charset=utf-8")
                return
            summary, latest_run, latest_analysis, candidates, scope_label = _current_candidate_view(repository)
            analysis_degraded = False
            if latest_run is None:
                health_html = "<p class='note'>No durable collection run has been recorded. This is unknown, not healthy.</p>"
            else:
                counters = latest_run["counters"]
                analysis_failures = int(counters.get("analysis_failures", 0))
                analysis_audit_failures = int(counters.get("analysis_audit_failures", 0))
                analysis_degraded = analysis_failures > 0 or analysis_audit_failures > 0
                terminal_note = (
                    "The run has a durable terminal state."
                    if latest_run["terminal_state_confirmed"]
                    else "The run is in progress or its terminal audit state is unconfirmed; do not treat it as healthy."
                )
                health_html = (
                    "<dl><dt>Run state</dt><dd>"
                    f"{escape(str(latest_run['state']))}</dd><dt>Audit state</dt><dd>{escape(str(latest_run['audit_state']))}</dd>"
                    f"<dt>Last received</dt><dd>{escape(str(latest_run['last_received_at'] or 'none'))}</dd>"
                    f"<dt>Last persisted</dt><dd>{escape(str(latest_run['last_persisted_at'] or 'none'))}</dd>"
                    f"<dt>Policy rejected</dt><dd>{escape(str(counters.get('rejected_policy', 0)))}</dd>"
                    f"<dt>Rate dropped</dt><dd>{escape(str(counters.get('rate_dropped', 0)))}</dd>"
                    f"<dt>Template missing</dt><dd>{escape(str(counters.get('template_missing', 0)))}</dd>"
                    f"<dt>Malformed</dt><dd>{escape(str(counters.get('malformed', 0)))}</dd>"
                    f"<dt>Persistence failures</dt><dd>{escape(str(counters.get('persistence_failures', 0)))}</dd>"
                    f"<dt>Options sets ignored</dt><dd>{escape(str(counters.get('options_data_ignored', 0)))}</dd>"
                    f"<dt>Analysis failures</dt><dd>{escape(str(analysis_failures))}</dd>"
                    f"<dt>Analysis audit failures</dt><dd>{escape(str(analysis_audit_failures))}</dd></dl>"
                    f"<p class='note'>{escape(terminal_note)} UDP source allowlisting is not exporter authentication; no traffic is not a healthy state.</p>"
                )
            if latest_analysis is None:
                analysis_html = (
                    "<p class='note'>No durable analysis result has been recorded for the displayed collection run. "
                    "Candidate state is unknown.</p>"
                )
                analysis_degraded = True
            else:
                analysis_html = (
                    f"<p class='note'>Analysis record scope: {escape(scope_label)}.</p><dl><dt>Status</dt><dd>"
                    f"{escape(str(latest_analysis['status']))}</dd><dt>Candidate count</dt><dd>"
                    f"{escape(str(latest_analysis['candidate_count']))}</dd><dt>Detector configuration</dt><dd>"
                    f"{escape(str(latest_analysis['detector_configuration_sha256']))}</dd><dt>Reason</dt><dd>"
                    f"{escape(str(latest_analysis['reason_code'] or 'none'))}</dd><dt>Completed</dt><dd>"
                    f"{escape(str(latest_analysis['completed_at']))}</dd></dl>"
                )
                snapshot = latest_analysis["input_snapshot"]
                if isinstance(snapshot, dict):
                    analysis_html += (
                        "<dl><dt>Input snapshot state</dt><dd>"
                        f"{escape(str(snapshot.get('snapshot_state', 'unknown')))}</dd><dt>Source generation boundary</dt><dd>"
                        f"{escape(str(snapshot.get('source_generation_lte', 'unknown')))}</dd><dt>Input flow count</dt><dd>"
                        f"{escape(str(snapshot.get('flow_count', snapshot.get('flow_count_at_least', 'unknown'))))}</dd></dl>"
                    )
                if latest_analysis["status"] != "completed":
                    analysis_degraded = True
            if analysis_degraded:
                analysis_html += (
                    "<p class='note'>Analysis is degraded or its audit is unavailable; a zero candidate count "
                    "must not be treated as a clean result.</p>"
                )
            candidate_rows = "".join(
                "<tr>"
                f"<td>{escape(str(candidate['rule_id']))}</td>"
                f"<td>{escape(str(candidate['source_ip'] or 'n/a'))}</td>"
                f"<td>{escape(_candidate_endpoint(candidate))}</td>"
                f"<td>{escape(_candidate_metric(candidate))}</td>"
                f"<td>{escape(str(candidate['window_start']))}</td>"
                f"<td>{escape(str(candidate['explanation']))}</td>"
                "</tr>"
                for candidate in candidates
            ) or (
                "<tr><td colspan='6'>No auditable successful analysis result is available; candidate state is unknown.</td></tr>"
                if analysis_degraded
                else "<tr><td colspan='6'>No candidates were produced by the latest completed analysis.</td></tr>"
            )
            html = f"""<!doctype html>
<html lang='en'><head><meta charset='utf-8'><title>Network AI Flow POC</title>
<style>body{{font-family:system-ui;margin:2rem;max-width:1100px}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #bbb;padding:.5rem;text-align:left}}.note{{color:#555}}</style>
</head><body><h1>Network AI Flow POC</h1>
<p class='note'>Single-user localhost view. Exporter identity is IP-allowlisted but unauthenticated. Candidates require analyst review.</p>
<dl><dt>Flows</dt><dd>{escape(str(summary['flow_count']))}</dd><dt>Datagrams</dt><dd>{escape(str(summary['datagram_count']))}</dd><dt>Current candidates</dt><dd>{escape(str(len(candidates)))}</dd><dt>Retained candidate facts</dt><dd>{escape(str(summary['candidate_count']))}</dd></dl>
<h2>Collection health</h2>{health_html}
<h2>Analysis status</h2>{analysis_html}
<h2>Current analyst candidates</h2><table><thead><tr><th>Rule</th><th>Source</th><th>Endpoint</th><th>Observed evidence</th><th>Window</th><th>Evidence-bound explanation</th></tr></thead><tbody>{candidate_rows}</tbody></table>
<p class='note'>JSON: <a href='/api/summary'>summary</a> · <a href='/api/flows'>flows</a> · <a href='/api/candidates'>candidates</a></p>
</body></html>"""
            self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            self._send(405, b"method not allowed\n", "text/plain; charset=utf-8")

        def log_message(self, _format: str, *_args: object) -> None:
            # Avoid writing sensitive flow metadata to process logs.
            return

    return ThreadingHTTPServer((host, port), Handler)
