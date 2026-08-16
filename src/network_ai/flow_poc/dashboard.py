"""Local-only, read-only dashboard for a trusted single-user POC host."""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
from typing import Any

from .collector import FlowCollector, ListenerPolicy
from .storage import FlowRepository


LIVE_FLOW_FRESHNESS_SECONDS = 120


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True).encode("utf-8")


def _age_seconds(value: object, *, now: datetime) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        observed_at = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None
    return max(0, int((now - observed_at).total_seconds()))


def _age_label(seconds: int | None) -> str:
    if seconds is None:
        return "unknown"
    if seconds < 60:
        return f"{seconds} seconds ago"
    if seconds < 3_600:
        return f"{seconds // 60} minutes ago"
    return f"{seconds // 3_600} hours ago"


def _freshness_view(
    latest_run: dict[str, object] | None,
    latest_analysis: dict[str, object] | None,
    *,
    now: datetime,
) -> dict[str, object]:
    last_persisted_at = latest_run.get("last_persisted_at") if latest_run is not None else None
    persisted_age_seconds = _age_seconds(last_persisted_at, now=now)
    analysis_completed_at = latest_analysis.get("completed_at") if latest_analysis is not None else None
    analysis_age_seconds = _age_seconds(analysis_completed_at, now=now)
    collection_running = (
        latest_run is not None
        and latest_run.get("state") == "running"
        and latest_run.get("audit_state") == "written"
    )
    flow_data_live = collection_running and persisted_age_seconds is not None and persisted_age_seconds <= LIVE_FLOW_FRESHNESS_SECONDS
    analysis_caught_up = (
        flow_data_live
        and isinstance(last_persisted_at, str)
        and isinstance(analysis_completed_at, str)
        and analysis_completed_at >= last_persisted_at
        and latest_analysis is not None
        and latest_analysis.get("status") == "completed"
    )
    if analysis_caught_up:
        unavailable_reason = None
    elif not collection_running:
        unavailable_reason = "collector_not_running"
    elif persisted_age_seconds is None or persisted_age_seconds > LIVE_FLOW_FRESHNESS_SECONDS:
        unavailable_reason = "fresh_flow_unavailable"
    else:
        unavailable_reason = "analysis_not_caught_up"
    return {
        "analysis_age_seconds": analysis_age_seconds,
        "analysis_completed_at": analysis_completed_at,
        "analysis_caught_up": analysis_caught_up,
        "flow_data_live": flow_data_live,
        "last_persisted_age_seconds": persisted_age_seconds,
        "last_persisted_at": last_persisted_at,
        "mode": "live_flow_anomaly_view" if analysis_caught_up else "live_flow_anomaly_unavailable",
        "unavailable_reason": unavailable_reason,
    }


def _signature_page() -> str:
    return """<!doctype html>
<html lang='en'><head><meta charset='utf-8'><title>Signature Catalog</title>
<style>
body{font-family:system-ui;margin:2rem auto;max-width:1180px;padding:0 1rem;color:#1d2730;background:#f5f6f2}
header{display:flex;justify-content:space-between;align-items:flex-end;border-bottom:2px solid #263640;padding-bottom:1rem;margin-bottom:1.5rem}
h1{margin:0;font-size:1.8rem} .muted{color:#56636b} .toolbar{display:flex;gap:.6rem;flex-wrap:wrap;margin:1rem 0}
button,.button{border:1px solid #263640;background:#fff;color:#16222a;padding:.55rem .75rem;cursor:pointer;font:inherit;text-decoration:none}
button.primary{background:#0c6b61;color:#fff;border-color:#0c6b61} button.danger{color:#9c1f1f;border-color:#9c1f1f}
table{border-collapse:collapse;width:100%;background:#fff}th,td{border-bottom:1px solid #d5d9d5;padding:.65rem;text-align:left;vertical-align:top}th{background:#e4ebe6;font-size:.8rem;text-transform:uppercase}td.actions{white-space:nowrap;display:flex;gap:.4rem}
.state{font-weight:600}.enabled{color:#0c6b61}.disabled{color:#8a4b00}dialog{border:1px solid #263640;max-width:680px;width:calc(100% - 2rem)}form{display:grid;gap:.75rem}label{display:grid;gap:.3rem;font-weight:600}input,textarea,select{font:inherit;padding:.5rem;border:1px solid #8b9798}textarea{min-height:10rem;font-family:ui-monospace,monospace}menu{display:flex;gap:.6rem;padding:0;margin:0}@media(max-width:720px){body{margin:1rem auto}header{align-items:flex-start;gap:1rem;flex-direction:column}table{display:block;overflow-x:auto}}
</style></head><body>
<header><div><h1>Local Signature Catalog</h1><p class='muted'>Catalog state only. No signature is deployed to a sensor or network device.</p></div><a class='button' href='/'>Flow review</a></header>
<div class='toolbar'><button class='primary' id='add'>Add signature</button><button id='import'>Import update</button><a class='button' href='/api/signatures/download'>Download catalog</a><input id='file' type='file' accept='application/json' hidden></div>
<table><thead><tr><th>ID</th><th>Name</th><th>Severity</th><th>State</th><th>Updated</th><th>Actions</th></tr></thead><tbody id='rows'><tr><td colspan='6'>Loading local catalog...</td></tr></tbody></table>
<dialog id='editor'><form method='dialog' id='form'><h2 id='form-title'>Add signature</h2><label>Signature ID<input id='signature-id' type='number' min='1' max='2147483647' required></label><label>Name<input id='name' maxlength='256' required></label><label>Severity<select id='severity'><option value='1'>1 - High</option><option value='2'>2 - Elevated</option><option value='3'>3 - Moderate</option><option value='4'>4 - Informational</option></select></label><label>Signature text<textarea id='rule-text' maxlength='8192' required></textarea></label><label><span>Enabled</span><input id='enabled' type='checkbox' checked></label><menu><button type='button' id='cancel'>Cancel</button><button class='primary' value='default'>Save update</button></menu></form></dialog>
<script>
const rows=document.querySelector('#rows'), editor=document.querySelector('#editor'), form=document.querySelector('#form');let signatures=[];let editing=false;
async function api(path,options={}){const response=await fetch(path,options);const data=await response.json();if(!response.ok)throw new Error(data.error||'request_failed');return data}
function value(id){return document.querySelector(id).value} function set(id,v){document.querySelector(id).value=v}
function render(){rows.replaceChildren(...signatures.map(signature=>{const row=document.createElement('tr');const state=signature.enabled?'Enabled':'Disabled';row.innerHTML=`<td>${signature.signature_id}</td><td>${text(signature.name)}</td><td>${signature.severity}</td><td class='state ${signature.enabled?'enabled':'disabled'}'>${state}</td><td>${text(signature.updated_at)}</td><td class='actions'></td>`;const actions=row.querySelector('.actions');const toggle=document.createElement('button');toggle.textContent=signature.enabled?'Disable':'Enable';toggle.onclick=()=>setEnabled(signature,!signature.enabled);const edit=document.createElement('button');edit.textContent='Edit';edit.onclick=()=>openEditor(signature);const remove=document.createElement('button');remove.textContent='Remove';remove.className='danger';remove.onclick=()=>removeSignature(signature);actions.append(toggle,edit,remove);return row}));if(!signatures.length)rows.innerHTML='<tr><td colspan="6">No local signatures.</td></tr>'}
function text(value){const node=document.createElement('span');node.textContent=value;return node.innerHTML}
async function load(){signatures=(await api('/api/signatures')).signatures;render()}
function openEditor(signature){editing=Boolean(signature);document.querySelector('#form-title').textContent=editing?'Edit signature':'Add signature';set('#signature-id',signature?.signature_id??'');document.querySelector('#signature-id').disabled=editing;set('#name',signature?.name??'');set('#severity',signature?.severity??'3');set('#rule-text',signature?.rule_text??'');document.querySelector('#enabled').checked=signature?.enabled??true;editor.showModal()}
async function save(){const body={action:editing?'update':'create',signature_id:Number(value('#signature-id')),name:value('#name'),severity:Number(value('#severity')),rule_text:value('#rule-text'),enabled:document.querySelector('#enabled').checked};await api('/api/signatures',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});editor.close();await load()}
async function setEnabled(signature,enabled){await api('/api/signatures',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'set_enabled',signature_id:signature.signature_id,enabled})});await load()}
async function removeSignature(signature){if(!confirm(`Remove signature ${signature.signature_id}?`))return;await api('/api/signatures',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'delete',signature_id:signature.signature_id})});await load()}
document.querySelector('#add').onclick=()=>openEditor();document.querySelector('#cancel').onclick=()=>editor.close();form.onsubmit=event=>{event.preventDefault();save().catch(error=>alert(error.message))};document.querySelector('#import').onclick=()=>document.querySelector('#file').click();document.querySelector('#file').onchange=async event=>{const file=event.target.files[0];if(!file)return;try{const catalog=JSON.parse(await file.text());await api('/api/signatures',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'import',signatures:catalog.signatures})});await load()}catch(error){alert(error.message)}finally{event.target.value=''}};load().catch(error=>rows.innerHTML=`<tr><td colspan="6">${text(error.message)}</td></tr>`);
</script></body></html>"""


def _collector_controls() -> str:
    return """<section><h2>Live collector</h2>
<form id='collector-form'><label>Bind host<input id='collector-host' value='127.0.0.1' required></label><label>Port<input id='collector-port' type='number' min='1' max='65535' value='2055' required></label><label>Exporter allowlist<input id='collector-allowlist' value='127.0.0.1/32' required></label><label>Duration seconds<input id='collector-duration' type='number' min='1' max='3600' value='300' required></label><label>Maximum datagrams<input id='collector-max-datagrams' type='number' min='1' max='10000' value='3000' required></label><label>Allow non-loopback<input id='collector-nonloopback' type='checkbox'></label><button id='collector-start' type='submit'>Start collector</button><button id='collector-stop' type='button'>Stop collector</button></form><p class='note' id='collector-state'>Collector state unavailable.</p></section>
<script>
const collectorState=document.querySelector('#collector-state'),collectorStart=document.querySelector('#collector-start'),collectorStop=document.querySelector('#collector-stop');
async function collectorRequest(action,policy){const response=await fetch('/api/collector',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action,policy})});const payload=await response.json();if(!response.ok)throw new Error(payload.error||'collector_request_failed');return payload}
function collectorPolicy(){return {bind_host:document.querySelector('#collector-host').value,port:Number(document.querySelector('#collector-port').value),exporter_allowlist:document.querySelector('#collector-allowlist').value.split(',').map(value=>value.trim()).filter(Boolean),duration_seconds:Number(document.querySelector('#collector-duration').value),max_datagrams:Number(document.querySelector('#collector-max-datagrams').value),allow_nonloopback:document.querySelector('#collector-nonloopback').checked}}
function renderCollector(status){const stats=status.stats||{};collectorState.textContent=status.running?`Running. Received ${stats.received||0}; accepted ${stats.accepted||0}.`:`Stopped. Last state ${stats.run_state||'not started'}.`;collectorStart.disabled=status.running;collectorStop.disabled=!status.running}
async function refreshCollector(){try{const response=await fetch('/api/collector');renderCollector(await response.json())}catch(error){collectorState.textContent=error.message}}
document.querySelector('#collector-form').onsubmit=async event=>{event.preventDefault();try{renderCollector(await collectorRequest('start',collectorPolicy()))}catch(error){collectorState.textContent=error.message}};collectorStop.onclick=async()=>{try{renderCollector(await collectorRequest('stop'))}catch(error){collectorState.textContent=error.message}};refreshCollector();setInterval(refreshCollector,2000);
</script>"""


def _current_candidate_view(
    repository: FlowRepository,
    *,
    now: datetime,
) -> tuple[dict[str, object], dict[str, object] | None, dict[str, object] | None, tuple[dict[str, object], ...], dict[str, object]]:
    """Return only candidates that belong to a fresh active collection run."""

    summary = repository.summary()
    latest_run = summary["latest_collection_run"]
    latest_analysis = (
        repository.latest_analysis_run_for_collection(str(latest_run["run_id"]))
        if latest_run is not None
        else summary["latest_analysis_run"]
    )
    freshness = _freshness_view(latest_run, latest_analysis, now=now)
    if freshness["analysis_caught_up"]:
        candidates = repository.candidate_rows(limit=50, analysis_run_id=str(latest_analysis["analysis_run_id"]))
    else:
        candidates = ()
    return summary, latest_run, latest_analysis, candidates, freshness


def _candidate_metric(candidate: dict[str, object]) -> str:
    if candidate.get("rule_id") == "flow-rate-baseline.v1":
        basis = candidate.get("basis")
        if not isinstance(basis, dict):
            return "baseline basis unavailable"
        return (
            f"{candidate.get('observed_value')} flows / {candidate.get('threshold')} threshold; "
            f"baseline windows {basis.get('baseline_counts')}"
        )
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


class _CollectorController:
    """One bounded collector lifecycle, owned by the localhost dashboard."""

    def __init__(self, repository: FlowRepository) -> None:
        self._repository = repository
        self._lock = threading.Lock()
        self._collector: FlowCollector | None = None
        self._policy: ListenerPolicy | None = None
        self._stop_event: threading.Event | None = None
        self._thread: threading.Thread | None = None
        self._last_stats: dict[str, object] | None = None

    def status(self) -> dict[str, object]:
        with self._lock:
            running = self._thread is not None and self._thread.is_alive()
            stats = self._collector.stats.as_dict() if running and self._collector is not None else self._last_stats
            policy = self._policy
        return {
            "policy": {
                "allow_nonloopback": policy.allow_nonloopback,
                "bind_host": policy.bind_host,
                "duration_seconds": policy.duration_seconds,
                "exporter_allowlist": list(policy.exporter_allowlist),
                "max_datagrams": policy.max_datagrams,
                "port": policy.port,
            }
            if policy is not None
            else None,
            "running": running,
            "stats": stats,
        }

    def start(self, *, policy: ListenerPolicy) -> dict[str, object]:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                raise ValueError("collector_already_running")
            collector = FlowCollector(self._repository, policy, auto_analyze=True)
            stop_event = threading.Event()
            self._collector = collector
            self._policy = policy
            self._stop_event = stop_event
            self._last_stats = None
            thread = threading.Thread(target=self._run, args=(collector, stop_event), daemon=True)
            self._thread = thread
            thread.start()
        return self.status()

    def stop(self) -> dict[str, object]:
        with self._lock:
            if self._stop_event is None or self._thread is None or not self._thread.is_alive():
                raise ValueError("collector_not_running")
            self._stop_event.set()
            thread = self._thread
        thread.join(timeout=2)
        return self.status()

    def shutdown(self) -> None:
        with self._lock:
            stop_event = self._stop_event
            thread = self._thread
        if stop_event is not None:
            stop_event.set()
        if thread is not None:
            thread.join(timeout=2)

    def _run(self, collector: FlowCollector, stop_event: threading.Event) -> None:
        stats = collector.serve(stop_event=stop_event)
        with self._lock:
            self._last_stats = stats.as_dict()


def dashboard_server(root: Path | str, *, host: str = "127.0.0.1", port: int = 8081) -> ThreadingHTTPServer:
    if host != "127.0.0.1":
        raise ValueError("dashboard_must_bind_literal_ipv4_loopback")
    repository = FlowRepository(root)
    collector_controller = _CollectorController(repository)

    class Handler(BaseHTTPRequestHandler):
        server_version = "NetworkAIFlowPOC/1.0"
        sys_version = ""

        def _send(self, status: int, body: bytes, content_type: str, *, download_name: str | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; connect-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'")
            if download_name is not None:
                self.send_header("Content-Disposition", f'attachment; filename="{download_name}"')
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            if self.path == "/api/summary":
                self._send(200, _json_bytes(repository.summary()), "application/json; charset=utf-8")
                return
            if self.path == "/api/flows":
                self._send(200, _json_bytes(repository.flow_rows(limit=200)), "application/json; charset=utf-8")
                return
            if self.path == "/api/collector":
                self._send(200, _json_bytes(collector_controller.status()), "application/json; charset=utf-8")
                return
            if self.path == "/api/candidates":
                _summary, _run, analysis, candidates, freshness = _current_candidate_view(
                    repository, now=datetime.now(tz=timezone.utc)
                )
                self._send(
                    200,
                    _json_bytes(
                        {
                            "analysis_run_id": analysis["analysis_run_id"] if freshness["analysis_caught_up"] else None,
                            "analysis_status": analysis["status"] if freshness["analysis_caught_up"] else "unavailable",
                            "input_snapshot": analysis["input_snapshot"] if freshness["analysis_caught_up"] else {"snapshot_state": "live_view_unavailable"},
                            "candidates": candidates,
                            "freshness": freshness,
                            "scope": "active collector and caught-up analysis only",
                        }
                    ),
                    "application/json; charset=utf-8",
                )
                return
            if self.path == "/api/signatures":
                self._send(200, _json_bytes({"signatures": repository.signature_rows()}), "application/json; charset=utf-8")
                return
            if self.path == "/api/signatures/download":
                self._send(
                    200,
                    _json_bytes({"signatures": repository.signature_rows(), "version": "local-signature-catalog.v1"}),
                    "application/json; charset=utf-8",
                    download_name="local-signature-catalog.json",
                )
                return
            if self.path == "/signatures":
                self._send(200, _signature_page().encode("utf-8"), "text/html; charset=utf-8")
                return
            if self.path != "/":
                self._send(404, b"not found\n", "text/plain; charset=utf-8")
                return
            summary, latest_run, latest_analysis, candidates, freshness = _current_candidate_view(
                repository, now=datetime.now(tz=timezone.utc)
            )
            analysis_degraded = False
            live_status = (
                "Live anomaly view: the active collector has fresh persisted flow data and analysis has caught up."
                if freshness["analysis_caught_up"]
                else "No live anomaly analysis is available. Stored historical analysis is intentionally hidden."
            )
            freshness_html = (
                "<dl><dt>View mode</dt><dd>"
                f"{escape(str(freshness['mode']))}</dd><dt>Newest persisted flow</dt><dd>"
                f"{escape(str(freshness['last_persisted_at'] or 'none'))} ({escape(_age_label(freshness['last_persisted_age_seconds']))})</dd><dt>Analysis refreshed</dt><dd>"
                f"{escape(str(freshness['analysis_completed_at'] or 'none'))} ({escape(_age_label(freshness['analysis_age_seconds']))})</dd><dt>Live-view availability</dt><dd>"
                f"{escape('available' if freshness['analysis_caught_up'] else str(freshness['unavailable_reason']))}</dd></dl>"
                f"<p class='note'>{escape(live_status)}</p>"
            )
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
            if not freshness["analysis_caught_up"]:
                analysis_html = (
                    f"{freshness_html}<p class='note'>The dashboard does not display stored snapshots. "
                    "Start an active collector and wait for its analysis to catch up.</p>"
                )
                analysis_degraded = True
            else:
                analysis_html = (
                    f"{freshness_html}<dl><dt>Status</dt><dd>"
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
            refresh_script = (
                "<script>window.setTimeout(() => window.location.reload(), 2000);</script>"
                if collector_controller.status()["running"]
                else ""
            )
            html = f"""<!doctype html>
<html lang='en'><head><meta charset='utf-8'><title>Network AI Flow POC</title>
<style>body{{font-family:system-ui;margin:2rem;max-width:1100px}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #bbb;padding:.5rem;text-align:left}}.note{{color:#555}}</style>
</head><body><h1>Network AI Flow POC</h1>
<p class='note'>Single-user localhost live anomaly view. Exporter identity is IP-allowlisted but unauthenticated. Candidates require analyst review.</p>
<dl><dt>Live candidates</dt><dd>{escape(str(len(candidates)))}</dd><dt>Live view</dt><dd>{escape(str(freshness['mode']))}</dd></dl>
{_collector_controls()}
<h2>Collection health</h2>{health_html}
<h2>Analysis status</h2>{analysis_html}
<h2>Live analyst candidates</h2><table><thead><tr><th>Rule</th><th>Source</th><th>Endpoint</th><th>Observed evidence</th><th>Window</th><th>Evidence-bound explanation</th></tr></thead><tbody>{candidate_rows}</tbody></table>
<p class='note'><a href='/signatures'>Local signature catalog</a> · JSON: <a href='/api/summary'>summary</a> · <a href='/api/flows'>flows</a> · <a href='/api/candidates'>candidates</a></p>
{refresh_script}
</body></html>"""
            self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            if self.path == "/api/collector":
                try:
                    content_length = int(self.headers.get("Content-Length", "0"))
                    if not 1 <= content_length <= 64 * 1024:
                        raise ValueError("request_size_invalid")
                    payload = json.loads(self.rfile.read(content_length).decode("utf-8"))
                    if not isinstance(payload, dict) or not isinstance(payload.get("action"), str):
                        raise ValueError("request_invalid")
                    if payload["action"] == "start":
                        policy_data = payload.get("policy")
                        if not isinstance(policy_data, dict):
                            raise ValueError("collector_policy_invalid")
                        allowlist = policy_data.get("exporter_allowlist")
                        if not isinstance(allowlist, list) or not 1 <= len(allowlist) <= 16 or not all(isinstance(item, str) for item in allowlist):
                            raise ValueError("collector_policy_invalid")
                        status = collector_controller.start(
                            policy=ListenerPolicy(
                                bind_host=policy_data.get("bind_host"),
                                port=policy_data.get("port"),
                                exporter_allowlist=tuple(allowlist),
                                allow_nonloopback=policy_data.get("allow_nonloopback"),
                                duration_seconds=policy_data.get("duration_seconds"),
                                max_datagrams=policy_data.get("max_datagrams"),
                            )
                        )
                    elif payload["action"] == "stop":
                        status = collector_controller.stop()
                    else:
                        raise ValueError("request_action_invalid")
                    self._send(200, _json_bytes(status), "application/json; charset=utf-8")
                except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
                    self._send(400, _json_bytes({"error": "invalid_collector_request"}), "application/json; charset=utf-8")
                return
            if self.path != "/api/signatures":
                self._send(405, b"method not allowed\n", "text/plain; charset=utf-8")
                return
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
                if not 1 <= content_length <= 512 * 1024:
                    raise ValueError("request_size_invalid")
                payload = json.loads(self.rfile.read(content_length).decode("utf-8"))
                if not isinstance(payload, dict) or not isinstance(payload.get("action"), str):
                    raise ValueError("request_invalid")
                action = payload["action"]
                if action in {"create", "update"}:
                    signature = repository.save_signature(
                        signature_id=payload.get("signature_id"),
                        name=payload.get("name"),
                        severity=payload.get("severity"),
                        rule_text=payload.get("rule_text"),
                        enabled=payload.get("enabled"),
                        require_existing=action == "update",
                    )
                    self._send(201 if action == "create" else 200, _json_bytes({"signature": signature}), "application/json; charset=utf-8")
                    return
                if action == "set_enabled":
                    signature = repository.set_signature_enabled(
                        signature_id=payload.get("signature_id"), enabled=payload.get("enabled")
                    )
                    self._send(200, _json_bytes({"signature": signature}), "application/json; charset=utf-8")
                    return
                if action == "delete":
                    deleted = repository.delete_signature(signature_id=payload.get("signature_id"))
                    if not deleted:
                        raise ValueError("signature_not_found")
                    self._send(200, _json_bytes({"deleted": 1}), "application/json; charset=utf-8")
                    return
                if action == "import":
                    updated = repository.import_signatures(payload.get("signatures"))
                    self._send(200, _json_bytes({"updated": updated}), "application/json; charset=utf-8")
                    return
                raise ValueError("request_action_invalid")
            except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
                self._send(400, _json_bytes({"error": "invalid_signature_request"}), "application/json; charset=utf-8")

        def log_message(self, _format: str, *_args: object) -> None:
            # Avoid writing sensitive flow metadata to process logs.
            return

    class DashboardHTTPServer(ThreadingHTTPServer):
        def server_close(self) -> None:
            collector_controller.shutdown()
            super().server_close()

    server = DashboardHTTPServer((host, port), Handler)
    server.collector_controller = collector_controller
    return server
