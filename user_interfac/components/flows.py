from reactpy import component, html
from reactpy_django.hooks import use_query

from .queries import analyst_snapshot
from .theme import banner, card_style, limitation_note, loading_panel, muted, table


@component
def flows():
    query = use_query(analyst_snapshot, postprocessor=None)
    if query.loading and query.data is None:
        return html.div(html.h2("Flows"), loading_panel())
    snapshot = query.data or {}
    flow = snapshot.get("flows") or {}
    if not flow.get("available"):
        return html.div(
            html.h2("Flows"),
            limitation_note(),
            banner(snapshot, query.error),
            html.div(
                {**card_style()},
                html.p({"style": muted()}, "No local flow store is present at the configured read-only path."),
                html.p(
                    {"style": muted()},
                    "This screen queries an already-persisted NetFlow/IPFIX repository only. "
                    "It does not start a collector or change a router.",
                ),
            ),
        )
    return html.div(
        html.h2("Flows"),
        limitation_note(),
        banner(snapshot, query.error),
        html.p({"style": muted()}, f"Persisted flow rows: {flow.get('flow_count', 0)}"),
        html.h3("Recent persisted flows"),
        table(
            ("Time", "Source", "Destination", "Protocol", "Bytes", "Packets", "Flow ID"),
            [
                (
                    row.get("event_time"),
                    f"{row.get('source_ip')}:{row.get('source_port')}",
                    f"{row.get('destination_ip')}:{row.get('destination_port')}",
                    row.get("protocol"),
                    row.get("byte_count"),
                    row.get("packet_count"),
                    row.get("flow_id"),
                )
                for row in flow.get("rows") or []
            ],
        ),
        html.h3("Stored analyst candidates"),
        table(
            ("Created", "Rule", "Source", "Destination", "Observed", "Explanation"),
            [
                (
                    row.get("created_at"),
                    row.get("rule_id"),
                    row.get("source_ip"),
                    f"{row.get('destination_ip')}:{row.get('destination_port')}",
                    row.get("observed_value"),
                    row.get("explanation"),
                )
                for row in flow.get("candidates") or []
            ],
        ),
    )
