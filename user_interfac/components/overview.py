from reactpy import component, html
from reactpy_django.hooks import use_query

from .queries import analyst_snapshot
from .theme import banner, card_style, limitation_note, loading_panel, metric, muted, table


@component
def overview():
    query = use_query(analyst_snapshot, postprocessor=None)
    if query.loading and query.data is None:
        return html.div(html.h2("Overview"), loading_panel())
    snapshot = query.data or {}
    overview_data = snapshot.get("overview") or {}
    sensors = snapshot.get("sensors") or {}
    store = snapshot.get("store") or {}
    return html.div(
        html.h2("Overview"),
        limitation_note(),
        banner(snapshot, query.error),
        html.div(
            {
                "style": {
                    "display": "grid",
                    "gridTemplateColumns": "repeat(auto-fit, minmax(160px, 1fr))",
                    "gap": "0.85rem",
                    "margin": "1rem 0",
                }
            },
            metric("Accepted evidence", overview_data.get("accepted_count", 0)),
            metric("Quarantined", overview_data.get("quarantined_count", 0)),
            metric("Ledger", store.get("ledger_id") or "unavailable"),
            metric("Suricata process", (sensors.get("suricata") or {}).get("process")),
            metric("Zeek process", (sensors.get("zeek") or {}).get("process")),
            metric("Flow store", (sensors.get("flow") or {}).get("store")),
        ),
        html.div(
            {
                "style": {
                    "display": "grid",
                    "gridTemplateColumns": "repeat(auto-fit, minmax(240px, 1fr))",
                    "gap": "0.85rem",
                    "marginBottom": "1rem",
                }
            },
            html.div(
                {**card_style()},
                html.h3("Sources"),
                html.pre({"style": muted()}, str(overview_data.get("source_counts") or {})),
            ),
            html.div(
                {**card_style()},
                html.h3("Alert severity"),
                html.pre({"style": muted()}, str(overview_data.get("alerts_by_severity") or {})),
            ),
            html.div(
                {**card_style()},
                html.h3("Traffic correlation outcomes"),
                html.pre({"style": muted()}, str(overview_data.get("correlation_outcomes") or {})),
            ),
        ),
        html.h3("Top sources"),
        table(
            ("Source IP", "Count"),
            [(item.get("value"), item.get("count")) for item in overview_data.get("top_sources") or []],
        ),
        html.h3("Top destinations"),
        table(
            ("Destination IP", "Count"),
            [(item.get("value"), item.get("count")) for item in overview_data.get("top_destinations") or []],
        ),
        html.h3("Top protocols"),
        table(
            ("Protocol", "Count"),
            [(item.get("value"), item.get("count")) for item in overview_data.get("top_protocols") or []],
        ),
    )


home = overview
