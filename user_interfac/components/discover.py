from reactpy import component, event, html, use_state
from reactpy_django.hooks import use_query

from .queries import discover_rows
from .theme import banner, card_style, limitation_note, loading_panel, muted, table


@component
def discover():
    source, set_source = use_state("")
    protocol, set_protocol = use_state("")
    text, set_text = use_state("")
    query = use_query(
        discover_rows,
        {"source": source, "protocol": protocol, "text": text},
        postprocessor=None,
    )
    snapshot = query.data or {}
    rows = snapshot.get("evidence") or []

    @event(prevent_default=True)
    def refresh(_event):
        query.refetch()

    return html.div(
        html.h2("Discover"),
        limitation_note(),
        banner(snapshot, query.error),
        html.form(
            {
                "on_submit": refresh,
                "style": {
                    **card_style(),
                    "display": "grid",
                    "gridTemplateColumns": "repeat(auto-fit, minmax(180px, 1fr))",
                    "gap": "0.75rem",
                    "marginBottom": "1rem",
                },
            },
            html.label(
                "Source",
                html.select(
                    {
                        "value": source,
                        "on_change": lambda event: set_source(event["target"]["value"]),
                        "style": {"width": "100%", "marginTop": "0.3rem"},
                    },
                    html.option({"value": ""}, "all"),
                    html.option({"value": "suricata"}, "suricata"),
                    html.option({"value": "zeek"}, "zeek"),
                    html.option({"value": "mikrotik"}, "mikrotik"),
                ),
            ),
            html.label(
                "Protocol",
                html.input(
                    {
                        "value": protocol,
                        "placeholder": "TCP",
                        "on_change": lambda event: set_protocol(event["target"]["value"]),
                        "style": {"width": "100%", "marginTop": "0.3rem"},
                    }
                ),
            ),
            html.label(
                "Free-text filter",
                html.input(
                    {
                        "value": text,
                        "placeholder": "evidence id, signature, IP",
                        "on_change": lambda event: set_text(event["target"]["value"]),
                        "style": {"width": "100%", "marginTop": "0.3rem"},
                    }
                ),
            ),
            html.button({"type": "submit", "style": {"alignSelf": "end"}}, "Apply / refresh"),
        ),
        html.p(
            {"style": muted()},
            f"{len(rows)} projected rows from the current ledger snapshot.",
        ),

        loading_panel() if query.loading and query.data is None else html.div(
            {
                "style": {
                    "overflowX": "auto",
                    **card_style(),
                }
            },

            html.div(
                {
                    "style": {
                        "display": "grid",
                        "gridTemplateColumns": (
                            "170px 100px 130px 150px 120px minmax(280px, 1fr) 260px"
                        ),
                        "gap": "0.75rem",
                        "padding": "0.65rem",
                        "fontWeight": "600",
                        "borderBottom": "1px solid #303846",
                        "maxWidth": "800px",
                    }
                },
                html.div("Time"),
                html.div("Source"),
                html.div("Outcome"),
                html.div("Reason"),
                html.div("Network"),
                html.div("Summary"),
                html.div("Evidence ID"),
            ),

            *[
                html.div(
                    {
                        "key": row.get("evidence_id") or str(index),
                        "style": {
                            "display": "grid",
                            "gridTemplateColumns": (
                                "170px 100px 130px 150px 120px minmax(280px, 1fr) 260px"
                            ),
                            "gap": "0.75rem",
                            "padding": "0.65rem",
                            "borderBottom": "1px solid #202833",
                            "alignItems": "center",
                            "minWidth": "800px",
                        },
                    },

                    html.div(row.get("event_time") or "-"),
                    html.div(row.get("source") or "-"),
                    html.div(row.get("outcome") or "-"),
                    html.div(row.get("reason_code") or "-"),
                    html.div(_network_label(row.get("network"))),
                    html.div(row.get("summary") or "-"),
                    html.div(row.get("evidence_id") or "-"),
                )
                for index, row in enumerate(rows)
            ],
        ))











def _network_label(network):
    if not isinstance(network, dict):
        return ""
    source = network.get("source_ip", "")
    destination = network.get("destination_ip", "")
    protocol = network.get("protocol", "")
    source_port = network.get("source_port")
    destination_port = network.get("destination_port")
    left = f"{source}:{source_port}" if source_port else source
    right = f"{destination}:{destination_port}" if destination_port else destination
    return " ".join(part for part in (protocol, left, "->", right) if part)
