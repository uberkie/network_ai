from reactpy import component, html
from reactpy_django.hooks import use_query

from .queries import analyst_snapshot
from .theme import banner, card_style, limitation_note, loading_panel, muted


@component
def probes():
    query = use_query(analyst_snapshot, postprocessor=None)
    if query.loading and query.data is None:
        return html.div(html.h2("Sensors"), loading_panel())
    snapshot = query.data or {}
    sensors = snapshot.get("sensors") or {}
    cards = []
    for name in ("suricata", "zeek", "mikrotik", "flow"):
        details = sensors.get(name) or {}
        cards.append(
            html.div(
                {**card_style()},
                html.h3(name),
                html.ul(
                    {"style": muted()},
                    [html.li(f"{key}: {value}") for key, value in sorted(details.items())],
                ),
            )
        )
    return html.div(
        html.h2("Sensors"),
        limitation_note(),
        banner(snapshot, query.error),
        html.p(
            {"style": muted()},
            "Process observation is host health only. It does not authorize log tailing, "
            "RouterOS access, or a live collector.",
        ),
        html.div(
            {
                "style": {
                    "display": "grid",
                    "gridTemplateColumns": "repeat(auto-fit, minmax(240px, 1fr))",
                    "gap": "0.85rem",
                }
            },
            *cards,
        ),
    )
