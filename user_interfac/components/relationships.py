from reactpy import component, html
from reactpy_django.hooks import use_query

from .queries import analyst_snapshot
from .theme import banner, card_style, limitation_note, loading_panel, muted, table


@component
def relation():
    query = use_query(analyst_snapshot, postprocessor=None)
    if query.loading and query.data is None:
        return html.div(html.h2("Relationships"), loading_panel())
    snapshot = query.data or {}
    rows = snapshot.get("correlations") or []
    return html.div(
        html.h2("Relationships"),
        limitation_note(),
        banner(snapshot, query.error),
        html.div(
            {**card_style(), "marginBottom": "1rem"},
            html.p(
                {"style": muted()},
                "Traffic and session outcomes are separate. A probable match means only that supplied evidence "
                "shared an exact five-tuple/time window or a declared session IP/time binding. "
                "It is not packet identity, subscriber ownership, or causation.",
            ),
        ),
        table(
            (
                "Traffic outcome",
                "Session outcome",
                "Anchor evidence",
                "Zeek candidates",
                "Session evidence",
                "Traffic rationale",
            ),
            [
                (
                    row.get("traffic_outcome"),
                    row.get("session_outcome"),
                    row.get("anchor_evidence_id"),
                    ", ".join(row.get("traffic_candidate_ids") or []),
                    ", ".join(row.get("session_evidence_ids") or []),
                    row.get("traffic_rationale"),
                )
                for row in rows
            ],
        ),
    )
