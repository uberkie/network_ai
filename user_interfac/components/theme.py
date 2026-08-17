"""Shared Kibana-style layout for the read-only analyst UI."""

from __future__ import annotations

from typing import Any

from reactpy import component, html
from reactpy_django.router import django_router
from reactpy_router import link, route


NAV_ITEMS = (
    ("/", "Overview"),
    ("/discover", "Discover"),
    ("/relationships", "Relationships"),
    ("/flows", "Flows"),
    ("/sensors", "Sensors"),
    ("/mail", "Mail"),
    ("/signatures", "Signatures"),
)

COLORS = {
    "bg": "#0b1017",
    "panel": "#151b24",
    "sidebar": "#111722",
    "border": "#243041",
    "text": "#d5dde8",
    "muted": "#8b97a8",
    "accent": "#36a2ef",
    "accent_soft": "#16324a",
    "warn": "#d99a2b",
    "danger": "#d4534c",
    "ok": "#3fa36a",
}


def page_style() -> dict[str, str]:
    return {
        "minHeight": "100vh",
        "margin": "0",
        "background": COLORS["bg"],
        "color": COLORS["text"],
        "fontFamily": "Inter, Segoe UI, system-ui, sans-serif",
        "display": "grid",
        "gridTemplateColumns": "220px 1fr",
    }


def sidebar_style() -> dict[str, str]:
    return {
        "background": COLORS["sidebar"],
        "borderRight": f"1px solid {COLORS['border']}",
        "padding": "1.25rem 0.85rem",
        "display": "flex",
        "flexDirection": "column",
        "gap": "0.35rem",
    }


def content_style() -> dict[str, str]:
    return {"padding": "1.25rem 1.5rem 2rem", "overflow": "auto"}


def card_style() -> dict[str, str]:
    return {
        "background": COLORS["panel"],
        "border": f"1px solid {COLORS['border']}",
        "borderRadius": "10px",
        "padding": "1rem",
    }


def muted() -> dict[str, str]:
    return {"color": COLORS["muted"], "fontSize": "0.85rem", "lineHeight": "1.45"}


def nav_link(href: str, label: str) -> Any:
    return link(
        {
            "to": href,
            "style": {
                "display": "block",
                "padding": "0.55rem 0.75rem",
                "borderRadius": "8px",
                "color": COLORS["text"],
                "textDecoration": "none",
                "fontSize": "0.92rem",
            },
        },
        label,
    )


def banner(snapshot: dict[str, Any] | None, error: Exception | None) -> Any:
    problems = list((snapshot or {}).get("problems") or [])
    if error is not None:
        problems.insert(0, f"query_failed:{error}")
    if not problems:
        return None
    return html.div(
        {
            "style": {
                **card_style(),
                "borderColor": COLORS["warn"],
                "marginBottom": "1rem",
                "color": COLORS["warn"],
            }
        },
        html.strong("Visible limitations / problems"),
        html.ul([html.li(str(item)) for item in problems]),
    )


def limitation_note() -> Any:
    return html.p(
        {"style": muted()},
        "Read-only analyst view. Live Suricata, Zeek, and MikroTik readers are not authorized. "
        "This UI queries already-persisted evidence, derived correlations, process health, and a local flow store if present. "
        "A correlation is evidence linkage, not identity, causation, or compromise.",
    )


def loading_panel() -> Any:
    return html.div({**card_style(), "color": COLORS["muted"]}, "Loading local analyst snapshot...")


def empty_panel(message: str) -> Any:
    return html.div({**card_style(), "color": COLORS["muted"]}, message)


def metric(label: str, value: Any) -> Any:
    return html.div(
        {**card_style()},
        html.div({"style": {**muted(), "textTransform": "uppercase", "letterSpacing": "0.04em"}}, label),
        html.div({"style": {"fontSize": "1.6rem", "marginTop": "0.35rem", "fontWeight": "650"}}, str(value)),
    )


def table(headers: tuple[str, ...], rows: list[tuple[Any, ...]]) -> Any:
    if not rows:
        return empty_panel("No matching rows in the current read-only snapshot.")
    return html.div(
        {"style": {"overflowX": "auto", **card_style(), "padding": "0"}},
        html.table(
            {
                "style": {
                    "width": "100%",
                    "borderCollapse": "collapse",
                    "fontSize": "0.86rem",
                }
            },
            html.thead(
                html.tr(
                    [
                        html.th(
                            {
                                "style": {
                                    "textAlign": "left",
                                    "padding": "0.7rem 0.75rem",
                                    "borderBottom": f"1px solid {COLORS['border']}",
                                    "color": COLORS["muted"],
                                    "fontWeight": "600",
                                }
                            },
                            header,
                        )
                        for header in headers
                    ]
                )
            ),
            html.tbody(
                [
                    html.tr(
                        [
                            html.td(
                                {
                                    "style": {
                                        "padding": "0.65rem 0.75rem",
                                        "borderBottom": f"1px solid {COLORS['border']}",
                                        "verticalAlign": "top",
                                        "maxWidth": "22rem",
                                        "wordBreak": "break-word",
                                    }
                                },
                                "" if cell is None else str(cell),
                            )
                            for cell in row
                        ]
                    )
                    for row in rows
                ]
            ),
        ),
    )


@component
def shell(child: Any) -> Any:
    return html.div(
        {"style": page_style()},
        html.aside(
            {"style": sidebar_style()},
            html.div(
                {"style": {"padding": "0 0.75rem 1rem"}},
                html.h1({"style": {"fontSize": "1.05rem", "margin": "0 0 0.25rem"}}, "Network AI"),
                html.div({"style": muted()}, "Suricata + Zeek + MikroTik"),
            ),
            *[nav_link(href, label) for href, label in NAV_ITEMS],
        ),
        html.main({"style": content_style()}, child),
    )


@component
def application() -> Any:
    from .discover import discover
    from .flows import flows
    from .mail import mail
    from .overview import overview
    from .probes import probes
    from .relationships import relation
    from .signatures import sigs

    return django_router(
        route("/", shell(overview())),
        route("/discover", shell(discover())),
        route("/relationships", shell(relation())),
        route("/flows", shell(flows())),
        route("/sensors", shell(probes())),
        route("/mail", shell(mail())),
        route("/signatures", shell(sigs())),
        route("*", shell(html.h2("404 - Page not found"))),
    )
