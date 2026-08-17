from reactpy import component, html

from .theme import card_style, limitation_note, muted


@component
def mail():
    return html.div(
        html.h2("Mail"),
        limitation_note(),
        html.div(
            {**card_style()},
            html.p({"style": muted()}, "Mail inspection is not implemented and not authorized in this release."),
            html.p({"style": muted()}, "No SMTP, IMAP, or attachment reader is queried."),
        ),
    )
