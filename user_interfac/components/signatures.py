from reactpy import component, html

from .theme import card_style, limitation_note, muted


@component
def sigs():
    return html.div(
        html.h2("Signatures"),
        limitation_note(),
        html.div(
            {**card_style()},
            html.p(
                {"style": muted()},
                "Signature deployment is not authorized. This screen does not generate, promote, or push Suricata rules.",
            ),
        ),
    )
