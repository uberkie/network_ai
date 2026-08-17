from typing import Any

from reactpy import component

from .theme import application


@component
def app() -> Any:
    return application()