from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.helpers.record import EmptyRecord
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


class LocalePlugin(Plugin):
    """Default locale plugin."""

    def check_compatible(self) -> None:
        pass

    @export(property=True)
    def timezone(self) -> str | None:
        """Get the timezone of the system."""
        return None

    @export(property=True)
    def language(self) -> list[str]:
        """Get the configured locale(s) of the system."""
        return []

    @export(record=EmptyRecord)
    def keyboard(self) -> Iterator[EmptyRecord]:
        """Get the keyboard layout(s) of the system."""
        yield from []
