from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.util import ts

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from datetime import datetime


class GenericPlugin(Plugin):
    """Generic Citrix plugin."""

    def check_compatible(self) -> None:
        if self.target.os != "citrix-netscaler":
            raise UnsupportedPluginError("Citrix Netscaler specific plugin loaded on non-Citrix target")

    @export(property=True)
    def install_date(self) -> datetime | None:
        """Return the likely install date of Citrix Netscaler."""
        entries = ["/flash/.version", "/flash", "/var"]
        for entry in entries:
            if (path := self.target.fs.path(entry)).exists():
                # Prioritize birth time if available
                stat = path.stat()
                return ts.from_unix(stat.st_birthtime or stat.st_ctime)
        return None
