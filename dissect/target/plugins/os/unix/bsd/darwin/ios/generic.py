from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.util import ts

from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.generic import calculate_last_activity

if TYPE_CHECKING:
    from datetime import datetime


class GenericPlugin(Plugin):
    """Generic plugin for iOS targets."""

    def check_compatible(self) -> None:
        pass

    @export(property=True)
    def activity(self) -> datetime | None:
        """Return last seen activity based on filesystem timestamps."""

        return calculate_last_activity(self.target.fs.path("/private/var/log"), recursive=True)

    @export(property=True)
    def install_date(self) -> datetime | None:
        """Return the likely install date of the operating system."""

        # prng.seed seems to be created when iOS is first installed and not touched afterwards,
        # this is an educated guess without any further research.
        for path in ["/private/var/db/prng.seed"]:
            if (file := self.target.fs.path(path)).exists():
                return ts.from_unix(file.lstat().st_mtime)
        return None
