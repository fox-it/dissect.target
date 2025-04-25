from __future__ import annotations

from datetime import timezone, tzinfo
from typing import TYPE_CHECKING
from zoneinfo import ZoneInfoNotFoundError

from dissect.target.plugin import internal
from dissect.target.plugins.os.default.datetime import DateTimePlugin

if TYPE_CHECKING:
    from dissect.target.target import Target


class UnixDateTimePlugin(DateTimePlugin):
    __namespace__ = "datetime"

    def __init__(self, target: Target):
        super().__init__(target)

        try:
            self._tzinfo = self.tz(target.timezone)
        except (TypeError, ZoneInfoNotFoundError):
            self.target.log.warning("Could not determine timezone of target, falling back to UTC for datetime helpers")
            self._tzinfo = timezone.utc

    def check_compatible(self) -> None:
        pass

    @internal(property=True)
    def tzinfo(self) -> tzinfo:
        """Return a ``datetime.tzinfo`` of the current system timezone."""
        return self._tzinfo
