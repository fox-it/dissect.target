from datetime import datetime, timezone, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from dissect.target.plugin import Plugin, internal
from dissect.target.target import Target


class DateTimePlugin(Plugin):
    __namespace__ = "datetime"

    def __init__(self, target: Target):
        super().__init__(target)
        self.timezone = target.timezone
        if not self.timezone:
            self.target.log.warning("Could not determine timezone of target, falling back to UTC for datetime helpers.")

    def check_compatible(self) -> None:
        pass

    @internal
    def tz(self, name: str) -> tzinfo:
        return ZoneInfo(name)

    @internal(property=True)
    def tzinfo(self) -> tzinfo:
        """Return a datetime.tzinfo of the current system timezone."""
        try:
            return self.tz(self.timezone)
        except (TypeError, ZoneInfoNotFoundError):
            return timezone.utc

    @internal
    def local(self, dt: datetime) -> datetime:
        """Replace the tzinfo of a given datetime.datetime object with the current system tzinfo without conversion."""
        return dt.replace(tzinfo=self.tzinfo)

    @internal
    def to_utc(self, dt: datetime) -> datetime:
        """Convert any datetime.datetime object into a UTC datetime.datetime object.

        First replaces the current tzinfo with the system tzinfo without conversion, then converts it to an aware
        UTC datetime object.
        """
        return self.local(dt).astimezone(timezone.utc)
