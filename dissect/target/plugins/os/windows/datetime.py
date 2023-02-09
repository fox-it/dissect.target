import calendar
from collections import namedtuple
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Dict, Tuple

from dissect import cstruct

from dissect.target.exceptions import RegistryError, UnsupportedPluginError
from dissect.target.helpers.regutil import RegistryKey
from dissect.target.plugin import Plugin, internal

tz_def = """
typedef struct _SYSTEMTIME {
    WORD wYear;
    WORD wMonth;
    WORD wDayOfWeek;
    WORD wDay;
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
    WORD wMilliseconds;
} SYSTEMTIME;

typedef struct _REG_TZI_FORMAT {
    LONG Bias;
    LONG StandardBias;
    LONG DaylightBias;
    SYSTEMTIME StandardDate;
    SYSTEMTIME DaylightDate;
} REG_TZI_FORMAT;
"""
c_tz = cstruct.cstruct()
c_tz.load(tz_def)


SundayFirstCalendar = calendar.Calendar(calendar.SUNDAY)
TimezoneInformation = namedtuple(
    "TimezoneInformation",
    (
        # The current bias from UTC
        "bias",
        # The additional bias on top of the current bias when in standard time (usually 0)
        "standard_bias",
        # The additional bias on top of the current bias when in daylight saving time (usually -60)
        "daylight_bias",
        # When standard time starts, or in other words, daylight saving ends (see parse_systemtime_transition)
        "standard_date",
        # When daylight saving starts (see parse_systemtime_transition)
        "daylight_date",
    ),
)


ZERO = timedelta(0)
HOUR = timedelta(hours=1)


def parse_systemtime_transition(systemtime: cstruct.Instance, year: int) -> datetime:
    """Return the transition datetime for a given year using the SYSTEMTIME of a STD or DST transition date.

    The SYSTEMTIME date of a TZI structure needs to be used to calculate the actual date for a given year.
    The wMonth member indicates the month, the wDayOfWeek member indicates the weekday and the wDay indicates the
    occurance of the day of the week within the month (1 to 5, where 5 indicates the final occurrence during the
    month if that day of the week does not occur 5 times).

    Reference:
        - https://docs.microsoft.com/en-us/windows/win32/api/timezoneapi/ns-timezoneapi-time_zone_information
    """
    month = SundayFirstCalendar.monthdayscalendar(year, systemtime.wMonth)
    occurrences = [week[systemtime.wDayOfWeek] for week in month if week[systemtime.wDayOfWeek]]
    target_occurrence = -1 if systemtime.wDay == 5 and len(occurrences) < 5 else systemtime.wDay - 1

    return datetime(
        year,
        systemtime.wMonth,
        occurrences[target_occurrence],
        systemtime.wHour,
        systemtime.wMinute,
        systemtime.wSecond,
        systemtime.wMilliseconds * 1000,
    )


def parse_dynamic_dst(key: RegistryKey) -> Dict[int, TimezoneInformation]:
    """Parse dynamic DST information from a given TimeZoneInformation registry key.

    If a timezone has dynamic DST information, there's a "Dynamic DST" subkey with values for each year.
    The FirstEntry and LastEntry contain the first and last year respectively. The TZI structure is the same as the
    main TimeZoneInformation TZI.
    """
    result = {}
    try:
        dynamic_key = key.subkey("Dynamic DST")
        first = int(dynamic_key.value("FirstEntry").value)
        last = int(dynamic_key.value("LastEntry").value)

        for year in range(first, last + 1):
            result[year] = parse_tzi(dynamic_key.value(str(year)).value)
    except RegistryError:
        pass

    return result


def parse_tzi(tzi: bytes) -> TimezoneInformation:
    """Parse binary TZI into a TimezoneInformation namedtuple."""
    parsed = c_tz.REG_TZI_FORMAT(tzi)
    return TimezoneInformation(
        parsed.Bias,
        parsed.StandardBias,
        parsed.DaylightBias,
        parsed.StandardDate,
        parsed.DaylightDate,
    )


def get_dst_range(tzi: TimezoneInformation, year: int) -> Tuple[datetime, datetime]:
    """Get the start and end date of DST for the given year."""
    start = parse_systemtime_transition(tzi.daylight_date, year)
    end = parse_systemtime_transition(tzi.standard_date, year)

    return (start, end)


class WindowsTimezone(tzinfo):
    """A datetime.tzinfo class representing a timezone from parsed Windows TZI data.

    Mostly inspired by the examples in the Python documentation.
    """

    def __init__(self, name: str, key: RegistryKey):
        self.name = name
        self.display = key.value("Display").value
        self.dlt_name = key.value("Dlt").value
        self.std_name = key.value("Std").value
        self.tzi = parse_tzi(key.value("TZI").value)
        self.dynamic_dst = parse_dynamic_dst(key)

        self.bias = timedelta(minutes=-self.tzi.bias)

    def __repr__(self) -> str:
        return self.display

    def is_dst(self, dt: datetime) -> bool:
        assert dt.tzinfo is self

        tzi = self.dynamic_dst.get(dt.year, self.tzi)
        start, end = get_dst_range(tzi, dt.year)

        # DST is flipped in some regions
        flip = False
        if start > end:
            flip = True
            start, end = end, start

        # Can't compare naive to aware objects, so strip the timezone from
        # dt first.
        dt = dt.replace(tzinfo=None)

        result = False
        if start + HOUR <= dt < end - HOUR:
            # DST is in effect.
            result = True
        elif end - HOUR <= dt < end:
            # Fold (an ambiguous hour): use dt.fold to disambiguate.
            result = False if dt.fold else True
        elif start <= dt < start + HOUR:
            # Gap (a non-existent hour): reverse the fold rule.
            result = True if dt.fold else False
        else:
            # DST is off.
            result = False

        return not result if flip else result

    def utcoffset(self, dt: datetime) -> int:
        # Windows timezones use a default bias and a separate additional bias when in STD or DST
        return self.bias + self.dst(dt)

    def dst(self, dt: datetime) -> timedelta:
        tzi = self.dynamic_dst.get(dt.year, self.tzi)
        std_bias = timedelta(minutes=-tzi.standard_bias)
        dst_bias = timedelta(minutes=-tzi.daylight_bias)

        return dst_bias if self.is_dst(dt) else std_bias

    def tzname(self, dt: datetime) -> str:
        return self.dlt_name if self.is_dst(dt) else self.std_name


class DateTimePlugin(Plugin):
    __namespace__ = "datetime"

    def __init__(self, target):
        super().__init__(target)

        tz_info_key = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation"

        try:
            tz_name = self.target.registry.key(tz_info_key).value("TimeZoneKeyName").value
            self._tzinfo = self.tz(tz_name)
        except RegistryError:
            self.target.log.error("Failed to load timezone information")
            self._tzinfo = None

    def check_compatible(self):
        if not self._tzinfo:
            raise UnsupportedPluginError("No time zone information")

    @internal
    def tz(self, name: str) -> tzinfo:
        """Return a datetime.tzinfo of the given timezone name."""
        tz_data_key = "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones"
        tz_data = self.target.registry.key("\\".join([tz_data_key, name]))
        return WindowsTimezone(name, tz_data)

    @internal(property=True)
    def tzinfo(self) -> tzinfo:
        """Return a datetime.tzinfo of the current system timezone."""
        return self._tzinfo

    @internal
    def local(self, dt: datetime) -> datetime:
        """Replace the tzinfo of a given datetime.datetime object with the current system tzinfo without conversion."""
        return dt.replace(tzinfo=self._tzinfo)

    @internal
    def to_utc(self, dt: datetime) -> datetime:
        """Convert any datetime.datetime object into a UTC datetime.datetime object.

        First replaces the current tzinfo with the system tzinfo without conversion, then converts it to an aware
        UTC datetime object.
        """
        return self.local(dt).astimezone(timezone.utc)
