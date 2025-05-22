from __future__ import annotations

import calendar
from datetime import datetime, timedelta, timezone, tzinfo
from typing import TYPE_CHECKING, NamedTuple

from dissect.cstruct import cstruct

from dissect.target.exceptions import (
    RegistryError,
    RegistryKeyNotFoundError,
    RegistryValueNotFoundError,
)
from dissect.target.helpers.mui import MUI_TZ_MAP
from dissect.target.plugin import internal
from dissect.target.plugins.os.default.datetime import DateTimePlugin

if TYPE_CHECKING:
    from dissect.target.helpers.regutil import RegistryKey
    from dissect.target.target import Target

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
c_tz = cstruct().load(tz_def)


# Althoug calendar.SUNDAY is only officially documented since Python 3.10, it
# is present in Python 3.9, so we ignore the vermin warnings.
SUNDAY = calendar.SUNDAY  # novermin
SundayFirstCalendar = calendar.Calendar(SUNDAY)


class TimezoneInformation(NamedTuple):
    # The current bias from UTC
    bias: timedelta
    # The additional bias on top of the current bias when in standard time (usually 0)
    standard_bias: timedelta
    # The additional bias on top of the current bias when in daylight saving time (usually -60)
    daylight_bias: timedelta
    # When standard time starts, or in other words, daylight saving ends (see parse_systemtime_transition)
    standard_date: c_tz._SYSTEMTIME
    # When daylight saving starts (see parse_systemtime_transition)
    daylight_date: c_tz._SYSTEMTIME


ZERO = timedelta(0)
HOUR = timedelta(hours=1)


def parse_systemtime_transition(systemtime: c_tz._SYSTEMTIME, year: int) -> datetime:
    """Return the transition datetime for a given year using the SYSTEMTIME of a STD or DST transition date.

    The SYSTEMTIME date of a TZI structure needs to be used to calculate the actual date for a given year.
    The wMonth member indicates the month, the wDayOfWeek member indicates the weekday and the wDay indicates the
    occurance of the day of the week within the month (1 to 5, where 5 indicates the final occurrence during the
    month if that day of the week does not occur 5 times).

    Reference:
        - https://docs.microsoft.com/en-us/windows/win32/api/timezoneapi/ns-timezoneapi-time_zone_information
    """
    if not (1 <= systemtime.wDay <= 5):
        raise ValueError("systemtime.wDay should be between 1 and 5")

    month = SundayFirstCalendar.monthdayscalendar(year, systemtime.wMonth)
    occurrences = [week[systemtime.wDayOfWeek] for week in month if week[systemtime.wDayOfWeek]]
    target_occurrence = -1 if systemtime.wDay == 5 and len(occurrences) < 5 else systemtime.wDay - 1

    return datetime(  # noqa: DTZ001
        year,
        systemtime.wMonth,
        occurrences[target_occurrence],
        systemtime.wHour,
        systemtime.wMinute,
        systemtime.wSecond,
        systemtime.wMilliseconds * 1000,
    )


def parse_dynamic_dst(key: RegistryKey) -> dict[int, TimezoneInformation]:
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
    """Parse binary TZI into a ``TimezoneInformation`` namedtuple."""
    parsed = c_tz.REG_TZI_FORMAT(tzi)
    return TimezoneInformation(
        parsed.Bias,
        parsed.StandardBias,
        parsed.DaylightBias,
        parsed.StandardDate,
        parsed.DaylightDate,
    )


def get_dst_range(tzi: TimezoneInformation, year: int) -> tuple[datetime, datetime]:
    """Get the start and end date of DST for the given year."""
    start = parse_systemtime_transition(tzi.daylight_date, year)
    end = parse_systemtime_transition(tzi.standard_date, year)

    return (start, end)


class WindowsTimezone(tzinfo):
    """A ``datetime.tzinfo`` class representing a timezone from parsed Windows TZI data.

    Mostly inspired by the examples in the Python documentation.
    """

    def __init__(self, name: str, key: RegistryKey):
        self.name = name
        self.display = translate_tz(key, "Display")
        self.dlt_name = translate_tz(key, "Dlt")
        self.std_name = translate_tz(key, "Std")
        self.tzi = parse_tzi(key.value("TZI").value)
        self.dynamic_dst = parse_dynamic_dst(key)

        self.bias = timedelta(minutes=-self.tzi.bias)

    def __repr__(self) -> str:
        return self.display

    def is_dst(self, dt: datetime) -> bool:
        assert dt.tzinfo is self

        tzi = self.dynamic_dst.get(dt.year, self.tzi)
        # If the time zone does not support daylight saving time the wMonth member is zero
        if tzi.daylight_date.wMonth == 0 or tzi.standard_date.wMonth == 0:
            return False

        start, end = get_dst_range(tzi, dt.year)

        # DST is flipped in some regions
        flip = False
        if start > end:
            flip = True
            start, end = end, start

        # Can't compare naive to aware objects, so strip the timezone from dt first
        # Cast to a proper datetime object to avoid issues with subclassed datetime objects
        dt = datetime(  # noqa: DTZ001
            dt.year,
            dt.month,
            dt.day,
            dt.hour,
            dt.minute,
            dt.second,
            dt.microsecond,
            tzinfo=None,
            fold=dt.fold,
        )

        result = False
        if start + HOUR <= dt < end - HOUR:
            # DST is in effect.
            result = True
        elif end - HOUR <= dt < end:
            # Fold (an ambiguous hour): use dt.fold to disambiguate.
            result = not dt.fold
        elif start <= dt < start + HOUR:
            # Gap (a non-existent hour): reverse the fold rule.
            result = bool(dt.fold)
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


class WindowsDateTimePlugin(DateTimePlugin):
    __namespace__ = "datetime"

    def __init__(self, target: Target):
        super().__init__(target)

        tz_name = None

        try:
            timezone_information = self.target.registry.key(
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation"
            )

            try:
                # Windows 7+
                tz_name = timezone_information.value("TimeZoneKeyName").value
            except RegistryValueNotFoundError:
                # < Windows 7 (https://github.com/dateutil/dateutil/issues/210)
                tz_name_localized = timezone_information.value("StandardName").value
                for timezone_key in self.target.registry.key(
                    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones"
                ).subkeys():
                    if tz_name_localized == timezone_key.value("Std").value:
                        tz_name = timezone_key.name
        except RegistryKeyNotFoundError:
            pass

        if tz_name is None:
            self.target.log.warning("Could not determine timezone of target, falling back to UTC for datetime helpers")
            self._tzinfo = timezone.utc
        else:
            self._tzinfo = self.tz(tz_name)

    def check_compatible(self) -> None:
        pass

    @internal
    def tz(self, name: str) -> tzinfo:
        """Return a ``datetime.tzinfo`` of the given timezone name."""
        tz_data = self.target.registry.key(f"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones\\{name}")
        return WindowsTimezone(name, tz_data)

    @internal(property=True)
    def tzinfo(self) -> tzinfo:
        """Return a ``datetime.tzinfo`` of the current system timezone."""
        return self._tzinfo


def translate_tz(key: RegistryKey, name: str) -> str:
    """Translate a timezone resource string to English.

    Non-English distributions of Windows contain a local translation in the "Display", "Dlt" and "Std" keys.
    The ``MUI_*`` keys contain a reference to the English timezone name we want, e.g. "@tzres.dll,-1337".
    """
    try:
        string_id = int(key.value("MUI_" + name).value.replace("@tzres.dll,-", ""))
        if translation := MUI_TZ_MAP.get(string_id):
            return translation
    except (RegistryValueNotFoundError, ValueError):
        pass

    return key.value(name).value
