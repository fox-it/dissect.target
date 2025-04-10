from __future__ import annotations

import re
from datetime import datetime
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import export
from dissect.target.plugins.apps.remoteaccess.remoteaccess import (
    GENERIC_LOG_RECORD_FIELDS,
    RemoteAccessPlugin,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.plugins.general.users import UserDetails
    from dissect.target.target import Target


RE_LOG = re.compile(
    r"""
        ^
        (?P<date>(\d{2,4}\/)?\d{2}\/\d{2})                  # YYYY/MM/DD or YY/MM/DD or MM/DD
        \s
        (?P<time>\d{2}\:\d{2}\:\d{2}(?:[\.\:]\d{3})?)       # HH:MM:SS or HH:MM:SS.FFF or HH:MM:SS:FFF
        \s+
        (?P<message>.+)
        $
    """,
    re.VERBOSE,
)
RE_START = re.compile(
    r"""
        ^Start\:
        \s+
        (?P<date>\S+)
        \s
        (?P<time>\S+)
        (
            \s
            \((?P<timezone>\S+)\)                           # UTC+2:00
        )?
        $
    """,
    re.VERBOSE,
)


class TeamViewerPlugin(RemoteAccessPlugin):
    """TeamViewer client plugin.

    Resources:
        - https://teamviewer.com/en/global/support/knowledge-base/teamviewer-classic/contact-support/find-your-log-files
        - https://www.systoolsgroup.com/forensics/teamviewer/
        - https://benleeyr.wordpress.com/2020/05/19/teamviewer-forensics-tested-on-v15/
    """

    __namespace__ = "teamviewer"

    SYSTEM_GLOBS = (
        "sysvol/Program Files/TeamViewer/*.log",
        "sysvol/Program Files (x86)/TeamViewer/*.log",
        "/var/log/teamviewer*/*.log",
    )

    USER_GLOBS = (
        "AppData/Roaming/TeamViewer/teamviewer*_logfile.log",
        "Library/Logs/TeamViewer/teamviewer*_logfile*.log",
    )

    RemoteAccessLogRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "remoteaccess/teamviewer/log", GENERIC_LOG_RECORD_FIELDS
    )

    def __init__(self, target: Target):
        super().__init__(target)

        self.logfiles: set[tuple[str, UserDetails | None]] = set()

        # Find system service log files.
        for log_glob in self.SYSTEM_GLOBS:
            for logfile in self.target.fs.glob(log_glob):
                self.logfiles.add((logfile, None))

        # Find user log files.
        for user_details in self.target.user_details.all_with_home():
            for log_glob in self.USER_GLOBS:
                for logfile in user_details.home_path.glob(log_glob):
                    self.logfiles.add((logfile, user_details))

    def check_compatible(self) -> None:
        if not len(self.logfiles):
            raise UnsupportedPluginError("No Teamviewer logs found on target")

    @export(record=RemoteAccessLogRecord)
    def logs(self) -> Iterator[RemoteAccessLogRecord]:
        """Yield TeamViewer client logs.

        TeamViewer is a commercial remote desktop application. An adversary may use it to gain persistence on a system.
        """
        target_tz = self.target.datetime.tzinfo

        for logfile, user_details in self.logfiles:
            logfile = self.target.fs.path(logfile)

            start_date = None
            for line in logfile.open("rt", errors="replace"):
                if not (line := line.strip()) or line.startswith("# "):
                    continue

                if line.startswith("Start:"):
                    try:
                        start_date = parse_start(line)
                    except Exception as e:
                        self.target.log.warning("Failed to parse Start message %r in %s", line, logfile)
                        self.target.log.debug("", exc_info=e)

                    continue

                if not (match := RE_LOG.search(line)):
                    self.target.log.warning("Skipping TeamViewer log line %r in %s", line, logfile)
                    continue

                log = match.groupdict()
                date = log["date"]
                time = log["time"]

                # Older TeamViewer versions first mention the start time and then leave out the year,
                # so we have to correct for the missing year in date.
                if date.count("/") == 1:
                    if not start_date:
                        self.target.log.warning("Missing year in log line, skipping line %r in %s", line, logfile)
                        continue
                    date = f"{start_date.year}/{log['date']}"

                # Correct for year if short notation for 2000 is used
                if date.count("/") == 2 and len(date.split("/")[0]) == 2:
                    date = "20" + date

                # Correct for ``:`` separator of milliseconds
                if time.count(":") == 3:
                    hms, _, ms = time.rpartition(":")
                    time = f"{hms}.{ms}"

                # Convert milliseconds to microseconds
                if "." in time:
                    hms, _, ms = time.rpartition(".")
                    time = f"{hms}.{ms:0<6}"
                else:
                    time += ".000000"

                try:
                    timestamp = datetime.strptime(f"{date} {time}", "%Y/%m/%d %H:%M:%S.%f").replace(
                        tzinfo=start_date.tzinfo if start_date else target_tz
                    )
                except Exception as e:
                    self.target.log.warning("Unable to parse timestamp %r in file %s", line, logfile)
                    self.target.log.debug("", exc_info=e)
                    timestamp = 0

                yield self.RemoteAccessLogRecord(
                    ts=timestamp,
                    message=log.get("message"),
                    source=logfile,
                    _target=self.target,
                    _user=user_details.user if user_details else None,
                )


def parse_start(line: str) -> datetime | None:
    """TeamViewer ``Start`` messages can be formatted in different ways
    and might contain the timezone offset of all timestamps.

    .. code-block::

        Start: 2021/11/11 12:34:56
        Start: 2024/12/31 01:02:03.123 (UTC+2:00)
    """

    if match := RE_START.search(line):
        dt = match.groupdict()

        # Drop milliseconds
        if "." in dt["time"]:
            dt["time"] = dt["time"].rsplit(".")[0]

        # Format timezone, e.g. "UTC+2:00" to "UTC+0200"
        if dt["timezone"]:
            name, operator, amount = re.split(r"(\+|\-)", dt["timezone"])
            amount = int(amount.replace(":", ""))
            dt["timezone"] = f"{name}{operator}{amount:0>4d}"

        return datetime.strptime(  # noqa: DTZ007
            f"{dt['date']} {dt['time']}" + (f" {dt['timezone']}" if dt["timezone"] else ""),
            "%Y/%m/%d %H:%M:%S" + (" %Z%z" if dt["timezone"] else ""),
        )
    return None
