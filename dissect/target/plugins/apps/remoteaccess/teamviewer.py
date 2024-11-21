import re
from datetime import datetime, timezone
from typing import Iterator

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import export
from dissect.target.plugins.apps.remoteaccess.remoteaccess import (
    GENERIC_LOG_RECORD_FIELDS,
    RemoteAccessPlugin,
)
from dissect.target.plugins.general.users import UserDetails

START_PATTERN = re.compile(r"^(\d{2}|\d{4})/")


class TeamViewerPlugin(RemoteAccessPlugin):
    """TeamViewer client plugin.

    Resources:
        - https://teamviewer.com/en/global/support/knowledge-base/teamviewer-classic/contact-support/find-your-log-files
        - https://www.systoolsgroup.com/forensics/teamviewer/
        - https://benleeyr.wordpress.com/2020/05/19/teamviewer-forensics-tested-on-v15/
    """

    __namespace__ = "teamviewer"

    SYSTEM_GLOBS = [
        "sysvol/Program Files/TeamViewer/*.log",
        "sysvol/Program Files (x86)/TeamViewer/*.log",
        "/var/log/teamviewer*/*.log",
    ]

    USER_GLOBS = [
        "AppData/Roaming/TeamViewer/teamviewer*_logfile.log",
        "Library/Logs/TeamViewer/teamviewer*_logfile*.log",
    ]

    RemoteAccessLogRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "remoteaccess/teamviewer/log", GENERIC_LOG_RECORD_FIELDS
    )

    def __init__(self, target):
        super().__init__(target)

        self.logfiles: list[list[TargetPath, UserDetails]] = []

        # Find system service log files.
        for log_glob in self.SYSTEM_GLOBS:
            for logfile in self.target.fs.glob(log_glob):
                self.logfiles.append([logfile, None])

        # Find user log files.
        for user_details in self.target.user_details.all_with_home():
            for log_glob in self.USER_GLOBS:
                for logfile in user_details.home_path.glob(log_glob):
                    self.logfiles.append([logfile, user_details])

    def check_compatible(self) -> None:
        if not len(self.logfiles):
            raise UnsupportedPluginError("No Teamviewer logs found")

    @export(record=RemoteAccessLogRecord)
    def logs(self) -> Iterator[RemoteAccessLogRecord]:
        """Yield TeamViewer client logs.

        TeamViewer is a commercial remote desktop application. An adversary may use it to gain persistence on a system.
        """
        for logfile, user_details in self.logfiles:
            logfile = self.target.fs.path(logfile)

            start_date = None
            with logfile.open("rt") as file:
                while True:
                    try:
                        line = file.readline()
                    except UnicodeDecodeError:
                        continue

                    # End of file, quit while loop
                    if not line:
                        break

                    line = line.strip()

                    # Skip empty lines
                    if not line:
                        continue
                    # Older logs first mention the start time and then leave out the year
                    if line.startswith("Start:"):
                        start_date = datetime.strptime(line.split()[1], "%Y/%m/%d")

                    # Sometimes there are weird, mult-line/pretty print log messages.
                    # We only parse the start line which starts with year (%Y/) or month (%m/)
                    if not re.match(START_PATTERN, line):
                        continue

                    ts_day, ts_time, message = line.split(" ", 2)
                    ts_time = ts_time.split(".")[0]

                    # Correct for use of : as millisecond separator
                    if ts_time.count(":") > 2:
                        ts_time = ":".join(ts_time.split(":")[:3])
                    # Correct for missing year in date
                    if ts_day.count("/") == 1:
                        if not start_date:
                            self.target.log.debug("Missing year in log line, skipping line.")
                            continue
                        ts_day = f"{start_date.year}/{ts_day}"
                    # Correct for year if short notation for 2000 is used
                    if ts_day.count("/") == 2 and len(ts_day.split("/")[0]) == 2:
                        ts_day = "20" + ts_day

                    timestamp = datetime.strptime(f"{ts_day} {ts_time}", "%Y/%m/%d %H:%M:%S").replace(
                        tzinfo=timezone.utc
                    )

                    yield self.RemoteAccessLogRecord(
                        ts=timestamp,
                        message=message,
                        source=logfile,
                        _target=self.target,
                        _user=user_details.user if user_details else None,
                    )
