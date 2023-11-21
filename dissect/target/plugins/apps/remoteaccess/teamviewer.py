import re
from datetime import datetime

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import export
from dissect.target.plugins.apps.remoteaccess.remoteaccess import (
    RemoteAccessPlugin,
    RemoteAccessRecord,
)

START_PATTERN = re.compile(r"^(\d{2}|\d{4})/")


class TeamviewerPlugin(RemoteAccessPlugin):
    """
    Teamviewer plugin.
    """

    __namespace__ = "teamviewer"

    # Teamviewer log when service (Windows)
    GLOBS = [
        "sysvol/Program Files/TeamViewer/*.log",
        "sysvol/Program Files (x86)/TeamViewer/*.log",
    ]

    def __init__(self, target):
        super().__init__(target)

        self.logfiles = []

        # Check service globs
        user = None
        for log_glob in self.GLOBS:
            for logfile in self.target.fs.glob(log_glob):
                self.logfiles.append([logfile, user])

        # Teamviewer logs when as user (Windows)
        for user_details in self.target.user_details.all_with_home():
            for logfile in user_details.home_path.glob("appdata/roaming/teamviewer/teamviewer*_logfile.log"):
                self.logfiles.append([logfile, user_details.user])

    def check_compatible(self) -> None:
        if not len(self.logfiles):
            raise UnsupportedPluginError("No Teamviewer logs found")

    @export(record=RemoteAccessRecord)
    def logs(self):
        """Return the content of the TeamViewer logs.

        TeamViewer is a commercial remote desktop application. An adversary may use it to gain persistence on a
        system.

        References:
            - https://www.teamviewer.com/nl/
        """
        for logfile, user in self.logfiles:
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

                    ts_day, ts_time, description = line.split(" ", 2)
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

                    timestamp = datetime.strptime(f"{ts_day} {ts_time}", "%Y/%m/%d %H:%M:%S")

                    yield RemoteAccessRecord(
                        tool="teamviewer",
                        ts=timestamp,
                        logfile=str(logfile),
                        description=description,
                        _target=self.target,
                        _user=user,
                    )
