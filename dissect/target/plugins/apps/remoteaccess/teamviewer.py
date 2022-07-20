from datetime import datetime

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.apps.remoteaccess.remoteaccess import RemoteAccessRecord


class TeamviewerPlugin(Plugin):
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

    def check_compatible(self):
        if not len(self.logfiles):
            raise UnsupportedPluginError("No Teamviewer logs found")

    @export(record=RemoteAccessRecord)
    def remoteaccess(self):
        """Return the content of the TeamViewer logs.

        TeamViewer is a commercial remote desktop application. An adversary may use it to gain persistence on a
        system.

        Sources:
            - https://www.teamviewer.com/nl/
        """
        for logfile, user in self.logfiles:
            logfile = self.target.fs.path(logfile)

            for line in logfile.open("rt"):
                line = line.strip()

                # Skip empty lines
                if not line:
                    continue

                # Sometimes there are weird, mult-line/pretty print log messages.
                try:
                    # should be year (%Y)
                    int(line[0])
                except ValueError:
                    continue

                ts_day, ts_time, description = line.split(" ", 2)
                ts_time = ts_time.split(".")[0]

                timestamp = datetime.strptime(f"{ts_day} {ts_time}", "%Y/%m/%d %H:%M:%S")

                yield RemoteAccessRecord(
                    tool="teamviewer",
                    ts=timestamp,
                    logfile=str(logfile),
                    description=description,
                    _target=self.target,
                    _user=user,
                )
