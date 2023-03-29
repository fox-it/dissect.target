from datetime import datetime

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.apps.remoteaccess.remoteaccess import RemoteAccessRecord


class AnydeskPlugin(Plugin):
    """
    Anydesk plugin.
    """

    __namespace__ = "anydesk"

    # Anydesk log when service (Windows)
    GLOBS = [
        "/sysvol/ProgramData/AnyDesk/*.trace",
    ]

    def __init__(self, target):
        super().__init__(target)

        self.logfiles = []

        # Check service globs (Windows)
        user = None
        for log_glob in self.GLOBS:
            for logfile in self.target.fs.glob(log_glob):
                self.logfiles.append([logfile, user])

        # Anydesk logs when as user
        for user_details in self.target.user_details.all_with_home():
            for logfile in user_details.home_path.glob("appdata/roaming/AnyDesk/*.trace"):
                self.logfiles.append([logfile, user_details.user])

    def check_compatible(self):
        if not (len(self.logfiles)):
            raise UnsupportedPluginError("No Anydesk logs found")

    @export(record=RemoteAccessRecord)
    def remoteaccess(self):
        """Return the content of the AnyDesk logs.

        AnyDesk is a remote desktop application and can be used by adversaries to get (persistent) access to a machine.
        Log files (.trace files) are retrieved from /ProgramData/AnyDesk/ and AppData/roaming/AnyDesk/

        References:
            - https://www.inversecos.com/2021/02/forensic-analysis-of-anydesk-logs.html
        """
        for logfile, user in self.logfiles:
            logfile = self.target.fs.path(logfile)

            for line in logfile.open("rt"):
                line = line.strip()

                # Skip empty lines
                if not line:
                    continue

                if "* * * * * * * * * * * * * *" in line:
                    continue

                level, ts_day, ts_time, description = line.split(" ", 3)
                description = f"{level} {description}"
                ts_time = ts_time.split(".")[0]

                timestamp = datetime.strptime(f"{ts_day} {ts_time}", "%Y-%m-%d %H:%M:%S")

                yield RemoteAccessRecord(
                    ts=timestamp,
                    tool="anydesk",
                    logfile=str(logfile),
                    description=description,
                    _target=self.target,
                    _user=user,
                )
