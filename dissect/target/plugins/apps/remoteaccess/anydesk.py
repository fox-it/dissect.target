from datetime import datetime

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import export
from dissect.target.plugins.apps.remoteaccess.remoteaccess import (
    RemoteAccessPlugin,
    RemoteAccessRecord,
)


class AnydeskPlugin(RemoteAccessPlugin):
    """
    Anydesk plugin.
    """

    __namespace__ = "anydesk"

    # Anydesk logs when installed as a service
    SERVICE_GLOBS = [
        "/sysvol/ProgramData/AnyDesk/*.trace",  # Standard client >= Windows 7
        "/sysvol/ProgramData/AnyDesk/ad_*/*.trace",  # Custom client >= Windows 7
        "/var/log/anydesk*.trace",  # Standard/Custom client Linux/MacOS
    ]

    # User specific Anydesk logs
    USER_GLOBS = [
        "appdata/roaming/AnyDesk/*.trace",  # Standard client Windows
        "appdata/roaming/AnyDesk/ad_*/*.trace",  # Custom client Windows
        ".anydesk/*.trace",  # Standard client Linux/MacOS
        ".anydesk_ad_*/*.trace",  # Custom client Linux/MacOS
    ]

    def __init__(self, target):
        super().__init__(target)

        self.logfiles = []

        # Check service globs
        user = None
        for log_glob in self.SERVICE_GLOBS:
            for logfile in self.target.fs.glob(log_glob):
                self.logfiles.append([logfile, user])

        # Anydesk logs when as user
        for user_details in self.target.user_details.all_with_home():
            for log_glob in self.USER_GLOBS:
                for logfile in user_details.home_path.glob(log_glob):
                    self.logfiles.append([logfile, user_details.user])

    def check_compatible(self) -> None:
        if not (len(self.logfiles)):
            raise UnsupportedPluginError("No Anydesk logs found")

    @export(record=RemoteAccessRecord)
    def logs(self):
        """Return the content of the AnyDesk logs.

        AnyDesk is a remote desktop application and can be used by adversaries to get (persistent) access to a machine.
        Log files (.trace files) are retrieved from various location based on OS and client type.

        References:
            - https://www.inversecos.com/2021/02/forensic-analysis-of-anydesk-logs.html
            - https://support.anydesk.com/knowledge/trace-files#trace-file-locations
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
