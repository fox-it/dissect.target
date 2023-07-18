from datetime import datetime
from typing import Iterator

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

CpanelLastloginRecord = TargetRecordDescriptor(
    "application/log/cpanel/lastlogin",
    [
        ("datetime", "ts"),
        ("string", "user"),
        ("net.ipaddress", "remote_ip"),
    ],
)

CPANEL_LASTLOGIN = ".lastlogin"
CPANEL_LOGS_PATH = "/usr/local/cpanel/logs"


class CpanelPlugin(Plugin):
    # TODO: Parse other log files https://support.cartika.com/portal/en/kb/articles/whm-cpanel-log-files-and-locations
    __namespace__ = "cpanel"

    def check_compatible(self) -> None:
        return bool(self.target.fs.path(CPANEL_LOGS_PATH).exists())

    @export(record=CpanelLastloginRecord)
    def lastlogin(self) -> Iterator[CpanelLastloginRecord]:
        """Return the content of the cPanel lastlogin file.

        The lastlogin files tracks successful cPanel interface logons. New logon events are only tracked
        if the IP-address of the logon changes.

        References:
            - https://forums.cpanel.net/threads/cpanel-control-panel-last-login-clarification.579221/
            - https://forums.cpanel.net/threads/lastlogin.707557/
        """
        for user_details in self.target.user_details.all_with_home():
            if (lastlogin := user_details.home_path.joinpath(CPANEL_LASTLOGIN)).exists():
                try:
                    for index, line in enumerate(lastlogin.open("rt")):
                        if not line:
                            continue

                        line = line.strip().split()

                        # In certain cases two log lines are part of the same line
                        if len(line) != 5 or len(line[4]) != 5:
                            self.target.log.warning(
                                "The cPanel lastlogin line number %s is malformed: %s", index + 1, lastlogin
                            )
                            continue

                        remote_ip, _, date, time, utc_offset = line

                        timestamp = datetime.strptime(f"{date} {time} {utc_offset}", "%Y-%m-%d %H:%M:%S %z")

                        yield CpanelLastloginRecord(
                            ts=timestamp,
                            user=user_details.user.name,
                            remote_ip=remote_ip,
                            _target=self.target,
                        )

                except Exception:
                    self.target.log.warning(
                        "An error occurred parsing cPanel lastlogin line number %i in file: %s", index + 1, lastlogin
                    )
