from __future__ import annotations

import re
from datetime import datetime
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

CPanelLastloginRecord = TargetRecordDescriptor(
    "application/log/cpanel/lastlogin",
    [
        ("datetime", "ts"),
        ("string", "user"),
        ("net.ipaddress", "remote_ip"),
    ],
)

CPANEL_LASTLOGIN = ".lastlogin"
CPANEL_LOGS_PATH = "/usr/local/cpanel/logs"
CPANEL_LASTLOGIN_PATTERN = re.compile(
    r"([^\s]+) # ([0-9]{4}-[0-9]{2}-[0-9]{2}) ([0-9]{2}:[0-9]{2}:[0-9]{2}) ([+-][0-9]{4})"
)


class CPanelPlugin(Plugin):
    """cPanel webhosting plugin."""

    # TODO: Parse other log files https://support.cartika.com/portal/en/kb/articles/whm-cpanel-log-files-and-locations
    __namespace__ = "cpanel"

    def check_compatible(self) -> None:
        if not self.target.fs.path(CPANEL_LOGS_PATH).exists():
            raise UnsupportedPluginError("No cPanel log path found")

    @export(record=CPanelLastloginRecord)
    def lastlogin(self) -> Iterator[CPanelLastloginRecord]:
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
                        line = line.strip()
                        if not line:
                            continue

                        if events := CPANEL_LASTLOGIN_PATTERN.findall(line):
                            for event in events:
                                remote_ip, date, time, utc_offset = event

                                timestamp = datetime.strptime(f"{date} {time} {utc_offset}", "%Y-%m-%d %H:%M:%S %z")

                                yield CPanelLastloginRecord(
                                    ts=timestamp,
                                    user=user_details.user.name,
                                    remote_ip=remote_ip,
                                    _target=self.target,
                                )
                        else:
                            self.target.log.warning(
                                "The cPanel lastlogin line number %s is malformed: %s", index + 1, lastlogin
                            )

                except Exception:
                    self.target.log.warning(
                        "An error occurred parsing cPanel lastlogin line number %i in file: %s", index + 1, lastlogin
                    )
