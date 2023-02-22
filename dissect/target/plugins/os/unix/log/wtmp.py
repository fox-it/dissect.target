import socket
import struct

from dissect.util.ts import from_unix

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.log.utmp import UtmpFile, utmp

WtmpRecord = TargetRecordDescriptor(
    "linux/log/wtmp",
    [
        ("datetime", "ts"),
        ("string", "ut_type"),
        ("string", "ut_user"),
        ("varint", "ut_pid"),
        ("string", "ut_line"),
        ("string", "ut_id"),
        ("string", "ut_host"),
        ("net.ipaddress", "ut_addr"),
    ],
)


class WtmpPlugin(Plugin):
    def check_compatible(self):
        check = list(self.target.fs.glob("/var/log/wtmp*"))
        return len(check) > 0

    @export(record=[WtmpRecord])
    def wtmp(self):
        """Return the content of the wtmp log files.

        The wtmp file contains the historical data of the utmp file. The utmp file contains information about users
        logins at which terminals, logouts, system events and current status of the system, system boot time
        (used by uptime) etc.

        Sources:
            - https://www.thegeekdiary.com/what-is-the-purpose-of-utmp-wtmp-and-btmp-files-in-linux/
        """
        wtmp_paths = self.target.fs.glob("/var/log/wtmp*")
        for wtmp_path in wtmp_paths:
            if "gz" in wtmp_path:
                wtmp = UtmpFile(self.target.fs.open(wtmp_path), compressed=True)
            else:
                wtmp = UtmpFile(self.target.fs.open(wtmp_path))
            r_type = ""
            for entry in wtmp:
                if entry.ut_type in utmp.Type.reverse:
                    r_type = utmp.Type.reverse[entry.ut_type]

                yield WtmpRecord(
                    ts=from_unix(entry.ut_tv.tv_sec),
                    ut_type=r_type,
                    ut_pid=entry.ut_pid,
                    ut_user=entry.ut_user.decode().strip("\x00"),
                    ut_line=entry.ut_line.decode().strip("\x00"),
                    ut_id=entry.ut_id.decode().strip("\x00"),
                    ut_host=entry.ut_host.decode().strip("\x00"),
                    ut_addr=socket.inet_ntoa(struct.pack("<i", entry.ut_addr_v6[0])),
                    _target=self.target,
                )
