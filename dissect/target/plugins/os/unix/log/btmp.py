import datetime
import socket
import struct

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

from dissect.target.plugins.os.unix.log.utmp import utmp, UtmpFile


BtmpRecord = TargetRecordDescriptor(
    "linux/log/btmp",
    [
        ("datetime", "ts"),
        ("string", "ut_type"),
        ("string", "ut_user"),
        ("string", "ut_pid"),
        ("string", "ut_line"),
        ("string", "ut_id"),
        ("string", "ut_host"),
        ("string", "ut_addr"),
    ],
)


class BtmpPlugin(Plugin):
    """btmp log records failed login attempts"""

    def check_compatible(self):
        check = list(self.target.fs.glob("/var/log/btmp*"))
        return len(check) > 0

    @export(record=[BtmpRecord])
    def btmp(self):
        """Return failed login attempts stored in the btmp file.

        On a Linux system, failed login attempts are stored in the btmp file located in the var/log/ folder.

        Sources:
            - https://en.wikipedia.org/wiki/Utmp
            - https://www.thegeekdiary.com/what-is-the-purpose-of-utmp-wtmp-and-btmp-files-in-linux/
        """
        btmp_paths = self.target.fs.glob("/var/log/btmp*")
        for btmp_path in btmp_paths:
            if "gz" in btmp_path:
                btmp = UtmpFile(self.target.fs.open(btmp_path), compressed=True)
            else:
                btmp = UtmpFile(self.target.fs.open(btmp_path))
            r_type = ""
            for entry in btmp:
                if entry.ut_type in utmp.Type.reverse:
                    r_type = utmp.Type.reverse[entry.ut_type]

                yield BtmpRecord(
                    ts=datetime.datetime.utcfromtimestamp(entry.ut_tv.tv_sec),
                    ut_type=r_type,
                    ut_pid=entry.ut_pid,
                    ut_user=entry.ut_user.decode().strip("\x00"),
                    ut_line=entry.ut_line.decode().strip("\x00"),
                    ut_id=entry.ut_id.decode().strip("\x00"),
                    ut_host=entry.ut_host.decode().strip("\x00"),
                    ut_addr=socket.inet_ntoa(struct.pack("<i", entry.ut_addr_v6[0])),
                    _target=self.target,
                )
