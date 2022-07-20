import datetime
import socket
import struct

from dissect.target.exceptions import FileNotFoundError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

from dissect.target.plugins.os.unix.log.utmp import utmp, UtmpFile


LastlogRecord = TargetRecordDescriptor(
    "linux/log/lastlog",
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


class LastlogPlugin(Plugin):
    def check_compatible(self):
        lastlog = self.target.fs.path("/var/log/lastlog")
        return lastlog.exists()

    @export(record=[LastlogRecord])
    def lastlog(self):
        """Return last logins information from /var/log/lastlog.

        The lastlog file contains the most recent logins of all users on a Unix based operating system.

        Sources:
            - https://www.tutorialspoint.com/unix_commands/lastlog.htm
        """
        try:
            wtmp = self.target.fs.open("/var/log/lastlog")
        except FileNotFoundError:
            return

        log = UtmpFile(wtmp)

        for entry in log:

            if entry.ut_type in utmp.Type.reverse:
                r_type = utmp.Type.reverse[entry.ut_type]
            else:
                r_type = None

            yield LastlogRecord(
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
