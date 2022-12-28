from typing import BinaryIO

from dissect import cstruct
from dissect.util import ts

from dissect.target.exceptions import FileNotFoundError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

LastLogRecord = TargetRecordDescriptor(
    "linux/log/lastlog",
    [
        ("datetime", "ts"),
        ("uint32", "uid"),
        ("string", "ut_user"),  # name
        ("string", "ut_host"),  # source
        ("string", "ut_tty"),  # port
    ],
)

lastlog_def = """
#define UT_NAMESIZE 32
#define UT_HOSTSIZE 256
#define size        292


struct {
    uint32 tv_sec;
} time_t;


struct entry {
    struct time_t ll_time;
    char    ut_user[UT_NAMESIZE];
    char    ut_host[UT_HOSTSIZE];
};
"""

c_lastlog = cstruct.cstruct()
c_lastlog.load(lastlog_def)


class LastLogFile:
    def __init__(self, fh: BinaryIO):
        self.fh = fh

    def __iter__(self):
        while True:
            try:
                yield c_lastlog.entry(self.fh)
            except EOFError:
                break


class LastLogPlugin(Plugin):
    def check_compatible(self):
        lastlog = self.target.fs.path("/var/log/lastlog")
        return lastlog.exists()

    @export(record=[LastLogRecord])
    def lastlog(self):
        """Return last logins information from /var/log/lastlog.

        The lastlog file contains the most recent logins of all users on a Unix based operating system.

        Sources:
            - https://www.tutorialspoint.com/unix_commands/lastlog.htm
        """
        try:
            lastlog = self.target.fs.open("/var/log/lastlog")
        except FileNotFoundError:
            return

        users = {}
        for user in self.target.users():
            users[user.uid] = user.name

        log = LastLogFile(lastlog)

        for idx, entry in enumerate(log):

            # if ts=0 the uid has never logged in before
            if entry.ut_host.strip(b"\x00") == b"" or entry.ll_time.tv_sec == 0:
                continue

            yield LastLogRecord(
                ts=ts.from_unix(entry.ll_time.tv_sec),
                uid=idx,
                ut_user=users.get(idx),
                ut_tty=entry.ut_user.decode().strip("\x00"),
                ut_host=entry.ut_host.decode(errors="ignore").strip("\x00"),
                _target=self.target,
            )
