from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.log.utmp import UtmpFile

BtmpRecord = TargetRecordDescriptor(
    "linux/log/btmp",
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


class BtmpPlugin(Plugin):
    """btmp log records failed login attempts"""

    def check_compatible(self):
        check = list(self.target.fs.glob("/var/log/btmp*"))
        return len(check) > 0

    @export(record=[BtmpRecord])
    def btmp(self):
        """Return failed login attempts stored in the btmp file.

        On a Linux system, failed login attempts are stored in the btmp file located in the var/log/ folder.

        References:
            - https://en.wikipedia.org/wiki/Utmp
            - https://www.thegeekdiary.com/what-is-the-purpose-of-utmp-wtmp-and-btmp-files-in-linux/
        """
        btmp_paths = self.target.fs.glob("/var/log/btmp*")
        for btmp_path in btmp_paths:
            if "gz" in btmp_path:
                btmp = UtmpFile(self.target.fs.open(btmp_path), compressed=True)
            else:
                btmp = UtmpFile(self.target.fs.open(btmp_path))

            for entry in btmp:
                yield BtmpRecord(
                    ts=entry.ts,
                    ut_type=entry.ut_type,
                    ut_pid=entry.ut_pid,
                    ut_user=entry.ut_user,
                    ut_line=entry.ut_line,
                    ut_id=entry.ut_id,
                    ut_host=entry.ut_host,
                    ut_addr=entry.ut_addr,
                    _target=self.target,
                )
