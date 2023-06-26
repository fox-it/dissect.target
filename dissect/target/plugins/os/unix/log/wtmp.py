from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.log.utmp import UtmpFile

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

        References:
            - https://www.thegeekdiary.com/what-is-the-purpose-of-utmp-wtmp-and-btmp-files-in-linux/
        """
        wtmp_paths = self.target.fs.glob("/var/log/wtmp*")
        for wtmp_path in wtmp_paths:
            if "gz" in wtmp_path:
                wtmp = UtmpFile(self.target.fs.open(wtmp_path), compressed=True)
            else:
                wtmp = UtmpFile(self.target.fs.open(wtmp_path))

            for entry in wtmp:
                yield WtmpRecord(
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
