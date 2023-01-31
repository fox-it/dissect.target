import re
from itertools import chain
from typing import Generator

from flow.record.fieldtypes import path

from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.helpers.utils import year_rollover_helper
from dissect.target.plugin import Plugin, export

AuthLogRecord = TargetRecordDescriptor(
    "linux/log/auth",
    [
        ("datetime", "ts"),
        ("string", "message"),
        ("string", "source"),
    ],
)

ts_regex = r"^[A-Za-z]{3}\s*[0-9]{1,2}\s[0-9]{1,2}:[0-9]{2}:[0-9]{2}"
RE_TS = re.compile(ts_regex)
RE_TS_AND_HOSTNAME = re.compile(ts_regex + r"\s\w+\s")


class AuthPlugin(Plugin):
    def __init__(self, target):
        super().__init__(target)

        self.target_timezone = target.datetime.tzinfo

    def check_compatible(self):
        return self.target.fs.path("/var/log/auth.log").exists() or self.target.fs.path("/var/log/secure").exists()

    @export(record=[AuthLogRecord])
    def securelog(self):
        """Return contents of /var/log/auth.log* and /var/log/secure*."""
        return self.authlog()

    @export(record=[AuthLogRecord])
    def authlog(self):
        """Return contents of /var/log/auth.log* and /var/log/secure*."""

        # Assuming no custom date_format template is set in syslog-ng or systemd (M d H:M:S)
        # CentOS format: Jan 12 13:37:00 hostname daemon: message
        # Debian format: Jan 12 13:37:00 hostname daemon[pid]: pam_unix(daemon:session): message

        authlogs = list(self.target.fs.path("/var/log/").glob("auth.log*"))
        securelogs = list(self.target.fs.path("/var/log/").glob("secure*"))
        auth_files: Generator[TargetPath] = chain(authlogs, securelogs)

        for auth_file in auth_files:
            for ts, line in year_rollover_helper(auth_file, RE_TS, "%b %d %H:%M:%S", self.target_timezone):
                line = line.rstrip()
                message = line.replace(re.search(RE_TS_AND_HOSTNAME, line).group(0), "").strip()
                yield AuthLogRecord(
                    ts=ts,
                    message=message,
                    source=path.from_posix(auth_file),
                    _target=self.target,
                )
