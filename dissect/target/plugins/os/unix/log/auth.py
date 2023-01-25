import re
from datetime import datetime, timezone
from itertools import chain
from typing import Generator
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from dissect.util import ts
from flow.record.fieldtypes import path

from dissect.target.helpers.fsutil import TargetPath, open_decompress
from dissect.target.helpers.record import TargetRecordDescriptor
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

        try:
            self.target_timezone = ZoneInfo(f"{target.timezone}")
        except ZoneInfoNotFoundError:
            self.target.log.warning("Could not determine timezone of target, falling back to UTC.")
            self.target_timezone = timezone.utc

    def check_compatible(self):
        return self.target.fs.path("/var/log/auth.log").exists() or self.target.fs.path("/var/log/secure").exists()

    @export(record=[AuthLogRecord])
    def securelog(self):
        """Return contents of /var/log/auth.log* and /var/log/secure*."""
        return self.authlog()

    @export(record=[AuthLogRecord])
    def authlog(self):
        """Return contents of /var/log/auth.log* and /var/log/secure*."""
        authlogs = list(self.target.fs.path("/var/log/").glob("auth.log*"))
        securelogs = list(self.target.fs.path("/var/log/").glob("secure*"))
        auth_files: Generator[TargetPath] = chain(authlogs, securelogs)

        for auth_file in auth_files:

            file_ctime = self.target.fs.get(str(auth_file)).stat().st_ctime
            year_file_created = ts.from_unix(file_ctime).year
            last_seen_year = year_file_created
            last_seen_month = 0

            for line in open_decompress(auth_file, "rt"):
                if line.startswith("#"):
                    continue

                line = line.rstrip()

                # This assumes no custom date_format template in syslog-ng or systemd (M d H:M:S)
                # CentOS format: Jan 12 13:37:00 hostname daemon: message
                # Debian format: Jan 12 13:37:00 hostname daemon[pid]: pam_unix(daemon:session): message

                relative_ts = re.search(RE_TS, line).group(0)
                abs_ts = datetime.strptime(relative_ts, "%b %d %H:%M:%S")

                if last_seen_month > abs_ts.month:
                    last_seen_year += 1
                last_seen_month = abs_ts.month

                abs_ts = abs_ts.replace(year=last_seen_year, tzinfo=self.target_timezone)
                msg = line.replace(re.search(RE_TS_AND_HOSTNAME, line).group(0), "").strip()

                yield AuthLogRecord(
                    ts=abs_ts,
                    message=msg,
                    source=path.from_posix(auth_file),
                    _target=self.target,
                )
