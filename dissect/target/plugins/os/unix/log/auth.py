from dissect.target.helpers.fsutil import TargetPath, decompress_and_readlines
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

from datetime import datetime
import re

AuthLogRecord = TargetRecordDescriptor(
    "linux/log/auth",
    [
        ("datetime", "ts"),
        ("string", "msg"),
    ],
)


class AuthPlugin(Plugin):
    def check_compatible(self):
        return self.target.fs.path("/var/log/auth.log").exists() or self.target.fs.path("/var/log/secure").exists()

    @export(record=[AuthLogRecord])
    def securelog(self):
        return self.authlog()

    @export(record=[AuthLogRecord])
    def authlog(self):
        """
        Yields AuthLogRecords from /var/log/auth.log* and /var/log/secure*
        """
        auth_files: [TargetPath] = list(self.target.fs.path("/var/log/").glob("auth.log*")) + list(
            self.target.fs.path("/var/log/").glob("secure*")
        )

        RE_TS = r"^[A-Za-z]{3}\s*[0-9]{1,2}\s[0-9]{1,2}:[0-9]{2}:[0-9]{2}"
        RE_TS_AND_HOSTNAME = RE_TS + r"\s\w+\s"

        for auth_file in auth_files:

            file_ctime = self.target.fs.get(str(auth_file)).stat().st_ctime
            year_file_created = datetime.fromtimestamp(file_ctime).year
            last_seen_year = year_file_created
            last_seen_month = 0

            for line in decompress_and_readlines(auth_file):
                if line.startswith("#"):
                    continue

                line = line.decode() if type(line) == bytes else line
                line = line.rstrip()

                # This assumes no custom date_format template in syslog-ng or systemd (M d H:M:S)
                # CentOS format: Jan 12 13:37:00 hostname daemon: message
                # Debian format: Jan 12 13:37:00 hostname daemon[pid]: pam_unix(daemon:session): message

                relative_ts = re.search(RE_TS, line).group(0)
                abs_ts = datetime.strptime(relative_ts, "%b %d %H:%M:%S")

                if last_seen_month > abs_ts.month:
                    last_seen_year += 1
                last_seen_month = abs_ts.month

                abs_ts = abs_ts.replace(year=last_seen_year)
                msg = line.replace(re.search(RE_TS_AND_HOSTNAME, line).group(0), "").strip()

                yield AuthLogRecord(
                    ts=abs_ts,
                    msg=msg,
                    _target=self.target,
                )
