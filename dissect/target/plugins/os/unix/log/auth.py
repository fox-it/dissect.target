import re
from typing import Iterator

from dissect.target import Target
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.helpers.utils import year_rollover_helper
from dissect.target.plugin import Plugin, export

AuthLogRecord = TargetRecordDescriptor(
    "linux/log/auth",
    [
        ("datetime", "ts"),
        ("string", "message"),
        ("path", "source"),
    ],
)

_TS_REGEX = r"^[A-Za-z]{3}\s*[0-9]{1,2}\s[0-9]{1,2}:[0-9]{2}:[0-9]{2}"
RE_TS = re.compile(_TS_REGEX)
RE_TS_AND_HOSTNAME = re.compile(_TS_REGEX + r"\s\S+\s")


class AuthPlugin(Plugin):
    def __init__(self, target: Target):
        super().__init__(target)

        self.var_log = self.target.fs.path("/var/log")
        self.secure_log = "secure*"
        self.auth_log = "auth.log*"
        self.tzinfo = self.target.datetime.tzinfo

    def check_compatible(self) -> bool:
        return any(self.var_log.glob(self.secure_log)) or any(self.var_log.glob(self.auth_log))

    def _get_records(self, log_file_glob: str) -> Iterator[AuthLogRecord]:
        for auth_file in self.var_log.glob(log_file_glob):
            for ts, line in year_rollover_helper(auth_file, RE_TS, "%b %d %H:%M:%S", self.tzinfo):
                ts_and_hostname = re.search(RE_TS_AND_HOSTNAME, line)

                if not ts_and_hostname:
                    self.target.log.warning("No timestamp and hostname found on one of the lines in %s.", auth_file)
                    self.target.log.debug("Skipping this line: %s", line)
                    continue

                message = line.replace(ts_and_hostname.group(0), "").strip()

                yield AuthLogRecord(
                    ts=ts,
                    message=message,
                    source=auth_file,
                    _target=self.target,
                )

    @export(record=[AuthLogRecord])
    def securelog(self) -> Iterator[AuthLogRecord]:
        """Return contents of /var/log/secure*."""
        yield from self._get_records(self.secure_log)

    @export(record=[AuthLogRecord])
    def authlog(self) -> Iterator[AuthLogRecord]:
        """Return contents of /var/log/auth.log*."""

        # Assuming no custom date_format template is set in syslog-ng or systemd (M d H:M:S)
        # CentOS format: Jan 12 13:37:00 hostname daemon: message
        # Debian format: Jan 12 13:37:00 hostname daemon[pid]: pam_unix(daemon:session): message
        yield from self._get_records(self.auth_log)
