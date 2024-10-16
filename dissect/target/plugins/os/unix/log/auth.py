import itertools
import logging
import re
from itertools import chain
from typing import Iterator

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.fsutil import TargetPath, open_decompress
from dissect.target.helpers.record import DynamicDescriptor, TargetRecordDescriptor
from dissect.target.helpers.utils import year_rollover_helper
from dissect.target.plugin import Plugin, alias, export

log = logging.getLogger(__name__)

_RE_TS = r"^[A-Za-z]{3}\s*[0-9]{1,2}\s[0-9]{1,2}:[0-9]{2}:[0-9]{2}"
_RE_TS_ISO = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+\d{2}:\d{2}"

RE_TS = re.compile(_RE_TS)
RE_TS_ISO = re.compile(_RE_TS_ISO)
RE_LINE = re.compile(
    rf"(?P<ts>{_RE_TS}|{_RE_TS_ISO})\s(?P<hostname>\S+)\s(?P<service>\S+?)(\[(?P<pid>\d+)\])?:\s(?P<message>.+)$"
)

AuthLogRecord = TargetRecordDescriptor(
    "linux/log/auth",
    [
        ("datetime", "ts"),
        ("string", "message"),
        ("path", "source"),
    ],
)


class AuthPlugin(Plugin):
    """Unix auth log plugin."""

    def check_compatible(self) -> None:
        var_log = self.target.fs.path("/var/log")
        if not any(var_log.glob("auth.log*")) and not any(var_log.glob("secure*")):
            raise UnsupportedPluginError("No auth log files found")

    @alias("securelog")
    @export(record=DynamicDescriptor(["datetime", "path", "string"]))
    def authlog(self) -> Iterator[any]:
        """Yield contents of ``/var/log/auth.log*`` and ``/var/log/secure*`` files.

        Order of returned events is not guaranteed to be chronological because of year
        rollover detection efforts for log files without a year in the timestamp.

        The following timestamp formats are recognised automatically. This plugin
        assumes that no custom ``date_format`` template is set in ``syslog-ng`` or ``systemd``
        configuration (defaults to ``M d H:M:S``).

        ISO formatted authlog entries are parsed as can be found in Ubuntu 24.04 and later.

        .. code-block:: text

            CentOS format: Jan 12 13:37:00 hostname daemon: message
            Debian format: Jan 12 13:37:00 hostname daemon[pid]: pam_unix(daemon:session): message
            Ubuntu  24.04: 2024-01-12T13:37:00.000000+02:00 hostname daemon[pid]: pam_unix(daemon:session): message

        Resources:
            - https://help.ubuntu.com/community/LinuxLogFiles
        """

        tzinfo = self.target.datetime.tzinfo

        var_log = self.target.fs.path("/var/log")
        for auth_file in chain(var_log.glob("auth.log*"), var_log.glob("secure*")):
            if is_iso_fmt(auth_file):
                iterable = iso_readlines(auth_file)

            else:
                iterable = year_rollover_helper(auth_file, RE_TS, "%b %d %H:%M:%S", tzinfo)

            for ts, line in iterable:
                yield self._auth_log_builder.build_record(ts, auth_file, line)


def iso_readlines(file: TargetPath) -> Iterator[tuple[datetime, str]]:
    """Iterator reading the provided auth log file in ISO format. Mimics ``year_rollover_helper`` behaviour."""

    with open_decompress(file, "rt") as fh:
        for line in fh:
            if not (match := RE_TS_ISO.match(line)):
                log.warning("No timestamp found in one of the lines in %s!", file)
                log.debug("Skipping line: %s", line)
                continue

            try:
                ts = datetime.strptime(match[0], "%Y-%m-%dT%H:%M:%S.%f%z")

            except ValueError as e:
                log.warning("Unable to parse ISO timestamp in line: %s", line)
                log.debug("", exc_info=e)
                continue

            yield ts, line


def is_iso_fmt(file: TargetPath) -> bool:
    """Determine if the provided auth log file uses new ISO format logging or not."""
    return any(itertools.islice(iso_readlines(file), 0, 2))
