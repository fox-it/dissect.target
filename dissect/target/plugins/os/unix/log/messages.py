import re
from pathlib import Path
from typing import Iterator

from dissect.target import Target
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.helpers.utils import year_rollover_helper
from dissect.target.plugin import Plugin, alias, export

MessagesRecord = TargetRecordDescriptor(
    "linux/log/messages",
    [
        ("datetime", "ts"),
        ("string", "daemon"),
        ("varint", "pid"),
        ("string", "message"),
        ("path", "source"),
    ],
)

DEFAULT_TS_LOG_FORMAT = "%b %d %H:%M:%S"
RE_TS = re.compile(r"(\w+\s{1,2}\d+\s\d{2}:\d{2}:\d{2})")
RE_DAEMON = re.compile(r"^[^:]+:\d+:\d+[^\[\]:]+\s([^\[:]+)[\[|:]{1}")
RE_PID = re.compile(r"\w\[(\d+)\]")
RE_MSG = re.compile(r"[^:]+:\d+:\d+[^:]+:\s(.*)$")
RE_CLOUD_INIT_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - (?P<daemon>.*)\[(?P<log_level>\w+)\]\: (?P<message>.*)$"
)


class MessagesPlugin(Plugin):
    def __init__(self, target: Target):
        super().__init__(target)
        self.log_files = set(self._find_log_files())

    def _find_log_files(self) -> Iterator[Path]:
        log_dirs = ["/var/log/", "/var/log/installer/"]
        file_globs = ["syslog*", "messages*", "cloud-init.log*"]
        for log_dir in log_dirs:
            for glob in file_globs:
                yield from self.target.fs.path(log_dir).glob(glob)

    def check_compatible(self) -> None:
        if not self.log_files:
            raise UnsupportedPluginError("No log files found")

    @alias("syslog")
    @export(record=MessagesRecord)
    def messages(self) -> Iterator[MessagesRecord]:
        """Return contents of /var/log/messages*, /var/log/syslog* and cloud-init logs.

        Due to year rollover detection, the contents of the files are returned in reverse.

        The messages log file holds information about a variety of events such as the system error messages, system
        startups and shutdowns, change in the network configuration, etc. Aims to store valuable, non-debug and
        non-critical messages. This log should be considered the "general system activity" log.

        References:
            - https://geek-university.com/linux/var-log-messages-file/
            - https://www.geeksforgeeks.org/file-timestamps-mtime-ctime-and-atime-in-linux/
            - https://cloudinit.readthedocs.io/en/latest/development/logging.html#logging-command-output
        """

        tzinfo = self.target.datetime.tzinfo

        for log_file in self.log_files:
            if "cloud-init" in log_file.name:
                yield from self._parse_cloud_init_log(log_file)
                continue

            for ts, line in year_rollover_helper(log_file, RE_TS, DEFAULT_TS_LOG_FORMAT, tzinfo):
                daemon = dict(enumerate(RE_DAEMON.findall(line))).get(0)
                pid = dict(enumerate(RE_PID.findall(line))).get(0)
                message = dict(enumerate(RE_MSG.findall(line))).get(0, line)

                yield MessagesRecord(
                    ts=ts,
                    daemon=daemon,
                    pid=pid,
                    message=message,
                    source=log_file,
                    _target=self.target,
                )

    def _parse_cloud_init_log(self, log_file: Path) -> Iterator[MessagesRecord]:
        """Parse a cloud-init.log file.

        Lines are structured in the following format:
        ``YYYY-MM-DD HH:MM:SS,000 - dhcp.py[DEBUG]: Received dhcp lease on IFACE for IP/MASK``

        NOTE: ``cloud-init-output.log`` files are not supported as they do not contain structured logs.

        Args:
            ``log_file``: path to cloud-init.log file.

        Returns: ``MessagesRecord``
        """
        for line in log_file.open("rt").readlines():
            if line := line.strip():
                if match := RE_CLOUD_INIT_LINE.match(line):
                    match = match.groupdict()
                    yield MessagesRecord(
                        ts=match["ts"].split(",")[0],
                        daemon=match["daemon"],
                        pid=None,
                        message=match["message"],
                        source=log_file,
                        _target=self.target,
                    )
                else:
                    self.target.log.warning("Could not match cloud-init log line")
                    self.target.log.debug("No match for line '%s'", line)
