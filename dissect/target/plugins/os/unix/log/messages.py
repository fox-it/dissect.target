import re
from typing import Iterator

from dissect.target import Target
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.helpers.utils import year_rollover_helper
from dissect.target.plugin import Plugin, export

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


class MessagesPlugin(Plugin):
    def __init__(self, target: Target):
        super().__init__(target)

        self.var_log = self.target.fs.path("/var/log")
        self.syslog_glob = "syslog*"
        self.messages_glob = "messages*"
        self.tzinfo = self.target.datetime.tzinfo

    def check_compatible(self) -> bool:
        return any(self.var_log.glob(self.syslog_glob)) or any(self.var_log.glob(self.messages_glob))

    def _get_records(self, log_file_glob: str) -> Iterator[MessagesRecord]:
        for log_file in self.var_log.glob(log_file_glob):
            for ts, line in year_rollover_helper(log_file, RE_TS, DEFAULT_TS_LOG_FORMAT, self.tzinfo):
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

    @export(record=MessagesRecord)
    def syslog(self) -> Iterator[MessagesRecord]:
        """Return contents of /var/log/syslog*.

        See ``messages`` for more information.
        """
        yield from self._get_records(self.syslog_glob)

    @export(record=MessagesRecord)
    def messages(self) -> Iterator[MessagesRecord]:
        """Return contents of /var/log/messages*.

        Note: due to year rollover detection, the contents of the files are returned in reverse.

        The messages log file holds information about a variety of events such as the system error messages, system
        startups and shutdowns, change in the network configuration, etc. Aims to store valuable, non-debug and
        non-critical messages. This log should be considered the "general system activity" log.

        References:
            - https://geek-university.com/linux/var-log-messages-file/
            - https://www.geeksforgeeks.org/file-timestamps-mtime-ctime-and-atime-in-linux/
        """
        yield from self._get_records(self.messages_glob)
