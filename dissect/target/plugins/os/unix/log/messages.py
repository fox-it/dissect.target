import re
from itertools import chain

from flow.record.fieldtypes import path

from dissect.target.helpers.fsutil import open_decompress, YearRolloverHelper
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

MessagesRecord = TargetRecordDescriptor(
    "linux/messages",
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
    def check_compatible(self):
        return any(self.target.fs.path("/var/log").glob("syslog*")) or any(
            self.target.fs.path("/var/log").glob("messages*")
        )

    @export(record=MessagesRecord)
    def syslog(self):
        """Return contents of /var/log/messages* and /var/log/syslog*.

        See ``messages`` for more information.
        """
        return self.messages()

    @export(record=MessagesRecord)
    def messages(self):
        """Return contents of /var/log/messages* and /var/log/syslog*.

        The messages log file holds information about a variety of events such as the system error messages, system
        startups and shutdowns, change in the network configuration, etc. Aims to store valuable, non-debug and
        non-critical messages. This log should be considered the "general system activity" log.

        Sources:
            - https://geek-university.com/linux/var-log-messages-file/
            - https://www.geeksforgeeks.org/file-timestamps-mtime-ctime-and-atime-in-linux/
        """

        var_log = self.target.fs.path("/var/log")
        for log_file in chain(var_log.glob("syslog*"), var_log.glob("messages*")):

            # First iteration: we count the number of year rollovers.
            helper = YearRolloverHelper(self.target, log_file, RE_TS, DEFAULT_TS_LOG_FORMAT)

            # Second iteration: yield results with correct year ts.
            for line in open_decompress(log_file, "rt"):
                line = line.strip()
                if not line:
                    continue

                absolute_ts_dt = helper.apply_year_rollovers(line)
                daemon = dict(enumerate(RE_DAEMON.findall(line))).get(0)
                pid = dict(enumerate(RE_PID.findall(line))).get(0)
                message = dict(enumerate(RE_MSG.findall(line))).get(0, line)

                yield MessagesRecord(
                    ts=absolute_ts_dt,
                    daemon=daemon,
                    pid=pid,
                    message=message,
                    source=path.from_posix(log_file),
                    _target=self.target,
                )
