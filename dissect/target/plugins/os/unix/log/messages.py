import re
from datetime import datetime

from dissect.target.helpers.fsutil import TargetPath, decompress_and_readlines
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

MessagesRecord = TargetRecordDescriptor(
    "linux/messages",
    [
        ("datetime", "ts"),
        ("string", "daemon"),
        ("varint", "pid"),
        ("string", "message"),
        ("string", "raw"),
        ("uri", "source"),
    ],
)

RE_TS = re.compile(r"(\w+\s{1,2}\d+\s\d{2}:\d{2}:\d{2})")
RE_DAEMON = re.compile(r"^[^:]+:\d+:\d+[^\[\]:]+\s([^\[:]+)[\[|:]{1}")
RE_PID = re.compile(r"\w\[(\d+)\]")
RE_MSG = re.compile(r"[^:]+:\d+:\d+[^:]+:\s(.*)$")


class MessagesPlugin(Plugin):
    def check_compatible(self):
        return self.target.fs.path("/var/log/syslog").exists() or self.target.fs.path("/var/log/messages").exists()

    @export(record=MessagesRecord)
    def syslog(self):
        return self.messages()

    @export(record=MessagesRecord)
    def messages(self):
        """Return contents of /var/log/messages.

        The messages log file holds information about a variety of events such as the system error messages, system
        startups and shutdowns, change in the network configuration, etc. Aims to store valuable, non-debug and
        non-critical messages. This log should be considered the "general system activity" log.

        Sources:
            - https://geek-university.com/linux/var-log-messages-file/
        """

        log_files: [TargetPath] = list(self.target.fs.path("/var/log/").glob("syslog*")) + list(
            self.target.fs.path("/var/log/").glob("messages*")
        )

        for log_file in log_files:

            file_ctime = self.target.fs.get(str(log_file)).stat().st_ctime
            year_file_created = datetime.fromtimestamp(file_ctime).year
            last_seen_year = year_file_created
            last_seen_month = 0

            for line in decompress_and_readlines(log_file):

                # Line can be a byte object on debian and centos
                if isinstance(line, bytes):
                    line = line.decode("utf-8").strip()
                else:
                    line = line.strip()

                if not line or line == "":
                    continue

                try:
                    ts = datetime.strptime(RE_TS.search(line).groups()[0], "%b %d %H:%M:%S")
                    if last_seen_month > ts.month:
                        last_seen_year += 1
                    last_seen_month = ts.month
                    ts = ts.replace(year=last_seen_year)
                except Exception as e:
                    self.target.log.warn(f"Could not convert timestamp line in {log_file}: {e}")
                    # Set ts to epoch 1970-01-01 if we could not convert
                    ts = datetime.utcfromtimestamp(0)

                try:
                    daemon = RE_DAEMON.search(line).groups()[0]
                except Exception:
                    daemon = None

                try:
                    pid = RE_PID.search(line)
                    if pid is not None:
                        pid = pid.groups()[0]
                except Exception:
                    pid = None

                try:
                    msg = RE_MSG.search(line).groups()[0]
                    if msg is None:
                        msg = line
                except Exception:
                    msg = line

                yield MessagesRecord(
                    ts=ts,
                    daemon=daemon,
                    pid=pid,
                    message=msg,
                    raw=line,
                    source=str(log_file),
                    _target=self.target,
                )
