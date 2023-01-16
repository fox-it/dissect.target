import bz2
import datetime
import re
import zlib
from io import StringIO

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

MessagesRecord = TargetRecordDescriptor(
    "linux/messages",
    [
        ("datetime", "ts"),
        ("uri", "filepath"),
        ("string", "daemon"),
        ("varint", "pid"),
        ("string", "msg"),
        ("string", "raw"),
    ],
)

RE_TS = re.compile(r"(\w+\s\d+\s\d{2}:\d{2}:\d{2})")
RE_DAEMON = re.compile(r"^[^:]+:\d+:\d+[^\[\]:]+\s([^\[:]+)[\[|:]{1}")
RE_PID = re.compile(r"\w\[(\d+)\]")
RE_MSG = re.compile(r"[^:]+:\d+:\d+[^:]+:\s(.*)$")

LOG_LOCATIONS = [
    "/var/log/messages*",
    "/var/log/syslog*",
]


class MessagesPlugin(Plugin):
    def check_compatible(self):
        for log_location in LOG_LOCATIONS:
            if len(list(self.target.fs.glob_ext(log_location))) > 0:
                return True
        return False

    @export(record=MessagesRecord)
    def messages(self):
        """Return contents of /var/log/messages.

        The messages log file holds information about a variety of events such as the system error messages, system
        startups and shutdowns, change in the network configuration, etc. Aims to store valuable, non-debug and
        non-critical messages. This log should be considered the "general system activity" log.

        Sources:
            - https://geek-university.com/linux/var-log-messages-file/
        """
        for log_location in LOG_LOCATIONS:
            if self.target.fs.glob_ext(log_location):
                for f in self.target.fs.glob_ext(log_location):
                    # FIXME Year is not part of syslog timestamp, take it from file. does not work yet for tar.
                    # FIXME watch for change of year in file!!!
                    file_mtime = self.target.fs.get(str(f)).stat().st_mtime
                    year = datetime.datetime.fromtimestamp(file_mtime).year

                    fh = f.open()
                    if f.name[-2:] == "gz":
                        fh = zlib.decompress(fh.read(), 31)
                        try:
                            fh = StringIO(fh.decode())
                        except UnicodeDecodeError:
                            pass
                    if "bz2" in f.name:
                        fh = bz2.decompress(fh)
                        fh = StringIO(fh.decode())

                    for line in fh:

                        # Line can be a byte object on debian and centos
                        if isinstance(line, bytes):
                            line = line.decode("utf-8").strip()
                        else:
                            line = line.strip()

                        if not line:
                            continue

                        try:
                            ts = datetime.datetime.strptime(RE_TS.search(line).groups()[0], "%b %d %H:%M:%S")
                            ts = ts.replace(year=year)
                        except Exception:
                            # Set ts to epoch 1970-01-01 if we could not convert
                            ts = datetime.datetime.utcfromtimestamp(0)

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
                            filepath=f.path,
                            daemon=daemon,
                            pid=pid,
                            msg=msg,
                            raw=line,
                            _target=self.target,
                        )
