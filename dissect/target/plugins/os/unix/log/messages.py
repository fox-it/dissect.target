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


class MessagesPlugin(Plugin):
    def check_compatible(self):
        pass

    @export(record=MessagesRecord)
    def messages(self):
        """Return contents of /var/log/messages.

        The messages log file holds information about a variety of events such as the system error messages, system
        startups and shutdowns, change in the network configuration, etc. Aims to store valuable, non-debug and
        non-critical messages. This log should be considered the "general system activity" log.

        Sources:
            - https://geek-university.com/linux/var-log-messages-file/
        """
        for f in self.target.fs.glob_ext("/var/log/messages*"):
            # FIXME Year is not part of syslog timestamp, take it from file. does not work yet for tar.
            # FIXME watch for change of year in file!!!
            # year = datetime.datetime.fromtimestamp(f.stat.mtime).year
            year = 2018
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
                line = line.strip()
                if not line:
                    continue

                # FIXME some messages files have long and short hostname in the file
                try:
                    # FIXME add timezone?
                    ts = datetime.datetime.strptime(RE_TS.search(line).groups()[0], "%b %d %H:%M:%S")
                    ts = ts.replace(year=year)
                except Exception:
                    ts = datetime.datetime.now()

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
                    filepath=f.name,
                    daemon=daemon,
                    pid=pid,
                    msg=msg,
                    raw=line,
                    _target=self.target,
                )
