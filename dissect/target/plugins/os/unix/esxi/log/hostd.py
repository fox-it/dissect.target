from __future__ import annotations

import re
from datetime import datetime
from re import Pattern
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target, TargetPath

HostdRecord = TargetRecordDescriptor(
    "esxi/log/hostd",
    [
        ("datetime", "ts"),
        ("string", "log_level"),
        ("string", "application"),
        ("string", "pid"),
        ("string", "op_id"),
        ("string", "user"),
        ("string", "event_metadata"),
        ("string", "message"),
        ("path", "source"),
    ],
)


class HostdPlugin(Plugin):
    """Unix audit log plugin."""

    RE_HOSTD: Pattern = re.compile(
        r"""
        (
            (?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z) # ts, including milliseconds
            \s
            ((?P<log_level>[\w()]+)\s)? # info, warning, of In(166), Wa(164), Er(163) in esxi8+
            ((?P<application>(\w+|-))\[(?P<pid>(\d+))\]|-):?\s  # hostd[pid] < esxi8, Hostd[pid]: esxi8+

        )?
       (?P<newline_delimiter>--> ?)? # in Exi8+, newline marker is positionned after the ts loglevel application part
       # but for some log this marker is missing...
       (\[(?P<metadata>(.+?))\]\s)?
       (?P<message>.*?)""",
        re.VERBOSE,
    )

    def __init__(self, target: Target):
        super().__init__(target)
        self.log_paths = self.get_log_paths()

    def check_compatible(self) -> None:
        if not len(self.log_paths):
            raise UnsupportedPluginError("No hostd path found")

    def get_log_paths(self) -> list[TargetPath]:
        log_paths = []

        log_paths.extend(self.target.fs.path("/var/log").glob("hostd.*"))
        log_paths.extend(self.target.fs.path("/var/run/log").glob("hostd.*"))
        log_paths.extend(self.target.fs.path("/var/lib/vmware/osdata").glob("hostd.*"))
        if osdata_fs := self.target.osdata_fs():
            log_paths.extend(osdata_fs.glob("log/hostd.*"))
        return log_paths

    @export(record=HostdRecord)
    def hostd(self) -> Iterator[HostdRecord]:
        """Return CentOS and RedHat audit information stored in /var/log/audit*.

        The audit log file on a Linux machine stores security-relevant information.
        Based on pre-configured rules. Log messages consist of space delimited key=value pairs.

        References:
            - https://knowledge.broadcom.com/external/article/306962/location-of-esxi-log-files.html
        """
        for path in self.log_paths:
            try:
                path = path.resolve(strict=True)
                current_record = None
                for line in open_decompress(path, "rt"):
                    if not line:
                        continue
                    line = line.strip("\n")
                    # For multiline event, line start with --> Before Esxi8
                    # For Esxi8+, --> is after the Date loglevel application[pid] block
                    if match := self.RE_HOSTD.fullmatch(line):
                        log = match.groupdict()
                        if log.get("newline_delimiter") == "-->" or log.get("ts") is None:
                            # for multiline log entries --> should be present, but sometime this marker is missing
                            current_record.message = current_record.message + "\n" + log.get("message")
                        else:
                            if current_record:
                                yield current_record
                            current_record = None
                            if metadata := log.get("metadata"):
                                user = re.search(r"user=(\S+)", metadata)
                                op_id = re.search(r"opID=(\S+)", metadata)
                            else:
                                user = None
                                op_id = None
                            current_record = HostdRecord(
                                _target=self.target,
                                message=log.get("message", ""),
                                log_level=log.get("log_level", None),
                                application=log.get("application", None),
                                pid=log.get("pid", None),
                                user=None if user is None else user.groups()[0],
                                op_id=None if op_id is None else op_id.groups()[0],
                                event_metadata=log.get("metadata", ""),
                                ts=datetime.strptime(log["ts"], "%Y-%m-%dT%H:%M:%S.%f%z"),
                                source=path,
                            )
                    else:
                        print("NO MATCH")
                        self.target.log.warning("log file contains unrecognized format in %s", path)
                        self.target.log.warning("log file contains unrecognized format in %s : %s", path, line)
                        continue
                if current_record:
                    yield current_record
            except Exception as e:
                self.target.log.warning("An error occurred parsing hostd log file %s: %s", path, str(e), exc_info=e)
                self.target.log.debug("", exc_info=e)
