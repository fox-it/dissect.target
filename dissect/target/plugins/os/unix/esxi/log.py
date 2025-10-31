from __future__ import annotations

import abc
import re
from abc import ABC
from datetime import datetime
from re import Pattern
from typing import TYPE_CHECKING, ClassVar

from dissect.target.exceptions import FilesystemError, UnsupportedPluginError
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import OperatingSystem, Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target, TargetPath

ESXiLogRecord = TargetRecordDescriptor(
    "esxi/log",
    [
        ("datetime", "ts"),
        ("string", "type"),
        ("string", "log_level"),
        ("string", "application"),
        ("varint", "pid"),
        ("string", "op_id"),
        ("string", "user"),
        ("string", "event_metadata"),
        ("string", "message"),
        ("path", "source"),
    ],
)


class EsxiLogBasePlugin(Plugin, ABC):
    """Esxi base log plugin."""

    # ESXi relies a lot on symlink, depending on version/collection log dir may change...
    __register__ = False
    COMMON_LOG_LOCATION: ClassVar[list[str]] = ["/var/log", "/var/run/log", "/scratch/log", "/var/lib/vmware/osdata"]
    RE_LOG_FORMAT: ClassVar[Pattern] = re.compile(
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
        # Log path as the same as on other unix target, so we fail fast
        if not self.target.os == OperatingSystem.ESXI:
            raise UnsupportedPluginError(f"No {self.logname} path found")
        if not len(self.log_paths):
            raise UnsupportedPluginError("Not an ESXi host")

    @property
    @abc.abstractmethod
    def logname(self) -> str:
        """
        base name of the log file (e.g : shell, auth, hostd)
        """

    def get_log_paths(self) -> list[TargetPath]:
        log_paths = []
        for log_location in self.COMMON_LOG_LOCATION:
            for path in self.target.fs.path(log_location).glob(f"{self.logname}.*"):
                try:
                    log_paths.append(path.resolve(strict=True))
                except FilesystemError as e:  # noqa PERF203
                    self.target.info.warning("Fail to resolve path to %s : %s", path, str(e))

        if osdata_fs := self.target.osdata_fs():
            log_paths.extend(osdata_fs.glob(f"log/{self.logname}.*"))
        return list(set(log_paths))

    def yield_log_records(self) -> Iterator[ESXiLogRecord]:
        """Return CentOS and RedHat audit information stored in /var/log/audit*.

        The audit log file on a Linux machine stores security-relevant information.
        Based on pre-configured rules. Log messages consist of space delimited key=value pairs.

        References:
            - https://knowledge.broadcom.com/external/article/306962/location-of-esxi-log-files.html
        """
        for path in self.log_paths:
            try:
                current_record = None
                for line in open_decompress(path, "rt"):
                    if not line:
                        continue
                    line = line.strip("\n")
                    # For multiline event, line start with --> Before Esxi8
                    # For Esxi8+, --> is after the Date loglevel application[pid] block
                    if match := self.RE_LOG_FORMAT.fullmatch(line):
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
                            current_record = ESXiLogRecord(
                                _target=self.target,
                                type=self.logname,
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
                        self.target.log.warning("log file contains unrecognized format in %s", path)
                        self.target.log.warning("log file contains unrecognized format in %s : %s", path, line)
                        continue
                if current_record:
                    yield current_record
            except Exception as e:
                self.target.log.warning(
                    "An error occurred parsing %s log file %s: %s", self.logname, path, str(e), exc_info=e
                )
                self.target.log.debug("", exc_info=e)


class HostdPlugin(EsxiLogBasePlugin):
    """ESXi hostd logs plugins"""

    __register__ = True

    @export(record=ESXiLogRecord)
    def hostd(self) -> Iterator[ESXiLogRecord]:
        """
        Records for hostd log file (Host management service logs, including virtual machine and host Task and Events)
        """
        yield from self.yield_log_records()

    @property
    def logname(self) -> str:
        return "hostd"


class EsxiAuthPLugin(EsxiLogBasePlugin):
    """ESXi auth logs plugins"""

    __register__ = True

    @export(record=ESXiLogRecord)
    def auth(self) -> Iterator[ESXiLogRecord]:
        """
        Records for auth log file (ESXi Shell authentication success and failure.)
        """
        yield from self.yield_log_records()

    @property
    def logname(self) -> str:
        return "auth"
