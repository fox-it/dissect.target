import re
from collections.abc import Iterator
from pathlib import Path

from dissect.target import Target
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import OperatingSystem, Plugin, export
from dissect.target.plugins.os.unix.esxi.esxi_log import (
    ESXiLogRecord,
    get_esxi_log_path,
    yield_log_records,
)


class ShellLogPlugin(Plugin):
    """ESXi shell.log plugins"""

    # Mostly equal to EsxiLogBasePlugin.RE_LOG_FORMAT, but some difference in metadata part
    RE_LOG_FORMAT: re.Pattern = re.compile(
        r"""
        ((?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z)\s)? # ts, moslty including milliseconds, but not always
        (
            ((?P<log_level>[\w()]+)\s)? # info, warning, of In(166), Wa(164), Er(163) in esxi8+, sometime missing
            ((?P<application>(\w+))\[(?P<pid>(\d+))\]):?\s  # hostd[pid] < esxi8, Hostd[pid]: esxi8+

        )?
       (?P<newline_delimiter>--> ?)? # in Exi8+, newline marker is positionned after the ts loglevel application part
       # but for some log this marker is missing...
       (\[(?P<metadata>(.+?))\]:\s)? # Metadata = user. Instead of \s, metadata is followed by a ":"
       (?P<message>.*?)""",
        re.VERBOSE,
    )

    def __init__(self, target: Target):
        super().__init__(target)
        self.log_paths: list[Path] = list(self.get_paths())

    def check_compatible(self) -> None:
        # Log path as the same as on other unix target, so we fail fast
        if not self.target.os == OperatingSystem.ESXI:
            raise UnsupportedPluginError("Not an ESXi host")
        if not len(self.log_paths):
            raise UnsupportedPluginError("No log found")

    def _get_paths(self) -> Iterator[Path]:
        yield from get_esxi_log_path(self.target, "shell")

    @export(record=ESXiLogRecord)
    def shell_log(self) -> Iterator[ESXiLogRecord]:
        """
        Records for shell.log files (ESXi Shell usage logs, including enable/disable and every command entered).

        References:
            - https://knowledge.broadcom.com/external/article/321910
        """
        for record in yield_log_records(self.target, self.log_paths, self.RE_LOG_FORMAT, "shell"):
            record.user = record.event_metadata
            record.event_metadata = None
            yield record
