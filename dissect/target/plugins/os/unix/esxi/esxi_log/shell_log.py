from __future__ import annotations

import re
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import OperatingSystem, Plugin, export
from dissect.target.plugins.os.unix.esxi.esxi_log import (
    RE_APPLICATION,
    RE_LOG_LEVEL,
    RE_NEW_LINE,
    RE_TIMESTAMP,
    ESXiLogRecord,
    get_esxi_log_path,
    yield_log_records,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target import Target


class ShellLogPlugin(Plugin):
    """ESXi shell.log plugins."""

    # Mostly equal to EsxiLogBasePlugin.RE_LOG_FORMAT, but some difference in metadata part
    RE_LOG_FORMAT: re.Pattern = re.compile(
        rf"""
            {RE_TIMESTAMP}?
            (
                {RE_LOG_LEVEL}?
                {RE_APPLICATION}\s
            )?
       {RE_NEW_LINE}?
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
        """Records for shell.log files (ESXi Shell usage logs, including enable/disable and every command entered).

        References:
            - https://knowledge.broadcom.com/external/article/321910
        """
        for record in yield_log_records(self.target, self.log_paths, self.RE_LOG_FORMAT, "shell"):
            record.user = record.event_metadata
            record.event_metadata = None
            yield record
