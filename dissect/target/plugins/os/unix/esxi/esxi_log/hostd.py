from collections.abc import Iterator
from pathlib import Path

from dissect.target import Target
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import OperatingSystem, Plugin, export
from dissect.target.plugins.os.unix.esxi.esxi_log import (
    RE_LOG_FORMAT,
    ESXiLogRecord,
    get_esxi_log_path,
    yield_log_records,
)


class HostdPlugin(Plugin):
    """ESXi hostd logs plugins"""

    def __init__(self, target: Target):
        super().__init__(target)
        self.log_paths: list[Path] = list(self.get_paths())

    def check_compatible(self) -> None:
        # Log path as the same as on other unix target, so we fail fast
        if not self.target.os == OperatingSystem.ESXI:
            raise UnsupportedPluginError("Not an ESXi host")
        if not len(self.log_paths):
            raise UnsupportedPluginError("No hostd logs found")

    def _get_paths(self) -> Iterator[Path]:
        yield from get_esxi_log_path(self.target, "hostd")

    @export(record=ESXiLogRecord)
    def hostd(self) -> Iterator[ESXiLogRecord]:
        """
        Records for hostd log file (Host management service logs, including virtual machine and host Task and Events)
        """
        yield from yield_log_records(self.target, self.log_paths, RE_LOG_FORMAT, "hostd")
