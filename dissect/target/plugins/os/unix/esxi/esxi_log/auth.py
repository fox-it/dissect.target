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


class EsxiAuthPlugin(Plugin):
    """ESXi auth.log plugins"""

    def __init__(self, target: Target):
        super().__init__(target)
        self.log_paths: list[Path] = list(self.get_paths())

    def check_compatible(self) -> None:
        # Log path as the same as on other unix target, so we fail fast
        if not self.target.os == OperatingSystem.ESXI:
            raise UnsupportedPluginError("Not an ESXi host")
        if not len(self.log_paths):
            raise UnsupportedPluginError("No auth logs found")

    def _get_paths(self) -> Iterator[Path]:
        yield from get_esxi_log_path(self.target, "auth")

    @export(record=ESXiLogRecord)
    def auth(self) -> Iterator[ESXiLogRecord]:
        """
        Records for auth log file (ESXi Shell authentication success and failure.) Seems to be empty in ESXi8+
        """
        yield from yield_log_records(self.target, self.log_paths, RE_LOG_FORMAT, "auth")
