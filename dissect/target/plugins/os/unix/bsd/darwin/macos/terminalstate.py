from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


TerminalStateRecord = TargetRecordDescriptor(
    "macos/terminalstate/file",
    [
        ("string", "filename"),
        ("varint", "size"),
        ("path", "source"),
    ],
)


class MacOSTerminalStatePlugin(Plugin):
    """Plugin to list files in Terminal saved state.

    Terminal's saved state directory may contain window restore data,
    including previously displayed terminal content.
    """

    __namespace__ = "terminalstate"

    GLOBS = [
        "Users/*/Library/Saved Application State/com.apple.Terminal.savedState/*",
        "Users/*/Library/Daemon Containers/*/Data/Library/Saved Application State/com.apple.Terminal.savedState/*",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._file_paths = []
        root = self.target.fs.path("/")
        for g in self.GLOBS:
            self._file_paths.extend(root.glob(g))

    def check_compatible(self) -> None:
        if not self._file_paths:
            raise UnsupportedPluginError("No Terminal saved state files found")

    @export(record=TerminalStateRecord)
    def files(self) -> Iterator[TerminalStateRecord]:
        """List files in Terminal saved state directory."""
        for path in self._file_paths:
            try:
                if path.is_dir():
                    continue

                size = 0
                try:
                    stat = path.stat()
                    size = stat.st_size if hasattr(stat, "st_size") else 0
                except Exception:
                    pass

                yield TerminalStateRecord(
                    filename=path.name,
                    size=size,
                    source=path,
                    _target=self.target,
                )
            except Exception as e:
                self.target.log.warning("Error reading Terminal state file %s: %s", path, e)
