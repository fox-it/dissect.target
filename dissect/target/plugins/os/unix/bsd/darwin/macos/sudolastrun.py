from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


SudoLogRecord = TargetRecordDescriptor(
    "macos/sudolog/entry",
    [
        ("string", "username"),
        ("datetime", "ts_last_sudo"),
        ("path", "source"),
    ],
)


class MacOSSudoLastRunPlugin(Plugin):
    """Plugin to parse macOS sudo timestamp files.

    Each file in /private/var/db/sudo/ts/ or /private/var/run/sudo/ts/
    is named after the user who ran sudo. The file mtime indicates
    when sudo was last used by that user.
    """

    __namespace__ = "sudolog"

    TS_GLOBS = [
        "private/var/db/sudo/ts/*",
        "private/var/run/sudo/ts/*",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._ts_paths = []
        for pattern in self.TS_GLOBS:
            for path in self.target.fs.path("/").glob(pattern):
                self._ts_paths.append(path)

    def check_compatible(self) -> None:
        if not self._ts_paths:
            raise UnsupportedPluginError("No sudo timestamp files found")

    @export(record=SudoLogRecord)
    def entries(self) -> Iterator[SudoLogRecord]:
        """Parse sudo timestamp files to determine last sudo usage per user."""
        for path in self._ts_paths:
            try:
                username = path.name
                stat = path.stat()
                mtime = stat.st_mtime if hasattr(stat, "st_mtime") else 0
                if mtime:
                    ts = datetime.fromtimestamp(mtime, tz=timezone.utc)
                else:
                    ts = datetime(2001, 1, 1, tzinfo=timezone.utc)

                yield SudoLogRecord(
                    username=username,
                    ts_last_sudo=ts,
                    source=path,
                    _target=self.target,
                )
            except Exception as e:
                self.target.log.warning("Error reading sudo ts file %s: %s", path, e)
