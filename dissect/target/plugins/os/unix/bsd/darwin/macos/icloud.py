from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


ICloudFileRecord = TargetRecordDescriptor(
    "macos/icloudfiles/file",
    [
        ("string", "filename"),
        ("string", "file_path"),
        ("varint", "size"),
        ("path", "source"),
    ],
)


class MacOSICloudFilesPlugin(Plugin):
    """Plugin to list files in iCloud Drive local storage.

    Files synced via iCloud Drive are stored under each user's
    ~/Library/Mobile Documents/com~apple~CloudDocs/ directory.
    """

    __namespace__ = "icloudfiles"

    GLOBS = [
        "Users/*/Library/Mobile Documents/com~apple~CloudDocs/*",
        "Users/*/Library/Mobile Documents/com~apple~CloudDocs/*/*",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._file_paths = []
        for pattern in self.GLOBS:
            for path in self.target.fs.path("/").glob(pattern):
                self._file_paths.append(path)

    def check_compatible(self) -> None:
        if not self._file_paths:
            raise UnsupportedPluginError("No iCloud Drive files found")

    @export(record=ICloudFileRecord)
    def files(self) -> Iterator[ICloudFileRecord]:
        """List files in iCloud Drive local storage."""
        for path in self._file_paths:
            try:
                # Skip directories
                try:
                    if path.is_dir():
                        continue
                except Exception:
                    pass

                size = 0
                try:
                    stat = path.stat()
                    size = stat.st_size if hasattr(stat, "st_size") else 0
                except Exception:
                    pass

                yield ICloudFileRecord(
                    filename=path.name,
                    file_path=str(path),
                    size=size,
                    source=path,
                    _target=self.target,
                )
            except Exception as e:
                self.target.log.warning("Error reading iCloud file %s: %s", path, e)
