from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


TrashFileRecord = TargetRecordDescriptor(
    "macos/trash/file",
    [
        ("datetime", "ts_modified"),
        ("string", "filename"),
        ("varint", "size_bytes"),
        ("string", "trash_location"),
        ("path", "source"),
    ],
)

TrashICloudRecord = TargetRecordDescriptor(
    "macos/trash/icloud",
    [
        ("datetime", "ts_modified"),
        ("string", "filename"),
        ("varint", "size_bytes"),
        ("string", "trash_location"),
        ("path", "source"),
    ],
)


class MacOSTrashPlugin(Plugin):
    """Plugin to parse macOS Trash contents.

    Locations:
    - ~/.Trash/ (user trash)
    - /.Trashes/<uid>/ (volume-level trash)
    - ~/Library/Mobile Documents/.Trash/ (iCloud trash)
    """

    __namespace__ = "trash"

    TRASH_GLOBS = [
        "Users/*/.Trash/*",
        "Users/*/%2ETrash/*",
        ".Trashes/*/*",
        "%2ETrashes/*/*",
    ]

    ICLOUD_TRASH_GLOBS = [
        "Users/*/Library/Mobile Documents/.Trash/*",
        "Users/*/Library/Mobile Documents/%2ETrash/*",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._trash_paths = []
        for pattern in self.TRASH_GLOBS:
            for path in self.target.fs.path("/").glob(pattern):
                if path.name.startswith("."):
                    continue
                self._trash_paths.append(path)

        self._icloud_trash_paths = []
        for pattern in self.ICLOUD_TRASH_GLOBS:
            for path in self.target.fs.path("/").glob(pattern):
                if path.name.startswith("."):
                    continue
                self._icloud_trash_paths.append(path)

    def check_compatible(self) -> None:
        # Always compatible on macOS — Trash dirs exist even if empty
        pass

    def _stat_file(self, path):
        try:
            stat = path.stat()
            size = stat.st_size if hasattr(stat, "st_size") else 0
            mtime = stat.st_mtime if hasattr(stat, "st_mtime") else 0
            ts = datetime.fromtimestamp(mtime, tz=timezone.utc) if mtime else datetime(2001, 1, 1, tzinfo=timezone.utc)
            return ts, size
        except Exception:
            return datetime(2001, 1, 1, tzinfo=timezone.utc), 0

    @export(record=TrashFileRecord)
    def files(self) -> Iterator[TrashFileRecord]:
        """List files in the user Trash and volume-level .Trashes."""
        for path in self._trash_paths:
            try:
                ts, size = self._stat_file(path)
                # Determine trash location
                path_str = str(path)
                location = "volume" if "/.Trashes/" in path_str else "user"

                yield TrashFileRecord(
                    ts_modified=ts,
                    filename=path.name,
                    size_bytes=size,
                    trash_location=location,
                    source=path,
                    _target=self.target,
                )
            except Exception as e:
                self.target.log.warning("Error reading trash item %s: %s", path, e)

    @export(record=TrashICloudRecord)
    def icloud(self) -> Iterator[TrashICloudRecord]:
        """List files in the iCloud Drive trash (~/Library/Mobile Documents/.Trash/)."""
        for path in self._icloud_trash_paths:
            try:
                ts, size = self._stat_file(path)
                yield TrashICloudRecord(
                    ts_modified=ts,
                    filename=path.name,
                    size_bytes=size,
                    trash_location="icloud",
                    source=path,
                    _target=self.target,
                )
            except Exception as e:
                self.target.log.warning("Error reading iCloud trash item %s: %s", path, e)
