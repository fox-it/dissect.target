from collections.abc import Iterator
from typing import ClassVar

from dissect.target import Target
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.windows.everything.everything_types import (
    EverythingDBParser,
)

EverythingRecord = TargetRecordDescriptor(
    "windows/everything/everything_record",
    [
        ("string", "path"),
        ("filesize", "size"),
        ("datetime", "date_created"),
        ("datetime", "date_modified"),
        ("datetime", "date_accessed"),
        ("uint32", "attributes"),
        ("string", "record_type"),
        ("string", "source"),
    ],
)


class EverythingPlugin(Plugin):
    """Voidtools Everything database parser
    Extracts files and metadata from the Everything database, which is stored in a proprietary format
    """

    __namespace__ = "everything"

    PATH_GLOBS: ClassVar = [
        "C:\\Program Files\\Everything\\Everything*.db",
        "C:\\Program Files (x86)\\Everything\\Everything*.db",
    ]
    USER_PATH: ClassVar = "AppData\\Local\\Everything\\Everything*.db"

    def __init__(self, target: Target):
        super().__init__(target)
        self.configs = []
        for path_option in self.PATH_GLOBS:
            self.configs.extend(self.target.fs.path().glob(path_option))

        self.configs.extend(self.find_user_files())

    def find_user_files(self) -> Iterator[TargetPath]:
        for user_details in self.target.user_details.all_with_home():
            yield from user_details.home_path.glob(self.USER_PATH)

    def check_compatible(self) -> None:
        if not self.configs:
            raise UnsupportedPluginError("No everything.db files found")

    @export(record=EverythingRecord)
    def locate(self) -> Iterator[EverythingRecord]:
        """Yield file and directory names from everything.db file."""
        for path in self.configs:
            try:
                with self.target.fs.path(path).open() as everything_fh:
                    everything_file = EverythingDBParser(everything_fh)

                    for item in everything_file:
                        yield EverythingRecord(
                            path=item.file_path,
                            size=item.size,
                            date_created=item.date_created,
                            date_modified=item.date_modified,
                            date_accessed=item.date_accessed,
                            attributes=item.attributes,
                            record_type=item.file_type,
                            source=path,
                            _target=self.target,
                        )
            except (NotImplementedError, ValueError) as e:  # noqa: PERF203
                self.target.log.warning("Invalid EverythingDB %s: %s", path, e)
