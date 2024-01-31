from typing import Iterator, Union

from dissect.target import Target
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.locate.everything import (
    EverythingDirectory,
    EverythingFile,
    EverythingDBParser,
)
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import export
from dissect.target.plugin import Plugin

EverythingDirectoryRecord = TargetRecordDescriptor(
    "windows/everything/everything_directory",
    [
        ("string", "path"),
        ("filesize", "size"),
        ("datetime", "date_created"),
        ("datetime", "date_modified"),
        ("datetime", "date_accessed"),
        ("uint32", "attributes"),
        ("string", "source"),
    ],
)

EverythingFileRecord = TargetRecordDescriptor(
    "windows/everything/everything_file",
    [
        ("string", "path"),
        ("filesize", "size"),
        ("datetime", "date_created"),
        ("datetime", "date_modified"),
        ("datetime", "date_accessed"),
        ("uint32", "attributes"),
        ("string", "source"),
    ],
)

EverythingRecord = Union[
    EverythingFileRecord,
    EverythingDirectoryRecord,
]


class EverythingPlugin(Plugin):
    __namespace__ = "everything"

    PATH_GLOBS = [
        "C:\\Program Files\\Everything\\Everything*.db",
        "C:\\Program Files (x86)\\Everything\\Everything*.db",
    ]
    USER_PATH = "AppData\\Local\\Everything\\Everything*.db"

    def __init__(self, target: Target):
        super().__init__(target)
        self.configs = []

    def find_user_files(self):
        for user_details in self.target.user_details.all_with_home():
            for db in user_details.home_path.glob(self.USER_PATH):
                if db.exists():
                    yield db

    def check_compatible(self) -> None:
        for path_option in self.PATH_GLOBS:
            for path in self.target.fs.path().glob(path_option):
                if path.exists():
                    self.configs.append(path)

        for path in self.find_user_files():
            self.configs.append(path)

        if not self.configs:
            raise UnsupportedPluginError("No everything.db files found")

    @export(record=EverythingRecord)
    def locate(self) -> Iterator[EverythingRecord]:
        """Yield file and directory names from everything.db file.
        """
        for path in self.configs:
            everything_fh = self.target.fs.path(path).open()
            everything_file = EverythingDBParser(everything_fh)

            for item in everything_file:
                if isinstance(item, EverythingDirectory):
                    typ = EverythingDirectoryRecord
                elif isinstance(item, EverythingFile):
                    typ = EverythingFileRecord
                else:
                    raise NotImplementedError(f"type {type(item)} is not Recordable")
                yield typ(
                    path=item.file_path,
                    size=item.size,
                    date_created=item.date_created,
                    date_modified=item.date_modified,
                    date_accessed=item.date_accessed,
                    attributes=item.attributes,
                    source=path,
                    _target=self.target
                )
