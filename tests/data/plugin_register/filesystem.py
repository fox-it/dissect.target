from typing import BinaryIO, Optional

from dissect.target.filesystem import Filesystem, FilesystemEntry, register
from dissect.target.volume import Volume


class TestFilesystem(Filesystem):

    __fstype__: str = "Data"

    def __init__(
        self, case_sensitive: bool = True, alt_separator: Optional[str] = None, volume: Optional[Volume] = None
    ) -> None:
        super().__init__(case_sensitive, alt_separator, volume)
        print("Helloworld from TestFilesystem")

    def get(self, path: str) -> FilesystemEntry:
        pass

    def detect(fh: BinaryIO):
        return False


register(__name__, TestFilesystem.__name__, internal=False)
