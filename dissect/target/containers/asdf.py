import io

from dissect.evidence import AsdfSnapshot, AsdfStream
from dissect.evidence.asdf import FILE_MAGIC
from dissect.target.container import Container


class AsdfContainer(Container):
    def __init__(self, fh, *args, **kwargs):
        file_container = fh

        if not hasattr(file_container, "read"):
            file_container = AsdfSnapshot(fh.open("rb"))

        if isinstance(file_container, AsdfSnapshot):
            file_container = fh.open(0)

        if not isinstance(file_container, AsdfStream):
            raise TypeError(f"Invalid type for AsdfContainer: {fh}")

        self.asdf = file_container

        super().__init__(fh, self.asdf.size, *args, **kwargs)

    @staticmethod
    def detect_fh(fh, original):
        magic = fh.read(4)
        fh.seek(-4, io.SEEK_CUR)

        return magic == FILE_MAGIC

    @staticmethod
    def detect_path(path, original):
        return path.suffix.lower() == ".asdf"

    def read(self, length):
        return self.asdf.read(length)

    def seek(self, offset, whence=io.SEEK_SET):
        self.asdf.seek(offset, whence)

    def tell(self):
        return self.asdf.tell()

    def close(self):
        self.asdf.close()
