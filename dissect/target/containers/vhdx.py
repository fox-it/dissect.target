import io

from dissect.hypervisor import vhdx

from dissect.target.container import Container


class VhdxContainer(Container):
    def __init__(self, fh, *args, **kwargs):
        self.vhdx = vhdx.VHDX(fh)
        super().__init__(fh, self.vhdx.size, *args, **kwargs)

    @staticmethod
    def detect_fh(fh, original):
        magic = fh.read(8)
        fh.seek(-8, io.SEEK_CUR)

        return magic == b"vhdxfile"

    @staticmethod
    def detect_path(path, original):
        return path.suffix.lower() in (".vhdx", ".avhdx")

    def read(self, length):
        return self.vhdx.read(length)

    def seek(self, offset, whence=io.SEEK_SET):
        self.vhdx.seek(offset, whence)

    def tell(self):
        return self.vhdx.tell()

    def close(self):
        pass
