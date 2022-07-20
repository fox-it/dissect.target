import io

from dissect.hypervisor import vhd

from dissect.target.container import Container


class VhdContainer(Container):
    def __init__(self, fh, *args, **kwargs):
        f = fh
        if not hasattr(fh, "read"):
            f = fh.open("rb")
        self.vhd = vhd.VHD(f)

        super().__init__(fh, self.vhd.size, *args, **kwargs)

    @staticmethod
    def detect_fh(fh, original):
        offset = fh.tell()
        fh.seek(-512, io.SEEK_END)
        magic = fh.read(9)
        fh.seek(offset)

        return b"conectix" in magic

    @staticmethod
    def detect_path(path, original):
        return path.suffix.lower() == ".vhd"

    def read(self, length):
        return self.vhd.read(length)

    def seek(self, offset, whence=io.SEEK_SET):
        self.vhd.seek(offset, whence)

    def tell(self):
        return self.vhd.tell()

    def close(self):
        pass
