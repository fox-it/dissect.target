import io

from dissect.hypervisor import vdi

from dissect.target.container import Container


class VdiContainer(Container):
    """VirtualBox hard disks"""

    def __init__(self, fh, *args, **kwargs):
        f = fh
        if not hasattr(fh, "read"):
            f = fh.open("rb")
        self.vdi = vdi.VDI(f)

        super().__init__(fh, self.vdi.size, *args, **kwargs)

    @staticmethod
    def detect_fh(fh, original):
        magic = fh.read(68)
        fh.seek(-68, io.SEEK_CUR)

        return magic[-4:] == 0xBEDA107F

    @staticmethod
    def detect_path(path, original):
        return path.suffix.lower() == ".vdi"

    def read(self, length):
        return self.vdi.read(length)

    def seek(self, offset, whence=io.SEEK_SET):
        self.vdi.seek(offset, whence)

    def tell(self):
        return self.vdi.tell()

    def close(self):
        pass
