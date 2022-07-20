import io

from dissect.hypervisor import vmdk

from dissect.target.container import Container


class VmdkContainer(Container):
    """VMWare hard disks"""

    def __init__(self, fh, *args, **kwargs):
        self.vmdk = vmdk.VMDK(fh)
        super().__init__(fh, self.vmdk.size, *args, **kwargs)

    @staticmethod
    def detect_fh(fh, original):
        magic = fh.read(4)
        fh.seek(-4, io.SEEK_CUR)

        return magic in (b"KDMV", b"COWD", b"# Di")

    @staticmethod
    def detect_path(path, original):
        return path.suffix.lower().endswith(".vmdk")

    def read(self, length):
        return self.vmdk.read(length)

    def seek(self, offset, whence=io.SEEK_SET):
        self.vmdk.seek(offset, whence)

    def tell(self):
        return self.vmdk.tell()

    def close(self):
        pass
