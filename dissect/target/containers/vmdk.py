import io
from pathlib import Path
from typing import BinaryIO, Union

from dissect.hypervisor import vmdk

from dissect.target.container import Container


class VmdkContainer(Container):
    """VMWare hard disks"""

    __type__ = "vmdk"

    def __init__(self, fh: Union[BinaryIO, Path], *args, **kwargs):
        self.vmdk = vmdk.VMDK(fh)
        super().__init__(fh, self.vmdk.size, *args, **kwargs)

    @staticmethod
    def _detect_fh(fh: BinaryIO, original: Union[list, BinaryIO]) -> bool:
        return fh.read(4) in (b"KDMV", b"COWD", b"# Di")

    @staticmethod
    def detect_path(path: Path, original: Union[list, BinaryIO]) -> bool:
        return path.suffix.lower().endswith(".vmdk")

    def read(self, length: int) -> bytes:
        return self.vmdk.read(length)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self.vmdk.seek(offset, whence)

    def tell(self) -> int:
        return self.vmdk.tell()

    def close(self) -> None:
        pass
