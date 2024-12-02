import io
from pathlib import Path

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.loaders.single import SingleFileLoader


def test_single_loader(target_default: Target) -> None:
    path = Path("test/single.txt")
    vfs = VirtualFilesystem()
    vfs.map_file_fh("test/single.txt", io.BytesIO(b"\x00"))
    log_loader = SingleFileLoader(vfs.path(path))
    log_loader.map(target_default)

    assert target_default.fs.exists("$drop$/single.txt")
