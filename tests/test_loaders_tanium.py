from pathlib import Path
from unittest.mock import patch

from dissect.target.loaders.tanium import TaniumLoader

from ._utils import absolute_path, mkdirs


@patch("dissect.target.filesystems.dir.DirectoryFilesystem.ntfs", None, create=True)
def test_tanium_loader(mock_target, tmpdir_name):
    root = Path(tmpdir_name)
    mkdirs(root, ["file/C/windows/system32", "file/C/$Extend", "file/D/test", "file/E/test"])

    # Only need this to exist up until the root directory record to make dissect.ntfs happy
    with open(absolute_path("data/mft.raw"), "rb") as fh:
        (root / "file/C/$MFT").write_bytes(fh.read(10 * 1025))

    # Add one record so we can test if it works
    data = bytes.fromhex(
        "5800000002000000c100000000000100bf000000000001002003010000000000"
        "6252641a86a4d7010381008000000000000000002000000018003c0069007300"
        "2d00310035005000320036002e0074006d00700000000000"
    )
    (root / "file/C/$Extend/$UsnJrnl_$J").write_bytes(data)

    assert TaniumLoader.detect(root)

    loader = TaniumLoader(root)
    loader.map(mock_target)

    # The 3 found drive letter directories + the fake NTFS filesystem
    assert len(mock_target.filesystems) == 4
    assert len(mock_target.fs.mounts) == 3
    assert len(list(mock_target.usnjrnl())) == 1
