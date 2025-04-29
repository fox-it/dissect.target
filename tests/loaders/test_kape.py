from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import patch

from dissect.target.loaders.kape import KapeLoader
from tests._utils import absolute_path, mkdirs

if TYPE_CHECKING:
    from dissect.target.target import Target


@patch("dissect.target.filesystems.dir.DirectoryFilesystem.ntfs", None, create=True)
def test_kape_dir_loader(target_bare: Target, tmp_path: Path) -> None:
    root = tmp_path
    mkdirs(root, ["C/windows/system32", "C/$Extend", "D/test", "E/test"])

    # Only need this to exist up until the root directory record to make dissect.ntfs happy
    with absolute_path("_data/plugins/filesystem/ntfs/mft/mft.raw").open("rb") as fh:
        (root / "C/$MFT").write_bytes(fh.read(10 * 1024))

    # Add one record so we can test if it works
    data = bytes.fromhex(
        "5800000002000000c100000000000100bf000000000001002003010000000000"
        "6252641a86a4d7010381008000000000000000002000000018003c0069007300"
        "2d00310035005000320036002e0074006d00700000000000"
    )
    (root / "C/$Extend/$J").write_bytes(data)

    assert KapeLoader.detect(root)

    loader = KapeLoader(root)
    loader.map(target_bare)
    target_bare.apply()

    assert "sysvol" in target_bare.fs.mounts
    assert "c:" in target_bare.fs.mounts
    assert "d:" in target_bare.fs.mounts
    assert "e:" in target_bare.fs.mounts

    # The 3 found drive letter directories + the fake NTFS filesystem
    assert len(target_bare.filesystems) == 4
    # The 3 found drive letters + sysvol + the fake NTFS filesystem at /$fs$
    assert len(target_bare.fs.mounts) == 5
    assert len(list(target_bare.fs.mounts["c:"].ntfs.usnjrnl.records())) == 1


def test_kape_vhdx_loader(target_bare: Target) -> None:
    p = Path(absolute_path("_data/loaders/kape/test.vhdx"))

    assert KapeLoader.detect(p)

    loader = KapeLoader(p)
    loader.map(target_bare)
    target_bare.apply()

    assert "sysvol" in target_bare.fs.mounts
    assert "c:" in target_bare.fs.mounts
