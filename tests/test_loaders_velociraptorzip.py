import shutil
from pathlib import Path

from dissect.target.loaders.velociraptorzip import VelociraptorZipLoader

from ._utils import absolute_path, mkdirs


def test_velociraptorzip_loader_windows_ntfs(mock_target, tmp_path):
    root = tmp_path

    mkdirs(
        root,
        [
            "uploads/auto/C%3A/Windows/System32",
            "uploads/ntfs/%5C%5C.%5CC%3A/$Extend",
            "uploads/lazy_ntfs/%5C%5C.%5CD%3A",  # D drive
            "uploads/mft/%5C%5C%3F%5CGLOBALROOT%5CDevice%5CHarddiskVolumeShadowCopy1",
        ],
    )

    (root / "uploads.json").write_bytes(b"{}")

    with open(absolute_path("data/mft.raw"), "rb") as fh:
        (root / "uploads/ntfs/%5C%5C.%5CC%3A/$MFT").write_bytes(fh.read(10 * 1025))

    # Add one record so we can test if it works
    data = bytes.fromhex(
        "5800000002000000c100000000000100bf000000000001002003010000000000"
        "6252641a86a4d7010381008000000000000000002000000018003c0069007300"
        "2d00310035005000320036002e0074006d00700000000000"
    )
    (root / "uploads/ntfs/%5C%5C.%5CC%3A/$Extend/$UsnJrnl%3A$J").write_bytes(data)

    shutil.make_archive(f"{tmp_path}/test", "zip", tmp_path)

    zip_path = Path(f"{tmp_path}/test.zip")
    assert VelociraptorZipLoader.detect(zip_path) is True

    loader = VelociraptorZipLoader(zip_path)
    loader.map(mock_target)

    assert len(list(mock_target.usnjrnl())) == 1
    assert len(mock_target.filesystems) == 3
