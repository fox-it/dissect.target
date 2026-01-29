from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest
from dissect.ntfs import NTFS

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.filesystems.dir import DirectoryFilesystem
from dissect.target.helpers import loaderutil
from dissect.target.tools.mount import main as target_mount
from dissect.target.volume import Volume
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target


@pytest.fixture
def mock_ntfs_dirfs(tmp_path: Path) -> Path:
    root = tmp_path

    # Cleanup first (conftest creates a MockTarget- tempfile)
    for item in root.iterdir():
        item.unlink()

    # Create files
    (root / "$Boot").touch()
    (root / "$Extend_$Usnjrnl_$J").touch()
    (root / "$Secure_$SDS").touch()

    # Only need this to exist up until the root directory record to make dissect.ntfs happy
    with absolute_path("_data/plugins/filesystem/ntfs/mft/mft.raw").open("rb") as fh:
        (root / "$MFT").write_bytes(fh.read(10 * 1024))

    return root


def test_duplicate_volume_name(target_bare: Target, monkeypatch: pytest.MonkeyPatch) -> None:
    with monkeypatch.context() as m:
        m.setattr("sys.argv", ["target-mount", "mock-target", "mock-mount"])
        m.setattr("dissect.target.tools.mount.HAS_FUSE", True)

        with (
            patch("dissect.target.tools.mount.open_target", return_value=target_bare),
            patch("dissect.target.tools.mount.FUSE", create=True) as MockFUSE,
            patch("dissect.target.tools.mount.DissectMount", create=True) as MockDissectMount,
        ):
            target_bare.volumes.add(Volume(BytesIO(), 1, 0, 0, None, name="first"))
            target_bare.volumes.add(Volume(BytesIO(), 2, 0, 0, None, name="second"))
            target_bare.volumes.add(Volume(BytesIO(), 3, 0, 0, None, name="second_1"))
            target_bare.volumes.add(Volume(BytesIO(), 4, 0, 0, None, name="second"))

            mock_fs = VirtualFilesystem()
            mock_fs.volume = target_bare.volumes[1]
            target_bare.filesystems.add(mock_fs)
            mock_fs = VirtualFilesystem()
            mock_fs.volume = target_bare.volumes[2]
            target_bare.filesystems.add(mock_fs)
            mock_fs = VirtualFilesystem()
            mock_fs.volume = target_bare.volumes[3]
            target_bare.filesystems.add(mock_fs)

            target_mount()

            MockFUSE.assert_called_once()
            MockDissectMount.assert_called_once()
            vfs = MockDissectMount.call_args[0][0]

            assert vfs.listdir("/volumes") == ["first", "second", "second_1", "second_2"]
            assert vfs.listdir("/filesystems") == ["second", "second_1", "second_2"]


def test_mounting_multi_volume_filesystem(target_bare: Target, monkeypatch: pytest.MonkeyPatch) -> None:
    with monkeypatch.context() as m:
        m.setattr("sys.argv", ["target-mount", "mock-target", "mock-mount"])
        m.setattr("dissect.target.tools.mount.HAS_FUSE", True)

        with (
            patch("dissect.target.tools.mount.open_target", return_value=target_bare),
            patch("dissect.target.tools.mount.FUSE", create=True) as MockFUSE,
            patch("dissect.target.tools.mount.DissectMount", create=True) as MockDissectMount,
        ):
            volumes = [
                Volume(BytesIO(), 1, 0, 0, None, name="first"),
                Volume(BytesIO(), 2, 0, 0, None, name="second"),
            ]

            for vol in volumes:
                target_bare.volumes.add(vol)

            mock_fs = VirtualFilesystem()
            mock_fs.volume = volumes
            target_bare.filesystems.add(mock_fs)

            target_mount()

            MockFUSE.assert_called_once()
            MockDissectMount.assert_called_once()
            vfs = MockDissectMount.call_args[0][0]

            assert vfs.listdir("/filesystems") == ["first", "second"]


def test_mounting_virtual_ntfs_filesystem(
    target_bare: Target,
    monkeypatch: pytest.MonkeyPatch,
    mock_ntfs_dirfs: Path,
) -> None:
    with monkeypatch.context() as m:
        m.setattr("sys.argv", ["target-mount", "mock-target", "mock-mount"])
        m.setattr("dissect.target.tools.mount.HAS_FUSE", True)

        with (
            patch("dissect.target.tools.mount.open_target", return_value=target_bare),
            patch("dissect.target.tools.mount.FUSE", create=True) as MockFUSE,
            patch("dissect.target.tools.mount.DissectMount", create=True) as MockDissectMount,
        ):
            # Use the mock_ntfs_dirfs fixture for the NTFS files
            dir_fs = DirectoryFilesystem(mock_ntfs_dirfs)
            virtual_fs = VirtualFilesystem()
            virtual_fs.map_fs("", dir_fs)

            # Add the VirtualFileSystem
            target_bare.filesystems.add(virtual_fs)
            # Mount the VirtualFileSystem as c:
            target_bare.fs.mount("c:", virtual_fs)

            loaderutil.add_virtual_ntfs_filesystem(
                target_bare,
                virtual_fs,
                usnjrnl_path="$Extend_$Usnjrnl_$J",
                sds_path="$Secure_$SDS",
            )

            # The loaderutil should now have made a mock NTFS
            ntfs_obj = getattr(virtual_fs, "ntfs", None)
            assert isinstance(ntfs_obj, NTFS)

            target_mount()

            MockFUSE.assert_called_once()
            MockDissectMount.assert_called_once()
            vfs = MockDissectMount.call_args[0][0]

            # Only the VirtualFileSystem should be available in /filesystems, not the mock NTFS
            assert vfs.listdir("/filesystems") == ["fs_0"]
            # The VirtualFileSystem should have the NTFS files
            required_ntfs_files = ["$Extend_$Usnjrnl_$J", "$MFT", "$Secure_$SDS", "$Boot"]
            assert all(file in required_ntfs_files for file in vfs.listdir("/filesystems/fs_0"))
            # The c: volume should be mounted, and should be the only mount
            assert vfs.listdir("/fs") == ["c:"]
