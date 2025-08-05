from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING, Callable
from unittest.mock import Mock, patch

import pytest

from dissect.target.exceptions import LoaderError
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.loader import open as loader_open
from dissect.target.loaders.hyperv import HyperVLoader
from dissect.target.loaders.raw import RawLoader
from dissect.target.loaders.vbk import VbkLoader
from dissect.target.loaders.vmx import VmxLoader
from dissect.target.target import Target
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize(
    ("opener"),
    [
        pytest.param(Target.open, id="target-open"),
        pytest.param(lambda x: next(Target.open_all([x])), id="target-open-all"),
    ],
)
def test_target_open(opener: Callable[[str | Path], Target]) -> None:
    """Test that we correctly use ``VbkLoader`` when opening a ``Target``."""
    path = absolute_path(
        "_data/loaders/vbk/Backup Job 1/VBK-Test-VM.e56465c7-3a5a-4599-bc25-3555b9b8cD2025-07-20T160920_3702.vbk"
    )

    target = opener(path)
    assert isinstance(target._loader, VbkLoader)
    assert target.path == path


@pytest.mark.parametrize(
    ("path", "disk_sizes"),
    [
        (
            "Backup Job 1/VBK-Test-VM.e56465c7-3a5a-4599-bc25-3555b9b8cD2025-07-20T160920_3702.vbk",
            [20 * 1024 * 1024 * 1024],
        ),
        (
            "Backup Job 2_1/VBK-Test-VM-SCSI.8637b8b5-28a2-41e1-90c6-f8a0D2025-07-29T171659_FB82.vbk",
            [40 * 1024 * 1024 * 1024],
        ),
    ],
)
def test_loader(path: str, disk_sizes: list[int]) -> None:
    """Test the VBK loader on real files."""
    path = absolute_path("_data/loaders/vbk").joinpath(path)

    loader = loader_open(path)
    assert isinstance(loader, VbkLoader)

    t = Target()
    loader.map(t)
    assert len(t.disks) == len(disk_sizes)
    for disk, size in zip(sorted(t.disks, key=lambda disk: disk.size), sorted(disk_sizes)):
        assert disk.size == size


def test_mock_raw() -> None:
    """Test the VBK loader on a raw disk backup layout."""
    vfs = VirtualFilesystem()
    with patch("dissect.target.loaders.vbk.VbkFilesystem") as mock_vbk_fs:
        mock_vbk_fs.return_value = vfs

        loader = VbkLoader(Mock())
        t = Target()

        with pytest.raises(LoaderError, match="Unexpected empty VBK filesystem"):
            loader.map(t)

        vfs.makedirs("guid")

        with pytest.raises(LoaderError, match="Unsupported VBK structure"):
            loader.map(t)

        vfs.map_file_fh("guid/DEV__dummy", BytesIO("🍖👑".encode()))
        vfs.map_file_fh("guid/summary.xml", BytesIO())

        loader.map(t)
        assert isinstance(loader.loader, RawLoader)
        assert len(t.disks) == 1

        t.disks[0].seek(0)
        assert t.disks[0].read().decode() == "🍖👑"


def test_mock_vmx() -> None:
    """Test the VBK loader on a VMware backup layout."""
    vfs = VirtualFilesystem()
    with patch("dissect.target.loaders.vbk.VbkFilesystem") as mock_vbk_fs:
        mock_vbk_fs.return_value = vfs

        vfs.map_file_fh("guid/summary.xml", BytesIO())
        vfs.map_file_fh("guid/candidate.vmx", BytesIO(b'scsi0:0.fileName = "candidate.vmdk"'))
        vfs.map_file_fh(
            "guid/candidate.vmdk",
            BytesIO(b'# Disk DescriptorFile\nparentCID=ffffffff\nRW 16777216 VMFS "candidate-flat.vmdk"'),
        )
        vfs.map_file_fh("guid/candidate-flat.vmdk", BytesIO("🍖👑".encode()))

        loader = VbkLoader(Mock())
        t = Target()

        loader.map(t)
        assert isinstance(loader.loader, VmxLoader)
        assert len(t.disks) == 1

        t.disks[0].seek(0)
        assert t.disks[0].read(-1).decode() == "🍖👑"


def test_mock_vmcx() -> None:
    """Test the VBK loader on a Hyper-V backup layout."""
    vfs = VirtualFilesystem()
    with (
        patch("dissect.target.loaders.vbk.VbkFilesystem") as mock_vbk_fs,
        patch("dissect.target.loaders.hyperv.hyperv.HyperVFile") as mock_hyperv_file,
    ):
        mock_vbk_fs.return_value = vfs

        mock_hyperv_file.return_value = mock_hyperv_file
        mock_hyperv_file.as_dict.return_value = {
            "configuration": {
                "manifest": {
                    "vdev0": {
                        "device": "83f8638b-8dca-4152-9eda-2ca8b33039b4",
                        "instance": "83f8638b-8dca-4152-9eda-2ca8b33039b4",
                    },
                    "vdev1": {
                        "device": "d422512d-2bf2-4752-809d-7b82b5fcb1b4",
                        "instance": "d422512d-2bf2-4752-809d-7b82b5fcb1b4",
                    },
                },
                "_83f8638b-8dca-4152-9eda-2ca8b33039b4_": {
                    "controller0": {"drive0": {"type": "VHD", "pathname": "C:\\Fake\\Path\\ide.vhdx"}},
                },
                "_d422512d-2bf2-4752-809d-7b82b5fcb1b4_": {
                    "controller0": {"drive0": {"type": "VHD", "pathname": "C:\\Fake\\Path\\scsi.vhdx"}},
                },
            }
        }

        vfs.map_file_fh("guid/summary.xml", BytesIO())
        vfs.map_file_fh("guid/Config/candidate.vmcx", BytesIO())
        vfs.map_file_fh("guid/Ide0-0/ide.vhdx", BytesIO("🐌".encode()))
        vfs.map_file_fh("guid/Scsi0-0/scsi.vhdx", BytesIO("🏃🏃".encode()))

        loader = VbkLoader(Mock())
        t = Target()

        loader.map(t)
        assert isinstance(loader.loader, HyperVLoader)
        assert len(t.disks) == 2

        disks = sorted(t.disks, key=lambda d: d.size)

        disks[0].seek(0)
        assert disks[0].read(-1).decode() == "🐌"

        disks[1].seek(0)
        assert disks[1].read(-1).decode() == "🏃🏃"
