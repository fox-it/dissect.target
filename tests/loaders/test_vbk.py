from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

import pytest

from dissect.target.exceptions import LoaderError
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.loader import open as loader_open
from dissect.target.loaders.hyperv import HyperVLoader
from dissect.target.loaders.raw import RawLoader
from dissect.target.loaders.vbk import VbkLoader
from dissect.target.loaders.vmx import VmxLoader
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target


@patch("dissect.target.loaders.vbk.VbkFilesystem")
def test_vbk_loader_mock_raw(VbkFilesystem: Mock, target_default: Target) -> None:
    """Test the VBK loader on a raw disk backup layout."""
    vfs = VirtualFilesystem()
    VbkFilesystem.return_value = vfs

    loader = VbkLoader(Mock())
    with pytest.raises(LoaderError, match="Unexpected empty VBK filesystem"):
        loader.map(target_default)

    vfs.makedirs("guid")

    with pytest.raises(LoaderError, match="Unsupported VBK structure"):
        loader.map(target_default)

    vfs.map_file_fh("guid/DEV__dummy", BytesIO("🍖👑".encode()))
    vfs.map_file_fh("guid/summary.xml", BytesIO(b""))

    loader.map(target_default)
    assert isinstance(loader.loader, RawLoader)
    assert len(target_default.disks) == 1

    target_default.disks[0].seek(0)
    assert target_default.disks[0].read().decode() == "🍖👑"


@patch("dissect.target.loaders.vbk.VbkFilesystem")
def test_vbk_loader_mock_vmx(VbkFilesystem: Mock, target_default: Target) -> None:
    """Test the VBK loader on a VMware backup layout."""
    vfs = VirtualFilesystem()
    VbkFilesystem.return_value = vfs

    loader = VbkLoader(Mock())

    vfs.map_file_fh("guid/summary.xml", BytesIO(b""))
    vfs.map_file_fh("guid/candidate.vmx", BytesIO(b'scsi0:0.fileName = "candidate.vmdk"'))
    vfs.map_file_fh(
        "guid/candidate.vmdk",
        BytesIO(b'# Disk DescriptorFile\nparentCID=ffffffff\nRW 16777216 VMFS "candidate-flat.vmdk"'),
    )
    vfs.map_file_fh("guid/candidate-flat.vmdk", BytesIO("🍖👑".encode()))

    loader.map(target_default)
    assert isinstance(loader.loader, VmxLoader)
    assert len(target_default.disks) == 1

    target_default.disks[0].seek(0)
    assert target_default.disks[0].read(-1).decode() == "🍖👑"


@patch("dissect.target.loaders.hyperv.hyperv.HyperVFile")
@patch("dissect.target.loaders.vbk.VbkFilesystem")
def test_vbk_loader_mock_vmcx(VbkFilesystem: Mock, HyperVFile: Mock, target_default: Target) -> None:
    """Test the VBK loader on a Hyper-V backup layout."""
    vfs = VirtualFilesystem()
    VbkFilesystem.return_value = vfs

    HyperVFile.return_value = HyperVFile
    HyperVFile.as_dict.return_value = {
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

    loader = VbkLoader(Mock())

    vfs.map_file_fh("guid/summary.xml", BytesIO(b""))
    vfs.map_file_fh("guid/Config/candidate.vmcx", BytesIO(b""))
    vfs.map_file_fh("guid/Ide0-0/ide.vhdx", BytesIO("🐌".encode()))
    vfs.map_file_fh("guid/Scsi0-0/scsi.vhdx", BytesIO("🏃🏃".encode()))

    loader.map(target_default)
    assert isinstance(loader.loader, HyperVLoader)
    assert len(target_default.disks) == 2

    disks = sorted(target_default.disks, key=lambda d: d.size)

    disks[0].seek(0)
    assert disks[0].read(-1).decode() == "🐌"

    disks[1].seek(0)
    assert disks[1].read(-1).decode() == "🏃🏃"


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
def test_vbk_loader(path: Path, disk_sizes: list[int], target_default: Target) -> None:
    """Test the VBK loader on real files."""

    path = absolute_path("_data/loaders/vbk").joinpath(path)

    loader = loader_open(path)
    assert isinstance(loader, VbkLoader)

    loader.map(target_default)

    assert len(target_default.disks) == len(disk_sizes)
    for disk, size in zip(sorted(target_default.disks, key=lambda disk: disk.size), sorted(disk_sizes)):
        assert disk.size == size
