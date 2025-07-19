from io import BytesIO
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from dissect.target.exceptions import LoaderError
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.loaders.raw import RawLoader
from dissect.target.loaders.vbk import VbkLoader
from dissect.target.target import Target
from tests._utils import absolute_path


@patch("dissect.target.loaders.vbk.VbkFilesystem")
def test_vbk_loader(VbkFilesystem: Mock, target_default: Target) -> None:
    """Test the VBK loader."""
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
def test_vbk_loader_vhdx(VbkFilesystem: Mock, target_default: Target) -> None:
    """Test the VBK loader when a VHDX file is found."""
    vfs = VirtualFilesystem()
    VbkFilesystem.return_value = vfs

    loader = VbkLoader(Mock())

    vfs.makedirs("guid")
    vfs.makedirs("guid/scsi0-0")

    vfs.map_file_fh("guid/summary.xml", BytesIO(b""))

    # Map raw candidate
    candidate = Path(absolute_path("_data/loaders/vbk/vbk_candidate.raw"))
    vfs.map_file("guid/scsi0-0/candidate.vhdx", candidate)

    loader.map(target_default)
    target_default.apply()

    # The `vbk_candidate.raw` file is a raw container with just enough data to fit
    # a partition table parse. If the raw container in the vbk file
    # is opened correctly, these checks should all pass.
    assert len(target_default.disks) == 1
    assert len(target_default.volumes) == 4
    assert target_default.volumes[0].name == "Basic data partition"
    assert target_default.volumes[0].size == 471858688
    assert target_default.volumes[0].fs is None
    assert target_default.volumes[1].name == "EFI system partition"
    assert target_default.volumes[1].size == 103808512
    assert target_default.volumes[1].fs is None
    assert target_default.volumes[2].name == "Microsoft reserved partition"
    assert target_default.volumes[2].size == 16776704
    assert target_default.volumes[2].fs is None
    assert target_default.volumes[3].name == "Basic data partition"
    assert target_default.volumes[3].size == 136844410368
    assert target_default.volumes[3].fs is None
