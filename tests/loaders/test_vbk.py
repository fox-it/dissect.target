from io import BytesIO
from unittest.mock import Mock, patch

import pytest

from dissect.target.exceptions import LoaderError
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.loaders.raw import RawLoader
from dissect.target.loaders.vbk import VbkLoader
from dissect.target.target import Target


@patch("dissect.target.loaders.vbk.VbkFilesystem")
def test_vbk_loader(VbkFilesystem: Mock, target_default: Target) -> None:
    """Test the VBK loader."""
    vfs = VirtualFilesystem()
    VbkFilesystem.return_value = vfs

    loader = VbkLoader(Mock())
    with pytest.raises(LoaderError, match="Unexpected empty VBK filesystem"):
        loader.map(target_default)

    vfs.makedirs("a")

    with pytest.raises(LoaderError, match="Unsupported VBK structure"):
        loader.map(target_default)

    vfs.map_file_fh("a/DEV__dummy", BytesIO("🍖👑".encode()))
    vfs.map_file_fh("a/summary.xml", BytesIO(b""))

    loader.map(target_default)
    assert isinstance(loader.loader, RawLoader)
    assert len(target_default.disks) == 1
    target_default.disks[0].seek(0)
    assert target_default.disks[0].read().decode() == "🍖👑"
