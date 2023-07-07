from unittest.mock import Mock, patch

import pytest

from dissect.target.loaders.phobos import (
    EXTFS_NEEDLE,
    EXTFS_NEEDLE_OFFSET,
    NTFS_NEEDLE,
    PhobosLoader,
)


@pytest.mark.parametrize(
    "needle, offset, expected_offset, element_count, element_size",
    (
        (
            EXTFS_NEEDLE,
            EXTFS_NEEDLE_OFFSET + 1337,
            1337,
            1024,
            1024,
        ),
        (
            NTFS_NEEDLE,
            1337,
            1337,
            1024,
            1024,
        ),
    ),
)
def test_phobos_loader_map(
    needle: bytes,
    offset: int,
    expected_offset: int,
    element_count: int,
    element_size: int,
):
    mock_target = Mock()
    phobos_loader = PhobosLoader(mock_target)
    mock_fh = Mock()
    mock_fs = Mock()
    mock_fs.ntfs.boot_sector.NumberSectors = element_count
    mock_fs.ntfs.sector_size = element_size
    mock_fs.extfs.block_count = element_count
    mock_fs.extfs.block_size = element_size
    expected_size = element_count * element_size

    with patch.object(phobos_loader.path, "open", return_value=mock_fh):
        with (
            patch(
                "dissect.target.loaders.phobos.scrape_pos",
                return_value=[(needle, offset)],
                autospec=True,
            ),
            patch("dissect.util.stream.RelativeStream", autospec=True) as mock_stream,
            patch(
                "dissect.target.filesystem.open",
                return_value=mock_fs,
                autospec=True,
            ),
        ):
            phobos_loader.map(mock_target)
            mock_stream.assert_called_with(mock_fh, expected_offset)
            mock_target.filesystems.add.assert_called_with(mock_fs)
            mock_target.fs.mount.assert_called_with("fs0", mock_fs)
            mock_fh.seek.assert_called_with(offset + expected_size)
