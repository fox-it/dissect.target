from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

import pytest

from dissect.target.loaders.scrape import (
    EXTFS_NEEDLE,
    NEEDLE_OFFSETS,
    NTFS_NEEDLE,
    ScrapeLoader,
)

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize(
    ("needle", "offset", "expected_offset", "element_count", "element_size"),
    [
        (
            EXTFS_NEEDLE,
            NEEDLE_OFFSETS[EXTFS_NEEDLE] + 1337,
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
    ],
)
def test_scrape_loader_map(
    needle: bytes,
    offset: int,
    expected_offset: int,
    element_count: int,
    element_size: int,
    tmp_path: Path,
) -> None:
    mock_target = Mock()
    scrape_loader = ScrapeLoader(mock_target)

    mock_fh = Mock()
    mock_fh.__enter__ = Mock(return_value=mock_fh)
    mock_fh.__exit__ = Mock()

    mock_fs = Mock()
    mock_fs.ntfs.boot_sector.NumberSectors = element_count
    mock_fs.ntfs.sector_size = element_size
    mock_fs.extfs.block_count = element_count
    mock_fs.extfs.block_size = element_size
    expected_size = element_count * element_size

    with (
        patch.object(scrape_loader.path, "open", return_value=mock_fh),
        patch(
            "dissect.target.helpers.scrape.find_needles",
            return_value=[(needle, offset, None)],
            autospec=True,
        ),
        patch("dissect.util.stream.RelativeStream", autospec=True) as mock_stream,
        patch(
            "dissect.target.filesystem.open",
            return_value=mock_fs,
            autospec=True,
        ),
    ):
        scrape_loader.map(mock_target)
        mock_stream.assert_called_with(mock_fh, expected_offset)
        mock_target.filesystems.add.assert_called_with(mock_fs)
        mock_fh.seek.assert_called_with(offset + expected_size)
