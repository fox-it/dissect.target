from __future__ import annotations

import io
import logging
from pathlib import Path

import pytest

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem


def test_direct_overlap_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Assert direct raise warning in case sensitive mode if some files overlap
    We must uncompress files in a temporary directory as having two files with same name
    would cause issue with git on case insensitive fs.
    """
    source_vfs = VirtualFilesystem(case_sensitive=True)
    source_vfs.map_file_fh("file.txt", io.BytesIO(b"a"))
    source_vfs.map_file_fh("File.txt", io.BytesIO(b"b"))
    with caplog.at_level(logging.WARNING):
        _ = Target.open_direct([source_vfs.path("/")], case_sensitive=True)
        assert (
            "Direct mode used in case insensitive mode, but this will cause files overlap, "
            "consider using --direct-sensitive" not in caplog.text
        )
    with caplog.at_level(logging.WARNING):
        _ = Target.open_direct([source_vfs.path("/")], case_sensitive=False)
        assert (
            "Direct mode used in case insensitive mode, but this will cause files overlap, "
            "consider using --direct-sensitive" in caplog.text
        )
    with caplog.at_level(logging.WARNING):
        _ = Target.open_direct([source_vfs.path("/file.txt"), source_vfs.path("/File.txt")], case_sensitive=False)
        assert (
            "Direct mode used in case insensitive mode, but this will cause files overlap, "
            "consider using --direct-sensitive" in caplog.text
        )
