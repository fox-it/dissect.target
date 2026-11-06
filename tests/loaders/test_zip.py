from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.loaders.zip import ZipLoader
from dissect.target.plugin import OperatingSystem
from dissect.target.target import Target
from tests._utils import absolute_path

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


@pytest.mark.parametrize(
    ("opener"),
    [
        pytest.param(Target.open, id="target-open"),
        pytest.param(lambda x: next(Target.open_all([x])), id="target-open-all"),
    ],
)
def test_unix_zip(opener: Callable[[str | Path], Target]) -> None:
    """Test the ``ZipLoader`` for Linux directories."""
    path = absolute_path("_data/loaders/zip/linux.zip")
    t = opener(path)
    assert isinstance(t._loader, ZipLoader)
    assert len(t.filesystems) == 1
    assert t.os == OperatingSystem.UNIX
    assert t.fs.path("/etc/hostname").read_bytes() == b"test\n"
    assert t.fs.path("/etc/apt/sources.list.d/test.list").read_bytes() == b"test_2\n"
    assert not t.fs.path("/etC/hostname").exists()  # Unix is considered as case sensitive
    assert not t.fs.path("/etc/Hostname").exists()


@pytest.mark.parametrize(
    ("opener"),
    [
        pytest.param(Target.open, id="target-open"),
        pytest.param(lambda x: next(Target.open_all([x])), id="target-open-all"),
    ],
)
def test_windows_drive_letters_zip(opener: Callable[[str | Path], Target]) -> None:
    """Test the ``ZipLoader`` for a Windows like structure archive with 3 drives."""
    path = absolute_path("_data/loaders/zip/windows_drive_letter.zip")
    t = opener(path)
    assert isinstance(t._loader, ZipLoader)
    assert t.os == OperatingSystem.WINDOWS

    assert t.fs.path("sysvol/windows/system32/config/software").exists()
    assert t.fs.path("sysvol/Windows/System32/config/SOFTWARE").exists()
    assert t.fs.path("sysvol/Windows/System32/config/SOFTWARE").read_bytes() == b"test\n"
