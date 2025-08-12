from __future__ import annotations

import platform
import tarfile
from typing import TYPE_CHECKING

import pytest

from dissect.target.loaders.tar import TarLoader
from dissect.target.plugins.os.windows._os import WindowsPlugin
from tests._utils import absolute_path
from tests.filesystems.test_tar import _mkdir

if TYPE_CHECKING:
    import pathlib

    from dissect.target.target import Target


def test_tar_loader_compressed_tar_file(target_win: Target) -> None:
    archive_path = absolute_path("_data/loaders/tar/test-archive.tar.gz")

    loader = TarLoader(archive_path)
    loader.map(target_win)

    assert len(target_win.filesystems) == 2

    test_file = target_win.fs.path("test-data/test-file.txt")

    assert test_file.exists()
    assert test_file.open().read() == b"test-value\n"


def test_tar_loader_compressed_tar_file_with_empty_dir(target_unix: Target) -> None:
    archive_path = absolute_path("_data/loaders/tar/test-archive-empty-folder.tgz")
    loader = TarLoader(archive_path)
    loader.map(target_unix)

    assert len(target_unix.filesystems) == 2
    test_file = target_unix.fs.path("test/test_file_with_content")
    assert test_file.exists()
    assert test_file.is_file()
    assert test_file.open().read() == b"This is a test!\n"
    empty_folder = target_unix.fs.path("test/empty_dir")
    assert empty_folder.exists()
    assert empty_folder.is_dir()


def test_tar_loader_windows_case_sensitivity(target_default: Target, tmp_path: pathlib.Path) -> None:
    """Test if we correctly map a tar with Windows folder structure as a case-insensitive filesystem."""

    tar_path = tmp_path.joinpath("target.tar.gz")
    with tarfile.open(tar_path, "w:gz") as tf:
        _mkdir(tf, "Windows")
        _mkdir(tf, "Windows/System32")

    loader = TarLoader(tar_path)
    loader.map(target_default)

    # Make sure the case sensitiveness is changed to False and make sure we detect the target as Windows.
    assert not target_default.filesystems[0].case_sensitive
    assert WindowsPlugin.detect(target_default)

    # We also test the inverse, make sure a random Linux target is not marked as case-insensitive.
    tar_path = tmp_path.joinpath("second_target.tar.gz")
    with tarfile.open(tar_path, "w:gz") as tf:
        _mkdir(tf, "etc")
        _mkdir(tf, "var")
        _mkdir(tf, "opt")
    loader = TarLoader(tar_path)
    loader.map(target_default)
    assert target_default.filesystems[1].case_sensitive


@pytest.mark.parametrize(
    ("should_detect", "filename", "buffer"),
    [
        # regular tar file
        (True, "file.tar", ""),
        # gzip tar file
        (True, "file.tar.gz", ""),
        (True, "file.tgz", ""),
        # bzip2 tar file
        (True, "file.tar.bz2", ""),
        (True, "file.tar.bz", ""),
        (True, "file.tbz", ""),
        (True, "file.tbz2", ""),
        # xz tar file
        (True, "file.tar.xz", ""),
        (True, "file.txz", ""),
        # some things it should not detect
        (False, "file", "00010203"),
        (False, "file.zip", "504b0304"),
    ],
)
def test_tar_detect_extension(should_detect: bool, filename: str, buffer: str, tmp_path: pathlib.Path) -> None:
    """Test if we detect the given buffer as a (compressed) tar file or not."""
    tmp_tar = tmp_path.joinpath(filename)
    tmp_tar.touch()
    with tmp_tar.open("wb") as fh:
        fh.write(bytes.fromhex(buffer))
    assert TarLoader.detect(tmp_tar) == should_detect


@pytest.mark.parametrize(
    "file",
    [
        "small.tar",
        "small.tar.bz2",
        "small.tar.gz",
        "small.tar.lz",
        "small.tar.xz",
    ],
)
def test_tar_detect_buffer(file: str, tmp_path: pathlib.Path) -> None:
    """Test if we detect the given files as a (compressed) tar file or not."""

    if file == "small.tar.lz" and (platform.python_implementation() == "PyPy" or platform.system() == "Windows"):
        pytest.skip(reason="LZMA is flaky on PyPy and/or Windows")

    small_file = absolute_path(f"_data/loaders/tar/detect/{file}")

    # We rename the file to prevent detection based on file suffix.
    tmp_tar = tmp_path.joinpath(file.replace(".", "-"))
    tmp_tar.write_bytes(small_file.read_bytes())

    assert TarLoader.detect(tmp_tar)
