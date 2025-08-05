from __future__ import annotations

import logging
import platform
import tarfile
from typing import TYPE_CHECKING, Callable

import pytest

from dissect.target.loader import open as loader_open
from dissect.target.loaders.tar import GenericTarSubLoader, TarLoader
from dissect.target.plugins.os.windows._os import WindowsPlugin
from dissect.target.target import Target
from tests._utils import absolute_path
from tests.filesystems.test_tar import _mkdir

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
    """Test that we correctly use ``TarLoader`` when opening a ``Target``."""
    path = absolute_path("_data/loaders/tar/test-archive.tar")

    target = opener(path)
    assert isinstance(target._loader, TarLoader)
    assert target.path == path


def test_compressed_tar_file(caplog: pytest.LogCaptureFixture) -> None:
    """Test if we can handle a compressed tar file."""
    path = absolute_path("_data/loaders/tar/test-archive.tar.gz")

    with caplog.at_level(logging.WARNING):
        loader = loader_open(path)
        assert isinstance(loader, TarLoader)
        assert "is compressed" in caplog.text

    t = Target()
    loader.map(t)
    assert isinstance(loader.subloader, GenericTarSubLoader)

    assert len(t.filesystems) == 1

    test_file = t.fs.path("test-data/test-file.txt")

    assert test_file.exists()
    assert test_file.open().read() == b"test-value\n"


def test_compressed_tar_file_with_empty_dir() -> None:
    """Test if we can handle a tar file with an empty directory."""
    path = absolute_path("_data/loaders/tar/test-archive-empty-folder.tgz")

    loader = loader_open(path)
    assert isinstance(loader, TarLoader)

    t = Target()
    loader.map(t)
    assert isinstance(loader.subloader, GenericTarSubLoader)

    assert len(t.filesystems) == 1

    test_file = t.fs.path("test/test_file_with_content")
    assert test_file.exists()
    assert test_file.is_file()
    assert test_file.open().read() == b"This is a test!\n"

    empty_folder = t.fs.path("test/empty_dir")
    assert empty_folder.exists()
    assert empty_folder.is_dir()


def test_case_sensitivity_windows(tmp_path: Path) -> None:
    """Test if we correctly map a tar with Windows folder structure as a case-insensitive filesystem."""
    path = tmp_path.joinpath("target.tar.gz")
    with tarfile.open(path, "w:gz") as tf:
        _mkdir(tf, "Windows")
        _mkdir(tf, "Windows/System32")

    loader = loader_open(path)
    assert isinstance(loader, TarLoader)

    t = Target()
    loader.map(t)
    assert isinstance(loader.subloader, GenericTarSubLoader)

    # Make sure the case sensitiveness is changed to False and make sure we detect the target as Windows.
    assert not t.filesystems[0].case_sensitive
    assert WindowsPlugin.detect(t)


def test_case_sensitivity_linux(tmp_path: Path) -> None:
    """Test if we correctly map a tar with Linux folder structure as a case-sensitive filesystem."""
    path = tmp_path.joinpath("target.tar.gz")
    with tarfile.open(path, "w:gz") as tf:
        _mkdir(tf, "etc")
        _mkdir(tf, "var")
        _mkdir(tf, "opt")

    loader = loader_open(path)
    assert isinstance(loader, TarLoader)

    t = Target()
    loader.map(t)
    assert isinstance(loader.subloader, GenericTarSubLoader)

    assert t.filesystems[0].case_sensitive


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
def test_detect_extension(should_detect: bool, filename: str, buffer: str, tmp_path: Path) -> None:
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
def test_detect_buffer(file: str, tmp_path: Path) -> None:
    """Test if we detect the given files as a (compressed) tar file or not."""

    if file == "small.tar.lz" and (platform.python_implementation() == "PyPy" or platform.system() == "Windows"):
        pytest.skip(reason="LZMA is flaky on PyPy and/or Windows")

    small_file = absolute_path(f"_data/loaders/tar/detect/{file}")

    # We rename the file to prevent detection based on file suffix.
    tmp_tar = tmp_path.joinpath(file.replace(".", "-"))
    tmp_tar.write_bytes(small_file.read_bytes())

    assert TarLoader.detect(tmp_tar)
