from __future__ import annotations

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


def test_tar_sensitive_drive_letter(target_bare: Target) -> None:
    tar_file = absolute_path("_data/loaders/tar/uppercase_driveletter.tar")

    loader = TarLoader(tar_file)
    loader.map(target_bare)

    # mounts = / and c:
    assert sorted(target_bare.fs.mounts.keys()) == ["/", "c:"]
    assert "C:" not in target_bare.fs.mounts

    # Initialize our own WindowsPlugin to override the detection
    target_bare._os_plugin = WindowsPlugin.create(target_bare, target_bare.fs.mounts["c:"])
    target_bare._init_os()

    # sysvol is now added
    assert sorted(target_bare.fs.mounts.keys()) == ["/", "c:", "sysvol"]

    # WindowsPlugin sets the case sensitivity to False
    assert target_bare.fs.get("C:/test.file").open().read() == b"hello_world"
    assert target_bare.fs.get("c:/test.file").open().read() == b"hello_world"


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


@pytest.mark.parametrize(
    ("archive", "expected_drive_letter"),
    [
        ("_data/loaders/tar/test-windows-sysvol-absolute.tar", "c:"),  # C: due to backwards compatibility
        ("_data/loaders/tar/test-windows-sysvol-relative.tar", "c:"),  # C: due to backwards compatibility
        ("_data/loaders/tar/test-windows-fs-c-relative.tar", "c:"),
        ("_data/loaders/tar/test-windows-fs-c-absolute.tar", "c:"),
        ("_data/loaders/tar/test-windows-fs-x.tar", "x:"),
    ],
)
def test_tar_loader_windows_sysvol_formats(target_default: Target, archive: str, expected_drive_letter: str) -> None:
    loader = TarLoader(absolute_path(archive))
    loader.map(target_default)

    assert WindowsPlugin.detect(target_default)
    # NOTE: for the sysvol archives, this also tests the backwards compatibility
    assert sorted(target_default.fs.mounts.keys()) == [expected_drive_letter]


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


def test_tar_anonymous_filesystems(target_default: Target) -> None:
    tar_file = absolute_path("_data/loaders/tar/test-anon-filesystems.tar")

    loader = TarLoader(tar_file)
    loader.map(target_default)

    # mounts = $fs$/fs0, $fs$/fs1 and /
    assert len(target_default.fs.mounts) == 3
    assert "$fs$/fs0" in target_default.fs.mounts
    assert "$fs$/fs1" in target_default.fs.mounts
    assert "/" in target_default.fs.mounts
    assert target_default.fs.get("$fs$/fs0/foo").open().read() == b"hello world\n"
    assert target_default.fs.get("$fs$/fs1/bar").open().read() == b"hello world\n"


@pytest.mark.parametrize(
    ("should_detect", "filename", "buffer"),
    [
        # regular tar file
        (True, "file.tar", ""),
        (True, "file", "00" * 257 + "7573746172202000"),
        # gzip tar file
        (True, "file.tar.gz", ""),
        (True, "file.tgz", ""),
        (True, "file", "1f8b0800000000000000"),
        # bzip2 tar file
        (True, "file.tar.bz2", ""),
        (True, "file.tar.bz", ""),
        (True, "file.tbz", ""),
        (True, "file.tbz2", ""),
        (True, "file", "425a6839314159265359"),
        # xz tar file
        (True, "file.tar.xz", ""),
        (True, "file.txz", ""),
        (True, "file", "fd377a585a000004e6d6"),
        # some things it should not detect
        (False, "file", "00010203"),
        (False, "file.zip", "504b0304"),
    ],
)
def test_tar_detect(should_detect: bool, filename: str, buffer: str, tmp_path: pathlib.Path) -> None:
    """Test if we detect the given buffer as a (compressed) tar file or not."""
    tmp_tar = tmp_path.joinpath(filename)
    tmp_tar.touch()
    with tmp_tar.open("wb") as fh:
        fh.write(bytes.fromhex(buffer))
    assert TarLoader.detect(tmp_tar) == should_detect
