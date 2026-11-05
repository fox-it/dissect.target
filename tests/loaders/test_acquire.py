from __future__ import annotations

import logging
import tarfile
from typing import TYPE_CHECKING

import pytest

from dissect.target.loader import open as loader_open
from dissect.target.loaders.acquire import (
    FILESYSTEMS_LEGACY_ROOT,
    FILESYSTEMS_ROOT,
    AcquireTarSubLoader,
    AcquireZipSubLoader,
)
from dissect.target.loaders.tar import TarLoader
from dissect.target.loaders.zip import ZipLoader
from dissect.target.plugins.os.windows._os import WindowsPlugin
from dissect.target.target import Target
from tests._utils import absolute_path
from tests.filesystems.test_tar import _mkfile

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from pytest_benchmark.fixture import BenchmarkFixture

    from dissect.target.loader import Loader


@pytest.mark.parametrize(
    ("opener"),
    [
        pytest.param(Target.open, id="target-open"),
        pytest.param(lambda x: next(Target.open_all([x])), id="target-open-all"),
    ],
)
def test_target_open(opener: Callable[[str | Path], Target]) -> None:
    """Test that we correctly use ``AcquireTarSubLoader`` when opening a ``Target``."""
    path = absolute_path("_data/loaders/acquire/test-windows-sysvol-absolute.tar")

    target = opener(path)
    assert isinstance(target._loader, TarLoader)
    assert target.path == path


def test_case_sensitive_drive_letter() -> None:
    """Test that we correctly handle case sensitivity of drive letters."""
    path = absolute_path("_data/loaders/acquire/uppercase_driveletter.tar")

    loader = loader_open(path)
    assert isinstance(loader, TarLoader)

    t = Target()
    loader.map(t)
    assert isinstance(loader.subloader, AcquireTarSubLoader)

    # mounts = / and c:
    assert sorted(t.fs.mounts.keys()) == ["c:", "fs"]
    assert "C:" not in t.fs.mounts

    # Initialize our own WindowsPlugin to override the detection
    t._os_plugin = WindowsPlugin.create(t, t.fs.mounts["c:"])
    t.apply()

    # sysvol is now added
    assert sorted(t.fs.mounts.keys()) == ["c:", "fs", "sysvol"]

    # WindowsPlugin sets the case sensitivity to False
    assert t.fs.get("C:/test.file").open().read() == b"hello_world"
    assert t.fs.get("c:/test.file").open().read() == b"hello_world"


@pytest.mark.parametrize(
    ("archive", "expected_drive_letter"),
    [
        ("_data/loaders/acquire/test-windows-sysvol-absolute.tar", "c:"),  # C: due to backwards compatibility
        ("_data/loaders/acquire/test-windows-sysvol-relative.tar", "c:"),  # C: due to backwards compatibility
        ("_data/loaders/acquire/test-windows-fs-c-relative.tar", "c:"),
        ("_data/loaders/acquire/test-windows-fs-c-absolute.tar", "c:"),
        ("_data/loaders/acquire/test-windows-fs-x.tar", "x:"),
    ],
)
def test_windows_sysvol_formats(archive: str, expected_drive_letter: str) -> None:
    """Test that we correctly handle different sysvol formats."""
    path = absolute_path(archive)

    loader = loader_open(path)
    assert isinstance(loader, TarLoader)

    t = Target()
    loader.map(t)
    assert isinstance(loader.subloader, AcquireTarSubLoader)

    assert WindowsPlugin.detect(t)
    # NOTE: for the sysvol archives, this also tests the backwards compatibility
    assert sorted(t.fs.mounts.keys()) == [expected_drive_letter]
    assert t.fs.get(f"{expected_drive_letter}/Windows/System32/foo.txt")


def test_windows_sysvol_formats_zip() -> None:
    """Test that we correctly handle sysvol formats in ZIP archives."""
    path = absolute_path("_data/loaders/acquire/test-windows-fs-c.zip")

    loader = loader_open(path)
    assert isinstance(loader, ZipLoader)

    t = Target()
    loader.map(t)
    assert isinstance(loader.subloader, AcquireZipSubLoader)

    assert WindowsPlugin.detect(t)
    # NOTE: for the sysvol archives, this also tests the backwards compatibility
    assert sorted(t.fs.mounts.keys()) == ["c:"]
    assert t.fs.get("c:/Windows/System32/foo.txt")


@pytest.mark.parametrize(
    ("prefix", "subfolder"),
    [
        (f"{FILESYSTEMS_ROOT}/", "java.prefs"),
        (f"{FILESYSTEMS_ROOT}/", FILESYSTEMS_ROOT),
        (f"/{FILESYSTEMS_ROOT}/", "java.prefs"),
        (f"/{FILESYSTEMS_ROOT}/", FILESYSTEMS_ROOT),
    ],
)
def test_linux_acquire_with_fs_subfolder(prefix: str, subfolder: str, tmp_path: Path) -> None:
    """Test that we correctly handle Linux Acquire archives with a subfolder containing 'fs/'."""
    path = tmp_path.joinpath("target.tar.gz")
    with tarfile.open(path, "w:gz") as tf:
        _mkfile(tf, f"{prefix}$rootfs$/etc/test", b"testdata1")
        _mkfile(tf, f"{prefix}$rootfs$/etc/{subfolder}/test", b"testdata2")

    loader = loader_open(path)
    assert isinstance(loader, TarLoader)

    t = Target()
    loader.map(t)
    assert isinstance(loader.subloader, AcquireTarSubLoader)

    # Test directly on $rootfs$
    assert t.fs.get("$rootfs$/etc/test").open().read() == b"testdata1"
    assert t.fs.get(f"$rootfs$/etc/{subfolder}/test").open().read() == b"testdata2"

    # The OS plugin is not applied, so manually mount to also test this case
    t.fs.mount("/", t.fs.mounts["$rootfs$"])
    assert t.fs.get("/etc/test").open().read() == b"testdata1"
    assert t.fs.get(f"/etc/{subfolder}/test").open().read() == b"testdata2"


def test_duplicate_sysvol_and_drive_letter(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """Test that we correctly handle legacy Acquire archives containing both 'sysvol' and a drive letter."""
    path = tmp_path.joinpath("target.tar.gz")
    with tarfile.open(path, "w:gz") as tf:
        _mkfile(tf, f"{FILESYSTEMS_ROOT}/c:/Windows/System32/foo.txt", b"testdata1")
        _mkfile(tf, f"{FILESYSTEMS_ROOT}/{FILESYSTEMS_LEGACY_ROOT}/Windows/System32/foo.txt", b"testdata2")

    loader = loader_open(path)
    assert isinstance(loader, TarLoader)

    t = Target()
    with caplog.at_level(logging.DEBUG, "dissect.target.loaders.acquire"):
        loader.map(t)
    assert isinstance(loader.subloader, AcquireTarSubLoader)

    # Test if sysvols is ignored and the file is present at c:
    assert set(t.fs.mounts.keys()) == {"c:"}
    assert t.fs.get("c:/Windows/System32/foo.txt").open().read() == b"testdata1"

    # Test that the duplicate entry is skipped and logged
    assert "Skipping member" in caplog.text
    assert "in tar as 'Windows/System32/foo.txt' is already mapped" in caplog.text


def test_anonymous_filesystems() -> None:
    """Test that we correctly handle anonymous filesystems in Acquire archives."""
    path = absolute_path("_data/loaders/acquire/test-anon-filesystems.tar")

    loader = loader_open(path)
    assert isinstance(loader, TarLoader)

    t = Target()
    loader.map(t)
    assert isinstance(loader.subloader, AcquireTarSubLoader)

    assert t.fs.get("$fs$/fs0/foo").open().read() == b"hello world\n"
    assert t.fs.get("$fs$/fs1/bar").open().read() == b"hello world\n"


@pytest.mark.parametrize(
    ("archive", "loader"),
    [
        ("_data/loaders/acquire/test-windows-fs-c-relative.tar", TarLoader),
        ("_data/loaders/acquire/test-windows-fs-c.zip", ZipLoader),
    ],
)
@pytest.mark.benchmark
def test_benchmark(benchmark: BenchmarkFixture, archive: str, loader: type[Loader]) -> None:
    """Benchmark the loading of Acquire archives."""
    file = absolute_path(archive)

    benchmark(lambda: loader(file).map(Target()))
