from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.loader import open as loader_open
from dissect.target.loaders.acquire import AcquireTarSubLoader, AcquireZipSubLoader
from dissect.target.loaders.tar import TarLoader
from dissect.target.loaders.zip import ZipLoader
from dissect.target.plugins.os.windows._os import WindowsPlugin
from dissect.target.target import Target
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture

    from dissect.target.loader import Loader


def test_case_sensitive_drive_letter(target_bare: Target) -> None:
    path = absolute_path("_data/loaders/acquire/uppercase_driveletter.tar")

    loader = loader_open(path)
    assert isinstance(loader, TarLoader)

    loader.map(target_bare)
    # mounts = / and c:
    assert sorted(target_bare.fs.mounts.keys()) == ["c:", "fs"]
    assert "C:" not in target_bare.fs.mounts

    # Initialize our own WindowsPlugin to override the detection
    target_bare._os_plugin = WindowsPlugin.create(target_bare, target_bare.fs.mounts["c:"])
    target_bare.apply()

    # sysvol is now added
    assert sorted(target_bare.fs.mounts.keys()) == ["c:", "fs", "sysvol"]

    # WindowsPlugin sets the case sensitivity to False
    assert target_bare.fs.get("C:/test.file").open().read() == b"hello_world"
    assert target_bare.fs.get("c:/test.file").open().read() == b"hello_world"


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
def test_windows_sysvol_formats(target_default: Target, archive: str, expected_drive_letter: str) -> None:
    path = absolute_path(archive)

    loader = loader_open(path)
    assert isinstance(loader, TarLoader)

    loader = TarLoader(path)
    loader.map(target_default)
    assert isinstance(loader.subloader, AcquireTarSubLoader)

    assert WindowsPlugin.detect(target_default)
    # NOTE: for the sysvol archives, this also tests the backwards compatibility
    assert sorted(target_default.fs.mounts.keys()) == [expected_drive_letter]
    assert target_default.fs.get(f"{expected_drive_letter}/Windows/System32/foo.txt")


def test_windows_sysvol_formats_zip(target_default: Target) -> None:
    path = absolute_path("_data/loaders/acquire/test-windows-fs-c.zip")

    loader = loader_open(path)
    assert isinstance(loader, ZipLoader)

    loader.map(target_default)
    assert isinstance(loader.subloader, AcquireZipSubLoader)

    assert WindowsPlugin.detect(target_default)
    # NOTE: for the sysvol archives, this also tests the backwards compatibility
    assert sorted(target_default.fs.mounts.keys()) == ["c:"]
    assert target_default.fs.get("c:/Windows/System32/foo.txt")


def test_anonymous_filesystems(target_default: Target) -> None:
    path = absolute_path("_data/loaders/acquire/test-anon-filesystems.tar")

    loader = loader_open(path)
    assert isinstance(loader, TarLoader)

    loader.map(target_default)
    assert isinstance(loader.subloader, AcquireTarSubLoader)

    assert target_default.fs.get("$fs$/fs0/foo").open().read() == b"hello world\n"
    assert target_default.fs.get("$fs$/fs1/bar").open().read() == b"hello world\n"


@pytest.mark.parametrize(
    ("archive", "loader"),
    [
        ("_data/loaders/acquire/test-windows-fs-c-relative.tar", TarLoader),
        ("_data/loaders/acquire/test-windows-fs-c.zip", ZipLoader),
    ],
)
@pytest.mark.benchmark
def test_benchmark(benchmark: BenchmarkFixture, archive: str, loader: type[Loader]) -> None:
    file = absolute_path(archive)

    benchmark(lambda: loader(file).map(Target()))
