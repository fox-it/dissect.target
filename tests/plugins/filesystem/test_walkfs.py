from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from dissect.target.filesystem import VirtualFile, VirtualFilesystem
from dissect.target.loaders.tar import TarLoader
from dissect.target.plugins.filesystem.walkfs import WalkFSPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture

    from dissect.target.target import Target


def test_walkfs_plugin(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file_entry("/path/to/some/file", VirtualFile(fs_unix, "file", None))
    fs_unix.map_file_entry("/path/to/some/other/file.ext", VirtualFile(fs_unix, "file.ext", None))
    fs_unix.map_file_entry("/root_file", VirtualFile(fs_unix, "root_file", None))
    fs_unix.map_file_entry("/other_root_file.ext", VirtualFile(fs_unix, "other_root_file.ext", None))
    fs_unix.map_file_entry("/.test/test.txt", VirtualFile(fs_unix, "test.txt", None))
    fs_unix.map_file_entry("/.test/.more.test.txt", VirtualFile(fs_unix, ".more.test.txt", None))

    target_unix.add_plugin(WalkFSPlugin)

    results = list(target_unix.walkfs())
    assert len(results) == 14
    assert sorted([r.path for r in results]) == [
        "/",
        "/.test",
        "/.test/.more.test.txt",
        "/.test/test.txt",
        "/etc",
        "/other_root_file.ext",
        "/path",
        "/path/to",
        "/path/to/some",
        "/path/to/some/file",
        "/path/to/some/other",
        "/path/to/some/other/file.ext",
        "/root_file",
        "/var",
    ]


@pytest.mark.benchmark
def test_benchmark_walkfs(target_bare: Target, benchmark: BenchmarkFixture) -> None:
    """Benchmark walkfs performance on a small tar archive with ~500 files."""

    loader = TarLoader(Path(absolute_path("_data/loaders/containerimage/alpine.tar")))
    loader.map(target_bare)
    target_bare.apply()

    result = benchmark(lambda: next(WalkFSPlugin(target_bare).walkfs()))

    assert result.path == "/"
