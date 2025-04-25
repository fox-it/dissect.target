from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO

import pytest

from dissect.target import container
from dissect.target.containers.split import SplitContainer

if TYPE_CHECKING:
    from pathlib import Path


def _assert_split_container(fh: SplitContainer) -> None:
    assert isinstance(fh, SplitContainer)
    assert fh.read(4096) == (b"A" * 512) + (b"B" * 512) + (b"C" * 512) + (b"D" * 512)


@pytest.fixture
def split_fhs() -> list[BinaryIO]:
    return [BytesIO(bytes([char] * 512)) for char in b"ABCD"]


@pytest.fixture
def split_paths(tmp_path: Path, split_fhs: list[BinaryIO]) -> list[Path]:
    paths = [(tmp_path / f"split.{i:>03}") for i in range(4)]

    for fh, path in zip(split_fhs, paths):
        fh.seek(0)
        path.write_bytes(fh.read())

    return paths


@pytest.fixture
def split_symlink(tmp_path: Path, split_paths: list[Path]) -> Path:
    dir_path = tmp_path / "dir"
    symlink_path = dir_path / split_paths[0].name
    dir_path.mkdir()
    symlink_path.symlink_to(split_paths[0])

    return symlink_path


@pytest.mark.parametrize(
    "obj",
    [
        "split_fhs",
        "split_paths",
        "split_symlink",
    ],
)
def test_split_container(obj: str, request: pytest.FixtureRequest) -> None:
    fh = container.open(request.getfixturevalue(obj))
    _assert_split_container(fh)
