from io import BytesIO
from pathlib import Path

import pytest

from dissect.target import container
from dissect.target.containers.split import SplitContainer


def _assert_split_container(fh: SplitContainer):
    assert isinstance(fh, SplitContainer)
    assert fh.read(4096) == (b"A" * 512) + (b"B" * 512) + (b"C" * 512) + (b"D" * 512)


@pytest.fixture
def split_fhs():
    fhs = []
    for char in b"ABCD":
        fhs.append(BytesIO(bytes([char] * 512)))

    yield fhs


@pytest.fixture
def split_paths(tmpdir_name, split_fhs):
    root = Path(tmpdir_name)
    paths = [(root / f"split.{i:>03}") for i in range(4)]

    for fh, path in zip(split_fhs, paths):
        fh.seek(0)
        path.write_bytes(fh.read())

    yield paths


@pytest.fixture
def split_symlink(tmpdir_name, split_paths):
    dir_path = Path(tmpdir_name) / "dir"
    symlink_path = dir_path / split_paths[0].name
    dir_path.mkdir()
    symlink_path.symlink_to(split_paths[0])

    yield symlink_path


@pytest.mark.parametrize(
    "obj",
    [
        "split_fhs",
        "split_paths",
        "split_symlink",
    ],
)
def test_split_container(obj, request):
    fh = container.open(request.getfixturevalue(obj))
    _assert_split_container(fh)
