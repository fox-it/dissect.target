from io import BytesIO
from pathlib import Path

from dissect.target import container
from dissect.target.containers.split import SplitContainer


def _assert_split_container(fh):
    assert isinstance(fh, SplitContainer)
    assert fh.read(4096) == (b"A" * 512) + (b"B" * 512) + (b"C" * 512) + (b"D" * 512)


def test_split_container(tmpdir_name):
    fhs = []
    for char in b"ABCD":
        fhs.append(BytesIO(bytes([char] * 512)))

    # Test open by list of file handlers
    fh = container.open(fhs)
    _assert_split_container(fh)

    root = Path(tmpdir_name)
    paths = [(root / f"split.{i:>03}") for i in range(4)]

    for fh, path in zip(fhs, paths):
        fh.seek(0)
        path.write_bytes(fh.read())

    # Test open by list of paths
    fh = container.open(paths)
    _assert_split_container(fh)

    # Test open by first path
    fh = container.open(paths[0])
    _assert_split_container(fh)

    dir_path = root / "dir"
    symlink_path = dir_path / paths[0].name
    dir_path.mkdir()
    symlink_path.symlink_to(paths[0])

    # Test open by symlink
    fh = container.open(symlink_path)
    _assert_split_container(fh)
