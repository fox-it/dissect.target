from io import BytesIO
from pathlib import Path

from dissect.target import container
from dissect.target.containers.split import SplitContainer


def test_split_container(tmpdir_name):
    fhs = []
    for char in b"ABCD":
        fhs.append(BytesIO(bytes([char] * 512)))

    # Test open by list of file handlers
    fh = container.open(fhs)
    assert isinstance(fh, SplitContainer)
    assert fh.read(4096) == (b"A" * 512) + (b"B" * 512) + (b"C" * 512) + (b"D" * 512)

    root = Path(tmpdir_name)
    paths = [(root / f"split.{i:>03}") for i in range(4)]

    for fh, path in zip(fhs, paths):
        fh.seek(0)
        path.write_bytes(fh.read())

    # Test open by list of paths
    fh = container.open(paths)
    assert isinstance(fh, SplitContainer)
    assert fh.read(4096) == (b"A" * 512) + (b"B" * 512) + (b"C" * 512) + (b"D" * 512)

    # Test open by first path
    fh = container.open(paths[0])
    assert isinstance(fh, SplitContainer)
    assert fh.read(4096) == (b"A" * 512) + (b"B" * 512) + (b"C" * 512) + (b"D" * 512)
