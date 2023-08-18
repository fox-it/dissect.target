import io
from pathlib import Path

import pytest

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.loaders.multiraw import MultiRawLoader


def test_multiraw_loader(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    (tmp_path / "file1.bin").touch()
    (tmp_path / "file2.bin").touch()

    root = str(tmp_path)
    assert not MultiRawLoader.detect(Path(f"{root}/file1.bin"))
    assert MultiRawLoader.detect(Path(f"{root}/file1.bin+{root}/file2.bin"))

    monkeypatch.chdir(root)
    assert Path("file1.bin").exists()
    assert not MultiRawLoader.detect(Path("file1.bin"))
    assert MultiRawLoader.detect(Path("file1.bin+file2.bin"))

    fs = VirtualFilesystem()
    fs.map_file_fh("/dir/file1.bin", io.BytesIO())
    fs.map_file_fh("/dir/file2.bin", io.BytesIO())

    assert not MultiRawLoader.detect(fs.path("/dir/file1.bin"))
    assert MultiRawLoader.detect(fs.path("/dir/file1.bin+/dir/file2.bin"))
