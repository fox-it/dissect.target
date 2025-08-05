from __future__ import annotations

import io
from pathlib import Path
from typing import Callable
from unittest.mock import call, patch

import pytest

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.loader import open as loader_open
from dissect.target.loaders.multiraw import MultiRawLoader
from dissect.target.target import Target


@pytest.mark.parametrize(
    ("opener"),
    [
        pytest.param(Target.open, id="target-open"),
        pytest.param(lambda x: next(Target.open_all([x])), id="target-open-all"),
    ],
)
def test_target_open(opener: Callable[[str | Path], Target], tmp_path: Path) -> None:
    """Test that we correctly use ``MultiRawLoader`` when opening a ``Target``."""
    file1 = tmp_path / "file1.bin"
    file2 = tmp_path / "file2.bin"
    file1.touch()
    file2.touch()

    fs = VirtualFilesystem()
    fs.map_file_fh("/dir/file1.bin", io.BytesIO())
    fs.map_file_fh("/dir/file2.bin", io.BytesIO())

    for path in (f"{file1}+{file2}", fs.path("/dir/file1.bin+/dir/file2.bin")):
        with patch("dissect.target.container.open"), patch("dissect.target.target.Target.apply"):
            target = opener(path)
            assert isinstance(target._loader, MultiRawLoader)

            if isinstance(path, str):
                assert target.path == Path(path)
            else:
                assert target.path == path


def test_local(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that ``MultiRawLoader`` works with local files, absolute and relative."""
    (tmp_path / "file1.bin").touch()
    (tmp_path / "file2.bin").touch()

    root = str(tmp_path)

    loader = loader_open(Path(f"{root}/file1.bin"))
    assert not isinstance(loader, MultiRawLoader)

    loader = loader_open(Path(f"{root}/file1.bin+{root}/file2.bin"))
    assert isinstance(loader, MultiRawLoader)

    with patch("dissect.target.container.open") as mock_container_open:
        t = Target()
        loader.map(t)

        assert len(t.disks) == 2
        assert mock_container_open.call_count == 2
        mock_container_open.assert_has_calls(
            [
                call(Path(f"{root}/file1.bin")),
                call(Path(f"{root}/file2.bin")),
            ]
        )

    monkeypatch.chdir(root)
    assert Path("file1.bin").exists()

    loader = loader_open(Path("file1.bin"))
    assert not isinstance(loader, MultiRawLoader)

    loader = loader_open(Path("file1.bin+file2.bin"))
    assert isinstance(loader, MultiRawLoader)


def test_path() -> None:
    """Test that ``MultiRawLoader`` works with a ``TargetPath``."""
    fs = VirtualFilesystem()
    fs.map_file_fh("/dir/file1.bin", io.BytesIO())
    fs.map_file_fh("/dir/file2.bin", io.BytesIO())

    loader = loader_open(fs.path("/dir/file1.bin"))
    assert not isinstance(loader, MultiRawLoader)

    loader = loader_open(fs.path("/dir/file1.bin+/dir/file2.bin"))
    assert isinstance(loader, MultiRawLoader)

    with patch("dissect.target.container.open") as mock_container_open:
        t = Target()
        loader.map(t)

        assert len(t.disks) == 2
        assert mock_container_open.call_count == 2
        mock_container_open.assert_has_calls(
            [
                call(fs.path("/dir/file1.bin")),
                call(fs.path("/dir/file2.bin")),
            ]
        )
