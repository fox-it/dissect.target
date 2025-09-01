from __future__ import annotations

import io
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest

from dissect.target.filesystem import VirtualFile, VirtualFilesystem
from dissect.target.tools.fs import _extract_path, cp
from dissect.target.tools.fs import main as target_fs

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def vfs(files: list[str]) -> VirtualFilesystem:
    vfs = VirtualFilesystem()
    for file in files:
        if file[-1] == "/":
            vfs.makedirs(file)
        else:
            vfs.map_file_entry(file, VirtualFile(vfs, file, io.BytesIO()))
    return vfs


@pytest.mark.parametrize(
    ("path", "expected_files"),
    [
        ("root/.bash_history", 1),
        ("this/path/doesntexist", 0),
        ("**/*_history", 4),
    ],
)
def test_target_fs(
    path: str, expected_files: int, tmp_path: Path, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    with monkeypatch.context() as m:
        m.setattr("sys.argv", ["target-fs", "tests/_data/tools/info/image.tar", "cp", path, "-o", str(tmp_path)])

        target_fs()
        stdout, _ = capsys.readouterr()

        if expected_files > 0:
            lines = [line for line in stdout.split("\n") if line != ""]
            assert len(lines) == expected_files
        else:
            assert stdout == "[!] Path doesn't exist\n"


@pytest.mark.parametrize("files", [["file"]])
def test_extract_file(vfs: VirtualFilesystem, tmp_path: Path) -> None:
    output_path = tmp_path / "file"

    try:
        _extract_path(vfs.path("file"), output_path)
    except Exception:  # noqua
        # The files are virtual, so we expect the method to raise an exception
        pass

    assert output_path.exists()


@pytest.mark.parametrize("files", [[]])
def test_file_not_exist(vfs: VirtualFilesystem, tmp_path: Path) -> None:
    output_path = tmp_path / "file"

    _extract_path(vfs.path("file"), output_path)

    assert not output_path.exists()


@pytest.mark.parametrize("files", [["dir/"]])
def test_extract_directory(vfs: VirtualFilesystem, tmp_path: Path) -> None:
    output_path = tmp_path / "out"

    _extract_path(vfs.path("dir"), output_path)

    assert output_path.exists()


@pytest.mark.parametrize("files", [["dir/", "dir/test"]])
def test_cp_file_path(vfs: VirtualFilesystem, tmp_path: Path) -> None:
    output_path = tmp_path / "out"

    args = Mock()
    args.output = str(output_path)

    cp(None, vfs.path("dir/test"), args)

    assert output_path.joinpath("test").exists()


@pytest.mark.parametrize("files", [["dir/", "dir/test"]])
def test_cp_directory(vfs: VirtualFilesystem, tmp_path: Path) -> None:
    output_path = tmp_path / "out"

    args = Mock()
    args.output = str(output_path)

    cp(None, vfs.path("dir"), args)

    assert output_path.joinpath("test").exists()


@pytest.mark.parametrize("files", [[]])
def test_cp_non_existing_file(vfs: VirtualFilesystem, tmp_path: Path) -> None:
    output_path = tmp_path / "out"

    args = Mock()
    args.output = str(output_path)

    cp(None, vfs.path("dir/test"), args)

    assert not output_path.exists()


@pytest.mark.parametrize(
    "files",
    [["dir/", "dir/test", "dir/subdirectory_1/", "dir/subdirectory_2/", "dir/subdirectory_3/subdirectory_4/"]],
)
def test_cp_subdirectories(vfs: VirtualFilesystem, files: list[str], tmp_path: Path) -> None:
    output_path = tmp_path / "out"

    args = Mock()
    args.output = str(output_path)

    cp(None, vfs.path("dir/"), args)

    filesystem_files = (file.replace("dir/", "") for file in files)

    for directories in filesystem_files:
        assert output_path.joinpath(directories).exists()
