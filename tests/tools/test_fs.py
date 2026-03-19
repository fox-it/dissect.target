from __future__ import annotations

import io
import sys as _sys
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest

from dissect.target.filesystem import VirtualFile, VirtualFilesystem
from dissect.target.tools.fs import _extract_path, _preserve_links, cp
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
        m.setattr("sys.argv", [
                  "target-fs", "tests/_data/tools/info/image.tar", "cp", path, "-o", str(tmp_path)])

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
    [["dir/", "dir/test", "dir/subdirectory_1/",
        "dir/subdirectory_2/", "dir/subdirectory_3/subdirectory_4/"]],
)
def test_cp_subdirectories(vfs: VirtualFilesystem, files: list[str], tmp_path: Path) -> None:
    output_path = tmp_path / "out"

    args = Mock()
    args.output = str(output_path)

    cp(None, vfs.path("dir/"), args)

    filesystem_files = (file.replace("dir/", "") for file in files)

    for directories in filesystem_files:
        assert output_path.joinpath(directories).exists()


def _symlink_args(**kwargs) -> Mock:
    """Return a Mock args object with symlink-related flags set to their defaults."""
    args = Mock()
    args.no_dereference = False
    args.preserve = None
    args.d = False
    for k, v in kwargs.items():
        setattr(args, k, v)
    return args


@pytest.mark.parametrize("files", [[]])
@pytest.mark.skipif(_sys.platform == "win32", reason="symlink preservation not supported on Windows")
def test_cp_symlink_no_dereference(vfs: VirtualFilesystem, tmp_path: Path) -> None:
    """Test that -P/--no-dereference preserves symlinks instead of copying target content."""
    vfs.map_file_entry("target_file", VirtualFile(
        vfs, "target_file", io.BytesIO(b"content")))
    vfs.symlink("/target_file", "link_to_file")

    output_path = tmp_path / "out"
    args = _symlink_args(output=str(output_path), no_dereference=True)

    cp(None, vfs.path("link_to_file"), args)

    result = output_path / "link_to_file"
    assert result.is_symlink()
    assert str(result.readlink()) == "/target_file"


@pytest.mark.parametrize("files", [[]])
@pytest.mark.skipif(_sys.platform == "win32", reason="symlink preservation not supported on Windows")
def test_cp_symlink_preserve_links(vfs: VirtualFilesystem, tmp_path: Path) -> None:
    """Test that --preserve=links preserves symlinks."""
    vfs.map_file_entry("target_file", VirtualFile(
        vfs, "target_file", io.BytesIO(b"content")))
    vfs.symlink("/target_file", "link_to_file")

    output_path = tmp_path / "out"
    args = _symlink_args(output=str(output_path), preserve="links")

    cp(None, vfs.path("link_to_file"), args)

    result = output_path / "link_to_file"
    assert result.is_symlink()
    assert str(result.readlink()) == "/target_file"


@pytest.mark.parametrize("files", [[]])
@pytest.mark.skipif(_sys.platform == "win32", reason="symlink preservation not supported on Windows")
def test_cp_symlink_d_flag(vfs: VirtualFilesystem, tmp_path: Path) -> None:
    """Test that -d (--no-dereference --preserve=links) preserves symlinks."""
    vfs.map_file_entry("target_file", VirtualFile(
        vfs, "target_file", io.BytesIO(b"content")))
    vfs.symlink("/target_file", "link_to_file")

    output_path = tmp_path / "out"
    args = _symlink_args(output=str(output_path), d=True)

    cp(None, vfs.path("link_to_file"), args)

    result = output_path / "link_to_file"
    assert result.is_symlink()
    assert str(result.readlink()) == "/target_file"


@pytest.mark.parametrize("files", [[]])
@pytest.mark.skipif(_sys.platform == "win32", reason="symlink preservation not supported on Windows")
def test_cp_symlink_in_directory_no_dereference(vfs: VirtualFilesystem, tmp_path: Path) -> None:
    """Test that -P preserves symlinks encountered during directory traversal."""
    vfs.makedirs("dir")
    vfs.map_file_entry("dir/real_file", VirtualFile(vfs,
                       "dir/real_file", io.BytesIO(b"content")))
    vfs.symlink("/dir/real_file", "dir/link_to_file")

    output_path = tmp_path / "out"
    args = _symlink_args(output=str(output_path), no_dereference=True)

    cp(None, vfs.path("dir"), args)

    assert (output_path / "link_to_file").is_symlink()
    assert str((output_path / "link_to_file").readlink()) == "/dir/real_file"


@pytest.mark.parametrize("files", [[]])
def test_cp_symlink_dereference_by_default(vfs: VirtualFilesystem, tmp_path: Path) -> None:
    """Test that without any flags, symlinks are followed and target content is copied."""
    vfs.map_file_entry("target_file", VirtualFile(
        vfs, "target_file", io.BytesIO(b"content")))
    vfs.symlink("/target_file", "link_to_file")

    output_path = tmp_path / "out"
    args = _symlink_args(output=str(output_path))

    cp(None, vfs.path("link_to_file"), args)

    result = output_path / "link_to_file"
    assert result.exists()
    assert not result.is_symlink()


@pytest.mark.parametrize(
    ("no_dereference", "preserve", "d", "expected"),
    [
        (True, None, False, True),
        (False, "links", False, True),
        (False, "all", False, True),
        (False, "links,mode", False, True),
        (False, None, True, True),
        (False, None, False, False),
        (False, "mode,ownership", False, False),
    ],
)
def test_preserve_links(
    no_dereference: bool, preserve: str | None, d: bool, expected: bool
) -> None:
    args = Mock()
    args.no_dereference = no_dereference
    args.preserve = preserve
    args.d = d
    assert _preserve_links(args) == expected


@pytest.mark.parametrize(
    ("preserve", "expected_warnings"),
    [
        ("mode", {"mode"}),
        ("ownership", {"ownership"}),
        ("mode,ownership", {"mode", "ownership"}),
        ("links,mode", {"mode"}),
        ("links", set()),
        ("all", set()),
    ],
)
def test_preserve_links_warns_unsupported(
    preserve: str, expected_warnings: set[str], caplog: pytest.LogCaptureFixture
) -> None:
    args = Mock()
    args.no_dereference = False
    args.preserve = preserve
    args.d = False

    import logging

    with caplog.at_level(logging.WARNING, logger="dissect.target.tools.fs"):
        _preserve_links(args)

    if expected_warnings:
        assert caplog.records, "Expected a warning but none was emitted"
        warned_attrs = {attr for record in caplog.records for attr in record.message.split(": ", 1)[-1].split(", ")}
        assert warned_attrs == expected_warnings
    else:
        assert not caplog.records, f"Expected no warnings but got: {[r.message for r in caplog.records]}"
