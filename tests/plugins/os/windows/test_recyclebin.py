from __future__ import annotations

import io
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import Mock, mock_open, patch

import pytest

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.windows.recyclebin import RecyclebinPlugin, c_recyclebin

if TYPE_CHECKING:
    from dissect.target.target import Target


@pytest.fixture
def recycle_bin(tmp_path: Path) -> VirtualFilesystem:
    recycle_bin = VirtualFilesystem()
    recycle_bin.map_dir("$a_random_recycle_bin_file", tmp_path)
    return recycle_bin


def test_recycle_bin_compatibility_failed(target_win: Target) -> None:
    with pytest.raises(UnsupportedPluginError):
        RecyclebinPlugin(target_win).check_compatible()


def test_recycle_bin_compat_succeeded(target_win: Target, recycle_bin: VirtualFilesystem) -> None:
    target_win.fs.mount("C:\\$recycle.bin", recycle_bin)
    assert RecyclebinPlugin(target_win).check_compatible() is None


def test_read_recycle_bin(target_win: Target) -> None:
    mocked_file = Mock()

    mocked_file.is_file.return_value = True
    mocked_file.is_dir.return_value = False
    with patch.object(RecyclebinPlugin, "read_bin_file") as mocked_bin_file:
        assert [mocked_bin_file.return_value] == list(RecyclebinPlugin(target_win).read_recycle_bin(mocked_file))


def test_filtered_name(target_win: Target) -> None:
    mocked_file = Mock()
    mocked_file.is_file.return_value = True
    mocked_file.is_dir.return_value = False

    mocked_file.name = "hello"

    assert list(RecyclebinPlugin(target_win).read_recycle_bin(mocked_file)) == []


def test_read_recycle_bin_directory(target_win: Target) -> None:
    mocked_dir = Mock()
    mocked_dir.is_file.return_value = False
    mocked_dir.is_dir.return_value = True
    mocked_dir.name = "SID-SOME_RANDOM_SID"

    mocked_file = Mock()
    mocked_file.is_file.return_value = True
    mocked_file.is_dir.return_value = False
    mocked_file.name = "$ihello"

    mocked_dir.iterdir.return_value = [mocked_file] * 3

    with patch.object(RecyclebinPlugin, "read_bin_file", return_value=mocked_file):
        data = list(RecyclebinPlugin(target_win).read_recycle_bin(mocked_dir))

        assert data == [mocked_file] * 3


@pytest.mark.parametrize(
    ("version_number", "expected_header"),
    [
        (b"\x00" * 8, "header_v1"),
        (b"\x01" * 8, "header_v1"),
        (b"\x02" + b"\x00" * 7, "header_v2"),
    ],
)
def test_parse_header(target_win: Target, version_number: bytes, expected_header: str) -> None:
    recycle_plugin = RecyclebinPlugin(target_win)

    header = recycle_plugin.select_header(version_number)
    assert header is getattr(c_recyclebin, expected_header)


@pytest.mark.parametrize(
    "path",
    [
        "file/to/some/sid",
        "file/to/$recycle.bin/sid",
    ],
)
def test_read_bin_file_unknown(target_win: Target, path: str) -> None:
    recycle_plugin = RecyclebinPlugin(target_win)

    header_1 = c_recyclebin.header_v1(version=0, file_size=0x20, timestamp=0x20, filename="hello_world" + "\x00" * 249)

    with patch.object(Path, "open", mock_open(read_data=header_1.dumps())):
        normal_path = Path(path)

        output = recycle_plugin.read_bin_file(normal_path)

    assert output.filesize == 0x20
    assert output.path == "hello_world"


def test_recyclebin_plugin_file(target_win: Target, recycle_bin: VirtualFilesystem) -> None:
    recycle_bin.map_file_fh("$ihello_world", io.BytesIO(b""))

    target_win.fs.mount("C:\\$recycle.bin", recycle_bin)
    target_win.fs.mount("D:\\$recycle.bin", recycle_bin)
    target_win.add_plugin(RecyclebinPlugin)

    with patch.object(RecyclebinPlugin, "read_bin_file") as mocked_bin_file:
        recycle_bin_entries = list(target_win.recyclebin())
        assert recycle_bin_entries == [mocked_bin_file.return_value, mocked_bin_file.return_value]


def test_recyclebin_plugin_wrong_prefix(target_win: Target, recycle_bin: VirtualFilesystem) -> None:
    recycle_bin.map_file_fh("hello_world", io.BytesIO(b""))
    target_win.fs.mount("C:\\$recycle.bin", recycle_bin)
    target_win.add_plugin(RecyclebinPlugin)

    with patch.object(RecyclebinPlugin, "read_bin_file"):
        recycle_bin_entries = list(target_win.recyclebin())
        assert recycle_bin_entries == []


@pytest.mark.parametrize(
    ("path", "expected_output"),
    [
        ("C:/$Recycle.bin/sid-data/file", "sid-data"),
        ("$Recycle.bin/sid-data/file", "sid-data"),
        ("$Recycle.bin/just_another_file", "unknown"),
        ("C:/$Recycle.bin/just_another_file", "unknown"),
    ],
)
def test_find_sid_from_path(target_win: Target, path: str, expected_output: str) -> None:
    recycle_plugin = RecyclebinPlugin(target_win)

    assert recycle_plugin.find_sid(Path(path)) == expected_output
