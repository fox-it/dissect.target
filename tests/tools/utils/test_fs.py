from __future__ import annotations

import stat
import sys
from typing import TYPE_CHECKING
from unittest.mock import MagicMock

import pytest

from dissect.target.exceptions import FileNotFoundError
from dissect.target.filesystem import FilesystemEntry
from dissect.target.helpers.fsutil import stat_result
from dissect.target.tools.utils.fs import LsEntry, file_type_from_mode, fmt_ls_colors, print_ls_entry

if TYPE_CHECKING:
    from dissect.target.target import Target


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        # Files
        pytest.param(stat.S_IFREG, "fi", id="file"),
        pytest.param(stat.S_IFREG | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH, "ex", id="executable"),
        pytest.param(stat.S_IFREG | stat.S_ISUID, "su", id="setuid"),
        pytest.param(stat.S_IFREG | stat.S_ISGID, "sg", id="setgid"),
        # Directories
        pytest.param(stat.S_IFDIR, "di", id="directory"),
        pytest.param(stat.S_IFDIR | stat.S_IWOTH, "ow", id="otherwritable"),
        pytest.param(stat.S_IFDIR | stat.S_ISVTX, "st", id="sticky"),
        pytest.param(stat.S_IFDIR | stat.S_IWOTH | stat.S_ISVTX, "tw", id="sticky-otherwritable"),
        # Special files
        pytest.param(stat.S_IFLNK, "ln", id="link"),
        pytest.param(stat.S_IFIFO, "pi", id="pipe"),
        pytest.param(stat.S_IFSOCK, "so", id="socket"),
        pytest.param(stat.S_IFBLK, "bd", id="blockdevice"),
        pytest.param(stat.S_IFCHR, "cd", id="chardevice"),
        # Other, unknown
        pytest.param(0, "or", id="other"),
        pytest.param(None, "or", id="other-none"),
    ],
)
def test_file_type_from_mode(mode: int | None, expected: str) -> None:
    """Test that file_type_from_mode correctly identifies file types and special permissions based on the mode."""
    assert file_type_from_mode(mode) == expected


@pytest.mark.parametrize(
    ("name", "has_color"),
    [
        pytest.param("archive.7z", True, id="7z"),
        pytest.param("notes.bak", True, id="bak"),
        pytest.param("script.sh", False, id="no-color"),
    ],
)
def test_fmt_ls_colors_file_extension(name: str, has_color: bool) -> None:
    """Test that fmt_ls_colors applies color codes based on some known file extensions."""
    if has_color:
        # The actual color code is not important for this test, just that it's different from the input name
        assert fmt_ls_colors("fi", name) != name
    else:
        # If no color should be applied, the output should be the same as the input name
        assert fmt_ls_colors("fi", name) == name


def test_target_cli_print_extensive_file_stat(target_win: Target, capsys: pytest.CaptureFixture) -> None:
    mock_stat = stat_result([0o100777, 1, 2, 3, 1337, 7331, 999, 0, 0, 0])
    mock_entry = MagicMock(spec_set=FilesystemEntry)
    mock_entry.lstat.return_value = mock_stat
    mock_entry.is_symlink.return_value = False

    print_ls_entry(stdout=sys.stdout, lsentry=LsEntry("foo", mock_entry, mock_stat), long_listing=True)

    captured = capsys.readouterr()
    assert captured.out == "-rwxrwxrwx 1337 7331        999 1970-01-01T00:00:00.000000+00:00 foo\n"


def test_print_extensive_file_stat_symlink(target_win: Target, capsys: pytest.CaptureFixture) -> None:
    mock_stat = stat_result([0o120777, 1, 2, 3, 1337, 7331, 999, 0, 0, 0])
    mock_entry = MagicMock(spec_set=FilesystemEntry)
    mock_entry.lstat.return_value = mock_stat
    mock_entry.is_symlink.return_value = True
    mock_entry.readlink.return_value = "bar"

    print_ls_entry(stdout=sys.stdout, lsentry=LsEntry("foo", mock_entry, mock_stat), long_listing=True)

    captured = capsys.readouterr()
    assert captured.out == "lrwxrwxrwx 1337 7331        999 1970-01-01T00:00:00.000000+00:00 foo -> bar\n"


def test_print_extensive_file_stat_fail(target_win: Target, capsys: pytest.CaptureFixture) -> None:
    mock_entry = MagicMock(spec_set=FilesystemEntry)
    mock_entry.lstat.side_effect = FileNotFoundError("ERROR")
    print_ls_entry(stdout=sys.stdout, lsentry=LsEntry("foo", mock_entry, None), long_listing=True)

    captured = capsys.readouterr()
    assert captured.out == "??????????    ?    ?          ? ????-??-??T??:??:??.??????+??:?? foo\n"
