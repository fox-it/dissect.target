from __future__ import annotations

import sys
from typing import TYPE_CHECKING
from unittest.mock import MagicMock

from dissect.target.exceptions import FileNotFoundError
from dissect.target.filesystem import FilesystemEntry
from dissect.target.helpers.fsutil import stat_result
from dissect.target.tools.fsutils import print_extensive_file_stat_listing

if TYPE_CHECKING:
    import pytest

    from dissect.target.target import Target


def test_target_cli_print_extensive_file_stat(target_win: Target, capsys: pytest.CaptureFixture) -> None:
    mock_stat = stat_result([0o100777, 1, 2, 3, 1337, 7331, 999, 0, 0, 0])
    mock_entry = MagicMock(spec_set=FilesystemEntry)
    mock_entry.lstat.return_value = mock_stat
    mock_entry.is_symlink.return_value = False

    print_extensive_file_stat_listing(sys.stdout, "foo", mock_entry)

    captured = capsys.readouterr()
    assert captured.out == "-rwxrwxrwx 1337 7331        999 1970-01-01T00:00:00.000000+00:00 foo\n"


def test_print_extensive_file_stat_symlink(target_win: Target, capsys: pytest.CaptureFixture) -> None:
    mock_stat = stat_result([0o120777, 1, 2, 3, 1337, 7331, 999, 0, 0, 0])
    mock_entry = MagicMock(spec_set=FilesystemEntry)
    mock_entry.lstat.return_value = mock_stat
    mock_entry.is_symlink.return_value = True
    mock_entry.readlink.return_value = "bar"

    print_extensive_file_stat_listing(sys.stdout, "foo", mock_entry)

    captured = capsys.readouterr()
    assert captured.out == "lrwxrwxrwx 1337 7331        999 1970-01-01T00:00:00.000000+00:00 foo -> bar\n"


def test_print_extensive_file_stat_fail(target_win: Target, capsys: pytest.CaptureFixture) -> None:
    mock_entry = MagicMock(spec_set=FilesystemEntry)
    mock_entry.lstat.side_effect = FileNotFoundError("ERROR")
    print_extensive_file_stat_listing(sys.stdout, "foo", mock_entry)

    captured = capsys.readouterr()
    assert captured.out == "??????????    ?    ?          ? ????-??-??T??:??:??.??????+??:?? foo\n"
