import argparse
import sys
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from dissect.target.exceptions import FileNotFoundError
from dissect.target.filesystem import FilesystemEntry
from dissect.target.helpers.fsutil import TargetPath, normalize, stat_result
from dissect.target.tools import shell
from dissect.target.tools.shell import TargetCli


def test_target_cli_ls(target_win, capsys, monkeypatch):
    # disable colorful output in `target-shell`
    monkeypatch.setattr(shell, "LS_COLORS", {})

    cli = TargetCli(target_win)
    cli.onecmd("ls")

    captured = capsys.readouterr()
    assert captured.out == "\n".join(["c:", "sysvol"]) + "\n"


def test_target_cli_print_extensive_file_stat(target_win, capsys):
    mock_stat = stat_result([0o1777, 1, 2, 3, 1337, 7331, 999, 0, 0, 0])
    mock_entry = MagicMock(spec_set=FilesystemEntry)
    mock_entry.lstat.return_value = mock_stat
    mock_entry.is_symlink.return_value = False
    mock_path = MagicMock(spec_set=TargetPath)
    mock_path.get.return_value = mock_entry

    cli = TargetCli(target_win)
    cli.print_extensive_file_stat(sys.stdout, mock_path, "foo")

    captured = capsys.readouterr()
    assert captured.out == "-rwxrwxrwx 1337 7331    999 1970-01-01T00:00:00 foo\n"


def test_target_cli_print_extensive_file_stat_symlink(target_win, capsys):
    mock_stat = stat_result([0o1777, 1, 2, 3, 1337, 7331, 999, 0, 0, 0])
    mock_entry = MagicMock(spec_set=FilesystemEntry)
    mock_entry.lstat.return_value = mock_stat
    mock_entry.is_symlink.return_value = True
    mock_entry.readlink.return_value = "bar"
    mock_path = MagicMock(spec_set=TargetPath)
    mock_path.get.return_value = mock_entry

    cli = TargetCli(target_win)
    cli.print_extensive_file_stat(sys.stdout, mock_path, "foo")

    captured = capsys.readouterr()
    assert captured.out == "-rwxrwxrwx 1337 7331    999 1970-01-01T00:00:00 foo -> bar\n"


def test_target_cli_print_extensive_file_stat_fail(target_win, capsys):
    mock_path = MagicMock(spec_set=TargetPath)
    mock_path.get.side_effect = FileNotFoundError("ERROR")

    cli = TargetCli(target_win)
    cli.print_extensive_file_stat(sys.stdout, mock_path, "foo")

    captured = capsys.readouterr()
    assert captured.out == "??????????    ?    ?      ? ????-??-??T??:??:??.?????? foo\n"


@pytest.mark.parametrize(
    "folders, files, save, expected",
    [
        ("/a/b/c|/d", "/a/1.txt|/a/b/2.txt|/d/3.txt", "/a", "a|a/1.txt|a/b|a/b/2.txt|a/b/c"),
        ("/a/b/c|/d", "/a/1.txt|/b/2.txt|/d/3.txt", "/d", "d|d/3.txt"),
        ("/a/b/c|/d", "/a/1.txt|/b/2.txt|/d/3.txt", "/b", "b|b/2.txt"),
        ("/p/q/n", "/p/q/n/1.txt", "/p/q/n/1.txt", "1.txt"),
        ("/p/q/n", "/p/q/n/1.txt|2.txt", "/p/q/n/1.txt", "1.txt"),
        (
            "/save_test/bin|save_test/data",
            "/save_test/data/hello|/save_test/bin/world",
            "/save_test",
            "save_test|save_test/bin|save_test/bin/world|save_test/data|save_test/data/hello",
        ),
    ],
)
def test_target_cli_save(target_win, tmp_path, folders, files, save, expected):
    cli = TargetCli(target_win)
    for folder in folders.split("|"):
        target_win.fs.root.makedirs(folder)
    for _file in files.split("|"):
        target_win.fs.root.map_file_fh(_file, BytesIO(_file.encode("utf-8")))
    args = argparse.Namespace(path=[save], out=tmp_path, verbose=False)
    cli.cmd_save(args, sys.stdout)

    def _map_function(path: Path) -> str:
        relative_path = str(path.relative_to(tmp_path))
        return normalize(relative_path, alt_separator=target_win.fs.alt_separator)

    path_map = map(lambda path: _map_function(path), tmp_path.rglob("*"))
    tree = "|".join(sorted(path_map))
    assert tree == expected
