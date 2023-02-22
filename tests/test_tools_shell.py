import sys
from unittest.mock import MagicMock

from dissect.target.exceptions import FileNotFoundError
from dissect.target.filesystem import FilesystemEntry
from dissect.target.helpers.fsutil import TargetPath, stat_result
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
