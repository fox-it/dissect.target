import argparse
import platform
import sys
from io import BytesIO, StringIO
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from dissect.target.exceptions import FileNotFoundError
from dissect.target.filesystem import FilesystemEntry
from dissect.target.helpers.fsutil import TargetPath, normalize, stat_result
from dissect.target.tools import shell
from dissect.target.tools.shell import (
    TargetCli,
    TargetHubCli,
    build_pipe,
    build_pipe_stdout,
)
from dissect.target.tools.shell import main as target_shell
from tests._utils import absolute_path

GREP_MATCH = "test1 and test2"
GREP_MISSING = "test2 alone"
INPUT_STREAM = f"""
    line 1
    test1 alone
    {GREP_MATCH}
    {GREP_MISSING}
    last line
"""


@pytest.mark.skipif(platform.system() == "Windows", reason="Unix-specific test.")
def test_build_pipe():
    pipeparts = [
        "grep",
        "test2",
        "|",
        "grep",
        "test1",
    ]

    with build_pipe(pipeparts) as (pipe_stdin, pipe_stdout):
        print(INPUT_STREAM, file=pipe_stdin)

    output = pipe_stdout.read().decode("utf-8").strip()
    assert output == GREP_MATCH


@pytest.mark.skipif(platform.system() == "Windows", reason="Unix-specific test.")
def test_build_pipe_nonexisting_command():
    dummy_command = "non-existing-command"
    pipeparts = ["grep", "test1", "|", dummy_command]
    input_stream = "input data test1"

    with pytest.raises(OSError):
        with build_pipe_stdout(pipeparts) as pipe_stdin:
            print(input_stream, file=pipe_stdin)

    with pytest.raises(OSError):
        with build_pipe(pipeparts) as (pipe_stdin, _):
            print(input_stream, file=pipe_stdin)


@pytest.mark.skipif(platform.system() == "Windows", reason="Unix-specific test.")
def test_build_pipe_broken_pipe():
    # `ls` command does not accept stdin, so pipe closes prematurely
    pipeparts = ["grep", "test1", "|", "ls"]
    input_stream = "input data test1"

    # there should be no errors raised
    with build_pipe(pipeparts) as (pipe_stdin, _):
        print(input_stream, file=pipe_stdin)

    # there should be no errors raised
    with build_pipe_stdout(pipeparts) as pipe_stdin:
        print(input_stream, file=pipe_stdin)


def test_targethubcli_autocomplete_enter(make_mock_targets):
    target1, target2 = make_mock_targets(2)

    target1.hostname = "dev-null-1.localhost"
    target2.hostname = "dev-null-2.localhost"

    hub_cli = TargetHubCli([target1, target2], TargetCli)
    suggestions = hub_cli.complete_enter("dev-", "enter dev-", 6, 10)
    assert suggestions == [
        "dev-null-1.localhost",
        "dev-null-2.localhost",
    ]

    suggestions = hub_cli.complete_enter("dev-null-1", "enter dev-null-1", 6, 16)
    assert suggestions == ["dev-null-1.localhost"]

    suggestions = hub_cli.complete_enter("xxx-", "enter xxx-", 6, 10)
    assert suggestions == []

    suggestions = hub_cli.complete_enter("1", "enter 1", 6, 7)
    assert suggestions == ["1"]


def test_targetcli_autocomplete(target_bare):
    target_cli = TargetCli(target_bare)

    base_path = "/base-path/"
    subpath_match = "subpath1"
    subpath_mismatch = "mismatch"

    def dummy_scandir(path):
        assert path == base_path
        return [
            (None, subpath_match),
            (None, subpath_mismatch),
        ]

    target_cli.scandir = dummy_scandir

    suggestions = target_cli.completedefault("sub", f"ls {base_path}sub", 3 + len(base_path), 3 + len(base_path) + 3)
    assert suggestions == [subpath_match]


@pytest.mark.skipif(platform.system() == "Windows", reason="Unix-specific test.")
def test_pipe_symbol_parsing(capfd, target_bare):
    cli = TargetCli(target_bare)

    def mock_func(func_args, func_stdout):
        # if the operation of parsing out the first `|` was successful,
        # `mock_func` should receive an empty `func_args` list
        assert len(func_args) == 0

        print(INPUT_STREAM, file=func_stdout)

    command_args_str = "|grep test2|grep test1"

    cli._exec(mock_func, command_args_str)

    sys.stdout.flush()
    sys.stderr.flush()

    captured = capfd.readouterr()

    assert GREP_MATCH in captured.out
    assert GREP_MISSING not in captured.out


@pytest.mark.skipif(platform.system() == "Windows", reason="Unix-specific test.")
def test_exec_target_command(capfd, target_default):
    cli = TargetCli(target_default)
    command = "users"
    # `users` from the general OSPlugin does not ouput any records, but as the
    # ouput is piped to, the records are transformed to a binary record stream,
    # so we pipe it through rdump to get a correct count of 0 from wc.
    command_args_str = "| rdump | wc -l"
    cli._exec_target(command, command_args_str)

    sys.stdout.flush()
    sys.stderr.flush()

    captured = capfd.readouterr()

    assert captured.out.endswith("0\n")


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


@pytest.mark.parametrize(
    "provided_input, expected_output",
    [
        ("hello", "world.txt"),  # Latin
        ("ħēļľŏ", "ŵőřŀđ.txt"),  # Latin Extended-A
        ("مرحبًا", "عالم.txt"),  # Arabic
        ("你好", "世界.txt"),  # Chineese Simplified
        ("привет", "мир.txt"),  # Cyrillic
        ("🕵🕵🕵", "👀👀👀.txt"),  # Emoji
    ],
)
def test_target_cli_unicode_argparse(
    capsys: pytest.CaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
    provided_input: str,
    expected_output: str,
) -> None:
    with monkeypatch.context() as m:
        target_file = absolute_path("_data/tools/shell/unicode.tar")
        m.setattr("sys.argv", ["target-shell", target_file])
        m.setattr("sys.stdin", StringIO(f"ls unicode/charsets/{provided_input}"))
        target_shell()
        out, err = capsys.readouterr()
        out = out.replace("unicode.tar />", "").strip()

        assert out == expected_output
        assert "unrecognized arguments" not in err
