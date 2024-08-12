import argparse
import platform
import sys
from io import BytesIO, StringIO
from pathlib import Path
from typing import Callable
from unittest.mock import MagicMock

import pytest

from dissect.target.helpers.fsutil import TargetPath, normalize
from dissect.target.target import Target
from dissect.target.tools import fsutils
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
def test_build_pipe() -> None:
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
def test_build_pipe_nonexisting_command() -> None:
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
def test_build_pipe_broken_pipe() -> None:
    # `ls` command does not accept stdin, so pipe closes prematurely
    pipeparts = ["grep", "test1", "|", "ls"]
    input_stream = "input data test1"

    # there should be no errors raised
    with build_pipe(pipeparts) as (pipe_stdin, _):
        print(input_stream, file=pipe_stdin)

    # there should be no errors raised
    with build_pipe_stdout(pipeparts) as pipe_stdin:
        print(input_stream, file=pipe_stdin)


def test_targethubcli_autocomplete_enter(make_mock_targets: Callable) -> None:
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


def test_targetcli_autocomplete(target_bare: Target, monkeypatch: pytest.MonkeyPatch) -> None:
    target_cli = TargetCli(target_bare)

    mock_subfolder = MagicMock(spec_set=TargetPath)
    mock_subfolder.is_dir.return_value = True
    mock_subfile = MagicMock(spec_set=TargetPath)
    mock_subfile.is_dir.return_value = False

    base_path = "/base-path"

    subfolder_name = "subfolder"
    subfile_name = "subfile"
    subpath_mismatch = "mismatch"

    def dummy_scandir(path: TargetPath):
        assert str(path) == base_path
        return [
            (mock_subfolder, subfolder_name),
            (mock_subfile, subfile_name),
            (None, subpath_mismatch),
        ]

    monkeypatch.setattr("dissect.target.tools.shell.ls_scandir", dummy_scandir)
    suggestions = target_cli.completedefault("sub", f"ls {base_path}/sub", 3 + len(base_path), 3 + len(base_path) + 3)

    # We expect folder suggestions to be trailed with a '/'
    assert suggestions == [f"{subfolder_name}/", subfile_name]


@pytest.mark.skipif(platform.system() == "Windows", reason="Unix-specific test.")
def test_pipe_symbol_parsing(capfd: pytest.CaptureFixture, target_bare: Target) -> None:
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
def test_exec_target_command(capfd: pytest.CaptureFixture, target_default: Target) -> None:
    cli = TargetCli(target_default)
    # `users` from the general OSPlugin does not ouput any records, but as the
    # ouput is piped to, the records are transformed to a binary record stream,
    # so we pipe it through rdump to get a correct count of 0 from wc.
    cli.default("users | rdump | wc -l")

    sys.stdout.flush()
    sys.stderr.flush()

    captured = capfd.readouterr()

    assert captured.out.endswith("0\n")


def test_target_cli_ls(target_win: Target, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    # disable colorful output in `target-shell`
    monkeypatch.setattr(fsutils, "LS_COLORS", {})

    cli = TargetCli(target_win)
    cli.onecmd("ls")

    captured = capsys.readouterr()
    assert captured.out == "\n".join(["c:", "sysvol"]) + "\n"


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
def test_target_cli_save(
    target_win: Target, tmp_path: Path, folders: str, files: str, save: str, expected: str
) -> None:
    output_dir = tmp_path / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    cli = TargetCli(target_win)
    for folder in folders.split("|"):
        target_win.fs.root.makedirs(folder)
    for _file in files.split("|"):
        target_win.fs.root.map_file_fh(_file, BytesIO(_file.encode("utf-8")))
    args = argparse.Namespace(path=[save], out=output_dir, verbose=False)
    cli.cmd_save(args, sys.stdout)

    def _map_function(path: Path) -> str:
        relative_path = str(path.relative_to(output_dir))
        return normalize(relative_path, alt_separator=target_win.fs.alt_separator)

    path_map = map(lambda path: _map_function(path), output_dir.rglob("*"))
    tree = "|".join(sorted(path_map))

    assert tree == expected


def run_target_shell(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture, target_path: str, stdin: str
) -> tuple[bytes, bytes]:
    with monkeypatch.context() as m:
        m.setattr("sys.argv", ["target-shell", target_path])
        m.setattr("sys.stdin", StringIO(stdin))
        m.setenv("NO_COLOR", "1")
        target_shell()
        return capsys.readouterr()


@pytest.mark.parametrize(
    "provided_input, expected_output",
    [
        ("hello", "world.txt"),  # Latin
        ("ħēļľŏ", "ŵőřŀđ.txt"),  # Latin Extended-A
        ("مرحبًا", "عالم.txt"),  # Arabic
        ("你好", "世界.txt"),  # Chinese Simplified
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
    out, err = run_target_shell(
        monkeypatch, capsys, absolute_path("_data/tools/shell/unicode.tar"), f"ls unicode/charsets/{provided_input}"
    )
    out = out.replace("unicode.tar:/$", "").strip()
    assert out == expected_output
    assert "unrecognized arguments" not in err


def test_shell_cmd_alias(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
    """test if alias commands call their parent attribute correctly."""
    target_path = absolute_path("_data/tools/info/image.tar")

    # 'dir' and 'ls' should return the same output
    dir_out, _ = run_target_shell(monkeypatch, capsys, target_path, "dir")
    ls_out, _ = run_target_shell(monkeypatch, capsys, target_path, "ls")
    assert dir_out == ls_out

    # ll is not really a standard aliased command so we test that separately.
    ls_la_out, _ = run_target_shell(monkeypatch, capsys, target_path, "ls -la")
    ll_out, _ = run_target_shell(monkeypatch, capsys, target_path, "ll")
    assert ls_la_out == ll_out
