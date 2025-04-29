from __future__ import annotations

import argparse
import os
import pathlib
import platform
import re
import sys
from collections import ChainMap
from io import BytesIO, StringIO
from pathlib import Path
from typing import IO, TYPE_CHECKING, Callable, TextIO
from unittest.mock import MagicMock, call, mock_open, patch

import pytest

from dissect.target.helpers.fsutil import TargetPath, normalize
from dissect.target.tools import fsutils
from dissect.target.tools.shell import (
    TargetCli,
    TargetHubCli,
    build_pipe,
    build_pipe_stdout,
)
from dissect.target.tools.shell import main as target_shell
from tests._utils import absolute_path

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

try:
    import pexpect
    import pexpect.expect

    HAS_PEXPECT = True
except ImportError:
    HAS_PEXPECT = False

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

    with (
        pytest.raises(OSError, match="No such file or directory: 'non-existing-command'"),
        build_pipe_stdout(pipeparts) as pipe_stdin,
    ):
        print(input_stream, file=pipe_stdin)

    with (
        pytest.raises(OSError, match="No such file or directory: 'non-existing-command'"),
        build_pipe(pipeparts) as (pipe_stdin, _),
    ):
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

    def dummy_scandir(path: TargetPath) -> list[tuple[TargetPath | None, str]]:
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


@pytest.fixture
def targetrc_file() -> Iterator[list[str]]:
    content = """
    ls
        # This is a comment line and should be ignored
    ll
    """

    original_open = pathlib.Path.open

    def custom_open(self: Path, *args, **kwargs) -> IO:
        if self.name.endswith(".targetrc"):
            return mock_open(read_data=content)()
        return original_open(self, *args, **kwargs)

    with patch("pathlib.Path.open", custom_open):
        yield ["ls", "ll"]


def test_targetcli_targetrc(target_bare: Target, targetrc_file: list[str]) -> None:
    with patch.object(TargetCli, "onecmd", autospec=True) as mock_onecmd:
        cli = TargetCli(target_bare)

        cli.preloop()

        expected_calls = [call(cli, cmd) for cmd in targetrc_file]
        mock_onecmd.assert_has_calls(expected_calls, any_order=False)


@pytest.mark.skipif(platform.system() == "Windows", reason="Unix-specific test.")
def test_pipe_symbol_parsing(capfd: pytest.CaptureFixture, target_bare: Target) -> None:
    cli = TargetCli(target_bare)

    def mock_func(func_args: list[str], func_stdout: TextIO) -> None:
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
    assert captured.out == "c:\nsysvol" + "\n"


@pytest.mark.parametrize(
    ("folders", "files", "save", "expected"),
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

    path_map = (_map_function(path) for path in output_dir.rglob("*"))
    tree = "|".join(sorted(path_map))

    assert tree == expected


def run_target_shell(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture, argv: str | list, stdin: str
) -> tuple[bytes, bytes]:
    with monkeypatch.context() as m:
        m.setattr("sys.argv", ["target-shell"] + (argv if isinstance(argv, list) else [argv]))
        m.setattr("sys.stdin", StringIO(stdin))
        m.setenv("NO_COLOR", "1")
        target_shell()
        return capsys.readouterr()


@pytest.mark.parametrize(
    ("provided_input", "expected_output"),
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
        monkeypatch,
        capsys,
        str(absolute_path("_data/tools/shell/unicode.tar")),
        f"ls unicode/charsets/{provided_input}",
    )
    out = out.replace("unicode.tar:/$", "").strip()
    assert out == expected_output
    assert "unrecognized arguments" not in err


def test_shell_cmd_alias(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
    """Test if alias commands call their parent attribute correctly."""
    target_path = str(absolute_path("_data/tools/info/image.tar"))

    # 'dir' and 'ls' should return the same output
    dir_out, _ = run_target_shell(monkeypatch, capsys, target_path, "dir")
    ls_out, _ = run_target_shell(monkeypatch, capsys, target_path, "ls")
    assert dir_out == ls_out

    # ll is not really a standard aliased command so we test that separately.
    ls_la_out, _ = run_target_shell(monkeypatch, capsys, target_path, "ls -la")
    ll_out, _ = run_target_shell(monkeypatch, capsys, target_path, "ll")
    assert ls_la_out == ll_out


def test_shell_cli_command(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
    target_path = str(absolute_path("_data/tools/info/image.tar"))
    dir_out, _ = run_target_shell(monkeypatch, capsys, target_path, "dir")
    ls_out, _ = run_target_shell(monkeypatch, capsys, [target_path, "-c", "dir"], "")
    assert dir_out == "ubuntu:/$ " + ls_out + "ubuntu:/$ \n"


def test_shell_cmd_alias_runtime(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
    """Test if alias commands call their parent attribute correctly."""
    target_path = str(absolute_path("_data/tools/info/image.tar"))

    # 'list' and 'ls' should return the same output after runtime aliasing
    list_out, _ = run_target_shell(monkeypatch, capsys, target_path, "alias list=ls xxl='ls -la'\nlist")
    sys.stdout.flush()
    ls_out, _ = run_target_shell(monkeypatch, capsys, target_path, "ls")
    assert list_out == "ubuntu:/$ " + ls_out

    # list aliases
    sys.stdout.flush()
    out, _ = run_target_shell(monkeypatch, capsys, target_path, "alias")
    assert out == "ubuntu:/$ alias list=ls\nalias xxl=ls -la\nubuntu:/$ \n"

    # list single aliases
    sys.stdout.flush()
    out, _ = run_target_shell(monkeypatch, capsys, target_path, "alias list")
    assert out == "ubuntu:/$ alias list=ls\nubuntu:/$ \n"

    # unalias
    sys.stdout.flush()
    run_target_shell(monkeypatch, capsys, target_path, "unalias xxl")
    out, _ = run_target_shell(monkeypatch, capsys, target_path, "alias")
    assert out == "ubuntu:/$ alias list=ls\nubuntu:/$ \n"

    # unalias multiple and non-existant
    sys.stdout.flush()
    out, _ = run_target_shell(monkeypatch, capsys, target_path, "unalias list abc")
    assert out == "ubuntu:/$ alias abc not found\nubuntu:/$ \n"

    # alias multiple broken - b will be empty
    sys.stdout.flush()
    run_target_shell(monkeypatch, capsys, target_path, "alias a=1 b=")
    out, _ = run_target_shell(monkeypatch, capsys, target_path, "alias")
    assert out == "ubuntu:/$ alias a=1\nalias b=\nubuntu:/$ \n"

    # alias set/get mixed
    sys.stdout.flush()
    out, _ = run_target_shell(monkeypatch, capsys, target_path, "alias b=1 a")
    assert out == "ubuntu:/$ alias a=1\nubuntu:/$ \n"

    # alias with other symbols not allowed due to parser difference
    sys.stdout.flush()
    out, _ = run_target_shell(monkeypatch, capsys, target_path, "alias b+1")
    assert out.find("*** Unhandled error: Token not allowed") > -1


def test_shell_hostname_escaping(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture, tmp_path: Path
) -> None:
    """Test if we properly escape hostnames in the base prompt."""

    tmp_path.joinpath("etc").mkdir()
    tmp_path.joinpath("var").mkdir()
    tmp_path.joinpath("opt").mkdir()
    tmp_path.joinpath("etc/hostname").write_bytes(b"hostname\x00\x01\x02\x03")

    sys.stdout.flush()
    out, _ = run_target_shell(monkeypatch, capsys, str(tmp_path), "\n")

    assert "hostname\\x00\\x01\\x02\\x03" in out


@pytest.mark.skipif(not HAS_PEXPECT, reason="requires pexpect")
@pytest.mark.skipif(
    platform.system() == "Windows",
    reason="pexpect.spawn not available on Windows",
)
def test_shell_prompt_tab_autocomplete() -> None:
    """Test the prompt tab-autocompletion."""

    ANSI_ESCAPE = re.compile(rb"\x07|\x08|\x0d|\x7f|\x1b[@-_][0-?]*[ -/]*[@-~]")
    original_new_data = pexpect.expect.Expecter.new_data

    def ansi_new_data(cls: pexpect.expect.Expecter, data: bytes) -> int | None:
        """Matches on carriage returns (``\x0d`` / ``\r``) so change your ``child.expect()`` calls accordingly."""
        return original_new_data(cls, ANSI_ESCAPE.sub(b"", data))

    target_path = absolute_path("_data/tools/info/image.tar")

    with patch("pexpect.expect.Expecter.new_data", new=ansi_new_data):
        # We set NO_COLOR=1 so that the output is not colored and easier to match
        child = pexpect.spawn("target-shell", args=[str(target_path)], env=ChainMap(os.environ, {"NO_COLOR": "1"}))

        # increase window size to avoid line wrapping
        child.setwinsize(100, 100)

        if platform.python_implementation() == "PyPy":
            major, minor, _patch = tuple(map(int, platform.python_version_tuple()))
            if major < 3 or (major == 3 and (minor < 10 or (minor == 10 and _patch < 14))):
                child.expect_exact(
                    "Note for users of PyPy < 3.10.14:\n"
                    "Autocomplete might not work due to an outdated version of pyrepl/readline.py\n"
                    "To fix this, please update your version of PyPy.\n",
                    timeout=30,
                )
                child.kill(9)  # 🔫
                return

            pytest.skip("PyPy in CI does not have a functional readline")

        child.expect_exact("ubuntu:/$ ", timeout=30)
        # this should auto complete to `ls /home/user`
        child.send("ls /home/u\t")
        # expect the prompt to be printed again
        child.expect_exact("ls /home/user/", timeout=5)
        # execute the autocompleted command
        child.send("\n")
        # we expect the files in /home/user to be printed
        child.expect_exact(".bash_history\n.zsh_history\n", timeout=5)
        child.expect_exact("ubuntu:/$ ", timeout=5)

        # send partial ls /etc/ command
        child.send("ls /etc/")

        # we send two TABS to get the list of files in /etc/
        child.send("\t\t")

        # expect the files in /etc/ to be printed
        child.expect(
            r"hosts\s+localtime\s+network\/\s+os-release\s+passwd\s+shadow\s+timezone\s*ubuntu:\/\$ ls \/etc\/",
            timeout=5,
        )

        # send newline to just list everything in /etc/
        child.send("\n")
        # expect the last few files in /etc/ to be printed
        child.expect_exact("shadow\ntimezone\n", timeout=5)

        # exit the shell
        child.expect_exact("ubuntu:/$ ", timeout=5)
        child.sendline("exit")
        child.expect(pexpect.EOF, timeout=5)
