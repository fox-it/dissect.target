import sys

import pytest

from dissect.target.tools.shell import (
    TargetCli,
    TargetHubCli,
    build_pipe,
    build_pipe_stdout,
)

GREP_MATCH = "test1 and test2"
GREP_MISSING = "test2 alone"
INPUT_STREAM = f"""
    line 1
    test1 alone
    {GREP_MATCH}
    {GREP_MISSING}
    last line
"""


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


def test_targetcli_autocomplete(mock_target):
    target_cli = TargetCli(mock_target)

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


def test_pipe_symbol_parsing(capfd, mock_target):
    cli = TargetCli(mock_target)

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


def test_exec_target_command(capfd, mock_target):
    cli = TargetCli(mock_target)
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
