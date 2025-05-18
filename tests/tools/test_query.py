from __future__ import annotations

import json
import os
import re
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

import pytest

from dissect.target.plugin import FunctionDescriptor
from dissect.target.tools.query import main as target_query

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_list(capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    with monkeypatch.context() as m:
        m.setattr("sys.argv", ["target-query", "--list"])

        target_query()
        out, _ = capsys.readouterr()

        assert out.startswith("Available plugins:")
        assert "Failed to load:\n    None\n\nAvailable loaders:\n" in out


@pytest.mark.parametrize(
    ("given_funcs", "expected_invalid_funcs"),
    [
        (
            ["foo"],
            ["foo"],
        ),
        (
            ["bar", "version"],
            ["bar"],
        ),
        (
            ["version", "foo", "wireguard.config", "bar", "apps.webserver.iis*"],
            ["bar", "foo"],
        ),
        (
            ["apps.browser.*.downloads", "bar", "version", "foo"],
            ["bar", "foo"],
        ),
        (
            ["apps.webserver.iis.doesnt.exist", "apps.webserver.apache.access"],
            ["apps.webserver.iis.doesnt.exist"],
        ),
    ],
)
def test_invalid_functions(
    given_funcs: list[str],
    expected_invalid_funcs: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    with monkeypatch.context() as m:
        m.setattr(
            "sys.argv",
            ["target-query", "-f", ",".join(given_funcs), "tests/_data/loaders/tar/test-archive.tar.gz"],
        )

        with pytest.raises(SystemExit):
            target_query()
        _, err = capsys.readouterr()

        assert "target-query: error: argument -f/--function contains invalid plugin(s):" in err

        # Workaround for https://github.com/fox-it/dissect.target/issues/266
        RE_ERR = re.compile(r"contains invalid plugin\(s\)\: (?P<funcs>.*?)\n$")
        match = RE_ERR.search(err).groupdict()

        invalid_funcs = [i.strip() for i in match["funcs"].split(",")]
        invalid_funcs.sort()

        assert invalid_funcs == expected_invalid_funcs


@pytest.mark.parametrize(
    ("given_funcs", "expected_invalid_funcs"),
    [
        (
            ["foo"],
            ["foo"],
        ),
        (
            ["bar", "version"],
            ["bar"],
        ),
        (
            ["version", "foo", "wireguard.config", "bar", "apps.webserver.iis*"],
            ["bar", "foo"],
        ),
        (
            ["apps.browser.*.downloads", "bar", "version", "foo"],
            ["bar", "foo"],
        ),
        (
            ["apps.webserver.iis.doesnt.exist", "apps.webserver.apache.access"],
            ["apps.webserver.iis.doesnt.exist"],
        ),
    ],
)
def test_invalid_excluded_functions(
    given_funcs: list[str],
    expected_invalid_funcs: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    with monkeypatch.context() as m:
        m.setattr(
            "sys.argv",
            [
                "target-query",
                "-f",
                "hostname",
                "-xf",
                ",".join(given_funcs),
                "tests/_data/loaders/tar/test-archive.tar.gz",
            ],
        )

        with pytest.raises(SystemExit):
            target_query()
        _, err = capsys.readouterr()

        assert "target-query: error: argument -xf/--excluded-functions contains invalid plugin(s):" in err

        # Workaround for https://github.com/fox-it/dissect.target/issues/266
        RE_ERR = re.compile(r"contains invalid plugin\(s\)\: (?P<funcs>.*?)\n$")
        match = RE_ERR.search(err).groupdict()

        invalid_funcs = [i.strip() for i in match["funcs"].split(",")]
        invalid_funcs.sort()

        assert invalid_funcs == expected_invalid_funcs


def test_unsupported_plugin_log(caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    with monkeypatch.context() as m:
        m.setattr(
            "sys.argv",
            ["target-query", "-f", "regf", "tests/_data/loaders/tar/test-archive.tar.gz"],
        )

        target_query()

        assert "Unsupported plugin for regf: Registry plugin not loaded" in caplog.text


def mock_find_functions(patterns: str, *args, **kwargs) -> tuple[list[FunctionDescriptor], set[str]]:
    plugins = [
        FunctionDescriptor(
            name=pattern,
            namespace=None,
            path=pattern,
            exported=True,
            internal=False,
            findable=True,
            alias=False,
            output="record",
            method_name=pattern,
            module=pattern,
            qualname=pattern.capitalize(),
        )
        for pattern in patterns.split(",")
    ]

    return (plugins, set())


def mock_execute_function(
    target: Target,
    func: FunctionDescriptor,
    arguments: list[str] | None = None,
) -> tuple[str, Any, list[str]]:
    return (func.output, func.name, "")


def test_filtered_functions(monkeypatch: pytest.MonkeyPatch) -> None:
    with monkeypatch.context() as m:
        m.setattr(
            "sys.argv",
            [
                "target-query",
                "-f",
                "foo,bar,bla,foo",
                "-xf",
                "bla",
                "tests/_data/loaders/tar/test-archive.tar.gz",
            ],
        )

        with (
            patch(
                "dissect.target.tools.query.find_functions",
                autospec=True,
                side_effect=mock_find_functions,
            ),
            patch(
                "dissect.target.tools.utils.find_functions",
                autospec=True,
                side_effect=mock_find_functions,
            ),
            patch(
                "dissect.target.tools.query.execute_function_on_target",
                autospec=True,
                side_effect=mock_execute_function,
            ) as mock_execute,
            patch(
                "dissect.target.tools.query.record_output",
                autospec=True,
            ),
        ):
            target_query()

            assert len(mock_execute.mock_calls) == 2

            executed_func_names = set()
            for call in mock_execute.mock_calls:
                executed_func_names.add(call.args[1].name)
            assert executed_func_names == {"foo", "bar"}


def test_dry_run(capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    if os.sep == "\\":
        target_file = "tests\\_data\\loaders\\tar\\test-archive.tar.gz"
    else:
        target_file = "tests/_data/loaders/tar/test-archive.tar.gz"

    with monkeypatch.context() as m:
        m.setattr(
            "sys.argv",
            ["target-query", "-f", "general.*", "--dry-run", target_file],
        )

        target_query()
        out, _ = capsys.readouterr()

        assert out == (f"Dry run on: <Target {target_file}>\n  execute: osinfo (general.osinfo.osinfo)\n")


def test_list_json(capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test if target-query --list --json output is formatted as we expect it to be."""

    with monkeypatch.context() as m:
        m.setattr("sys.argv", ["target-query", "-l", "-j"])
        target_query()
        out, _ = capsys.readouterr()

    try:
        output = json.loads(out)
    except json.JSONDecodeError:
        pass

    # test the generic structure of the returned dictionary.
    assert isinstance(output, dict), "Could not load JSON output of 'target-query --list --json'"
    assert output["plugins"], "Expected a dictionary of plugins"
    assert output["loaders"], "Expected a dictionary of loaders"
    assert len(output["plugins"]["loaded"]) > 200, "Expected more loaded plugins"
    assert not output["plugins"].get("failed"), "Some plugin(s) failed to initialize"

    def get_plugin(plugins: list[dict], needle: str) -> dict | bool:
        match = [p for p in plugins["plugins"]["loaded"] if p["name"] == needle]
        return match[0] if match else False

    # general plugin
    users_plugin = get_plugin(output, "users")
    assert users_plugin == {
        "name": "users",
        "description": "Return the users available in the target.",
        "output": "record",
        "arguments": [],
        "alias": False,
        "path": "os.default._os.users",
    }

    # namespaced plugin
    plocate_plugin = get_plugin(output, "plocate.locate")
    assert plocate_plugin == {
        "name": "plocate.locate",
        "description": "Yield file and directory names from the plocate.db.",
        "output": "record",
        "arguments": [],
        "alias": False,
        "path": "os.unix.locate.plocate.locate",
    }

    # regular plugin
    sam_plugin = get_plugin(output, "sam")
    assert sam_plugin == {
        "name": "sam",
        "description": "Dump SAM entries",
        "output": "record",
        "arguments": [],
        "alias": False,
        "path": "os.windows.credential.sam.sam",
    }

    # plugin with arguments
    docker_plugin = get_plugin(output, "docker.logs")
    assert docker_plugin == {
        "name": "docker.logs",
        "output": "record",
        "description": "Returns log files (stdout/stderr) from Docker containers.",
        "arguments": [
            {
                "name": "--raw-messages",
                "type": "bool",
                "help": "preserve ANSI escape sequences and trailing newlines from log messages",
                "default": False,
                "required": False,
            },
            {
                "name": "--remove-backspaces",
                "type": "bool",
                "help": "alter messages by removing ASCII backspaces and the corresponding characters",
                "default": False,
                "required": False,
            },
        ],
        "path": "apps.container.docker.logs",
        "alias": False,
    }


def test_record_stream_write_exception_handling(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test if we correctly print the function name of the iterator that failed to iterate."""

    with monkeypatch.context() as m:
        m.setattr("sys.argv", ["target-query", "-f", "users,walkfs", "tests/_data/loaders/tar/test-archive.tar.gz"])

        with patch("dissect.target.tools.query.record_output", return_value=None):
            target_query()

    assert "Exception occurred while processing output of WalkFSPlugin.walkfs:" in caplog.text
